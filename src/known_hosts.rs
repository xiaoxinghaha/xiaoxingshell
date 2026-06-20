//! Host-key verification store (#109-5 / #105).
//!
//! Replaces the old "accept any server key" behaviour with a TOFU-style
//! known_hosts file plus a first-connect confirmation dialog:
//!   • unknown host  → prompt the user with the key fingerprint; on accept the
//!                     key is remembered here.
//!   • known + match  → connect silently.
//!   • known + differ → flagged as *changed* (possible MITM); the user must
//!                     re-confirm before the new key replaces the stored one.
//!
//! The file lives next to `sessions.json` (one entry per line):
//!     `host:port ssh-ed25519 AAAA...`
//! i.e. the `host:port` id followed by the key in its OpenSSH one-line form.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ssh_key::{HashAlg, PublicKey};

/// Result of checking a server key against the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// No entry for this host:port — first time we've seen it.
    Unknown,
    /// Stored key matches the presented one — trusted.
    Match,
    /// A key is stored for this host:port but it differs (possible MITM).
    Changed,
}

/// `host:port` lookup key.
fn id(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Path to the known_hosts file (alongside sessions.json). `None` if the user
/// config directory can't be determined.
fn path() -> Option<PathBuf> {
    crate::config::app_config_dir()
        .ok()
        .map(|dir| dir.join("known_hosts"))
}

/// The presented key in its canonical OpenSSH one-line form (`type base64`,
/// no comment), used for exact comparison and for storage.
fn openssh_line(key: &PublicKey) -> String {
    // `to_openssh` only fails on an unsupported/!encodable key, which russh
    // would not have negotiated; fall back to the SHA256 fingerprint so a
    // freak case still stores *something* stable rather than panicking.
    key.to_openssh().unwrap_or_else(|_| fingerprint(key))
}

/// Human-readable SHA256 fingerprint (`SHA256:base64…`) shown in the dialog.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Parse the file into `(id, openssh_key)` entries. Missing file → empty.
/// Malformed / comment (`#`) lines are skipped.
fn load() -> Vec<(String, String)> {
    let Some(p) = path() else { return Vec::new() };
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (id, key) = line.split_once(char::is_whitespace)?;
            Some((id.to_string(), key.trim().to_string()))
        })
        .collect()
}

/// Check a presented server key against the store.
pub fn verify(host: &str, port: u16, key: &PublicKey) -> HostKeyStatus {
    let want = openssh_line(key);
    let id = id(host, port);
    let mut seen_host = false;
    for (entry_id, entry_key) in load() {
        if entry_id != id {
            continue;
        }
        seen_host = true;
        if entry_key == want {
            return HostKeyStatus::Match;
        }
    }
    if seen_host {
        HostKeyStatus::Changed
    } else {
        HostKeyStatus::Unknown
    }
}

/// Remember (or replace) the key for `host:port`. Rewrites the file with any
/// stale entry for the same id removed, then appends the new one.
pub fn remember(host: &str, port: u16, key: &PublicKey) -> Result<()> {
    let p = path().context("could not determine config directory")?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).context("create config dir")?;
    }
    let id = id(host, port);
    let line = openssh_line(key);
    let mut out = String::new();
    for (entry_id, entry_key) in load() {
        if entry_id == id {
            continue; // drop the old key for this host:port
        }
        out.push_str(&entry_id);
        out.push(' ');
        out.push_str(&entry_key);
        out.push('\n');
    }
    out.push_str(&id);
    out.push(' ');
    out.push_str(&line);
    out.push('\n');
    std::fs::write(&p, out).with_context(|| format!("write {}", p.display()))?;
    Ok(())
}
