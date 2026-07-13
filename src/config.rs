//! Session / application configuration.
//!
//! Persists a simple JSON file under the platform's standard config dir
//! (e.g. `%APPDATA%/xiaoxingshell/sessions.json` on Windows,
//!  `~/.config/xiaoxingshell/sessions.json` on Linux/macOS).
//!
//! ## Password encryption
//!
//! Passwords are **not** stored in plaintext.  On first launch a random
//! 256-bit key is written to `secret.key` in the same config directory
//! (mode `0600` on Unix).  Every non-empty password is then encrypted with
//! **ChaCha20-Poly1305** (a random 96-bit nonce per value) and stored as
//!
//! ```text
//! enc:v1:<base64url(nonce_12_bytes || ciphertext)>
//! ```
//!
//! Legacy plaintext passwords (from older installs) are left untouched in
//! memory and silently re-encrypted the next time the config is saved.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use directories::BaseDirs;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// A secret string (e.g. a session password) whose heap buffer is zeroed when
/// it is dropped, so plaintext credentials don't survive in freed memory and
/// turn up in core dumps, a debugger, or `/proc/<pid>/mem`.  `Clone` makes an
/// independent copy that is likewise zeroed on its own drop, and `Debug` is
/// redacted so a password can never be logged by accident.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the contents in logs / debug output.
        f.write_str(if self.0.is_empty() {
            "Secret(\"\")"
        } else {
            "Secret(***)"
        })
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Secret(String::deserialize(d)?))
    }
}

/// Which transport a session uses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// SSH shell + SFTP (the original and default behaviour).
    #[default]
    Ssh,
    /// Local serial port (COM3 / /dev/ttyUSB0) for switches, routers, MCUs (#14).
    Serial,
    /// Plain Telnet over TCP, for legacy network gear (#17).
    Telnet,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::Ssh => "ssh",
            SessionKind::Serial => "serial",
            SessionKind::Telnet => "telnet",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "serial" => SessionKind::Serial,
            "telnet" => SessionKind::Telnet,
            _ => SessionKind::Ssh,
        }
    }
}

fn default_baud() -> u32 {
    115_200
}
fn default_data_bits() -> u8 {
    8
}
fn default_stop_bits() -> u8 {
    1
}
fn default_parity() -> String {
    "none".to_string()
}
fn default_flow() -> String {
    "none".to_string()
}

/// How a session authenticates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::Key => "key",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "key" => AuthMethod::Key,
            _ => AuthMethod::Password,
        }
    }
}

/// A single saved SSH target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub password: Secret,
    #[serde(default)]
    pub key_passphrase: Secret,
    #[serde(default)]
    pub private_key_path: String,
    /// Optional outbound proxy, e.g. "socks5://127.0.0.1:1080" or
    /// "http://user:pass@host:8080". Empty = use $ALL_PROXY, else direct.
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub last_used: Option<String>,
    /// Optional folder/group name to organize sessions in the list (#41).
    /// Empty = ungrouped. Sessions are grouped by this in Quick Connect.
    #[serde(default)]
    pub group: String,

    // --- Transport ----------------------------------------------------------
    /// SSH (default), Serial, or Telnet. Absent in old config files → Ssh.
    #[serde(default)]
    pub kind: SessionKind,

    // --- Serial-only fields (ignored unless kind == Serial) -----------------
    /// Serial device path, e.g. "COM3" (Windows) or "/dev/ttyUSB0" (Linux).
    #[serde(default)]
    pub serial_port: String,
    #[serde(default = "default_baud")]
    pub baud_rate: u32,
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,
    /// "none" | "odd" | "even".
    #[serde(default = "default_parity")]
    pub parity: String,
    /// "none" | "hardware" | "software".
    #[serde(default = "default_flow")]
    pub flow_control: String,

    // --- SSH port forwarding / tunnels (#56) --------------------------------
    /// Tunnels established automatically when this SSH session connects.
    #[serde(default)]
    pub forwards: Vec<PortForward>,
    #[serde(default)]
    pub ui_state: SessionUiState,
}

/// One SSH tunnel (#56). `kind` is "local" (-L), "remote" (-R) or
/// "dynamic" (-D / SOCKS5). For local/remote, `host:host_port` is the target;
/// for dynamic it is ignored (the SOCKS client picks the destination).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortForward {
    pub kind: String,
    /// Listener bind address (local side for L/D, remote side for R).
    /// Empty → 127.0.0.1.
    #[serde(default)]
    pub bind_addr: String,
    pub bind_port: u16,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub host_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionUiState {
    #[serde(default)]
    pub sftp_panel_height: u32,
    #[serde(default)]
    pub sftp_saved_height: u32,
    #[serde(default)]
    pub sftp_collapsed: bool,
    #[serde(default)]
    pub sftp_tree_width: u32,
    #[serde(default)]
    pub sftp_col_name_width: u32,
    #[serde(default)]
    pub sftp_col_size_width: u32,
    #[serde(default)]
    pub sftp_col_type_width: u32,
    #[serde(default)]
    pub sftp_col_modified_width: u32,
    #[serde(default)]
    pub sftp_col_mode_width: u32,
    #[serde(default)]
    pub sftp_col_owner_width: u32,
    /// Per-session preference for SSH local input optimization. Defaults off.
    #[serde(default)]
    pub local_input_optimization: bool,
}

impl Session {
    pub fn new_empty() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            host: String::new(),
            port: 22,
            user: "root".into(),
            auth: AuthMethod::Password,
            password: Secret::default(),
            key_passphrase: Secret::default(),
            private_key_path: String::new(),
            proxy: String::new(),
            last_used: None,
            group: String::new(),
            kind: SessionKind::Ssh,
            serial_port: String::new(),
            baud_rate: default_baud(),
            data_bits: default_data_bits(),
            stop_bits: default_stop_bits(),
            parity: default_parity(),
            flow_control: default_flow(),
            forwards: Vec::new(),
            ui_state: SessionUiState::default(),
        }
    }
}

/// A saved quick command (#55): a named snippet the user clicks to send to the
/// active terminal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuickCommand {
    pub name: String,
    pub command: String,
}

/// One suffix -> editor executable rule for "Edit externally".
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ExternalEditorRule {
    #[serde(default)]
    pub suffix: String,
    #[serde(default)]
    pub program: String,
}

/// Last non-minimized top-level window placement. Size is the client area
/// (inner size) in physical pixels; position is the outer top-left in physical
/// screen coordinates. On platforms that don't expose window positioning (for
/// example some Wayland sessions), x/y may stay absent while width/height still
/// restore correctly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowState {
    #[serde(default)]
    pub x: Option<i32>,
    #[serde(default)]
    pub y: Option<i32>,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub maximized: bool,
}

/// On-disk layout. Keep additive to ease forward-compat.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// Preset SFTP download directory. Empty = ask each time.
    #[serde(default)]
    pub download_dir: String,
    /// Preferred external editor executable path for "Edit externally".
    #[serde(default)]
    pub external_editor: String,
    /// Optional suffix-specific editor overrides, e.g. `.py` -> Code.
    #[serde(default)]
    pub external_editor_rules: Vec<ExternalEditorRule>,
    /// Last directory used by the private-key file picker in the session dialog.
    #[serde(default)]
    pub last_key_dir: String,
    /// UI language code: "zh" (default) or "en".
    #[serde(default)]
    pub language: String,
    /// Theme preference: "system" (default) | "dark" | "light".
    #[serde(default)]
    pub theme_pref: String,
    /// Background color override for the narrow left nav rail. Empty = default.
    #[serde(default)]
    pub nav_rail_bg: String,
    /// Background color override for the custom top title bar. Empty = default.
    #[serde(default)]
    pub top_bar_bg: String,
    /// Background color override for the terminal viewport. Empty = default.
    #[serde(default)]
    pub term_bg: String,
    /// Background image path for the terminal viewport. Empty = disabled.
    #[serde(default)]
    pub term_bg_image: String,
    /// Overlay opacity above the terminal background image (0-100).
    #[serde(default)]
    pub term_bg_image_opacity: u32,
    /// Terminal background image fit mode: cover | contain | fill | preserve.
    #[serde(default)]
    pub term_bg_image_fit: String,
    /// Terminal font family. Empty = the built-in default ("Meatshell Mono").
    #[serde(default)]
    pub font_family: String,
    /// Terminal font size in px. 0 = the built-in default.
    #[serde(default)]
    pub font_size: u32,
    /// Maximum terminal scrollback lines kept in memory. 0 = built-in default.
    #[serde(default)]
    pub terminal_scrollback_lines: u32,
    /// Duration for the short session-row flash after create/edit/connect. 0 =
    /// built-in default.
    #[serde(default)]
    pub session_flash_ms: u32,
    /// Explicit session groups/folders (#41), including empty ones so a folder
    /// can exist before any session is moved into it. "default" is implicit and
    /// not stored here.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Stored inverted ("don't follow") so both serde and the Default derive
    /// yield `false` = the feature defaults to ON: the SFTP panel follows the
    /// terminal's cd (OSC 7) unless the user opts out in Interface settings.
    #[serde(default)]
    pub sftp_no_follow_cd: bool,
    /// SSH/SFTP protocol keepalive interval in seconds. 0 = built-in default
    /// (120s); kept as a global setting because both shell and SFTP channels
    /// need the same idle-connection protection.
    #[serde(default)]
    pub keepalive_interval_secs: u32,
    /// Number of unanswered keepalive probes tolerated before russh considers
    /// the SSH/SFTP connection dead. Defaults to 5.
    #[serde(default)]
    pub disconnect_retry_count: u32,
    /// SFTP application-level auto refresh interval in seconds. 0 = built-in
    /// default (60s). Stored globally because it applies to every SFTP panel.
    #[serde(default)]
    pub sftp_auto_refresh_secs: u32,
    /// Always prompt for the save location on each download instead of using the
    /// preset download dir. Defaults to false (#87).
    #[serde(default)]
    pub download_always_ask: bool,
    /// Saved quick commands (#55).
    #[serde(default)]
    pub quick_commands: Vec<QuickCommand>,
    /// Recent commands sent from the command box, oldest first, capped (#55).
    #[serde(default)]
    pub command_history: Vec<String>,
    /// Collapse the left resource sidebar on startup (#78).
    #[serde(default)]
    pub collapse_sidebar_default: bool,
    /// Collapse the bottom SFTP panel on startup (#78).
    #[serde(default)]
    pub collapse_sftp_default: bool,
    /// Shared bottom SFTP panel height in px. 0 = built-in default.
    #[serde(default)]
    pub sftp_panel_height: u32,
    /// Shared restored SFTP panel height in px when expanding from collapsed.
    #[serde(default)]
    pub sftp_saved_height: u32,
    /// When session-sync is on, also mirror SFTP uploads to the other online
    /// sessions (same path, falling back to each panel's current dir).
    #[serde(default)]
    pub sync_upload: bool,
    /// Remember the main window's last placement so relaunch restores it.
    #[serde(default)]
    pub window_state: WindowState,
}

/// Portable export file (issue #46): sessions with everything in plaintext
/// **except** the password, which is encrypted with a fixed key baked into the
/// binary so the file opens on *any* machine running meatshell.
///
/// Security note: a built-in key in open-source code is **obfuscation, not real
/// security** — anyone with the source can derive it. It only stops a casual
/// over-the-shoulder read of the file, same level as FinalShell's export.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportFile {
    /// Format marker / version so the schema can evolve later.
    meatshell_export: u32,
    sessions: Vec<Session>,
}

pub struct ConfigStore {
    path: PathBuf,
    cache: ConfigFile,
    /// ChaCha20-Poly1305 key loaded from (or freshly generated into)
    /// `secret.key` in the same directory as `sessions.json`.
    key: [u8; 32],
}

/// Remove duplicate entries in place, keeping the *last* (most recent)
/// occurrence of each and preserving relative order (#113). The list is capped
/// at 200, so the quadratic scan is trivial.
fn dedup_keep_last(items: &mut Vec<String>) {
    let mut i = 0;
    while i < items.len() {
        if items[i + 1..].contains(&items[i]) {
            items.remove(i);
        } else {
            i += 1;
        }
    }
}

fn normalize_editor_suffix(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    Some(if lower.starts_with('.') {
        lower
    } else {
        format!(".{lower}")
    })
}

fn matches_editor_suffix(path: &str, suffix: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    file_name.to_ascii_lowercase().ends_with(suffix)
}

impl ConfigStore {
    /// The prefix that marks an encrypted password blob in sessions.json.
    const ENC_PREFIX: &'static str = "enc:v1:";

    /// Marks a password encrypted with the **portable export key** (issue #46).
    const EXPORT_PREFIX: &'static str = "enc:exp:v1:";

    /// Fixed 32-byte key for portable exports. Baked into the binary so an
    /// exported file decrypts on any machine. Obfuscation only — see `ExportFile`.
    const EXPORT_KEY: [u8; 32] = *b"meatshell.export.portable.key.01";

    // ── Encryption helpers ────────────────────────────────────────────────

    /// Encrypt `plaintext` with ChaCha20-Poly1305 and return
    /// `"enc:v1:<base64url(nonce_12_bytes || ciphertext)>"`.
    fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 12 random bytes
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("password encrypt error: {e}"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            Self::ENC_PREFIX,
            URL_SAFE_NO_PAD.encode(&blob)
        ))
    }

    /// Try to decrypt a value produced by [`Self::encrypt`].
    /// Returns `None` if the string is not an encrypted blob (e.g. a legacy
    /// plaintext value, an empty string, or a tampered/corrupt blob).
    fn try_decrypt(key: &[u8; 32], s: &str) -> Option<String> {
        let b64 = s.strip_prefix(Self::ENC_PREFIX)?;
        let blob = URL_SAFE_NO_PAD.decode(b64).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plain).ok()
    }

    // ── Key file management ───────────────────────────────────────────────

    /// Load the 32-byte key from `<config_dir>/secret.key`, or generate and
    /// persist a fresh one.  On Unix the key file is created with mode `0600`
    /// so other local accounts cannot read it.  On Windows files in `%APPDATA%`
    /// are already restricted to the owning user by default ACLs.
    fn load_or_create_key(config_dir: &Path) -> Result<[u8; 32]> {
        use rand::RngCore as _;
        let key_path = config_dir.join("secret.key");

        if key_path.exists() {
            let bytes = fs::read(&key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
            tracing::warn!("secret.key has wrong length — regenerating");
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        fs::write(&key_path, &key)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", key_path.display()))?;
        }
        tracing::info!("generated new encryption key at {}", key_path.display());
        Ok(key)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Load (or initialise) the config file. On any parse error we back up the
    /// broken file and start fresh — losing saved sessions is better than
    /// crashing at launch.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        let config_dir = path
            .parent()
            .context("config path has no parent directory")?
            .to_path_buf();

        fs::create_dir_all(&config_dir)
            .with_context(|| format!("failed to create config dir {}", config_dir.display()))?;

        let key = Self::load_or_create_key(&config_dir)?;

        let cache = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            match serde_json::from_str::<ConfigFile>(&raw) {
                Ok(mut cfg) => {
                    // Decrypt any encrypted passwords; leave legacy plaintext
                    // values untouched (they will be encrypted on next save).
                    for session in &mut cfg.sessions {
                        if let Some(plain) = Self::try_decrypt(&key, session.password.as_str()) {
                            session.password = Secret::new(plain);
                        }
                        if let Some(plain) =
                            Self::try_decrypt(&key, session.key_passphrase.as_str())
                        {
                            session.key_passphrase = Secret::new(plain);
                        }
                        // Older builds stored the private-key passphrase in the
                        // shared `password` field for key-based auth. Migrate it
                        // into the dedicated field on load.
                        if session.auth == AuthMethod::Key
                            && session.key_passphrase.is_empty()
                            && !session.password.is_empty()
                        {
                            session.key_passphrase = session.password.clone();
                            session.password = Secret::default();
                        }
                    }
                    // Clean up any duplicate history accumulated before #113,
                    // keeping the last (most recent) occurrence of each command.
                    dedup_keep_last(&mut cfg.command_history);
                    cfg
                }
                Err(err) => {
                    let backup = path.with_extension("json.broken");
                    let _ = fs::rename(&path, &backup);
                    tracing::warn!(
                        "config file was corrupt ({err}); backed up to {}",
                        backup.display()
                    );
                    ConfigFile::default()
                }
            }
        } else {
            ConfigFile::default()
        };

        Ok(Self { path, cache, key })
    }

    fn config_path() -> Result<PathBuf> {
        Ok(app_config_dir()?.join("sessions.json"))
    }

    pub fn sessions(&self) -> &[Session] {
        &self.cache.sessions
    }

    #[allow(dead_code)] // reserved for an upcoming reorder/drag-drop feature
    pub fn sessions_mut(&mut self) -> &mut Vec<Session> {
        &mut self.cache.sessions
    }

    pub fn upsert(&mut self, session: Session) {
        self.touch_group_usage(&session.group);
        if let Some(existing) = self.cache.sessions.iter_mut().find(|s| s.id == session.id) {
            *existing = session;
        } else {
            self.cache.sessions.push(session);
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.cache.sessions.retain(|s| s.id != id);
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.cache.sessions.iter().find(|s| s.id == id)
    }

    pub fn download_dir(&self) -> &str {
        &self.cache.download_dir
    }

    pub fn set_download_dir(&mut self, dir: String) {
        self.cache.download_dir = dir;
    }

    pub fn external_editor(&self) -> &str {
        &self.cache.external_editor
    }

    pub fn set_external_editor(&mut self, path: String) {
        self.cache.external_editor = path.trim().to_string();
    }

    pub fn external_editor_rules(&self) -> &[ExternalEditorRule] {
        &self.cache.external_editor_rules
    }

    pub fn upsert_external_editor_rule(&mut self, suffix: String, program: String) {
        let Some(suffix) = normalize_editor_suffix(&suffix) else {
            return;
        };
        let program = program.trim().to_string();
        if program.is_empty() {
            return;
        }
        if let Some(rule) =
            self.cache.external_editor_rules.iter_mut().find(|rule| {
                normalize_editor_suffix(&rule.suffix).as_deref() == Some(suffix.as_str())
            })
        {
            rule.suffix = suffix;
            rule.program = program;
            return;
        }
        self.cache
            .external_editor_rules
            .push(ExternalEditorRule { suffix, program });
    }

    pub fn remove_external_editor_rule(&mut self, index: usize) {
        if index < self.cache.external_editor_rules.len() {
            self.cache.external_editor_rules.remove(index);
        }
    }

    /// Longest matching suffix wins; otherwise fall back to the default editor.
    pub fn editor_for_path(&self, path: &str) -> Option<String> {
        let best = self
            .cache
            .external_editor_rules
            .iter()
            .filter_map(|rule| {
                let suffix = normalize_editor_suffix(&rule.suffix)?;
                let program = rule.program.trim();
                if program.is_empty() || !matches_editor_suffix(path, &suffix) {
                    return None;
                }
                Some((suffix.len(), program.to_string()))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, program)| program);
        best.or_else(|| {
            let fallback = self.cache.external_editor.trim();
            if fallback.is_empty() {
                None
            } else {
                Some(fallback.to_string())
            }
        })
    }

    /// UI language code ("zh" default / "en").
    pub fn language(&self) -> &str {
        if self.cache.language.is_empty() {
            "zh"
        } else {
            &self.cache.language
        }
    }

    pub fn set_language(&mut self, lang: String) {
        self.cache.language = lang;
    }

    /// Theme preference: "system" (default) | "dark" | "light".
    pub fn theme_pref(&self) -> &str {
        if self.cache.theme_pref.is_empty() {
            "system"
        } else {
            &self.cache.theme_pref
        }
    }

    pub fn set_theme_pref(&mut self, pref: String) {
        self.cache.theme_pref = pref;
    }

    pub fn nav_rail_bg(&self) -> &str {
        &self.cache.nav_rail_bg
    }

    pub fn set_nav_rail_bg(&mut self, color: String) {
        self.cache.nav_rail_bg = color;
    }

    pub fn top_bar_bg(&self) -> &str {
        &self.cache.top_bar_bg
    }

    pub fn set_top_bar_bg(&mut self, color: String) {
        self.cache.top_bar_bg = color;
    }

    pub fn term_bg(&self) -> &str {
        &self.cache.term_bg
    }

    pub fn set_term_bg(&mut self, color: String) {
        self.cache.term_bg = color;
    }

    pub fn term_bg_image(&self) -> &str {
        &self.cache.term_bg_image
    }

    pub fn set_term_bg_image(&mut self, path: String) {
        self.cache.term_bg_image = path;
    }

    pub fn term_bg_image_opacity(&self) -> u32 {
        if self.cache.term_bg_image_opacity > 100 {
            55
        } else if self.cache.term_bg_image_opacity == 0 {
            55
        } else {
            self.cache.term_bg_image_opacity
        }
    }

    pub fn set_term_bg_image_opacity(&mut self, value: u32) {
        self.cache.term_bg_image_opacity = value.min(100);
    }

    pub fn term_bg_image_fit(&self) -> &str {
        if self.cache.term_bg_image_fit.is_empty() {
            "cover"
        } else {
            &self.cache.term_bg_image_fit
        }
    }

    pub fn set_term_bg_image_fit(&mut self, value: String) {
        self.cache.term_bg_image_fit = value;
    }

    /// Terminal font family ("" = built-in default).
    pub fn font_family(&self) -> &str {
        &self.cache.font_family
    }

    pub fn set_font_family(&mut self, family: String) {
        self.cache.font_family = family;
    }

    /// Terminal font size in px (falls back to 13 when unset).
    pub fn font_size(&self) -> u32 {
        if self.cache.font_size == 0 {
            13
        } else {
            self.cache.font_size
        }
    }

    pub fn set_font_size(&mut self, size: u32) {
        self.cache.font_size = size.clamp(8, 32);
    }

    /// Maximum terminal scrollback lines kept in memory (default 9999).
    pub fn terminal_scrollback_lines(&self) -> u32 {
        if self.cache.terminal_scrollback_lines == 0 {
            9_999
        } else {
            self.cache.terminal_scrollback_lines.clamp(100, 200_000)
        }
    }

    pub fn set_terminal_scrollback_lines(&mut self, lines: u32) {
        self.cache.terminal_scrollback_lines = lines.clamp(100, 200_000);
    }

    /// Session row flash duration in milliseconds (default 1000).
    pub fn session_flash_ms(&self) -> u32 {
        if self.cache.session_flash_ms == 0 {
            1_000
        } else {
            self.cache.session_flash_ms.clamp(100, 5_000)
        }
    }

    pub fn set_session_flash_ms(&mut self, ms: u32) {
        self.cache.session_flash_ms = ms.clamp(100, 5_000);
    }

    /// Whether the SFTP panel follows the terminal's cd (default true).
    pub fn sftp_follow_cd(&self) -> bool {
        !self.cache.sftp_no_follow_cd
    }

    pub fn set_sftp_follow_cd(&mut self, follow: bool) {
        self.cache.sftp_no_follow_cd = !follow;
    }

    /// SSH/SFTP protocol keepalive interval in seconds (default 120).
    pub fn keepalive_interval_secs(&self) -> u32 {
        if self.cache.keepalive_interval_secs == 0 {
            120
        } else {
            self.cache.keepalive_interval_secs.clamp(30, 3600)
        }
    }

    pub fn set_keepalive_interval_secs(&mut self, secs: u32) {
        self.cache.keepalive_interval_secs = secs.clamp(30, 3600);
    }

    /// Unanswered keepalive probes tolerated before disconnect (default 5).
    pub fn disconnect_retry_count(&self) -> u32 {
        if self.cache.disconnect_retry_count == 0 {
            5
        } else {
            self.cache.disconnect_retry_count.clamp(1, 20)
        }
    }

    pub fn set_disconnect_retry_count(&mut self, retries: u32) {
        self.cache.disconnect_retry_count = retries.clamp(1, 20);
    }

    /// SFTP application-level auto refresh interval in seconds (default 60).
    pub fn sftp_auto_refresh_secs(&self) -> u32 {
        if self.cache.sftp_auto_refresh_secs == 0 {
            60
        } else {
            self.cache.sftp_auto_refresh_secs.clamp(10, 3600)
        }
    }

    pub fn set_sftp_auto_refresh_secs(&mut self, secs: u32) {
        self.cache.sftp_auto_refresh_secs = secs.clamp(10, 3600);
    }

    /// Saved quick commands (#55).
    pub fn quick_commands(&self) -> &[QuickCommand] {
        &self.cache.quick_commands
    }

    pub fn set_quick_commands(&mut self, cmds: Vec<QuickCommand>) {
        self.cache.quick_commands = cmds;
    }

    /// Recent command-box history, oldest first (#55).
    pub fn command_history(&self) -> &[String] {
        &self.cache.command_history
    }

    /// Append a command to the history: skips blanks, de-duplicates globally so
    /// each command appears once, and re-appends at the end so the most-recently
    /// used command is always last. Capped so it can't grow without bound (#113).
    pub fn push_command_history(&mut self, cmd: String) {
        if cmd.trim().is_empty() {
            return;
        }
        // Drop any earlier occurrence, then push → no duplicates and "last used"
        // moves to the end (bash `HISTCONTROL=erasedups` semantics).
        self.cache.command_history.retain(|c| c != &cmd);
        const CAP: usize = 200;
        self.cache.command_history.push(cmd);
        let len = self.cache.command_history.len();
        if len > CAP {
            self.cache.command_history.drain(0..len - CAP);
        }
    }

    /// Remove a single command-history entry by storage index (#96).
    pub fn remove_command_history(&mut self, index: usize) {
        if index < self.cache.command_history.len() {
            self.cache.command_history.remove(index);
        }
    }

    /// Collapse the resource sidebar on startup (default false) (#78).
    pub fn collapse_sidebar_default(&self) -> bool {
        self.cache.collapse_sidebar_default
    }

    pub fn set_collapse_sidebar_default(&mut self, v: bool) {
        self.cache.collapse_sidebar_default = v;
    }

    /// Collapse the SFTP panel on startup (default false) (#78).
    pub fn collapse_sftp_default(&self) -> bool {
        self.cache.collapse_sftp_default
    }

    pub fn set_collapse_sftp_default(&mut self, v: bool) {
        self.cache.collapse_sftp_default = v;
    }

    /// Shared SFTP panel height in px (falls back to 220 when unset).
    pub fn sftp_panel_height(&self) -> u32 {
        if self.cache.sftp_panel_height == 0 {
            220
        } else {
            self.cache.sftp_panel_height
        }
    }

    pub fn set_sftp_panel_height(&mut self, height: u32) {
        self.cache.sftp_panel_height = height.clamp(60, 1200);
    }

    /// Restored SFTP panel height in px after un-collapsing.
    pub fn sftp_saved_height(&self) -> u32 {
        if self.cache.sftp_saved_height == 0 {
            self.sftp_panel_height()
        } else {
            self.cache.sftp_saved_height
        }
    }

    pub fn set_sftp_saved_height(&mut self, height: u32) {
        self.cache.sftp_saved_height = height.clamp(60, 1200);
    }

    /// Mirror SFTP uploads to other sessions while session-sync is on (default
    /// false). Only has effect when the session-sync toggle is on.
    pub fn sync_upload(&self) -> bool {
        self.cache.sync_upload
    }

    pub fn set_sync_upload(&mut self, v: bool) {
        self.cache.sync_upload = v;
    }

    pub fn last_key_dir(&self) -> &str {
        &self.cache.last_key_dir
    }

    pub fn set_last_key_dir(&mut self, dir: String) {
        self.cache.last_key_dir = dir;
    }

    /// Whether each download prompts for a save location (default false) (#87).
    pub fn download_always_ask(&self) -> bool {
        self.cache.download_always_ask
    }

    pub fn set_download_always_ask(&mut self, ask: bool) {
        self.cache.download_always_ask = ask;
    }

    /// Saved window placement. Returns `(x, y, width, height)` where x/y may be
    /// absent on window systems that don't expose absolute positioning.
    pub fn window_geometry(&self) -> Option<(Option<i32>, Option<i32>, u32, u32)> {
        let ws = &self.cache.window_state;
        if ws.width == 0 || ws.height == 0 {
            None
        } else {
            Some((ws.x, ws.y, ws.width, ws.height))
        }
    }

    pub fn window_maximized(&self) -> bool {
        self.cache.window_state.maximized
    }

    pub fn set_window_geometry(&mut self, x: Option<i32>, y: Option<i32>, width: u32, height: u32) {
        let ws = &mut self.cache.window_state;
        if let Some(x) = x {
            ws.x = Some(x);
        }
        if let Some(y) = y {
            ws.y = Some(y);
        }
        if width > 0 {
            ws.width = width;
        }
        if height > 0 {
            ws.height = height;
        }
    }

    pub fn set_window_maximized(&mut self, maximized: bool) {
        self.cache.window_state.maximized = maximized;
    }

    // ── Session groups / folders (#41) ────────────────────────────────────

    /// Explicit groups (empty folders included). "default" is implicit.
    pub fn groups(&self) -> &[String] {
        &self.cache.groups
    }

    /// Create an empty group. Ignores blank names, the reserved "default", and
    /// duplicates.
    pub fn add_group(&mut self, name: String) {
        let n = name.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") {
            return;
        }
        self.touch_group_usage(&n);
    }

    /// Delete a group. Any session still in it falls back to ungrouped — the UI
    /// only offers delete on empty groups, but we clear sessions defensively.
    pub fn remove_group(&mut self, name: &str) {
        self.cache.groups.retain(|g| g != name);
        for s in &mut self.cache.sessions {
            if s.group == name {
                s.group.clear();
            }
        }
    }

    /// Rename a group, moving its sessions along. No-op for blank / "default".
    pub fn rename_group(&mut self, old: &str, new: String) {
        let n = new.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") || n == old {
            return;
        }
        if let Some(idx) = self.cache.groups.iter().position(|g| g == old) {
            self.cache.groups.remove(idx);
        }
        for s in &mut self.cache.sessions {
            if s.group == old {
                s.group = n.clone();
            }
        }
        self.touch_group_usage(&n);
    }

    /// Move a group to the front of the history so the dialog dropdown prefers
    /// recently used groups over alphabetical order.
    pub fn touch_group_usage(&mut self, name: &str) {
        let n = name.trim();
        if n.is_empty() || n.eq_ignore_ascii_case("default") {
            return;
        }
        self.cache.groups.retain(|g| g != n);
        self.cache.groups.insert(0, n.to_string());
    }

    pub fn save(&self) -> Result<()> {
        // Build a disk copy where every non-empty password is encrypted.
        let mut disk = self.cache.clone();
        for session in &mut disk.sessions {
            if !session.password.is_empty()
                && !session.password.as_str().starts_with(Self::ENC_PREFIX)
            {
                let enc = Self::encrypt(&self.key, session.password.as_str())?;
                session.password = Secret::new(enc);
            }
            if !session.key_passphrase.is_empty()
                && !session
                    .key_passphrase
                    .as_str()
                    .starts_with(Self::ENC_PREFIX)
            {
                let enc = Self::encrypt(&self.key, session.key_passphrase.as_str())?;
                session.key_passphrase = Secret::new(enc);
            }
        }
        let raw = serde_json::to_string_pretty(&disk)?;
        // Write to a sibling temp file then rename — cheap atomicity.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, &raw).with_context(|| format!("failed to write {}", tmp.display()))?;
        // Restrict to owner-only before publishing (#34): sessions.json holds
        // (encrypted) credentials, so it shouldn't be world-readable. Set 0600
        // on the temp file so the permission is already in place at rename.
        // Windows %APPDATA% is owner-restricted by default ACLs — no-op there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", tmp.display()))?;
        }
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("failed to finalise {}", self.path.display()))?;
        Ok(())
    }

    // ── Portable export / import (issue #46) ──────────────────────────────

    /// Encrypt a password with the portable export key → `"enc:exp:v1:<b64>"`.
    fn encrypt_export(plaintext: &str) -> Result<String> {
        let cipher = ChaCha20Poly1305::new((&Self::EXPORT_KEY).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("export encrypt error: {e}"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            Self::EXPORT_PREFIX,
            URL_SAFE_NO_PAD.encode(&blob)
        ))
    }

    /// Decrypt a value produced by [`Self::encrypt_export`]; `None` if it isn't one.
    fn decrypt_export(s: &str) -> Option<String> {
        let b64 = s.strip_prefix(Self::EXPORT_PREFIX)?;
        let blob = URL_SAFE_NO_PAD.decode(b64).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new((&Self::EXPORT_KEY).into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plain).ok()
    }

    /// Export all sessions to a portable JSON file. Passwords are re-encrypted
    /// with the built-in export key; everything else stays plaintext so the
    /// file is human-readable and editable. Returns the number of sessions.
    pub fn export_to(&self, path: &Path) -> Result<usize> {
        let mut out = ExportFile {
            meatshell_export: 1,
            sessions: self.cache.sessions.clone(),
        };
        for s in &mut out.sessions {
            // `cache` holds plaintext passwords; obfuscate with the export key.
            if !s.password.is_empty() {
                let enc = Self::encrypt_export(s.password.as_str())?;
                s.password = Secret::new(enc);
            }
            if !s.key_passphrase.is_empty() {
                let enc = Self::encrypt_export(s.key_passphrase.as_str())?;
                s.key_passphrase = Secret::new(enc);
            }
            // `last_used` is machine-local noise — don't carry it across.
            s.last_used = None;
        }
        let raw = serde_json::to_string_pretty(&out)?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(out.sessions.len())
    }

    /// Import sessions from a file produced by [`Self::export_to`]. New sessions
    /// get fresh ids; duplicates (same host+user+port+kind) are skipped.
    /// Returns `(added, skipped)`. The store is saved if anything was added.
    pub fn import_from(&mut self, path: &Path) -> Result<(usize, usize)> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let file: ExportFile =
            serde_json::from_str(&raw).context("not a valid meatshell export file")?;

        let mut added = 0usize;
        let mut skipped = 0usize;
        for mut s in file.sessions {
            // Recover the plaintext password (cache stores plaintext). Accept an
            // export blob, our local enc:v1 blob, or a legacy plaintext value.
            if let Some(plain) = Self::decrypt_export(s.password.as_str()) {
                s.password = Secret::new(plain);
            } else if let Some(plain) = Self::try_decrypt(&self.key, s.password.as_str()) {
                s.password = Secret::new(plain);
            }
            if let Some(plain) = Self::decrypt_export(s.key_passphrase.as_str()) {
                s.key_passphrase = Secret::new(plain);
            } else if let Some(plain) = Self::try_decrypt(&self.key, s.key_passphrase.as_str()) {
                s.key_passphrase = Secret::new(plain);
            }
            if s.auth == AuthMethod::Key && s.key_passphrase.is_empty() && !s.password.is_empty() {
                s.key_passphrase = s.password.clone();
                s.password = Secret::default();
            }
            let dup = self.cache.sessions.iter().any(|x| {
                x.host == s.host && x.user == s.user && x.port == s.port && x.kind == s.kind
            });
            if dup {
                skipped += 1;
                continue;
            }
            s.id = Uuid::new_v4().to_string();
            self.cache.sessions.push(s);
            added += 1;
        }
        if added > 0 {
            self.save()?;
        }
        Ok((added, skipped))
    }
}

/// Platform-native config directory used by xiaoxingshell:
/// Windows   → `%APPDATA%/xiaoxingshell`
/// Linux     → `~/.config/xiaoxingshell`
/// macOS     → `~/Library/Application Support/xiaoxingshell`
pub(crate) fn app_config_dir() -> Result<PathBuf> {
    let base = BaseDirs::new().context("could not determine user config directory")?;
    Ok(base.config_dir().join("xiaoxingshell"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> ConfigStore {
        let path = std::env::temp_dir().join(format!("ms-test-{}.json", Uuid::new_v4()));
        ConfigStore {
            path,
            cache: ConfigFile::default(),
            key: [7u8; 32],
        }
    }

    #[test]
    fn export_import_roundtrip_preserves_password() {
        let mut a = temp_store();
        a.cache.sessions.push(Session {
            name: "pve".into(),
            host: "192.168.100.2".into(),
            port: 22,
            user: "root".into(),
            password: Secret::new("s3cr3t"),
            ..Session::new_empty()
        });

        let export_path = std::env::temp_dir().join(format!("ms-exp-{}.json", Uuid::new_v4()));
        assert_eq!(a.export_to(&export_path).unwrap(), 1);

        // The file keeps host/user plaintext but the password is obfuscated.
        let raw = std::fs::read_to_string(&export_path).unwrap();
        assert!(raw.contains("192.168.100.2"));
        assert!(raw.contains(ConfigStore::EXPORT_PREFIX));
        assert!(!raw.contains("s3cr3t"));

        // Importing into a fresh store recovers the plaintext password.
        let mut b = temp_store();
        assert_eq!(b.import_from(&export_path).unwrap(), (1, 0));
        assert_eq!(b.cache.sessions.len(), 1);
        assert_eq!(b.cache.sessions[0].password.as_str(), "s3cr3t");
        assert_eq!(b.cache.sessions[0].host, "192.168.100.2");

        // Re-importing the same file skips the duplicate.
        assert_eq!(b.import_from(&export_path).unwrap(), (0, 1));

        let _ = std::fs::remove_file(&export_path);
        let _ = std::fs::remove_file(&a.path);
        let _ = std::fs::remove_file(&b.path);
    }

    #[test]
    fn load_migrates_legacy_key_passphrase_from_password() {
        let key = [9u8; 32];
        let enc = ConfigStore::encrypt(&key, "legacy-pass").unwrap();
        let mut cfg = ConfigFile::default();
        cfg.sessions.push(Session {
            name: "legacy-key".into(),
            host: "10.0.0.8".into(),
            user: "root".into(),
            auth: AuthMethod::Key,
            password: Secret::new(enc),
            ..Session::new_empty()
        });
        for session in &mut cfg.sessions {
            if let Some(plain) = ConfigStore::try_decrypt(&key, session.password.as_str()) {
                session.password = Secret::new(plain);
            }
            if let Some(plain) = ConfigStore::try_decrypt(&key, session.key_passphrase.as_str()) {
                session.key_passphrase = Secret::new(plain);
            }
            if session.auth == AuthMethod::Key
                && session.key_passphrase.is_empty()
                && !session.password.is_empty()
            {
                session.key_passphrase = session.password.clone();
                session.password = Secret::default();
            }
        }

        assert_eq!(cfg.sessions.len(), 1);
        assert_eq!(cfg.sessions[0].password.as_str(), "");
        assert_eq!(cfg.sessions[0].key_passphrase.as_str(), "legacy-pass");
    }

    #[test]
    fn terminal_scrollback_lines_defaults_and_clamps() {
        let mut store = temp_store();

        assert_eq!(store.terminal_scrollback_lines(), 9_999);

        store.set_terminal_scrollback_lines(50);
        assert_eq!(store.terminal_scrollback_lines(), 100);

        store.set_terminal_scrollback_lines(500_000);
        assert_eq!(store.terminal_scrollback_lines(), 200_000);
    }

    #[test]
    fn session_flash_ms_defaults_and_clamps() {
        let mut store = temp_store();

        assert_eq!(store.session_flash_ms(), 1_000);

        store.set_session_flash_ms(50);
        assert_eq!(store.session_flash_ms(), 100);

        store.set_session_flash_ms(8_000);
        assert_eq!(store.session_flash_ms(), 5_000);
    }

    #[test]
    fn sftp_auto_refresh_secs_defaults_and_clamps() {
        let mut store = temp_store();

        assert_eq!(store.sftp_auto_refresh_secs(), 60);

        store.set_sftp_auto_refresh_secs(1);
        assert_eq!(store.sftp_auto_refresh_secs(), 10);

        store.set_sftp_auto_refresh_secs(9_999);
        assert_eq!(store.sftp_auto_refresh_secs(), 3_600);
    }

    #[test]
    fn editor_for_path_prefers_suffix_rules_and_falls_back() {
        let mut store = temp_store();
        store.set_external_editor("notepad.exe".into());
        store.upsert_external_editor_rule("py".into(), "code.exe".into());
        store.upsert_external_editor_rule(".xlsx".into(), "wps.exe".into());

        assert_eq!(store.editor_for_path("README"), Some("notepad.exe".into()));
        assert_eq!(store.editor_for_path("script.PY"), Some("code.exe".into()));
        assert_eq!(store.editor_for_path("report.xlsx"), Some("wps.exe".into()));
    }
}
