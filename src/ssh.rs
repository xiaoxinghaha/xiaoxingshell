//! SSH session manager.
//!
//! Each open terminal tab maps to exactly one `SshSession`. The session runs
//! on the shared Tokio runtime; commands come in via an MPSC channel and
//! output lines are pushed back via an `UnboundedSender<SessionEvent>`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use russh::client::{self, Handle, Handler, Msg};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::load_secret_key;
use russh::{Channel, ChannelId, ChannelMsg, Disconnect};
use ssh_key::{HashAlg, PublicKey};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::{AuthMethod, Session};
use crate::i18n::t;

// ---------------------------------------------------------------------------
// SFTP-related shared types
// ---------------------------------------------------------------------------

/// Metadata for a single remote filesystem entry returned by SFTP listing.
#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub full_path: String,
    pub is_dir: bool,
    pub file_type: String,
    /// Raw size in bytes (0 for directories or unknown).
    pub size: u64,
    /// Modification time as Unix timestamp (seconds, u32 = SFTP wire format).
    pub modified: u32,
    /// POSIX permission bits (the low 12, i.e. rwx + setuid/setgid/sticky).
    /// 0 when the server didn't report permissions. Used to prefill the chmod
    /// dialog (#84).
    pub mode: u32,
    pub mode_text: String,
    pub owner_group: String,
}

/// One node in the remote directory tree panel.
#[derive(Debug, Clone)]
pub struct RemoteTreeNode {
    pub path: String,
    pub name: String,
    pub depth: u32,
    pub expanded: bool,
    pub has_children: bool,
}

/// Format a byte count as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_024 * 1_024 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_024 * 1_024 * 1_024 {
        format!("{:.1} MB", bytes as f64 / (1_024.0 * 1_024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1_024.0 * 1_024.0 * 1_024.0))
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` in UTC+08:00.
pub fn format_mtime(ts: u32) -> String {
    use chrono::{DateTime, FixedOffset, TimeZone, Utc};
    let dt: DateTime<Utc> = Utc
        .timestamp_opt(ts as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    let east_8 = FixedOffset::east_opt(8 * 3600).expect("valid UTC+08:00 offset");
    dt.with_timezone(&east_8)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// The canonical ZMODEM abort sequence: eight CAN (0x18) then eight BS (0x08).
/// Sending this makes the remote `sz`/`rz` give up so the session recovers (#76).
const ZMODEM_CANCEL: [u8; 16] = [
    0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
];

/// Detect the start of a ZMODEM transfer (sz/rz) in a raw channel chunk.
///
/// Every ZMODEM frame begins with ZDLE (0x18) followed by a type byte; the
/// `sz` handshake leads with a ZRQINIT hex header (`**\x18B00...`). Matching
/// ZDLE followed by `B` (hex frame) or `C` (binary frame) reliably catches the
/// handshake without false-positiving on a lone 0x18 (Ctrl-X) in normal output.
fn contains_zmodem_init(data: &[u8]) -> bool {
    data.windows(2)
        .any(|w| w[0] == 0x18 && (w[1] == b'B' || w[1] == b'C'))
}

/// Extract the remote path from an OSC 7 sequence embedded in `text`.
///
/// Format: `ESC ] 7 ; file://hostname/path BEL`
/// Returns the decoded absolute path component (without hostname).
pub fn extract_osc7_path(text: &str) -> Option<String> {
    extract_osc7_end(text).map(|(path, _)| path)
}

/// SSH client defaults shared by the interactive shell and the dedicated SFTP
/// connection. Keepalives are important for long-lived idle SFTP browsing:
/// without them, NATs/servers can drop the quiet side-channel while the shell
/// tab still looks healthy.
pub fn client_config(keepalive_interval_secs: u32, disconnect_retry_count: u32) -> client::Config {
    let keepalive_interval_secs = keepalive_interval_secs.clamp(30, 3600);
    let disconnect_retry_count = disconnect_retry_count.clamp(1, 20);
    client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(60 * 60 * 2)),
        keepalive_interval: Some(std::time::Duration::from_secs(
            keepalive_interval_secs as u64,
        )),
        keepalive_max: disconnect_retry_count as usize,
        ..<_>::default()
    }
}

/// Like [`extract_osc7_path`] but also returns the byte index just past the OSC
/// sequence's terminator, so the caller can cut everything up to and including
/// it — used to discard the echoed setup line (which may wrap) at connect (#98).
fn extract_osc7_end(text: &str) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != 0x1b || bytes[i + 1] != b']' {
            i += 1;
            continue;
        }
        let osc_start = i + 2;
        i += 2;
        // Scan for BEL (0x07) or ST (ESC \)
        let mut end = i;
        let mut term_len = 0;
        while end < bytes.len() {
            if bytes[end] == 0x07 {
                term_len = 1;
                break;
            } else if bytes[end] == 0x1b && end + 1 < bytes.len() && bytes[end + 1] == b'\\' {
                term_len = 2;
                break;
            }
            end += 1;
        }
        if end >= bytes.len() {
            break;
        }
        if let Ok(content) = std::str::from_utf8(&bytes[osc_start..end]) {
            if let Some(rest) = content.strip_prefix("7;file://") {
                // rest = "hostname/path" or "/path" (empty hostname)
                let path = if rest.starts_with('/') {
                    rest.to_string()
                } else if let Some(slash) = rest.find('/') {
                    rest[slash..].to_string()
                } else {
                    "/".to_string()
                };
                return Some((url_decode(&path), end + term_len));
            }
        }
        i = end + term_len.max(1);
    }
    None
}

/// Find a meatshell command-capture sequence (`ESC ] 697 ; <command> BEL|ST`)
/// emitted by the shell hook (#113). Returns the command text and the byte
/// range of the whole escape sequence, so the caller can strip it before the
/// text is rendered. An incomplete sequence (terminator not yet received)
/// yields `None` — vt100 buffers it and the next chunk completes it.
pub fn extract_osc_command(text: &str) -> Option<(String, std::ops::Range<usize>)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != 0x1b || bytes[i + 1] != b']' {
            i += 1;
            continue;
        }
        let seq_start = i;
        let osc_start = i + 2;
        i += 2;
        // Scan for BEL (0x07) or ST (ESC \).
        let mut end = i;
        let mut term_len = 0;
        while end < bytes.len() {
            if bytes[end] == 0x07 {
                term_len = 1;
                break;
            } else if bytes[end] == 0x1b && end + 1 < bytes.len() && bytes[end + 1] == b'\\' {
                term_len = 2;
                break;
            }
            end += 1;
        }
        if end >= bytes.len() {
            break; // incomplete — leave it for the next chunk
        }
        if let Ok(content) = std::str::from_utf8(&bytes[osc_start..end]) {
            if let Some(cmd) = content.strip_prefix("697;") {
                return Some((cmd.to_string(), seq_start..end + term_len));
            }
        }
        i = end + term_len;
    }
    None
}

/// Percent-decode a URL path segment (e.g. `%20` → space).
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            match (h1, h2) {
                (Some(a), Some(b)) => {
                    let hex = format!("{a}{b}");
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push(a);
                        result.push(b);
                    }
                }
                (Some(a), None) => {
                    result.push('%');
                    result.push(a);
                }
                _ => result.push('%'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Commands posted to the worker task by the UI.
#[derive(Debug)]
pub enum SessionCommand {
    /// Send raw bytes directly to the PTY (individual keystrokes, no modification).
    RawInput(Vec<u8>),
    /// Notify the remote PTY of a terminal resize.
    Resize(u32, u32),
    /// Collect a one-shot read-only system overview over a separate exec channel.
    RunSystemInfo { request_id: String },
    /// Gracefully disconnect and drop the session.
    Close,
}

/// Carries the user's answer to a host-key confirmation prompt back to the
/// blocked `check_server_key` handler. Wrapped in `Arc<Mutex<Option<…>>>` so the
/// enclosing [`SessionEvent`] stays `Clone` (a bare `oneshot::Sender` is not);
/// the first `respond` consumes the sender, later calls are no-ops.
#[derive(Clone)]
pub struct HostKeyResponder(Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>);

impl HostKeyResponder {
    pub fn new(tx: tokio::sync::oneshot::Sender<bool>) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(tx))))
    }

    /// Deliver the user's decision (`true` = trust). Idempotent.
    pub fn respond(&self, accept: bool) {
        if let Ok(mut guard) = self.0.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(accept);
            }
        }
    }
}

impl std::fmt::Debug for HostKeyResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKeyResponder")
    }
}

/// The user's answer to a connect-time credential prompt: `(username, password,
/// remember)`, or `None` if they cancelled.
pub type CredentialReply = (String, String, bool);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialSecretKind {
    Password,
    KeyPassphrase,
}

/// Carries the credential prompt's answer back to the blocked auth flow (#110).
/// `Arc<Mutex<Option<…>>>` so the enclosing [`SessionEvent`] stays `Clone`.
#[derive(Clone)]
pub struct CredentialResponder(
    Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Option<CredentialReply>>>>>,
);

impl CredentialResponder {
    pub fn new(tx: tokio::sync::oneshot::Sender<Option<CredentialReply>>) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(tx))))
    }

    /// Deliver the user's answer (`None` = cancelled). Idempotent.
    pub fn respond(&self, reply: Option<CredentialReply>) {
        if let Ok(mut guard) = self.0.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(reply);
            }
        }
    }
}

impl std::fmt::Debug for CredentialResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialResponder")
    }
}

/// One process row sampled from the remote `ps` (#23). CPU/mem are percentages
/// as reported by `ps` (pcpu/pmem); `command` is the (width-truncated) args.
/// Events emitted back to the UI thread.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Free-form status text for the tab header / status line.
    Status(String),
    /// A chunk of stdout/stderr output from the remote shell.
    Output(String),
    /// Connection is up.
    Connected,
    /// Connection closed (either cleanly or after an error).
    Closed(String),
    /// The server presented a host key that is unknown or has changed; the UI
    /// must show a confirmation dialog and answer via `responder` (#109-5). The
    /// handler is blocked awaiting that answer.
    HostKeyPrompt {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
        /// True when a *different* key was previously stored (possible MITM).
        changed: bool,
        responder: HostKeyResponder,
    },
    /// The session is missing a username and/or connect-time secret (password or
    /// key passphrase); the UI must prompt for them and answer via `responder`.
    /// The auth flow is blocked meanwhile (#110).
    CredentialPrompt {
        session_id: String,
        host: String,
        user: String,
        need_user: bool,
        secret_kind: Option<CredentialSecretKind>,
        force_prompt: bool,
        responder: CredentialResponder,
    },
    /// Remote machine resource sample (from the monitor channel).
    /// Memory/swap are in KiB (as reported by /proc/meminfo).
    ResourceStats {
        cpu_percent: f32,
        mem_used_kib: u64,
        mem_total_kib: u64,
        swap_used_kib: u64,
        swap_total_kib: u64,
        /// Per-interface (name, rx_bytes_per_sec, tx_bytes_per_sec).
        net: Vec<(String, u64, u64)>,
        /// Per-filesystem (mount_point, available_bytes, total_bytes).
        disks: Vec<(String, u64, u64)>,
    },
    /// One-shot remote system overview for the "server info" tab.
    SystemInfo {
        request_id: String,
        content: String,
        error: String,
    },

    /// A command the user ran in the terminal, captured via the shell hook
    /// (OSC 697) so it can join the command-box history (#113).
    CommandRan(String),

    // --- SFTP events -------------------------------------------------------
    /// The shell's current working directory changed (parsed from OSC 7).
    CwdChanged(String),
    /// SFTP directory listing arrived.
    SftpEntries {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    /// Effective SFTP login user, used by the toolbar's sudo/root upload switch.
    SftpUser { user: String },
    /// Free-form SFTP status message (progress, errors, etc.).
    SftpStatus(String),
    /// A directory listing failed (e.g. permission denied): show the message and
    /// stop the panel's loading spinner without disturbing the current view (#112).
    SftpError(String),
    /// Directory tree structure changed (full rebuild pushed on every toggle).
    SftpTreeUpdate(Vec<RemoteTreeNode>),
    /// File-transfer progress / completion (download or upload).
    SftpTransfer {
        id: String,
        tab_id: String,
        name: String,
        is_upload: bool,
        local_path: String,
        remote_path: String,
        transferred: u64,
        total: u64,
        state: u8, // 0 = active, 1 = done, 2 = error
        msg: String,
        completed_at: Option<String>,
    },
    /// A remote text file loaded for the built-in viewer/editor (#70). On
    /// failure (too large, binary, non-UTF-8, I/O error) `error` is non-empty
    /// and `content` is empty.
    SftpFileText {
        path: String,
        name: String,
        content: String,
        edit: bool,
        error: String,
    },
}

/// Handle retained by the UI layer to talk to a running session.
pub struct SessionHandle {
    #[allow(dead_code)] // used by future resize / reconnect flows
    pub tab_id: String,
    pub commands: UnboundedSender<SessionCommand>,
    #[allow(dead_code)] // keep alive; detach on Drop is fine for v0.1
    pub join: JoinHandle<()>,
}

impl SessionHandle {
    pub fn send_raw(&self, bytes: Vec<u8>) {
        let _ = self.commands.send(SessionCommand::RawInput(bytes));
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.commands.send(SessionCommand::Resize(cols, rows));
    }

    pub fn system_info(&self, request_id: String) {
        let _ = self
            .commands
            .send(SessionCommand::RunSystemInfo { request_id });
    }

    pub fn close(&self) {
        let _ = self.commands.send(SessionCommand::Close);
    }
}

/// Entry point: spawn a session on the shared tokio runtime.
///
/// `initial_cols` / `initial_rows` are the PTY dimensions to request when
/// opening the channel. Slint fires a `terminal-resize` callback very shortly
/// after the tab becomes active; passing the best-known size here avoids the
/// remote shell starting at a stale 80×24 and sending an extra SIGWINCH.
///
/// Returns a [`SessionHandle`] for the UI + an [`UnboundedReceiver`] the UI
/// should drain on the Slint event loop.
pub fn spawn_session(
    runtime: &tokio::runtime::Handle,
    tab_id: String,
    session: Session,
    initial_cols: u32,
    initial_rows: u32,
    keepalive_interval_secs: u32,
    disconnect_retry_count: u32,
) -> (SessionHandle, UnboundedReceiver<SessionEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<SessionEvent>();

    let evt_tx_for_task = evt_tx.clone();
    let join = runtime.spawn(async move {
        if let Err(err) = run_session(
            session,
            cmd_rx,
            evt_tx_for_task.clone(),
            initial_cols,
            initial_rows,
            keepalive_interval_secs,
            disconnect_retry_count,
        )
        .await
        {
            tracing::warn!("ssh session ended with error: {err:#}");
            let _ = evt_tx_for_task.send(SessionEvent::Closed(format!("{err:#}")));
        }
    });

    (
        SessionHandle {
            tab_id,
            commands: cmd_tx,
            join,
        },
        evt_rx,
    )
}

async fn run_session(
    session: Session,
    mut commands: UnboundedReceiver<SessionCommand>,
    events: UnboundedSender<SessionEvent>,
    initial_cols: u32,
    initial_rows: u32,
    keepalive_interval_secs: u32,
    disconnect_retry_count: u32,
) -> Result<()> {
    let _ = events.send(SessionEvent::Status(format!(
        "{} {}@{}:{} ...",
        t("连接中", "Connecting"),
        session.user,
        session.host,
        session.port
    )));

    let config = Arc::new(client_config(
        keepalive_interval_secs,
        disconnect_retry_count,
    ));

    // Remote (-R) forwards are serviced inside the handler when the server
    // opens channels back, so it needs the bind-port → local-target map up
    // front (the handler is moved into `connect`) (#56).
    let remote_forwards: std::collections::HashMap<u32, (String, u16)> = session
        .forwards
        .iter()
        .filter(|f| f.kind == "remote")
        .map(|f| (f.bind_port as u32, (f.host.clone(), f.host_port)))
        .collect();
    let handler = ClientHandler {
        host: session.host.clone(),
        port: session.port,
        remote_forwards,
        events: events.clone(),
    };
    let addr = format!("{}:{}", session.host, session.port);
    // Connect directly, or tunnel through a SOCKS5 / HTTP proxy (issue #7).
    let mut handle = match crate::proxy::resolve(&session.proxy) {
        Some(p) => {
            let _ = events.send(SessionEvent::Status(format!(
                "{} {} → {}",
                t("经代理连接", "via proxy"),
                crate::proxy::describe(&p),
                addr
            )));
            let stream = crate::proxy::connect(&p, &session.host, session.port)
                .await
                .with_context(|| format!("proxy connect to {} failed", addr))?;
            client::connect_stream(config, stream, handler)
                .await
                .with_context(|| format!("connect {} failed", addr))?
        }
        None => client::connect(config, addr.as_str(), handler)
            .await
            .with_context(|| format!("connect {} failed", addr))?,
    };

    let mut user = session.user.trim().to_string();
    let password = if matches!(session.auth, AuthMethod::Password) {
        match resolve_credentials(&session, &events).await {
            Some((resolved_user, resolved_password)) => {
                user = resolved_user;
                resolved_password
            }
            None => {
                let _ = events.send(SessionEvent::Closed(
                    t("已取消登录", "login cancelled").into(),
                ));
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "cancelled", "")
                    .await;
                return Ok(());
            }
        }
    } else {
        String::new()
    };

    // --- Auth ----------------------------------------------------------
    let authed = match session.auth {
        AuthMethod::Password => {
            let mut current_user = user.clone();
            let mut current_password = password;
            let allow_user_retry = session.user.trim().is_empty();
            loop {
                let authed = handle
                    .authenticate_password(&current_user, current_password.as_str())
                    .await
                    .context("password auth failed")?;
                if authed {
                    user = current_user;
                    break true;
                }
                match reprompt_credentials(
                    &session,
                    &events,
                    current_user.clone(),
                    allow_user_retry,
                    Some(CredentialSecretKind::Password),
                )
                .await
                {
                    Some((u, p, _remember)) => {
                        if allow_user_retry {
                            current_user = u.trim().to_string();
                        }
                        current_password = p;
                    }
                    None => {
                        let _ = events.send(SessionEvent::Closed(
                            t("已取消登录", "login cancelled").into(),
                        ));
                        let _ = handle
                            .disconnect(Disconnect::ByApplication, "cancelled", "")
                            .await;
                        return Ok(());
                    }
                }
            }
        }
        AuthMethod::Key => {
            let Some((resolved_user, key_with_hash)) = resolve_key_auth(&session, &events).await?
            else {
                let _ = events.send(SessionEvent::Closed(
                    t("已取消登录", "login cancelled").into(),
                ));
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "cancelled", "")
                    .await;
                return Ok(());
            };
            user = resolved_user;
            handle
                .authenticate_publickey(&user, key_with_hash)
                .await
                .context("publickey auth failed")?
        }
    };

    if !authed {
        tracing::warn!("ssh authentication failed for {}@{}", user, session.host);
        let _ = events.send(SessionEvent::Closed(
            t("认证失败", "authentication failed").into(),
        ));
        let _ = handle
            .disconnect(Disconnect::ByApplication, "auth failed", "")
            .await;
        return Ok(());
    }

    // --- Shell channel --------------------------------------------------
    let mut channel = handle
        .channel_open_session()
        .await
        .context("open session channel")?;

    channel
        .request_pty(
            true,
            "xterm-256color",
            initial_cols,
            initial_rows,
            0,
            0,
            &[],
        )
        .await
        .context("request PTY")?;
    channel.request_shell(true).await.context("request shell")?;

    let _ = events.send(SessionEvent::Connected);
    let _ = events.send(SessionEvent::Status(format!(
        "{} {}@{}",
        t("已连接", "Connected"),
        session.user,
        session.host
    )));

    // Whether we have already injected the PROMPT_COMMAND setup.
    // We wait for the first non-empty data chunk (the initial shell prompt)
    // before sending so the command doesn't interleave with banner text.
    let mut prompt_injected = false;
    // True from injecting PROMPT_SETUP until the echoed setup line has been
    // received and stripped; output is buffered (not shown) during that window.
    let mut suppress_echo = false;
    // Keystrokes sent while the setup line is being echoed can appear before
    // the setup's OSC 7 marker and be swallowed with that echo. Queue them
    // until the hook is installed, then replay them in order.
    let mut pending_input_while_suppress: Vec<u8> = Vec::new();
    // Buffers output while `suppress_echo` so the (long) echoed setup line can be
    // stripped even when it splits across reads (#98).
    let mut echo_buf = String::new();
    // After a ZMODEM transfer finishes we briefly ignore ZMODEM detection so the
    // sender's lingering close frames can't spawn a spurious second receive (#76).
    let mut zmodem_done_at: Option<std::time::Instant> = None;

    // Cwd-notification (OSC 7) setup, injected once after the first prompt so
    // the SFTP panel can follow `cd` (#91). It must work across shells:
    //   • bash/sh  → PROMPT_COMMAND runs `__ms7` before every prompt.
    //   • zsh      → bash's PROMPT_COMMAND is IGNORED by zsh, so we register a
    //                `precmd` hook via `add-zsh-hook` instead (non-destructive —
    //                it preserves oh-my-zsh / p10k hooks, unlike `precmd(){…}`).
    //   • fish     → guarded out (fish 3.1+ emits OSC 7 itself).
    // `__ms7` is called once at the end so the initial cwd arrives immediately.
    //
    // The whole shell-specific body lives inside `eval '…'`: fish can't parse
    // bash/zsh function & `if` syntax, but it CAN parse `eval '<opaque string>'`,
    // and the `test -z "$FISH_VERSION" &&` guard short-circuits before the eval
    // ever runs under fish (#71). The body uses only double quotes inside so the
    // outer single-quoted string needs no escaping; printf turns \033/\007 into
    // ESC/BEL at prompt time. No array syntax → safe to *parse* in dash/ash too.
    //
    // The leading space keeps the line out of shell history when HISTCONTROL=
    // ignorespace is enabled. Some root/server profiles don't enable it, so
    // bash also deletes the last history entry after the line has been accepted.
    // Its echo is stripped locally (the needle below), so the bookkeeping
    // command never shows up.
    //
    // Besides OSC 7 (cwd), the hook also captures the command the user just ran
    // and reports it via a private `OSC 697 ; <cmd> BEL` so it can join the
    // command-box history (#113) — terminal-typed commands aren't otherwise
    // recorded. `__msc` reads the last history entry with `fc -ln -1`; this only
    // ever sees real executed commands, never password prompts (those use
    // `read -s` and aren't shell commands). `__cl` remembers the last reported
    // command so a redrawn prompt (e.g. Enter on an empty line) doesn't re-emit
    // it, and is primed once up front so the pre-session history isn't replayed.
    //
    // The echoed setup line is discarded by anchoring on the OSC 7 it produces
    // (see the suppress block below), so it doesn't matter that the long line
    // wraps — we never substring-match it.
    const PROMPT_BODY: &str = "test -z \"$FISH_VERSION\" && eval '__msc(){ __c=\"$(fc -ln -1 2>/dev/null)\"; [ -n \"$__c\" ] && [ \"$__c\" != \"$__cl\" ] && { __cl=\"$__c\"; printf \"\\033]697;%s\\007\" \"$__c\"; }; }; __ms7(){ __msc; printf \"\\033]7;file://%s%s\\007\" \"$HOSTNAME\" \"$PWD\"; }; __h=\"$(history 1 2>/dev/null)\"; __h=\"${__h#\"${__h%%[! ]*}\"}\"; __h=\"${__h%%[!0-9]*}\"; [ -n \"$BASH_VERSION\" ] && [ -n \"$__h\" ] && history -d \"$__h\" 2>/dev/null; unset __h; __cl=\"$(fc -ln -1 2>/dev/null)\"; if [ -n \"$ZSH_VERSION\" ]; then autoload -Uz add-zsh-hook 2>/dev/null; add-zsh-hook precmd __ms7; else PROMPT_COMMAND=\"__ms7${PROMPT_COMMAND:+;$PROMPT_COMMAND}\"; fi; __ms7'";
    let prompt_setup = format!(" {}\r", PROMPT_BODY);

    // --- Remote resource monitor (separate exec channel) ----------------
    // A tiny remote loop streams /proc/stat + /proc/meminfo every 2s; we parse
    // it into CPU% / mem / swap for the sidebar.  Best-effort: if the channel
    // or exec fails (e.g. a non-Linux host without /proc), monitoring is
    // silently skipped and the interactive shell is unaffected.
    // Reset PATH to the standard system directories first (#27): the monitor
    // runs over an exec channel, so a server with a hijacked PATH (or a
    // BASH_ENV pointing at a malicious file) could otherwise shadow awk/cat/df/
    // sleep with arbitrary binaries. A fixed PATH covering /usr/bin and /bin is
    // more portable than hardcoding one absolute path per tool (their location
    // differs across distros). Monitoring is best-effort, so even if this shell
    // is unusual and the reset finds nothing, only the sidebar stats are lost.
    const MON_CMD: &[u8] = b"PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; while :; do awk '/^cpu /{print}' /proc/stat; awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/{print}' /proc/meminfo; cat /proc/net/dev; echo __DF__; df -kP 2>/dev/null; echo __MSTICK__; sleep 2; done\n";
    let mut mon_channel = match handle.channel_open_session().await {
        Ok(ch) => match ch.exec(true, MON_CMD).await {
            Ok(()) => Some(ch),
            Err(e) => {
                tracing::warn!("monitor exec failed: {e}");
                None
            }
        },
        Err(e) => {
            tracing::warn!("monitor channel open failed: {e}");
            None
        }
    };
    let mut mon_buf = String::new();
    let mut prev_cpu: Option<(u64, u64)> = None; // (total jiffies, idle jiffies)
    let mut prev_net: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new(); // iface -> (rx_bytes, tx_bytes)
    let mut prev_net_at = std::time::Instant::now();

    // --- Port forwarding / tunnels (#56) --------------------------------
    // Remote (-R) first, while we still hold `handle` mutably (tcpip_forward
    // takes &mut self); the server then opens channels back, serviced in the
    // handler. Then wrap the handle in an Arc so the local/dynamic listener
    // tasks can share it (russh's Handle isn't Clone, but its methods are &self).
    for f in session.forwards.iter().filter(|f| f.kind == "remote") {
        let bind = if f.bind_addr.trim().is_empty() {
            "127.0.0.1".to_string()
        } else {
            f.bind_addr.trim().to_string()
        };
        match handle.tcpip_forward(bind.clone(), f.bind_port as u32).await {
            Ok(_) => {
                let _ = events.send(SessionEvent::Output(format!(
                    "\r\n[meatshell] -R {bind}:{} → {}:{}\r\n",
                    f.bind_port, f.host, f.host_port
                )));
            }
            Err(e) => {
                let _ = events.send(SessionEvent::Output(format!(
                    "\r\n[meatshell] -R {bind}:{} 请求失败 / request failed: {e}\r\n",
                    f.bind_port
                )));
            }
        }
    }
    let handle = Arc::new(handle);
    // Local (-L) and dynamic (-D) listen client-side; their tasks are aborted
    // on session exit.
    let mut forward_tasks: Vec<JoinHandle<()>> = Vec::new();
    for f in &session.forwards {
        match f.kind.as_str() {
            "local" => forward_tasks.push(crate::forward::spawn_local(
                handle.clone(),
                f.bind_addr.clone(),
                f.bind_port,
                f.host.clone(),
                f.host_port,
                events.clone(),
            )),
            "dynamic" => forward_tasks.push(crate::forward::spawn_dynamic(
                handle.clone(),
                f.bind_addr.clone(),
                f.bind_port,
                events.clone(),
            )),
            _ => {}
        }
    }

    // --- Main pump ------------------------------------------------------
    loop {
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(SessionCommand::RawInput(bytes)) => {
                        // Only log the byte count — never the bytes themselves,
                        // which are raw keystrokes and may contain passwords (#15).
                        tracing::debug!("ssh channel.data len={} bytes", bytes.len());
                        if suppress_echo {
                            pending_input_while_suppress.extend_from_slice(&bytes);
                            continue;
                        }
                        if let Err(err) = channel.data(&bytes[..]).await {
                            let _ = events.send(SessionEvent::Closed(format!("{}: {err}", t("写入失败", "write failed"))));
                            break;
                        }
                    }
                    Some(SessionCommand::Resize(cols, rows)) => {
                        let _ = channel.window_change(cols, rows, 0, 0).await;
                    }
                    Some(SessionCommand::RunSystemInfo { request_id }) => {
                        let handle = handle.clone();
                        let events = events.clone();
                        tokio::spawn(async move {
                            let (content, error) = match collect_system_info(&handle).await {
                                Ok(text) => (text, String::new()),
                                Err(err) => (String::new(), err.to_string()),
                            };
                            let _ = events.send(SessionEvent::SystemInfo {
                                request_id,
                                content,
                                error,
                            });
                        });
                    }
                    Some(SessionCommand::Close) | None => {
                        let _ = channel.eof().await;
                        break;
                    }
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        // A `sz` in the terminal starts a ZMODEM send. Receive it
                        // straight to the Downloads dir (FinalShell style, #76).
                        // On any protocol error, cancel so the session recovers.
                        let zmodem_cooldown = zmodem_done_at
                            .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(2));
                        if !zmodem_cooldown && contains_zmodem_init(&data) {
                            let result =
                                crate::zmodem::receive(&mut channel, &data, &events).await;
                            zmodem_done_at = Some(std::time::Instant::now());
                            match result {
                                Ok(leftover) => {
                                    // Bytes after the transfer (the shell prompt):
                                    // run them through the normal output path so
                                    // the prompt shows and the cwd updates.
                                    if !leftover.is_empty() {
                                        let text =
                                            String::from_utf8_lossy(&leftover).into_owned();
                                        if let Some(cwd) = extract_osc7_path(&text) {
                                            let _ =
                                                events.send(SessionEvent::CwdChanged(cwd));
                                        }
                                        let _ = events.send(SessionEvent::Output(text));
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("zmodem receive failed: {e:#}");
                                    let _ = channel.data(&ZMODEM_CANCEL[..]).await;
                                    let _ = events.send(SessionEvent::Output(format!(
                                        "\r\n[meatshell] {}: {e}\r\n",
                                        t("ZMODEM 接收失败,已取消", "ZMODEM receive failed; cancelled")
                                    ).into()));
                                }
                            }
                            continue;
                        }

                        let chunk = String::from_utf8_lossy(&data).into_owned();

                        // Inject PROMPT_COMMAND after the first real shell output.
                        if !prompt_injected && !chunk.trim().is_empty() {
                            prompt_injected = true;
                            suppress_echo = true;
                            let _ = channel.data(prompt_setup.as_bytes()).await;
                            // Fall through: this chunk is buffered below so the
                            // echoed setup line is stripped as a single piece.
                        }

                        // While suppressing, buffer output until the injected
                        // __ms7 prints its OSC 7 (it runs right after the setup
                        // line is echoed and executed), then discard everything up
                        // to and including that OSC 7 — the echoed setup line (which
                        // may WRAP across the terminal width, so substring-matching
                        // it is unreliable) plus the pre-injection prompt. Whatever
                        // follows the OSC 7 is the fresh prompt, which we keep (#98).
                        // A size cap is the safety valve for a shell that never
                        // reports back (e.g. dash without PROMPT_COMMAND).
                        let mut flush_pending_input = false;
                        let mut text = if suppress_echo {
                            echo_buf.push_str(&chunk);
                            const ECHO_BUF_CAP: usize = 1 << 14; // 16 KiB
                            if let Some((cwd, seq_end)) = extract_osc7_end(&echo_buf) {
                                suppress_echo = false;
                                flush_pending_input = true;
                                tracing::debug!("OSC7 cwd={:?}", cwd);
                                let _ = events.send(SessionEvent::CwdChanged(cwd));
                                let rest = echo_buf[seq_end..].to_string();
                                echo_buf.clear();
                                rest
                            } else if echo_buf.len() >= ECHO_BUF_CAP {
                                suppress_echo = false;
                                flush_pending_input = true;
                                std::mem::take(&mut echo_buf)
                            } else {
                                continue; // keep buffering; show nothing yet
                            }
                        } else {
                            chunk
                        };

                        // Capture commands run in the terminal via our OSC 697
                        // hook, and strip the sequence so it never reaches the
                        // renderer (#113). Skip our own injected setup line in the
                        // rare case HISTCONTROL=ignorespace isn't in effect.
                        while let Some((cmd, range)) = extract_osc_command(&text) {
                            text.replace_range(range, "");
                            let cmd = cmd.trim();
                            if !cmd.is_empty() && !cmd.contains("__ms7") {
                                let _ = events.send(SessionEvent::CommandRan(cmd.to_string()));
                            }
                        }

                        // Scan after command capture so prompt hooks that emit
                        // both OSC 697 and OSC 7 let the UI decide cd-follow
                        // using the command that caused this prompt.
                        if let Some(cwd) = extract_osc7_path(&text) {
                            tracing::debug!("OSC7 cwd={:?}", cwd);
                            let _ = events.send(SessionEvent::CwdChanged(cwd));
                        }

                        let _ = events.send(SessionEvent::Output(text));
                        if flush_pending_input && !pending_input_while_suppress.is_empty() {
                            let queued = std::mem::take(&mut pending_input_while_suppress);
                            if let Err(err) = channel.data(&queued[..]).await {
                                let _ = events.send(SessionEvent::Closed(format!("{}: {err}", t("写入失败", "write failed"))));
                                break;
                            }
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: _ }) => {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        let _ = events.send(SessionEvent::Output(text));
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = events.send(SessionEvent::Status(
                            format!("{} (code {exit_status})", t("远程进程退出", "remote process exited")),
                        ));
                    }
                    Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            // Remote resource monitor channel.  The `async { ... }` lets us poll
            // an Option<Channel>: once the monitor channel closes we replace it
            // with `pending()` so this arm simply never fires again.
            mon = async {
                match mon_channel.as_mut() {
                    Some(ch) => ch.wait().await,
                    None => std::future::pending().await,
                }
            } => {
                match mon {
                    Some(ChannelMsg::Data { data }) => {
                        mon_buf.push_str(&String::from_utf8_lossy(&data));
                        // Process every complete sample terminated by the marker.
                        while let Some(idx) = mon_buf.find("__MSTICK__") {
                            let block = mon_buf[..idx].to_string();
                            let rest = mon_buf[idx + "__MSTICK__".len()..]
                                .trim_start_matches(['\r', '\n'])
                                .to_string();
                            mon_buf = rest;
                            if let Some(stats) = parse_monitor_block(
                                &block,
                                &mut prev_cpu,
                                &mut prev_net,
                                &mut prev_net_at,
                            ) {
                                let _ = events.send(stats);
                            }
                        }
                        // Bound the leftover (incomplete) tail: a server that
                        // streams data but never emits the __MSTICK__ marker must
                        // not grow this buffer without limit (memory DoS, #27).
                        // A real sample is a few KiB; 1 MiB is a generous ceiling.
                        const MON_BUF_CAP: usize = 1 << 20;
                        if mon_buf.len() > MON_BUF_CAP {
                            mon_buf.clear();
                        }
                    }
                    Some(ChannelMsg::Close) | None => {
                        mon_channel = None;
                    }
                    _ => {}
                }
            }
        }
    }

    // Tear down any port-forward listeners (#56); -R forwards die with the
    // session's disconnect below.
    for task in forward_tasks {
        task.abort();
    }

    let _ = handle
        .disconnect(Disconnect::ByApplication, "bye", "")
        .await;
    // The shell pump loop only exits when the channel closes / EOFs (incl. a
    // peer/bastion-initiated disconnect), so record it for #86 diagnostics.
    tracing::warn!("ssh connection closed ({}@{})", session.user, session.host);
    let _ = events.send(SessionEvent::Closed(
        t("连接已关闭", "connection closed").into(),
    ));
    Ok(())
}

async fn collect_system_info(handle: &Handle<ClientHandler>) -> Result<String> {
    const CMD: &str = r#"PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
printf '===== Basic =====\n'
printf 'User: '; whoami 2>/dev/null || true
printf 'Host: '; hostname 2>/dev/null || true
printf 'Kernel: '; uname -a 2>/dev/null || true
printf 'Uptime: '; (uptime -p 2>/dev/null || uptime 2>/dev/null || true)
printf '\n===== CPU =====\n'
(lscpu 2>/dev/null | sed -n '1,12p') || (grep -m1 'model name' /proc/cpuinfo 2>/dev/null; grep -c '^processor' /proc/cpuinfo 2>/dev/null)
printf '\n===== Memory =====\n'
free -h 2>/dev/null || sed -n '1,8p' /proc/meminfo 2>/dev/null
printf '\n===== Disk =====\n'
df -hT 2>/dev/null | sed -n '1,12p'
printf '\n===== Network =====\n'
(ip -brief addr 2>/dev/null || ifconfig 2>/dev/null || true) | sed -n '1,20p'
printf '\n===== Login =====\n'
(last -n 5 2>/dev/null || who 2>/dev/null || true)
"#;
    let mut channel = handle
        .channel_open_session()
        .await
        .context("open system info channel")?;
    channel
        .exec(true, CMD.as_bytes())
        .await
        .context("start system info command")?;

    let mut output = String::new();
    let mut stderr = String::new();
    let mut exit_status: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => output.push_str(&String::from_utf8_lossy(&data)),
            ChannelMsg::ExtendedData { data, ext: _ } => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    match exit_status {
        Some(0) => Ok(output),
        Some(code) => {
            if output.trim().is_empty() {
                Err(anyhow!(
                    "system info command exited {code}: {}",
                    stderr.trim()
                ))
            } else {
                Ok(format!(
                    "{output}\n[meatshell] system info command exited {code}: {}",
                    stderr.trim()
                ))
            }
        }
        None => {
            if output.trim().is_empty() {
                Err(anyhow!(
                    "system info command failed: no exit status received"
                ))
            } else {
                Ok(output)
            }
        }
    }
}

/// Parse one monitor sample (a block of `/proc/stat` cpu line + `/proc/meminfo`
/// fields) into a [`SessionEvent::ResourceStats`].
///
/// CPU usage needs two consecutive `/proc/stat` snapshots; `prev` carries the
/// previous (total, idle) jiffies across calls.  The first sample therefore
/// reports 0% (no baseline yet).
fn parse_monitor_block(
    block: &str,
    prev: &mut Option<(u64, u64)>,
    prev_net: &mut std::collections::HashMap<String, (u64, u64)>,
    prev_net_at: &mut std::time::Instant,
) -> Option<SessionEvent> {
    let mut cpu_total = 0u64;
    let mut cpu_idle = 0u64;
    let mut have_cpu = false;
    let mut mem_total = 0u64;
    let mut mem_avail = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    // Raw /proc/net/dev counters this sample: iface -> (rx_bytes, tx_bytes).
    let mut net_now: Vec<(String, u64, u64)> = Vec::new();
    // Filesystems from `df -kP`: (mount, available_bytes, total_bytes).
    let mut disks: Vec<(String, u64, u64)> = Vec::new();
    // The sample is split into sections by `echo` markers; everything before the
    // first marker is the cpu/mem/net block.
    enum Section {
        Top,
        Df,
    }
    let mut section = Section::Top;

    // Cap how many interfaces / filesystems / processes we accept from one sample
    // so a hostile server can't flood the parser and sidebar with fabricated rows
    // (#27). No real machine has anywhere near this many.
    const MAX_MON_ENTRIES: usize = 64;

    for line in block.lines() {
        if line == "__DF__" {
            section = Section::Df;
            continue;
        }
        match section {
            Section::Df => {
                if disks.len() < MAX_MON_ENTRIES {
                    if let Some(d) = parse_df_line(line) {
                        disks.push(d);
                    }
                }
                continue;
            }
            Section::Top => {}
        }
        if let Some(rest) = line.strip_prefix("cpu ") {
            let nums: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            // user nice system idle iowait irq softirq steal ...
            if nums.len() >= 4 {
                // Saturating arithmetic: a server can send arbitrary jiffy
                // values, and a plain sum/add would panic on overflow in debug.
                cpu_total = nums.iter().copied().fold(0u64, u64::saturating_add);
                cpu_idle = nums[3].saturating_add(nums.get(4).copied().unwrap_or(0)); // idle + iowait
                have_cpu = true;
            }
        } else if let Some(v) = line.strip_prefix("MemTotal:") {
            mem_total = parse_meminfo_kib(v);
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            mem_avail = parse_meminfo_kib(v);
        } else if let Some(v) = line.strip_prefix("SwapTotal:") {
            swap_total = parse_meminfo_kib(v);
        } else if let Some(v) = line.strip_prefix("SwapFree:") {
            swap_free = parse_meminfo_kib(v);
        } else if net_now.len() < MAX_MON_ENTRIES {
            if let Some((iface, counters)) = parse_net_dev_line(line) {
                net_now.push((iface, counters.0, counters.1));
            }
        }
    }

    // Convert raw byte counters into per-second rates using the previous sample.
    let now = std::time::Instant::now();
    let elapsed = now.duration_since(*prev_net_at).as_secs_f64().max(0.001);
    let mut net: Vec<(String, u64, u64)> = Vec::new();
    if !net_now.is_empty() {
        for (iface, rx, tx) in &net_now {
            if let Some((prx, ptx)) = prev_net.get(iface) {
                let rx_bps = (rx.saturating_sub(*prx) as f64 / elapsed) as u64;
                let tx_bps = (tx.saturating_sub(*ptx) as f64 / elapsed) as u64;
                net.push((iface.clone(), rx_bps, tx_bps));
            }
        }
        prev_net.clear();
        for (iface, rx, tx) in net_now {
            prev_net.insert(iface, (rx, tx));
        }
        *prev_net_at = now;
        // Show busiest first so the default-selected NIC is the active one.
        net.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
    }

    let cpu_percent = if have_cpu {
        let result = match *prev {
            Some((ptotal, pidle)) => {
                let dt = cpu_total.saturating_sub(ptotal);
                let di = cpu_idle.saturating_sub(pidle);
                if dt > 0 {
                    (1.0 - di as f32 / dt as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        *prev = Some((cpu_total, cpu_idle));
        result
    } else {
        0.0
    };

    // Need at least memory numbers to be a useful sample.
    if mem_total == 0 {
        return None;
    }

    Some(SessionEvent::ResourceStats {
        cpu_percent,
        mem_used_kib: mem_total.saturating_sub(mem_avail),
        mem_total_kib: mem_total,
        swap_used_kib: swap_total.saturating_sub(swap_free),
        swap_total_kib: swap_total,
        net,
        disks,
    })
}

/// Parse one `df -kP` data line into `(mount, available_bytes, total_bytes)`.
/// Columns: `Filesystem 1024-blocks Used Available Capacity Mounted-on`.
fn parse_df_line(line: &str) -> Option<(String, u64, u64)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 6 || f[0] == "Filesystem" {
        return None;
    }
    let total_kb: u64 = f[1].parse().ok()?;
    let avail_kb: u64 = f[3].parse().ok()?;
    if total_kb == 0 {
        return None;
    }
    // Mount point is the last column (joined in case it contains spaces).
    let mount = f[5..].join(" ");
    // Saturating: a server can report arbitrary block counts; KiB→bytes must
    // not overflow-panic in debug (#27).
    Some((
        mount,
        avail_kb.saturating_mul(1024),
        total_kb.saturating_mul(1024),
    ))
}

/// Extract the leading integer (KiB) from a `/proc/meminfo` value like
/// `"  3288560 kB"`.
fn parse_meminfo_kib(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

/// Parse one `/proc/net/dev` data line into `(iface, (rx_bytes, tx_bytes))`.
/// Format: `  eth0: <rx_bytes> <rx_pkts> ... <tx_bytes> <tx_pkts> ...`
/// (16 numeric columns; rx_bytes is col 0, tx_bytes is col 8).  The `lo`
/// loopback interface is skipped — it never reflects real traffic.
fn parse_net_dev_line(line: &str) -> Option<(String, (u64, u64))> {
    let (name, rest) = line.split_once(':')?;
    let iface = name.trim();
    if iface.is_empty() || iface == "lo" || iface.contains(' ') {
        return None;
    }
    let nums: Vec<u64> = rest
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    if nums.len() < 9 {
        return None;
    }
    Some((iface.to_string(), (nums[0], nums[8])))
}

/// Client handler. Verifies the server host key against the known_hosts store,
/// prompting the user on first contact / on a changed key (#109-5).
///
/// Carries the remote-forward (-R) map so we can service channels the server
/// opens back to us: server bind-port → local `(host, port)` target (#56).
pub(crate) struct ClientHandler {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) remote_forwards: std::collections::HashMap<u32, (String, u16)>,
    pub(crate) events: UnboundedSender<SessionEvent>,
}

/// Shared host-key check used by both the shell and SFTP connections: trust a
/// matching stored key silently; otherwise ask the UI (via `events`) and, on
/// acceptance, remember the key. A dropped/closed reply channel (UI gone)
/// counts as a rejection so we never connect to an unverified host.
pub(crate) async fn verify_host_key(
    host: &str,
    port: u16,
    key: &PublicKey,
    events: &UnboundedSender<SessionEvent>,
) -> bool {
    use crate::known_hosts::HostKeyStatus;
    match crate::known_hosts::verify(host, port, key) {
        HostKeyStatus::Match => true,
        status => {
            let changed = status == HostKeyStatus::Changed;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = events.send(SessionEvent::HostKeyPrompt {
                host: host.to_string(),
                port,
                key_type: key.algorithm().to_string(),
                fingerprint: crate::known_hosts::fingerprint(key),
                changed,
                responder: HostKeyResponder::new(tx),
            });
            if sent.is_err() {
                return false; // no UI to ask
            }
            match rx.await {
                Ok(true) => {
                    if let Err(e) = crate::known_hosts::remember(host, port, key) {
                        tracing::warn!("could not save host key for {host}:{port}: {e:#}");
                    }
                    true
                }
                _ => false,
            }
        }
    }
}

/// Resolve a session's username/password, prompting the UI for whatever is
/// missing (#110). Returns the effective `(user, password)`, or `None` if the
/// user cancelled. Both the shell and SFTP connections call this; the UI
/// de-duplicates by session id so a single dialog serves both. A dropped reply
/// channel (no UI) falls through with the stored values so auth fails normally.
async fn prompt_for_credentials(
    session: &Session,
    events: &UnboundedSender<SessionEvent>,
    user: String,
    need_user: bool,
    secret_kind: Option<CredentialSecretKind>,
    force_prompt: bool,
) -> Option<CredentialReply> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let sent = events.send(SessionEvent::CredentialPrompt {
        session_id: session.id.clone(),
        host: session.host.clone(),
        user: user.clone(),
        need_user,
        secret_kind,
        force_prompt,
        responder: CredentialResponder::new(tx),
    });
    if sent.is_err() {
        return Some((user, String::new(), false));
    }
    rx.await.ok().flatten()
}

pub(crate) async fn resolve_credentials(
    session: &Session,
    events: &UnboundedSender<SessionEvent>,
) -> Option<(String, String)> {
    let mut user = session.user.trim().to_string();
    let mut password = session.password.as_str().to_string();
    let need_user = user.is_empty();
    let secret_kind = if matches!(session.auth, AuthMethod::Password) && password.is_empty() {
        Some(CredentialSecretKind::Password)
    } else {
        None
    };
    if !(need_user || secret_kind.is_some()) {
        return Some((user, password));
    }
    match prompt_for_credentials(session, events, user.clone(), need_user, secret_kind, false).await
    {
        Some((u, p, _remember)) => {
            if need_user {
                user = u.trim().to_string();
            }
            if secret_kind.is_some() {
                password = p;
            }
            Some((user, password))
        }
        _ => None,
    }
}

pub(crate) async fn reprompt_credentials(
    session: &Session,
    events: &UnboundedSender<SessionEvent>,
    user: String,
    need_user: bool,
    secret_kind: Option<CredentialSecretKind>,
) -> Option<CredentialReply> {
    prompt_for_credentials(session, events, user, need_user, secret_kind, true).await
}

fn key_load_error_needs_passphrase(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}").to_ascii_lowercase();
    msg.contains("encrypted")
        || (msg.contains("passphrase") && (msg.contains("required") || msg.contains("missing")))
        || msg.contains("cryptographic error")
}

pub(crate) async fn resolve_key_auth(
    session: &Session,
    events: &UnboundedSender<SessionEvent>,
) -> Result<Option<(String, PrivateKeyWithHashAlg)>> {
    let mut user = session.user.trim().to_string();
    if user.is_empty() {
        match prompt_for_credentials(session, events, user.clone(), true, None, false).await {
            Some((u, _secret, _remember)) => user = u.trim().to_string(),
            None => return Ok(None),
        }
    }

    let raw = session.private_key_path.trim();
    if raw.is_empty() {
        return Err(anyhow!(t("私钥路径为空", "private key path is empty")));
    }
    let normalised = raw.replace('\\', "/");
    let key_path = normalised
        .strip_suffix(".pub")
        .map(str::to_string)
        .unwrap_or(normalised);

    let load_key = |pass: Option<&str>| -> Result<PrivateKeyWithHashAlg> {
        let keypair = load_secret_key(Path::new(&key_path), pass)
            .with_context(|| format!("failed to load key {key_path}"))?;
        let hash = keypair.algorithm().is_rsa().then_some(HashAlg::Sha256);
        PrivateKeyWithHashAlg::new(Arc::new(keypair), hash).context("invalid private key")
    };

    let stored_pass = session.key_passphrase.as_str();
    let mut current_pass = if stored_pass.is_empty() {
        None
    } else {
        Some(stored_pass.to_string())
    };
    let mut force_prompt = false;
    loop {
        match load_key(current_pass.as_deref()) {
            Ok(key) => return Ok(Some((user, key))),
            Err(err) if key_load_error_needs_passphrase(&err) => {
                let reply = prompt_for_credentials(
                    session,
                    events,
                    user.clone(),
                    false,
                    Some(CredentialSecretKind::KeyPassphrase),
                    force_prompt,
                )
                .await;
                match reply {
                    Some((_u, secret, _remember)) => {
                        current_pass = Some(secret);
                        force_prompt = true;
                    }
                    None => return Ok(None),
                }
            }
            Err(err) => return Err(err),
        }
    }
}

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(verify_host_key(&self.host, self.port, server_public_key, &self.events).await)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Remote forward (-R): the server opened a channel for a connection that
    /// arrived on a port we asked it to listen on. Connect to the configured
    /// local target and splice the two together (#56).
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote_forwards.get(&connected_port).cloned();
        let events = self.events.clone();
        let bind = connected_address.to_string();
        tokio::spawn(async move {
            let Some((host, port)) = target else {
                tracing::warn!("forwarded-tcpip on {bind}:{connected_port} with no mapping");
                return;
            };
            match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(mut tcp) => {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                }
                Err(e) => {
                    let _ = events.send(SessionEvent::Output(format!(
                        "\r\n[meatshell] -R {host}:{port} 连接失败 / connect failed: {e}\r\n"
                    )));
                }
            }
        });
        Ok(())
    }
}

// Marker trait impl so `Arc<Handle<Handler>>` is nameable in external code.
#[allow(dead_code)]
fn _assert_handle_send() {
    fn takes<T: Send>() {}
    takes::<Handle<ClientHandler>>();
}

#[cfg(test)]
mod osc_command_tests {
    use super::extract_osc_command;

    #[test]
    fn extracts_and_locates_bel_terminated() {
        let text = "before\u{1b}]697;ls -la\u{07}after";
        let (cmd, range) = extract_osc_command(text).expect("found");
        assert_eq!(cmd, "ls -la");
        // Stripping the range leaves the surrounding text intact.
        let mut s = text.to_string();
        s.replace_range(range, "");
        assert_eq!(s, "beforeafter");
    }

    #[test]
    fn extracts_st_terminated() {
        let text = "\u{1b}]697;echo hi\u{1b}\\";
        let (cmd, _) = extract_osc_command(text).expect("found");
        assert_eq!(cmd, "echo hi");
    }

    #[test]
    fn ignores_other_osc_and_incomplete() {
        // OSC 7 (cwd) is not a command sequence.
        assert!(extract_osc_command("\u{1b}]7;file:///home\u{07}").is_none());
        // No terminator yet → wait for more.
        assert!(extract_osc_command("\u{1b}]697;ls").is_none());
        assert!(extract_osc_command("plain text").is_none());
    }
}

#[cfg(test)]
mod monitor_hardening_tests {
    use super::{parse_df_line, parse_monitor_block};
    use std::collections::HashMap;
    use std::time::Instant;

    #[test]
    fn df_line_saturates_instead_of_overflowing() {
        // avail/total near u64::MAX must not panic on the KiB->bytes multiply.
        let line = "/dev/sda1 18446744073709551615 0 18446744073709551615 100% /";
        let (_, avail, total) = parse_df_line(line).expect("parses");
        assert_eq!(avail, u64::MAX);
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn cpu_overflow_values_do_not_panic() {
        let big = u64::MAX;
        let block =
            format!("cpu {big} {big} {big} {big} {big}\nMemTotal: 1000 kB\nMemAvailable: 500 kB");
        let mut prev = None;
        let mut prev_net = HashMap::new();
        let mut at = Instant::now();
        // Must not panic; with no baseline the first sample reports 0% CPU.
        assert!(parse_monitor_block(&block, &mut prev, &mut prev_net, &mut at).is_some());
    }

    #[test]
    fn floods_of_fake_interfaces_are_capped() {
        let mut block = String::from("MemTotal: 1000 kB\nMemAvailable: 500 kB\n");
        for i in 0..500 {
            block.push_str(&format!("eth{i}: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n"));
        }
        let mut prev = None;
        let mut prev_net = HashMap::new();
        let mut at = Instant::now();
        assert!(parse_monitor_block(&block, &mut prev, &mut prev_net, &mut at).is_some());
        // The remembered interface set is capped, not 500.
        assert!(prev_net.len() <= 64, "prev_net held {}", prev_net.len());
    }
}

#[cfg(test)]
mod credential_prompt_tests {
    use super::key_load_error_needs_passphrase;

    #[test]
    fn encrypted_key_error_requests_passphrase_prompt() {
        let err = anyhow::anyhow!("failed to load key: The key is encrypted");
        assert!(key_load_error_needs_passphrase(&err));
    }

    #[test]
    fn unrelated_key_error_does_not_force_prompt() {
        let err = anyhow::anyhow!("failed to load key: no such file or directory");
        assert!(!key_load_error_needs_passphrase(&err));
    }
}
