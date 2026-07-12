//! SFTP subsystem worker.
//!
//! Each terminal tab that spawns an SSH shell also spawns a *separate* SSH
//! connection for SFTP. This keeps the shell PTY completely unblocked: large
//! file transfers cannot stall readline or vim.
//!
//! The public API is a simple command channel (`SftpHandle::commands`) that
//! accepts `SftpCommand` messages. Results and status updates are pushed back
//! via the shared `UnboundedSender<SessionEvent>` that already exists for the
//! terminal tab.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use russh::client::{self, Handler};
use russh::ChannelMsg;
use russh::Disconnect;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use ssh_key::PublicKey;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::{AuthMethod, Session};
use crate::i18n::t;
use crate::ssh::{format_mtime, format_size, RemoteEntry, RemoteTreeNode, SessionEvent};

#[derive(Default)]
struct OwnerMaps {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Commands sent to the SFTP worker task from the UI thread.
#[derive(Debug)]
pub enum SftpCommand {
    /// List the contents of a remote directory.
    ListDir(String),
    SudoListDir {
        path: String,
        target_user: String,
        password: String,
    },
    /// Toggle a directory node in the tree (expand if collapsed, collapse if expanded).
    ToggleTreeNode(String),
    /// Download a remote file to a local directory.
    Download { remote: String, local_dir: String },
    /// Ask the remote host to zip a directory, then download that one archive.
    DownloadDirZip { remote: String, local_dir: String },
    /// Upload a local file into a remote directory.
    Upload { local: String, remote_dir: String },
    /// Upload a local file through sudo by staging it in a temp path first.
    SudoUpload {
        local: String,
        remote_dir: String,
        target_user: String,
        password: String,
    },
    /// Upload a local file to an exact remote file path.
    UploadTo { local: String, remote_path: String },
    SudoUploadTo {
        local: String,
        remote_path: String,
        target_user: String,
        owner_spec: String,
        password: String,
    },
    /// Delete a remote file (falls back to removing an empty directory).
    Delete(String),
    /// Download a file to a temp dir and open it with the OS default app
    /// ("Open/Edit externally", #81). When `edit` is set, watch the temp copy
    /// and re-upload on every change.
    OpenTemp {
        remote: String,
        edit: bool,
        program: Option<String>,
    },
    SudoOpenTemp {
        remote: String,
        edit: bool,
        program: Option<String>,
        target_user: String,
        password: String,
    },
    /// Rename / move a remote file or directory (#69).
    Rename { from: String, to: String },
    /// Change a remote path's permission bits (POSIX mode, e.g. 0o755) (#69).
    Chmod { path: String, mode: u32 },
    /// Create an empty remote directory (#69).
    MkDir(String),
    /// Create an empty remote file (#69).
    TouchFile(String),
    /// Read a remote file's text for the built-in viewer/editor (#70).
    ReadText { remote: String, edit: bool },
    SudoReadText {
        remote: String,
        edit: bool,
        target_user: String,
        password: String,
    },
    /// Overwrite a remote file with text from the built-in editor (#70).
    WriteText { remote: String, content: String },
    SudoWriteText {
        remote: String,
        content: String,
        target_user: String,
        password: String,
    },
    /// Gracefully shut down the SFTP worker.
    Close,
}

/// Handle retained by the UI to drive a running SFTP worker.
pub struct SftpHandle {
    pub commands: UnboundedSender<SftpCommand>,
    cancelled_transfers: Arc<Mutex<HashSet<String>>>,
    #[allow(dead_code)]
    pub join: JoinHandle<()>,
}

impl SftpHandle {
    pub fn list_dir(&self, path: String) {
        let _ = self.commands.send(SftpCommand::ListDir(path));
    }
    pub fn sudo_list_dir(&self, path: String, target_user: String, password: String) {
        let _ = self.commands.send(SftpCommand::SudoListDir {
            path,
            target_user,
            password,
        });
    }
    pub fn download(&self, remote: String, local_dir: String) {
        let _ = self
            .commands
            .send(SftpCommand::Download { remote, local_dir });
    }
    pub fn download_dir_zip(&self, remote: String, local_dir: String) {
        let _ = self
            .commands
            .send(SftpCommand::DownloadDirZip { remote, local_dir });
    }
    pub fn cancel_transfer(&self, id: &str) {
        if let Ok(mut cancelled) = self.cancelled_transfers.lock() {
            cancelled.insert(id.to_string());
        }
    }
    pub fn upload(&self, local: String, remote_dir: String) {
        let _ = self
            .commands
            .send(SftpCommand::Upload { local, remote_dir });
    }
    pub fn sudo_upload(
        &self,
        local: String,
        remote_dir: String,
        target_user: String,
        password: String,
    ) {
        let _ = self.commands.send(SftpCommand::SudoUpload {
            local,
            remote_dir,
            target_user,
            password,
        });
    }
    pub fn toggle_tree_node(&self, path: String) {
        let _ = self.commands.send(SftpCommand::ToggleTreeNode(path));
    }
    pub fn delete(&self, path: String) {
        let _ = self.commands.send(SftpCommand::Delete(path));
    }
    pub fn open_temp(&self, remote: String, edit: bool, program: Option<String>) {
        let _ = self.commands.send(SftpCommand::OpenTemp {
            remote,
            edit,
            program,
        });
    }
    pub fn sudo_open_temp(
        &self,
        remote: String,
        edit: bool,
        program: Option<String>,
        target_user: String,
        password: String,
    ) {
        let _ = self.commands.send(SftpCommand::SudoOpenTemp {
            remote,
            edit,
            program,
            target_user,
            password,
        });
    }
    pub fn rename(&self, from: String, to: String) {
        let _ = self.commands.send(SftpCommand::Rename { from, to });
    }
    pub fn chmod(&self, path: String, mode: u32) {
        let _ = self.commands.send(SftpCommand::Chmod { path, mode });
    }
    pub fn mkdir(&self, path: String) {
        let _ = self.commands.send(SftpCommand::MkDir(path));
    }
    pub fn touch(&self, path: String) {
        let _ = self.commands.send(SftpCommand::TouchFile(path));
    }
    pub fn read_text(&self, remote: String, edit: bool) {
        let _ = self.commands.send(SftpCommand::ReadText { remote, edit });
    }
    pub fn sudo_read_text(
        &self,
        remote: String,
        edit: bool,
        target_user: String,
        password: String,
    ) {
        let _ = self.commands.send(SftpCommand::SudoReadText {
            remote,
            edit,
            target_user,
            password,
        });
    }
    pub fn write_text(&self, remote: String, content: String) {
        let _ = self
            .commands
            .send(SftpCommand::WriteText { remote, content });
    }
    pub fn sudo_write_text(
        &self,
        remote: String,
        content: String,
        target_user: String,
        password: String,
    ) {
        let _ = self.commands.send(SftpCommand::SudoWriteText {
            remote,
            content,
            target_user,
            password,
        });
    }
    pub fn close(&self) {
        let _ = self.commands.send(SftpCommand::Close);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Spawn an SFTP worker on the Tokio runtime.
///
/// The worker opens its own SSH connection to the same server, authenticates,
/// and requests the `sftp` subsystem. Events (directory listings, progress,
/// errors) are sent back via `events`, which is the same sender used by the
/// terminal's shell session.
pub fn spawn_sftp(
    runtime: &tokio::runtime::Handle,
    ui_tab_id: String,
    session: Session,
    events: UnboundedSender<SessionEvent>,
    keepalive_interval_secs: u32,
    disconnect_retry_count: u32,
) -> SftpHandle {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let self_tx = cmd_tx.clone();
    let events_err = events.clone();
    let cancelled_transfers = Arc::new(Mutex::new(HashSet::new()));
    let cancelled_for_task = cancelled_transfers.clone();
    let join = runtime.spawn(async move {
        if let Err(err) = run_sftp(
            ui_tab_id,
            session,
            cmd_rx,
            self_tx,
            events,
            cancelled_for_task,
            keepalive_interval_secs,
            disconnect_retry_count,
        )
        .await
        {
            let _ = events_err.send(SessionEvent::SftpStatus(format!(
                "{}: {err:#}",
                t("SFTP 错误", "SFTP error")
            )));
        }
    });
    SftpHandle {
        commands: cmd_tx,
        cancelled_transfers,
        join,
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tree state helpers
// ---------------------------------------------------------------------------

/// Recursively build the flat node list from tree state (DFS pre-order).
fn build_tree_nodes(
    path: &str,
    depth: u32,
    expanded: &std::collections::HashSet<String>,
    tree_dirs: &std::collections::HashMap<String, Vec<(String, String)>>,
    nodes: &mut Vec<RemoteTreeNode>,
) {
    let name = if path == "/" {
        "/".to_string()
    } else {
        path.rsplit('/').next().unwrap_or(path).to_string()
    };
    let children = tree_dirs.get(path);
    let has_children = children.map(|c| !c.is_empty()).unwrap_or(true);
    let is_expanded = expanded.contains(path);
    nodes.push(RemoteTreeNode {
        path: path.to_string(),
        name,
        depth,
        expanded: is_expanded,
        has_children,
    });
    if is_expanded {
        if let Some(ch) = children {
            for (_, child_path) in ch {
                build_tree_nodes(child_path, depth + 1, expanded, tree_dirs, nodes);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

async fn run_sftp(
    ui_tab_id: String,
    session: Session,
    mut commands: UnboundedReceiver<SftpCommand>,
    self_tx: UnboundedSender<SftpCommand>,
    events: UnboundedSender<SessionEvent>,
    cancelled_transfers: Arc<Mutex<HashSet<String>>>,
    keepalive_interval_secs: u32,
    disconnect_retry_count: u32,
) -> Result<()> {
    let _ = events.send(SessionEvent::SftpStatus(
        t("SFTP 连接中...", "SFTP connecting...").into(),
    ));

    // Open a dedicated SSH connection for SFTP.
    let config = Arc::new(crate::ssh::client_config(
        keepalive_interval_secs,
        disconnect_retry_count,
    ));

    let addr = format!("{}:{}", session.host, session.port);
    // Tunnel through the same proxy as the shell session, if configured.
    let mut handle = match crate::proxy::resolve(&session.proxy) {
        Some(p) => {
            let stream = crate::proxy::connect(&p, &session.host, session.port)
                .await
                .with_context(|| format!("sftp proxy connect {} failed", addr))?;
            client::connect_stream(config, stream, sftp_handler(&session, &events))
                .await
                .with_context(|| format!("sftp connect {} failed", addr))?
        }
        None => client::connect(config, addr.as_str(), sftp_handler(&session, &events))
            .await
            .with_context(|| format!("sftp connect {} failed", addr))?,
    };

    // --- Authenticate (same method as the shell session) -------------------
    let effective_user: String;
    let authed = match session.auth {
        AuthMethod::Password => {
            let (mut user, mut password) =
                match crate::ssh::resolve_credentials(&session, &events).await {
                    Some(c) => c,
                    None => return Err(anyhow!(t("已取消登录", "login cancelled"))),
                };
            let allow_user_retry = session.user.trim().is_empty();
            loop {
                let authed = handle
                    .authenticate_password(&user, password.as_str())
                    .await
                    .context("sftp password auth failed")?;
                if authed {
                    effective_user = user.clone();
                    break true;
                }
                match crate::ssh::reprompt_credentials(
                    &session,
                    &events,
                    user.clone(),
                    allow_user_retry,
                    Some(crate::ssh::CredentialSecretKind::Password),
                )
                .await
                {
                    Some((u, p, _remember)) => {
                        if allow_user_retry {
                            user = u.trim().to_string();
                        }
                        password = p;
                    }
                    None => return Err(anyhow!(t("已取消登录", "login cancelled"))),
                }
            }
        }
        AuthMethod::Key => {
            let Some((user, key_with_hash)) =
                crate::ssh::resolve_key_auth(&session, &events).await?
            else {
                return Err(anyhow!(t("已取消登录", "login cancelled")));
            };
            effective_user = user.clone();
            handle
                .authenticate_publickey(&user, key_with_hash)
                .await
                .context("sftp publickey auth failed")?
        }
    };

    if !authed {
        return Err(anyhow!(t("SFTP 认证失败", "SFTP authentication failed")));
    }
    let _ = events.send(SessionEvent::SftpUser {
        user: effective_user.clone(),
    });
    let effective_owner_spec = match login_owner_spec(&mut handle, &effective_user).await {
        Ok(spec) if !spec.trim().is_empty() => spec,
        _ => effective_user.clone(),
    };

    // --- Open the sftp subsystem channel -----------------------------------
    let channel = handle
        .channel_open_session()
        .await
        .context("open sftp channel")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("request sftp subsystem")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("sftp handshake")?;
    let mut owner_maps = OwnerMaps::default();

    // Resolve the home directory and do an initial listing.
    let home = sftp
        .canonicalize(".")
        .await
        .unwrap_or_else(|_| "/".to_string());
    let _ = events.send(SessionEvent::SftpStatus(format!(
        "{} {}...",
        t("SFTP 加载", "SFTP loading"),
        home
    )));
    match list_dir_impl(&sftp, &home, &owner_maps).await {
        Ok(entries) => {
            let _ = events.send(SessionEvent::SftpEntries {
                path: home.clone(),
                entries,
            });
            let _ = events.send(SessionEvent::SftpStatus(home.clone()));
        }
        Err(e) => {
            let _ = events.send(SessionEvent::SftpError(list_error_msg(&home, &e)));
        }
    }

    // --- Directory tree initialization -------------------------------------
    // tree_dirs: path -> [(child_name, child_full_path)] for directories only
    // tree_expanded: set of paths currently shown as expanded
    let mut tree_dirs: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();
    let mut tree_expanded: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Fetch only root "/" subdirs on startup. Deeper levels are loaded lazily
    // when the user expands a node, which makes the first SFTP open much
    // faster on high-latency servers.
    let root_dirs = list_dirs_only_impl(&sftp, "/", &owner_maps)
        .await
        .unwrap_or_default();
    tree_dirs.insert("/".to_string(), root_dirs);
    tree_expanded.insert("/".to_string());
    {
        let mut nodes = Vec::new();
        build_tree_nodes("/", 0, &tree_expanded, &tree_dirs, &mut nodes);
        let _ = events.send(SessionEvent::SftpTreeUpdate(nodes));
    }

    // Load uid/gid -> user/group names AFTER the first listing/tree render so
    // the SFTP panel opens immediately on slow servers. Once the maps arrive we
    // refresh the current directory and tree display in-place.
    if let Ok(loaded_maps) = load_owner_maps(&sftp).await {
        owner_maps = loaded_maps;

        if let Ok(entries) = list_dir_impl(&sftp, &home, &owner_maps).await {
            let _ = events.send(SessionEvent::SftpEntries {
                path: home.clone(),
                entries,
            });
        }

        let root_dirs = list_dirs_only_impl(&sftp, "/", &owner_maps)
            .await
            .unwrap_or_default();
        tree_dirs.insert("/".to_string(), root_dirs);
        let mut nodes = Vec::new();
        build_tree_nodes("/", 0, &tree_expanded, &tree_dirs, &mut nodes);
        let _ = events.send(SessionEvent::SftpTreeUpdate(nodes));
    }

    // --- Command loop -------------------------------------------------------
    while let Some(cmd) = commands.recv().await {
        match cmd {
            SftpCommand::Close => break,

            SftpCommand::ListDir(path) => {
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("加载", "Loading"),
                    path
                )));
                match list_dir_impl(&sftp, &path, &owner_maps).await {
                    Ok(entries) => {
                        let _ = events.send(SessionEvent::SftpEntries {
                            path: path.clone(),
                            entries,
                        });
                        let _ = events.send(SessionEvent::SftpStatus(path));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpError(list_error_msg(&path, &e)));
                    }
                }
            }

            SftpCommand::SudoListDir {
                path,
                target_user,
                password,
            } => {
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("root 加载", "Root loading"),
                    path
                )));
                match sudo_list_dir_impl(&handle, &path, &target_user, &password).await {
                    Ok(entries) => {
                        let _ = events.send(SessionEvent::SftpEntries {
                            path: path.clone(),
                            entries,
                        });
                        let _ = events.send(SessionEvent::SftpStatus(path));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpError(list_error_msg(&path, &e)));
                    }
                }
            }

            SftpCommand::ToggleTreeNode(path) => {
                if tree_expanded.contains(&path) {
                    // Collapse this node and all descendants.
                    let prefix = format!("{}/", path.trim_end_matches('/'));
                    tree_expanded.retain(|p| p != &path && !p.starts_with(&prefix));
                } else {
                    // Expand: fetch children if not yet cached.
                    if !tree_dirs.contains_key(&path) {
                        let dirs = list_dirs_only_impl(&sftp, &path, &owner_maps)
                            .await
                            .unwrap_or_default();
                        tree_dirs.insert(path.clone(), dirs);
                    }
                    tree_expanded.insert(path.clone());
                }
                let mut nodes = Vec::new();
                build_tree_nodes("/", 0, &tree_expanded, &tree_dirs, &mut nodes);
                let _ = events.send(SessionEvent::SftpTreeUpdate(nodes));
            }

            SftpCommand::Download { remote, local_dir } => {
                // A directory target → recursively mirror the whole tree (#50).
                let is_dir = sftp
                    .metadata(&remote)
                    .await
                    .ok()
                    .map(|m| (m.permissions.unwrap_or(0) & 0o170_000) == 0o040_000)
                    .unwrap_or(false);
                if is_dir {
                    let dirname = base_name(&remote);
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{} {}/...",
                        t("下载文件夹", "Downloading folder"),
                        dirname
                    )));
                    match download_dir(
                        &sftp,
                        &ui_tab_id,
                        &remote,
                        &local_dir,
                        &events,
                        &cancelled_transfers,
                    )
                    .await
                    {
                        Ok(_) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {}",
                                t("下载完成", "Downloaded"),
                                dirname
                            )));
                        }
                        Err(e) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {e}",
                                t("下载失败", "Download failed")
                            )));
                        }
                    }
                } else {
                    // Sanitize the server-supplied name before it touches the local
                    // filesystem (#26): a malicious server could otherwise craft a
                    // name with traversal, shell-special chars or a Windows reserved
                    // device name to write outside the chosen dir or hit a device.
                    let filename = sanitize_filename(&base_name(&remote));
                    let local_path = format!("{}/{}", local_dir.trim_end_matches('/'), filename);
                    let id = Uuid::new_v4().to_string();
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{} {}...",
                        t("下载", "Downloading"),
                        filename
                    )));
                    match download_impl(
                        &sftp,
                        &ui_tab_id,
                        &remote,
                        &local_path,
                        &filename,
                        &id,
                        &events,
                        &cancelled_transfers,
                    )
                    .await
                    {
                        Ok(_) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {}",
                                t("下载完成", "Downloaded"),
                                filename
                            )));
                        }
                        Err(e) => {
                            emit_transfer(
                                &events,
                                &id,
                                &session.id,
                                &filename,
                                &local_path,
                                &remote,
                                false,
                                0,
                                0,
                                2,
                                &e.to_string(),
                            );
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {e}",
                                t("下载失败", "Download failed")
                            )));
                        }
                    }
                }
            }

            SftpCommand::DownloadDirZip { remote, local_dir } => {
                let dirname = sanitize_filename(&base_name(&remote));
                let zip_name = format!("{dirname}.zip");
                let local_path = format!("{}/{}", local_dir.trim_end_matches('/'), zip_name);
                let id = Uuid::new_v4().to_string();
                let is_dir = sftp
                    .metadata(&remote)
                    .await
                    .ok()
                    .map(|m| (m.permissions.unwrap_or(0) & 0o170_000) == 0o040_000)
                    .unwrap_or(false);
                if !is_dir {
                    let msg = t("目标不是文件夹", "target is not a folder");
                    emit_transfer(
                        &events,
                        &id,
                        &session.id,
                        &zip_name,
                        &local_path,
                        &remote,
                        false,
                        0,
                        0,
                        2,
                        &msg,
                    );
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{}: {msg}",
                        t("下载失败", "Download failed")
                    )));
                    continue;
                }

                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("正在远端打包", "Creating remote zip"),
                    zip_name
                )));
                match download_dir_as_remote_zip(
                    &handle,
                    &sftp,
                    &ui_tab_id,
                    &remote,
                    &local_path,
                    &zip_name,
                    &id,
                    &events,
                    &cancelled_transfers,
                )
                .await
                {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("下载完成", "Downloaded"),
                            zip_name
                        )));
                    }
                    Err(e) => {
                        emit_transfer(
                            &events,
                            &id,
                            &session.id,
                            &zip_name,
                            &local_path,
                            &remote,
                            false,
                            0,
                            0,
                            2,
                            &e.to_string(),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("下载失败", "Download failed")
                        )));
                    }
                }
            }

            SftpCommand::Upload { local, remote_dir } => {
                // A directory source → recursively upload the whole tree (#50).
                let is_dir = tokio::fs::metadata(&local)
                    .await
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    let dirname = base_name(&local);
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{} {}/...",
                        t("上传文件夹", "Uploading folder"),
                        dirname
                    )));
                    let res = upload_dir(
                        &handle,
                        &sftp,
                        &ui_tab_id,
                        &local,
                        &remote_dir,
                        &events,
                        &cancelled_transfers,
                    )
                    .await;
                    if let Ok(entries) = list_dir_impl(&sftp, &remote_dir, &owner_maps).await {
                        let _ = events.send(SessionEvent::SftpEntries {
                            path: remote_dir.clone(),
                            entries,
                        });
                    }
                    match res {
                        Ok(_) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {}",
                                t("上传完成", "Uploaded"),
                                dirname
                            )));
                        }
                        Err(e) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {e}",
                                t("上传失败", "Upload failed")
                            )));
                        }
                    }
                } else {
                    let filename = base_name(&local);
                    let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), filename);
                    let id = Uuid::new_v4().to_string();
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{} {}...",
                        t("上传", "Uploading"),
                        filename
                    )));
                    match upload_pipelined(
                        &handle,
                        &ui_tab_id,
                        &local,
                        &remote_path,
                        &filename,
                        &id,
                        &events,
                        &cancelled_transfers,
                    )
                    .await
                    {
                        Ok(_) => {
                            if let Ok(entries) =
                                list_dir_impl(&sftp, &remote_dir, &owner_maps).await
                            {
                                let _ = events.send(SessionEvent::SftpEntries {
                                    path: remote_dir.clone(),
                                    entries,
                                });
                            }
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {}",
                                t("上传完成", "Uploaded"),
                                filename
                            )));
                        }
                        Err(e) => {
                            emit_transfer(
                                &events,
                                &id,
                                &ui_tab_id,
                                &filename,
                                &local,
                                "",
                                true,
                                0,
                                0,
                                2,
                                &e.to_string(),
                            );
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {e}",
                                t("上传失败", "Upload failed")
                            )));
                        }
                    }
                }
            }

            SftpCommand::SudoUpload {
                local,
                remote_dir,
                target_user,
                password,
            } => {
                let is_dir = tokio::fs::metadata(&local)
                    .await
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    let _ = events.send(SessionEvent::SftpStatus(
                        t(
                            "root 视角暂不支持上传文件夹",
                            "Root view does not support folder upload yet",
                        )
                        .into(),
                    ));
                    continue;
                }
                let filename = base_name(&local);
                let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), filename);
                let tmp_path = format!(
                    "/tmp/.meatshell-{}-{}",
                    Uuid::new_v4(),
                    sanitize_filename(&filename)
                );
                let id = Uuid::new_v4().to_string();
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("root 上传", "Root uploading"),
                    filename
                )));
                let stage_result = upload_pipelined(
                    &handle,
                    &ui_tab_id,
                    &local,
                    &tmp_path,
                    &filename,
                    &id,
                    &events,
                    &cancelled_transfers,
                )
                .await;
                let result = match stage_result {
                    Ok(_) => {
                        sudo_install_temp_file(
                            &handle,
                            &tmp_path,
                            &remote_path,
                            &target_user,
                            &effective_owner_spec,
                            &password,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(_) => {
                        let _ = remove_remote_temp(&handle, &tmp_path).await;
                        if let Ok(entries) =
                            sudo_list_dir_impl(&handle, &remote_dir, &target_user, &password).await
                        {
                            let _ = events.send(SessionEvent::SftpEntries {
                                path: remote_dir.clone(),
                                entries,
                            });
                        }
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            1,
                            1,
                            1,
                            &t("已通过 root 视角上传", "Uploaded through root view"),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("root 上传完成", "Root upload complete"),
                            filename
                        )));
                    }
                    Err(e) => {
                        let _ = remove_remote_temp(&handle, &tmp_path).await;
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            0,
                            0,
                            2,
                            &e.to_string(),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("root 上传失败", "Root upload failed")
                        )));
                    }
                }
            }

            SftpCommand::UploadTo { local, remote_path } => {
                let filename = base_name(&remote_path);
                let remote_dir = parent_dir(&remote_path);
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("上传", "Uploading"),
                    filename
                )));
                let id = Uuid::new_v4().to_string();
                match upload_pipelined(
                    &handle,
                    &ui_tab_id,
                    &local,
                    &remote_path,
                    &filename,
                    &id,
                    &events,
                    &cancelled_transfers,
                )
                .await
                {
                    Ok(_) => {
                        if let Ok(entries) = list_dir_impl(&sftp, &remote_dir, &owner_maps).await {
                            let _ = events.send(SessionEvent::SftpEntries {
                                path: remote_dir.clone(),
                                entries,
                            });
                        }
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            1,
                            1,
                            1,
                            &t(
                                "保存后已覆盖服务器文件",
                                "Saved and replaced the server file",
                            ),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t(
                                "保存后已覆盖服务器文件",
                                "Saved and replaced the server file"
                            ),
                            filename
                        )));
                    }
                    Err(e) => {
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            0,
                            0,
                            2,
                            &e.to_string(),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("上传失败", "Upload failed")
                        )));
                    }
                }
            }

            SftpCommand::SudoUploadTo {
                local,
                remote_path,
                target_user,
                owner_spec,
                password,
            } => {
                let filename = base_name(&remote_path);
                let remote_dir = parent_dir(&remote_path);
                let tmp_path = format!(
                    "/tmp/.meatshell-{}-{}",
                    Uuid::new_v4(),
                    sanitize_filename(&filename)
                );
                let id = Uuid::new_v4().to_string();
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("root 上传", "Root uploading"),
                    filename
                )));
                let result = match upload_pipelined(
                    &handle,
                    &ui_tab_id,
                    &local,
                    &tmp_path,
                    &filename,
                    &id,
                    &events,
                    &cancelled_transfers,
                )
                .await
                {
                    Ok(_) => {
                        sudo_install_temp_file(
                            &handle,
                            &tmp_path,
                            &remote_path,
                            &target_user,
                            &owner_spec,
                            &password,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(_) => {
                        let _ = remove_remote_temp(&handle, &tmp_path).await;
                        if let Ok(entries) =
                            sudo_list_dir_impl(&handle, &remote_dir, &target_user, &password).await
                        {
                            let _ = events.send(SessionEvent::SftpEntries {
                                path: remote_dir.clone(),
                                entries,
                            });
                        }
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            1,
                            1,
                            1,
                            &t("root 保存已上传", "Root save uploaded"),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("root 保存已上传", "Root save uploaded"),
                            filename
                        )));
                    }
                    Err(e) => {
                        let _ = remove_remote_temp(&handle, &tmp_path).await;
                        emit_transfer(
                            &events,
                            &id,
                            &ui_tab_id,
                            &filename,
                            &local,
                            &remote_path,
                            true,
                            0,
                            0,
                            2,
                            &e.to_string(),
                        );
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("root 上传失败", "Root upload failed")
                        )));
                    }
                }
            }

            SftpCommand::Delete(path) => {
                let filename = base_name(&path);
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("删除", "Deleting"),
                    filename
                )));
                // Directories are removed recursively (a plain remove_dir only
                // works on an empty dir, so an uploaded folder couldn't be
                // deleted); files via remove_file.
                let is_dir = sftp
                    .metadata(&path)
                    .await
                    .ok()
                    .map(|m| (m.permissions.unwrap_or(0) & 0o170_000) == 0o040_000)
                    .unwrap_or(false);
                let res: Result<()> = if is_dir {
                    remove_dir_recursive(&sftp, &path).await
                } else {
                    sftp.remove_file(&path)
                        .await
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("{e}"))
                };
                match res {
                    Ok(_) => {
                        let parent = parent_dir(&path);
                        if let Ok(entries) = list_dir_impl(&sftp, &parent, &owner_maps).await {
                            let _ = events.send(SessionEvent::SftpEntries {
                                path: parent.clone(),
                                entries,
                            });
                        }
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("已删除", "Deleted"),
                            filename
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("删除失败", "Delete failed")
                        )));
                    }
                }
            }

            SftpCommand::Rename { from, to } => {
                let refresh = parent_dir(&from);
                match sftp.rename(&from, &to).await {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("已重命名", "Renamed"),
                            base_name(&to)
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("重命名失败", "Rename failed")
                        )));
                    }
                }
                if let Ok(entries) = list_dir_impl(&sftp, &refresh, &owner_maps).await {
                    let _ = events.send(SessionEvent::SftpEntries {
                        path: refresh,
                        entries,
                    });
                }
            }

            SftpCommand::Chmod { path, mode } => {
                let refresh = parent_dir(&path);
                let attrs = FileAttributes {
                    permissions: Some(mode),
                    ..Default::default()
                };
                match sftp.set_metadata(&path, attrs).await {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {} → {:o}",
                            t("已修改权限", "Permissions changed"),
                            base_name(&path),
                            mode
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("修改权限失败", "chmod failed")
                        )));
                    }
                }
                if let Ok(entries) = list_dir_impl(&sftp, &refresh, &owner_maps).await {
                    let _ = events.send(SessionEvent::SftpEntries {
                        path: refresh,
                        entries,
                    });
                }
            }

            SftpCommand::MkDir(path) => {
                let refresh = parent_dir(&path);
                match sftp.create_dir(&path).await {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("已新建文件夹", "Folder created"),
                            base_name(&path)
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("新建文件夹失败", "Create folder failed")
                        )));
                    }
                }
                if let Ok(entries) = list_dir_impl(&sftp, &refresh, &owner_maps).await {
                    let _ = events.send(SessionEvent::SftpEntries {
                        path: refresh,
                        entries,
                    });
                }
            }

            SftpCommand::TouchFile(path) => {
                let refresh = parent_dir(&path);
                // create() truncates if the file exists, so refuse to clobber.
                let exists = sftp.metadata(&path).await.is_ok();
                if exists {
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{}: {}",
                        t("文件已存在", "File already exists"),
                        base_name(&path)
                    )));
                } else {
                    match sftp.create(&path).await {
                        Ok(_) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {}",
                                t("已新建文件", "File created"),
                                base_name(&path)
                            )));
                        }
                        Err(e) => {
                            let _ = events.send(SessionEvent::SftpStatus(format!(
                                "{}: {e}",
                                t("新建文件失败", "Create file failed")
                            )));
                        }
                    }
                }
                if let Ok(entries) = list_dir_impl(&sftp, &refresh, &owner_maps).await {
                    let _ = events.send(SessionEvent::SftpEntries {
                        path: refresh,
                        entries,
                    });
                }
            }

            SftpCommand::OpenTemp {
                remote,
                edit,
                program,
            } => {
                // Sanitize the remote-controlled name before it becomes a local
                // file path that we later hand to the OS "open" call.
                let filename = temp_edit_filename(&session, &remote, edit);
                let tmp_dir = std::env::temp_dir().join("xiaoxingshell");
                let _ = tokio::fs::create_dir_all(&tmp_dir).await;
                let local = tmp_dir.join(&filename);
                let local_str = local.to_string_lossy().to_string();
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("打开", "Opening"),
                    filename
                )));
                let xid = Uuid::new_v4().to_string();
                match download_impl(
                    &sftp,
                    &ui_tab_id,
                    &remote,
                    &local_str,
                    &filename,
                    &xid,
                    &events,
                    &cancelled_transfers,
                )
                .await
                {
                    Ok(_) => {
                        let launch = match program.as_deref() {
                            Some(p) => open_with_program(p, &local_str).map(Some),
                            None => {
                                open_with_os(&local_str);
                                Ok(None)
                            }
                        };
                        match launch {
                            Ok(child) => {
                                let _ = events.send(SessionEvent::SftpStatus(format!(
                                    "{}: {}",
                                    if edit {
                                        t("已打开编辑", "Opened for editing")
                                    } else {
                                        t("已打开", "Opened")
                                    },
                                    filename
                                )));
                                if edit {
                                    spawn_edit_watcher(
                                        self_tx.clone(),
                                        local_str,
                                        remote.clone(),
                                        filename,
                                        events.clone(),
                                        child,
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = events.send(SessionEvent::SftpStatus(format!(
                                    "{}: {e}",
                                    t("打开失败", "Open failed")
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("打开失败", "Open failed")
                        )));
                    }
                }
            }
            SftpCommand::SudoOpenTemp {
                remote,
                edit,
                program,
                target_user,
                password,
            } => {
                let filename = temp_edit_filename(&session, &remote, edit);
                let tmp_dir = std::env::temp_dir().join("xiaoxingshell");
                let _ = tokio::fs::create_dir_all(&tmp_dir).await;
                let local = tmp_dir.join(&filename);
                let local_str = local.to_string_lossy().to_string();
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("root 打开", "Root opening"),
                    filename
                )));
                match sudo_read_file_to_local(&handle, &remote, &local_str, &target_user, &password)
                    .await
                {
                    Ok(owner_spec) => {
                        let launch = match program.as_deref() {
                            Some(p) => open_with_program(p, &local_str).map(Some),
                            None => {
                                open_with_os(&local_str);
                                Ok(None)
                            }
                        };
                        match launch {
                            Ok(child) => {
                                let _ = events.send(SessionEvent::SftpStatus(format!(
                                    "{}: {}",
                                    if edit {
                                        t("已打开 root 编辑", "Opened for root editing")
                                    } else {
                                        t("已打开", "Opened")
                                    },
                                    filename
                                )));
                                if edit {
                                    spawn_sudo_edit_watcher(
                                        self_tx.clone(),
                                        local_str,
                                        remote.clone(),
                                        filename,
                                        target_user,
                                        owner_spec,
                                        password,
                                        events.clone(),
                                        child,
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = events.send(SessionEvent::SftpStatus(format!(
                                    "{}: {e}",
                                    t("打开失败", "Open failed")
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e}",
                            t("打开失败", "Open failed")
                        )));
                    }
                }
            }
            SftpCommand::ReadText { remote, edit } => {
                let name = base_name(&remote);
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("打开", "Opening"),
                    name
                )));
                let (content, error) = match read_text_guarded(&sftp, &remote).await {
                    Ok(text) => (text, String::new()),
                    Err(msg) => (String::new(), msg),
                };
                let _ = events.send(SessionEvent::SftpFileText {
                    path: remote,
                    name,
                    content,
                    edit,
                    error,
                });
            }
            SftpCommand::SudoReadText {
                remote,
                edit,
                target_user,
                password,
            } => {
                let name = base_name(&remote);
                let _ = events.send(SessionEvent::SftpStatus(format!(
                    "{} {}...",
                    t("root 打开", "Root opening"),
                    name
                )));
                let (content, error) =
                    match sudo_read_text_guarded(&handle, &remote, &target_user, &password).await {
                        Ok(text) => (text, String::new()),
                        Err(msg) => (String::new(), msg),
                    };
                let _ = events.send(SessionEvent::SftpFileText {
                    path: remote,
                    name,
                    content,
                    edit,
                    error,
                });
            }
            SftpCommand::WriteText { remote, content } => {
                let name = base_name(&remote);
                match write_text_file(&sftp, &remote, &content).await {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("已保存", "Saved"),
                            name
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e:#}",
                            t("保存失败", "Save failed")
                        )));
                    }
                }
            }
            SftpCommand::SudoWriteText {
                remote,
                content,
                target_user,
                password,
            } => {
                let name = base_name(&remote);
                match sudo_write_text_preserve_owner(
                    &sftp,
                    &handle,
                    &remote,
                    &content,
                    &target_user,
                    &password,
                )
                .await
                {
                    Ok(_) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("root 已保存", "Root saved"),
                            name
                        )));
                    }
                    Err(e) => {
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {e:#}",
                            t("保存失败", "Save failed")
                        )));
                    }
                }
            }
        }
    }

    let _ = handle
        .disconnect(Disconnect::ByApplication, "bye", "")
        .await;
    Ok(())
}

/// Read a remote file as UTF-8 text for the built-in editor, rejecting files
/// that are too large, binary, or not valid UTF-8 (#70). Returns the text on
/// success or a human-readable error message on failure.
async fn read_text_guarded(
    sftp: &SftpSession,
    remote: &str,
) -> std::result::Result<String, String> {
    use tokio::io::AsyncReadExt;
    const MAX_EDIT_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB
    let size = sftp
        .metadata(remote)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0);
    if size > MAX_EDIT_BYTES {
        return Err(t(
            "文件过大,无法在内置编辑器中打开(上限 2 MB),请下载查看",
            "Too large for the built-in editor (2 MB limit); download it instead",
        )
        .into());
    }
    let mut f = sftp
        .open(remote)
        .await
        .map_err(|e| format!("{}: {e}", t("打开失败", "Open failed")))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .await
        .map_err(|e| format!("{}: {e}", t("读取失败", "Read failed")))?;
    // Control characters (beyond tab/newline/CR) have no glyph — they render as
    // tofu boxes — and round-tripping them through the editor risks corrupting
    // the file (e.g. .viminfo). Treat such files as binary (#70).
    if bytes
        .iter()
        .any(|&b| (b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r') || b == 0x7f)
    {
        return Err(t(
            "包含控制字符(疑似二进制),无法以文本打开,请下载查看",
            "Contains control characters (likely binary); download it instead",
        )
        .into());
    }
    String::from_utf8(bytes)
        .map_err(|_| t("非 UTF-8 文本,无法打开", "Not UTF-8 text; cannot open").into())
}

/// Overwrite a remote file with the given text (CREATE | WRITE | TRUNCATE).
async fn write_text_file(sftp: &SftpSession, remote: &str, content: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = sftp
        .create(remote)
        .await
        .with_context(|| format!("create remote {remote}"))?;
    f.write_all(content.as_bytes())
        .await
        .context("write remote file")?;
    f.flush().await.context("flush remote file")?;
    let _ = f.shutdown().await;
    Ok(())
}

/// File name component of a path.  Handles both remote (`/`) and local Windows
/// (`\`) separators, so uploading `C:\…\frp.tar.gz` yields `frp.tar.gz` rather
/// than the whole path (which previously became the remote file name).
fn base_name(path: &str) -> String {
    let sep = |c: char| c == '/' || c == '\\';
    path.trim_end_matches(sep)
        .rsplit(sep)
        .next()
        .unwrap_or(path)
        .to_string()
}

/// Parent directory of a remote path ("/a/b" → "/a", "/a" → "/").
fn parent_dir(path: &str) -> String {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => p[..i].to_string(),
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Open a local file with the OS default application.
///
/// Security: we must NOT route the path through a shell.  The previous
/// `cmd /C start "" <path>` let cmd.exe re-parse the path, so a remote file name
/// containing shell metacharacters (`&` `|` `>` `<` `^` …) — e.g. `foo&calc.exe`
/// — could inject and run arbitrary commands when the user opened it.  We call
/// `ShellExecuteW` directly instead: it treats the path as one opaque string, so
/// no shell parsing happens.  (`xdg-open` on Unix already takes a single argv
/// argument and never invokes a shell.)
#[cfg(windows)]
pub(crate) fn open_with_os(path: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }
    let to_wide = |s: &str| -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let op = to_wide("open");
    let file = to_wide(path);
    unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // SW_SHOWNORMAL
        );
    }
}

#[cfg(not(windows))]
pub(crate) fn open_with_os(path: &str) {
    let _ = std::process::Command::new("xdg-open").arg(path).spawn();
}

pub(crate) fn open_with_program(program: &str, path: &str) -> Result<std::process::Child> {
    std::process::Command::new(program)
        .arg(path)
        .spawn()
        .with_context(|| format!("launch editor failed: {program}"))
}

/// Make a remote-supplied file name safe to use as a *local* file name (for
/// both downloads and temp files): drops path separators (defence-in-depth
/// against traversal), replaces characters invalid on Windows or special to
/// shells with `_`, trims surrounding whitespace and Windows' trailing dots,
/// and neutralises reserved device names (CON, NUL, COM1…).  Normal names
/// (letters, digits, `.`, `-`, `_`, Unicode) pass through; Unix dotfiles keep
/// their leading dot.  Falls back to `file` when nothing usable remains.
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*' | '&' | '^' | '%' | '!' | '`'
            | '$' | '\'' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    // Drop leading whitespace and trailing dots/spaces (Windows strips the
    // latter silently). A leading dot is preserved so `.bashrc` survives.
    let trimmed = cleaned.trim_start_matches(' ').trim_end_matches([' ', '.']);
    if trimmed.is_empty() {
        return "file".to_string();
    }
    // Windows reserved device names are reserved case-insensitively and even
    // with an extension ("CON.txt" still opens the console). A download named
    // after one could read/write a device instead of a file, so prefix `_`.
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let reserved = matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if reserved {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

fn temp_edit_filename(session: &Session, remote: &str, edit: bool) -> String {
    let filename = sanitize_filename(&base_name(remote));
    if !edit {
        return filename;
    }
    let prefix = if session.name.trim().is_empty() {
        format!("{}_{}", session.host.trim(), session.port)
    } else {
        session.name.trim().to_string()
    };
    format!("{}_{}", sanitize_filename(&prefix), filename)
}

/// Watch a downloaded temp file and re-upload it to the remote whenever it
/// changes on disk (the "edit" flow).  Re-upload is routed back through the
/// worker's own command channel.  Stops when the channel closes or after a
/// generous idle window.
async fn local_mtime(path: String) -> Option<std::time::SystemTime> {
    tokio::task::spawn_blocking(move || std::fs::metadata(path).ok()?.modified().ok())
        .await
        .ok()
        .flatten()
}

async fn local_bytes(path: String) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || std::fs::read(path).ok())
        .await
        .ok()
        .flatten()
}

fn spawn_edit_watcher(
    self_tx: UnboundedSender<SftpCommand>,
    local: String,
    remote: String,
    filename: String,
    events: UnboundedSender<SessionEvent>,
    child: Option<std::process::Child>,
) {
    tokio::spawn(async move {
        use std::time::{Duration, Instant};

        let mut last = local_mtime(local.clone()).await;
        let mut last_content = local_bytes(local.clone()).await;
        let mut child = child;
        let started = Instant::now();
        // VS Code and similar launchers often exit immediately after handing
        // the file off to an already-running editor process. Treat a very early
        // child exit as a detached-launch hint instead of "editing is over",
        // otherwise save -> re-upload silently stops working.
        let detached_launch_grace = Duration::from_secs(10);
        // ~40 min of 2s polls; also exits early once the worker is gone.
        for _ in 0..1200 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if self_tx.is_closed() {
                break;
            }
            let cur = local_mtime(local.clone()).await;
            if cur.is_some() && cur != last {
                let cur_content = local_bytes(local.clone()).await;
                // Atomic-save editors can briefly replace the file between the
                // mtime change and our read. If the read fails, keep `last`
                // unchanged so the next poll retries instead of dropping the
                // upload forever.
                if let Some(cur_content) = cur_content {
                    let changed = Some(cur_content.clone()) != last_content;
                    last = cur;
                    if changed {
                        last_content = Some(cur_content);
                        let _ = self_tx.send(SftpCommand::UploadTo {
                            local: local.clone(),
                            remote_path: remote.clone(),
                        });
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("已上传修改", "Re-uploaded changes"),
                            filename
                        )));
                    } else {
                        last_content = Some(cur_content);
                    }
                }
            }
            let exited = if let Some(proc) = child.as_mut() {
                proc.try_wait().ok().flatten().is_some()
            } else {
                false
            };
            if exited {
                if started.elapsed() < detached_launch_grace {
                    // Likely a launcher stub (for example VS Code reusing an
                    // existing window). Keep watching the file until timeout.
                    child = None;
                    continue;
                }
                let final_content = local_bytes(local.clone()).await;
                if final_content.is_some() && final_content != last_content {
                    let _ = self_tx.send(SftpCommand::UploadTo {
                        local: local.clone(),
                        remote_path: remote.clone(),
                    });
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{}: {}",
                        t("编辑器关闭后已上传", "Uploaded after editor closed"),
                        filename
                    )));
                }
                break;
            }
        }
    });
}

fn spawn_sudo_edit_watcher(
    self_tx: UnboundedSender<SftpCommand>,
    local: String,
    remote: String,
    filename: String,
    target_user: String,
    owner_spec: String,
    password: String,
    events: UnboundedSender<SessionEvent>,
    child: Option<std::process::Child>,
) {
    tokio::spawn(async move {
        use std::time::{Duration, Instant};

        let mut last = local_mtime(local.clone()).await;
        let mut last_content = local_bytes(local.clone()).await;
        let mut child = child;
        let started = Instant::now();
        let detached_launch_grace = Duration::from_secs(10);
        for _ in 0..1200 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if self_tx.is_closed() {
                break;
            }
            let cur = local_mtime(local.clone()).await;
            if cur.is_some() && cur != last {
                let cur_content = local_bytes(local.clone()).await;
                if let Some(cur_content) = cur_content {
                    let changed = Some(cur_content.clone()) != last_content;
                    last = cur;
                    if changed {
                        last_content = Some(cur_content);
                        let _ = self_tx.send(SftpCommand::SudoUploadTo {
                            local: local.clone(),
                            remote_path: remote.clone(),
                            target_user: target_user.clone(),
                            owner_spec: owner_spec.clone(),
                            password: password.clone(),
                        });
                        let _ = events.send(SessionEvent::SftpStatus(format!(
                            "{}: {}",
                            t("root 已上传修改", "Root re-uploaded changes"),
                            filename
                        )));
                    } else {
                        last_content = Some(cur_content);
                    }
                }
            }
            let exited = if let Some(proc) = child.as_mut() {
                proc.try_wait().ok().flatten().is_some()
            } else {
                false
            };
            if exited {
                if started.elapsed() < detached_launch_grace {
                    child = None;
                    continue;
                }
                let final_content = local_bytes(local.clone()).await;
                if final_content.is_some() && final_content != last_content {
                    let _ = self_tx.send(SftpCommand::SudoUploadTo {
                        local: local.clone(),
                        remote_path: remote.clone(),
                        target_user: target_user.clone(),
                        owner_spec: owner_spec.clone(),
                        password: password.clone(),
                    });
                    let _ = events.send(SessionEvent::SftpStatus(format!(
                        "{}: {}",
                        t(
                            "root 编辑器关闭后已上传",
                            "Root uploaded after editor closed"
                        ),
                        filename
                    )));
                }
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// SFTP helpers
// ---------------------------------------------------------------------------

/// A friendlier message for a failed directory listing, calling out the common
/// permission-denied case explicitly rather than dumping the raw error (#112).
fn list_error_msg(path: &str, e: &impl std::fmt::Display) -> String {
    let raw = e.to_string();
    let low = raw.to_lowercase();
    if low.contains("permission") || low.contains("denied") {
        format!("{}: {}", t("权限不足,无法访问", "Permission denied"), path)
    } else {
        format!("{} {}: {}", t("无法访问", "Cannot open"), path, raw)
    }
}

async fn list_dir_impl(
    sftp: &SftpSession,
    path: &str,
    owner_maps: &OwnerMaps,
) -> Result<Vec<RemoteEntry>> {
    let raw = sftp
        .read_dir(path)
        .await
        .with_context(|| format!("read_dir {path} failed"))?;

    let mut entries: Vec<RemoteEntry> = raw
        .into_iter()
        .filter(|e| {
            let n = e.file_name();
            n != "." && n != ".."
        })
        .map(|e| {
            let name = e.file_name().to_string();
            let full_path = format!("{}/{}", path.trim_end_matches('/'), name);
            let meta = e.metadata();
            let permissions = meta.permissions.unwrap_or(0);
            let kind = permissions & 0o170_000;
            let is_dir = kind == 0o040_000;
            let size = meta.size.unwrap_or(0);
            let modified = meta.mtime.unwrap_or(0);
            let mode = permissions & 0o7777;
            RemoteEntry {
                file_type: file_type_label(kind, &name),
                name,
                full_path,
                is_dir,
                size,
                modified,
                mode,
                mode_text: format_mode(permissions),
                owner_group: format_owner_group(meta.uid, meta.gid, owner_maps),
            }
        })
        .collect();

    // Sort: directories first, then files; both groups alphabetically.
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(entries)
}

fn file_type_label(kind: u32, name: &str) -> String {
    if kind == 0o040_000 {
        return t("文件夹", "Folder").to_string();
    }
    if kind == 0o120_000 {
        return t("链接", "Link").to_string();
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".sh") {
        t("SH 文件", "SH file").to_string()
    } else if lower.ends_with(".conf") {
        t("CONF 文件", "CONF file").to_string()
    } else if lower.ends_with(".bashrc") || lower.ends_with(".profile") {
        t("配置文件", "Profile file").to_string()
    } else {
        t("文件", "File").to_string()
    }
}

fn format_owner_group(uid: Option<u32>, gid: Option<u32>, owner_maps: &OwnerMaps) -> String {
    match (uid, gid) {
        (Some(u), Some(g)) => {
            let user = owner_maps
                .users
                .get(&u)
                .cloned()
                .unwrap_or_else(|| u.to_string());
            let group = owner_maps
                .groups
                .get(&g)
                .cloned()
                .unwrap_or_else(|| g.to_string());
            format!("{user}/{group}")
        }
        (Some(u), None) => owner_maps
            .users
            .get(&u)
            .cloned()
            .unwrap_or_else(|| u.to_string()),
        (None, Some(g)) => owner_maps
            .groups
            .get(&g)
            .cloned()
            .unwrap_or_else(|| g.to_string()),
        (None, None) => "-".to_string(),
    }
}

async fn load_owner_maps(sftp: &SftpSession) -> Result<OwnerMaps> {
    use tokio::io::AsyncReadExt;
    let mut out = OwnerMaps::default();
    if let Ok(mut f) = sftp.open("/etc/passwd").await {
        let mut text = String::new();
        if f.read_to_string(&mut text).await.is_ok() {
            for line in text.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        out.users.insert(uid, parts[0].to_string());
                    }
                }
            }
        }
    }
    if let Ok(mut f) = sftp.open("/etc/group").await {
        let mut text = String::new();
        if f.read_to_string(&mut text).await.is_ok() {
            for line in text.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(gid) = parts[2].parse::<u32>() {
                        out.groups.insert(gid, parts[0].to_string());
                    }
                }
            }
        }
    }
    Ok(out)
}

fn format_mode(permissions: u32) -> String {
    let kind = match permissions & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o100_000 => '-',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '-',
    };
    let bit = |v: u32, mask: u32, ch: char| if v & mask != 0 { ch } else { '-' };
    let mut out = String::with_capacity(10);
    out.push(kind);
    out.push(bit(permissions, 0o400, 'r'));
    out.push(bit(permissions, 0o200, 'w'));
    out.push(if permissions & 0o4000 != 0 {
        if permissions & 0o100 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        bit(permissions, 0o100, 'x')
    });
    out.push(bit(permissions, 0o040, 'r'));
    out.push(bit(permissions, 0o020, 'w'));
    out.push(if permissions & 0o2000 != 0 {
        if permissions & 0o010 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        bit(permissions, 0o010, 'x')
    });
    out.push(bit(permissions, 0o004, 'r'));
    out.push(bit(permissions, 0o002, 'w'));
    out.push(if permissions & 0o1000 != 0 {
        if permissions & 0o001 != 0 {
            't'
        } else {
            'T'
        }
    } else {
        bit(permissions, 0o001, 'x')
    });
    out
}

/// List only the subdirectories of `path` (no files). Used to build the tree.
async fn list_dirs_only_impl(
    sftp: &SftpSession,
    path: &str,
    owner_maps: &OwnerMaps,
) -> Result<Vec<(String, String)>> {
    let entries = list_dir_impl(sftp, path, owner_maps).await?;
    Ok(entries
        .into_iter()
        .filter(|e| e.is_dir)
        .map(|e| (e.name, e.full_path))
        .collect())
}

/// Emit a transfer-progress event.
fn emit_transfer(
    events: &UnboundedSender<SessionEvent>,
    id: &str,
    tab_id: &str,
    name: &str,
    local_path: &str,
    remote_path: &str,
    is_upload: bool,
    transferred: u64,
    total: u64,
    state: u8,
    msg: &str,
) {
    let _ = events.send(SessionEvent::SftpTransfer {
        id: id.to_string(),
        tab_id: tab_id.to_string(),
        name: name.to_string(),
        is_upload,
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        transferred,
        total,
        state,
        msg: msg.to_string(),
        completed_at: if state == 1 {
            Some(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            None
        },
    });
}

const XFER_CHUNK: usize = 64 * 1024;

fn transfer_cancelled(cancelled_transfers: &Arc<Mutex<HashSet<String>>>, id: &str) -> bool {
    cancelled_transfers
        .lock()
        .map(|set| set.contains(id))
        .unwrap_or(false)
}

fn clear_cancelled_transfer(cancelled_transfers: &Arc<Mutex<HashSet<String>>>, id: &str) {
    if let Ok(mut set) = cancelled_transfers.lock() {
        set.remove(id);
    }
}

async fn download_impl(
    sftp: &SftpSession,
    tab_id: &str,
    remote: &str,
    local: &str,
    name: &str,
    id: &str,
    events: &UnboundedSender<SessionEvent>,
    cancelled_transfers: &Arc<Mutex<HashSet<String>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let total = sftp
        .metadata(remote)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0);
    let mut remote_file = sftp
        .open(remote)
        .await
        .with_context(|| format!("open remote {remote}"))?;
    let mut local_file = tokio::fs::File::create(local)
        .await
        .with_context(|| format!("create local {local}"))?;

    emit_transfer(
        events, id, tab_id, name, local, remote, false, 0, total, 0, "",
    );
    let mut buf = vec![0u8; XFER_CHUNK];
    let mut done: u64 = 0;
    let mut last = Instant::now();
    loop {
        if transfer_cancelled(cancelled_transfers, id) {
            clear_cancelled_transfer(cancelled_transfers, id);
            emit_transfer(
                events,
                id,
                tab_id,
                name,
                local,
                remote,
                false,
                done,
                total,
                2,
                &t("已取消下载", "Download cancelled"),
            );
            return Err(anyhow!(t("已取消下载", "download cancelled")));
        }
        let n = remote_file
            .read(&mut buf)
            .await
            .context("read remote file")?;
        if n == 0 {
            break;
        }
        local_file
            .write_all(&buf[..n])
            .await
            .context("write local file")?;
        done += n as u64;
        if last.elapsed() >= Duration::from_millis(150) {
            last = Instant::now();
            emit_transfer(
                events, id, tab_id, name, local, remote, false, done, total, 0, "",
            );
        }
    }
    local_file.flush().await.context("flush local file")?;
    emit_transfer(
        events,
        id,
        tab_id,
        name,
        local,
        remote,
        false,
        done,
        total.max(done),
        1,
        "",
    );
    clear_cancelled_transfer(cancelled_transfers, id);
    Ok(())
}

/// Recursively download a remote directory tree under `local_parent` (#50).
///
/// Iterative (work-stack) rather than a boxed async recursion: each remote dir
/// is mirrored to a sanitized local name, then its files are downloaded with the
/// same per-file pipeline used for single downloads. Names are sanitized (#26)
/// so a hostile server can't escape the chosen folder.
async fn download_dir(
    sftp: &SftpSession,
    tab_id: &str,
    remote_root: &str,
    local_parent: &str,
    events: &UnboundedSender<SessionEvent>,
    cancelled_transfers: &Arc<Mutex<HashSet<String>>>,
) -> Result<()> {
    let owner_maps = OwnerMaps::default();
    let root_name = sanitize_filename(&base_name(remote_root));
    let root_local = std::path::PathBuf::from(local_parent).join(&root_name);
    // (remote_dir, local_dir) pairs still to mirror.
    let mut stack = vec![(remote_root.trim_end_matches('/').to_string(), root_local)];
    while let Some((rdir, ldir)) = stack.pop() {
        tokio::fs::create_dir_all(&ldir)
            .await
            .with_context(|| format!("create local dir {}", ldir.display()))?;
        for entry in list_dir_impl(sftp, &rdir, &owner_maps).await? {
            if entry.is_dir {
                let child_local = ldir.join(sanitize_filename(&entry.name));
                stack.push((entry.full_path, child_local));
            } else {
                let fname = sanitize_filename(&entry.name);
                let lpath = ldir.join(&fname);
                let lpath_str = lpath.to_string_lossy().to_string();
                let id = Uuid::new_v4().to_string();
                download_impl(
                    sftp,
                    tab_id,
                    &entry.full_path,
                    &lpath_str,
                    &fname,
                    &id,
                    events,
                    cancelled_transfers,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn download_dir_as_remote_zip(
    handle: &client::Handle<SftpClientHandler>,
    sftp: &SftpSession,
    tab_id: &str,
    remote_dir: &str,
    local_zip: &str,
    zip_name: &str,
    id: &str,
    events: &UnboundedSender<SessionEvent>,
    cancelled_transfers: &Arc<Mutex<HashSet<String>>>,
) -> Result<()> {
    let remote_dir = remote_dir.trim_end_matches('/');
    let remote_parent = parent_dir(remote_dir);
    let remote_name = base_name(remote_dir);
    let remote_zip = format!(
        "/tmp/meatshell-{}-{}.zip",
        sanitize_filename(&remote_name),
        Uuid::new_v4()
    );
    let cmd = format!(
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; command -v zip >/dev/null 2>&1 || {{ echo 'zip command not found' >&2; exit 127; }}; cd {} && rm -f {} && zip -qry {} {}",
        shell_quote(&remote_parent),
        shell_quote(&remote_zip),
        shell_quote(&remote_zip),
        shell_quote(&remote_name),
    );

    if let Err(err) = run_remote_exec(handle, &cmd).await {
        let _ = sftp.remove_file(&remote_zip).await;
        return Err(err);
    }

    let result = download_impl(
        sftp,
        tab_id,
        &remote_zip,
        local_zip,
        zip_name,
        id,
        events,
        cancelled_transfers,
    )
    .await;
    let _ = sftp.remove_file(&remote_zip).await;
    result
}

async fn run_remote_exec(handle: &client::Handle<SftpClientHandler>, cmd: &str) -> Result<()> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("open remote exec channel")?;
    channel
        .exec(true, cmd.as_bytes())
        .await
        .context("start remote exec")?;

    let mut stderr = String::new();
    let mut exit_status: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, ext: _ } => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::Data { data } => {
                tracing::debug!("remote exec stdout: {}", String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = Some(code);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    match exit_status {
        Some(0) => Ok(()),
        Some(code) => Err(anyhow!(remote_zip_error_message(code, &stderr))),
        None => {
            let detail = stderr.trim();
            if detail.is_empty() {
                Err(anyhow!(t(
                    "远端打包失败: 未收到退出状态",
                    "remote zip failed: no exit status received"
                )))
            } else {
                Err(anyhow!(remote_zip_error_message(255, detail)))
            }
        }
    }
}

async fn sudo_install_temp_file(
    handle: &client::Handle<SftpClientHandler>,
    tmp_path: &str,
    remote_path: &str,
    target_user: &str,
    owner_spec: &str,
    password: &str,
) -> Result<()> {
    let target = if target_user.trim().is_empty() {
        "root"
    } else {
        target_user.trim()
    };
    let owner = owner_spec.trim();
    let chown = if owner.is_empty() {
        String::new()
    } else {
        format!(
            " && chown {} {}",
            shell_quote(owner),
            shell_quote(remote_path)
        )
    };
    let inner = format!(
        "install -m 0644 {} {}{}",
        shell_quote(tmp_path),
        shell_quote(remote_path),
        chown
    );
    let cmd = format!(
        "sudo -S -p '' -u {} sh -c {}",
        shell_quote(target),
        shell_quote(&inner)
    );
    run_remote_exec_with_stdin(handle, &cmd, &format!("{password}\n")).await
}

async fn login_owner_spec(
    handle: &mut client::Handle<SftpClientHandler>,
    user: &str,
) -> Result<String> {
    let user = user.trim();
    if user.is_empty() {
        return Ok(String::new());
    }
    let cmd = format!("id -gn {}", shell_quote(user));
    let group = run_remote_exec_capture(handle, &cmd)
        .await?
        .trim()
        .to_string();
    if group.is_empty() {
        Ok(user.to_string())
    } else {
        Ok(format!("{user}:{group}"))
    }
}

async fn sudo_list_dir_impl(
    handle: &client::Handle<SftpClientHandler>,
    path: &str,
    target_user: &str,
    password: &str,
) -> Result<Vec<RemoteEntry>> {
    let script = format!(
        "find {} -mindepth 1 -maxdepth 1 -printf '%f\\t%p\\t%y\\t%s\\t%T@\\t%m\\t%u:%g\\n'",
        shell_quote(path)
    );
    let output = run_sudo_capture(handle, target_user, password, &script).await?;
    parse_sudo_find_listing(&output)
}

async fn sudo_read_text_guarded(
    handle: &client::Handle<SftpClientHandler>,
    remote: &str,
    target_user: &str,
    password: &str,
) -> std::result::Result<String, String> {
    let script = format!(
        "size=$(wc -c < {0}) || exit 1; [ \"$size\" -le 2097152 ] || {{ echo __MEATSHELL_TOO_LARGE__; exit 42; }}; cat -- {0}",
        shell_quote(remote)
    );
    match run_sudo_capture(handle, target_user, password, &script).await {
        Ok(text) => {
            if text
                .as_bytes()
                .iter()
                .any(|&b| (b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r') || b == 0x7f)
            {
                Err(t(
                    "包含控制字符(疑似二进制),无法以文本打开,请下载查看",
                    "Contains control characters (likely binary); download it instead",
                )
                .into())
            } else {
                Ok(text)
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("__MEATSHELL_TOO_LARGE__") {
                Err(t(
                    "文件过大,无法在内置编辑器中打开(上限 2 MB),请下载查看",
                    "Too large for the built-in editor (2 MB limit); download it instead",
                )
                .into())
            } else {
                Err(msg)
            }
        }
    }
}

async fn sudo_read_file_to_local(
    handle: &client::Handle<SftpClientHandler>,
    remote: &str,
    local: &str,
    target_user: &str,
    password: &str,
) -> Result<String> {
    use tokio::io::AsyncWriteExt;
    let owner = sudo_owner_spec(handle, remote, target_user, password).await?;
    let data = run_sudo_capture_bytes(
        handle,
        target_user,
        password,
        &format!("cat -- {}", shell_quote(remote)),
    )
    .await?;
    let mut f = tokio::fs::File::create(local)
        .await
        .with_context(|| format!("create local temp {local}"))?;
    f.write_all(&data).await.context("write local temp")?;
    f.flush().await.context("flush local temp")?;
    Ok(owner)
}

async fn sudo_write_text_preserve_owner(
    sftp: &SftpSession,
    handle: &client::Handle<SftpClientHandler>,
    remote: &str,
    content: &str,
    target_user: &str,
    password: &str,
) -> Result<()> {
    let owner = sudo_owner_spec(handle, remote, target_user, password).await?;
    let tmp = format!("/tmp/.meatshell-{}-edit", Uuid::new_v4());
    write_text_file(sftp, &tmp, content).await?;
    sudo_install_temp_file(handle, &tmp, remote, target_user, &owner, password).await?;
    let _ = remove_remote_temp(handle, &tmp).await;
    Ok(())
}

async fn sudo_owner_spec(
    handle: &client::Handle<SftpClientHandler>,
    remote: &str,
    target_user: &str,
    password: &str,
) -> Result<String> {
    let out = run_sudo_capture(
        handle,
        target_user,
        password,
        &format!("stat -c '%U:%G' -- {}", shell_quote(remote)),
    )
    .await?;
    Ok(out.trim().to_string())
}

async fn run_sudo_capture(
    handle: &client::Handle<SftpClientHandler>,
    target_user: &str,
    password: &str,
    script: &str,
) -> Result<String> {
    let bytes = run_sudo_capture_bytes(handle, target_user, password, script).await?;
    String::from_utf8(bytes).context("remote output is not UTF-8")
}

async fn run_sudo_capture_bytes(
    handle: &client::Handle<SftpClientHandler>,
    target_user: &str,
    password: &str,
    script: &str,
) -> Result<Vec<u8>> {
    let target = if target_user.trim().is_empty() {
        "root"
    } else {
        target_user.trim()
    };
    let cmd = format!(
        "sudo -S -p '' -u {} sh -c {}",
        shell_quote(target),
        shell_quote(script)
    );
    run_remote_exec_capture_with_stdin(handle, &cmd, &format!("{password}\n")).await
}

async fn run_remote_exec_capture(
    handle: &client::Handle<SftpClientHandler>,
    cmd: &str,
) -> Result<String> {
    let bytes = run_remote_exec_capture_with_stdin(handle, cmd, "").await?;
    String::from_utf8(bytes).context("remote output is not UTF-8")
}

async fn run_remote_exec_capture_with_stdin(
    handle: &client::Handle<SftpClientHandler>,
    cmd: &str,
    stdin: &str,
) -> Result<Vec<u8>> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("open remote exec channel")?;
    channel
        .exec(true, cmd.as_bytes())
        .await
        .context("start remote exec")?;
    if !stdin.is_empty() {
        channel
            .data(stdin.as_bytes())
            .await
            .context("write remote exec stdin")?;
    }
    let _ = channel.eof().await;

    let mut stdout = Vec::new();
    let mut stderr = String::new();
    let mut exit_status: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: _ } => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    match exit_status {
        Some(0) => Ok(stdout),
        Some(code) => Err(anyhow!("remote command exited {code}: {}", stderr.trim())),
        None => Err(anyhow!("remote command failed: no exit status received")),
    }
}

fn parse_sudo_find_listing(output: &str) -> Result<Vec<RemoteEntry>> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        let name = cols[0].to_string();
        if name == "." || name == ".." {
            continue;
        }
        let full_path = cols[1].to_string();
        let kind_char = cols[2].chars().next().unwrap_or('f');
        let is_dir = kind_char == 'd';
        let size = cols[3].parse::<u64>().unwrap_or(0);
        let modified = cols[4]
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let mode = u32::from_str_radix(cols[5], 8).unwrap_or(0) & 0o7777;
        let kind = match kind_char {
            'd' => 0o040_000,
            'l' => 0o120_000,
            _ => 0o100_000,
        };
        let permissions = kind | mode;
        entries.push(RemoteEntry {
            file_type: file_type_label(kind, &name),
            name,
            full_path,
            is_dir,
            size,
            modified,
            mode,
            mode_text: format_mode(permissions),
            owner_group: cols[6].to_string(),
        });
    }
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    Ok(entries)
}

async fn remove_remote_temp(
    handle: &client::Handle<SftpClientHandler>,
    tmp_path: &str,
) -> Result<()> {
    run_remote_exec(handle, &format!("rm -f -- {}", shell_quote(tmp_path))).await
}

async fn run_remote_exec_with_stdin(
    handle: &client::Handle<SftpClientHandler>,
    cmd: &str,
    stdin: &str,
) -> Result<()> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("open remote exec channel")?;
    channel
        .exec(true, cmd.as_bytes())
        .await
        .context("start remote exec")?;
    if !stdin.is_empty() {
        channel
            .data(stdin.as_bytes())
            .await
            .context("write remote exec stdin")?;
    }
    let _ = channel.eof().await;

    let mut stderr = String::new();
    let mut stdout = String::new();
    let mut exit_status: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, ext: _ } => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::Data { data } => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = Some(code);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    match exit_status {
        Some(0) => Ok(()),
        Some(code) => {
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            Err(anyhow!("remote command exited {code}: {detail}"))
        }
        None => Err(anyhow!("remote command failed: no exit status received")),
    }
}

fn remote_zip_error_message(code: u32, stderr: &str) -> String {
    let detail = stderr.trim();
    let lower = detail.to_ascii_lowercase();
    if code == 127 || lower.contains("zip command not found") {
        return t("远端未安装 zip 命令", "remote zip command is not installed").to_string();
    }
    if lower.contains("no space left on device")
        || lower.contains("enospc")
        || lower.contains("disk quota exceeded")
        || lower.contains("quota exceeded")
    {
        return t(
            "远端磁盘空间不足,无法生成临时 zip",
            "remote disk is full; cannot create temporary zip",
        )
        .to_string();
    }
    if detail.is_empty() {
        format!("remote zip failed with exit code {code}")
    } else {
        format!("remote zip failed with exit code {code}: {detail}")
    }
}

/// Recursively remove a remote directory tree (#50 follow-up).
///
/// A plain `remove_dir` only deletes an *empty* directory, so deleting an
/// uploaded folder failed. We BFS to discover every sub-directory (deleting
/// files as we go), then rmdir them deepest-first.
async fn remove_dir_recursive(sftp: &SftpSession, root: &str) -> Result<()> {
    let owner_maps = OwnerMaps::default();
    let mut all_dirs = vec![root.trim_end_matches('/').to_string()];
    let mut i = 0;
    while i < all_dirs.len() {
        let d = all_dirs[i].clone();
        i += 1;
        for entry in list_dir_impl(sftp, &d, &owner_maps).await? {
            if entry.is_dir {
                all_dirs.push(entry.full_path);
            } else {
                sftp.remove_file(&entry.full_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("remove file {}: {e}", entry.full_path))?;
            }
        }
    }
    // BFS discovered parents before children, so reversing gives deepest-first.
    for d in all_dirs.iter().rev() {
        sftp.remove_dir(d)
            .await
            .map_err(|e| anyhow::anyhow!("remove dir {d}: {e}"))?;
    }
    Ok(())
}

/// Recursively upload a local directory tree into `remote_parent` (#50).
///
/// Iterative work-stack: mirror each local dir to the remote (create_dir, whose
/// "already exists" error is ignored), then upload its files with the pipelined
/// path. Symlinks and other special files are skipped.
async fn upload_dir(
    handle: &client::Handle<SftpClientHandler>,
    sftp: &SftpSession,
    tab_id: &str,
    local_root: &str,
    remote_parent: &str,
    events: &UnboundedSender<SessionEvent>,
    cancelled_transfers: &Arc<Mutex<HashSet<String>>>,
) -> Result<()> {
    let root_name = base_name(local_root);
    let remote_root = format!("{}/{}", remote_parent.trim_end_matches('/'), root_name);
    let mut stack = vec![(local_root.to_string(), remote_root)];
    while let Some((ldir, rdir)) = stack.pop() {
        // Best-effort mkdir; an error usually just means the dir already exists.
        let _ = sftp.create_dir(&rdir).await;
        let mut rd = tokio::fs::read_dir(&ldir)
            .await
            .with_context(|| format!("read local dir {ldir}"))?;
        while let Some(entry) = rd.next_entry().await.context("read dir entry")? {
            let name = entry.file_name().to_string_lossy().to_string();
            let lpath = entry.path().to_string_lossy().to_string();
            let rchild = format!("{}/{}", rdir, name);
            let ft = entry.file_type().await.context("file type")?;
            if ft.is_dir() {
                stack.push((lpath, rchild));
            } else if ft.is_file() {
                let id = Uuid::new_v4().to_string();
                upload_pipelined(
                    handle,
                    tab_id,
                    &lpath,
                    &rchild,
                    &name,
                    &id,
                    events,
                    cancelled_transfers,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Pipelined SFTP upload (#16).
///
/// The high-level `SftpSession`/`File` writes one chunk and waits for the
/// server's ack before sending the next, so throughput is capped by the
/// round-trip time (~15x slower than scp on a latent link).  Here we open a
/// dedicated raw SFTP channel and keep many WRITE requests in flight at once
/// (each tagged with its absolute offset, so out-of-order completion is fine),
/// which hides the latency and brings us within a single order of magnitude of
/// native scp.
async fn upload_pipelined(
    handle: &client::Handle<SftpClientHandler>,
    tab_id: &str,
    local: &str,
    remote: &str,
    name: &str,
    id: &str,
    events: &UnboundedSender<SessionEvent>,
    cancelled_transfers: &Arc<Mutex<HashSet<String>>>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    const CHUNK: usize = 32 * 1024; // safe SFTP write size
    const MAX_INFLIGHT: usize = 32; // ~1 MB of outstanding writes hides the RTT

    let total = tokio::fs::metadata(local)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let mut local_file = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("open local {local}"))?;

    // Dedicated raw SFTP channel for the transfer (keeps the browse session
    // responsive and lets us issue concurrent WRITE requests).
    let channel = handle
        .channel_open_session()
        .await
        .context("open sftp upload channel")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("request sftp subsystem")?;
    let raw = Arc::new(RawSftpSession::new(channel.into_stream()));
    raw.init().await.context("sftp upload handshake")?;

    let fhandle = raw
        .open(
            remote,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            FileAttributes::default(),
        )
        .await
        .with_context(|| format!("create remote {remote}"))?
        .handle;

    emit_transfer(
        events, id, tab_id, name, local, remote, true, 0, total, 0, "",
    );

    let mut offset: u64 = 0;
    let mut done: u64 = 0;
    let mut last = Instant::now();
    let mut eof = false;
    let mut err: Option<anyhow::Error> = None;
    let mut inflight = FuturesUnordered::new();

    while !eof || !inflight.is_empty() {
        if transfer_cancelled(cancelled_transfers, id) {
            clear_cancelled_transfer(cancelled_transfers, id);
            let _ = raw.close(fhandle.clone()).await;
            emit_transfer(
                events,
                id,
                tab_id,
                name,
                local,
                remote,
                true,
                done,
                total,
                2,
                &t("已取消上传", "Upload cancelled"),
            );
            return Err(anyhow!(t("已取消上传", "upload cancelled")));
        }
        // Top up the pipeline with fresh WRITE requests.
        while !eof && inflight.len() < MAX_INFLIGHT {
            let mut buf = vec![0u8; CHUNK];
            match local_file.read(&mut buf).await {
                Ok(0) => eof = true,
                Ok(n) => {
                    buf.truncate(n);
                    let off = offset;
                    offset += n as u64;
                    let raw2 = raw.clone();
                    let h = fhandle.clone();
                    inflight.push(async move { raw2.write(h, off, buf).await.map(|_| n as u64) });
                }
                Err(e) => {
                    err = Some(anyhow!("read local file: {e}"));
                    eof = true;
                }
            }
        }
        match inflight.next().await {
            Some(Ok(n)) => {
                done += n;
                if last.elapsed() >= Duration::from_millis(150) {
                    last = Instant::now();
                    emit_transfer(
                        events, id, tab_id, name, local, remote, true, done, total, 0, "",
                    );
                }
            }
            Some(Err(e)) => {
                err = Some(anyhow!("write remote file: {e}"));
                eof = true; // stop reading more
            }
            None => {}
        }
        if err.is_some() {
            break;
        }
    }

    let _ = raw.close(fhandle).await;
    if let Some(e) = err {
        return Err(e);
    }
    emit_transfer(
        events,
        id,
        tab_id,
        name,
        local,
        remote,
        true,
        done,
        total.max(done),
        1,
        "",
    );
    clear_cancelled_transfer(cancelled_transfers, id);
    Ok(())
}

// ---------------------------------------------------------------------------
// russh client handler — verifies the host key against known_hosts, reusing the
// shell session's prompt path (#109-5). The UI de-duplicates by host:port, so a
// fresh host confirmed for the shell won't prompt again for SFTP.
// ---------------------------------------------------------------------------

struct SftpClientHandler {
    host: String,
    port: u16,
    events: UnboundedSender<SessionEvent>,
}

fn sftp_handler(session: &Session, events: &UnboundedSender<SessionEvent>) -> SftpClientHandler {
    SftpClientHandler {
        host: session.host.clone(),
        port: session.port,
        events: events.clone(),
    }
}

#[async_trait]
impl Handler for SftpClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(
            crate::ssh::verify_host_key(&self.host, self.port, server_public_key, &self.events)
                .await,
        )
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        _data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Keep format helpers and RemoteTreeNode imports live.
const _: fn() = || {
    let _ = format_size(0);
    let _ = format_mtime(0);
    let _: RemoteTreeNode;
};

#[cfg(test)]
mod sanitize_tests {
    use super::{remote_zip_error_message, sanitize_filename, shell_quote, temp_edit_filename};
    use crate::config::Session;

    #[test]
    fn plain_names_pass_through() {
        assert_eq!(sanitize_filename("report.txt"), "report.txt");
        assert_eq!(sanitize_filename("my-file_v2.tar.gz"), "my-file_v2.tar.gz");
        assert_eq!(sanitize_filename("数据.csv"), "数据.csv");
        // Unix dotfiles keep their leading dot.
        assert_eq!(sanitize_filename(".bashrc"), ".bashrc");
    }

    #[test]
    fn strips_path_separators_and_traversal() {
        // base_name already strips dirs, but sanitize is defence-in-depth: the
        // result must never keep a separator that could escape the target dir.
        assert_eq!(sanitize_filename("a/b\\c"), "a_b_c");
        let traversal = sanitize_filename("../../etc/passwd");
        assert!(!traversal.contains('/') && !traversal.contains('\\'));
        let win = sanitize_filename("..\\..\\Windows\\System32");
        assert!(!win.contains('/') && !win.contains('\\'));
    }

    #[test]
    fn replaces_shell_and_windows_special_chars() {
        assert_eq!(sanitize_filename("foo&calc.exe"), "foo_calc.exe");
        assert_eq!(sanitize_filename("a|b>c<d:e?f*g"), "a_b_c_d_e_f_g");
        assert_eq!(sanitize_filename("$(whoami)"), "_(whoami)");
        assert_eq!(sanitize_filename("a`b'c"), "a_b_c");
    }

    #[test]
    fn trims_whitespace_and_trailing_dots() {
        assert_eq!(sanitize_filename("   spaced.txt  "), "spaced.txt");
        assert_eq!(sanitize_filename("name..."), "name");
        // control chars become underscores, not trimmed
        assert_eq!(sanitize_filename("a\tb"), "a_b");
    }

    #[test]
    fn neutralises_windows_reserved_device_names() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("nul"), "_nul");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        assert_eq!(sanitize_filename("LPT9.txt"), "_LPT9.txt"); // reserved even with ext
        assert_eq!(sanitize_filename("Aux.log"), "_Aux.log");
        // Not reserved: a name that merely starts with the same letters.
        assert_eq!(sanitize_filename("console.txt"), "console.txt");
        assert_eq!(sanitize_filename("COM10"), "COM10");
    }

    #[test]
    fn empty_or_all_bad_falls_back() {
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename("   "), "file");
        assert_eq!(sanitize_filename("..."), "file");
    }

    #[test]
    fn edit_temp_filename_is_prefixed_by_session_label() {
        let mut session = Session::new_empty();
        session.name = "ss1".into();
        session.host = "10.0.0.1".into();
        assert_eq!(
            temp_edit_filename(&session, "/root/aaa.py", true),
            "ss1_aaa.py"
        );
        assert_eq!(
            temp_edit_filename(&session, "/root/aaa.py", false),
            "aaa.py"
        );
    }

    #[test]
    fn edit_temp_filename_falls_back_to_host_port() {
        let mut session = Session::new_empty();
        session.host = "10.0.0.8".into();
        session.port = 2222;
        assert_eq!(
            temp_edit_filename(&session, "/tmp/aaa.py", true),
            "10.0.0.8_2222_aaa.py"
        );
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("/tmp/a b"), "'/tmp/a b'");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn remote_zip_errors_are_human_readable() {
        assert!(remote_zip_error_message(127, "zip command not found").contains("zip"));
        assert!(
            remote_zip_error_message(3, "zip I/O error: No space left on device")
                .contains("磁盘空间不足")
        );
        assert!(remote_zip_error_message(3, "Disk quota exceeded").contains("磁盘空间不足"));
    }
}
