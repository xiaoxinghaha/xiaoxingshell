// Entry point. Wires the Slint UI to the config store, system sampler and
// SSH session manager.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod errlog;
mod forward;
mod i18n;
mod known_hosts;
mod proxy;
mod serial;
mod sftp;
mod ssh;
mod ssh_config;
mod system;
mod telnet;
mod zmodem;

fn main() -> anyhow::Result<()> {
    init_tracing();

    // ── IME policy ───────────────────────────────────────────────────────────
    // NOTE: We deliberately DO **NOT** call `ImmDisableIME` here.
    //
    // An earlier version disabled the IME for the whole Slint event-loop thread
    // to work around a vim `:q!` glitch (Chinese IMEs intercept letter keys and,
    // on a Shift press, discard the in-flight pinyin).  But disabling the IME
    // also makes 中文输入 completely impossible — there is no composition window
    // at all, which is exactly the "无法输入任何中文" bug.
    //
    // Chinese input now flows through the hidden `ime-input` TextInput in
    // terminal_view.slint: composition happens there, and committed text is
    // forwarded to the PTY via the `edited` callback.  The vim/Shift side-effects
    // are handled instead by the C0-marker + 3-layer Backspace filters in
    // `app::on_send_key`, so we no longer need (and must not use) ImmDisableIME.

    app::run()
}

/// Set up tracing: stderr (honours RUST_LOG, default info) **plus** a capped
/// `error.log` file at WARN and above so users can send diagnostics — e.g. a
/// bastion disconnect reason — without setting RUST_LOG (#86).
fn init_tracing() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(env_filter);

    // One file, capped at 5 MiB, auto-overwriting when full.
    let file_layer = errlog::path()
        .and_then(|p| errlog::CappedFile::open(p, 5 * 1024 * 1024).ok())
        .map(|cf| {
            fmt::layer()
                .with_ansi(false)
                .with_writer(errlog::CappedWriter::new(cf))
                .with_filter(LevelFilter::WARN)
        });

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .init();
}
