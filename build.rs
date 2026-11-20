fn main() {
    // Bundle the gettext `.po` translations under `lang/` so the UI's `@tr(...)`
    // strings can switch language at runtime via slint::select_bundled_translation.
    // Source language is Chinese (the msgids); `lang/<lc>/LC_MESSAGES/xiaoxingshell.po`
    // provides other locales.  No per-component context, so msgids are the raw
    // Chinese strings.
    println!("cargo:rerun-if-changed=lang");
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new()
            .with_style("fluent".into())
            .with_bundled_translations("lang")
            .with_default_translation_context(slint_build::DefaultTranslationContext::None),
    )
    .expect("Slint build failed");

    // Embed the application icon into the Windows executable so it shows up in
    // Explorer, the taskbar and shortcuts. No-op on non-Windows targets.
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/xiaoxingshell.ico");
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/xiaoxingshell.ico");
        res.set("FileDescription", "xiaoxingshell");
        res.set("ProductName", "xiaoxingshell");
        res.set("InternalName", "xiaoxingshell");
        res.set("OriginalFilename", "xiaoxingshell.exe");
        res.set("CompanyName", "xiaoxing");
        res.set("LegalCopyright", "Copyright © 2026 xiaoxing");
        // winresource looks the Windows SDK up in the registry (spawning
        // reg.exe). Sandboxed / locked-down build environments block that, the
        // lookup fails, and the icon is silently dropped with
        // "系统找不到指定的路径 (os error 3)" — the exe then ships without an
        // icon. Point it straight at the newest installed SDK bin dir.
        if let Some(bin) = windows_sdk_bin_dir() {
            res.set_toolkit_path(&bin);
        }
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows icon: {e}");
        }
    }
}

/// Newest `…\Windows Kits\10\bin\<version>\x64` directory that contains `rc.exe`,
/// or `None` when the SDK is not installed (the icon is then skipped).
#[cfg(windows)]
fn windows_sdk_bin_dir() -> Option<String> {
    let root = std::path::Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut best: Option<(Vec<u32>, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let version: Vec<u32> = name.split('.').filter_map(|p| p.parse().ok()).collect();
        if version.len() != 4 {
            continue;
        }
        let bin = entry.path().join("x64");
        if !bin.join("rc.exe").exists() {
            continue;
        }
        if best.as_ref().map(|(v, _)| version > *v).unwrap_or(true) {
            best = Some((version, bin));
        }
    }
    best.map(|(_, p)| p.to_string_lossy().into_owned())
}
