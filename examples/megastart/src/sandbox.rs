//! Constrain generated test binaries to their candidate directory on macOS.
use anyhow::{Context, Result};
use std::{path::Path, process::Stdio};
use tokio::process::Command;

pub fn available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file()
}

pub fn command(binary: &Path, directory: &Path) -> Result<Command> {
    anyhow::ensure!(
        available(),
        "Model execution requires the macOS sandbox executor; use reference mode on this platform"
    );
    let root = directory.canonicalize()?;
    let root = root.to_str().context("Workspace must be UTF-8")?;
    anyhow::ensure!(
        !root.contains(['"', '\\', '\n']),
        "Workspace path cannot be represented by the sandbox policy"
    );
    let toolchain = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .context("HOME is required for the Rust toolchain")?
        .join(".rustup/toolchains");
    let toolchain = toolchain.to_str().context("Toolchain path must be UTF-8")?;
    anyhow::ensure!(
        !toolchain.contains(['"', '\\', '\n']),
        "Invalid toolchain path"
    );
    let fork_policy = if binary.starts_with(directory) {
        "(deny process-fork)"
    } else {
        ""
    };
    let profile = format!("(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow file-read-metadata)(allow file-map-executable)(allow file-read* (literal \"/\") (subpath \"/System\") (subpath \"/usr\") (subpath \"{toolchain}\") (subpath \"/Library\") (subpath \"/Applications/Xcode.app\") (subpath \"/private/var/db/dyld\") (subpath \"{root}\") (literal \"/dev/null\") (literal \"/dev/urandom\"))(allow file-write* (subpath \"{root}\") (literal \"/dev/null\")){fork_policy}");
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(binary)
        .env_clear()
        .stdin(Stdio::null());
    Ok(command)
}
