use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn wasm_path(artifact_name: &str) -> PathBuf {
    repo_root()
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{artifact_name}.wasm"))
}

pub fn load_rust_example_wasm(package_name: &str, artifact_name: &str) -> Vec<u8> {
    let path = wasm_path(artifact_name);
    if !path.exists() {
        let _guard = build_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !path.exists() {
            build_rust_example(package_name);
        }
    }

    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "Rust guard WASM not found at {}: {err}. Build with: cargo build --target wasm32-unknown-unknown --release -p {package_name}",
            path.display()
        )
    })
}

fn build_rust_example(package_name: &str) {
    let root = repo_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            package_name,
        ])
        .status()
        .unwrap_or_else(|err| {
            panic!("failed to build {package_name} for wasm32-unknown-unknown: {err}")
        });

    if !status.success() {
        panic!("cargo build failed for {package_name} with status {status}");
    }
}
