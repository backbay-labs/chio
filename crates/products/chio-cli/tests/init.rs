#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-cli-init-{}-{nonce}-{counter}",
        std::process::id()
    ))
}

#[test]
fn init_creates_expected_project_files() {
    let project_dir = unique_test_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");

    assert!(
        output.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for path in [
        project_dir.join("Cargo.toml"),
        project_dir.join("README.md"),
        project_dir.join("policy.yaml"),
        project_dir.join(".gitignore"),
        project_dir.join("src/bin/hello_server.rs"),
        project_dir.join("src/bin/demo.rs"),
    ] {
        assert!(path.exists(), "expected scaffold file `{}`", path.display());
    }

    let readme = fs::read_to_string(project_dir.join("README.md")).expect("read scaffold readme");
    assert!(readme.contains("cargo build"));
    assert!(readme.contains("cargo run --quiet --bin demo"));

    let cargo_toml =
        fs::read_to_string(project_dir.join("Cargo.toml")).expect("read scaffold manifest");
    assert!(cargo_toml.contains("[package]"));
    assert!(!cargo_toml.contains("{{PACKAGE_NAME}}"));
}

#[test]
fn scaffolded_demo_runs_governed_hello_flow() {
    let project_dir = unique_test_dir();
    let init = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");
    assert!(
        init.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let cargo_target_dir = project_dir.join(".chio-test-target");
    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(project_dir.join("Cargo.toml"))
        .arg("--bin")
        .arg("demo")
        .arg("--")
        .arg("Codex")
        .env("CHIO_BIN", env!("CARGO_BIN_EXE_chio"))
        .env("CARGO_TARGET_DIR", &cargo_target_dir)
        .output()
        .expect("run scaffold demo");

    assert!(
        output.status.success(),
        "scaffold demo failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello, Codex! This call was mediated by Chio."));
    assert!(stdout.contains("latest receipt:"));
    assert!(project_dir.join(".chio/receipts.db").exists());
}
