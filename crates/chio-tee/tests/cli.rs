#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn skeleton_binary_help_exits_successfully() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let output = Command::new(binary)
        .arg("--help")
        .output()
        .expect("run chio-tee binary");

    assert!(output.status.success(), "--help must be image-smoke safe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: chio-tee"),
        "stdout should include usage text: {stdout}"
    );
}

#[test]
fn skeleton_binary_exits_nonzero_until_runtime_is_implemented() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let output = Command::new(binary).output().expect("run chio-tee binary");

    assert!(
        !output.status.success(),
        "skeleton binary must fail closed instead of reporting success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not yet implemented"),
        "stderr should explain that the runtime is unavailable: {stderr}"
    );
}
