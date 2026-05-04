#![allow(clippy::expect_used)]

use std::process::Command;

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
