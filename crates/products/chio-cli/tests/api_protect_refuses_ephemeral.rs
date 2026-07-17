//! The sidecar refuses to boot without a durable receipt store unless ephemeral
//! receipts are explicitly opted in, so a manifest that forgets `--receipt-store`
//! fails loudly at startup instead of silently losing audit evidence.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn api_protect_refuses_ephemeral_without_optin() {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "api",
            "protect",
            "--upstream",
            "http://127.0.0.1:8080",
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .expect("run chio api protect");

    assert!(
        !output.status.success(),
        "must exit non-zero without --receipt-store or --allow-ephemeral-receipts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to start") && stderr.contains("--allow-ephemeral-receipts"),
        "expected the durable-receipts gate message, got: {stderr}"
    );
}

#[test]
fn api_protect_ephemeral_optin_bypasses_the_gate() {
    // With the opt-in the gate passes and the process proceeds to boot, so we
    // only assert that the gate did not reject it (the process is killed before
    // it can settle into its accept loop).
    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "api",
            "protect",
            "--upstream",
            "http://127.0.0.1:8080",
            "--listen",
            "127.0.0.1:0",
            "--allow-ephemeral-receipts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio api protect");

    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let output = child.wait_with_output().expect("wait for chio api protect");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("refusing to start"),
        "the ephemeral opt-in must bypass the gate, got: {stderr}"
    );
}
