#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn trust_serve_help_advertises_service_token_env_without_value() {
    let secret = "trust-serve-help-secret";
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["trust", "serve", "--help"])
        .env("CHIO_TRUST_SERVICE_TOKEN", secret)
        .output()
        .expect("spawn chio trust serve --help");

    assert!(
        output.status.success(),
        "trust serve --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("help output is utf8");
    assert!(
        stdout.contains("CHIO_TRUST_SERVICE_TOKEN"),
        "expected service token env var in help: {stdout}"
    );
    assert!(
        !stdout.contains(secret),
        "service token env value leaked in help: {stdout}"
    );
}
