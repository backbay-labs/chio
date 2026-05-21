use std::process::Command;

#[test]
fn legacy_chiodos_env_does_not_allow_direct_command_execution() {
    let scratch = match tempfile::TempDir::new() {
        Ok(scratch) => scratch,
        Err(error) => panic!("create scratch tempdir: {error}"),
    };
    let report_path = scratch.path().join("legacy-report.json");

    let output = match Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_ENABLE_LEGACY_CHIODOS_CLI", "1")
        .arg("chiodos")
        .arg("verify")
        .arg("--package")
        .arg(scratch.path().join("missing-package.json"))
        .arg("--trust-bundle")
        .arg(scratch.path().join("missing-trust-bundle.json"))
        .arg("--context")
        .arg(scratch.path().join("missing-context.json"))
        .arg("--report")
        .arg(&report_path)
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("spawn chio chiodos verify: {error}"),
    };

    assert_eq!(
        output.status.code(),
        Some(2),
        "legacy command should be rejected before dispatch; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("legacy `chio chiodos` command execution is disabled"),
        "expected execution guard error, got stderr={stderr}",
    );
    assert!(
        !report_path.exists(),
        "legacy command guard must not create verifier reports",
    );
}

#[test]
fn legacy_chiodos_env_still_allows_hidden_help_inspection() {
    let output = match Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_ENABLE_LEGACY_CHIODOS_CLI", "1")
        .arg("chiodos")
        .arg("help")
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("spawn chio chiodos help: {error}"),
    };

    assert!(
        output.status.success(),
        "env-gated legacy help should remain inspectable; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "expected help text, got stdout={stdout}",
    );
}
