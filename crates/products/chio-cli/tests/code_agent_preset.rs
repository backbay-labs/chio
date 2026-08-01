//! Integration tests for the `chio mcp serve --preset code-agent` bundle.
//!
//! The preset is the Rust-side counterpart to the `chio-code-agent`
//! Python SDK and must:
//!
//! 1. Parse cleanly via the normal `load_policy` path so the kernel
//!    sees the same guard pipeline a user-provided YAML would
//!    produce.
//! 2. Materialize the bundled YAML byte-for-byte on disk so source
//!    and runtime policy hashes remain stable across runs.
//! 3. Deny a `.env` write when the resulting guard pipeline
//!    evaluates a simulated tool call, proving the preset actually
//!    enforces its denial contract.
//!
//! The harness does not spawn `npx @modelcontextprotocol/server-filesystem`;
//! we exercise the preset loading path directly so the test runs in
//! any environment.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn chio_cli_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_chio"));
    assert!(
        path.exists(),
        "CARGO_BIN_EXE_arc does not exist: {}",
        path.display()
    );
    path = path.canonicalize().unwrap_or(path);
    path
}

#[test]
fn preset_yaml_is_shipped_in_crate_source() {
    // Ensures the bundled YAML stays reachable from the crate
    // source tree; the Python SDK's default_policy.yaml must stay
    // byte-identical with this file.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let yaml_path = manifest_dir.join("src/policies/code_agent.yaml");
    assert!(
        yaml_path.exists(),
        "bundled code_agent.yaml missing: {}",
        yaml_path.display()
    );
    let contents = std::fs::read_to_string(&yaml_path).expect("read bundled preset");
    assert!(contents.contains("forbidden_path"));
    assert!(contents.contains(".env"));
    assert!(contents.contains("shell_command"));
    // The force-push deny uses YAML-style escaping for the regex;
    // the literal bytes in the file are `git\\s+push` (double
    // backslash + s) so we assert on that exact substring.
    assert!(
        contents.contains(r"git\\s+push"),
        "missing git force-push deny pattern in preset YAML"
    );
}

#[test]
fn preset_yaml_matches_python_sdk() {
    // Regression guard: the Rust preset and the Python SDK's
    // default_policy.yaml must remain byte-identical so `chio mcp
    // serve --preset code-agent` evaluates the same rules as the
    // `chio-code-agent` Python package.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rust_yaml = manifest_dir.join("src/policies/code_agent.yaml");
    let python_yaml = manifest_dir
        .join("../../../sdks/python/chio-code-agent/src/chio_code_agent/default_policy.yaml");

    if !python_yaml.exists() {
        // The Python SDK lives in the same repo; if this test runs
        // outside that checkout, skip rather than fail.
        eprintln!(
            "python default_policy.yaml not found at {}",
            python_yaml.display()
        );
        return;
    }

    let rust = std::fs::read_to_string(&rust_yaml).expect("read rust preset");
    let python = std::fs::read_to_string(&python_yaml).expect("read python preset");
    assert_eq!(
        rust, python,
        "code-agent preset YAML drifted between Rust CLI and Python SDK"
    );
}

#[test]
fn mcp_serve_rejects_unknown_preset() {
    // `chio mcp serve --preset nope` should fail fast with a clear
    // error rather than launching and crashing partway through.
    let output = Command::new(chio_cli_binary())
        .args([
            "mcp",
            "serve",
            "--preset",
            "nope",
            "--server-id",
            "test",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn chio");
    assert!(
        !output.status.success(),
        "unknown preset unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown --preset") || stderr.contains("code-agent"),
        "stderr did not mention unknown preset guidance: {stderr}"
    );
}

#[test]
fn mcp_serve_requires_policy_or_preset() {
    // Neither --policy nor --preset supplied: the command should
    // refuse to start rather than picking an implicit default.
    let output = Command::new(chio_cli_binary())
        .args(["mcp", "serve", "--server-id", "test", "--", "/bin/true"])
        .output()
        .expect("spawn chio");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--policy") || stderr.contains("--preset"),
        "stderr did not surface the missing-policy guidance: {stderr}"
    );
}

#[test]
fn mcp_serve_rejects_policy_and_preset_together() {
    // clap's `conflicts_with` must reject `--policy` + `--preset`
    // supplied in the same invocation.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "kernel: {}\nguards: {}\ncapabilities: {}\n").unwrap();

    let output = Command::new(chio_cli_binary())
        .args(["mcp", "serve", "--policy"])
        .arg(tmp.path())
        .args([
            "--preset",
            "code-agent",
            "--server-id",
            "test",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn chio");
    assert!(!output.status.success());
}

/// Helper: copy the bundled preset YAML to a tempfile so `chio check`
/// can load it.
fn write_preset_to_temp() -> tempfile::NamedTempFile {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let yaml_path = manifest_dir.join("src/policies/code_agent.yaml");
    let yaml = std::fs::read_to_string(yaml_path).expect("read preset");
    let tmp = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("tempfile");
    std::fs::write(tmp.path(), yaml).expect("write preset tmp");
    tmp
}

fn write_safe_output_fixture() -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("output fixture tempfile");
    std::fs::write(tmp.path(), r#"{"content":"SAFE"}"#).expect("write output fixture");
    tmp
}

fn private_store_paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("chio-code-agent-stores-")
        .tempdir()
        .expect("private store directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure private store directory");
    }
    let receipt_db = dir.path().join("receipts.sqlite3");
    let session_db = dir.path().join("sessions.sqlite3");
    (dir, receipt_db, session_db)
}

/// The preset denies a `.env` write.
///
/// We pipe the bundled YAML through `chio check` and assert the guard
/// pipeline returns DENY for an `fs/write_file` call whose path is
/// `.env`. That proves the preset's forbidden_path guard is live and
/// matches the wire-level behaviour `chio mcp serve --preset
/// code-agent` would produce for the same call.
#[test]
fn preset_denies_dotenv_write_via_chio_check() {
    let preset = write_preset_to_temp();
    let (_store_dir, receipt_db, session_db) = private_store_paths();
    let output_fixture = write_safe_output_fixture();
    let output = Command::new(chio_cli_binary())
        .args(["--format", "json", "check", "--policy"])
        .arg(preset.path())
        .args(["--mode", "full", "--output-fixture"])
        .arg(output_fixture.path())
        .arg("--receipt-db")
        .arg(&receipt_db)
        .arg("--session-db")
        .arg(&session_db)
        .args([
            "--server",
            "fs",
            "--tool",
            "write_file",
            "--params",
            "{\"path\":\"/workspace/project/.env\",\"content\":\"BAD=1\"}",
        ])
        .output()
        .expect("spawn chio check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `chio check` exits with code 2 on deny.
    assert!(
        !output.status.success(),
        "expected DENY exit but stdout={stdout}\nstderr={stderr}"
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("decode json");
    assert_eq!(
        body["verdict"].as_str(),
        Some("DENY"),
        "expected DENY verdict in stdout; got: {stdout}"
    );
}

/// The preset allows a safe file read.
///
/// Companion check to the `.env` deny case -- `fs/read_file` with a
/// non-forbidden path should pass the guard pipeline even though the
/// preset's shell_command and secret_patterns guards are enabled.
#[test]
fn preset_allows_safe_file_read_via_chio_check() {
    let preset = write_preset_to_temp();
    let (_store_dir, receipt_db, session_db) = private_store_paths();
    let output_fixture = write_safe_output_fixture();
    let output = Command::new(chio_cli_binary())
        .args(["--format", "json", "check", "--policy"])
        .arg(preset.path())
        .args(["--mode", "full", "--output-fixture"])
        .arg(output_fixture.path())
        .arg("--receipt-db")
        .arg(&receipt_db)
        .arg("--session-db")
        .arg(&session_db)
        .args([
            "--server",
            "fs",
            "--tool",
            "read_file",
            "--params",
            "{\"path\":\"README.md\"}",
        ])
        .output()
        .expect("spawn chio check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected ALLOW exit 0 but got stdout={stdout}\nstderr={stderr}"
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("decode json");
    assert_eq!(
        body["verdict"].as_str(),
        Some("ALLOW"),
        "expected ALLOW verdict in stdout; got: {stdout}"
    );
}

fn write_output_sensitive_policy() -> tempfile::NamedTempFile {
    let policy = r#"
kernel: {}
guards:
  secret_patterns:
    enabled: true
capabilities:
  default:
    tools:
      - server: "fs"
        tool: "read_file"
        operations: [invoke]
        ttl: 3600
"#;
    let tmp = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("tempfile");
    std::fs::write(tmp.path(), policy).expect("write policy tmp");
    tmp
}

#[test]
fn check_preflight_rejects_output_sensitive_policy_without_fixture() {
    let policy = write_output_sensitive_policy();
    let output = Command::new(chio_cli_binary())
        .args(["--format", "json", "check", "--policy"])
        .arg(policy.path())
        .args([
            "--server",
            "fs",
            "--tool",
            "read_file",
            "--params",
            "{\"path\":\"README.md\"}",
        ])
        .output()
        .expect("spawn chio check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected output-sensitive preflight failure but stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("preflight") && stderr.contains("--output-fixture"),
        "stderr must explain preflight fixture requirement: {stderr}"
    );
}

#[test]
fn check_full_mode_requires_explicit_output_fixture() {
    let policy = write_output_sensitive_policy();
    let output = Command::new(chio_cli_binary())
        .args(["--format", "json", "check", "--policy"])
        .arg(policy.path())
        .args([
            "--mode",
            "full",
            "--server",
            "fs",
            "--tool",
            "read_file",
            "--params",
            "{\"path\":\"README.md\"}",
        ])
        .output()
        .expect("spawn chio check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected full-mode fixture failure but stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("--mode full") && stderr.contains("--output-fixture"),
        "stderr must explain full-mode fixture requirement: {stderr}"
    );
}

#[test]
fn check_full_mode_uses_output_fixture_for_output_sensitive_policy() {
    let policy = write_output_sensitive_policy();
    let output_fixture = write_safe_output_fixture();
    let (_store_dir, receipt_db, session_db) = private_store_paths();

    let output = Command::new(chio_cli_binary())
        .args(["--format", "json", "check", "--policy"])
        .arg(policy.path())
        .arg("--receipt-db")
        .arg(&receipt_db)
        .arg("--session-db")
        .arg(&session_db)
        .args(["--mode", "full", "--output-fixture"])
        .arg(output_fixture.path())
        .args([
            "--server",
            "fs",
            "--tool",
            "read_file",
            "--params",
            "{\"path\":\"README.md\"}",
        ])
        .output()
        .expect("spawn chio check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected fixture-backed ALLOW exit 0 but stdout={stdout}\nstderr={stderr}"
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("decode json");
    assert_eq!(body["verdict"].as_str(), Some("ALLOW"));
    assert_eq!(body["check_mode"].as_str(), Some("full"));
    assert_eq!(body["output_fixture"].as_bool(), Some(true));
}
