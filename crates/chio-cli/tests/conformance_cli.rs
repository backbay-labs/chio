#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration coverage for `chio conformance run`.
//!
//! Snapshots the `--help` output and (when Python 3.11+ is available) drives
//! the live harness against the Python peer adapter and snapshots the JSON
//! report shape. Live portions are skipped when peers are unavailable.

use std::path::PathBuf;
use std::process::Command;

use insta::{assert_json_snapshot, assert_snapshot};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn python3_supports_chio_sdk() -> bool {
    let Ok(output) = Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let mut parts = version.trim().split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (3, 11)
}

/// Snapshot `chio conformance run --help` so flag-surface drift appears in
/// review.
#[test]
fn conformance_run_help_shape_is_stable() {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("conformance")
        .arg("run")
        .arg("--help")
        .output()
        .expect("spawn chio conformance run --help");
    assert!(
        output.status.success(),
        "`chio conformance run --help` failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let help_text = String::from_utf8(output.stdout).expect("help text is utf8");
    assert_snapshot!("conformance_run_help", help_text);
}

/// Drive the live harness against the Python peer and snapshot the JSON report
/// shape. Silently skips when Python 3.11+ is unavailable or
/// `CHIO_SKIP_CONFORMANCE_LIVE` is set.
#[test]
fn conformance_run_python_report_shape_is_stable() {
    if std::env::var_os("CHIO_SKIP_CONFORMANCE_LIVE").is_some() {
        return;
    }
    if !python3_supports_chio_sdk() {
        return;
    }

    // Hermetic output path so concurrent test invocations don't collide.
    let scratch = TempDir::new().expect("create scratch tempdir");
    let report_path = scratch.path().join("report.json");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("conformance")
        .arg("run")
        .arg("--peer")
        .arg("python")
        .arg("--report")
        .arg("json")
        .arg("--output")
        .arg(&report_path)
        .output()
        .expect("spawn chio conformance run");
    assert!(
        output.status.success(),
        "`chio conformance run --peer python` failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = std::fs::read_to_string(&report_path).expect("read report file");
    let report: serde_json::Value = serde_json::from_str(&raw).expect("report is json");

    // Hard assertion: all 5 scenarios must be present and green. The
    // snapshot below proves the *shape* is stable; this proves the *content*
    // is correct (no silent regressions in pass/fail detection).
    let results = report
        .get("results")
        .and_then(serde_json::Value::as_array)
        .expect("results array");
    assert_eq!(results.len(), 5, "expected 5 mcp-core scenarios");
    let pass_count = results
        .iter()
        .filter(|result| result.get("status").and_then(serde_json::Value::as_str) == Some("pass"))
        .count();
    assert_eq!(
        pass_count, 5,
        "expected 5/5 scenarios green, got {pass_count}/5; results={results:#?}",
    );
    assert_eq!(
        report
            .get("scenarioCount")
            .and_then(serde_json::Value::as_u64),
        Some(5),
    );
    assert_eq!(
        report
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("chio-conformance-run/v1"),
    );

    // Snapshot the report's shape with redactions for fields that vary
    // run-to-run: the ephemeral listen port, every absolute filesystem
    // path, and the wall-clock scenario duration. The snapshot then
    // captures the stable envelope keys, the schema version, and the
    // structural shape of each scenario result.
    assert_json_snapshot!(
        "conformance_run_python_report",
        report,
        {
            ".listen" => "[listen-addr]",
            ".resultsDir" => "[results-dir]",
            ".reportOutput" => "[report-output]",
            ".peerResultFiles" => "[peer-result-files]",
            ".results[].durationMs" => "[duration-ms]",
            ".results[].artifacts.transcript" => "[transcript-path]",
        }
    );
}
