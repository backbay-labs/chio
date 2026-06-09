#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn chio_wall_control_path_export_writes_bounded_package() {
    let output_dir = unique_path("chio-wall-export");

    let output = Command::new(env!("CARGO_BIN_EXE_chio-wall"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("control-path")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run chio-wall control-path export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse export summary");
    assert_eq!(summary["workflowId"], "workflow-information-domain-barrier");
    assert_eq!(summary["buyerMotion"], "control_room_barrier_review");
    assert_eq!(summary["controlSurface"], "tool_access_domain_boundary");
    assert_eq!(summary["sourceDomain"], "research");
    assert_eq!(summary["requestedDomain"], "execution");

    for relative_path in [
        "control-profile.json",
        "policy-snapshot.json",
        "authorization-context.json",
        "guard-outcome.json",
        "denied-access-record.json",
        "buyer-review-package.json",
        "control-package.json",
        "control-path-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }
    assert!(
        output_dir.join("chio-evidence").exists(),
        "expected chio-evidence dir"
    );

    let package: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("control-package.json")).expect("read"))
            .expect("parse control package");
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["buyerMotion"], "control_room_barrier_review");
    assert_eq!(package["controlSurface"], "tool_access_domain_boundary");
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 7);

    let guard_outcome: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("guard-outcome.json")).expect("read guard outcome"),
    )
    .expect("parse guard outcome");
    assert_eq!(guard_outcome["decision"], "deny");
    assert_eq!(guard_outcome["guardName"], "mcp-tool");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn chio_wall_control_path_validate_writes_report_and_decision() {
    let output_dir = unique_path("chio-wall-validate");

    let output = Command::new(env!("CARGO_BIN_EXE_chio-wall"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("control-path")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run chio-wall control-path validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse validation report");
    assert_eq!(report["workflowId"], "workflow-information-domain-barrier");
    assert_eq!(report["decision"], "proceed_chio_wall_only");
    assert_eq!(report["buyerMotion"], "control_room_barrier_review");
    assert_eq!(report["controlSurface"], "tool_access_domain_boundary");
    assert_eq!(
        report["docs"]["operationsFile"],
        "docs/chio-wall/OPERATIONS.md"
    );

    for relative_path in [
        "control-path/control-package.json",
        "control-path/buyer-review-package.json",
        "control-path/guard-outcome.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read decision"),
    )
    .expect("parse decision");
    assert_eq!(decision["decision"], "proceed_chio_wall_only");
    assert_eq!(
        decision["selectedBuyerMotion"],
        "control_room_barrier_review"
    );
    assert_eq!(
        decision["selectedControlSurface"],
        "tool_access_domain_boundary"
    );
    assert!(decision["deferredScope"]
        .as_array()
        .expect("deferred scope")
        .iter()
        .any(|item| item.as_str() == Some("generic barrier-platform breadth")));

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn chio_wall_control_path_export_rejects_non_empty_output_dir() {
    let output_dir = unique_path("chio-wall-export-non-empty");
    fs::create_dir_all(&output_dir).expect("create output dir");
    fs::write(output_dir.join("sentinel.txt"), b"occupied").expect("write sentinel");

    let output = Command::new(env!("CARGO_BIN_EXE_chio-wall"))
        .current_dir(workspace_root())
        .arg("control-path")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run chio-wall control-path export");

    assert!(!output.status.success(), "expected export to fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("output directory must be empty")
            || stdout.contains("output directory must be empty"),
        "stdout={stdout}\nstderr={stderr}"
    );

    let _ = fs::remove_dir_all(output_dir);
}
