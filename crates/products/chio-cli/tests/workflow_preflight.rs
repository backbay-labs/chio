use chio_test_support::prelude::*;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

fn fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/workflow-preflight/{case_name}/preflight-plan.json"
    ))
}

fn write_json(path: &std::path::Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).test_expect("serialize preflight fixture");
    std::fs::write(path, bytes).test_expect("write preflight fixture");
}

#[test]
fn workflow_preflight_cli_accepts_planning_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(fixture_path("valid-child-scope"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.workflow.preflight-report.v1\""));
    assert!(stdout.contains("\"verdict\":\"accepted\""));
    assert!(stdout.contains("\"evidence_class\":\"planning\""));
    assert!(stdout.contains("\"live_authority_claims\":[]"));
}

#[test]
fn workflow_preflight_cli_rejects_broader_child_scope() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(fixture_path("broader-child-scope"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("workflow preflight rejected"));
    assert!(stderr.contains("payment.capture"));
}

#[test]
fn workflow_preflight_json_reports_rejected_checks() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("--json")
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(fixture_path("broader-child-scope"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("rejected preflight report parses");
    assert_eq!(report["schema"], "chio.workflow.preflight-report.v1");
    assert_eq!(report["verdict"], "rejected");
    assert!(report["rejected_checks"]
        .as_array()
        .test_expect("rejected checks array")
        .iter()
        .any(|check| check["code"] == "workflow_preflight_child_scope_exceeds_parent"));
}

#[test]
fn workflow_preflight_cli_rejects_planning_artifact_claiming_authority() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(fixture_path("planning-artifact-claims-authority"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("workflow preflight rejected"));
    assert!(stderr.contains("cannot satisfy live authority claims"));
}

#[test]
fn workflow_preflight_cli_rejects_conflicting_route_evidence() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let plan_path = tempdir.path().join("preflight-plan.json");
    let mut plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture_path("valid-child-scope")).test_expect("read plan"),
    )
    .test_expect("parse plan");
    plan["id"] = serde_json::Value::String("workflow-preflight-conflicting-route".to_string());
    plan["route_plans"] = serde_json::json!([
        {
            "route_ref": "route-local-market",
            "supported": false
        },
        {
            "route_ref": "route-local-market",
            "supported": true
        }
    ]);
    write_json(&plan_path, &plan);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(&plan_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("workflow preflight rejected"));
    assert!(stderr.contains("route ref route-local-market has conflicting support entries"));
}

#[test]
fn workflow_preflight_cli_rejects_conflicting_approval_evidence() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let plan_path = tempdir.path().join("preflight-plan.json");
    let mut plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture_path("valid-child-scope")).test_expect("read plan"),
    )
    .test_expect("parse plan");
    plan["id"] = serde_json::Value::String("workflow-preflight-conflicting-approval".to_string());
    plan["approvals"] = serde_json::json!([
        {
            "approval_ref": "approval-commerce-owner",
            "status": "rejected"
        },
        {
            "approval_ref": "approval-commerce-owner",
            "status": "approved"
        }
    ]);
    write_json(&plan_path, &plan);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(&plan_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("workflow preflight rejected"));
    assert!(stderr.contains("approval ref approval-commerce-owner has conflicting status entries"));
}

#[test]
fn workflow_preflight_cli_rejects_parent_budget_over_pool() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let plan_path = tempdir.path().join("preflight-plan.json");
    let mut plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture_path("valid-child-scope")).test_expect("read plan"),
    )
    .test_expect("parse plan");
    plan["id"] =
        serde_json::Value::String("workflow-preflight-parent-budget-over-pool".to_string());
    plan["parent_task"]["scope"]["budget_minor"] = serde_json::Value::Number(6000.into());
    plan["budget_pool"]["total_minor"] = serde_json::Value::Number(5000.into());
    plan["child_tasks"][0]["requested_scope"]["budget_minor"] =
        serde_json::Value::Number(3000.into());
    write_json(&plan_path, &plan);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("workflow")
        .arg("preflight")
        .arg("--plan")
        .arg(&plan_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("workflow preflight rejected"));
    assert!(stderr.contains("parent task budget 6000 exceeds budget pool 5000"));
}
