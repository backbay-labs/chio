#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::evidence_export;
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_kernel::build_checkpoint;
use chio_mercury_core::{
    sample_mercury_bundle_manifest, sample_mercury_receipt_metadata, MercurySupervisedLiveCapture,
    MercurySupervisedLiveCoverageState, MercurySupervisedLiveHealthStatus,
    MercurySupervisedLiveInterruptKind, MercurySupervisedLiveInterruption,
    MercurySupervisedLiveMode,
};
use chio_store_sqlite::SqliteReceiptStore;

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn mercury_receipt_with_ts(
    id: &str,
    capability_id: &str,
    timestamp: u64,
    keypair: &Keypair,
) -> ChioReceipt {
    let metadata = sample_mercury_receipt_metadata()
        .into_receipt_metadata_value()
        .expect("mercury metadata value");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "mercury".to_string(),
            tool_name: "release_control".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd":"release candidate"}))
                .expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .expect("sign mercury receipt")
}

fn write_mercury_bundle_manifest(path: &Path) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&sample_mercury_bundle_manifest()).expect("bundle manifest"),
    )
    .expect("write bundle manifest");
}

fn write_supervised_live_capture(path: &Path, mode: MercurySupervisedLiveMode) {
    let capture = MercurySupervisedLiveCapture::sample(mode);
    fs::write(
        path,
        serde_json::to_vec_pretty(&capture).expect("supervised live capture"),
    )
    .expect("write supervised live capture");
}

fn write_degraded_supervised_live_capture(path: &Path) {
    let mut capture = MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live);
    capture.control_state.coverage_state = MercurySupervisedLiveCoverageState::Degraded;
    capture.control_state.evidence_health.monitoring = MercurySupervisedLiveHealthStatus::Degraded;
    capture
        .control_state
        .interruptions
        .push(MercurySupervisedLiveInterruption {
            kind: MercurySupervisedLiveInterruptKind::MonitoringIssue,
            incident_id: "incident-monitoring-1".to_string(),
            summary: "Monitoring degraded; supervised-live export paused.".to_string(),
        });
    fs::write(
        path,
        serde_json::to_vec_pretty(&capture).expect("degraded supervised live capture"),
    )
    .expect("write degraded supervised live capture");
}

fn export_fixture_package(receipt_db_path: &Path, output_dir: &Path) {
    evidence_export::cmd_evidence_export(
        output_dir,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        false,
        Some(receipt_db_path),
        None,
        None,
    )
    .expect("export evidence fixture package");
}

#[test]
fn mercury_proof_and_inquiry_packages_export_and_verify() {
    let receipt_db_path = unique_path("chio-mercury-proof", ".sqlite3");
    let output_dir = unique_path("chio-mercury-proof-export", "");
    let bundle_manifest_path = unique_path("chio-mercury-bundle", ".json");
    let proof_package_path = unique_path("chio-mercury-proof-package", ".json");
    let inquiry_package_path = unique_path("chio-mercury-inquiry-package", ".json");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        let issuer = Keypair::generate();
        let seq = store
            .append_chio_receipt_returning_seq(&mercury_receipt_with_ts(
                "rcpt-mercury-1",
                "cap-mercury-proof",
                100,
                &issuer,
            ))
            .expect("append mercury receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq,
            seq,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    export_fixture_package(&receipt_db_path, &output_dir);
    write_mercury_bundle_manifest(&bundle_manifest_path);

    let proof_export = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("proof")
        .arg("export")
        .arg("--input")
        .arg(&output_dir)
        .arg("--output")
        .arg(&proof_package_path)
        .arg("--bundle-manifest")
        .arg(&bundle_manifest_path)
        .output()
        .expect("run mercury proof export");
    assert!(
        proof_export.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&proof_export.stdout),
        String::from_utf8_lossy(&proof_export.stderr)
    );

    let proof_verify = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("verify")
        .arg("--input")
        .arg(&proof_package_path)
        .output()
        .expect("run mercury verify on proof package");
    assert!(
        proof_verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&proof_verify.stdout),
        String::from_utf8_lossy(&proof_verify.stderr)
    );
    let proof_report: serde_json::Value =
        serde_json::from_slice(&proof_verify.stdout).expect("proof report json");
    assert_eq!(proof_report["packageKind"], "proof");
    assert_eq!(proof_report["workflowId"], "workflow-release-control");

    let inquiry_export = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("inquiry")
        .arg("export")
        .arg("--input")
        .arg(&proof_package_path)
        .arg("--output")
        .arg(&inquiry_package_path)
        .arg("--audience")
        .arg("compliance")
        .arg("--redaction-profile")
        .arg("internal-default")
        .output()
        .expect("run mercury inquiry export");
    assert!(
        inquiry_export.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&inquiry_export.stdout),
        String::from_utf8_lossy(&inquiry_export.stderr)
    );

    let inquiry_verify = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("verify")
        .arg("--input")
        .arg(&inquiry_package_path)
        .output()
        .expect("run mercury verify on inquiry package");
    assert!(
        inquiry_verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&inquiry_verify.stdout),
        String::from_utf8_lossy(&inquiry_verify.stderr)
    );
    let inquiry_report: serde_json::Value =
        serde_json::from_slice(&inquiry_verify.stdout).expect("inquiry report json");
    assert_eq!(inquiry_report["packageKind"], "inquiry");
    assert_eq!(inquiry_report["verifierEquivalent"], false);

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(bundle_manifest_path);
    let _ = fs::remove_file(proof_package_path);
    let _ = fs::remove_file(inquiry_package_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_pilot_export_writes_primary_and_rollback_corpus() {
    let output_dir = unique_path("chio-mercury-pilot", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("pilot")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury pilot export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("pilot summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["primaryReceiptCount"], 4);
    assert_eq!(summary["rollbackReceiptCount"], 4);

    for relative_path in [
        "scenario.json",
        "pilot-summary.json",
        "primary/events.json",
        "primary/receipts.sqlite3",
        "primary/bundle-manifest.json",
        "primary/evidence/manifest.json",
        "primary/proof-package.json",
        "primary/proof-verification.json",
        "primary/inquiry-package.json",
        "primary/inquiry-verification.json",
        "rollback/events.json",
        "rollback/receipts.sqlite3",
        "rollback/bundle-manifest.json",
        "rollback/evidence/manifest.json",
        "rollback/proof-package.json",
        "rollback/proof-verification.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let primary_proof_report: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("primary/proof-verification.json"))
            .expect("read primary proof report"),
    )
    .expect("parse primary proof report");
    assert_eq!(primary_proof_report["packageKind"], "proof");
    assert_eq!(primary_proof_report["receiptCount"], 4);

    let primary_inquiry_report: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("primary/inquiry-verification.json"))
            .expect("read primary inquiry report"),
    )
    .expect("parse primary inquiry report");
    assert_eq!(primary_inquiry_report["packageKind"], "inquiry");
    assert_eq!(primary_inquiry_report["verifierEquivalent"], false);

    let rollback_proof_report: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("rollback/proof-verification.json"))
            .expect("read rollback proof report"),
    )
    .expect("parse rollback proof report");
    assert_eq!(rollback_proof_report["packageKind"], "proof");
    assert_eq!(rollback_proof_report["receiptCount"], 4);

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_supervised_live_export_preserves_source_continuity_and_verifies() {
    let capture_path = unique_path("chio-mercury-supervised-live", ".json");
    let output_dir = unique_path("chio-mercury-supervised-live-export", "");
    write_supervised_live_capture(&capture_path, MercurySupervisedLiveMode::Mirrored);

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("supervised-live")
        .arg("export")
        .arg("--input")
        .arg(&capture_path)
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury supervised-live export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("supervised-live summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["mode"], "mirrored");
    assert_eq!(summary["receiptCount"], 4);
    assert_eq!(summary["controlState"]["coverageState"], "covered");
    assert_eq!(summary["controlState"]["releaseGate"]["state"], "approved");
    assert_eq!(summary["controlState"]["rollbackGate"]["state"], "approved");

    for relative_path in [
        "capture.json",
        "supervised-live-summary.json",
        "receipts.sqlite3",
        "bundle-manifest.json",
        "evidence/manifest.json",
        "proof-package.json",
        "proof-verification.json",
        "inquiry-package.json",
        "inquiry-verification.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let proof_package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("proof-package.json")).expect("read proof package"),
    )
    .expect("parse proof package");
    assert_eq!(proof_package["workflowId"], "workflow-release-control");
    assert_eq!(
        proof_package["receiptRecords"][0]["metadata"]["provenance"]["sourceRecordId"],
        "source-proposal-1"
    );
    assert_eq!(
        proof_package["bundleManifests"][0]["businessIds"]["workflowId"],
        "workflow-release-control"
    );

    let proof_verify = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("verify")
        .arg("--input")
        .arg(output_dir.join("proof-package.json"))
        .output()
        .expect("verify supervised-live proof package");
    assert!(
        proof_verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&proof_verify.stdout),
        String::from_utf8_lossy(&proof_verify.stderr)
    );
    let proof_report: serde_json::Value =
        serde_json::from_slice(&proof_verify.stdout).expect("proof report json");
    assert_eq!(proof_report["packageKind"], "proof");

    let inquiry_verify = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("verify")
        .arg("--input")
        .arg(output_dir.join("inquiry-package.json"))
        .output()
        .expect("verify supervised-live inquiry package");
    assert!(
        inquiry_verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&inquiry_verify.stdout),
        String::from_utf8_lossy(&inquiry_verify.stderr)
    );
    let inquiry_report: serde_json::Value =
        serde_json::from_slice(&inquiry_verify.stdout).expect("inquiry report json");
    assert_eq!(inquiry_report["packageKind"], "inquiry");

    let _ = fs::remove_file(capture_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_supervised_live_export_fails_closed_when_monitoring_is_degraded() {
    let capture_path = unique_path("chio-mercury-supervised-live-degraded", ".json");
    let output_dir = unique_path("chio-mercury-supervised-live-degraded-export", "");
    write_degraded_supervised_live_capture(&capture_path);

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("supervised-live")
        .arg("export")
        .arg("--input")
        .arg(&capture_path)
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run degraded mercury supervised-live export");

    assert!(
        !output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fail closed"), "stderr={stderr}");
    assert!(
        !output_dir.join("proof-package.json").exists(),
        "proof package should not be emitted when export fails closed"
    );

    let _ = fs::remove_file(capture_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_supervised_live_qualify_writes_reviewer_package_and_report() {
    let output_dir = unique_path("chio-mercury-supervised-live-qualification", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("supervised-live")
        .arg("qualify")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury supervised-live qualify");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let reviewer_package: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("reviewer package json");
    assert_eq!(reviewer_package["workflowId"], "workflow-release-control");
    assert_eq!(reviewer_package["decision"], "proceed");
    for relative_path in [
        "qualification-report.json",
        "reviewer-package.json",
        "supervised-live/capture.json",
        "supervised-live/proof-package.json",
        "supervised-live/inquiry-package.json",
        "pilot/scenario.json",
        "pilot/rollback/proof-package.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let qualification_report: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("qualification-report.json")).expect("read qualification report"),
    )
    .expect("parse qualification report");
    assert_eq!(qualification_report["decision"], "proceed");
    assert_eq!(qualification_report["supervisedLive"]["mode"], "live");
    assert_eq!(qualification_report["pilot"]["rollbackReceiptCount"], 4);

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_downstream_review_export_writes_case_management_drop_and_assurance_packages() {
    let output_dir = unique_path("chio-mercury-downstream-review-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("downstream-review")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury downstream-review export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("downstream review summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["consumerProfile"], "case_management_review");
    assert_eq!(summary["transport"], "file_drop");

    for relative_path in [
        "qualification/reviewer-package.json",
        "qualification/qualification-report.json",
        "assurance/internal-review/assurance-package.json",
        "assurance/internal-review/inquiry-package.json",
        "assurance/external-review/assurance-package.json",
        "assurance/external-review/inquiry-package.json",
        "consumer-drop/consumer-manifest.json",
        "consumer-drop/delivery-acknowledgement.json",
        "downstream-review-package.json",
        "downstream-review-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let downstream_package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("downstream-review-package.json"))
            .expect("read downstream review package"),
    )
    .expect("parse downstream review package");
    assert_eq!(
        downstream_package["consumerProfile"],
        "case_management_review"
    );
    assert_eq!(downstream_package["failClosed"], true);
    let artifact_roles = downstream_package["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .map(|value| value["role"].as_str().expect("artifact role"))
        .collect::<Vec<_>>();
    assert!(artifact_roles.contains(&"consumer_manifest"));
    assert!(artifact_roles.contains(&"delivery_acknowledgement"));

    let acknowledgement: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("consumer-drop/delivery-acknowledgement.json"))
            .expect("read delivery acknowledgement"),
    )
    .expect("parse acknowledgement");
    assert_eq!(acknowledgement["status"], "acknowledged");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_downstream_review_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-downstream-review-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("downstream-review")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury downstream-review validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("downstream validation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_case_management_only");
    assert_eq!(report["consumerProfile"], "case_management_review");
    for relative_path in [
        "downstream-review/downstream-review-package.json",
        "downstream-review/consumer-drop/consumer-manifest.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read expansion decision"),
    )
    .expect("parse expansion decision");
    assert_eq!(decision_record["decision"], "proceed_case_management_only");
    assert_eq!(
        decision_record["selectedConsumerProfile"],
        "case_management_review"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_governance_workbench_export_writes_decision_package_and_review_packages() {
    let output_dir = unique_path("chio-mercury-governance-workbench-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("governance-workbench")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury governance-workbench export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("governance summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["workflowPath"], "change_review_release_control");
    assert_eq!(summary["workflowOwner"], "mercury-workflow-owner");
    assert_eq!(summary["controlTeamOwner"], "mercury-control-review");
    assert_eq!(summary["controlState"]["approvalGate"], "approved");
    assert_eq!(summary["controlState"]["rollbackGate"], "ready");

    for relative_path in [
        "qualification/reviewer-package.json",
        "qualification/qualification-report.json",
        "governance-control-state.json",
        "governance-decision-package.json",
        "governance-reviews/workflow-owner/review-package.json",
        "governance-reviews/workflow-owner/inquiry-package.json",
        "governance-reviews/control-team/review-package.json",
        "governance-reviews/control-team/inquiry-package.json",
        "governance-workbench-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("governance-decision-package.json"))
            .expect("read governance decision package"),
    )
    .expect("parse governance decision package");
    assert_eq!(
        decision_package["workflowPath"],
        "change_review_release_control"
    );
    assert_eq!(decision_package["failClosed"], true);
    assert_eq!(decision_package["controlState"]["exceptionGate"], "routed");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_governance_workbench_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-governance-workbench-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("governance-workbench")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury governance-workbench validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("governance validation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_governance_workbench_only");
    assert_eq!(report["workflowPath"], "change_review_release_control");
    for relative_path in [
        "governance-workbench/governance-decision-package.json",
        "governance-workbench/governance-reviews/workflow-owner/review-package.json",
        "governance-workbench/governance-reviews/control-team/review-package.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read governance decision"),
    )
    .expect("parse governance decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_governance_workbench_only"
    );
    assert_eq!(
        decision_record["selectedWorkflowPath"],
        "change_review_release_control"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_assurance_suite_export_writes_population_packages_and_investigation_exports() {
    let output_dir = unique_path("chio-mercury-assurance-suite-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("assurance-suite")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury assurance-suite export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("assurance summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["reviewerOwner"], "mercury-assurance-review");
    assert_eq!(summary["supportOwner"], "mercury-assurance-ops");

    for relative_path in [
        "governance-workbench/governance-decision-package.json",
        "reviewer-populations/internal-review/disclosure-profile.json",
        "reviewer-populations/internal-review/review-package.json",
        "reviewer-populations/internal-review/investigation-package.json",
        "reviewer-populations/auditor-review/disclosure-profile.json",
        "reviewer-populations/auditor-review/review-package.json",
        "reviewer-populations/auditor-review/investigation-package.json",
        "reviewer-populations/counterparty-review/disclosure-profile.json",
        "reviewer-populations/counterparty-review/review-package.json",
        "reviewer-populations/counterparty-review/investigation-package.json",
        "assurance-suite-package.json",
        "assurance-suite-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let assurance_suite_package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("assurance-suite-package.json"))
            .expect("read assurance suite package"),
    )
    .expect("parse assurance suite package");
    assert_eq!(assurance_suite_package["failClosed"], true);
    assert_eq!(
        assurance_suite_package["reviewerPopulations"]
            .as_array()
            .expect("reviewer populations")
            .len(),
        3
    );
    assert_eq!(
        assurance_suite_package["artifacts"]
            .as_array()
            .expect("artifacts")
            .len(),
        9
    );

    let counterparty_review: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("reviewer-populations/counterparty-review/review-package.json"))
            .expect("read counterparty review package"),
    )
    .expect("parse counterparty review package");
    assert_eq!(
        counterparty_review["reviewerPopulation"],
        "counterparty_review"
    );
    assert_eq!(counterparty_review["verifierEquivalent"], false);

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_assurance_suite_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-assurance-suite-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("assurance-suite")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury assurance-suite validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("assurance validation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_assurance_suite_only");
    assert_eq!(report["reviewerOwner"], "mercury-assurance-review");
    assert_eq!(report["supportOwner"], "mercury-assurance-ops");
    for relative_path in [
        "assurance-suite/assurance-suite-package.json",
        "assurance-suite/reviewer-populations/internal-review/investigation-package.json",
        "assurance-suite/reviewer-populations/auditor-review/investigation-package.json",
        "assurance-suite/reviewer-populations/counterparty-review/investigation-package.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read assurance decision"),
    )
    .expect("parse assurance decision");
    assert_eq!(decision_record["decision"], "proceed_assurance_suite_only");
    assert_eq!(
        decision_record["selectedReviewerPopulations"]
            .as_array()
            .expect("selected reviewer populations")
            .len(),
        3
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_embedded_oem_export_writes_partner_bundle_and_manifest() {
    let output_dir = unique_path("chio-mercury-embedded-oem-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("embedded-oem")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury embedded-oem export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("embedded oem summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["partnerSurface"], "reviewer_workbench_embed");
    assert_eq!(summary["sdkSurface"], "signed_artifact_bundle");
    assert_eq!(summary["reviewerPopulation"], "counterparty_review");

    for relative_path in [
        "assurance-suite/assurance-suite-package.json",
        "embedded-oem-profile.json",
        "partner-sdk-manifest.json",
        "partner-sdk-bundle/assurance-suite-package.json",
        "partner-sdk-bundle/governance-decision-package.json",
        "partner-sdk-bundle/disclosure-profile.json",
        "partner-sdk-bundle/review-package.json",
        "partner-sdk-bundle/investigation-package.json",
        "partner-sdk-bundle/reviewer-package.json",
        "partner-sdk-bundle/qualification-report.json",
        "partner-sdk-bundle/delivery-acknowledgement.json",
        "embedded-oem-package.json",
        "embedded-oem-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("embedded-oem-package.json")).expect("read embedded oem package"),
    )
    .expect("parse embedded oem package");
    assert_eq!(package["reviewerPopulation"], "counterparty_review");
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["acknowledgementRequired"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("partner-sdk-manifest.json")).expect("read partner sdk manifest"),
    )
    .expect("parse partner sdk manifest");
    assert_eq!(manifest["partnerSurface"], "reviewer_workbench_embed");
    assert_eq!(manifest["sdkSurface"], "signed_artifact_bundle");
    assert_eq!(manifest["reviewerPopulation"], "counterparty_review");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_embedded_oem_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-embedded-oem-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("embedded-oem")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury embedded-oem validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("embedded oem validation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_embedded_oem_only");
    assert_eq!(report["partnerSurface"], "reviewer_workbench_embed");
    assert_eq!(report["sdkSurface"], "signed_artifact_bundle");
    assert_eq!(report["reviewerPopulation"], "counterparty_review");
    for relative_path in [
        "embedded-oem/embedded-oem-package.json",
        "embedded-oem/partner-sdk-manifest.json",
        "embedded-oem/partner-sdk-bundle/review-package.json",
        "embedded-oem/partner-sdk-bundle/delivery-acknowledgement.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read embedded oem decision"),
    )
    .expect("parse embedded oem decision");
    assert_eq!(decision_record["decision"], "proceed_embedded_oem_only");
    assert_eq!(
        decision_record["selectedPartnerSurface"],
        "reviewer_workbench_embed"
    );
    assert_eq!(
        decision_record["selectedSdkSurface"],
        "signed_artifact_bundle"
    );
    assert_eq!(
        decision_record["selectedReviewerPopulation"],
        "counterparty_review"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_trust_network_export_writes_shared_exchange_bundle() {
    let output_dir = unique_path("chio-mercury-trust-network-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("trust-network")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury trust-network export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("trust-network summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["sponsorBoundary"], "counterparty_review_exchange");
    assert_eq!(summary["trustAnchor"], "chio_checkpoint_witness_chain");
    assert_eq!(summary["interopSurface"], "proof_inquiry_bundle_exchange");
    assert_eq!(summary["reviewerPopulation"], "counterparty_review");

    for relative_path in [
        "embedded-oem/embedded-oem-package.json",
        "trust-network-profile.json",
        "trust-network-package.json",
        "trust-network-interoperability-manifest.json",
        "trust-network-share/shared-proof-package.json",
        "trust-network-share/review-package.json",
        "trust-network-share/inquiry-package.json",
        "trust-network-share/inquiry-verification.json",
        "trust-network-share/reviewer-package.json",
        "trust-network-share/qualification-report.json",
        "trust-network-share/witness-record.json",
        "trust-network-share/trust-anchor-record.json",
        "trust-network-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("trust-network-package.json"))
            .expect("read trust-network package"),
    )
    .expect("parse trust-network package");
    assert_eq!(package["reviewerPopulation"], "counterparty_review");
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 7);

    let shared_proof: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("trust-network-share/shared-proof-package.json"))
            .expect("read shared proof package"),
    )
    .expect("parse shared proof package");
    assert_eq!(
        shared_proof["publicationProfile"]["witnessRecord"],
        "trust-network-share/witness-record.json"
    );
    assert_eq!(
        shared_proof["publicationProfile"]["trustAnchor"],
        "trust-network-share/trust-anchor-record.json"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_trust_network_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-trust-network-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("trust-network")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury trust-network validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("trust-network validation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_trust_network_only");
    assert_eq!(report["sponsorBoundary"], "counterparty_review_exchange");
    assert_eq!(report["trustAnchor"], "chio_checkpoint_witness_chain");
    assert_eq!(report["interopSurface"], "proof_inquiry_bundle_exchange");
    assert_eq!(report["reviewerPopulation"], "counterparty_review");
    for relative_path in [
        "trust-network/trust-network-package.json",
        "trust-network/trust-network-interoperability-manifest.json",
        "trust-network/trust-network-share/shared-proof-package.json",
        "trust-network/trust-network-share/inquiry-package.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json")).expect("read trust-network decision"),
    )
    .expect("parse trust-network decision");
    assert_eq!(decision_record["decision"], "proceed_trust_network_only");
    assert_eq!(
        decision_record["selectedSponsorBoundary"],
        "counterparty_review_exchange"
    );
    assert_eq!(
        decision_record["selectedTrustAnchor"],
        "chio_checkpoint_witness_chain"
    );
    assert_eq!(
        decision_record["selectedInteropSurface"],
        "proof_inquiry_bundle_exchange"
    );
    assert_eq!(
        decision_record["selectedReviewerPopulation"],
        "counterparty_review"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_release_readiness_export_writes_partner_delivery_bundle() {
    let output_dir = unique_path("chio-mercury-release-readiness-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("release-readiness")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury release-readiness export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("release readiness summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["deliverySurface"], "signed_partner_review_bundle");
    assert_eq!(summary["audiences"].as_array().expect("audiences").len(), 3);

    for relative_path in [
        "trust-network/trust-network-package.json",
        "release-readiness-profile.json",
        "release-readiness-package.json",
        "partner-delivery/proof-package.json",
        "partner-delivery/inquiry-package.json",
        "partner-delivery/inquiry-verification.json",
        "partner-delivery/assurance-suite-package.json",
        "partner-delivery/trust-network-package.json",
        "partner-delivery/reviewer-package.json",
        "partner-delivery/qualification-report.json",
        "partner-delivery-manifest.json",
        "delivery-acknowledgement.json",
        "operator-release-checklist.json",
        "escalation-manifest.json",
        "support-handoff.json",
        "release-readiness-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("release-readiness-package.json"))
            .expect("read release readiness package"),
    )
    .expect("parse release readiness package");
    assert_eq!(package["deliverySurface"], "signed_partner_review_bundle");
    assert_eq!(package["acknowledgementRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 5);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("partner-delivery-manifest.json"))
            .expect("read partner delivery manifest"),
    )
    .expect("parse partner delivery manifest");
    assert_eq!(manifest["deliverySurface"], "signed_partner_review_bundle");
    assert_eq!(manifest["failClosed"], true);

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_release_readiness_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-release-readiness-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("release-readiness")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury release-readiness validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("release readiness report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "launch_release_readiness_only");
    assert_eq!(report["deliverySurface"], "signed_partner_review_bundle");
    for relative_path in [
        "release-readiness/release-readiness-package.json",
        "release-readiness/partner-delivery-manifest.json",
        "release-readiness/operator-release-checklist.json",
        "release-readiness/support-handoff.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json"))
            .expect("read release readiness decision"),
    )
    .expect("parse release readiness decision");
    assert_eq!(decision_record["decision"], "launch_release_readiness_only");
    assert_eq!(
        decision_record["selectedDeliverySurface"],
        "signed_partner_review_bundle"
    );
    assert_eq!(
        decision_record["selectedAudiences"]
            .as_array()
            .expect("selected audiences")
            .len(),
        3
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_controlled_adoption_export_writes_adoption_bundle() {
    let output_dir = unique_path("chio-mercury-controlled-adoption-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("controlled-adoption")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury controlled-adoption export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("controlled adoption summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["cohort"], "design_partner_renewal");
    assert_eq!(summary["adoptionSurface"], "renewal_reference_bundle");

    for relative_path in [
        "release-readiness/release-readiness-package.json",
        "controlled-adoption-profile.json",
        "controlled-adoption-package.json",
        "adoption-evidence/release-readiness-package.json",
        "adoption-evidence/trust-network-package.json",
        "adoption-evidence/assurance-suite-package.json",
        "adoption-evidence/proof-package.json",
        "adoption-evidence/inquiry-package.json",
        "adoption-evidence/inquiry-verification.json",
        "adoption-evidence/reviewer-package.json",
        "adoption-evidence/qualification-report.json",
        "customer-success-checklist.json",
        "renewal-evidence-manifest.json",
        "renewal-acknowledgement.json",
        "reference-readiness-brief.json",
        "support-escalation-manifest.json",
        "controlled-adoption-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("controlled-adoption-package.json"))
            .expect("read controlled adoption package"),
    )
    .expect("parse controlled adoption package");
    assert_eq!(package["cohort"], "design_partner_renewal");
    assert_eq!(package["adoptionSurface"], "renewal_reference_bundle");
    assert_eq!(package["acknowledgementRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 5);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("renewal-evidence-manifest.json"))
            .expect("read renewal evidence manifest"),
    )
    .expect("parse renewal evidence manifest");
    assert_eq!(manifest["cohort"], "design_partner_renewal");
    assert_eq!(manifest["adoptionSurface"], "renewal_reference_bundle");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_controlled_adoption_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-controlled-adoption-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("controlled-adoption")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury controlled-adoption validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("controlled adoption report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "scale_controlled_adoption_only");
    assert_eq!(report["cohort"], "design_partner_renewal");
    assert_eq!(report["adoptionSurface"], "renewal_reference_bundle");
    for relative_path in [
        "controlled-adoption/controlled-adoption-package.json",
        "controlled-adoption/renewal-evidence-manifest.json",
        "controlled-adoption/reference-readiness-brief.json",
        "controlled-adoption/support-escalation-manifest.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json"))
            .expect("read controlled adoption decision"),
    )
    .expect("parse controlled adoption decision");
    assert_eq!(
        decision_record["decision"],
        "scale_controlled_adoption_only"
    );
    assert_eq!(decision_record["selectedCohort"], "design_partner_renewal");
    assert_eq!(
        decision_record["selectedAdoptionSurface"],
        "renewal_reference_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_reference_distribution_export_writes_reference_bundle() {
    let output_dir = unique_path("chio-mercury-reference-distribution-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("reference-distribution")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury reference-distribution export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("reference distribution summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["expansionMotion"], "landed_account_expansion");
    assert_eq!(summary["distributionSurface"], "approved_reference_bundle");
    assert_eq!(summary["referenceOwner"], "mercury-reference-program");

    for relative_path in [
        "controlled-adoption/controlled-adoption-package.json",
        "reference-distribution-profile.json",
        "reference-distribution-package.json",
        "reference-evidence/controlled-adoption-package.json",
        "reference-evidence/renewal-evidence-manifest.json",
        "reference-evidence/renewal-acknowledgement.json",
        "reference-evidence/reference-readiness-brief.json",
        "reference-evidence/release-readiness-package.json",
        "reference-evidence/trust-network-package.json",
        "reference-evidence/assurance-suite-package.json",
        "reference-evidence/proof-package.json",
        "reference-evidence/inquiry-package.json",
        "reference-evidence/inquiry-verification.json",
        "reference-evidence/reviewer-package.json",
        "reference-evidence/qualification-report.json",
        "account-motion-freeze.json",
        "reference-distribution-manifest.json",
        "claim-discipline-rules.json",
        "buyer-reference-approval.json",
        "sales-handoff-brief.json",
        "reference-distribution-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("reference-distribution-package.json"))
            .expect("read reference distribution package"),
    )
    .expect("parse reference distribution package");
    assert_eq!(package["expansionMotion"], "landed_account_expansion");
    assert_eq!(package["distributionSurface"], "approved_reference_bundle");
    assert_eq!(package["approvalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 5);

    let approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("buyer-reference-approval.json"))
            .expect("read buyer reference approval"),
    )
    .expect("parse buyer reference approval");
    assert_eq!(approval["status"], "approved");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_reference_distribution_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-reference-distribution-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("reference-distribution")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury reference-distribution validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("reference distribution report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_reference_distribution_only");
    assert_eq!(report["expansionMotion"], "landed_account_expansion");
    assert_eq!(report["distributionSurface"], "approved_reference_bundle");
    for relative_path in [
        "reference-distribution/reference-distribution-package.json",
        "reference-distribution/account-motion-freeze.json",
        "reference-distribution/claim-discipline-rules.json",
        "reference-distribution/buyer-reference-approval.json",
        "reference-distribution/sales-handoff-brief.json",
        "validation-report.json",
        "expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-decision.json"))
            .expect("read reference distribution decision"),
    )
    .expect("parse reference distribution decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_reference_distribution_only"
    );
    assert_eq!(
        decision_record["selectedExpansionMotion"],
        "landed_account_expansion"
    );
    assert_eq!(
        decision_record["selectedDistributionSurface"],
        "approved_reference_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_broader_distribution_export_writes_governed_bundle() {
    let output_dir = unique_path("chio-mercury-broader-distribution-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("broader-distribution")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury broader-distribution export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("broader distribution summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(
        summary["distributionMotion"],
        "selective_account_qualification"
    );
    assert_eq!(
        summary["distributionSurface"],
        "governed_distribution_bundle"
    );
    assert_eq!(
        summary["qualificationOwner"],
        "mercury-account-qualification"
    );

    for relative_path in [
        "reference-distribution/reference-distribution-package.json",
        "broader-distribution-profile.json",
        "broader-distribution-package.json",
        "qualification-evidence/reference-distribution-package.json",
        "qualification-evidence/account-motion-freeze.json",
        "qualification-evidence/reference-distribution-manifest.json",
        "qualification-evidence/reference-claim-discipline-rules.json",
        "qualification-evidence/reference-buyer-approval.json",
        "qualification-evidence/reference-sales-handoff-brief.json",
        "qualification-evidence/controlled-adoption-package.json",
        "qualification-evidence/renewal-evidence-manifest.json",
        "qualification-evidence/renewal-acknowledgement.json",
        "qualification-evidence/reference-readiness-brief.json",
        "qualification-evidence/release-readiness-package.json",
        "qualification-evidence/trust-network-package.json",
        "qualification-evidence/assurance-suite-package.json",
        "qualification-evidence/proof-package.json",
        "qualification-evidence/inquiry-package.json",
        "qualification-evidence/inquiry-verification.json",
        "qualification-evidence/reviewer-package.json",
        "qualification-evidence/qualification-report.json",
        "target-account-freeze.json",
        "broader-distribution-manifest.json",
        "claim-governance-rules.json",
        "selective-account-approval.json",
        "distribution-handoff-brief.json",
        "broader-distribution-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("broader-distribution-package.json"))
            .expect("read broader distribution package"),
    )
    .expect("parse broader distribution package");
    assert_eq!(
        package["distributionMotion"],
        "selective_account_qualification"
    );
    assert_eq!(
        package["distributionSurface"],
        "governed_distribution_bundle"
    );
    assert_eq!(package["approvalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 5);

    let approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("selective-account-approval.json"))
            .expect("read selective account approval"),
    )
    .expect("parse selective account approval");
    assert_eq!(approval["status"], "approved");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_broader_distribution_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-broader-distribution-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("broader-distribution")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury broader-distribution validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("broader distribution report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_broader_distribution_only");
    assert_eq!(
        report["distributionMotion"],
        "selective_account_qualification"
    );
    assert_eq!(
        report["distributionSurface"],
        "governed_distribution_bundle"
    );
    for relative_path in [
        "broader-distribution/broader-distribution-package.json",
        "broader-distribution/target-account-freeze.json",
        "broader-distribution/claim-governance-rules.json",
        "broader-distribution/selective-account-approval.json",
        "broader-distribution/distribution-handoff-brief.json",
        "validation-report.json",
        "broader-distribution-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("broader-distribution-decision.json"))
            .expect("read broader distribution decision"),
    )
    .expect("parse broader distribution decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_broader_distribution_only"
    );
    assert_eq!(
        decision_record["selectedDistributionMotion"],
        "selective_account_qualification"
    );
    assert_eq!(
        decision_record["selectedDistributionSurface"],
        "governed_distribution_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_selective_account_activation_export_writes_controlled_bundle() {
    let output_dir = unique_path("chio-mercury-selective-account-activation-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("selective-account-activation")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury selective-account-activation export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("selective account activation summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["activationMotion"], "selective_account_activation");
    assert_eq!(summary["deliverySurface"], "controlled_delivery_bundle");
    assert_eq!(
        summary["activationOwner"],
        "mercury-selective-account-activation"
    );

    for relative_path in [
        "broader-distribution/broader-distribution-package.json",
        "selective-account-activation-profile.json",
        "selective-account-activation-package.json",
        "activation-evidence/broader-distribution-package.json",
        "activation-evidence/target-account-freeze.json",
        "activation-evidence/broader-distribution-manifest.json",
        "activation-evidence/claim-governance-rules.json",
        "activation-evidence/selective-account-approval.json",
        "activation-evidence/distribution-handoff-brief.json",
        "activation-evidence/reference-distribution-package.json",
        "activation-evidence/controlled-adoption-package.json",
        "activation-evidence/release-readiness-package.json",
        "activation-evidence/trust-network-package.json",
        "activation-evidence/assurance-suite-package.json",
        "activation-evidence/proof-package.json",
        "activation-evidence/inquiry-package.json",
        "activation-evidence/inquiry-verification.json",
        "activation-evidence/reviewer-package.json",
        "activation-evidence/qualification-report.json",
        "activation-scope-freeze.json",
        "selective-account-activation-manifest.json",
        "claim-containment-rules.json",
        "activation-approval-refresh.json",
        "customer-handoff-brief.json",
        "selective-account-activation-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("selective-account-activation-package.json"))
            .expect("read selective account activation package"),
    )
    .expect("parse selective account activation package");
    assert_eq!(package["activationMotion"], "selective_account_activation");
    assert_eq!(package["deliverySurface"], "controlled_delivery_bundle");
    assert_eq!(package["approvalRefreshRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 5);

    let approval_refresh: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("activation-approval-refresh.json"))
            .expect("read activation approval refresh"),
    )
    .expect("parse activation approval refresh");
    assert_eq!(approval_refresh["status"], "refreshed");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_selective_account_activation_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-selective-account-activation-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("selective-account-activation")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury selective-account-activation validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("selective account activation report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(
        report["decision"],
        "proceed_selective_account_activation_only"
    );
    assert_eq!(report["activationMotion"], "selective_account_activation");
    assert_eq!(report["deliverySurface"], "controlled_delivery_bundle");
    for relative_path in [
        "selective-account-activation/selective-account-activation-package.json",
        "selective-account-activation/activation-scope-freeze.json",
        "selective-account-activation/claim-containment-rules.json",
        "selective-account-activation/activation-approval-refresh.json",
        "selective-account-activation/customer-handoff-brief.json",
        "validation-report.json",
        "selective-account-activation-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("selective-account-activation-decision.json"))
            .expect("read selective account activation decision"),
    )
    .expect("parse selective account activation decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_selective_account_activation_only"
    );
    assert_eq!(
        decision_record["selectedActivationMotion"],
        "selective_account_activation"
    );
    assert_eq!(
        decision_record["selectedDeliverySurface"],
        "controlled_delivery_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_delivery_continuity_export_writes_outcome_bundle() {
    let output_dir = unique_path("chio-mercury-delivery-continuity-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("delivery-continuity")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury delivery-continuity export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("delivery continuity summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(
        summary["continuityMotion"],
        "controlled_delivery_continuity"
    );
    assert_eq!(summary["continuitySurface"], "outcome_evidence_bundle");
    assert_eq!(summary["continuityOwner"], "mercury-delivery-continuity");

    for relative_path in [
        "selective-account-activation/selective-account-activation-package.json",
        "delivery-continuity-profile.json",
        "delivery-continuity-package.json",
        "continuity-evidence/selective-account-activation-package.json",
        "continuity-evidence/activation-scope-freeze.json",
        "continuity-evidence/selective-account-activation-manifest.json",
        "continuity-evidence/claim-containment-rules.json",
        "continuity-evidence/activation-approval-refresh.json",
        "continuity-evidence/customer-handoff-brief.json",
        "continuity-evidence/broader-distribution-package.json",
        "continuity-evidence/broader-distribution-manifest.json",
        "continuity-evidence/target-account-freeze.json",
        "continuity-evidence/claim-governance-rules.json",
        "continuity-evidence/selective-account-approval.json",
        "continuity-evidence/reference-distribution-package.json",
        "continuity-evidence/controlled-adoption-package.json",
        "continuity-evidence/release-readiness-package.json",
        "continuity-evidence/trust-network-package.json",
        "continuity-evidence/assurance-suite-package.json",
        "continuity-evidence/proof-package.json",
        "continuity-evidence/inquiry-package.json",
        "continuity-evidence/inquiry-verification.json",
        "continuity-evidence/reviewer-package.json",
        "continuity-evidence/qualification-report.json",
        "account-boundary-freeze.json",
        "delivery-continuity-manifest.json",
        "outcome-evidence-summary.json",
        "renewal-gate.json",
        "delivery-escalation-brief.json",
        "customer-evidence-handoff.json",
        "delivery-continuity-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("delivery-continuity-package.json"))
            .expect("read delivery continuity package"),
    )
    .expect("parse delivery continuity package");
    assert_eq!(
        package["continuityMotion"],
        "controlled_delivery_continuity"
    );
    assert_eq!(package["continuitySurface"], "outcome_evidence_bundle");
    assert_eq!(package["renewalGateRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let renewal_gate: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("renewal-gate.json")).expect("read renewal gate"),
    )
    .expect("parse renewal gate");
    assert_eq!(renewal_gate["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_delivery_continuity_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-delivery-continuity-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("delivery-continuity")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury delivery-continuity validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("delivery continuity report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_delivery_continuity_only");
    assert_eq!(report["continuityMotion"], "controlled_delivery_continuity");
    assert_eq!(report["continuitySurface"], "outcome_evidence_bundle");
    for relative_path in [
        "delivery-continuity/delivery-continuity-package.json",
        "delivery-continuity/account-boundary-freeze.json",
        "delivery-continuity/outcome-evidence-summary.json",
        "delivery-continuity/renewal-gate.json",
        "delivery-continuity/delivery-escalation-brief.json",
        "delivery-continuity/customer-evidence-handoff.json",
        "validation-report.json",
        "delivery-continuity-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("delivery-continuity-decision.json"))
            .expect("read delivery continuity decision"),
    )
    .expect("parse delivery continuity decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_delivery_continuity_only"
    );
    assert_eq!(
        decision_record["selectedContinuityMotion"],
        "controlled_delivery_continuity"
    );
    assert_eq!(
        decision_record["selectedContinuitySurface"],
        "outcome_evidence_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_renewal_qualification_export_writes_outcome_review_bundle() {
    let output_dir = unique_path("chio-mercury-renewal-qualification-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("renewal-qualification")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury renewal-qualification export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("renewal qualification summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["renewalMotion"], "renewal_qualification");
    assert_eq!(summary["reviewSurface"], "outcome_review_bundle");
    assert_eq!(
        summary["qualificationOwner"],
        "mercury-renewal-qualification"
    );

    for relative_path in [
        "delivery-continuity/delivery-continuity-package.json",
        "renewal-qualification-profile.json",
        "renewal-qualification-package.json",
        "renewal-evidence/delivery-continuity-package.json",
        "renewal-evidence/account-boundary-freeze.json",
        "renewal-evidence/delivery-continuity-manifest.json",
        "renewal-evidence/outcome-evidence-summary.json",
        "renewal-evidence/renewal-gate.json",
        "renewal-evidence/delivery-escalation-brief.json",
        "renewal-evidence/customer-evidence-handoff.json",
        "renewal-evidence/selective-account-activation-package.json",
        "renewal-evidence/broader-distribution-package.json",
        "renewal-evidence/reference-distribution-package.json",
        "renewal-evidence/controlled-adoption-package.json",
        "renewal-evidence/release-readiness-package.json",
        "renewal-evidence/trust-network-package.json",
        "renewal-evidence/assurance-suite-package.json",
        "renewal-evidence/proof-package.json",
        "renewal-evidence/inquiry-package.json",
        "renewal-evidence/inquiry-verification.json",
        "renewal-evidence/reviewer-package.json",
        "renewal-evidence/qualification-report.json",
        "renewal-boundary-freeze.json",
        "renewal-qualification-manifest.json",
        "outcome-review-summary.json",
        "renewal-approval.json",
        "reference-reuse-discipline.json",
        "expansion-boundary-handoff.json",
        "renewal-qualification-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("renewal-qualification-package.json"))
            .expect("read renewal qualification package"),
    )
    .expect("parse renewal qualification package");
    assert_eq!(package["renewalMotion"], "renewal_qualification");
    assert_eq!(package["reviewSurface"], "outcome_review_bundle");
    assert_eq!(package["renewalApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let renewal_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("renewal-approval.json")).expect("read renewal approval"),
    )
    .expect("parse renewal approval");
    assert_eq!(renewal_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_renewal_qualification_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-renewal-qualification-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("renewal-qualification")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury renewal-qualification validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("renewal qualification report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_renewal_qualification_only");
    assert_eq!(report["renewalMotion"], "renewal_qualification");
    assert_eq!(report["reviewSurface"], "outcome_review_bundle");
    for relative_path in [
        "renewal-qualification/renewal-qualification-package.json",
        "renewal-qualification/renewal-boundary-freeze.json",
        "renewal-qualification/outcome-review-summary.json",
        "renewal-qualification/renewal-approval.json",
        "renewal-qualification/reference-reuse-discipline.json",
        "renewal-qualification/expansion-boundary-handoff.json",
        "validation-report.json",
        "renewal-qualification-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("renewal-qualification-decision.json"))
            .expect("read renewal qualification decision"),
    )
    .expect("parse renewal qualification decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_renewal_qualification_only"
    );
    assert_eq!(
        decision_record["selectedRenewalMotion"],
        "renewal_qualification"
    );
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "outcome_review_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_second_account_expansion_export_writes_portfolio_review_bundle() {
    let output_dir = unique_path("chio-mercury-second-account-expansion-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("second-account-expansion")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury second-account-expansion export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("second account expansion summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["expansionMotion"], "second_account_expansion");
    assert_eq!(summary["reviewSurface"], "portfolio_review_bundle");
    assert_eq!(
        summary["expansionOwner"],
        "mercury-second-account-expansion"
    );

    for relative_path in [
        "renewal-qualification/renewal-qualification-package.json",
        "second-account-expansion-profile.json",
        "second-account-expansion-package.json",
        "expansion-evidence/renewal-qualification-package.json",
        "expansion-evidence/renewal-boundary-freeze.json",
        "expansion-evidence/renewal-qualification-manifest.json",
        "expansion-evidence/outcome-review-summary.json",
        "expansion-evidence/renewal-approval.json",
        "expansion-evidence/reference-reuse-discipline.json",
        "expansion-evidence/expansion-boundary-handoff.json",
        "expansion-evidence/delivery-continuity-package.json",
        "expansion-evidence/account-boundary-freeze.json",
        "expansion-evidence/delivery-continuity-manifest.json",
        "expansion-evidence/outcome-evidence-summary.json",
        "expansion-evidence/renewal-gate.json",
        "expansion-evidence/delivery-escalation-brief.json",
        "expansion-evidence/customer-evidence-handoff.json",
        "expansion-evidence/selective-account-activation-package.json",
        "expansion-evidence/broader-distribution-package.json",
        "expansion-evidence/reference-distribution-package.json",
        "expansion-evidence/controlled-adoption-package.json",
        "expansion-evidence/release-readiness-package.json",
        "expansion-evidence/trust-network-package.json",
        "expansion-evidence/assurance-suite-package.json",
        "expansion-evidence/proof-package.json",
        "expansion-evidence/inquiry-package.json",
        "expansion-evidence/inquiry-verification.json",
        "expansion-evidence/reviewer-package.json",
        "expansion-evidence/qualification-report.json",
        "portfolio-boundary-freeze.json",
        "second-account-expansion-manifest.json",
        "portfolio-review-summary.json",
        "expansion-approval.json",
        "reuse-governance.json",
        "second-account-handoff.json",
        "second-account-expansion-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("second-account-expansion-package.json"))
            .expect("read second-account-expansion package"),
    )
    .expect("parse second-account-expansion package");
    assert_eq!(package["expansionMotion"], "second_account_expansion");
    assert_eq!(package["reviewSurface"], "portfolio_review_bundle");
    assert_eq!(package["expansionApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let expansion_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("expansion-approval.json")).expect("read expansion approval"),
    )
    .expect("parse expansion approval");
    assert_eq!(expansion_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_second_account_expansion_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-second-account-expansion-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("second-account-expansion")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury second-account-expansion validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("second account expansion report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_second_account_expansion_only");
    assert_eq!(report["expansionMotion"], "second_account_expansion");
    assert_eq!(report["reviewSurface"], "portfolio_review_bundle");
    for relative_path in [
        "second-account-expansion/second-account-expansion-package.json",
        "second-account-expansion/portfolio-boundary-freeze.json",
        "second-account-expansion/portfolio-review-summary.json",
        "second-account-expansion/expansion-approval.json",
        "second-account-expansion/reuse-governance.json",
        "second-account-expansion/second-account-handoff.json",
        "validation-report.json",
        "second-account-expansion-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("second-account-expansion-decision.json"))
            .expect("read second-account-expansion decision"),
    )
    .expect("parse second-account-expansion decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_second_account_expansion_only"
    );
    assert_eq!(
        decision_record["selectedExpansionMotion"],
        "second_account_expansion"
    );
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "portfolio_review_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_portfolio_program_export_writes_program_review_bundle() {
    let output_dir = unique_path("chio-mercury-portfolio-program-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("portfolio-program")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury portfolio-program export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("portfolio program summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["programMotion"], "portfolio_program");
    assert_eq!(summary["reviewSurface"], "program_review_bundle");
    assert_eq!(summary["programOwner"], "mercury-portfolio-program");

    for relative_path in [
        "second-account-expansion/second-account-expansion-package.json",
        "portfolio-program-profile.json",
        "portfolio-program-package.json",
        "portfolio-evidence/second-account-expansion-package.json",
        "portfolio-evidence/second-account-portfolio-boundary-freeze.json",
        "portfolio-evidence/second-account-expansion-manifest.json",
        "portfolio-evidence/second-account-portfolio-review-summary.json",
        "portfolio-evidence/second-account-expansion-approval.json",
        "portfolio-evidence/second-account-reuse-governance.json",
        "portfolio-evidence/second-account-handoff.json",
        "portfolio-evidence/renewal-qualification-package.json",
        "portfolio-evidence/renewal-boundary-freeze.json",
        "portfolio-evidence/renewal-qualification-manifest.json",
        "portfolio-evidence/outcome-review-summary.json",
        "portfolio-evidence/renewal-approval.json",
        "portfolio-evidence/reference-reuse-discipline.json",
        "portfolio-evidence/expansion-boundary-handoff.json",
        "portfolio-evidence/delivery-continuity-package.json",
        "portfolio-evidence/account-boundary-freeze.json",
        "portfolio-evidence/delivery-continuity-manifest.json",
        "portfolio-evidence/outcome-evidence-summary.json",
        "portfolio-evidence/renewal-gate.json",
        "portfolio-evidence/delivery-escalation-brief.json",
        "portfolio-evidence/customer-evidence-handoff.json",
        "portfolio-evidence/selective-account-activation-package.json",
        "portfolio-evidence/broader-distribution-package.json",
        "portfolio-evidence/reference-distribution-package.json",
        "portfolio-evidence/controlled-adoption-package.json",
        "portfolio-evidence/release-readiness-package.json",
        "portfolio-evidence/trust-network-package.json",
        "portfolio-evidence/assurance-suite-package.json",
        "portfolio-evidence/proof-package.json",
        "portfolio-evidence/inquiry-package.json",
        "portfolio-evidence/inquiry-verification.json",
        "portfolio-evidence/reviewer-package.json",
        "portfolio-evidence/qualification-report.json",
        "portfolio-program-boundary-freeze.json",
        "portfolio-program-manifest.json",
        "program-review-summary.json",
        "portfolio-approval.json",
        "revenue-operations-guardrails.json",
        "program-handoff.json",
        "portfolio-program-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-program-package.json"))
            .expect("read portfolio-program package"),
    )
    .expect("parse portfolio-program package");
    assert_eq!(package["programMotion"], "portfolio_program");
    assert_eq!(package["reviewSurface"], "program_review_bundle");
    assert_eq!(package["portfolioApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let portfolio_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-approval.json")).expect("read portfolio approval"),
    )
    .expect("parse portfolio approval");
    assert_eq!(portfolio_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_portfolio_program_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-portfolio-program-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("portfolio-program")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury portfolio-program validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("portfolio program report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_portfolio_program_only");
    assert_eq!(report["programMotion"], "portfolio_program");
    assert_eq!(report["reviewSurface"], "program_review_bundle");
    for relative_path in [
        "portfolio-program/portfolio-program-package.json",
        "portfolio-program/portfolio-program-boundary-freeze.json",
        "portfolio-program/program-review-summary.json",
        "portfolio-program/portfolio-approval.json",
        "portfolio-program/revenue-operations-guardrails.json",
        "portfolio-program/program-handoff.json",
        "validation-report.json",
        "portfolio-program-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-program-decision.json"))
            .expect("read portfolio-program decision"),
    )
    .expect("parse portfolio-program decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_portfolio_program_only"
    );
    assert_eq!(
        decision_record["selectedProgramMotion"],
        "portfolio_program"
    );
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "program_review_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_second_portfolio_program_export_writes_portfolio_reuse_bundle() {
    let output_dir = unique_path("chio-mercury-second-portfolio-program-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("second-portfolio-program")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury second-portfolio-program export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("second portfolio program summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["programMotion"], "second_portfolio_program");
    assert_eq!(summary["reviewSurface"], "portfolio_reuse_bundle");
    assert_eq!(summary["programOwner"], "mercury-second-portfolio-program");

    for relative_path in [
        "portfolio-program/portfolio-program-package.json",
        "second-portfolio-program-profile.json",
        "second-portfolio-program-package.json",
        "portfolio-reuse-evidence/portfolio-program-package.json",
        "portfolio-reuse-evidence/portfolio-program-boundary-freeze.json",
        "portfolio-reuse-evidence/portfolio-program-manifest.json",
        "portfolio-reuse-evidence/program-review-summary.json",
        "portfolio-reuse-evidence/portfolio-approval.json",
        "portfolio-reuse-evidence/revenue-operations-guardrails.json",
        "portfolio-reuse-evidence/program-handoff.json",
        "portfolio-reuse-evidence/second-account-expansion-package.json",
        "portfolio-reuse-evidence/second-account-portfolio-boundary-freeze.json",
        "portfolio-reuse-evidence/second-account-expansion-manifest.json",
        "portfolio-reuse-evidence/second-account-portfolio-review-summary.json",
        "portfolio-reuse-evidence/second-account-expansion-approval.json",
        "portfolio-reuse-evidence/second-account-reuse-governance.json",
        "portfolio-reuse-evidence/second-account-handoff.json",
        "portfolio-reuse-evidence/renewal-qualification-package.json",
        "portfolio-reuse-evidence/renewal-boundary-freeze.json",
        "portfolio-reuse-evidence/renewal-qualification-manifest.json",
        "portfolio-reuse-evidence/outcome-review-summary.json",
        "portfolio-reuse-evidence/renewal-approval.json",
        "portfolio-reuse-evidence/reference-reuse-discipline.json",
        "portfolio-reuse-evidence/expansion-boundary-handoff.json",
        "portfolio-reuse-evidence/delivery-continuity-package.json",
        "portfolio-reuse-evidence/account-boundary-freeze.json",
        "portfolio-reuse-evidence/delivery-continuity-manifest.json",
        "portfolio-reuse-evidence/outcome-evidence-summary.json",
        "portfolio-reuse-evidence/renewal-gate.json",
        "portfolio-reuse-evidence/delivery-escalation-brief.json",
        "portfolio-reuse-evidence/customer-evidence-handoff.json",
        "portfolio-reuse-evidence/selective-account-activation-package.json",
        "portfolio-reuse-evidence/broader-distribution-package.json",
        "portfolio-reuse-evidence/reference-distribution-package.json",
        "portfolio-reuse-evidence/controlled-adoption-package.json",
        "portfolio-reuse-evidence/release-readiness-package.json",
        "portfolio-reuse-evidence/trust-network-package.json",
        "portfolio-reuse-evidence/assurance-suite-package.json",
        "portfolio-reuse-evidence/proof-package.json",
        "portfolio-reuse-evidence/inquiry-package.json",
        "portfolio-reuse-evidence/inquiry-verification.json",
        "portfolio-reuse-evidence/reviewer-package.json",
        "portfolio-reuse-evidence/qualification-report.json",
        "second-portfolio-program-boundary-freeze.json",
        "second-portfolio-program-manifest.json",
        "portfolio-reuse-summary.json",
        "portfolio-reuse-approval.json",
        "revenue-boundary-guardrails.json",
        "second-program-handoff.json",
        "second-portfolio-program-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("second-portfolio-program-package.json"))
            .expect("read second-portfolio-program package"),
    )
    .expect("parse second-portfolio-program package");
    assert_eq!(package["programMotion"], "second_portfolio_program");
    assert_eq!(package["reviewSurface"], "portfolio_reuse_bundle");
    assert_eq!(package["portfolioReuseApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let portfolio_reuse_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-reuse-approval.json"))
            .expect("read portfolio reuse approval"),
    )
    .expect("parse portfolio reuse approval");
    assert_eq!(portfolio_reuse_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_second_portfolio_program_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-second-portfolio-program-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("second-portfolio-program")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury second-portfolio-program validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("second portfolio program report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_second_portfolio_program_only");
    assert_eq!(report["programMotion"], "second_portfolio_program");
    assert_eq!(report["reviewSurface"], "portfolio_reuse_bundle");
    for relative_path in [
        "second-portfolio-program/second-portfolio-program-package.json",
        "second-portfolio-program/second-portfolio-program-boundary-freeze.json",
        "second-portfolio-program/portfolio-reuse-summary.json",
        "second-portfolio-program/portfolio-reuse-approval.json",
        "second-portfolio-program/revenue-boundary-guardrails.json",
        "second-portfolio-program/second-program-handoff.json",
        "validation-report.json",
        "second-portfolio-program-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("second-portfolio-program-decision.json"))
            .expect("read second-portfolio-program decision"),
    )
    .expect("parse second-portfolio-program decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_second_portfolio_program_only"
    );
    assert_eq!(
        decision_record["selectedProgramMotion"],
        "second_portfolio_program"
    );
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "portfolio_reuse_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_third_program_export_writes_multi_program_reuse_bundle() {
    let output_dir = unique_path("chio-mercury-third-program-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("third-program")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury third-program export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("third program summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["programMotion"], "third_program");
    assert_eq!(summary["reviewSurface"], "multi_program_reuse_bundle");
    assert_eq!(summary["programOwner"], "mercury-third-program");

    for relative_path in [
        "second-portfolio-program/second-portfolio-program-package.json",
        "third-program-profile.json",
        "third-program-package.json",
        "multi-program-evidence/second-portfolio-program-package.json",
        "multi-program-evidence/second-portfolio-program-boundary-freeze.json",
        "multi-program-evidence/second-portfolio-program-manifest.json",
        "multi-program-evidence/portfolio-reuse-summary.json",
        "multi-program-evidence/portfolio-reuse-approval.json",
        "multi-program-evidence/revenue-boundary-guardrails.json",
        "multi-program-evidence/second-program-handoff.json",
        "multi-program-evidence/portfolio-program-package.json",
        "multi-program-evidence/proof-package.json",
        "multi-program-evidence/inquiry-package.json",
        "multi-program-evidence/reviewer-package.json",
        "multi-program-evidence/qualification-report.json",
        "third-program-boundary-freeze.json",
        "third-program-manifest.json",
        "multi-program-reuse-summary.json",
        "approval-refresh.json",
        "multi-program-guardrails.json",
        "third-program-handoff.json",
        "third-program-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("third-program-package.json"))
            .expect("read third-program package"),
    )
    .expect("parse third-program package");
    assert_eq!(package["programMotion"], "third_program");
    assert_eq!(package["reviewSurface"], "multi_program_reuse_bundle");
    assert_eq!(package["approvalRefreshRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let approval_refresh: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("approval-refresh.json")).expect("read approval refresh"),
    )
    .expect("parse approval refresh");
    assert_eq!(approval_refresh["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_third_program_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-third-program-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("third-program")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury third-program validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("third program report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_third_program_only");
    assert_eq!(report["programMotion"], "third_program");
    assert_eq!(report["reviewSurface"], "multi_program_reuse_bundle");
    for relative_path in [
        "third-program/third-program-package.json",
        "third-program/third-program-boundary-freeze.json",
        "third-program/multi-program-reuse-summary.json",
        "third-program/approval-refresh.json",
        "third-program/multi-program-guardrails.json",
        "third-program/third-program-handoff.json",
        "validation-report.json",
        "third-program-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("third-program-decision.json"))
            .expect("read third-program decision"),
    )
    .expect("parse third-program decision");
    assert_eq!(decision_record["decision"], "proceed_third_program_only");
    assert_eq!(decision_record["selectedProgramMotion"], "third_program");
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "multi_program_reuse_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_program_family_export_writes_shared_review_package() {
    let output_dir = unique_path("chio-mercury-program-family-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("program-family")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury program-family export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("program family summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["programMotion"], "program_family");
    assert_eq!(summary["reviewSurface"], "shared_review_package");
    assert_eq!(summary["programFamilyOwner"], "mercury-program-family");

    for relative_path in [
        "third-program/third-program-package.json",
        "program-family-profile.json",
        "program-family-package.json",
        "shared-review-evidence/third-program-package.json",
        "shared-review-evidence/third-program-boundary-freeze.json",
        "shared-review-evidence/third-program-manifest.json",
        "shared-review-evidence/multi-program-reuse-summary.json",
        "shared-review-evidence/approval-refresh.json",
        "shared-review-evidence/multi-program-guardrails.json",
        "shared-review-evidence/third-program-handoff.json",
        "shared-review-evidence/second-portfolio-program-package.json",
        "shared-review-evidence/proof-package.json",
        "shared-review-evidence/inquiry-package.json",
        "shared-review-evidence/reviewer-package.json",
        "shared-review-evidence/qualification-report.json",
        "program-family-boundary-freeze.json",
        "program-family-manifest.json",
        "shared-review-summary.json",
        "shared-review-approval.json",
        "portfolio-claim-discipline.json",
        "family-handoff.json",
        "program-family-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("program-family-package.json"))
            .expect("read program-family package"),
    )
    .expect("parse program-family package");
    assert_eq!(package["programMotion"], "program_family");
    assert_eq!(package["reviewSurface"], "shared_review_package");
    assert_eq!(package["sharedReviewApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let shared_review_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("shared-review-approval.json"))
            .expect("read shared review approval"),
    )
    .expect("parse shared review approval");
    assert_eq!(shared_review_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_program_family_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-program-family-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("program-family")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury program-family validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("program family report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(report["decision"], "proceed_program_family_only");
    assert_eq!(report["programMotion"], "program_family");
    assert_eq!(report["reviewSurface"], "shared_review_package");
    for relative_path in [
        "program-family/program-family-package.json",
        "program-family/program-family-boundary-freeze.json",
        "program-family/shared-review-summary.json",
        "program-family/shared-review-approval.json",
        "program-family/portfolio-claim-discipline.json",
        "program-family/family-handoff.json",
        "validation-report.json",
        "program-family-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("program-family-decision.json"))
            .expect("read program-family decision"),
    )
    .expect("parse program-family decision");
    assert_eq!(decision_record["decision"], "proceed_program_family_only");
    assert_eq!(decision_record["selectedProgramMotion"], "program_family");
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "shared_review_package"
    );

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_portfolio_revenue_boundary_export_writes_commercial_review_bundle() {
    let output_dir = unique_path("chio-mercury-portfolio-revenue-boundary-export", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("portfolio-revenue-boundary")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury portfolio-revenue-boundary export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("portfolio revenue boundary summary json");
    assert_eq!(summary["workflowId"], "workflow-release-control");
    assert_eq!(summary["programMotion"], "portfolio_revenue_boundary");
    assert_eq!(summary["reviewSurface"], "commercial_review_bundle");
    assert_eq!(
        summary["revenueBoundaryOwner"],
        "mercury-portfolio-revenue-boundary"
    );

    for relative_path in [
        "program-family/program-family-package.json",
        "portfolio-revenue-boundary-profile.json",
        "portfolio-revenue-boundary-package.json",
        "commercial-review-evidence/program-family-package.json",
        "commercial-review-evidence/program-family-boundary-freeze.json",
        "commercial-review-evidence/program-family-manifest.json",
        "commercial-review-evidence/shared-review-summary.json",
        "commercial-review-evidence/shared-review-approval.json",
        "commercial-review-evidence/portfolio-claim-discipline.json",
        "commercial-review-evidence/family-handoff.json",
        "commercial-review-evidence/third-program-package.json",
        "commercial-review-evidence/proof-package.json",
        "commercial-review-evidence/inquiry-package.json",
        "commercial-review-evidence/reviewer-package.json",
        "commercial-review-evidence/qualification-report.json",
        "revenue-boundary-freeze.json",
        "revenue-boundary-manifest.json",
        "commercial-review-summary.json",
        "commercial-approval.json",
        "channel-boundary-rules.json",
        "commercial-handoff.json",
        "portfolio-revenue-boundary-summary.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-revenue-boundary-package.json"))
            .expect("read portfolio-revenue-boundary package"),
    )
    .expect("parse portfolio-revenue-boundary package");
    assert_eq!(package["programMotion"], "portfolio_revenue_boundary");
    assert_eq!(package["reviewSurface"], "commercial_review_bundle");
    assert_eq!(package["commercialApprovalRequired"], true);
    assert_eq!(package["failClosed"], true);
    assert_eq!(package["artifacts"].as_array().expect("artifacts").len(), 6);

    let commercial_approval: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("commercial-approval.json")).expect("read commercial approval"),
    )
    .expect("parse commercial approval");
    assert_eq!(commercial_approval["status"], "ready");

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn mercury_portfolio_revenue_boundary_validate_writes_validation_report_and_decision() {
    let output_dir = unique_path("chio-mercury-portfolio-revenue-boundary-validate", "");

    let output = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("portfolio-revenue-boundary")
        .arg("validate")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run mercury portfolio-revenue-boundary validate");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("portfolio revenue boundary report json");
    assert_eq!(report["workflowId"], "workflow-release-control");
    assert_eq!(
        report["decision"],
        "proceed_portfolio_revenue_boundary_only"
    );
    assert_eq!(report["programMotion"], "portfolio_revenue_boundary");
    assert_eq!(report["reviewSurface"], "commercial_review_bundle");
    for relative_path in [
        "portfolio-revenue-boundary/portfolio-revenue-boundary-package.json",
        "portfolio-revenue-boundary/revenue-boundary-freeze.json",
        "portfolio-revenue-boundary/commercial-review-summary.json",
        "portfolio-revenue-boundary/commercial-approval.json",
        "portfolio-revenue-boundary/channel-boundary-rules.json",
        "portfolio-revenue-boundary/commercial-handoff.json",
        "validation-report.json",
        "portfolio-revenue-boundary-decision.json",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let decision_record: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("portfolio-revenue-boundary-decision.json"))
            .expect("read portfolio-revenue-boundary decision"),
    )
    .expect("parse portfolio-revenue-boundary decision");
    assert_eq!(
        decision_record["decision"],
        "proceed_portfolio_revenue_boundary_only"
    );
    assert_eq!(
        decision_record["selectedProgramMotion"],
        "portfolio_revenue_boundary"
    );
    assert_eq!(
        decision_record["selectedReviewSurface"],
        "commercial_review_bundle"
    );

    let _ = fs::remove_dir_all(output_dir);
}
