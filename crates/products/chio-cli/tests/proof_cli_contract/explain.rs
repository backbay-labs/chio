use super::support::*;
use chio_test_support::prelude::*;

#[test]
fn proof_explain_reports_claim_status_and_evidence_path() {
    let bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim_id\":\"claim.transaction.passport_root_verified\""));
    assert!(stdout.contains("\"status\":\"verified\""));
    assert!(stdout.contains("\"transaction-passport.json\""));
}

#[test]
fn proof_explain_rejects_unknown_claim_id() {
    let bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.example.fabricated",
        "--json",
    ]);

    assert_failure(&output, "unknown proof claim: claim.example.fabricated");
}

#[test]
fn proof_explain_reports_swarm_claims_as_verified() {
    let bundle =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.swarm.task_graph_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.swarm.task_graph_bound");
    assert_eq!(report["status"], "verified");
    assert!(report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array")
        .iter()
        .any(|path| path
            .as_str()
            .is_some_and(|path| path.ends_with("transaction-passport.json"))));
}

#[test]
fn proof_explain_reports_agent_web_projection_reasoning() {
    let bundle = workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.agent_web.unsupported_claims_limited",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(
        report["claim_id"],
        "claim.agent_web.unsupported_claims_limited"
    );
    assert_eq!(report["status"], "verified");
    let agent_web = &report["agent_web"];
    assert!(agent_web["projections"]
        .as_array()
        .test_expect("Agent Web projections array")
        .iter()
        .any(|projection| projection["source_protocol"] == "mcp"
            && projection["external_subject_digest"].as_str().is_some()));
    assert!(agent_web["unsupported_claims"]
        .as_array()
        .test_expect("Agent Web unsupported claims array")
        .iter()
        .any(|claim| claim == "claim.external.mcp_tool_call_is_chio_authority"));
    assert!(agent_web["limitations"]
        .as_array()
        .test_expect("Agent Web limitations array")
        .iter()
        .any(|limitation| limitation
            .as_str()
            .is_some_and(|limitation| limitation.contains("not Chio capability authority"))));
}

#[test]
fn proof_explain_reports_risk_facility_reasoning() {
    let bundle =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.risk.comptroller_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.risk.comptroller_report_bound");
    assert_eq!(report["status"], "verified");
    let risk = &report["risk"];
    assert_eq!(
        risk["risk_comptroller_report_ref"],
        "risk-comptroller-enterprise-valid"
    );
    assert_eq!(risk["facility"]["state"], "settlement_matched");
    assert!(risk["facility_lifecycle"]
        .as_array()
        .test_expect("risk facility lifecycle array")
        .iter()
        .any(|transition| transition["from_state"] == "coverage_bound"
            && transition["to_state"] == "settlement_matched"));
    assert_eq!(risk["reconciliation"]["status"], "balanced");
    assert_eq!(risk["actuarial_evidence"]["backtest"]["status"], "passed");
    assert_eq!(
        risk["insurance_copy"]["coverage_statement"],
        "coverage limited to supported exposure"
    );
}

#[test]
fn proof_explain_reports_risk_sanction_reserve_ledger() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_sanction_backed_market_slash(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.risk.comptroller_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.risk.comptroller_report_bound");
    assert_eq!(report["status"], "verified", "report: {report}");
    let sanction_ledger = report["risk"]["sanction_reserve_ledger"]
        .as_array()
        .test_expect("risk sanction reserve ledger array");
    assert!(sanction_ledger.iter().any(|entry| entry["bridge_id"]
        == "sanction-bridge-risk-market-slash"
        && entry["jurisdiction_ref"] == "approval-case"));
}

#[test]
fn proof_explain_reports_domain_claim_evidence_graph() {
    let bundle =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.enterprise.control_map_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.enterprise.control_map_bound");
    assert_eq!(report["status"], "verified");
    let evidence_paths = report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array");
    assert!(evidence_paths.iter().any(|path| path
        .as_str()
        .is_some_and(|path| path.ends_with("evidence-graph.json"))));
    assert!(evidence_paths.iter().any(|path| path
        .as_str()
        .is_some_and(|path| path.ends_with("verifier-policy.json"))));
}

#[test]
fn proof_explain_reports_negative_passport_verifier_failure() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(
        report["claim_id"],
        "claim.transaction.passport_root_verified"
    );
    assert_eq!(report["status"], "failed");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:passport-hash-mismatch"
    );
    assert!(report["verifier_error"]
        .as_str()
        .test_expect("verifier error string")
        .contains("verifier policy digest mismatch"));
    let evidence_paths = report["evidence_paths"]
        .as_array()
        .test_expect("evidence paths array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(evidence_paths
        .iter()
        .any(|path| path.ends_with("transaction-passport.json")));
    assert!(evidence_paths
        .iter()
        .any(|path| path.ends_with("verifier-policy.json")));
}

#[test]
fn proof_explain_reports_unsupported_passport_schema_failure_code() {
    let bundle =
        workspace_root().join("fixtures/proof-room/minimal-passport/unknown-passport-schema");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");

    assert_eq!(report["status"], "failed");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:passport-schema-unsupported"
    );
}

#[test]
fn proof_explain_reports_runtime_proof_rejection_failure_code() {
    let bundle =
        workspace_root().join("fixtures/proof-room/runtime-security/missing-execution-lease");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.runtime.execution_lease_valid",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");

    assert_eq!(report["status"], "failed");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:runtime-proof-rejected"
    );
}

#[test]
fn proof_explain_text_reports_negative_passport_verifier_failure() {
    let bundle = workspace_root()
        .join("fixtures/proof-room/minimal-passport/evidence-graph-digest-mismatch");
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.transaction.passport_root_verified",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("status: failed"));
    assert!(stdout.contains("verifier-error:"));
    assert!(stdout.contains("evidence graph digest mismatch"));
}

#[test]
fn proof_explain_reports_proof_room_claim_sources() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    for claim in [
        "claim.proof_room.allow_and_deny_visible",
        "claim.proof_room.receipt_coverage_matrix_bound",
    ] {
        let output = chio(&[
            "proof",
            "explain",
            bundle.as_str(),
            "--claim",
            claim,
            "--json",
        ]);

        assert_success(&output);
        let stdout = stdout(output);
        assert!(stdout.contains(&format!("\"claim_id\":\"{claim}\"")));
        assert!(stdout.contains("\"status\":\"verified\""));
        assert!(stdout.contains("artifacts/receipts/allow-receipt.json"));
        assert!(stdout.contains("artifacts/receipts/denial-receipt.json"));
    }
}

#[test]
fn proof_explain_reports_proof_room_manifest_claim_metadata() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.proof_room.verifier_report_bound",
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    assert_eq!(report["claim_id"], "claim.proof_room.verifier_report_bound");
    assert_eq!(report["status"], "verified");
    assert_eq!(
        report["checker"],
        "chio proof doctor --scenario single-call-authority"
    );
    assert_eq!(report["proof_level"], "hash-bound-display-report");
    assert_eq!(
        report["caveat"],
        "The UI report is a consumer of verifier output, not a proof source."
    );
}

#[test]
fn proof_explain_reports_receipt_coverage_exclusions_for_matrix_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-denial-receipt");
    copy_dir_all(&source, &artifact_path).test_expect("copy artifact dir");
    sign_transaction_receipt_artifact(&artifact_path, "kernel-receipt.json");

    let kernel_receipt_path = artifact_path.join("kernel-receipt.json");
    let kernel_receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&kernel_receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    let policy_digest = kernel_receipt["policy_digest"]
        .as_str()
        .test_expect("receipt policy digest")
        .to_string();
    write_json(
        &artifact_path.join("denial-receipt.json"),
        &signed_terminal_receipt(
            "receipt-terminal-denial",
            "denied_guard_request",
            &policy_digest,
        ),
    );

    let evidence_graph_path = artifact_path.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let denial_receipt_sha256 = sha256_file(&artifact_path.join("denial-receipt.json"));
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": denial_receipt_sha256,
            "schema": "chio.receipt.v1",
            "path": "denial-receipt.json",
            "sha256": denial_receipt_sha256,
            "role": "receipt"
        }));
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = artifact_path.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    let out_path = tempdir.path().join("collected-terminal-exclusions");
    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&collect);

    let explain = chio(&[
        "proof",
        "explain",
        utf8_path(&out_path).as_str(),
        "--claim",
        "claim.proof_room.receipt_coverage_matrix_bound",
        "--json",
    ]);
    assert_success(&explain);
    let stdout = stdout(explain);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("explain report parses");
    let coverage = report["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array");
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_failure"
            && entry["status"] == "excluded"
            && entry["exclusion_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("runtime_terminal_failure"))
    }));
}

#[test]
fn proof_explain_text_reports_receipt_coverage_exclusions_for_matrix_claim() {
    let bundle = proof_room_bundle_fixture();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "explain",
        bundle.as_str(),
        "--claim",
        "claim.proof_room.receipt_coverage_matrix_bound",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("coverage: runtime_terminal_allow covered"));
    assert!(stdout.contains("coverage: runtime_terminal_denial covered"));
    assert!(stdout.contains("coverage: runtime_terminal_failure excluded"));
    assert!(stdout.contains(
        "Single-call authority fixture covers allow and guard denial terminal receipts only."
    ));
}
