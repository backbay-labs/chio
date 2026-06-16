use super::support::*;
use chio_test_support::prelude::*;
use std::path::PathBuf;

#[test]
fn proof_verify_requires_commerce_claims_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let commerce_bundle =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let commerce_bundle = utf8_path(&commerce_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "commerce",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: commerce",
    );

    let commerce_output = chio(&[
        "proof",
        "verify",
        commerce_bundle.as_str(),
        "--require",
        "commerce",
    ]);

    assert_success(&commerce_output);
}

#[test]
fn proof_verify_rejects_commerce_payment_wrong_transfer_group() {
    let (_tempdir, bundle) = build_commerce_transfer_group_mismatch_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "commerce"]);

    assert_failure(&output, "payment transfer group mismatch");
}

#[test]
fn proof_verify_requires_runtime_claims_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let runtime_bundle =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let runtime_bundle = utf8_path(&runtime_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "runtime",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: runtime",
    );

    let runtime_output = chio(&[
        "proof",
        "verify",
        runtime_bundle.as_str(),
        "--require",
        "runtime",
    ]);

    assert_success(&runtime_output);
}

#[test]
fn proof_verify_runtime_requirement_rejects_advisory_only_runtime_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let bundle = tempdir.path().join("runtime-advisory-only");
    copy_dir_all(&source, &bundle).test_expect("copy runtime bundle");

    let verifier_policy_path = bundle.join("verifier-policy.json");
    let mut verifier_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("verifier policy parses");
    verifier_policy["required_claims"] =
        serde_json::json!(["claim.runtime.advisory_not_used_as_authorization"]);
    write_json(&verifier_policy_path, &verifier_policy);
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let policy_node = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .iter_mut()
        .find(|node| {
            node.get("role").and_then(serde_json::Value::as_str) == Some("verifier-policy")
        })
        .test_expect("verifier policy graph node");
    policy_node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256);
    write_json(&passport_path, &passport);

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "runtime",
    ]);

    assert_failure(&output, "required proof runtime authority missing");
}

#[test]
fn proof_verify_accepts_mixed_runtime_and_commerce_claim_policy() {
    let (_tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        bundle.as_str(),
        "--require",
        "runtime",
        "--require",
        "commerce",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
}

#[test]
fn proof_verify_accepts_integrated_runtime_commerce_settlement_and_agent_web_claim_policy() {
    let (_tempdir, bundle) = build_integrated_runtime_commerce_settlement_agent_web_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        bundle.as_str(),
        "--require",
        "runtime",
        "--require",
        "commerce",
        "--require",
        "settlement",
        "--require",
        "external-envelope",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.public_settlement.finality_verified\""));
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_verify_routes_risk_only_policy_through_domain_verifiers() {
    for (fixture_path, bundle_name) in [
        (
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "enterprise-risk-only",
        ),
        (
            "fixtures/proof-room/trust-market/valid-marketplace-context",
            "trust-market-risk-only",
        ),
    ] {
        let (_tempdir, bundle) = build_risk_only_policy_bundle(fixture_path, bundle_name);
        let bundle = utf8_path(&bundle);

        let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

        assert_success(&output);
        let stdout = stdout(output);
        assert!(stdout.contains("\"claim.risk.comptroller_report_bound\""));
    }
}

#[test]
fn proof_verify_routes_standalone_risk_policy_through_risk_comptroller() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"claim.risk.comptroller_report_bound\""));
    assert!(
        stdout.contains("\"risk_comptroller_report_ref\":\"risk-comptroller-enterprise-valid\"")
    );
}

#[test]
fn proof_verify_scopes_enterprise_verifier_to_enterprise_evidence() {
    let (_tempdir, bundle) = build_enterprise_bundle_with_unrelated_runtime_evidence();
    let bundle = utf8_path(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        bundle.as_str(),
        "--require",
        "enterprise",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.enterprise.control_map_bound\""));
}

#[test]
fn proof_verify_rejects_standalone_risk_with_unbound_evidence_ref() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    remove_standalone_risk_graph_node(&bundle, "data-governance-report");
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk facility lifecycle evidence missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_with_unbound_reserve_ledger_refs() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_unbound_reserve_ledger(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk reserve ledger receipt missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_lifecycle_authority_wrong_evidence_kind() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    point_standalone_risk_lifecycle_authority_at_supporting_evidence(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk facility lifecycle authority missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_denied_approval_case() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    deny_standalone_risk_approval_case(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk approval case denied");
}

#[test]
fn proof_verify_rejects_standalone_risk_with_uncovered_reserve_ledger_claim() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    add_standalone_risk_uncovered_reserve_ledger_claim(&bundle);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk claim outside coverage");
}

#[test]
fn proof_verify_requires_denial_evidence_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);
    let proof_room_bundle = proof_room_bundle_fixture();
    let proof_room_bundle = utf8_path(&proof_room_bundle);

    let minimal_output = chio(&[
        "proof",
        "verify",
        minimal_bundle.as_str(),
        "--require",
        "denials",
    ]);

    assert_failure(
        &minimal_output,
        "required proof claim family missing: denials",
    );

    let proof_room_output = chio(&[
        "proof",
        "verify",
        proof_room_bundle.as_str(),
        "--require",
        "denials",
    ]);

    assert_success(&proof_room_output);
}

#[test]
fn proof_verify_file_input_revalidates_sibling_manifest_before_denials_requirement() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("passport-with-forged-manifest");
    copy_dir_all(&source, &bundle).test_expect("copy minimal passport fixture");

    let manifest_path = bundle.join("manifest.json");
    let manifest = serde_json::json!({
        "schema": "chio.proof-room.bundle.v1",
        "claims": [
            {
                "claim_id": "claim.proof_room.allow_and_deny_visible",
                "required_artifacts": [],
                "checker": "forged",
                "result": "verified",
                "proof_level": "fixture-evidence",
                "caveat": "",
                "source_refs": []
            }
        ]
    });
    write_json(&manifest_path, &manifest);

    let passport_path = bundle.join("transaction-passport.json");
    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&passport_path).as_str(),
        "--require",
        "denials",
    ]);

    assert_failure(&output, "proof room bundle");
}

#[test]
fn proof_verify_requires_documented_claim_families_when_requested() {
    let minimal_bundle = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let minimal_bundle = utf8_path(&minimal_bundle);

    for (requirement, fixture_path, expected_label) in [
        (
            "delegation",
            "fixtures/proof-room/swarm-authority/valid-recursive-delegation",
            "delegation",
        ),
        (
            "disclosure",
            "fixtures/proof-room/disclosure-lineage/valid-lineage-ledger",
            "disclosure",
        ),
        (
            "enterprise",
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "enterprise",
        ),
        (
            "settlement",
            "fixtures/proof-room/public-settlement/valid-offline-finality",
            "settlement",
        ),
        (
            "trust-market",
            "fixtures/proof-room/trust-market/valid-marketplace-context",
            "trust-market",
        ),
        (
            "external-envelope",
            "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
            "external-envelope",
        ),
        (
            "risk",
            "fixtures/proof-room/enterprise-export/valid-autonomous-commerce",
            "risk",
        ),
    ] {
        let minimal_output = chio(&[
            "proof",
            "verify",
            minimal_bundle.as_str(),
            "--require",
            requirement,
        ]);
        assert_failure(
            &minimal_output,
            &format!("required proof claim family missing: {expected_label}"),
        );

        let proof_bundle = workspace_root().join(fixture_path);
        let proof_bundle = utf8_path(&proof_bundle);
        let proof_output = chio(&[
            "proof",
            "verify",
            proof_bundle.as_str(),
            "--require",
            requirement,
        ]);
        assert_success(&proof_output);
    }
}

#[test]
fn proof_verify_runtime_parity_requires_explicit_parity_evidence() {
    let runtime_bundle =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let runtime_bundle = utf8_path(&runtime_bundle);

    let output = chio(&[
        "proof",
        "verify",
        runtime_bundle.as_str(),
        "--require",
        "runtime-parity",
    ]);

    assert_failure(&output, "required proof runtime parity missing");
}

fn build_swarm_bundle_with_runtime_parity() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle = tempdir.path().join("swarm-with-runtime-parity");
    copy_dir_all(&source, &bundle).test_expect("copy swarm bundle");

    let parity_path = bundle.join("runtime-proof-parity-report.json");
    write_json(
        &parity_path,
        &serde_json::json!({
            "schema": "chio.runtime.proof-parity-report.v1",
            "runId": "runtime-swarm-valid",
            "accepted": true,
            "generatedAtUnixMs": 1800000001000_u64,
            "staticProofPackageSha256": "a".repeat(64),
            "runtimeProofPackageSha256": "a".repeat(64),
            "staticVerifierReportSha256": "b".repeat(64),
            "runtimeVerifierReportSha256": "b".repeat(64),
            "comparedFields": ["workflow_id", "workflow_steps"],
            "mismatches": []
        }),
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": "runtime-proof-parity-report",
            "schema": "chio.runtime.proof-parity-report.v1",
            "path": "runtime-proof-parity-report.json",
            "sha256": sha256_file(&parity_path),
            "role": "runtime-proof-parity-report"
        }));
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

#[test]
fn proof_verify_runtime_parity_accepts_evidence_graph_bound_report() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    assert!(stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(stdout.contains("\"runtime_proof_parity_report\""));
    assert!(stdout.contains("\"runId\":\"runtime-swarm-valid\""));
}

#[test]
fn proof_verify_runtime_parity_rejects_accepted_package_hash_drift() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();
    let parity_path = bundle.join("runtime-proof-parity-report.json");
    let mut parity_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&parity_path).test_expect("read parity report"))
            .test_expect("parity report parses");
    parity_report["runtimeProofPackageSha256"] = serde_json::Value::String("c".repeat(64));
    write_json(&parity_path, &parity_report);
    refresh_transaction_artifact_digest(&bundle, "runtime-proof-parity-report.json");

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_failure(&output, "runtime_proof_parity_accepted_package_hash_drift");
}

#[test]
fn proof_collect_runtime_spine_requires_delegation_and_runtime_parity() {
    let (tempdir, artifact_dir) = build_swarm_bundle_with_runtime_parity();
    let out_path = tempdir.path().join("collected-runtime-spine");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "runtime-spine",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).test_expect("collect report parses");
    assert_eq!(
        report.get("kind").and_then(serde_json::Value::as_str),
        Some("runtime-spine")
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    assert_eq!(
        manifest
            .get("source_command")
            .and_then(serde_json::Value::as_str),
        Some("chio proof collect --kind runtime-spine")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);
    assert_success(&verify);
}
