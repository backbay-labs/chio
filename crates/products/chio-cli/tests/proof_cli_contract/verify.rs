use super::support::*;
use chio_core::{canonical_json_bytes, sha256_hex, Keypair};
use chio_swarm_authority::{sign_swarm_task_graph, SwarmTaskGraph};
use chio_test_support::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
fn proof_verify_commerce_requires_dedicated_commerce_trust_roots() {
    let commerce_bundle =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let commerce_bundle = utf8_path(&commerce_bundle);
    let mut command = chio_command();
    command.env_remove("CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS");
    command.env_remove("CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS");

    let output = command
        .args([
            "proof",
            "verify",
            commerce_bundle.as_str(),
            "--require",
            "commerce",
        ])
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS must pin trusted commerce event authority receipt kernel keys",
    );
}

#[test]
fn proof_verify_commerce_rejects_untrusted_event_authority_root() {
    let commerce_bundle =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let commerce_bundle = utf8_path(&commerce_bundle);
    let mut command = chio_command();
    command.env(
        "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
        "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
    );

    let output = command
        .args([
            "proof",
            "verify",
            commerce_bundle.as_str(),
            "--require",
            "commerce",
        ])
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "authority receipt kernel key untrusted");
}

#[test]
fn proof_verify_commerce_rejects_untrusted_payment_signer_root() {
    let commerce_bundle =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let commerce_bundle = utf8_path(&commerce_bundle);
    let mut command = chio_command();
    command.env(
        "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
        "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
    );

    let output = command
        .args([
            "proof",
            "verify",
            commerce_bundle.as_str(),
            "--require",
            "commerce",
        ])
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "payment signer untrusted");
}

#[test]
fn proof_verify_rejects_commerce_payment_wrong_transfer_group() {
    let (_tempdir, bundle) = build_commerce_transfer_group_mismatch_bundle();
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "commerce"]);

    assert_failure(&output, "payment transfer group mismatch");
}

#[test]
fn proof_verify_rejects_commerce_claim_set_required_claim_not_verified() {
    let (_tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let report_dir = tempfile::tempdir().test_expect("tempdir");
    let out = report_dir.path().join("required-claim-missing-report.json");

    let claim_set_path = bundle.join("claim-set.json");
    let mut claim_set: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claim_set_path).test_expect("read claim set"))
            .test_expect("claim set parses");
    let claims = claim_set["claims"]
        .as_array_mut()
        .test_expect("claim set claims array");
    let claim = claims
        .iter_mut()
        .find(|claim| {
            claim.get("claim_id").and_then(serde_json::Value::as_str)
                == Some("claim.commerce.order_replay_consistent")
        })
        .test_expect("commerce claim exists");
    claim["status"] = serde_json::Value::String("omitted".to_string());
    write_json(&claim_set_path, &claim_set);
    let claim_set_sha256 = sha256_file(&claim_set_path);
    refresh_transaction_artifact_digest(&bundle, "claim-set.json");

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    write_json(&passport_path, &passport);

    let transaction_input_dir = report_dir.path().join("transaction-input");
    copy_dir_all(&bundle, &transaction_input_dir).test_expect("copy transaction input");
    let transaction_manifest = transaction_input_dir.join("manifest.json");
    if transaction_manifest.is_file() {
        std::fs::remove_file(transaction_manifest).test_expect("remove proof room manifest");
    }
    let passport_input = utf8_path(&transaction_input_dir.join("transaction-passport.json"));
    let output = chio(&[
        "proof",
        "verify",
        passport_input.as_str(),
        "--require",
        "commerce",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(
        &output,
        "claim set required claim was not verified: claim.commerce.order_replay_consistent",
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).test_expect("failed report was written"))
            .test_expect("failed report parses");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:required-claim-missing"
    );
}

#[test]
fn proof_verify_wraps_single_family_domain_report_with_machine_result_fields() {
    let fixture = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out = tempdir.path().join("commerce-report.json");

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&fixture).as_str(),
        "--require",
        "commerce",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).test_expect("commerce report was written"))
            .test_expect("commerce report parses");
    assert_json_schema_accepts(
        "spec/schemas/chio-transaction/v1/verifier-report.schema.json",
        &report,
    );
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["accepted"], true);
    assert_eq!(report["state"], "verified");
    assert_eq!(report["claimResults"][0]["status"], "verified");
    assert_eq!(
        report["claimResults"][0]["verifier_module"],
        "chio proof verify --require commerce"
    );
    assert_eq!(
        report["family_reports"][0]["schema"],
        "chio.commerce.order-passport.v1"
    );
}

#[test]
fn commerce_verify_exposes_dedicated_commerce_report_surface() {
    let fixture = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out = tempdir.path().join("commerce-report.json");

    let output = chio(&[
        "commerce",
        "verify",
        utf8_path(&fixture).as_str(),
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).test_expect("commerce report was written"))
            .test_expect("commerce report parses");
    assert_json_schema_accepts(
        "spec/schemas/chio-transaction/v1/verifier-report.schema.json",
        &report,
    );
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["accepted"], true);
    assert!(report["verified_claims"]
        .as_array()
        .test_expect("verified claims array")
        .iter()
        .any(|claim| claim.as_str() == Some("claim.commerce.order_replay_consistent")));
    assert!(report["claimResults"]
        .as_array()
        .test_expect("claim results array")
        .iter()
        .any(|claim| {
            claim
                .get("verifier_module")
                .and_then(serde_json::Value::as_str)
                == Some("chio commerce verify")
        }));
}

#[test]
fn proof_verify_writes_failed_transaction_report_to_out() {
    let fixture = workspace_root()
        .join("fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch");
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out = tempdir.path().join("failed-transaction-report.json");

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&fixture).as_str(),
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(&output, "verifier policy digest mismatch");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).test_expect("failed report was written"))
            .test_expect("failed report parses");
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "failed");
    assert_eq!(report["accepted"], false);
    assert_eq!(report["state"], "failed");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:passport-hash-mismatch"
    );
    assert_eq!(report["claimResults"][0]["status"], "failed");
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
        "required proof runtime authority missing: claim.runtime.execution_lease_valid",
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

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport["id"].as_str().test_expect("passport has id"),
        passport["issued_at"]
            .as_str()
            .test_expect("passport has issued_at"),
        &verifier_policy,
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256);
    write_json(&passport_path, &passport);
    sync_proof_room_transaction_roots(&bundle);
    retain_proof_room_manifest_claims(
        &bundle,
        &[
            "claim.transaction.passport_root_verified",
            "claim.proof_room.verifier_report_bound",
            "claim.runtime.advisory_not_used_as_authorization",
        ],
    );

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
fn proof_verify_rejects_integrated_commerce_settlement_order_mismatch() {
    let (_tempdir, bundle) =
        build_integrated_runtime_commerce_settlement_agent_web_bundle_with_mismatched_orders();
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
    ]);

    assert_failure(
        &output,
        "proof verify: public settlement commerce order mismatch",
    );
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
fn proof_verify_rejects_standalone_risk_tampered_supporting_evidence() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    tamper_standalone_risk_supporting_evidence_without_rehash(&bundle);
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
fn proof_verify_rejects_standalone_risk_duplicate_approval_quorum() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    set_standalone_risk_approval_quorum(
        &bundle,
        &[
            "did:chio:enterprise-reviewer",
            "did:chio:enterprise-reviewer",
        ],
        2,
    );
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk approval approver duplicate");
}

#[test]
fn proof_verify_rejects_standalone_risk_blank_approval_quorum() {
    let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
    set_standalone_risk_approval_quorum(&bundle, &["", "did:chio:enterprise-reviewer"], 2);
    let bundle = utf8_path(&bundle);

    let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

    assert_failure(&output, "risk approval approver missing");
}

#[test]
fn proof_verify_rejects_standalone_risk_approval_outside_validity_window() {
    for (issued_at, expires_at) in [
        ("2026-06-01T00:00:00Z", "2026-06-09T00:00:00Z"),
        ("2026-06-11T00:00:00Z", "2026-06-12T00:00:00Z"),
    ] {
        let (_tempdir, bundle) = build_standalone_risk_only_policy_bundle();
        set_standalone_risk_approval_window(&bundle, issued_at, expires_at);
        let bundle = utf8_path(&bundle);

        let output = chio(&["proof", "verify", bundle.as_str(), "--require", "risk"]);

        assert_failure(&output, "risk approval case outside validity window");
    }
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
        if requirement == "delegation" {
            assert_failure(
                &minimal_output,
                "required delegation claim not verified: claim.swarm.continuation_fresh",
            );
        } else {
            assert_failure(
                &minimal_output,
                &format!("required proof claim family missing: {expected_label}"),
            );
        }

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
fn proof_verify_delegation_requirement_rejects_root_only_swarm() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle = tempdir.path().join("root-only-swarm");
    copy_dir_all(&source, &bundle).test_expect("copy swarm bundle");

    let task_graph_path = bundle.join("task-graph.json");
    let mut task_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&task_graph_path).test_expect("read task graph"))
            .test_expect("task graph parses");
    let root_node = task_graph["nodes"][0].clone();
    task_graph["nodes"] = serde_json::json!([root_node]);
    task_graph["edges"] = serde_json::json!([]);
    task_graph["joins"] = serde_json::json!([]);
    task_graph["routePlanRefs"] = serde_json::json!([]);
    sign_swarm_task_graph_value(&mut task_graph);
    write_json(&task_graph_path, &task_graph);

    let budget_pool_path = bundle.join("budget-pool.json");
    let mut budget_pool: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&budget_pool_path).test_expect("read budget pool"))
            .test_expect("budget pool parses");
    budget_pool["allocations"] = serde_json::json!([]);
    write_json(&budget_pool_path, &budget_pool);

    let verifier_policy_path = bundle.join("verifier-policy.json");
    let mut verifier_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("verifier policy parses");
    verifier_policy["required_claims"] = serde_json::json!([
        "claim.swarm.task_graph_bound",
        "claim.swarm.budget_pool_bound",
        "claim.swarm.revocation_epoch_bound"
    ]);
    write_json(&verifier_policy_path, &verifier_policy);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes array");
    nodes.retain(|node| {
        node.get("role")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|role| {
                matches!(
                    role,
                    "swarm-task-graph"
                        | "swarm-budget-pool"
                        | "swarm-revocation-epoch"
                        | "verifier-policy"
                )
            })
    });
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    let retained_node_ids = evidence_graph["nodes"]
        .as_array()
        .test_expect("evidence graph nodes array")
        .iter()
        .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
        .map(std::string::ToString::to_string)
        .collect::<BTreeSet<_>>();
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges array")
        .retain(|edge| {
            let from = edge.get("from").and_then(serde_json::Value::as_str);
            let to = edge.get("to").and_then(serde_json::Value::as_str);
            from.is_some_and(|from| retained_node_ids.contains(from))
                && to.is_some_and(|to| retained_node_ids.contains(to))
        });
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    passport["verifier_policy_sha256"] =
        serde_json::Value::String(sha256_file(&verifier_policy_path));
    write_json(&passport_path, &passport);

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
    ]);

    assert_failure(&output, "signed swarm delegation evidence missing");
}

fn sign_swarm_task_graph_value(task_graph: &mut serde_json::Value) {
    let mut graph: SwarmTaskGraph =
        serde_json::from_value(task_graph.clone()).test_expect("task graph decodes");
    graph.signature = sign_swarm_task_graph(&graph, &Keypair::from_seed(&[31u8; 32]))
        .test_expect("task graph signs");
    *task_graph = serde_json::to_value(graph).test_expect("task graph encodes");
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

    write_runtime_regeneration_artifacts(&bundle);

    let parity_path = bundle.join("runtime-proof-parity-report.json");
    write_json(
        &parity_path,
        &serde_json::json!({
            "schema": "chio.runtime.proof-parity-report.v1",
            "runId": "runtime-swarm-valid",
            "accepted": true,
            "generatedAtUnixMs": 1800000001000_u64,
            "staticProofPackageSha256": canonical_file_sha256(&bundle.join("runtime-proof-package.json")),
            "runtimeProofPackageSha256": canonical_file_sha256(&bundle.join("runtime-proof-package.json")),
            "staticVerifierReportSha256": canonical_file_sha256(&bundle.join("runtime-verifier-report.json")),
            "runtimeVerifierReportSha256": canonical_file_sha256(&bundle.join("runtime-verifier-report.json")),
            "comparedFields": ["workflow_id", "workflow_steps"],
            "mismatches": []
        }),
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let graph_nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    let parity_sha256 = sha256_file(&parity_path);
    graph_nodes.push(serde_json::json!({
            "id": parity_sha256,
            "schema": "chio.runtime.proof-parity-report.v1",
            "path": "runtime-proof-parity-report.json",
            "sha256": parity_sha256,
            "role": "runtime-proof-parity-report"
    }));
    for (role, schema, path) in [
        (
            "runtime-proof-regeneration-report",
            "chio.runtime.proof-regeneration-report.v1",
            "proof-regeneration-report.json",
        ),
        (
            "runtime-proof-regeneration-input",
            "chio.runtime.proof-regeneration-input.v1",
            "proof-regeneration-input.json",
        ),
        (
            "runtime-evidence-manifest",
            "chio.runtime.evidence-manifest.v1",
            "runtime-evidence-manifest.json",
        ),
        (
            "runtime-workflow-run-report",
            "chio.runtime.workflow-run-report.v1",
            "runtime-workflow-run-report.json",
        ),
        (
            "runtime-proof-package",
            "test.runtime-proof-package.v1",
            "runtime-proof-package.json",
        ),
        (
            "runtime-verifier-report",
            "test.runtime-verifier-report.v1",
            "runtime-verifier-report.json",
        ),
        (
            "runtime-workflow-receipt",
            "test.runtime-workflow-receipt.v1",
            "runtime-workflow-receipt.json",
        ),
    ] {
        let sha256 = sha256_file(&bundle.join(path));
        graph_nodes.push(serde_json::json!({
            "id": sha256,
            "schema": schema,
            "path": path,
            "sha256": sha256,
            "role": role
        }));
    }
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
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

fn write_runtime_regeneration_artifacts(bundle: &Path) {
    let proof_package = serde_json::json!({
        "schema": "test.runtime-proof-package.v1",
        "packageId": "runtime-swarm-proof-package"
    });
    let verifier_report = serde_json::json!({
        "schema": "test.runtime-verifier-report.v1",
        "verdict": "verified"
    });
    let workflow_receipt = serde_json::json!({
        "schema": "test.runtime-workflow-receipt.v1",
        "receiptId": "runtime-swarm-workflow-receipt"
    });
    write_json(&bundle.join("runtime-proof-package.json"), &proof_package);
    write_json(
        &bundle.join("runtime-verifier-report.json"),
        &verifier_report,
    );
    write_json(
        &bundle.join("runtime-workflow-receipt.json"),
        &workflow_receipt,
    );

    let source_record = serde_json::json!({
        "stepIndex": 0,
        "admissionReportSha256": "a".repeat(64),
        "toolReceiptSha256": "b".repeat(64),
        "bilateralDsseSha256": "c".repeat(64),
        "workflowStepSha256": "d".repeat(64)
    });
    let proof_report = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-report.v1",
        "runId": "runtime-swarm-valid",
        "accepted": true,
        "generatedAtUnixMs": 1800000001000_u64,
        "proofPackageSha256": canonical_file_sha256(&bundle.join("runtime-proof-package.json")),
        "verifierReportSha256": canonical_file_sha256(&bundle.join("runtime-verifier-report.json")),
        "workflowReceiptSha256": canonical_file_sha256(&bundle.join("runtime-workflow-receipt.json")),
        "sourceRecords": [source_record.clone()],
        "checks": ["runtime_regeneration.source_records_bound"]
    });
    write_json(
        &bundle.join("proof-regeneration-report.json"),
        &proof_report,
    );
    let proof_report_sha256 = canonical_value_sha256(&proof_report);

    let workflow_report = serde_json::json!({
        "schema": "chio.runtime.workflow-run-report.v1",
        "runId": "runtime-swarm-valid",
        "accepted": true,
        "generatedAtUnixMs": 1800000001000_u64,
        "admissionReportSha256": "a".repeat(64),
        "evidencePaths": ["proof-regeneration-report.json"],
        "stepEvidence": [{
            "schema": "chio.runtime.step-evidence.v1",
            "stepIndex": 0,
            "admissionId": "runtime-swarm-admission",
            "admissionReportSha256": "a".repeat(64),
            "toolReceiptId": "runtime-swarm-tool-receipt",
            "toolReceiptSha256": "b".repeat(64),
            "outputSha256": "e".repeat(64),
            "bilateralDsseSha256": "c".repeat(64),
            "workflowStepSha256": "d".repeat(64),
            "consistencyAnchor": "runtime-swarm-anchor",
            "destructive": false
        }],
        "proofRegenerationReportSha256": proof_report_sha256
    });
    write_json(
        &bundle.join("runtime-workflow-run-report.json"),
        &workflow_report,
    );
    let workflow_report_sha256 = canonical_value_sha256(&workflow_report);

    let evidence_manifest = serde_json::json!({
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": "runtime-swarm-valid",
        "generatedAtUnixMs": 1800000001000_u64,
        "workflowRunReportSha256": workflow_report_sha256,
        "proofRegenerationReportSha256": proof_report_sha256,
        "entries": [
            runtime_manifest_entry(bundle, "proof_package", "runtime-proof-package.json"),
            runtime_manifest_entry(bundle, "verifier_report", "runtime-verifier-report.json"),
            runtime_manifest_entry(bundle, "workflow_receipt", "runtime-workflow-receipt.json"),
            runtime_manifest_entry(bundle, "proof_regeneration_report", "proof-regeneration-report.json"),
            runtime_manifest_entry(bundle, "runtime_run_report", "runtime-workflow-run-report.json")
        ]
    });
    write_json(
        &bundle.join("runtime-evidence-manifest.json"),
        &evidence_manifest,
    );
    let evidence_manifest_sha256 = canonical_value_sha256(&evidence_manifest);

    let proof_input = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-input.v1",
        "runId": "runtime-swarm-valid",
        "evidenceManifestSha256": evidence_manifest_sha256,
        "workflowRunReportSha256": workflow_report_sha256,
        "admissionReportSha256": "a".repeat(64),
        "trustBundleSha256": "f".repeat(64),
        "verificationContextSha256": "1".repeat(64),
        "sourceRecords": [source_record]
    });
    write_json(&bundle.join("proof-regeneration-input.json"), &proof_input);
}

fn runtime_manifest_entry(bundle: &Path, role: &str, path: &str) -> serde_json::Value {
    let bytes = std::fs::read(bundle.join(path)).test_expect("read runtime manifest entry");
    serde_json::json!({
        "role": role,
        "path": path,
        "sha256": sha256_hex(&bytes),
        "byteCount": bytes.len()
    })
}

fn canonical_file_sha256(path: &Path) -> String {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).test_expect("read canonical file"))
            .test_expect("canonical file parses");
    canonical_value_sha256(&value)
}

fn canonical_value_sha256(value: &serde_json::Value) -> String {
    let bytes = canonical_json_bytes(value).test_expect("canonical JSON serializes");
    sha256_hex(&bytes)
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
fn proof_verify_runtime_parity_rejects_failed_evidence_graph_bound_report() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();
    let parity_path = bundle.join("runtime-proof-parity-report.json");
    let mut parity_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&parity_path).test_expect("read parity report"))
            .test_expect("parity report parses");
    parity_report["accepted"] = serde_json::Value::Bool(false);
    parity_report["failureCode"] =
        serde_json::Value::String("runtime_proof_parity_package_hash_drift".to_string());
    parity_report["runtimeProofPackageSha256"] = serde_json::Value::String("c".repeat(64));
    parity_report["mismatches"] = serde_json::json!([{
        "field": "proof_package_sha256",
        "staticValueSha256": "a".repeat(64),
        "runtimeValueSha256": "c".repeat(64)
    }]);
    write_json(&parity_path, &parity_report);
    refresh_transaction_artifact_digest(&bundle, "runtime-proof-parity-report.json");

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
    ]);

    assert_failure(
        &output,
        "proof verify: runtime proof parity report is not accepted",
    );
}

#[test]
fn proof_verify_runtime_parity_requires_regeneration_artifacts_when_report_is_present() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();
    remove_runtime_regeneration_evidence_nodes(&bundle);

    let output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_failure(
        &output,
        "proof verify: runtime proof regeneration evidence missing: runtime-proof-regeneration-report",
    );
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
fn proof_verify_runtime_parity_binds_report_hashes_to_regenerated_artifacts() {
    let (_tempdir, bundle) = build_swarm_bundle_with_runtime_parity();
    let parity_path = bundle.join("runtime-proof-parity-report.json");
    let mut parity_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&parity_path).test_expect("read parity report"))
            .test_expect("parity report parses");
    parity_report["staticProofPackageSha256"] = serde_json::Value::String("a".repeat(64));
    parity_report["runtimeProofPackageSha256"] = serde_json::Value::String("a".repeat(64));
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

    assert_failure(&output, "runtime proof parity package hash mismatch");
}

fn remove_runtime_regeneration_evidence_nodes(bundle: &Path) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let graph_nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    graph_nodes.retain(|node| {
        let role = node.get("role").and_then(serde_json::Value::as_str);
        !matches!(
            role,
            Some(
                "runtime-proof-regeneration-report"
                    | "runtime-proof-regeneration-input"
                    | "runtime-evidence-manifest"
                    | "runtime-workflow-run-report"
                    | "runtime-proof-package"
                    | "runtime-verifier-report"
                    | "runtime-workflow-receipt"
            )
        )
    });
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);
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
