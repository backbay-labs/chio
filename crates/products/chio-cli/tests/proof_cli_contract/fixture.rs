use super::support::*;
use chio_test_support::prelude::*;
use std::collections::BTreeSet;

#[test]
fn proof_fixture_list_reports_proof_fixtures() {
    let output = chio(&["proof", "fixture", "list", "--json"]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture list report parses");
    let fixture_ids = report["fixtures"]
        .as_array()
        .test_expect("fixtures array")
        .iter()
        .map(|fixture| fixture["id"].as_str().test_expect("fixture id").to_string())
        .collect::<BTreeSet<_>>();

    for expected_fixture_id in [
        "single-call-authority",
        "commerce-transaction-passport",
        "minimal-passport-valid",
        "runtime-side-effecting-call",
        "commerce-offline-psp",
        "workflow-preflight-valid",
        "workflow-preflight-broader-child-scope",
        "workflow-preflight-planning-artifact-claims-authority",
        "recursive-runtime-swarm",
        "disclosure-and-agent-web-envelope",
        "recursive-runtime-swarm-stale-continuation",
        "recursive-runtime-swarm-budget-allocations-exceed-pool",
        "recursive-runtime-swarm-graph-cycle",
        "recursive-runtime-swarm-join-parent-set-mismatch",
        "recursive-runtime-swarm-replayed-continuation-nonce",
        "recursive-runtime-swarm-revoked-task",
        "recursive-runtime-swarm-stale-route-plan",
        "recursive-runtime-swarm-witness-child-scope-mismatch",
        "disclosure-lineage-ledger",
        "crypto-context-valid-bbs",
        "crypto-context-forbidden-algorithm",
        "crypto-context-missing-holder-binding",
        "crypto-context-missing-revocation-snapshot",
        "crypto-context-preview-transparency",
        "crypto-context-replayed-nonce",
        "crypto-context-stale-key",
        "crypto-context-wrong-audience",
        "public-settlement-offline-finality",
        "public-settlement-finality-below-threshold",
        "public-settlement-observed-execution-outside-window",
        "public-settlement-missing-commerce-order-binding",
        "public-settlement-order-evidence-mismatch",
        "public-settlement-missing-oracle-evidence",
        "public-settlement-refunded-posture-without-reversal",
        "public-settlement-deployment-provenance-mismatch",
        "public-settlement-advisory-witness",
        "public-settlement-wrong-chain-id",
        "agent-web-interop",
        "agent-web-external-digest-mismatch",
        "agent-web-missing-required-signature",
        "agent-web-cloudevents-specversion-mismatch",
        "agent-web-graphql-http-draft-version-missing",
        "agent-web-graphql-errors-projected-as-success",
        "agent-web-mcp-authority-claim-not-limited",
        "agent-web-sidecar-claim-marked-native",
        "agent-web-unsupported-claim-not-limited",
        "agent-web-external-subject-schema-mismatch",
        "agent-web-acp-client-unsupported-bridge-allowed",
        "agent-web-email-send-missing-message-digest",
        "agent-web-calendar-time-range-mismatch",
        "agent-web-slack-failed-provider-response",
        "agent-web-kubernetes-admission-uid-mismatch",
        "agent-web-oci-tag-only-ref",
        "agent-web-slsa-unverified-provenance",
        "agent-web-a2a-authority-claim-not-limited",
        "agent-web-ap2-detached-from-order",
        "agent-web-vc-unbound-receipt",
        "enterprise-autonomous-commerce",
        "trust-market-context",
        "minimal-passport-evidence-graph-digest-mismatch",
        "minimal-passport-policy-digest-mismatch",
        "minimal-passport-unknown-schema",
        "runtime-missing-execution-lease",
        "runtime-expired-execution-lease",
        "runtime-advisory-used-as-authorization",
        "runtime-ack-outside-lease",
        "runtime-missing-terminal-receipt",
        "runtime-reused-nonce",
        "runtime-sandbox-mismatch",
        "runtime-stale-revocation",
        "commerce-payment-wrong-merchant",
        "commerce-expired-mandate",
        "commerce-payment-before-budget",
        "commerce-quote-evidence-mismatch",
        "commerce-open-dispute-completed",
        "commerce-fraud-declined",
        "commerce-currency-mismatch",
        "commerce-payment-amount-mismatch",
        "commerce-mandate-occurrence-limit",
        "enterprise-coverage-subject-mismatch",
        "enterprise-risk-reserve-state-missing",
        "enterprise-settlement-counterparty-mismatch",
        "enterprise-control-map-missing-gate",
        "enterprise-double-consumed-reserve",
        "enterprise-duplicate-reserve-receipt-id",
        "enterprise-export-bundle-digest-mismatch",
        "enterprise-market-slash-facility-reserve",
        "enterprise-reverse-slash-without-prior-penalty",
        "enterprise-missing-approval-case",
        "enterprise-open-appeal-reserve-release",
        "enterprise-risk-payout-preobserved-instruction",
        "enterprise-pii-overdisclosure",
        "enterprise-telemetry-digest-mismatch",
        "enterprise-telemetry-passport-mismatch",
        "enterprise-telemetry-siem-without-receipt",
        "enterprise-facility-lifecycle-final-state-mismatch",
        "enterprise-insurance-copy-exceeds-actuarial-support",
        "enterprise-risk-exposure-exceeds-capital",
        "enterprise-risk-portfolio-capital-overallocated",
        "enterprise-actuarial-backtest-breach",
        "enterprise-mixed-currency-risk",
        "enterprise-claim-outside-coverage",
        "enterprise-payout-amount-mismatch",
        "disclosure-lineage-missing-ledger-entry",
        "disclosure-lineage-unknown-lineage-root",
        "disclosure-lineage-excess-disclosed-field",
        "disclosure-lineage-unsupported-edge-kind",
        "disclosure-lineage-missing-parent",
        "disclosure-lineage-node-digest-mismatch",
        "disclosure-lineage-depth-regression",
        "disclosure-lineage-frontier-mismatch",
        "disclosure-lineage-checkpoint-mismatch",
        "disclosure-lineage-evidence-below-floor",
        "trust-market-guarantee-wrong-beneficiary",
        "trust-market-unsupported-guarantee-type",
        "trust-market-unsupported-collateral-source",
        "trust-market-guarantee-without-backing",
        "trust-market-reputation-import-overweight",
        "trust-market-required-unsupported-market-claim",
        "trust-market-score-recompute-mismatch",
        "trust-market-selected-provider-absent",
        "trust-market-sla-wrong-order",
        "trust-market-slash-authority-outside-jurisdiction",
        "trust-market-stale-discovery",
        "trust-market-stale-reputation",
    ] {
        assert!(
            fixture_ids.contains(expected_fixture_id),
            "missing proof fixture id: {expected_fixture_id}"
        );
    }
}

#[test]
fn proof_fixture_generate_reports_verifiable_single_call_authority_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("single-call-authority");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "single-call-authority",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&["proof", "verify", verify_path]);

    assert_success(&verify_output);
}

#[test]
fn proof_fixture_generate_reports_verifiable_commerce_transaction_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("commerce-transaction-passport");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "commerce-transaction-passport",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("commerce-transaction-passport")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    let readme = std::fs::read_to_string(out_path.join("proof-room-bundle/README.md"))
        .test_expect("read generated Proof Room README");
    assert!(readme.contains("commerce-transaction-passport"));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("commerce-transaction-passport")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate commerce-transaction-passport")
    );
    let receipt_coverage = manifest["receipt_coverage"]
        .as_array()
        .test_expect("commerce stage receipt coverage array");
    for category in ["runtime_terminal_allow", "runtime_terminal_denial"] {
        assert!(
            receipt_coverage.iter().any(|entry| {
                entry["category"] == category
                    && entry["status"] == "covered"
                    && entry
                        .get("artifact_path")
                        .and_then(serde_json::Value::as_str)
                        .is_some()
            }),
            "{category} should be covered by the generated commerce stage"
        );
    }
    let claims = manifest["claims"]
        .as_array()
        .test_expect("commerce stage claims array");
    assert!(
        claims
            .iter()
            .any(|claim| claim["claim_id"] == "claim.proof_room.allow_and_deny_visible"),
        "commerce stage should render allow and deny receipt evidence"
    );
    let load_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/ui/proof-room-static/load-report.json"))
            .test_expect("read generated Proof Room load report"),
    )
    .test_expect("generated Proof Room load report parses");
    let rendered_claims = load_report["rendered_claims"]
        .as_array()
        .test_expect("commerce stage rendered claims array");
    assert!(
        rendered_claims
            .iter()
            .any(|claim| claim["claim_id"] == "claim.proof_room.allow_and_deny_visible"),
        "commerce stage load report should render allow and deny receipt evidence"
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "commerce",
        "--require",
        "settlement",
        "--require",
        "denials",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(verify_stdout.contains("\"claim.public_settlement.finality_verified\""));
}

#[test]
fn proof_fixture_generate_keeps_commerce_stage_available_with_installed_fixture_root() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let fixture_root = workspace_root().join("fixtures/proof-room");
    let out_path = tempdir.path().join("commerce-transaction-passport");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &fixture_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("commerce-transaction-passport")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "commerce",
        "--require",
        "settlement",
    ]);

    assert_success(&verify_output);
}

#[test]
fn proof_fixture_generate_reports_verifiable_recursive_runtime_swarm_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("recursive-runtime-swarm");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "recursive-runtime-swarm",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("recursive-runtime-swarm")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let bundle = out_path.join("proof-room-bundle");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/runtime-proof-parity-report.json")
        .exists());
    let parity_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/runtime-proof-parity-report.json"))
            .test_expect("read generated runtime parity report"),
    )
    .test_expect("generated runtime parity report parses");
    for field in [
        "staticProofPackageSha256",
        "runtimeProofPackageSha256",
        "staticVerifierReportSha256",
        "runtimeVerifierReportSha256",
    ] {
        let digest = parity_report[field]
            .as_str()
            .test_expect("runtime parity report digest is a string");
        assert_ne!(digest, "a".repeat(64));
        assert_ne!(digest, "b".repeat(64));
        assert_ne!(digest, "c".repeat(64));
        assert_ne!(digest, "d".repeat(64));
    }
    let evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join("evidence-graph.json"))
            .test_expect("read generated evidence graph"),
    )
    .test_expect("generated evidence graph parses");
    for schema in [
        "chio.runtime.proof-parity-report.v1",
        "chio.runtime.proof-regeneration-report.v1",
        "chio.runtime.proof-regeneration-input.v1",
        "chio.runtime.evidence-manifest.v1",
        "chio.runtime.workflow-run-report.v1",
    ] {
        let artifact = assert_graph_node_hashes_bundle_artifact(&bundle, &evidence_graph, schema);
        assert_eq!(
            artifact["schema"].as_str(),
            Some(schema),
            "runtime artifact schema mismatch for {schema}"
        );
        assert_eq!(
            artifact["runId"].as_str(),
            Some("runtime-loopback-1"),
            "runtime artifact run id mismatch for {schema}"
        );
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("recursive-runtime-swarm")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate recursive-runtime-swarm")
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(verify_stdout.contains("\"runtime_proof_parity_report\""));
    assert!(verify_stdout.contains("\"runId\":\"runtime-loopback-1\""));
}

#[test]
fn proof_verify_runtime_parity_rejects_tampered_regeneration_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("recursive-runtime-swarm");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "recursive-runtime-swarm",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);
    assert_success(&output);

    let bundle = out_path.join("proof-room-bundle");
    let report_path = bundle.join("proof-regeneration-report.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read proof report"))
            .test_expect("proof report parses");
    report["checks"]
        .as_array_mut()
        .test_expect("proof report checks array")
        .push(serde_json::Value::String(
            "runtime_regeneration.tampered".to_string(),
        ));
    write_json(&report_path, &report);
    refresh_transaction_artifact_digest(&bundle, "proof-regeneration-report.json");
    refresh_manifest_artifact_ref(&bundle, "proof-regeneration-report.json");
    refresh_manifest_artifact_ref(&bundle, "roots/evidence-graph.json");
    refresh_manifest_artifact_ref(&bundle, "roots/transaction-passport.json");
    refresh_bundle_signature_with_seed(&bundle, COLLECT_SIGNATURE_SEED);

    let verify_output = chio(&[
        "proof",
        "verify",
        utf8_path(&bundle).as_str(),
        "--require",
        "delegation",
        "--require",
        "runtime-parity",
    ]);

    assert_failure(
        &verify_output,
        "runtime proof regeneration report hash mismatch",
    );
}

#[test]
fn proof_fixture_generate_reports_verifiable_disclosure_agent_web_stage_entrypoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("disclosure-and-agent-web-envelope");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "disclosure-and-agent-web-envelope",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let generate_stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&generate_stdout).test_expect("fixture generate report parses");
    assert_eq!(
        report["fixture_id"].as_str(),
        Some("disclosure-and-agent-web-envelope")
    );
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    assert!(out_path.join("proof-room-bundle/manifest.json").exists());
    assert!(out_path
        .join("proof-room-bundle/bundle-signature.dsse.json")
        .exists());
    assert!(out_path
        .join("proof-room-bundle/verifier/report.json")
        .exists());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("proof-room-bundle/manifest.json"))
            .test_expect("read generated Proof Room manifest"),
    )
    .test_expect("generated Proof Room manifest parses");
    assert_eq!(
        manifest["fixture_id"].as_str(),
        Some("disclosure-and-agent-web-envelope")
    );
    assert_eq!(
        manifest["source_command"].as_str(),
        Some("chio proof fixture generate disclosure-and-agent-web-envelope")
    );

    let verify_output = chio(&[
        "proof",
        "verify",
        verify_path,
        "--require",
        "disclosure",
        "--require",
        "external-envelope",
    ]);

    assert_success(&verify_output);
    let verify_stdout = stdout(verify_output);
    assert!(verify_stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(verify_stdout.contains("\"claim.agent_web.projection_manifest_bound\""));
}

#[test]
fn proof_fixture_generate_copies_domain_passport_fixture() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("commerce-offline-psp");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "commerce-offline-psp",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    assert!(out_path.join("evidence-graph.json").exists());
    assert!(out_path.join("order-context.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"commerce-offline-psp\""));
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    let verifier_report_path = out_path.join("verifier/report.json");
    let verifier_report_path_string = verifier_report_path.to_string_lossy().into_owned();
    assert_eq!(
        report["verifier_report_path"].as_str(),
        Some(verifier_report_path_string.as_str())
    );
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&verifier_report_path).test_expect("read report"))
            .test_expect("verifier report parses");
    assert_eq!(
        verifier_report["schema"],
        "chio.transaction.verifier-report.v1"
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        out_dir.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
    let serve_report: serde_json::Value =
        serde_json::from_slice(&serve_output.stdout).test_expect("serve report parses");
    assert_eq!(
        serve_report
            .get("verifier_parity")
            .and_then(serde_json::Value::as_str),
        Some("verified")
    );
}

#[test]
fn proof_fixture_generate_outputs_servable_enterprise_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("enterprise-autonomous-commerce");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "enterprise-autonomous-commerce",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);
    assert_success(&output);

    let disclosure_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("disclosure-capsule.json"))
            .test_expect("read disclosure crypto context report"),
    )
    .test_expect("disclosure crypto context report parses");
    assert_eq!(
        disclosure_report
            .get("projection_manifest_ref")
            .and_then(serde_json::Value::as_str),
        Some("chio.bbs-projection.receipt.v1")
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        out_dir.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);

    assert_success(&serve_output);
}

#[test]
fn proof_fixture_generate_copies_crypto_context_fixture() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("crypto-context-valid-bbs");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "crypto-context-valid-bbs",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    assert!(out_path.join("verification-context.json").exists());
    assert!(out_path.join("crypto-context-report.json").exists());
    assert!(out_path.join("key-state.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"crypto-context-valid-bbs\""));
}

#[test]
fn proof_fixture_generate_reports_crypto_context_rejection_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("crypto-context-wrong-audience");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "crypto-context-wrong-audience",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "rejected");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("disclosure_context_audience_mismatch"));
    let verifier_report_path = report["verifier_report_path"]
        .as_str()
        .test_expect("fixture generate report includes verifier report path");
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(verifier_report_path).test_expect("read report"))
            .test_expect("verifier report parses");
    assert_eq!(
        verifier_report["schema"],
        "chio.disclosure.crypto-context-report.v1"
    );
    assert_eq!(verifier_report["verdict"], "rejected");
    assert!(verifier_report["rejected_checks"]
        .as_array()
        .test_expect("rejected checks array")
        .iter()
        .any(|check| check["code"] == "disclosure_context_audience_mismatch"));
}

#[test]
fn proof_fixture_generate_reports_negative_fixture_expected_failure() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("policy-digest-mismatch");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "minimal-passport-policy-digest-mismatch",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("verifier policy digest mismatch"));
    let verify_path = report["verify_path"]
        .as_str()
        .test_expect("fixture generate report includes verify path");
    let verify_output = chio(&["proof", "verify", verify_path]);

    assert_failure(&verify_output, "verifier policy digest mismatch");
}

#[test]
fn proof_fixture_root_catalog_uses_registered_schema() {
    let catalog_path = workspace_root().join("fixtures/proof-room/catalog.json");
    let catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&catalog_path).test_expect("read fixture catalog"))
            .test_expect("fixture catalog parses");
    let schema = "chio.proof-room.fixture-root-catalog.v1";

    assert_eq!(catalog["schema"], schema);
    assert!(
        chio_core_types::is_supported_signed_artifact_schema(schema),
        "fixture root catalog schema must be registry-backed"
    );
    assert_json_schema_accepts(
        "spec/schemas/chio-proof-room/v1/fixture-root-catalog.schema.json",
        &catalog,
    );
}

#[test]
fn proof_fixture_generate_uses_installed_fixture_root() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/valid");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed fixture");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "minimal-passport-valid",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Installed minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    std::fs::write(
        installed_fixture.join("installed-root-marker.txt"),
        "installed fixture root\n",
    )
    .test_expect("write installed marker");
    let out_path = tempdir.path().join("generated-minimal-passport");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("minimal-passport-valid")
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    assert!(out_path.join("installed-root-marker.txt").exists());
}

#[test]
fn proof_fixture_list_uses_installed_fixture_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Packaged minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("list")
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture list report parses");
    let fixture_ids: BTreeSet<_> = report["fixtures"]
        .as_array()
        .test_expect("fixture list includes fixtures")
        .iter()
        .map(|fixture| {
            fixture["id"]
                .as_str()
                .test_expect("fixture id is a string")
                .to_string()
        })
        .collect();
    assert!(fixture_ids.contains("packaged-minimal-passport"));
}

#[test]
fn proof_fixture_list_rejects_configured_fixture_root_without_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("list")
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "proof fixture catalog missing");
}

#[test]
fn proof_fixture_generate_uses_installed_fixture_catalog() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/valid");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed fixture");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "minimal-passport/valid",
                    "description": "Packaged minimal passport fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-minimal-passport");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("packaged-minimal-passport")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_success(&output);
    assert!(out_path.join("transaction-passport.json").exists());
    let stdout = stdout(output);
    assert!(stdout.contains("\"fixture_id\":\"packaged-minimal-passport\""));
}

#[test]
fn proof_fixture_generate_rejects_negative_fixture_expected_failure_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("minimal-passport/invalid-policy-digest-mismatch");
    let installed_metadata = installed_root.join("minimal-passport/negatives");
    let source = workspace_root()
        .join("fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("invalid-policy-digest-mismatch.json"),
        serde_json::json!({
            "schema": "chio.transaction.negative-fixture.v1",
            "id": "invalid-policy-digest-mismatch",
            "claim_ref": "claim.transaction.policy_digest_bound",
            "base_fixture": "fixtures/proof-room/minimal-passport/valid/transaction-passport.json",
            "case": "PolicyDigestMismatch",
            "expected_failure_code": "expected failure that does not occur"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "packaged-policy-digest-mismatch",
                    "kind": "negative-transaction-passport",
                    "path": "minimal-passport/invalid-policy-digest-mismatch",
                    "description": "Packaged policy digest mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-policy-digest-mismatch");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("packaged-policy-digest-mismatch")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "expected failure that does not occur");
}

#[test]
fn proof_fixture_generate_rejects_negative_fixture_failure_prefix() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let installed_fixture = installed_root.join("commerce-payments/payment-wrong-merchant");
    let installed_metadata = installed_root.join("commerce-payments/negatives");
    let source =
        workspace_root().join("fixtures/proof-room/commerce-payments/payment-wrong-merchant");
    copy_dir_all(&source, &installed_fixture).test_expect("copy installed negative fixture");
    std::fs::create_dir_all(&installed_metadata).test_expect("create negative metadata directory");
    std::fs::write(
        installed_metadata.join("payment-wrong-merchant.json"),
        serde_json::json!({
            "schema": "chio.commerce.negative-fixture.v1",
            "id": "payment-wrong-merchant",
            "claim_ref": "claim.commerce.payment_lifecycle_bound",
            "base_fixture": "fixtures/proof-room/commerce-payments/offline-psp-valid/transaction-passport.json",
            "case": "PaymentWrongMerchant",
            "expected_failure_code": "payment merchant"
        })
        .to_string(),
    )
    .test_expect("write installed negative metadata");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "commerce-payment-wrong-merchant",
                    "kind": "negative-transaction-passport",
                    "path": "commerce-payments/payment-wrong-merchant",
                    "description": "Packaged commerce payment mismatch fixture"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-commerce-mismatch");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("commerce-payment-wrong-merchant")
        .arg("--out")
        .arg(&out_path)
        .arg("--json")
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "payment merchant mismatch");
}

#[test]
fn proof_fixture_generate_rejects_installed_catalog_path_escape() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let installed_root = tempdir.path().join("installed-proof-room");
    let outside_fixture = tempdir.path().join("outside-fixture");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    copy_dir_all(&source, &outside_fixture).test_expect("copy outside fixture");
    std::fs::create_dir_all(&installed_root).test_expect("create installed fixture root");
    std::fs::write(
        installed_root.join("catalog.json"),
        serde_json::json!({
            "schema": "chio.proof-room.fixture-root-catalog.v1",
            "fixtures": [
                {
                    "id": "escaped-minimal-passport",
                    "kind": "transaction-passport",
                    "path": "../outside-fixture",
                    "description": "Escaped packaged fixture path"
                }
            ]
        })
        .to_string(),
    )
    .test_expect("write installed fixture catalog");
    let out_path = tempdir.path().join("generated-escaped-fixture");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("fixture")
        .arg("generate")
        .arg("escaped-minimal-passport")
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(&output, "installed proof fixture path escapes root");
    assert!(!out_path.exists());
}

#[test]
fn proof_fixture_generate_rejects_existing_output_directory() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_dir = utf8_path(tempdir.path());

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "single-call-authority",
        "--out",
        out_dir.as_str(),
    ]);

    assert_failure(&output, "proof output directory already exists");
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_plan() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir.path().join("workflow-preflight-valid");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-valid",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_success(&preflight_output);
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_denial() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir
        .path()
        .join("workflow-preflight-planning-artifact-claims-authority");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-planning-artifact-claims-authority",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("cannot satisfy live authority claims"));
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_failure(&preflight_output, "cannot satisfy live authority claims");
}

#[test]
fn proof_fixture_generate_reports_runnable_workflow_preflight_scope_denial() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let out_path = tempdir
        .path()
        .join("workflow-preflight-broader-child-scope");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "fixture",
        "generate",
        "workflow-preflight-broader-child-scope",
        "--out",
        out_dir.as_str(),
        "--json",
    ]);

    assert_success(&output);
    let stdout = stdout(output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("fixture generate report parses");
    assert_eq!(report["expected_verdict"], "failed");
    assert!(report["expected_failure"]
        .as_str()
        .test_expect("fixture generate report includes expected failure")
        .contains("outside parent scope"));
    let preflight_plan_path = report["preflight_plan_path"]
        .as_str()
        .test_expect("fixture generate report includes preflight plan path");
    let preflight_output = chio(&["workflow", "preflight", "--plan", preflight_plan_path]);

    assert_failure(&preflight_output, "outside parent scope");
}

#[test]
fn proof_fixture_generate_copies_runnable_negative_passport_fixtures() {
    for (fixture_id, expected_file, expected_failure) in [
        (
            "minimal-passport-evidence-graph-digest-mismatch",
            "verifier-policy.json",
            "evidence graph digest mismatch",
        ),
        (
            "minimal-passport-policy-digest-mismatch",
            "verifier-policy.json",
            "verifier policy digest mismatch",
        ),
        (
            "minimal-passport-unknown-schema",
            "transaction-passport.json",
            "unsupported transaction passport schema",
        ),
        (
            "minimal-passport-stale-capability",
            "capability-proof.json",
            "capability proof expired before evidence graph issuance",
        ),
        (
            "runtime-missing-execution-lease",
            "tool-server-ack.json",
            "missing execution lease",
        ),
        (
            "runtime-expired-execution-lease",
            "execution-lease.json",
            "execution lease expired before issuance",
        ),
        (
            "runtime-advisory-used-as-authorization",
            "execution-lease.json",
            "advisory evidence cannot authorize runtime execution",
        ),
        (
            "runtime-ack-outside-lease",
            "tool-server-ack.json",
            "acknowledgement outside execution lease",
        ),
        (
            "runtime-missing-terminal-receipt",
            "evidence-graph.json",
            "missing terminal receipt for execution lease",
        ),
        (
            "runtime-reused-nonce",
            "evidence-graph.json",
            "reused nonce",
        ),
        (
            "runtime-sandbox-mismatch",
            "sandbox-attestation.json",
            "sandbox tool binding mismatch",
        ),
        (
            "runtime-stale-revocation",
            "revocation-freshness-proof.json",
            "revocation freshness stale",
        ),
        (
            "commerce-payment-wrong-merchant",
            "payment-lifecycle.json",
            "payment merchant mismatch",
        ),
        (
            "commerce-expired-mandate",
            "mandate-allowance-ledger.json",
            "mandate expired before payment capture",
        ),
        (
            "commerce-payment-before-budget",
            "event-log.json",
            "unknown commerce transition",
        ),
        (
            "commerce-quote-evidence-mismatch",
            "event-log.json",
            "quote event missing quote evidence",
        ),
        (
            "commerce-open-dispute-completed",
            "payment-lifecycle.json",
            "unresolved payment recovery state",
        ),
        (
            "commerce-fraud-declined",
            "payment-lifecycle.json",
            "fraud outcome was not accepted",
        ),
        (
            "commerce-currency-mismatch",
            "payment-lifecycle.json",
            "payment amount or currency mismatch",
        ),
        (
            "commerce-payment-amount-mismatch",
            "payment-lifecycle.json",
            "payment amount or currency mismatch",
        ),
        (
            "commerce-mandate-occurrence-limit",
            "mandate-allowance-ledger.json",
            "mandate occurrence limit exceeded",
        ),
        (
            "recursive-runtime-swarm-stale-continuation",
            "continuation-child-a.json",
            "swarm continuation token is stale",
        ),
        (
            "recursive-runtime-swarm-budget-allocations-exceed-pool",
            "budget-pool.json",
            "swarm budget allocations exceed pool total",
        ),
        (
            "recursive-runtime-swarm-graph-cycle",
            "task-graph.json",
            "swarm task graph cycle at task-child-a",
        ),
        (
            "recursive-runtime-swarm-join-parent-set-mismatch",
            "join-receipt.json",
            "swarm join receipt parent set mismatch",
        ),
        (
            "recursive-runtime-swarm-replayed-continuation-nonce",
            "continuation-child-b.json",
            "swarm continuation nonce replay",
        ),
        (
            "recursive-runtime-swarm-revoked-task",
            "revocation-epoch.json",
            "swarm task is revoked",
        ),
        (
            "recursive-runtime-swarm-stale-route-plan",
            "route-child-a.json",
            "swarm route-plan receipt is stale",
        ),
        (
            "recursive-runtime-swarm-route-plan-mismatch",
            "route-child-a.json",
            "swarm route-plan selected route bridge mismatch",
        ),
        (
            "recursive-runtime-swarm-witness-child-scope-mismatch",
            "witness-child-a.json",
            "swarm witness child scope mismatch",
        ),
        (
            "public-settlement-wrong-chain-id",
            "settlement-proof-bundle.json",
            "settlement chain id mismatch",
        ),
        (
            "public-settlement-finality-below-threshold",
            "settlement-proof-bundle.json",
            "settlement finality below threshold",
        ),
        (
            "public-settlement-observed-execution-outside-window",
            "settlement-proof-bundle.json",
            "observed execution timestamp falls outside dispatch execution window",
        ),
        (
            "public-settlement-missing-commerce-order-binding",
            "settlement-proof-bundle.json",
            "public_settlement.commerce_order_id",
        ),
        (
            "public-settlement-order-evidence-mismatch",
            "settlement-proof-bundle.json",
            "public settlement commerce order evidence mismatch",
        ),
        (
            "public-settlement-missing-oracle-evidence",
            "settlement-proof-bundle.json",
            "receipt requires oracle_evidence for FX-sensitive settlement paths",
        ),
        (
            "public-settlement-refunded-posture-without-reversal",
            "settlement-proof-bundle.json",
            "refunded dispute posture requires reversed or timed out settlement",
        ),
        (
            "public-settlement-deployment-provenance-mismatch",
            "settlement-proof-bundle.json",
            "public settlement deployment contract package mismatch",
        ),
        (
            "public-settlement-advisory-witness",
            "settlement-proof-bundle.json",
            "public settlement witness mode advisory",
        ),
        (
            "agent-web-external-digest-mismatch",
            "cloudevents-envelope.json",
            "external subject digest mismatch",
        ),
        (
            "agent-web-missing-required-signature",
            "standard-webhooks-envelope.json",
            "missing external signature",
        ),
        (
            "agent-web-cloudevents-specversion-mismatch",
            "external/cloudevent.json",
            "CloudEvents specversion mismatch",
        ),
        (
            "agent-web-graphql-http-draft-version-missing",
            "graphql-http-manifest.json",
            "GraphQL over HTTP version must be draft-labeled",
        ),
        (
            "agent-web-graphql-errors-projected-as-success",
            "external/graphql-operation.json",
            "GraphQL response contains errors",
        ),
        (
            "agent-web-mcp-authority-claim-not-limited",
            "mcp-envelope.json",
            "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority",
        ),
        (
            "agent-web-sidecar-claim-marked-native",
            "cloudevents-manifest.json",
            "sidecar claim presented as native external proof",
        ),
        (
            "agent-web-unsupported-claim-not-limited",
            "cloudevents-envelope.json",
            "unsupported claim was not limited",
        ),
        (
            "agent-web-x402-detached-from-order",
            "evidence-graph.json",
            "missing x402 order binding",
        ),
        (
            "agent-web-external-subject-schema-mismatch",
            "evidence-graph.json",
            "external subject schema mismatch",
        ),
        (
            "agent-web-acp-client-unsupported-bridge-allowed",
            "external/acp-client-permission.json",
            "unsupported ACP-Client bridge allowed",
        ),
        (
            "agent-web-email-send-missing-message-digest",
            "external/email-message.json",
            "missing email message digest",
        ),
        (
            "agent-web-calendar-time-range-mismatch",
            "external/calendar-event.json",
            "Calendar time range changed after approval",
        ),
        (
            "agent-web-slack-failed-provider-response",
            "external/slack-message.json",
            "Slack response was not successful",
        ),
        (
            "agent-web-kubernetes-admission-uid-mismatch",
            "external/kubernetes-admission-review.json",
            "Kubernetes admission response UID mismatch",
        ),
        (
            "agent-web-oci-tag-only-ref",
            "external/oci-ref.json",
            "OCI reference must be digest-pinned",
        ),
        (
            "agent-web-slsa-unverified-provenance",
            "external/slsa-provenance.json",
            "unsupported SLSA verification status",
        ),
        (
            "agent-web-a2a-authority-claim-not-limited",
            "a2a-envelope.json",
            "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority",
        ),
        (
            "agent-web-ap2-detached-from-order",
            "evidence-graph.json",
            "missing ap2 order binding",
        ),
        (
            "agent-web-vc-unbound-receipt",
            "vc-envelope.json",
            "VC receipt ref is not bound",
        ),
        (
            "enterprise-coverage-subject-mismatch",
            "risk-comptroller-report.json",
            "risk coverage subject mismatch",
        ),
        (
            "enterprise-coverage-order-mismatch",
            "risk-comptroller-report.json",
            "risk coverage order mismatch",
        ),
        (
            "enterprise-risk-reserve-state-missing",
            "risk-comptroller-report.json",
            "risk reserve state missing",
        ),
        (
            "enterprise-settlement-counterparty-mismatch",
            "risk-comptroller-report.json",
            "risk settlement counterparty mismatch",
        ),
        (
            "enterprise-control-map-missing-gate",
            "control-evidence-map.json",
            "control gate did not run",
        ),
        (
            "enterprise-double-consumed-reserve",
            "risk-comptroller-report.json",
            "risk reserve double consumption",
        ),
        (
            "enterprise-duplicate-reserve-receipt-id",
            "risk-comptroller-report.json",
            "risk reserve ledger duplicate receipt",
        ),
        (
            "enterprise-export-bundle-digest-mismatch",
            "evidence-export-bundle.json",
            "export bundle digest mismatch",
        ),
        (
            "enterprise-market-slash-facility-reserve",
            "risk-comptroller-report.json",
            "risk market slash requires sanction bridge",
        ),
        (
            "enterprise-reverse-slash-without-prior-penalty",
            "risk-comptroller-report.json",
            "risk reverse slash missing prior reserve slash",
        ),
        (
            "enterprise-missing-approval-case",
            "evidence-graph.json",
            "missing approval case",
        ),
        (
            "enterprise-open-appeal-reserve-release",
            "risk-comptroller-report.json",
            "risk open appeal blocks reserve action",
        ),
        (
            "enterprise-open-appeal-claim-payout",
            "risk-comptroller-report.json",
            "risk open appeal blocks reserve action",
        ),
        (
            "enterprise-risk-payout-preobserved-instruction",
            "risk-comptroller-report.json",
            "risk payout preobserved instruction",
        ),
        (
            "enterprise-open-appeal-facility-closure",
            "risk-comptroller-report.json",
            "risk open appeal blocks facility closure",
        ),
        (
            "enterprise-pii-overdisclosure",
            "data-governance-report.json",
            "PII field was not redacted",
        ),
        (
            "enterprise-telemetry-digest-mismatch",
            "telemetry-projection.json",
            "telemetry artifact digest mismatch",
        ),
        (
            "enterprise-facility-lifecycle-final-state-mismatch",
            "risk-comptroller-report.json",
            "risk facility lifecycle final state mismatch",
        ),
        (
            "enterprise-insurance-copy-exceeds-actuarial-support",
            "risk-comptroller-report.json",
            "risk insurance copy exceeds actuarial support",
        ),
        (
            "enterprise-risk-exposure-exceeds-capital",
            "risk-comptroller-report.json",
            "risk exposure exceeds capital",
        ),
        (
            "enterprise-risk-capital-adequacy-breach",
            "risk-comptroller-report.json",
            "risk capital adequacy breach",
        ),
        (
            "enterprise-risk-portfolio-capital-overallocated",
            "risk-comptroller-report-secondary.json",
            "risk portfolio capital adequacy breach",
        ),
        (
            "enterprise-actuarial-backtest-breach",
            "risk-comptroller-report.json",
            "risk actuarial backtest breach",
        ),
        (
            "enterprise-mixed-currency-risk",
            "risk-comptroller-report.json",
            "risk coverage currency mismatch",
        ),
        (
            "enterprise-claim-outside-coverage",
            "risk-comptroller-report.json",
            "risk claim outside coverage",
        ),
        (
            "enterprise-payout-amount-mismatch",
            "risk-comptroller-report.json",
            "risk payout settlement mismatch",
        ),
        (
            "disclosure-lineage-missing-ledger-entry",
            "leakage-ledger.json",
            "disclosed field absent from leakage ledger",
        ),
        (
            "disclosure-lineage-unknown-lineage-root",
            "signed-lineage-subgraph.json",
            "unknown lineage root receipt",
        ),
        (
            "disclosure-lineage-excess-disclosed-field",
            "crypto-context-report.json",
            "crypto context report excess disclosed field",
        ),
        (
            "disclosure-lineage-unsupported-edge-kind",
            "signed-lineage-subgraph.json",
            "unsupported lineage edge kind",
        ),
        (
            "disclosure-lineage-missing-parent",
            "signed-lineage-subgraph.json",
            "unknown lineage edge source",
        ),
        (
            "disclosure-lineage-node-digest-mismatch",
            "signed-lineage-subgraph.json",
            "lineage node artifact digest mismatch",
        ),
        (
            "disclosure-lineage-depth-regression",
            "signed-lineage-subgraph.json",
            "lineage node depth not greater than parent",
        ),
        (
            "disclosure-lineage-frontier-mismatch",
            "signed-lineage-subgraph.json",
            "lineage frontier digest mismatch",
        ),
        (
            "disclosure-lineage-checkpoint-mismatch",
            "signed-lineage-subgraph.json",
            "lineage checkpoint inclusion digest mismatch",
        ),
        (
            "disclosure-lineage-evidence-below-floor",
            "signed-lineage-subgraph.json",
            "lineage node evidence class below floor",
        ),
        (
            "trust-market-guarantee-wrong-beneficiary",
            "guarantee-decision.json",
            "guarantee beneficiary mismatch",
        ),
        (
            "trust-market-unsupported-guarantee-type",
            "guarantee-decision.json",
            "guarantee type unsupported",
        ),
        (
            "trust-market-unsupported-collateral-source",
            "collateral-position-report.json",
            "collateral source type unsupported",
        ),
        (
            "trust-market-guarantee-without-backing",
            "guarantee-decision.json",
            "guarantee backing missing",
        ),
        (
            "trust-market-reputation-import-overweight",
            "reputation-import-report.json",
            "reputation import local weight exceeds policy",
        ),
        (
            "trust-market-required-unsupported-market-claim",
            "verifier-policy.json",
            "unsupported market claim cannot be required",
        ),
        (
            "trust-market-score-recompute-mismatch",
            "trust-scorecard-snapshot.json",
            "scorecard recompute mismatch",
        ),
        (
            "trust-market-selected-provider-absent",
            "provider-selection-report.json",
            "selected provider absent from discovery snapshot",
        ),
        (
            "trust-market-sla-wrong-order",
            "sla-commitment.json",
            "SLA order mismatch",
        ),
        (
            "trust-market-slash-authority-outside-jurisdiction",
            "collateral-position-report.json",
            "slash authority not bound to jurisdiction",
        ),
        (
            "trust-market-stale-discovery",
            "provider-discovery-snapshot.json",
            "discovery snapshot is stale",
        ),
        (
            "trust-market-stale-reputation",
            "trust-scorecard-snapshot.json",
            "scorecard component evidence is stale",
        ),
    ] {
        let tempdir = tempfile::tempdir().test_expect("tempdir");
        let out_path = tempdir.path().join(fixture_id);
        let out_dir = utf8_path(&out_path);

        let output = chio(&[
            "proof",
            "fixture",
            "generate",
            fixture_id,
            "--out",
            out_dir.as_str(),
            "--json",
        ]);

        assert_success(&output);
        assert!(out_path.join("transaction-passport.json").exists());
        assert!(out_path.join(expected_file).exists());
        let stdout = stdout(output);
        assert!(stdout.contains(&format!("\"fixture_id\":\"{fixture_id}\"")));

        let verify_output = chio(&["proof", "verify", out_dir.as_str()]);
        assert_failure(&verify_output, expected_failure);
    }
}
