use super::support::*;
use chio_test_support::prelude::*;
use std::collections::BTreeSet;

#[test]
fn proof_collect_outputs_servable_bundle_for_passport_artifacts() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = utf8_path(&artifact_dir);
    let out_path = tempdir.path().join("collected-passport");
    let out_dir = utf8_path(&out_path);

    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        artifact_dir.as_str(),
        "--out",
        out_dir.as_str(),
    ]);

    assert_success(&output);
    let passport_path = out_path.join("transaction-passport.json");
    let verifier_report_path = out_path.join("verifier/report.json");
    assert!(passport_path.exists());
    assert!(verifier_report_path.exists());

    let verify_output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);
    assert_success(&verify_output);
    let collected_report =
        std::fs::read(verifier_report_path).test_expect("read collected verifier report");
    assert_eq!(collected_report, verify_output.stdout);

    let manifest_path = out_path.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read collected manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("report-hash-mismatch")
            })
        })
        .test_expect("collected bundle includes verifier-backed negative case");
    assert_eq!(
        negative_case
            .get("expected_failure_code")
            .and_then(serde_json::Value::as_str),
        Some("proof-room.report.hash-mismatch")
    );
    assert_eq!(
        negative_case
            .get("observed_failure_code")
            .and_then(serde_json::Value::as_str),
        Some("proof-room.report.hash-mismatch")
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
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some("chio.proof.serve-report.v1")
    );
    assert_eq!(
        serve_report
            .get("verifier_parity")
            .and_then(serde_json::Value::as_str),
        Some("verified")
    );

    let archive_path = tempdir.path().join("collected-passport.tgz");
    let archive = utf8_path(&archive_path);
    let export_output = chio(&[
        "proof",
        "export",
        out_dir.as_str(),
        "--out",
        archive.as_str(),
    ]);
    assert_success(&export_output);
    let archive_verify = chio(&["proof", "verify", archive.as_str()]);
    assert_success(&archive_verify);
}

#[test]
fn proof_collect_accepts_launch_documented_collection_kinds() {
    let cases = [
        (
            "evidence",
            "fixtures/proof-room/minimal-passport/valid",
            None,
            "claim.transaction.passport_root_verified",
        ),
        (
            "replay",
            "fixtures/proof-room/commerce-payments/offline-psp-valid",
            Some("commerce"),
            "claim.commerce.order_replay_consistent",
        ),
        (
            "buyer-package",
            "fixtures/proof-room/public-stages/recursive-runtime-swarm/proof-room-bundle",
            Some("delegation"),
            "claim.swarm.route_plan_bound",
        ),
    ];

    for (kind, fixture_path, requirement, claim_id) in cases {
        let tempdir = tempfile::tempdir().test_expect("tempdir");
        let artifact_dir = workspace_root().join(fixture_path);
        let out_path = tempdir.path().join(format!("collected-{kind}"));
        let output = chio(&[
            "proof",
            "collect",
            "--kind",
            kind,
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
            Some(kind)
        );

        let out_dir = utf8_path(&out_path);
        let mut verify_args = vec!["proof", "verify", out_dir.as_str()];
        if let Some(requirement) = requirement {
            verify_args.extend(["--require", requirement]);
        }
        let verify = chio(&verify_args);
        assert_success(&verify);
        assert!(
            stdout(verify).contains(claim_id),
            "{kind} collection should preserve {claim_id}"
        );
    }
}

#[test]
fn proof_collect_binds_bundle_signature_to_manifest_trust_roots() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let out_path = tempdir.path().join("collected-passport");

    let collect = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&collect);

    let signature_path = out_path.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature_with_seed(&out_path, &mut signature, [99; 32]);
    write_json(&signature_path, &signature);

    let verify = chio(&["proof", "verify", utf8_path(&out_path).as_str()]);

    assert_failure(&verify, "proof-room.signature.signer-untrusted");
}

#[test]
fn proof_collect_requires_configured_bundle_signer() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let out_path = tempdir.path().join("collected-passport");
    let mut command = chio_command();
    let output = command
        .env_remove("CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX")
        .args([
            "proof",
            "collect",
            "--kind",
            "transaction-passport",
            "--artifact-dir",
            utf8_path(&artifact_dir).as_str(),
            "--out",
            utf8_path(&out_path).as_str(),
        ])
        .output()
        .test_expect("proof collect runs");

    assert_failure(
        &output,
        "proof collect requires CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX",
    );
    assert!(!out_path.join("bundle-signature.dsse.json").exists());
}

#[test]
fn proof_collect_ioa_web3_outputs_verifiable_commerce_settlement_bundle() {
    let (tempdir, artifact_dir) = build_commerce_settlement_passport_bundle();
    let out_path = tempdir.path().join("collected-ioa-web3");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "ioa-web3",
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
        Some("ioa-web3")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "commerce",
        "--require",
        "settlement",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.public_settlement.finality_verified\""));
}

#[test]
fn proof_collect_agent_web_envelope_outputs_verifiable_external_envelope_bundle() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let out_path = tempdir.path().join("collected-agent-web-envelope");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "agent-web-envelope",
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
        Some("agent-web-envelope")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "external-envelope",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_collect_disclosure_agent_web_envelope_outputs_verifiable_combined_bundle() {
    let (tempdir, artifact_dir) = build_disclosure_agent_web_bundle();
    let out_path = tempdir
        .path()
        .join("collected-disclosure-agent-web-envelope");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "disclosure-agent-web-envelope",
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
        Some("disclosure-agent-web-envelope")
    );

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "disclosure",
        "--require",
        "external-envelope",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
}

#[test]
fn proof_collect_disclosure_agent_web_envelope_rejects_missing_disclosure_family() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let out_path = tempdir
        .path()
        .join("collected-disclosure-agent-web-missing-disclosure");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "disclosure-agent-web-envelope",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
        "--json",
    ]);

    assert_failure(&output, "required proof claim family missing: disclosure");
}

#[test]
fn proof_collect_binds_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("commerce-payment-wrong-merchant")
            })
        })
        .test_expect("collected commerce bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("proof-room.negative.payment-merchant-mismatch")));

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_preserves_domain_claims_in_manifest() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let verifier_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("verifier/report.json"))
            .test_expect("read collected verifier report"),
    )
    .test_expect("collected verifier report parses");
    assert_json_schema_accepts(
        "spec/schemas/chio-transaction/v1/verifier-report.schema.json",
        &verifier_report,
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let ui_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("ui/proof-room-static/load-report.json"))
            .test_expect("read collected ui report"),
    )
    .test_expect("collected ui report parses");

    let verified_commerce_claim = verifier_report["family_reports"]
        .as_array()
        .test_expect("family reports array")
        .iter()
        .flat_map(|report| report["verified_claims"].as_array().into_iter().flatten())
        .filter_map(serde_json::Value::as_str)
        .find(|claim| claim.starts_with("claim.commerce."))
        .test_expect("commerce verifier report includes commerce claim");
    let checker_provenance = verifier_report["checker_provenance"]
        .as_array()
        .test_expect("collected verifier report includes checker provenance");
    assert!(checker_provenance.iter().any(|entry| {
        entry["claim_id"] == verified_commerce_claim
            && entry["checker"] == "chio proof verify --require commerce"
    }));
    let manifest_claims = manifest["claims"]
        .as_array()
        .test_expect("manifest claims array")
        .iter()
        .filter_map(|claim| claim["claim_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(manifest_claims.contains(verified_commerce_claim));
    let rendered_claims = ui_report["rendered_claims"]
        .as_array()
        .test_expect("ui rendered claims array")
        .iter()
        .filter_map(|claim| claim["claim_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(rendered_claims.contains(verified_commerce_claim));
    let rendered_commerce_claim = ui_report["rendered_claims"]
        .as_array()
        .test_expect("ui rendered claims array")
        .iter()
        .find(|claim| claim["claim_id"] == verified_commerce_claim)
        .test_expect("ui renders commerce claim");
    assert_eq!(
        rendered_commerce_claim["checker"].as_str(),
        Some("chio proof verify --require commerce")
    );
}

#[test]
fn proof_collect_rejects_catalog_negative_fixture_expected_failure_mismatch() {
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
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("collect")
        .arg("--kind")
        .arg("transaction-passport")
        .arg("--artifact-dir")
        .arg(&artifact_dir)
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "catalog negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "expected failure that does not occur");
}

#[test]
fn proof_collect_rejects_catalog_negative_fixture_failure_prefix() {
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
            "expected_failure_code": "proof-room.negative.payment-merchant"
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
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let out_path = tempdir.path().join("collected-commerce-passport");

    let output = chio_command()
        .env("CHIO_PROOF_FIXTURE_ROOT", &installed_root)
        .arg("proof")
        .arg("collect")
        .arg("--kind")
        .arg("transaction-passport")
        .arg("--artifact-dir")
        .arg(&artifact_dir)
        .arg("--out")
        .arg(&out_path)
        .output()
        .test_expect("chio command runs");

    assert_failure(
        &output,
        "catalog negative proof fixture failed for the wrong reason",
    );
    assert_failure(&output, "proof-room.negative.payment-merchant-mismatch");
}

#[test]
fn proof_collect_binds_runtime_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let out_path = tempdir.path().join("collected-runtime-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("runtime-missing-execution-lease")
            })
        })
        .test_expect("collected runtime bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/runtime-missing-execution-lease/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/runtime-missing-execution-lease/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("proof-room.negative.missing-execution-lease")));
    let allow_coverage = manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
        .and_then(|coverage| {
            coverage.iter().find(|entry| {
                entry.get("category").and_then(serde_json::Value::as_str)
                    == Some("runtime_terminal_allow")
            })
        })
        .test_expect("collected runtime bundle reports allow receipt coverage");
    assert_eq!(
        allow_coverage
            .get("status")
            .and_then(serde_json::Value::as_str),
        Some("covered")
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_binds_risk_catalog_semantic_negative_cases() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir =
        workspace_root().join("fixtures/proof-room/enterprise-export/standalone-risk-comptroller");
    let out_path = tempdir.path().join("collected-risk-passport");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read collected manifest"),
    )
    .test_expect("collected manifest parses");
    let negative_case = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|negative_cases| {
            negative_cases.iter().find(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("enterprise-double-consumed-reserve")
            })
        })
        .test_expect("collected risk bundle includes catalog semantic negative case");
    assert_eq!(
        negative_case
            .get("path")
            .and_then(serde_json::Value::as_str),
        Some("negatives/catalog/enterprise-double-consumed-reserve/transaction-passport.json")
    );
    assert!(out_path
        .join("negatives/catalog/enterprise-double-consumed-reserve/transaction-passport.json")
        .is_file());
    assert!(negative_case
        .get("observed_failure_code")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|code| code.contains("proof-room.negative.risk-reserve-double-consumption")));
}

#[test]
fn proof_assemble_writes_deterministic_verifiable_passport_roots() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("minimal-artifacts");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "capability-proof.json",
        "guard-decision.json",
        "kernel-receipt.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy source artifact");
    }

    let verifier_policy = source.join("verifier-policy.json");
    let first_out = tempdir.path().join("assembled-first");
    let second_out = tempdir.path().join("assembled-second");
    for out in [&first_out, &second_out] {
        let output = chio(&[
            "proof",
            "assemble",
            "--artifact-dir",
            utf8_path(&artifact_dir).as_str(),
            "--verifier-policy",
            utf8_path(&verifier_policy).as_str(),
            "--passport-id",
            "passport-assembled-minimal",
            "--issued-at",
            "2026-06-10T00:00:00Z",
            "--out",
            utf8_path(out).as_str(),
            "--json",
        ]);
        assert_success(&output);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).test_expect("assemble report parses");
        assert_eq!(report["schema"], "chio.proof.assemble-report.v1");
        assert_eq!(report["passport_id"], "passport-assembled-minimal");
        assert_eq!(report["out"], utf8_path(out));

        let verify = chio(&["proof", "verify", utf8_path(out).as_str()]);
        assert_success(&verify);
        let verify_stdout = stdout(verify);
        assert!(verify_stdout.contains("\"passport_id\":\"passport-assembled-minimal\""));
        assert!(verify_stdout.contains("\"verdict\":\"verified\""));
    }

    for artifact in [
        "transaction-passport.json",
        "evidence-graph.json",
        "verifier-policy.json",
    ] {
        let first = std::fs::read(first_out.join(artifact)).test_expect("read first artifact");
        let second = std::fs::read(second_out.join(artifact)).test_expect("read second artifact");
        assert_eq!(first, second, "{artifact} should be deterministic");
    }
}

#[test]
fn proof_assemble_rejects_reserved_roots_without_partial_output() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("artifact-dir-with-stale-root");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    std::fs::copy(
        source.join("kernel-receipt.json"),
        artifact_dir.join("kernel-receipt.json"),
    )
    .test_expect("copy receipt artifact");
    std::fs::copy(
        source.join("verifier-policy.json"),
        artifact_dir.join("verifier-policy.json"),
    )
    .test_expect("copy stale verifier policy root");

    let out = tempdir.path().join("assembled");
    let output = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-minimal",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(&output, "verifier-policy.json");
    assert!(
        !out.exists(),
        "proof assemble should not leave a partial output directory after rejecting stale roots"
    );
}

#[test]
fn proof_assemble_rejects_missing_required_receipt_without_partial_output() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = tempdir.path().join("artifact-dir-without-receipt");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "capability-proof.json",
        "guard-decision.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy source artifact");
    }

    let out = tempdir.path().join("assembled");
    let output = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-minimal",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);

    assert_failure(&output, "requires at least one receipt artifact");
    assert!(
        !out.exists(),
        "proof assemble should not leave a partial output directory after rejecting missing receipts"
    );
}

#[test]
fn proof_assemble_outputs_runtime_security_bundle_verifiable_by_runtime_requirement() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let artifact_dir = tempdir.path().join("runtime-artifacts");
    std::fs::create_dir_all(&artifact_dir).test_expect("create artifact dir");
    for artifact in [
        "allow-receipt.json",
        "request-digest.json",
        "execution-lease.json",
        "task-graph.json",
        "budget-pool.json",
        "join-receipt.json",
        "route-plan-receipt.json",
        "trust-root.json",
        "trusted-time-proof.json",
        "revocation-freshness-proof.json",
        "sandbox-attestation.json",
        "tool-server-ack.json",
    ] {
        std::fs::copy(source.join(artifact), artifact_dir.join(artifact))
            .test_expect("copy runtime artifact");
    }

    let out = tempdir.path().join("assembled-runtime");
    let assemble = chio(&[
        "proof",
        "assemble",
        "--artifact-dir",
        utf8_path(&artifact_dir).as_str(),
        "--verifier-policy",
        utf8_path(&source.join("verifier-policy.json")).as_str(),
        "--passport-id",
        "passport-assembled-runtime",
        "--issued-at",
        "2026-06-10T00:00:00Z",
        "--out",
        utf8_path(&out).as_str(),
    ]);
    assert_success(&assemble);

    let verify = chio(&[
        "proof",
        "verify",
        utf8_path(&out).as_str(),
        "--require",
        "runtime",
    ]);
    assert_success(&verify);
    let stdout = stdout(verify);
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
    assert!(stdout.contains("\"claim.runtime.advisory_not_used_as_authorization\""));
}

#[test]
fn proof_collect_derives_receipt_coverage_for_each_terminal_status() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-terminal-receipts");
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
    for (path, receipt_id, terminal_status) in [
        (
            "denial-receipt.json",
            "receipt-terminal-denial",
            "denied_guard_request",
        ),
        (
            "failure-receipt.json",
            "receipt-terminal-failure",
            "failed_tool_unreachable",
        ),
    ] {
        write_json(
            &artifact_path.join(path),
            &signed_terminal_receipt(receipt_id, terminal_status, &policy_digest),
        );
    }

    let evidence_graph_path = artifact_path.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("evidence graph parses");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    for path in ["denial-receipt.json", "failure-receipt.json"] {
        let sha256 = sha256_file(&artifact_path.join(path));
        nodes.push(serde_json::json!({
            "id": sha256,
            "schema": "chio.receipt.v1",
            "path": path,
            "sha256": sha256,
            "role": "receipt"
        }));
    }
    write_json(&evidence_graph_path, &evidence_graph);

    let passport_path = artifact_path.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);

    let out_path = tempdir.path().join("collected-terminal-coverage");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read manifest"),
    )
    .test_expect("manifest parses");
    let categories = manifest["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array")
        .iter()
        .map(|entry| {
            entry["category"]
                .as_str()
                .test_expect("coverage category")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        categories,
        BTreeSet::from([
            "runtime_terminal_allow".to_string(),
            "runtime_terminal_denial".to_string(),
            "runtime_terminal_failure".to_string(),
        ])
    );

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);

    let verify_denials = chio(&[
        "proof",
        "verify",
        utf8_path(&out_path).as_str(),
        "--require",
        "denials",
    ]);
    assert_success(&verify_denials);
}

#[test]
fn proof_collect_rejects_unsafe_receipt_coverage_node_path() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_path = tempdir.path().join("passport-with-unsafe-receipt-path");
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
    let receipt_path = artifact_path.join("receipt%2fescape.json");
    write_json(
        &receipt_path,
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
    let unsafe_receipt_sha256 = sha256_file(&receipt_path);
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": unsafe_receipt_sha256,
            "schema": "chio.receipt.v1",
            "path": "receipt%2fescape.json",
            "sha256": unsafe_receipt_sha256,
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

    let out_path = tempdir.path().join("collected-unsafe-receipt-path");
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);

    assert_failure(&output, "proof-room.artifact.unsafe-path");
}

#[test]
fn proof_collect_records_receipt_coverage_exclusions_for_missing_terminal_statuses() {
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
    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        utf8_path(&artifact_path).as_str(),
        "--out",
        utf8_path(&out_path).as_str(),
    ]);
    assert_success(&output);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out_path.join("manifest.json")).test_expect("read manifest"),
    )
    .test_expect("manifest parses");
    let coverage = manifest["receipt_coverage"]
        .as_array()
        .test_expect("receipt coverage array");
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_allow" && entry["status"] == "covered"
    }));
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_denial" && entry["status"] == "covered"
    }));
    assert!(coverage.iter().any(|entry| {
        entry["category"] == "runtime_terminal_failure"
            && entry["status"] == "excluded"
            && entry["exclusion_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("runtime_terminal_failure"))
    }));
    assert!(manifest["claims"]
        .as_array()
        .test_expect("manifest claims array")
        .iter()
        .any(|claim| claim["claim_id"] == "claim.proof_room.receipt_coverage_matrix_bound"));

    let serve_output = chio(&[
        "proof",
        "serve",
        utf8_path(&out_path).as_str(),
        "--listen",
        "127.0.0.1:0",
        "--dry-run",
        "--json",
    ]);
    assert_success(&serve_output);
}

#[test]
fn proof_collect_rejects_existing_output_directory() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let artifact_dir = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let artifact_dir = utf8_path(&artifact_dir);
    let out_dir = utf8_path(tempdir.path());

    let output = chio(&[
        "proof",
        "collect",
        "--kind",
        "transaction-passport",
        "--artifact-dir",
        artifact_dir.as_str(),
        "--out",
        out_dir.as_str(),
    ]);

    assert_failure(&output, "proof output directory already exists");
}
