#[path = "proof_verify/support.rs"]
mod support;

use chio_test_support::prelude::*;
use support::*;

#[test]
fn proof_verify_accepts_minimal_passport_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("valid"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"verifier-report-passport-minimal-valid\""));
    assert!(stdout.contains("\"issued_at\":\"2026-06-10T00:00:00Z\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-minimal-valid\""));
}

#[test]
fn proof_verify_rejects_minimal_passport_without_trusted_transaction_roots() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .env_remove("CHIO_TRANSACTION_TRUSTED_ROOT_KEYS")
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("valid"))
        .output()
        .test_expect("chio command runs");

    assert_eq!(output.status.code(), Some(50));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr
            .contains("CHIO_TRANSACTION_TRUSTED_ROOT_KEYS must pin trusted transaction root keys"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_accepts_minimal_passport_bundle_directory() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(workspace_root().join("fixtures/proof-room/minimal-passport/valid"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-minimal-valid\""));
}

#[test]
fn proof_verify_rejects_minimal_passport_missing_governed_action_evidence() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);
    let claim_set_sha256 = chio_core::sha256_hex(
        &std::fs::read(bundle_dir.join("claim-set.json")).test_expect("read claim set"),
    );
    let verifier_policy_sha256 = chio_core::sha256_hex(
        &std::fs::read(bundle_dir.join("verifier-policy.json")).test_expect("read verifier policy"),
    );

    write_minimal_evidence_graph(
        &bundle_dir,
        serde_json::json!({
            "schema": "chio.transaction.evidence-graph.v1",
            "id": "evidence-graph-minimal-missing-governed-action",
            "issued_at": "2026-06-10T00:00:00Z",
            "nodes": [
                {
                    "id": "claim-set",
                    "schema": "chio.transaction.claim-set.v1",
                    "path": "claim-set.json",
                    "sha256": claim_set_sha256,
                    "role": "claim-set"
                },
                {
                    "id": "verifier-policy",
                    "schema": "chio.transaction.verifier-policy.v1",
                    "path": "verifier-policy.json",
                    "sha256": verifier_policy_sha256,
                    "role": "verifier-policy"
                }
            ],
            "edges": [
                {
                    "evidence_class": "digest-bound-reference",
                    "from": "claim-set",
                    "predicate": "binds",
                    "to": "verifier-policy"
                }
            ]
        }),
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("minimal governed action evidence missing: receipt"));
}

#[test]
fn proof_verify_rejects_schema_invalid_evidence_graph_node_role() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);

    let unsupported_artifact = serde_json::json!({
        "schema": "chio.transaction.future-evidence.v1",
        "id": "future-evidence"
    });
    let unsupported_artifact_bytes =
        serde_json::to_vec(&unsupported_artifact).test_expect("serialize unsupported artifact");
    std::fs::write(
        bundle_dir.join("future-evidence.json"),
        &unsupported_artifact_bytes,
    )
    .test_expect("write unsupported artifact");

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .push(serde_json::json!({
            "id": "future-evidence",
            "schema": "chio.transaction.future-evidence.v1",
            "path": "future-evidence.json",
            "sha256": chio_core::sha256_hex(&unsupported_artifact_bytes),
            "role": "future-unsupported-role"
        }));
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unknown variant `future-unsupported-role`"));
}

#[test]
fn proof_verify_rejects_known_role_with_unregistered_evidence_schema() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("trust-root") {
            node["schema"] = serde_json::json!("chio.unsupported_future_schema.v999");
        }
    }
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unsupported evidence graph node schema"));
}

#[test]
fn proof_verify_rejects_minimal_passport_missing_governed_action_artifact() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);
    std::fs::remove_file(bundle_dir.join("kernel-receipt.json"))
        .test_expect("remove receipt artifact");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert_eq!(output.status.code(), Some(20));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:graph-not-closed"));
    assert!(stderr.contains("CHIO-TRANSACTION-GRAPH-NOT-CLOSED"));
    assert!(stderr.contains("proof verify: missing evidence graph artifact: kernel-receipt.json"));
}

#[test]
fn proof_verify_rejects_minimal_passport_governed_action_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);

    let guard_decision_path = bundle_dir.join("guard-decision.json");
    let mut guard_decision: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&guard_decision_path).test_expect("read guard decision"),
    )
    .test_expect("parse guard decision");
    guard_decision["capability_id"] = serde_json::Value::String("cap-tool-other".to_string());
    std::fs::write(
        &guard_decision_path,
        serde_json::to_vec(&guard_decision).test_expect("serialize guard decision"),
    )
    .test_expect("write guard decision");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "guard-decision.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("minimal governed action evidence invalid"));
}

#[test]
fn proof_verify_out_writes_the_deterministic_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let report_path = tempdir.path().join("verifier-report.json");
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(workspace_root().join("fixtures/proof-room/minimal-passport/valid"))
        .arg("--out")
        .arg(&report_path)
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report = std::fs::read_to_string(report_path).test_expect("report file reads");
    assert_eq!(report, stdout);
    assert!(report.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(report.contains("\"verdict\":\"verified\""));
}

#[test]
fn proof_verify_out_rejects_existing_report_file() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let report_path = tempdir.path().join("verifier-report.json");
    write_file(&report_path, "existing verifier report\n");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(workspace_root().join("fixtures/proof-room/minimal-passport/valid"))
        .arg("--out")
        .arg(&report_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("proof verify output already exists"));
    let report = std::fs::read_to_string(report_path).test_expect("report file reads");
    assert_eq!(report, "existing verifier report\n");
}

#[test]
fn proof_verify_rejects_unknown_passport_schema_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("unknown-passport-schema"))
        .output()
        .test_expect("chio command runs");

    assert_eq!(output.status.code(), Some(30));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unsupported transaction passport schema"));
}

#[test]
fn proof_verify_rejects_evidence_graph_digest_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("evidence-graph-digest-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert_eq!(output.status.code(), Some(20));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:passport-hash-mismatch"));
    assert!(stderr.contains("CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH"));
    assert!(stderr.contains("evidence graph digest mismatch"));
}

#[test]
fn proof_verify_rejects_stale_capability_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("stale-capability"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:authorization-not-bound"));
    assert!(stderr.contains("CHIO-TRANSACTION-AUTHORIZATION-NOT-BOUND"));
    assert!(stderr.contains("capability proof expired before evidence graph issuance"));
}

#[test]
fn proof_verify_accepts_runtime_passport_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(runtime_fixture_path("valid-side-effecting-call"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.runtime-security-report.v1\""));
    assert!(stdout.contains("\"id\":\"runtime-security-report-runtime-passport-valid\""));
    assert!(stdout.contains("\"issued_at\":\"2026-06-10T00:00:00Z\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"runtime-passport-valid\""));
    assert!(stdout.contains("\"claim.runtime.execution_lease_valid\""));
}

#[test]
fn proof_verify_accepts_runtime_denial_terminal_receipt_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(runtime_fixture_path("terminal-denial"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.runtime-security-report.v1\""));
    assert!(stdout.contains("\"id\":\"runtime-security-report-runtime-passport-denial\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"runtime-passport-denial\""));
    assert!(stdout.contains("\"claim.runtime.receipt_totality_complete\""));
}

#[test]
fn proof_verify_accepts_runtime_terminal_receipt_under_common_receipts_dir() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/runtime-security/terminal-denial");
    let bundle_dir = tempdir.path().join("runtime-terminal-common-receipts");
    copy_dir_all(&source, &bundle_dir);

    std::fs::create_dir_all(bundle_dir.join("receipts")).test_expect("create receipts dir");
    std::fs::rename(
        bundle_dir.join("denial-receipt.json"),
        bundle_dir.join("receipts/denial-receipt.json"),
    )
    .test_expect("move terminal receipt into common receipts dir");

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("denial-receipt.json") {
            node["path"] = serde_json::Value::String("receipts/denial-receipt.json".to_string());
        }
    }
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"claim.runtime.receipt_totality_complete\""));
}

#[test]
fn proof_verify_accepts_runtime_infrastructure_failure_receipt_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(runtime_fixture_path("terminal-infrastructure-failure"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.runtime-security-report.v1\""));
    assert!(stdout.contains("\"id\":\"runtime-security-report-runtime-passport-failure\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"runtime-passport-failure\""));
    assert!(stdout.contains("\"claim.runtime.receipt_totality_complete\""));
}

#[test]
fn proof_verify_accepts_enterprise_export_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(enterprise_fixture_path("valid-autonomous-commerce"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"enterprise-verifier-report-passport-enterprise-valid\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-enterprise-valid\""));
    assert!(
        stdout.contains("\"risk_comptroller_report_ref\":\"risk-comptroller-enterprise-valid\"")
    );
    assert!(stdout.contains("\"claim.enterprise.data_governance_bound\""));
    assert!(stdout.contains("\"claim.enterprise.evidence_export_digest_bound\""));
    assert!(stdout.contains("\"claim.enterprise.telemetry_projection_bound\""));
    assert!(stdout.contains("\"claim.enterprise.export_approval_bound\""));
    assert!(stdout.contains("\"claim.enterprise.control_map_bound\""));
    assert!(stdout.contains("\"enterprise_sections\""));
}

#[test]
fn proof_verify_require_risk_outputs_verified_risk_claim() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg("--require")
        .arg("risk")
        .arg(enterprise_fixture_path("valid-autonomous-commerce"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"claim.risk.comptroller_report_bound\""));
}

#[test]
fn proof_verify_rejects_enterprise_routed_unknown_risk_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle_dir = tempdir.path().join("enterprise");
    copy_dir_all(&source, &bundle_dir);
    add_verifier_policy_required_claim(&bundle_dir, "claim.risk.not_real");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert_eq!(output.status.code(), Some(10));
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:required-claim-missing"));
    assert!(stderr.contains("claim.risk.not_real"));
}

#[test]
fn proof_verify_rejects_standalone_risk_graph_node_without_schema() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/enterprise-export/standalone-risk-comptroller");
    let bundle_dir = tempdir.path().join("risk-only-comptroller");
    copy_dir_all(&source, &bundle_dir);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("risk-comptroller-report") {
            node.as_object_mut()
                .test_expect("evidence graph node object")
                .remove("schema");
        }
    }
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing risk comptroller report artifact schema"));
}

#[test]
fn proof_verify_rejects_enterprise_export_risk_subject_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(enterprise_fixture_path("coverage-subject-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("risk coverage subject mismatch"));
}

#[test]
fn proof_verify_rejects_enterprise_export_risk_portfolio_capital_overallocated_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(enterprise_fixture_path(
            "risk-portfolio-capital-overallocated",
        ))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("risk portfolio capital adequacy breach"));
}

#[test]
fn proof_verify_rejects_agent_web_fixture_without_configured_standard_webhooks_secret() {
    let output = chio_with_agent_web_fixture_trust_without_webhooks_secret()
        .arg("proof")
        .arg("verify")
        .arg(agent_web_fixture_path("valid-webhook-cloudevents"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing Standard Webhooks verifier secret"));
}

#[test]
fn proof_verify_accepts_agent_web_interop_fixture() {
    let output = chio_with_agent_web_fixture_secret()
        .arg("proof")
        .arg("verify")
        .arg(agent_web_fixture_path("valid-webhook-cloudevents"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.agent-web.interop-verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"agent-web-interop-report-passport-agent-web-valid\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-agent-web-valid\""));
    assert!(stdout.contains("\"source_protocol\":\"standard-webhooks\""));
    assert!(stdout.contains("\"source_protocol\":\"cloudevents\""));
    assert!(stdout.contains("\"source_protocol\":\"graphql-http\""));
    assert!(stdout.contains("\"source_protocol\":\"mcp\""));
    assert!(stdout.contains("\"source_protocol\":\"a2a\""));
    assert!(stdout.contains("\"source_protocol\":\"acp-client\""));
    assert!(stdout.contains("\"source_protocol\":\"acp-commerce\""));
    assert!(stdout.contains("\"source_protocol\":\"ag-ui\""));
    assert!(stdout.contains("\"source_protocol\":\"browser-automation\""));
    assert!(stdout.contains("\"source_protocol\":\"rpa\""));
    assert!(stdout.contains("\"source_protocol\":\"gmail-api\""));
    assert!(stdout.contains("\"source_protocol\":\"google-calendar-api\""));
    assert!(stdout.contains("\"source_protocol\":\"slack\""));
    assert!(stdout.contains("\"source_protocol\":\"oauth2\""));
    assert!(stdout.contains("\"source_protocol\":\"openid-connect\""));
    assert!(stdout.contains("\"source_protocol\":\"scim\""));
    assert!(stdout.contains("\"source_protocol\":\"spiffe\""));
    assert!(stdout.contains("\"source_protocol\":\"kubernetes-admission\""));
    assert!(stdout.contains("\"source_protocol\":\"oci\""));
    assert!(stdout.contains("\"source_protocol\":\"vc\""));
    assert!(stdout.contains("\"source_protocol\":\"sd-jwt-vc\""));
    assert!(stdout.contains("\"source_protocol\":\"bbs\""));
    assert!(stdout.contains("\"source_protocol\":\"sigstore\""));
    assert!(stdout.contains("\"source_protocol\":\"in-toto\""));
    assert!(stdout.contains("\"source_protocol\":\"dsse\""));
    assert!(stdout.contains("\"source_protocol\":\"slsa-provenance\""));
    assert!(stdout.contains("\"source_protocol\":\"openapi\""));
    assert!(stdout.contains("\"source_protocol\":\"asyncapi\""));
    assert!(stdout.contains("\"source_protocol\":\"ap2\""));
    assert!(stdout.contains("\"source_protocol\":\"x402\""));
    assert!(stdout.contains("\"claim.agent_web.external_subject_digest_bound\""));
    assert!(stdout.contains("\"claim.agent_web.projection_manifest_bound\""));
    assert!(stdout.contains("\"claim.agent_web.unsupported_claims_limited\""));
    assert!(stdout.contains("\"claim.agent_web.sidecar_not_native_authority\""));
    assert!(stdout.contains("\"claim.external.cloudevents_event_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.mcp_tool_call_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.a2a_task_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.acp_client_permission_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.acp_commerce_payment_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.ag_ui_event_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.browser_automation_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.rpa_transcript_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.email_action_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.calendar_action_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.slack_action_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.oauth2_token_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.openid_connect_identity_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.scim_lifecycle_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.spiffe_workload_identity_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.kubernetes_admission_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.oci_ref_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.vc_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.sd_jwt_vc_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.bbs_proof_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.vc_di_bbs_interop_verified\""));
    assert!(stdout.contains("\"claim.external.sigstore_bundle_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.in_toto_statement_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.dsse_envelope_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.slsa_provenance_is_chio_authority\""));
    assert!(stdout.contains("\"claim.external.asyncapi_message_is_chio_authority\""));
}

#[test]
fn proof_verify_rejects_agent_web_mcp_manifest_that_omits_authority_limitation() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle_dir = tempdir.path().join("agent-web");
    copy_dir_all(&source, &bundle_dir);

    let passport_path = set_agent_web_manifest_unsupported_claims(
        &bundle_dir,
        "mcp-manifest.json",
        serde_json::json!([]),
    );

    let output = chio_with_agent_web_fixture_secret()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "mcp manifest without authority limitation unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority"
    ));
}

#[test]
fn proof_verify_rejects_agent_web_a2a_manifest_that_omits_authority_limitation() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle_dir = tempdir.path().join("agent-web");
    copy_dir_all(&source, &bundle_dir);

    let passport_path = set_agent_web_manifest_unsupported_claims(
        &bundle_dir,
        "a2a-manifest.json",
        serde_json::json!([]),
    );

    let output = chio_with_agent_web_fixture_secret()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "a2a manifest without authority limitation unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority"
    ));
}

#[test]
fn proof_verify_rejects_agent_web_oauth2_manifest_that_omits_authority_limitation() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle_dir = tempdir.path().join("agent-web");
    copy_dir_all(&source, &bundle_dir);

    let passport_path = set_agent_web_manifest_unsupported_claims(
        &bundle_dir,
        "oauth2-manifest.json",
        serde_json::json!([]),
    );

    let output = chio_with_agent_web_fixture_secret()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "oauth2 manifest without authority limitation unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "missing Agent Web unsupported authority limitation: claim.external.oauth2_token_is_chio_authority"
    ));
}

#[test]
fn proof_verify_rejects_agent_web_external_authority_manifests_without_limitations() {
    for (manifest_path, required_claim) in [
        (
            "standard-webhooks-manifest.json",
            "claim.external.webhook_signature_is_chio_authority",
        ),
        (
            "cloudevents-manifest.json",
            "claim.external.cloudevents_event_is_chio_authority",
        ),
        (
            "openid-connect-manifest.json",
            "claim.external.openid_connect_identity_is_chio_authority",
        ),
        (
            "spiffe-manifest.json",
            "claim.external.spiffe_workload_identity_is_chio_authority",
        ),
        (
            "kubernetes-admission-manifest.json",
            "claim.external.kubernetes_admission_is_chio_authority",
        ),
        (
            "oci-ref-manifest.json",
            "claim.external.oci_ref_is_chio_authority",
        ),
        ("vc-manifest.json", "claim.external.vc_is_chio_authority"),
        (
            "sigstore-manifest.json",
            "claim.external.sigstore_bundle_is_chio_authority",
        ),
        (
            "acp-client-manifest.json",
            "claim.external.acp_client_permission_is_chio_authority",
        ),
        (
            "acp-commerce-manifest.json",
            "claim.external.acp_commerce_payment_is_chio_authority",
        ),
        (
            "ag-ui-manifest.json",
            "claim.external.ag_ui_event_is_chio_authority",
        ),
        (
            "browser-automation-manifest.json",
            "claim.external.browser_automation_is_chio_authority",
        ),
        (
            "rpa-manifest.json",
            "claim.external.rpa_transcript_is_chio_authority",
        ),
        (
            "email-manifest.json",
            "claim.external.email_action_is_chio_authority",
        ),
        (
            "calendar-manifest.json",
            "claim.external.calendar_action_is_chio_authority",
        ),
        (
            "slack-manifest.json",
            "claim.external.slack_action_is_chio_authority",
        ),
        (
            "scim-manifest.json",
            "claim.external.scim_lifecycle_is_chio_authority",
        ),
        (
            "sd-jwt-vc-manifest.json",
            "claim.external.sd_jwt_vc_is_chio_authority",
        ),
        (
            "bbs-manifest.json",
            "claim.external.bbs_proof_is_chio_authority",
        ),
        (
            "in-toto-manifest.json",
            "claim.external.in_toto_statement_is_chio_authority",
        ),
        (
            "slsa-manifest.json",
            "claim.external.slsa_provenance_is_chio_authority",
        ),
        (
            "openapi-manifest.json",
            "claim.external.openapi_operation_is_chio_authority",
        ),
        (
            "asyncapi-manifest.json",
            "claim.external.asyncapi_message_is_chio_authority",
        ),
        (
            "ap2-manifest.json",
            "claim.external.ap2_mandate_is_chio_authority",
        ),
        (
            "x402-manifest.json",
            "claim.external.x402_payment_is_chio_authority",
        ),
    ] {
        let tempdir = tempfile::tempdir().test_expect("tempdir");
        let source =
            workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
        let bundle_dir = tempdir.path().join("agent-web");
        copy_dir_all(&source, &bundle_dir);

        let passport_path = set_agent_web_manifest_unsupported_claims(
            &bundle_dir,
            manifest_path,
            serde_json::json!([]),
        );

        let output = chio_with_agent_web_fixture_secret()
            .arg("proof")
            .arg("verify")
            .arg(passport_path)
            .output()
            .test_expect("chio command runs");

        assert!(
            !output.status.success(),
            "{manifest_path} without authority limitation unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
        assert!(stderr.contains(&format!(
            "missing Agent Web unsupported authority limitation: {required_claim}"
        )));
    }
}

#[test]
fn proof_verify_rejects_agent_web_manifests_that_omit_secondary_authority_limitations() {
    for (manifest_path, retained_claim, omitted_claim) in [
        (
            "bbs-manifest.json",
            "claim.external.bbs_proof_is_chio_authority",
            "claim.external.vc_di_bbs_interop_verified",
        ),
        (
            "in-toto-manifest.json",
            "claim.external.in_toto_statement_is_chio_authority",
            "claim.external.dsse_envelope_is_chio_authority",
        ),
    ] {
        let tempdir = tempfile::tempdir().test_expect("tempdir");
        let source =
            workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
        let bundle_dir = tempdir.path().join("agent-web");
        copy_dir_all(&source, &bundle_dir);

        let passport_path = set_agent_web_manifest_unsupported_claims(
            &bundle_dir,
            manifest_path,
            serde_json::json!([retained_claim]),
        );

        let output = chio_with_agent_web_fixture_secret()
            .arg("proof")
            .arg("verify")
            .arg(passport_path)
            .output()
            .test_expect("chio command runs");

        assert!(
            !output.status.success(),
            "{manifest_path} without secondary authority limitation unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
        assert!(stderr.contains(&format!(
            "missing Agent Web unsupported authority limitation: {omitted_claim}"
        )));
    }
}

#[test]
fn proof_verify_accepts_trust_market_context_fixture() {
    let output = chio_with_trust_market_fixture_authority()
        .arg("proof")
        .arg("verify")
        .arg(trust_market_fixture_path("valid-marketplace-context"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"trust-market-verifier-report-passport-trust-market-valid\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-trust-market-valid\""));
    assert!(stdout.contains("\"risk_comptroller_report_ref\":\"risk-comptroller-market-valid\""));
    assert!(stdout.contains("\"selected_provider_subject\":\"did:chio:provider-alpha\""));
    assert!(stdout.contains("\"claim.trust_market.provider_discovery_bound\""));
    assert!(stdout.contains("\"claim.trust_market.provider_selection_bound\""));
    assert!(stdout.contains("\"claim.trust_market.local_scorecard_bound\""));
    assert!(stdout.contains("\"claim.trust_market.reputation_import_bound\""));
    assert!(stdout.contains("\"claim.trust_market.sla_commitment_bound\""));
    assert!(stdout.contains("\"claim.trust_market.collateral_guarantee_bound\""));
    assert!(stdout.contains("\"claim.trust_market.jurisdiction_bound\""));
    assert!(stdout.contains("\"claim.trust_market.unsupported_market_claims_limited\""));
    assert!(stdout.contains("\"claim.market.global_trust_score_published\""));
}

#[test]
fn proof_verify_accepts_public_settlement_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.public-settlement-verifier-report.v1\""));
    assert!(stdout.contains(
        "\"id\":\"public-settlement-verifier-report-web3-settlement-proof-public-valid\""
    ));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"bundle_id\":\"web3-settlement-proof-public-valid\""));
    assert!(stdout.contains("\"recomputed_settlement_state\":\"settled\""));
    assert!(stdout.contains("\"chain_id\":\"eip155:8453\""));
    assert!(
        stdout.contains("\"bond_vault_contract\":\"0x1000000000000000000000000000000000000003\"")
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).test_expect("stdout is json");
    let expected_amount = serde_json::json!({
        "currency": "USD",
        "units": 150,
    });
    let settlement_report = report["family_reports"]
        .as_array()
        .and_then(|reports| {
            reports.iter().find(|report| {
                report.get("schema").and_then(serde_json::Value::as_str)
                    == Some("chio.public-settlement-verifier-report.v1")
            })
        })
        .test_expect("public settlement family report");
    assert_eq!(
        settlement_report.pointer("/chain_context/posted_bond_amount"),
        Some(&expected_amount)
    );
    assert_eq!(
        settlement_report.pointer("/chain_context/minimum_bond_amount"),
        Some(&expected_amount)
    );
    assert!(stdout.contains(
        "\"block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
    ));
    assert!(stdout.contains(
        "\"anchor_tx_hash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
    ));
    assert!(stdout.contains(
        "\"settlement_tx_hash\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\""
    ));
    assert!(stdout.contains("\"claim.public_settlement.order_binding_verified\""));
    assert!(stdout.contains("\"claim.public_settlement.chain_context_verified\""));
    assert!(stdout.contains("\"claim.public_settlement.finality_verified\""));
    assert!(stdout.contains("\"claim.public_settlement.oracle_conversion_bound\""));
    assert!(stdout.contains("\"claim.public_settlement.dispute_posture_bound\""));
    assert!(!stdout.contains("\"claim.public_settlement.trust_market_refs_bound\""));
    assert!(!stdout.contains("\"trust_market_context\""));
}

#[test]
fn proof_verify_rejects_public_settlement_reorged_independent_head() {
    let independent_head = serde_json::json!({
        "chain_id": "eip155:8453",
        "observed_block_number": 12_345_678,
        "observed_block_hash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "latest_block_number": 12_345_701
    });

    let output = chio_with_transaction_fixture_roots()
        .env(
            "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON",
            independent_head.to_string(),
        )
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("public settlement independent head block hash mismatch"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_public_settlement_without_independent_head() {
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON")
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("public settlement independent head missing"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_public_settlement_trust_market_refs_without_configured_context() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);
    mutate_public_settlement_bundle(&bundle_dir, |settlement_bundle| {
        settlement_bundle["collateral_position_ref"] =
            serde_json::json!("collateral-trust-market-valid");
        settlement_bundle["guarantee_decision_ref"] =
            serde_json::json!("guarantee-trust-market-valid");
        settlement_bundle["sla_remedy_ref"] = serde_json::json!("remedy-policy-market-valid");
        settlement_bundle["slash_authority_ref"] = serde_json::json!("did:chio:slash-authority");
    });
    set_verifier_policy_required_claims(
        &bundle_dir,
        &[
            "claim.public_settlement.order_binding_verified",
            "claim.public_settlement.chain_context_verified",
            "claim.public_settlement.finality_verified",
            "claim.public_settlement.oracle_conversion_bound",
            "claim.public_settlement.dispute_posture_bound",
        ],
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "refs without configured trust-market context should fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("public settlement trust-market context missing"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_public_settlement_partial_trust_market_refs() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["guarantee_decision_ref"] =
                serde_json::json!("guarantee-trust-market-valid");
            settlement_bundle["sla_remedy_ref"] = serde_json::json!("remedy-policy-market-valid");
            settlement_bundle["slash_authority_ref"] =
                serde_json::json!("did:chio:slash-authority");
        },
        "public settlement trust-market refs incomplete",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_without_chain_allow_list() {
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS")
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains(
            "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS must pin trusted public settlement chain IDs"
        ),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_public_settlement_graph_node_without_schema() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("role").and_then(serde_json::Value::as_str)
            == Some("public-settlement-proof-bundle")
        {
            node.as_object_mut()
                .test_expect("evidence graph node object")
                .remove("schema");
        }
    }
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing public settlement proof bundle artifact schema"));
}

#[test]
fn proof_verify_rejects_public_settlement_invalid_chain_snapshot() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]["latest_block_number"] =
                serde_json::json!(12_345_900);
        },
        "public settlement chain snapshot is stale",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]["registry_root"] = serde_json::json!(
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            );
        },
        "public settlement registry root mismatch",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]["escrow"]["locked_amount"]["units"] =
                serde_json::json!(149);
        },
        "public settlement escrow balance below required amount",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]
                .as_object_mut()
                .test_expect("chain snapshot object")
                .remove("block");
        },
        "public settlement block snapshot missing",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]["block"]["transaction_hashes"] =
                serde_json::json!([
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                ]);
        },
        "public settlement anchor tx hash missing from block",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["dispute_snapshot"]["chain_event_tx_hashes"] = serde_json::json!([
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            ]);
        },
        "public settlement dispute event block evidence missing",
    );
    assert_public_settlement_mutation_rejected_with_codes(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]
                .as_object_mut()
                .test_expect("chain snapshot object")
                .remove("beneficiary_identity_binding");
        },
        "public settlement beneficiary identity binding missing",
        &[
            "urn:chio:error:transaction:identity-not-bound",
            "CHIO-TRANSACTION-IDENTITY-NOT-BOUND",
        ],
    );
    assert_public_settlement_mutation_rejected_with_codes(
        |settlement_bundle| {
            settlement_bundle
                .as_object_mut()
                .test_expect("settlement proof bundle object")
                .remove("dispute_snapshot");
        },
        "public settlement dispute snapshot missing",
        &[
            "urn:chio:error:transaction:dispute-unbound",
            "CHIO-TRANSACTION-DISPUTE-UNBOUND",
        ],
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]
                .as_object_mut()
                .test_expect("chain snapshot object")
                .remove("bond");
        },
        "public settlement bond snapshot missing",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]["bond"]["posted_amount"]["units"] =
                serde_json::json!(149);
        },
        "public settlement bond below policy",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_order_binding_settlement_tx_mismatch() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["order_binding"]["settlement_tx_hash"] = serde_json::json!(
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            );
        },
        "public settlement order binding settlement tx mismatch",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_order_binding_rail_mismatch() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["order_binding"]["settlement_rail_id"] =
                serde_json::json!("base-mainnet-unapproved-rail");
        },
        "public settlement order binding rail mismatch",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_order_binding_custody_provider_mismatch() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["order_binding"]["custody_provider_id"] = serde_json::json!(
                "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de"
            );
        },
        "public settlement order binding custody provider mismatch",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_stale_oracle_evidence() {
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["settlement_receipt"]["oracle_evidence"]["cache_age_seconds"] =
                serde_json::json!(3_601);
        },
        "oracle conversion evidence is stale",
    );
}

#[test]
fn proof_verify_rejects_public_settlement_unverified_required_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);
    add_verifier_policy_required_claim(
        &bundle_dir,
        "claim.public_settlement.future_claim_not_emitted",
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "required public settlement claim not verified: claim.public_settlement.future_claim_not_emitted"
    ));
}

#[test]
fn proof_verify_rejects_misspelled_required_claim_prefix() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce");
    copy_dir_all(&source, &bundle_dir);

    let policy_path = bundle_dir.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("parse verifier policy");
    policy["required_claims"]
        .as_array_mut()
        .test_expect("required claims array")
        .push(serde_json::Value::String(
            "claim.commerc.order_replay_consistent".to_string(),
        ));
    let policy_bytes = serde_json::to_vec(&policy).test_expect("serialize verifier policy");
    std::fs::write(&policy_path, &policy_bytes).test_expect("write verifier policy");
    let policy_digest = chio_core::sha256_hex(&policy_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("verifier-policy") {
            node["sha256"] = serde_json::Value::String(policy_digest.clone());
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);

    let passport_path = bundle_dir.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("parse passport");
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_digest);
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_digest);
    write_json(&passport_path, &passport);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("unsupported required proof claim: claim.commerc.order_replay_consistent")
    );
}

#[test]
fn proof_verify_rejects_public_settlement_passport_policy_digest_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);

    let passport_path = bundle_dir.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("parse passport");
    passport["verifier_policy_sha256"] = serde_json::Value::String("0".repeat(64));
    write_json(&passport_path, &passport);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:passport-hash-mismatch"));
    assert!(stderr.contains("CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH"));
    assert!(!stderr.contains("urn:chio:error:cli:other"));
    assert!(stderr.contains("verifier policy digest mismatch"));
}

#[test]
fn proof_verify_rejects_public_settlement_passport_id_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);
    mutate_public_settlement_bundle(&bundle_dir, |settlement_bundle| {
        settlement_bundle["transaction_passport_id"] =
            serde_json::Value::String("passport-other-settlement-root".to_string());
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("public settlement proof bundle passport mismatch"));
}

#[test]
fn proof_verify_accepts_commerce_payment_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("offline-psp-valid"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.commerce.order-passport.v1\""));
    assert!(stdout.contains("\"id\":\"commerce-order-passport-order-commerce-001\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"order_id\":\"order-commerce-001\""));
    assert!(stdout.contains("\"current_state\":\"completed\""));
    assert!(stdout.contains("\"artifact_digests\""));
    assert!(stdout.contains("\"order_context_sha256\""));
    assert!(stdout.contains("\"payment_lifecycle_sha256\""));
    assert!(stdout.contains("\"selective_disclosure_policy\""));
    assert!(stdout.contains("\"chio.commerce.order-passport.public-summary.v1\""));
    assert!(stdout.contains("\"redacted_fields\""));
    assert!(stdout.contains("\"payment_intent_id\""));
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.commerce.payment_lifecycle_bound\""));
    assert!(stdout.contains("\"claim.commerce.mandate_allowance_bound\""));
    assert!(stdout.contains("\"claim.commerce.admission_gates_bound\""));
    assert!(stdout.contains("\"claim.commerce.settlement_lifecycle_bound\""));
    assert!(stdout.contains("\"claim.commerce.order_passport_summary_bound\""));
}

#[test]
fn proof_verify_rejects_commerce_without_graph_bound_order_passport() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payment");
    copy_dir_all(&source, &bundle_dir);
    let _ = std::fs::remove_file(bundle_dir.join("order-passport.json"));

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .retain(|node| {
            node.get("role").and_then(serde_json::Value::as_str) != Some("commerce-order-passport")
        });
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("missing commerce order passport artifact role"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_commerce_without_trusted_provider_keys() {
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS")
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("offline-psp-valid"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr
        .contains("CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys"));
}

#[test]
fn proof_verify_rejects_commerce_cyclic_evidence_graph_before_family_verifier() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    let report_path = tempdir.path().join("graph-cycle-report.json");
    copy_dir_all(&source, &bundle_dir);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
        .push(serde_json::json!({
            "evidence_class": "digest-bound-reference",
            "from": "event-log",
            "predicate": "binds",
            "to": "order-context"
        }));
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--out")
        .arg(&report_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("urn:chio:error:transaction:graph-cycle"));
    assert!(stderr.contains("CHIO-TRANSACTION-GRAPH-CYCLE"));
    assert!(stderr.contains("cyclic evidence graph"));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read failure report"))
            .test_expect("failure report parses");
    assert_eq!(
        report["failureCode"],
        "urn:chio:error:transaction:graph-cycle"
    );
}

#[test]
fn proof_verify_rejects_commerce_payment_wrong_merchant_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("payment-wrong-merchant"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("payment merchant mismatch"));
}

#[test]
fn proof_verify_rejects_commerce_payment_bad_psp_object_ref() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_payment_lifecycle(&bundle_dir, |payment_lifecycle| {
        payment_lifecycle["capture_ref"] = serde_json::Value::String("charge_only".to_string());
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("payment capture_ref is not a supported PSP object ref"));
}

#[test]
fn proof_verify_rejects_commerce_payment_quote_digest_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_payment_lifecycle(&bundle_dir, |payment_lifecycle| {
        payment_lifecycle["quote_sha256"] =
            serde_json::json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("payment quote digest mismatch"));
}

#[test]
fn proof_verify_rejects_commerce_provider_passport_subject_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_provider_passport(&bundle_dir, |provider_passport| {
        provider_passport["provider_subject"] = serde_json::json!("merchant:stripe:other-shop");
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("provider passport subject mismatch"));
}

#[test]
fn proof_verify_rejects_commerce_mandate_missing_x402_projection() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_mandate_ledger(&bundle_dir, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        projections.retain(|projection| projection["protocol"] != "x402");
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("mandate projection missing: x402/payment_requirements"));
}

#[test]
fn proof_verify_rejects_commerce_mandate_missing_chio_projection() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_mandate_ledger(&bundle_dir, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        projections.retain(|projection| {
            projection["protocol"] != "chio" || projection["purpose"] != "authority_projection"
        });
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("mandate projection missing: chio/authority_projection"));
}

#[test]
fn proof_verify_rejects_commerce_refund_without_dispute_transition() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_event_log(&bundle_dir, |event_log| {
        event_log["events"]
            .as_array_mut()
            .test_expect("event log events array")
            .push(serde_json::json!({
                "actor": "agent:single-call-authority",
                "event_id": "event-commerce-001-refund",
                "order_id": "order-commerce-001",
                "prior_state": "completed",
                "next_state": "refunded",
                "transition": "refund_payment",
                "occurred_at": "2026-06-10T00:09:00Z",
                "authority_receipt_ref": "receipt-refund-commerce-001",
                "evidence_refs": ["payment-lifecycle-commerce-001"],
                "idempotency_key": "idem-event-commerce-001-refund"
            }));
    });
    mutate_commerce_payment_lifecycle(&bundle_dir, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("succeeded");
    });
    mutate_commerce_order_context(&bundle_dir, |order_context| {
        order_context["current_state"] = serde_json::json!("refunded");
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("unknown commerce transition: completed -> refunded via refund_payment")
    );
}

#[test]
fn proof_verify_rejects_commerce_intent_evidence_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("intent-evidence-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("intent event missing intent evidence"));
}

#[test]
fn proof_verify_rejects_commerce_provider_admission_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("provider-admission-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("provider event missing provider admission evidence"));
}

#[test]
fn proof_verify_rejects_commerce_settlement_packet_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("settlement-packet-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("settlement event missing settlement packet evidence"));
    assert!(stderr.contains("urn:chio:error:transaction:settlement-unverified"));
    assert!(stderr.contains("CHIO-TRANSACTION-SETTLEMENT-UNVERIFIED"));
}

#[test]
fn proof_verify_rejects_commerce_reconciliation_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(commerce_fixture_path("reconciliation-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("reconciliation event missing reconciliation evidence"));
}

#[test]
fn proof_verify_rejects_commerce_event_log_invalid_timestamp() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_event_log(&bundle_dir, |event_log| {
        event_log["events"][0]["occurred_at"] = serde_json::Value::String("not-a-timestamp".into());
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("commerce event occurred_at"));
}

#[test]
fn proof_verify_rejects_commerce_event_log_regressed_timestamp() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_event_log(&bundle_dir, |event_log| {
        event_log["events"][5]["occurred_at"] =
            serde_json::Value::String("2026-06-10T00:01:30Z".into());
    });

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("commerce event timestamp regressed"));
}

#[test]
fn proof_verify_accepts_swarm_authority_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(swarm_fixture_path("valid-recursive-delegation"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.swarm.authority-verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"swarm-authority-verifier-report-swarm-graph-proof-valid\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"graphId\":\"swarm-graph-proof-valid\""));
    assert!(stdout.contains("\"taskCount\":4"));
    assert!(stdout.contains("\"continuationCount\":3"));
    assert!(stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(stdout.contains("\"claim.swarm.continuation_fresh\""));
    assert!(stdout.contains("\"claim.swarm.attenuation_witness_chain_bound\""));
    assert!(stdout.contains("\"claim.swarm.route_plan_bound\""));
    assert!(stdout.contains("\"claim.swarm.join_receipt_bound\""));
    assert!(stdout.contains("\"claim.swarm.budget_pool_bound\""));
    assert!(stdout.contains("\"claim.swarm.revocation_epoch_bound\""));
}

#[test]
fn proof_verify_rejects_swarm_authority_without_trusted_witness_keys() {
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_SWARM_TRUSTED_WITNESS_KEYS")
        .arg("proof")
        .arg("verify")
        .arg(swarm_fixture_path("valid-recursive-delegation"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_swarm_authority_expired_at_verification_time() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle_dir = tempdir.path().join("swarm-authority");
    copy_dir_all(&source, &bundle_dir);
    expire_swarm_bundle_before_verification_time(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("swarm task graph is expired"), "{stderr}");
}

#[test]
fn proof_verify_rejects_local_family_malformed_verifier_policy() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let bundle_dir = tempdir.path().join("swarm-authority");
    copy_dir_all(&source, &bundle_dir);
    duplicate_first_verifier_policy_required_claim(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("duplicate verifier policy value in required_claims"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_accepts_disclosure_lineage_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(disclosure_lineage_fixture_path("valid-lineage-ledger"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.disclosure.lineage-verifier-report.v1\""));
    assert!(
        stdout.contains("\"id\":\"disclosure-lineage-verifier-report-disclosure-capsule-valid\"")
    );
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"capsule_id\":\"disclosure-capsule-valid\""));
    assert!(stdout.contains("\"crypto_verified\":true"));
    assert!(stdout.contains("\"privacy_profile_verified\":true"));
    assert!(stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(stdout.contains("\"claim.disclosure.leakage_ledger_complete\""));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_without_pinned_signer_keys() {
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS")
        .arg("proof")
        .arg("verify")
        .arg(disclosure_lineage_fixture_path("valid-lineage-ledger"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS must pin trusted disclosure lineage signer keys"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_disclosure_claim_set_required_claim_not_verified() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    mark_claim_set_claim_failed(&bundle_dir, "claim.disclosure.lineage_subgraph_bound");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure proof verified with failed root claim-set claim\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "claim set required claim was not verified: claim.disclosure.lineage_subgraph_bound"
    ));
}

fn mark_claim_set_claim_failed(bundle_dir: &std::path::Path, claim_id: &str) {
    let claim_set_path = bundle_dir.join("claim-set.json");
    let mut claim_set: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claim_set_path).test_expect("read claim set"))
            .test_expect("parse claim set");
    let claims = claim_set["claims"]
        .as_array_mut()
        .test_expect("claim set claims");
    let Some(claim) = claims
        .iter_mut()
        .find(|claim| claim.get("claim_id").and_then(serde_json::Value::as_str) == Some(claim_id))
    else {
        panic!("claim set contains {claim_id}");
    };
    claim["status"] = serde_json::Value::String("failed".to_string());
    claim["failure_reason"] = serde_json::Value::String("test mutation".to_string());
    write_json(&claim_set_path, &claim_set);

    let claim_set_sha256 = chio_core::sha256_hex(
        &std::fs::read(&claim_set_path).test_expect("read mutated claim set"),
    );
    refresh_claim_set_graph_digest(bundle_dir, &claim_set_sha256);
    set_passport_digest(bundle_dir, "claim_set_sha256", claim_set_sha256);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", String::new());
}

fn add_claim_set_verified_claim(bundle_dir: &std::path::Path, claim_id: &str) {
    let claim_set_path = bundle_dir.join("claim-set.json");
    let mut claim_set: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claim_set_path).test_expect("read claim set"))
            .test_expect("parse claim set");
    let claims = claim_set["claims"]
        .as_array_mut()
        .test_expect("claim set claims");
    claims.retain(|claim| {
        claim.get("claim_id").and_then(serde_json::Value::as_str) != Some(claim_id)
    });
    claims.push(serde_json::json!({
        "claim_id": claim_id,
        "status": "verified",
        "required_evidence": [
            "crypto-context-report.json",
            "verification-context.json",
            "selective-disclosure-proof.json"
        ],
        "evidence_refs": [
            "crypto-context-report.json",
            "verification-context.json",
            "selective-disclosure-proof.json"
        ],
        "verifier_module": "chio proof verify"
    }));
    write_json(&claim_set_path, &claim_set);

    let claim_set_sha256 = chio_core::sha256_hex(
        &std::fs::read(&claim_set_path).test_expect("read mutated claim set"),
    );
    refresh_claim_set_graph_digest(bundle_dir, &claim_set_sha256);
    set_passport_digest(bundle_dir, "claim_set_sha256", claim_set_sha256);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", String::new());
}

fn refresh_claim_set_graph_digest(bundle_dir: &std::path::Path, claim_set_sha256: &str) {
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes");
    let mut old_claim_set_ids = Vec::new();
    for node in nodes {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("claim-set") {
            if let Some(id) = node.get("id").and_then(serde_json::Value::as_str) {
                old_claim_set_ids.push(id.to_string());
            }
            node["id"] = serde_json::Value::String(claim_set_sha256.to_string());
            node["sha256"] = serde_json::Value::String(claim_set_sha256.to_string());
        }
    }
    if let Some(edges) = evidence_graph["edges"].as_array_mut() {
        for edge in edges {
            for field in ["from", "to"] {
                if old_claim_set_ids.iter().any(|id| {
                    edge.get(field).and_then(serde_json::Value::as_str) == Some(id.as_str())
                }) {
                    edge[field] = serde_json::Value::String(claim_set_sha256.to_string());
                }
            }
        }
    }
    write_json(&evidence_graph_path, &evidence_graph);
}

#[test]
fn proof_verify_rejects_disclosure_lineage_field_forbidden_by_privacy_profile() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    let profile_path = bundle_dir.join("privacy-profile.json");
    let mut profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&profile_path).test_expect("read privacy profile"))
            .test_expect("parse privacy profile");
    profile["forbidden_disclosed_fields"]
        .as_array_mut()
        .test_expect("forbidden disclosed fields")
        .push(serde_json::Value::String("tool_name".to_string()));
    write_json(&profile_path, &profile);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "privacy-profile.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "privacy profile forbidden disclosure unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("disclosed field forbidden by privacy profile: tool_name"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_disclosure_lineage_privacy_profile_transaction_ref_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    let profile_path = bundle_dir.join("privacy-profile.json");
    let mut profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&profile_path).test_expect("read privacy profile"))
            .test_expect("parse privacy profile");
    profile["transaction_passport_ref"] =
        serde_json::Value::String("passport-disclosure-other".to_string());
    write_json(&profile_path, &profile);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "privacy-profile.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "privacy profile transaction mismatch unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("privacy profile transaction passport ref mismatch"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_disclosure_lineage_missing_ledger_entry_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(disclosure_lineage_fixture_path("missing-ledger-entry"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("disclosed field absent from leakage ledger"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_unsupported_edge_kind_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(disclosure_lineage_fixture_path("unsupported-edge-kind"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unsupported lineage edge kind"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_missing_parent_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(disclosure_lineage_fixture_path("missing-parent"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unknown lineage edge source"));
}

#[test]
fn proof_verify_rejects_disclosure_swapped_crypto_proof_without_required_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    std::fs::copy(
        workspace_root().join(
            "fixtures/proof-room/disclosure-lineage/excess-disclosed-field/selective-disclosure-proof.json",
        ),
        bundle_dir.join("selective-disclosure-proof.json"),
    )
    .test_expect("copy overdisclosing proof");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure family verified swapped crypto proof\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn proof_verify_rejects_disclosure_evidence_failure_without_policy_required_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    std::fs::copy(
        workspace_root().join(
            "fixtures/proof-room/disclosure-lineage/excess-disclosed-field/selective-disclosure-proof.json",
        ),
        bundle_dir.join("selective-disclosure-proof.json"),
    )
    .test_expect("copy overdisclosing proof");
    std::fs::copy(
        workspace_root().join(
            "fixtures/proof-room/disclosure-lineage/excess-disclosed-field/bbs-projection-manifest.json",
        ),
        bundle_dir.join("bbs-projection-manifest.json"),
    )
    .test_expect("copy overdisclosing BBS projection manifest");
    std::fs::copy(
        workspace_root()
            .join("fixtures/proof-room/disclosure-lineage/excess-disclosed-field/capsule.json"),
        bundle_dir.join("capsule.json"),
    )
    .test_expect("copy overdisclosing disclosure capsule");
    std::fs::copy(
        workspace_root().join(
            "fixtures/proof-room/disclosure-lineage/excess-disclosed-field/transparency-inclusion-proof.json",
        ),
        bundle_dir.join("transparency-inclusion-proof.json"),
    )
    .test_expect("copy overdisclosing transparency inclusion proof");
    std::fs::copy(
        workspace_root().join(
            "fixtures/proof-room/disclosure-lineage/excess-disclosed-field/crypto-context-report.json",
        ),
        bundle_dir.join("crypto-context-report.json"),
    )
    .test_expect("copy overdisclosing crypto context report");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "selective-disclosure-proof.json");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "bbs-projection-manifest.json");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "capsule.json");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "transparency-inclusion-proof.json");
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "crypto-context-report.json");
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for edge in evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
    {
        if matches!(
            edge["predicate"].as_str(),
            Some("defines" | "verifies" | "anchors")
        ) {
            edge["predicate"] = serde_json::json!("binds");
        }
    }
    write_minimal_evidence_graph(&bundle_dir, evidence_graph);
    set_disclosure_policy_required_claims(&bundle_dir, &[]);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure evidence failure was skipped when policy required no disclosure claims\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("disclosure selective disclosure proof rejected")
            || stderr.contains(
                "BBS projection manifest message slot count does not match proof message count"
            )
            || stderr.contains("disclosed field forbidden by privacy profile")
            || stderr.contains("crypto context report excess disclosed field: customer_email"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_require_disclosure_rejects_missing_profile_context_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    remove_disclosure_crypto_context_verified_claim(
        &bundle_dir,
        "claim.disclosure.profile_context_policy_enforced",
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure requirement verified without profile context claim\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains(
            "proof verify: disclosure crypto report verified claims did not match recomputed BBS verification"
        ),
        "{stderr}"
    );
}

#[test]
fn proof_verify_require_disclosure_rejects_missing_crypto_context_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    remove_disclosure_crypto_context_report(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure requirement verified without crypto context report\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing crypto context report"), "{stderr}");
}

#[test]
fn proof_verify_accepts_disclosure_crypto_context_required_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    add_disclosure_crypto_verification_context(&bundle_dir);
    add_valid_disclosure_selective_disclosure_proof(&bundle_dir);
    set_disclosure_policy_required_claims(&bundle_dir, &["claim.disclosure.crypto_context_bound"]);
    add_claim_set_verified_claim(&bundle_dir, "claim.disclosure.crypto_context_bound");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "disclosure crypto context claim was not accepted\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.disclosure.lineage-verifier-report.v1\""));
    assert!(stdout.contains("\"claim.disclosure.crypto_context_bound\""));
}

#[test]
fn proof_verify_rejects_disclosure_crypto_context_preview_transparency() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    add_disclosure_crypto_verification_context(&bundle_dir);
    add_valid_disclosure_selective_disclosure_proof(&bundle_dir);
    let context_path = bundle_dir.join("verification-context.json");
    let mut context: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&context_path).test_expect("read context"))
            .test_expect("parse context");
    context["transparency_state"] = serde_json::Value::String("preview".to_string());
    write_json(&context_path, &context);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "verification-context.json");
    set_disclosure_policy_required_claims(&bundle_dir, &["claim.disclosure.crypto_context_bound"]);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure crypto context with preview transparency unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("disclosure_context_transparency_state_insufficient"));
    assert!(stderr.contains("urn:chio:error:transaction:transparency-preview-not-allowed"));
    assert!(stderr.contains("CHIO-TRANSACTION-TRANSPARENCY-PREVIEW-NOT-ALLOWED"));
}

#[test]
fn proof_verify_rejects_disclosure_crypto_context_required_claim_without_context_material() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    remove_disclosure_crypto_verification_context(&bundle_dir);
    remove_disclosure_selective_disclosure_proof(&bundle_dir);
    set_disclosure_policy_required_claims(&bundle_dir, &["claim.disclosure.crypto_context_bound"]);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure crypto context claim verified without context material\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing disclosure crypto verification context"));
}

#[test]
fn proof_verify_rejects_disclosure_crypto_context_required_claim_without_bbs_proof() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    add_disclosure_crypto_verification_context(&bundle_dir);
    remove_disclosure_selective_disclosure_proof(&bundle_dir);
    set_disclosure_policy_required_claims(&bundle_dir, &["claim.disclosure.crypto_context_bound"]);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure crypto context claim verified without BBS proof\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing disclosure selective disclosure proof"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_unregistered_crypto_context_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    add_disclosure_crypto_context_verified_claim(
        &bundle_dir,
        "claim.disclosure.unregistered_crypto_context_claim",
    );
    set_disclosure_policy_required_claims(
        &bundle_dir,
        &["claim.disclosure.unregistered_crypto_context_claim"],
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with unregistered crypto context claim unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "disclosure crypto report verified claims did not match recomputed BBS verification"
    ));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_missing_crypto_context_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    remove_disclosure_crypto_context_report(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage without crypto context unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing crypto context report"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_crypto_context_ref_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    let capsule_path = bundle_dir.join("capsule.json");
    let mut capsule: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&capsule_path).test_expect("read capsule"))
            .test_expect("parse capsule");
    capsule["crypto_context_report_ref"] =
        serde_json::Value::String("crypto-context-report-other".to_string());
    let capsule_bytes = serde_json::to_vec(&capsule).test_expect("serialize capsule");
    std::fs::write(&capsule_path, &capsule_bytes).test_expect("write capsule");
    add_disclosure_crypto_context_report(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with mismatched crypto context unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("crypto context report ref mismatch"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_projection_manifest_ref_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    let capsule_path = bundle_dir.join("capsule.json");
    let mut capsule: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&capsule_path).test_expect("read capsule"))
            .test_expect("parse capsule");
    capsule["projection_manifest_ref"] =
        serde_json::Value::String("chio.bbs-projection.other.v1".to_string());
    write_json(&capsule_path, &capsule);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "capsule.json");

    let report_path = bundle_dir.join("crypto-context-report.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read crypto report"))
            .test_expect("parse crypto report");
    report["projection_manifest_ref"] =
        serde_json::Value::String("chio.bbs-projection.other.v1".to_string());
    sign_disclosure_crypto_context_report(&mut report);
    write_json(&report_path, &report);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "crypto-context-report.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with mismatched projection manifest unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("disclosure crypto report projection manifest ref mismatch"));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_wholesale_only_projection_slot() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    add_disclosure_bbs_projection_manifest(
        &bundle_dir,
        serde_json::json!([
            {
                "slot": 0,
                "field": "capability_id",
                "message_class": "capability_identifier",
                "sensitivity_class": "capability_identifier",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": false
            },
            {
                "slot": 1,
                "field": "tool_name",
                "message_class": "tool_identity",
                "sensitivity_class": "tool_identity",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": true
            }
        ]),
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with wholesale-only disclosed BBS slot unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("BBS projection manifest wholesale-only slot disclosed"));
}

#[test]
fn proof_verify_rejects_disclosure_hidden_predicate_manifest_field_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    add_disclosure_bbs_projection_manifest(
        &bundle_dir,
        serde_json::json!([
            {
                "slot": 0,
                "field": "capability_id",
                "message_class": "capability_identifier",
                "sensitivity_class": "capability_identifier",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": false
            },
            {
                "slot": 1,
                "field": "tool_name",
                "message_class": "tool_identity",
                "sensitivity_class": "tool_identity",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": false
            }
        ]),
    );
    let manifest_path = bundle_dir.join("bbs-projection-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("parse manifest");
    manifest["hidden_predicates"][0]["field"] = serde_json::json!("raw_amount");
    write_json(&manifest_path, &manifest);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "bbs-projection-manifest.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with hidden predicate manifest field mismatch unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("hidden predicate field mismatch with projection manifest"));
}

#[test]
fn proof_verify_rejects_disclosure_hidden_predicate_manifest_operator_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);

    add_disclosure_bbs_projection_manifest(
        &bundle_dir,
        serde_json::json!([
            {
                "slot": 0,
                "field": "capability_id",
                "message_class": "capability_identifier",
                "sensitivity_class": "capability_identifier",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": false
            },
            {
                "slot": 1,
                "field": "tool_name",
                "message_class": "tool_identity",
                "sensitivity_class": "tool_identity",
                "encoding": "S",
                "disclosure": "disclosed",
                "wholesale_only": false
            }
        ]),
    );
    let manifest_path = bundle_dir.join("bbs-projection-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("parse manifest");
    manifest["hidden_predicates"][0]["operator"] = serde_json::json!(">=");
    write_json(&manifest_path, &manifest);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "bbs-projection-manifest.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with hidden predicate manifest operator mismatch unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("hidden predicate operator mismatch with projection manifest"));
}

#[test]
fn proof_verify_rejects_disclosure_hidden_predicate_projection_slot_field_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_valid_disclosure_selective_disclosure_proof(&bundle_dir);

    let manifest_path = bundle_dir.join("bbs-projection-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("parse manifest");
    manifest["message_slots"][2]["field"] = serde_json::json!("raw_amount");
    write_json(&manifest_path, &manifest);
    refresh_minimal_evidence_graph_node_digest(&bundle_dir, "bbs-projection-manifest.json");

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with hidden predicate projection slot mismatch unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("hidden predicate projection slot field mismatch with projection manifest")
    );
}

#[test]
fn proof_verify_rejects_disclosure_lineage_bad_transparency_inclusion_root() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_bad_disclosure_transparency_inclusion_proof(&bundle_dir);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "disclosure lineage with bad transparency inclusion root unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("transparency inclusion proof root mismatch"));
}

#[test]
fn proof_verify_rejects_policy_digest_mismatch_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("invalid-policy-digest-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("verifier policy digest mismatch"));
    assert!(stderr.contains("urn:chio:error:transaction:passport-hash-mismatch"));
    assert!(stderr.contains("CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH"));
    assert!(!stderr.contains("urn:chio:error:cli:other"));
}

#[cfg(unix)]
#[test]
fn proof_verify_rejects_symlink_escape_artifact() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let bundle_dir = tempdir.path().join("bundle");
    let outside_dir = tempdir.path().join("outside");
    std::fs::create_dir_all(&bundle_dir).test_expect("create bundle dir");
    std::fs::create_dir_all(&outside_dir).test_expect("create outside dir");

    let outside_evidence = outside_dir.join("evidence-graph.json");
    let evidence_graph = r#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-symlink-escape","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"verifier-policy","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"}],"edges":[]}"#;
    let verifier_policy = r#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-symlink-escape","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#;
    write_file(&outside_evidence, evidence_graph);
    write_file(&bundle_dir.join("verifier-policy.json"), verifier_policy);
    std::os::unix::fs::symlink(&outside_evidence, bundle_dir.join("evidence-graph.json"))
        .test_expect("create symlink");

    let claim_set = r#"{"schema":"chio.transaction.claim-set.v1","id":"claim-set-symlink-escape","issued_at":"2026-06-10T00:00:00Z","claims":[{"claim_id":"claim.transaction.passport_root_verified","status":"verified","required_evidence":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"evidence_refs":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"verifier_module":"chio proof verify"}]}"#;
    write_file(&bundle_dir.join("claim-set.json"), claim_set);
    let passport = format!(
        "{{\"schema\":\"chio.transaction-passport.v1\",\"id\":\"passport-symlink-escape\",\"issued_at\":\"2026-06-10T00:00:00Z\",\"evidence_graph_sha256\":\"{}\",\"evidence_graph_path\":\"evidence-graph.json\",\"claim_set_sha256\":\"{}\",\"claim_set_path\":\"claim-set.json\",\"verifier_policy_sha256\":\"{}\",\"verifier_policy_path\":\"verifier-policy.json\"}}",
        chio_core::sha256_hex(evidence_graph.as_bytes()),
        chio_core::sha256_hex(claim_set.as_bytes()),
        chio_core::sha256_hex(verifier_policy.as_bytes())
    );
    let passport_path = bundle_dir.join("transaction-passport.json");
    write_file(&passport_path, &passport);

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("artifact path escapes proof bundle"));
}

#[test]
fn proof_verify_rejects_runtime_missing_execution_lease_fixture() {
    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(runtime_fixture_path("missing-execution-lease"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing execution lease"));
}
