use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use chio_control_plane::{
    agent_web::{verify_agent_web_interop, AgentWebInteropBundle},
    transaction_passport::TransactionPassport,
};
use chio_core::{
    receipt::{body::ChioReceipt, decision::ToolCallAction},
    Keypair,
};
use chio_test_support::prelude::*;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .test_expect("workspace root resolves")
}

fn read_fixture_bytes(root: &Path, relative_path: &str) -> Vec<u8> {
    fs::read(root.join(relative_path)).test_expect("fixture artifact reads")
}

fn agent_web_fixture_bundle() -> AgentWebInteropBundle {
    let fixture_root =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let passport_bytes = read_fixture_bytes(&fixture_root, "transaction-passport.json");
    let evidence_graph_bytes = read_fixture_bytes(&fixture_root, "evidence-graph.json");
    let verifier_policy_bytes = read_fixture_bytes(&fixture_root, "verifier-policy.json");
    let passport: TransactionPassport =
        serde_json::from_slice(&passport_bytes).test_expect("passport parses");

    let evidence_graph: Value =
        serde_json::from_slice(&evidence_graph_bytes).test_expect("evidence graph parses");
    let nodes = evidence_graph
        .get("nodes")
        .and_then(Value::as_array)
        .test_expect("evidence graph has nodes");
    let mut artifacts = BTreeMap::new();
    for node in nodes {
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .test_expect("evidence graph node has path");
        artifacts.insert(path.to_string(), read_fixture_bytes(&fixture_root, path));
    }

    AgentWebInteropBundle {
        passport,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
    }
}

fn mutate_agent_web_json_artifact(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    mutate: impl FnOnce(&mut Value),
) -> String {
    let bytes = bundle
        .artifacts
        .get(relative_path)
        .test_expect("fixture artifact exists");
    let mut artifact: Value =
        serde_json::from_slice(bytes).test_expect("fixture artifact parses as JSON");
    mutate(&mut artifact);
    let updated_artifact =
        serde_json::to_vec(&artifact).test_expect("updated fixture artifact serializes");
    replace_agent_web_artifact(bundle, relative_path, updated_artifact)
}

fn replace_agent_web_artifact(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    updated_artifact: Vec<u8>,
) -> String {
    let updated_digest = chio_core::sha256_hex(&updated_artifact);
    bundle
        .artifacts
        .insert(relative_path.to_string(), updated_artifact);
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("evidence graph parses");
    let nodes = graph
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .test_expect("evidence graph has mutable nodes");
    let node = nodes
        .iter_mut()
        .find(|node| node.get("path").and_then(Value::as_str) == Some(relative_path))
        .test_expect("evidence graph contains mutated artifact node");
    node["sha256"] = Value::String(updated_digest.clone());
    let updated_graph = serde_json::to_vec(&graph).test_expect("updated evidence graph serializes");
    bundle.passport.evidence_graph_sha256 = chio_core::sha256_hex(&updated_graph);
    bundle.evidence_graph_bytes = updated_graph;
    updated_digest
}

fn resign_agent_web_receipt_for_subject_digest(
    bundle: &mut AgentWebInteropBundle,
    receipt_path: &str,
    subject_digest: &str,
) {
    let receipt_bytes = bundle
        .artifacts
        .get(receipt_path)
        .test_expect("agent web receipt exists");
    let receipt: ChioReceipt =
        serde_json::from_slice(receipt_bytes).test_expect("agent web receipt parses");
    let keypair = Keypair::generate();
    let mut body = receipt.body();
    body.content_hash = subject_digest.to_string();
    body.kernel_key = keypair.public_key();
    let mut parameters = body.action.parameters;
    parameters["content_hash"] = Value::String(subject_digest.to_string());
    body.action =
        ToolCallAction::from_parameters(parameters).test_expect("agent web receipt action hashes");
    let signed_receipt = ChioReceipt::sign(body, &keypair).test_expect("agent web receipt signs");
    let updated_receipt =
        serde_json::to_vec(&signed_receipt).test_expect("agent web receipt serializes");
    replace_agent_web_artifact(bundle, receipt_path, updated_receipt);
}

#[test]
fn control_plane_agent_web_reexport_verifies_product_fixture() {
    let bundle = agent_web_fixture_bundle();

    let report = verify_agent_web_interop(&bundle)
        .test_expect("control-plane Agent Web re-export verifies product fixture");

    assert_eq!(report.verdict, "verified");
    assert_eq!(report.passport_id, "passport-agent-web-valid");
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "standard-webhooks"));
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "sd-jwt-vc"));
    assert!(report
        .unsupported_claims
        .contains(&"claim.external.sd_jwt_vc_is_chio_authority".to_string()));
}

#[test]
fn agent_web_rejects_dsse_subject_without_chio_receipt_mediation() {
    let mut bundle = agent_web_fixture_bundle();
    let external_subject_digest =
        mutate_agent_web_json_artifact(&mut bundle, "external/dsse-envelope.json", |subject| {
            subject["mediated_by_chio_receipt"] = Value::Bool(false);
        });
    mutate_agent_web_json_artifact(&mut bundle, "dsse-envelope.json", |envelope| {
        envelope["external_subject_digest"] = Value::String(external_subject_digest.clone());
    });
    resign_agent_web_receipt_for_subject_digest(
        &mut bundle,
        "receipts/receipt-agent-web-dsse-envelope-allow.json",
        &external_subject_digest,
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("DSSE subject without Chio mediation must fail closed");

    assert!(error
        .to_string()
        .contains("DSSE envelope was not mediated by Chio receipt"));
}

fn assert_agent_web_rejects_unsupported_source_protocol_version(
    manifest_path: &str,
    envelope_path: &str,
    expected_message: &str,
) {
    assert_agent_web_rejects_unsupported_manifest_version(
        manifest_path,
        envelope_path,
        "future-unreviewed",
        expected_message,
    );
}

fn assert_agent_web_rejects_unsupported_manifest_version(
    manifest_path: &str,
    envelope_path: &str,
    unsupported_version: &str,
    expected_message: &str,
) {
    let mut bundle = agent_web_fixture_bundle();
    mutate_agent_web_json_artifact(&mut bundle, manifest_path, |manifest| {
        manifest["source_version"] = Value::String(unsupported_version.to_string());
    });
    mutate_agent_web_json_artifact(&mut bundle, envelope_path, |envelope| {
        envelope["source_protocol_version"] = Value::String(unsupported_version.to_string());
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("unsupported source protocol version must fail closed");

    assert!(error.to_string().contains(expected_message));
}

fn assert_agent_web_rejects_unsupported_protocol_field_version(
    manifest_path: &str,
    envelope_path: &str,
    receipt_path: &str,
    expected_message: &str,
) {
    let mut bundle = agent_web_fixture_bundle();
    let envelope_bytes = bundle
        .artifacts
        .get(envelope_path)
        .test_expect("agent web envelope exists");
    let envelope: Value =
        serde_json::from_slice(envelope_bytes).test_expect("agent web envelope parses");
    let subject_path = envelope["external_subject_path"]
        .as_str()
        .test_expect("agent web envelope has external subject path")
        .to_string();

    mutate_agent_web_json_artifact(&mut bundle, manifest_path, |manifest| {
        manifest["source_version"] = Value::String("future-unreviewed".to_string());
    });
    let external_subject_digest =
        mutate_agent_web_json_artifact(&mut bundle, &subject_path, |subject| {
            subject["protocol_version"] = Value::String("future-unreviewed".to_string());
        });
    mutate_agent_web_json_artifact(&mut bundle, envelope_path, |envelope| {
        envelope["source_protocol_version"] = Value::String("future-unreviewed".to_string());
        envelope["external_subject_digest"] = Value::String(external_subject_digest.clone());
    });
    resign_agent_web_receipt_for_subject_digest(
        &mut bundle,
        receipt_path,
        &external_subject_digest,
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("unsupported source protocol version must fail closed");

    assert!(error.to_string().contains(expected_message));
}

#[test]
fn agent_web_rejects_unsupported_payment_protocol_versions() {
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "ap2-manifest.json",
        "ap2-envelope.json",
        "unsupported AP2 source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "x402-manifest.json",
        "x402-envelope.json",
        "unsupported x402 source version",
    );
}

#[test]
fn agent_web_rejects_unsupported_supply_chain_protocol_versions() {
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "bbs-manifest.json",
        "bbs-envelope.json",
        "unsupported BBS source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "sd-jwt-vc-manifest.json",
        "sd-jwt-vc-envelope.json",
        "unsupported SD-JWT VC source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "sigstore-manifest.json",
        "sigstore-envelope.json",
        "unsupported Sigstore source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "in-toto-manifest.json",
        "in-toto-envelope.json",
        "unsupported in-toto source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "slsa-manifest.json",
        "slsa-envelope.json",
        "unsupported SLSA source version",
    );
}

#[test]
fn agent_web_rejects_unsupported_core_protocol_versions() {
    assert_agent_web_rejects_unsupported_protocol_field_version(
        "mcp-manifest.json",
        "mcp-envelope.json",
        "receipts/receipt-agent-web-mcp-tool-call-allow.json",
        "unsupported MCP source version",
    );
    assert_agent_web_rejects_unsupported_protocol_field_version(
        "a2a-manifest.json",
        "a2a-envelope.json",
        "receipts/receipt-agent-web-a2a-task-allow.json",
        "unsupported A2A source version",
    );
    assert_agent_web_rejects_unsupported_protocol_field_version(
        "acp-client-manifest.json",
        "acp-client-envelope.json",
        "receipts/receipt-agent-web-acp-client-permission-allow.json",
        "unsupported ACP-Client source version",
    );
    assert_agent_web_rejects_unsupported_protocol_field_version(
        "ag-ui-manifest.json",
        "ag-ui-envelope.json",
        "receipts/receipt-agent-web-ag-ui-event-allow.json",
        "unsupported AG-UI source version",
    );
}

#[test]
fn agent_web_rejects_unsupported_operational_protocol_versions() {
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "standard-webhooks-manifest.json",
        "standard-webhooks-envelope.json",
        "unsupported Standard Webhooks source version",
    );
    assert_agent_web_rejects_unsupported_manifest_version(
        "cloudevents-manifest.json",
        "cloudevents-envelope.json",
        "1.0-future",
        "unsupported CloudEvents source version",
    );
    assert_agent_web_rejects_unsupported_source_protocol_version(
        "acp-commerce-manifest.json",
        "acp-commerce-envelope.json",
        "unsupported ACP-Commerce source version",
    );
    assert_agent_web_rejects_unsupported_manifest_version(
        "browser-automation-manifest.json",
        "browser-automation-envelope.json",
        "webdriver-bidi-future-unreviewed",
        "unsupported browser automation source version",
    );
    assert_agent_web_rejects_unsupported_manifest_version(
        "rpa-manifest.json",
        "rpa-envelope.json",
        "uia-future-unreviewed",
        "unsupported RPA source version",
    );
}

#[test]
fn agent_web_rejects_graphql_http_without_authority_limitation() {
    let mut bundle = agent_web_fixture_bundle();
    mutate_agent_web_json_artifact(&mut bundle, "graphql-http-manifest.json", |manifest| {
        let unsupported_claims = manifest["unsupported_claims"]
            .as_array_mut()
            .test_expect("GraphQL manifest has unsupported claims");
        unsupported_claims.retain(|claim| {
            claim.as_str() != Some("claim.external.graphql_http_operation_is_chio_authority")
        });
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL HTTP projection without authority limitation must fail closed");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.graphql_http_operation_is_chio_authority"
    ));
}

#[test]
fn agent_web_rejects_standard_webhooks_manifest_that_disables_required_signature() {
    let mut bundle = agent_web_fixture_bundle();
    mutate_agent_web_json_artifact(&mut bundle, "standard-webhooks-manifest.json", |manifest| {
        manifest["requires_external_signature"] = Value::Bool(false);
        manifest["signature_algorithm"] = Value::String("none".to_string());
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks manifest must declare its external signature");

    assert!(error
        .to_string()
        .contains("Standard Webhooks projection requires external signature"));
}

#[test]
fn agent_web_rejects_unsupported_external_authority_claim_marked_native() {
    let mut bundle = agent_web_fixture_bundle();
    mutate_agent_web_json_artifact(&mut bundle, "mcp-manifest.json", |manifest| {
        let claim_mapping = manifest["claim_mapping"]
            .as_array_mut()
            .test_expect("MCP manifest has claim mappings");
        claim_mapping.push(serde_json::json!({
            "claim_ref": "claim.external.mcp_tool_call_is_chio_authority",
            "evidence_class": "native-external-proof"
        }));
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("unsupported external authority claim must not be native proof");

    assert!(error.to_string().contains(
        "unsupported external authority claim cannot be mapped as native external proof"
    ));
}
