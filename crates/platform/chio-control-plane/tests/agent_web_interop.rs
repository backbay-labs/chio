use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use chio_control_plane::{
    agent_web::{
        verify_agent_web_interop_with_trust, AgentWebInteropBundle, AgentWebInteropReport,
        AgentWebVerifierTrust, InMemoryAgentWebReplayStore,
    },
    transaction_passport::TransactionPassport,
};
use chio_core::{
    receipt::{body::ChioReceipt, decision::ToolCallAction},
    Keypair,
};
use chio_test_support::prelude::*;
use serde_json::Value;

const STANDARD_WEBHOOKS_WEBHOOK_ID: &str = "msg_agent_web_001";
const STANDARD_WEBHOOKS_VERIFIER_SECRET: &[u8] =
    b"chio-agent-web-standard-webhooks-fixture-secret-v1";
const STANDARD_WEBHOOKS_VERIFIER_NOW: u64 = 1_770_508_860;
const STANDARD_WEBHOOKS_MAX_AGE_SECONDS: u64 = 300;
const TRANSACTION_PASSPORT_SIGNATURE_SEED: [u8; 32] = [7; 32];
const AGENT_WEB_RECEIPT_KERNEL_SIGNATURE_SEED: [u8; 32] = [18; 32];
const AGENT_WEB_SIDECAR_SIGNATURE_SEED: [u8; 32] = [17; 32];

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
        root_evidence_graph_bytes: None,
        verifier_policy_bytes,
        artifacts,
    }
}

fn agent_web_fixture_trust() -> AgentWebVerifierTrust {
    AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_secret_for(
            STANDARD_WEBHOOKS_WEBHOOK_ID,
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
        )
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_standard_webhooks_replay_store(Arc::new(InMemoryAgentWebReplayStore::new()))
        .with_trusted_receipt_kernel_keys([Keypair::from_seed(
            &AGENT_WEB_RECEIPT_KERNEL_SIGNATURE_SEED,
        )
        .public_key()])
        .with_trusted_envelope_sidecar_keys([
            Keypair::from_seed(&AGENT_WEB_SIDECAR_SIGNATURE_SEED).public_key()
        ])
}

fn transaction_passport_keypair() -> Keypair {
    Keypair::from_seed(&TRANSACTION_PASSPORT_SIGNATURE_SEED)
}

fn sign_transaction_passport(passport: &mut TransactionPassport) {
    let keypair = transaction_passport_keypair();
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = String::new();
    passport.signature =
        chio_control_plane::transaction_passport::sign_transaction_passport(passport, &keypair)
            .test_expect("transaction passport signs");
}

fn verify_agent_web_fixture(
    bundle: &AgentWebInteropBundle,
) -> Result<AgentWebInteropReport, chio_control_plane::transaction_passport::TransactionPassportError>
{
    verify_agent_web_interop_with_trust(bundle, &agent_web_fixture_trust())
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
    let previous_id = node
        .get("id")
        .and_then(Value::as_str)
        .test_expect("evidence graph node has id")
        .to_string();
    node["id"] = Value::String(updated_digest.clone());
    node["sha256"] = Value::String(updated_digest.clone());
    for edge in graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .test_expect("evidence graph has mutable edges")
    {
        if edge.get("from").and_then(Value::as_str) == Some(previous_id.as_str()) {
            edge["from"] = Value::String(updated_digest.clone());
        }
        if edge.get("to").and_then(Value::as_str) == Some(previous_id.as_str()) {
            edge["to"] = Value::String(updated_digest.clone());
        }
    }
    let updated_graph = serde_json::to_vec(&graph).test_expect("updated evidence graph serializes");
    bundle.passport.evidence_graph_sha256 = chio_core::sha256_hex(&updated_graph);
    bundle.evidence_graph_bytes = updated_graph;
    sign_transaction_passport(&mut bundle.passport);
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
    let keypair = Keypair::from_seed(&AGENT_WEB_RECEIPT_KERNEL_SIGNATURE_SEED);
    let mut body = receipt.body();
    body.content_hash = subject_digest.to_string();
    body.kernel_key = keypair.public_key();
    let mut parameters = body.action.parameters;
    parameters["content_hash"] = Value::String(subject_digest.to_string());
    let receipt_ref = parameters
        .get("agent_web_receipt_ref")
        .and_then(Value::as_str)
        .test_expect("agent web receipt action has receipt ref");
    let envelope = bundle
        .artifacts
        .values()
        .filter_map(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .find(|envelope| {
            envelope.get("schema").and_then(Value::as_str)
                == Some("chio.agent-web-proof-envelope.v2")
                && envelope
                    .get("receipt_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| {
                        refs.iter()
                            .any(|candidate| candidate.as_str() == Some(receipt_ref))
                    })
        })
        .test_expect("agent web receipt resolves to one envelope");
    for (parameter, value) in [
        ("transaction_passport_id", bundle.passport.id.as_str()),
        (
            "transaction_passport_issuer",
            bundle.passport.issuer.as_str(),
        ),
        (
            "agent_web_envelope_id",
            envelope["envelope_id"]
                .as_str()
                .test_expect("agent web envelope has id"),
        ),
        (
            "projection_manifest_sha256",
            envelope["projection_manifest_sha256"]
                .as_str()
                .test_expect("agent web envelope has projection manifest digest"),
        ),
        (
            "source_protocol",
            envelope["source_protocol"]
                .as_str()
                .test_expect("agent web envelope has source protocol"),
        ),
        (
            "source_protocol_version",
            envelope["source_protocol_version"]
                .as_str()
                .test_expect("agent web envelope has source protocol version"),
        ),
    ] {
        parameters[parameter] = Value::String(value.to_string());
    }
    body.action =
        ToolCallAction::from_parameters(parameters).test_expect("agent web receipt action hashes");
    let signed_receipt = ChioReceipt::sign(body, &keypair).test_expect("agent web receipt signs");
    let updated_receipt =
        serde_json::to_vec(&signed_receipt).test_expect("agent web receipt serializes");
    replace_agent_web_artifact(bundle, receipt_path, updated_receipt);
}

fn resign_agent_web_envelope(bundle: &mut AgentWebInteropBundle, envelope_path: &str) {
    let envelope_bytes = bundle
        .artifacts
        .get(envelope_path)
        .test_expect("agent web envelope exists");
    let mut envelope: Value =
        serde_json::from_slice(envelope_bytes).test_expect("agent web envelope parses");
    let keypair = Keypair::from_seed(&AGENT_WEB_SIDECAR_SIGNATURE_SEED);
    let public_key = keypair.public_key().to_hex();
    envelope["envelope_id"] = Value::String(agent_web_envelope_id(&envelope));
    let payload = agent_web_envelope_signature_payload(&envelope);
    let canonical =
        chio_core::canonical_json_bytes(&payload).test_expect("agent web envelope canonicalizes");
    envelope["signature"] = Value::String(format!(
        "sig-ed25519:{public_key}:{}",
        keypair.sign(&canonical).to_hex()
    ));
    replace_agent_web_artifact(
        bundle,
        envelope_path,
        serde_json::to_vec(&envelope).test_expect("agent web envelope serializes"),
    );
    let receipt_refs = envelope["receipt_refs"]
        .as_array()
        .test_expect("agent web envelope has receipt refs")
        .iter()
        .map(|receipt_ref| {
            receipt_ref
                .as_str()
                .test_expect("agent web envelope receipt ref is a string")
                .to_string()
        })
        .collect::<Vec<_>>();
    for receipt_ref in receipt_refs {
        let receipt_path = bundle
            .artifacts
            .iter()
            .find_map(|(path, bytes)| {
                let receipt: ChioReceipt = serde_json::from_slice(bytes).ok()?;
                (receipt
                    .action
                    .parameters
                    .get("agent_web_receipt_ref")
                    .and_then(Value::as_str)
                    == Some(receipt_ref.as_str()))
                .then(|| path.clone())
            })
            .test_expect("agent web envelope receipt artifact exists");
        let subject_digest = envelope["external_subject_digest"]
            .as_str()
            .test_expect("agent web envelope has subject digest");
        resign_agent_web_receipt_for_subject_digest(bundle, &receipt_path, subject_digest);
    }
}

fn rebind_agent_web_manifest_digest(bundle: &mut AgentWebInteropBundle, manifest_path: &str) {
    let manifest_bytes = bundle
        .artifacts
        .get(manifest_path)
        .test_expect("agent web manifest exists");
    let manifest: Value =
        serde_json::from_slice(manifest_bytes).test_expect("agent web manifest parses");
    let projection_id = manifest
        .get("projection_id")
        .and_then(Value::as_str)
        .test_expect("agent web manifest has projection id");
    let manifest_digest = chio_core::sha256_hex(manifest_bytes);
    let envelope_paths = bundle
        .artifacts
        .iter()
        .filter_map(|(path, bytes)| {
            if !path.ends_with("-envelope.json") {
                return None;
            }
            let envelope: Value = serde_json::from_slice(bytes).ok()?;
            if envelope
                .get("projection_manifest_ref")
                .and_then(Value::as_str)
                == Some(projection_id)
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for envelope_path in envelope_paths {
        mutate_agent_web_json_artifact(bundle, &envelope_path, |envelope| {
            envelope["projection_manifest_sha256"] = Value::String(manifest_digest.clone());
        });
        resign_agent_web_envelope(bundle, &envelope_path);
    }
}

fn agent_web_envelope_signature_payload(envelope: &Value) -> Value {
    agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "envelope_id",
            "transaction_passport_ref",
            "agent_web_passport_scope_sha256",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    )
}

fn agent_web_envelope_id(envelope: &Value) -> String {
    let payload = agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "transaction_passport_ref",
            "agent_web_passport_scope_sha256",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    );
    let canonical =
        chio_core::canonical_json_bytes(&payload).test_expect("agent web envelope canonicalizes");
    chio_core::sha256_hex(&canonical)
}

fn agent_web_envelope_payload(envelope: &Value, fields: &[&str]) -> Value {
    let object = envelope
        .as_object()
        .test_expect("agent web envelope is object");
    let mut payload = serde_json::Map::new();
    for field in fields {
        payload.insert(
            (*field).to_string(),
            object
                .get(*field)
                .unwrap_or_else(|| panic!("agent web envelope missing field: {field}"))
                .clone(),
        );
    }
    Value::Object(payload)
}

#[test]
fn control_plane_agent_web_reexport_verifies_product_fixture() {
    let bundle = agent_web_fixture_bundle();

    let report = verify_agent_web_fixture(&bundle)
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
    resign_agent_web_envelope(&mut bundle, "dsse-envelope.json");
    resign_agent_web_receipt_for_subject_digest(
        &mut bundle,
        "receipts/receipt-agent-web-dsse-envelope-allow.json",
        &external_subject_digest,
    );

    let error = verify_agent_web_fixture(&bundle)
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
    rebind_agent_web_manifest_digest(&mut bundle, manifest_path);

    let error = verify_agent_web_fixture(&bundle)
        .test_expect_err("unsupported source protocol version must fail closed");

    let error_message = error.to_string();
    assert!(
        error_message.contains(expected_message),
        "expected error containing {expected_message:?}, got {error_message:?}"
    );
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
    rebind_agent_web_manifest_digest(&mut bundle, manifest_path);

    let error = verify_agent_web_fixture(&bundle)
        .test_expect_err("unsupported source protocol version must fail closed");

    let error_message = error.to_string();
    assert!(
        error_message.contains(expected_message),
        "expected error containing {expected_message:?}, got {error_message:?}"
    );
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
    rebind_agent_web_manifest_digest(&mut bundle, "graphql-http-manifest.json");

    let error = verify_agent_web_fixture(&bundle)
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
    rebind_agent_web_manifest_digest(&mut bundle, "standard-webhooks-manifest.json");

    let error = verify_agent_web_fixture(&bundle)
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
    rebind_agent_web_manifest_digest(&mut bundle, "mcp-manifest.json");

    let error = verify_agent_web_fixture(&bundle)
        .test_expect_err("unsupported external authority claim must not be native proof");

    assert!(error.to_string().contains(
        "unsupported external authority claim cannot be mapped as native external proof"
    ));
}
