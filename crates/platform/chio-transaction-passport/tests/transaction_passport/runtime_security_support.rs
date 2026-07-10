use super::{sha256_hex, workspace_root};
use chio_core_types::crypto::Keypair;
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) fn load_runtime_security_fixture(
    case_name: &str,
) -> chio_transaction_passport::RuntimeSecurityBundle {
    let dir = runtime_security_fixture_dir(case_name);
    let passport = serde_json::from_slice(&read_fixture_file(&dir, "transaction-passport.json"))
        .test_expect("runtime security passport parses");
    let evidence_graph_bytes = read_fixture_file(&dir, "evidence-graph.json");
    let verifier_policy_bytes = read_fixture_file(&dir, "verifier-policy.json");
    let mut artifacts = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).test_expect("runtime security fixture dir reads") {
        let entry = entry.test_expect("runtime security fixture entry reads");
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let relative_path = path
            .file_name()
            .and_then(|name| name.to_str())
            .test_expect("runtime security fixture path is utf8");
        if matches!(
            relative_path,
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        artifacts.insert(
            relative_path.to_string(),
            read_fixture_file(&dir, relative_path),
        );
    }

    chio_transaction_passport::RuntimeSecurityBundle {
        passport,
        evidence_graph_bytes,
        root_evidence_graph_bytes: None,
        verifier_policy_bytes,
        artifacts,
    }
}

fn runtime_security_fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/runtime-security/{case_name}"))
}

fn read_fixture_file(dir: &Path, relative_path: &str) -> Vec<u8> {
    std::fs::read(dir.join(relative_path)).test_expect("runtime security fixture file reads")
}

pub(super) fn rebind_runtime_graph(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    graph: Value,
) {
    let graph_bytes = serde_json::to_vec(&graph).test_expect("runtime graph serializes");
    bundle.passport.evidence_graph_sha256 = sha256_hex(&graph_bytes);
    bundle.evidence_graph_bytes = graph_bytes;
    resign_runtime_passport(bundle);
}

fn resign_runtime_passport(bundle: &mut chio_transaction_passport::RuntimeSecurityBundle) {
    let signing_key = Keypair::from_seed(&[7u8; 32]);
    bundle.passport.signature =
        chio_transaction_passport::sign_transaction_passport(&bundle.passport, &signing_key)
            .test_expect("runtime passport signs");
}

pub(super) fn update_runtime_graph_node_digest(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    artifact_path: &str,
    digest: &str,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    let nodes = graph["nodes"]
        .as_array_mut()
        .test_expect("runtime graph has nodes");
    for node in nodes {
        if node["path"] == artifact_path {
            let old_id = node["id"]
                .as_str()
                .test_expect("runtime graph node id")
                .to_string();
            node["id"] = Value::String(digest.to_string());
            node["sha256"] = Value::String(digest.to_string());
            for edge in graph["edges"]
                .as_array_mut()
                .test_expect("runtime graph has edges")
            {
                if edge["from"] == old_id {
                    edge["from"] = Value::String(digest.to_string());
                }
                if edge["to"] == old_id {
                    edge["to"] = Value::String(digest.to_string());
                }
            }
            rebind_runtime_graph(bundle, graph);
            return;
        }
    }
    panic!("runtime graph node exists for {artifact_path}");
}

pub(super) fn remove_runtime_graph_nodes_by_role(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    role: &str,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    let nodes = graph["nodes"]
        .as_array_mut()
        .test_expect("runtime graph has nodes");
    let removed_ids = nodes
        .iter()
        .filter(|node| node["role"] == role)
        .map(|node| {
            node["id"]
                .as_str()
                .test_expect("runtime graph node id")
                .to_string()
        })
        .collect::<Vec<_>>();
    nodes.retain(|node| node["role"] != role);
    graph["edges"]
        .as_array_mut()
        .test_expect("runtime graph has edges")
        .retain(|edge| {
            let from = edge["from"].as_str().unwrap_or_default();
            let to = edge["to"].as_str().unwrap_or_default();
            !removed_ids.iter().any(|id| id == from || id == to)
        });
    rebind_runtime_graph(bundle, graph);
}

pub(super) fn runtime_graph_node_id(
    bundle: &chio_transaction_passport::RuntimeSecurityBundle,
    path: &str,
) -> String {
    let graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    graph["nodes"]
        .as_array()
        .test_expect("runtime graph has nodes")
        .iter()
        .find(|node| node["path"] == path)
        .and_then(|node| node["id"].as_str())
        .test_expect("runtime graph node id")
        .to_string()
}

pub(super) fn update_runtime_policy_required_claims(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    required_claims: Vec<&str>,
) {
    let mut policy: Value =
        serde_json::from_slice(&bundle.verifier_policy_bytes).test_expect("runtime policy parses");
    let required_claims: Vec<String> = required_claims
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect();
    policy["required_claims"] = Value::Array(
        required_claims
            .iter()
            .map(|claim| Value::String(claim.clone()))
            .collect(),
    );
    let policy_bytes = serde_json::to_vec_pretty(&policy).test_expect("runtime policy serializes");
    let policy_digest = sha256_hex(&policy_bytes);
    bundle.passport.verifier_policy_sha256 = policy_digest.clone();
    bundle.verifier_policy_bytes = policy_bytes;
    update_runtime_claim_set_required_claims(bundle, &required_claims);
    update_runtime_graph_node_digest(bundle, "verifier-policy.json", &policy_digest);
}

fn update_runtime_claim_set_required_claims(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    required_claims: &[String],
) {
    let claims: Vec<Value> = required_claims
        .iter()
        .map(|claim| {
            json!({
                "claim_id": claim,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio proof verify"
            })
        })
        .collect();
    let claim_set = json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-runtime-passport-valid",
        "issued_at": bundle.passport.issued_at.clone(),
        "claims": claims
    });
    let claim_set_bytes =
        serde_json::to_vec_pretty(&claim_set).test_expect("runtime claim set serializes");
    let claim_set_digest = sha256_hex(&claim_set_bytes);
    bundle
        .artifacts
        .insert("claim-set.json".to_string(), claim_set_bytes);
    bundle.passport.claim_set_sha256 = claim_set_digest.clone();
    update_runtime_graph_node_digest(bundle, "claim-set.json", &claim_set_digest);
}

pub(super) fn update_runtime_artifact(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    artifact_path: &str,
    update: impl FnOnce(&mut Value),
) {
    let artifact_bytes = bundle
        .artifacts
        .get(artifact_path)
        .test_expect("runtime artifact exists")
        .clone();
    let mut artifact: Value =
        serde_json::from_slice(&artifact_bytes).test_expect("runtime artifact parses");
    update(&mut artifact);
    let artifact_bytes =
        serde_json::to_vec_pretty(&artifact).test_expect("runtime artifact serializes");
    let artifact_digest = sha256_hex(&artifact_bytes);
    bundle
        .artifacts
        .insert(artifact_path.to_string(), artifact_bytes);
    update_runtime_graph_node_digest(bundle, artifact_path, &artifact_digest);
}

pub(super) fn sign_runtime_lease_with_fixture_authority(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_runtime_execution_lease(value, &signing_key));
}

pub(super) fn sign_runtime_execution_lease(value: &Value, signing_key: &Keypair) -> String {
    let mut body = json!({
        "schema": "chio.runtime.execution-lease-signature.v1",
        "leaseId": value["lease_id"],
        "subjectAgent": value["subject_agent"],
        "toolServerId": value["tool_server_id"],
        "toolInstanceId": value["tool_instance_id"],
        "toolManifestDigest": value["tool_manifest_digest"],
        "sandboxAttestationRef": value["sandbox_attestation_ref"],
        "capabilityDigest": value["capability_digest"],
        "requestDigest": value["request_digest"],
        "responsePolicyDigest": value["response_policy_digest"],
        "taskGraphDigest": value["task_graph_digest"],
        "childTaskId": value["child_task_id"],
        "parentReceiptRef": value["parent_receipt_ref"],
        "joinReceiptRef": value["join_receipt_ref"],
        "budgetPoolRef": value["budget_pool_ref"],
        "budgetAllocationRef": value["budget_allocation_ref"],
        "subjectCapabilityDigest": value["subject_capability_digest"],
        "ancestorCapabilityDigest": value["ancestor_capability_digest"],
        "revocationFreshnessRef": value["revocation_freshness_ref"],
        "policyDigest": value["policy_digest"],
        "nonce": value["nonce"],
        "sideEffectClass": value["side_effect_class"],
        "issuedAt": value["issued_at"],
        "expiresAt": value["expires_at"],
        "issuer": value["issuer"],
    });
    if value.get("revocation_epoch_ref").is_some() {
        body["revocationEpochRef"] = value["revocation_epoch_ref"].clone();
    }
    if value.get("route_plan_receipt_ref").is_some() {
        body["routePlanReceiptRef"] = value["route_plan_receipt_ref"].clone();
    }
    if value.get("max_invocations").is_some() {
        body["maxInvocations"] = value["max_invocations"].clone();
    }
    signing_key
        .sign_canonical(&body)
        .test_expect("execution lease signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_route_plan_with_fixture_authority(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_runtime_route_plan(value, &signing_key));
}

fn sign_runtime_route_plan(value: &Value, signing_key: &Keypair) -> String {
    let body = json!({
        "schema": "chio.swarm.route-plan-receipt-signature.v1",
        "routePlanId": value["routePlanId"],
        "graphId": value["graphId"],
        "taskId": value["taskId"],
        "selectedRoute": value["selectedRoute"],
        "candidateSetDigest": value["candidateSetDigest"],
        "registrySnapshotHash": value["registrySnapshotHash"],
        "bridgeId": value["bridgeId"],
        "protocolTarget": value["protocolTarget"],
        "egressContractId": value["egressContractId"],
        "egressConstraints": value["egressConstraints"],
        "attenuationDecision": value["attenuationDecision"],
        "policyDigest": value["policyDigest"],
        "expiresAtUnixMs": value["expiresAtUnixMs"],
        "issuer": value["issuer"],
    });
    signing_key
        .sign_canonical(&body)
        .test_expect("runtime route plan signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_join_receipt_with_fixture_authority(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_runtime_join_receipt(value, &signing_key));
}

pub(super) fn sign_runtime_join_receipt(value: &Value, signing_key: &Keypair) -> String {
    let mut body = value.clone();
    body.as_object_mut()
        .test_expect("runtime join receipt is object")
        .remove("signature");
    signing_key
        .sign_canonical(&body)
        .test_expect("runtime join receipt signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_trusted_time_with_fixture_authority(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_runtime_trusted_time(value, &signing_key));
}

pub(super) fn sign_runtime_trusted_time(value: &Value, signing_key: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.trusted-time-proof-signature.v1",
        "proofId": value["proof_id"],
        "leaseId": value["lease_id"],
        "ackId": value["ack_id"],
        "observedAt": value["observed_at"],
        "maxClockSkewMs": value["max_clock_skew_ms"],
        "timeSourceId": value["time_source_id"],
        "issuer": value["issuer"],
    });
    signing_key
        .sign_canonical(&body)
        .test_expect("runtime trusted time proof signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_revocation_freshness_with_fixture_oracle(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[43u8; 32]);
    value["oracle_id"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_runtime_revocation_freshness(value, &signing_key));
}

fn sign_runtime_revocation_freshness(value: &Value, signing_key: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.revocation-freshness-proof-signature.v1",
        "proofId": value["proof_id"],
        "oracleId": value["oracle_id"],
        "epochId": value["epoch_id"],
        "epochRoot": value["epoch_root"],
        "sequence": value["sequence"],
        "fetchedAt": value["fetched_at"],
        "maxStalenessMs": value["max_staleness_ms"],
        "subjectCapabilityDigest": value["subject_capability_digest"],
        "ancestorCapabilityDigest": value["ancestor_capability_digest"],
        "revokedLeafResult": value["revoked_leaf_result"],
        "revokedAncestorResult": value["revoked_ancestor_result"],
    });
    signing_key
        .sign_canonical(&body)
        .test_expect("revocation freshness proof signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_terminal_receipt_with_fixture_kernel(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[23u8; 32]);
    value["kernel_key"] = Value::String(signing_key.public_key().to_hex());
    value["signature"] = Value::String(sign_runtime_terminal_receipt(value, &signing_key));
}

fn sign_runtime_terminal_receipt(value: &Value, signing_key: &Keypair) -> String {
    let mut body = json!({
        "schema": "chio.runtime.terminal-receipt-signature.v1",
        "receiptId": value["receipt_id"],
        "terminalStatus": value["terminal_status"],
        "policyDigest": value["policy_digest"],
        "kernelKey": value["kernel_key"],
    });
    if value.get("execution_lease_ref").is_some() {
        body["executionLeaseRef"] = value["execution_lease_ref"].clone();
    }
    if value.get("incident_ref").is_some() {
        body["incidentRef"] = value["incident_ref"].clone();
    }
    signing_key
        .sign_canonical(&body)
        .test_expect("terminal receipt signs")
        .0
        .to_hex()
}

pub(super) fn sign_runtime_trust_root(value: &Value, signing_key: &Keypair) -> String {
    let mut body = value.clone();
    body.as_object_mut()
        .test_expect("runtime trust root is an object")
        .remove("signature");
    signing_key
        .sign_canonical(&body)
        .test_expect("runtime trust root signs")
        .0
        .to_hex()
}

pub(super) fn runtime_trusted_root_keys() -> Vec<chio_core_types::PublicKey> {
    vec![Keypair::from_seed(&[46u8; 32]).public_key()]
}

pub(super) fn transaction_trusted_root_keys() -> Vec<chio_core_types::PublicKey> {
    vec![Keypair::from_seed(&[7u8; 32]).public_key()]
}

pub(super) fn verify_runtime_security_fixture(
    bundle: &chio_transaction_passport::RuntimeSecurityBundle,
) -> Result<
    chio_transaction_passport::RuntimeSecurityReport,
    chio_transaction_passport::TransactionPassportError,
> {
    chio_transaction_passport::verify_runtime_security_claims_with_trust(
        bundle,
        &chio_transaction_passport::RuntimeSecurityTrust {
            trusted_passport_signer_keys: transaction_trusted_root_keys(),
            trusted_root_signer_keys: runtime_trusted_root_keys(),
        },
    )
}

pub(super) fn add_unavailable_runtime_receipt_node(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("runtime graph has nodes")
        .push(json!({
            "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "schema": "chio.runtime.terminal-receipt.v1",
            "path": "missing-denial-receipt.json",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "role": "receipt"
        }));
    rebind_runtime_graph(bundle, graph);
}
