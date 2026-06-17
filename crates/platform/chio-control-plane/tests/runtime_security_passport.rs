use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chio_core::sha256_hex;
use chio_core::Keypair;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .and_then(|workspace| workspace.parent())
        .test_expect("workspace root is parent of crates/platform/chio-control-plane")
        .to_path_buf()
}

fn fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/runtime-security/{case_name}"))
}

fn read_file(dir: &Path, relative_path: &str) -> Vec<u8> {
    std::fs::read(dir.join(relative_path)).test_expect("fixture file reads")
}

fn read_runtime_negative_case(case_name: &str) -> Value {
    let path = fixture_dir("negatives").join(format!("{case_name}.json"));
    let bytes = std::fs::read(path).test_expect("negative case fixture reads");
    serde_json::from_slice(&bytes).test_expect("negative case fixture parses")
}

fn expected_failure(case: &Value) -> &str {
    case["expected_failure_code"]
        .as_str()
        .test_expect("negative case has expected failure code")
}

fn load_runtime_security_fixture(
    case_name: &str,
) -> chio_control_plane::transaction_passport::RuntimeSecurityBundle {
    let dir = fixture_dir(case_name);
    let passport_bytes = read_file(&dir, "transaction-passport.json");
    let passport = serde_json::from_slice(&passport_bytes).test_expect("passport parses");
    let evidence_graph_bytes = read_file(&dir, "evidence-graph.json");
    let verifier_policy_bytes = read_file(&dir, "verifier-policy.json");
    let mut artifacts = BTreeMap::new();
    for artifact_path in [
        "allow-receipt.json",
        "execution-lease.json",
        "trust-root.json",
        "revocation-freshness-proof.json",
        "sandbox-attestation.json",
        "tool-server-ack.json",
    ] {
        let path = dir.join(artifact_path);
        if path.is_file() {
            artifacts.insert(artifact_path.to_string(), read_file(&dir, artifact_path));
        }
    }

    chio_control_plane::transaction_passport::RuntimeSecurityBundle {
        passport,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
    }
}

fn rebind_graph(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    graph: Value,
) {
    let graph_bytes = serde_json::to_vec_pretty(&graph).test_expect("graph serializes");
    bundle.passport.evidence_graph_sha256 = sha256_hex(&graph_bytes);
    bundle.evidence_graph_bytes = graph_bytes;
}

fn rebind_policy(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    policy: Value,
) {
    let policy_bytes = serde_json::to_vec_pretty(&policy).test_expect("policy serializes");
    let policy_digest = sha256_hex(&policy_bytes);
    bundle.passport.verifier_policy_sha256 = policy_digest.clone();
    bundle.verifier_policy_bytes = policy_bytes;
    update_graph_node_digest(bundle, "verifier-policy.json", &policy_digest);
}

fn update_policy_required_claims(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    required_claims: Vec<&str>,
) {
    let mut policy: Value =
        serde_json::from_slice(&bundle.verifier_policy_bytes).test_expect("policy parses");
    policy["required_claims"] = Value::Array(
        required_claims
            .into_iter()
            .map(|claim| Value::String(claim.to_string()))
            .collect(),
    );
    rebind_policy(bundle, policy);
}

fn update_artifact(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    artifact_path: &str,
    update: impl FnOnce(&mut Value),
) {
    let artifact_bytes = bundle
        .artifacts
        .get(artifact_path)
        .test_expect("artifact exists")
        .clone();
    let mut artifact: Value =
        serde_json::from_slice(&artifact_bytes).test_expect("artifact parses");
    update(&mut artifact);
    let updated_bytes = serde_json::to_vec_pretty(&artifact).test_expect("artifact serializes");
    let updated_digest = sha256_hex(&updated_bytes);
    bundle
        .artifacts
        .insert(artifact_path.to_string(), updated_bytes);
    update_graph_node_digest(bundle, artifact_path, &updated_digest);
}

fn update_graph_node_digest(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    artifact_path: &str,
    digest: &str,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    for node in nodes {
        if node["path"] == artifact_path {
            node["sha256"] = Value::String(digest.to_string());
            rebind_graph(bundle, graph);
            return;
        }
    }
    panic!("graph node exists for {artifact_path}");
}

fn update_graph_node_schema(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    artifact_path: &str,
    schema: &str,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    for node in nodes {
        if node["path"] == artifact_path {
            node["schema"] = Value::String(schema.to_string());
            rebind_graph(bundle, graph);
            return;
        }
    }
    panic!("graph node exists for {artifact_path}");
}

fn add_runtime_ack_replay(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
) {
    let ack_bytes = bundle
        .artifacts
        .get("tool-server-ack.json")
        .test_expect("ack artifact exists")
        .clone();
    let mut ack: Value = serde_json::from_slice(&ack_bytes).test_expect("ack parses");
    ack["ack_id"] = Value::String("ack-runtime-replay".to_string());
    let replay_bytes = serde_json::to_vec_pretty(&ack).test_expect("ack serializes");
    let replay_digest = sha256_hex(&replay_bytes);
    bundle
        .artifacts
        .insert("tool-server-ack-replay.json".to_string(), replay_bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": "ack-runtime-replay",
            "schema": "chio.runtime.tool-server-ack.v1",
            "path": "tool-server-ack-replay.json",
            "sha256": replay_digest,
            "role": "tool-server-ack"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": "ack-runtime-replay",
            "to": "receipt-runtime-valid",
            "predicate": "acknowledges",
            "evidence_class": "native-external-proof"
        }));
    rebind_graph(bundle, graph);
}

fn add_second_runtime_attempt_without_terminal_receipt(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
) {
    let lease_path = "execution-lease-second.json";
    let revocation_path = "revocation-freshness-proof-second.json";
    let sandbox_path = "sandbox-attestation-second.json";
    let ack_path = "tool-server-ack-second.json";

    let mut lease: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("execution-lease.json")
            .test_expect("lease artifact exists"),
    )
    .test_expect("lease parses");
    lease["lease_id"] = Value::String("lease-runtime-second".to_string());
    lease["tool_instance_id"] = Value::String("tool-instance-002".to_string());
    lease["sandbox_attestation_ref"] = Value::String("sandbox-runtime-second".to_string());
    lease["revocation_freshness_ref"] = Value::String("revocation-runtime-second".to_string());
    lease["nonce"] = Value::String("nonce-runtime-second".to_string());
    sign_runtime_lease_with_fixture_authority(&mut lease);

    let mut revocation: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("revocation-freshness-proof.json")
            .test_expect("revocation artifact exists"),
    )
    .test_expect("revocation parses");
    revocation["proof_id"] = Value::String("revocation-runtime-second".to_string());
    let revocation_signing_key = Keypair::from_seed(&[43u8; 32]);
    revocation["signature"] = Value::String(sign_revocation_freshness(
        &revocation,
        &revocation_signing_key,
    ));

    let mut sandbox: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("sandbox-attestation.json")
            .test_expect("sandbox artifact exists"),
    )
    .test_expect("sandbox parses");
    sandbox["attestation_id"] = Value::String("sandbox-runtime-second".to_string());
    sandbox["tool_instance_id"] = Value::String("tool-instance-002".to_string());
    let sandbox_signing_key = Keypair::from_seed(&[44u8; 32]);
    sandbox["attester"] = Value::String(format!(
        "did:chio:{}",
        sandbox_signing_key.public_key().to_hex()
    ));
    sandbox["signature"] = Value::String(sign_sandbox_attestation(&sandbox, &sandbox_signing_key));

    let mut ack: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("tool-server-ack.json")
            .test_expect("ack artifact exists"),
    )
    .test_expect("ack parses");
    ack["ack_id"] = Value::String("ack-runtime-second".to_string());
    ack["lease_id"] = Value::String("lease-runtime-second".to_string());
    ack["tool_instance_id"] = Value::String("tool-instance-002".to_string());
    ack["sandbox_attestation_ref"] = Value::String("sandbox-runtime-second".to_string());
    ack["nonce"] = Value::String("nonce-runtime-second".to_string());
    let ack_signing_key = Keypair::from_seed(&[45u8; 32]);
    ack["signature"] = Value::String(sign_tool_server_ack(&ack, &ack_signing_key));

    let artifacts = [
        (
            lease_path,
            "lease-runtime-second",
            "chio.runtime.execution-lease.v1",
            "execution-lease",
            lease,
        ),
        (
            revocation_path,
            "revocation-runtime-second",
            "chio.runtime.revocation-freshness-proof.v1",
            "revocation-freshness-proof",
            revocation,
        ),
        (
            sandbox_path,
            "sandbox-runtime-second",
            "chio.runtime.sandbox-attestation.v1",
            "sandbox-attestation",
            sandbox,
        ),
        (
            ack_path,
            "ack-runtime-second",
            "chio.runtime.tool-server-ack.v1",
            "tool-server-ack",
            ack,
        ),
    ];

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    for (path, id, schema, role, value) in artifacts {
        let bytes = serde_json::to_vec_pretty(&value).test_expect("artifact serializes");
        let digest = sha256_hex(&bytes);
        bundle.artifacts.insert(path.to_string(), bytes);
        nodes.push(json!({
            "id": id,
            "schema": schema,
            "path": path,
            "sha256": digest,
            "role": role
        }));
    }
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .extend([
            json!({
                "from": "runtime-policy-valid",
                "to": "lease-runtime-second",
                "predicate": "authorizes",
                "evidence_class": "chio-sidecar-proof"
            }),
            json!({
                "from": "runtime-trust-root",
                "to": "lease-runtime-second",
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            }),
            json!({
                "from": "revocation-runtime-second",
                "to": "lease-runtime-second",
                "predicate": "freshens",
                "evidence_class": "native-external-proof"
            }),
            json!({
                "from": "sandbox-runtime-second",
                "to": "lease-runtime-second",
                "predicate": "attests",
                "evidence_class": "native-external-proof"
            }),
            json!({
                "from": "ack-runtime-second",
                "to": "lease-runtime-second",
                "predicate": "acknowledges",
                "evidence_class": "native-external-proof"
            }),
        ]);
    rebind_graph(bundle, graph);
}

fn sign_revocation_freshness(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.revocation-freshness-proof-signature.v1",
        "proofId": value["proof_id"],
        "oracleId": value["oracle_id"],
        "epochId": value["epoch_id"],
        "epochRoot": value["epoch_root"],
        "sequence": value["sequence"],
        "fetchedAt": value["fetched_at"],
        "maxStalenessMs": value["max_staleness_ms"],
        "revokedLeafResult": value["revoked_leaf_result"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("revocation proof signs")
        .0
        .to_hex()
}

fn sign_runtime_lease_with_fixture_authority(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] = Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = Value::String(sign_execution_lease(value, &signing_key));
}

fn sign_execution_lease(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.execution-lease-signature.v1",
        "leaseId": value["lease_id"],
        "toolServerId": value["tool_server_id"],
        "toolInstanceId": value["tool_instance_id"],
        "toolManifestDigest": value["tool_manifest_digest"],
        "sandboxAttestationRef": value["sandbox_attestation_ref"],
        "requestDigest": value["request_digest"],
        "revocationFreshnessRef": value["revocation_freshness_ref"],
        "policyDigest": value["policy_digest"],
        "nonce": value["nonce"],
        "sideEffectClass": value["side_effect_class"],
        "issuedAt": value["issued_at"],
        "expiresAt": value["expires_at"],
        "issuer": value["issuer"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("execution lease signs")
        .0
        .to_hex()
}

fn sign_sandbox_attestation(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.sandbox-attestation-signature.v1",
        "attestationId": value["attestation_id"],
        "toolServerId": value["tool_server_id"],
        "toolInstanceId": value["tool_instance_id"],
        "toolManifestDigest": value["tool_manifest_digest"],
        "sandboxProfileDigest": value["sandbox_profile_digest"],
        "egressPolicyDigest": value["egress_policy_digest"],
        "startedAt": value["started_at"],
        "expiresAt": value["expires_at"],
        "attester": value["attester"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("sandbox attestation signs")
        .0
        .to_hex()
}

fn sign_tool_server_ack(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.tool-server-ack-signature.v1",
        "ackId": value["ack_id"],
        "leaseId": value["lease_id"],
        "toolServerId": value["tool_server_id"],
        "toolInstanceId": value["tool_instance_id"],
        "sandboxAttestationRef": value["sandbox_attestation_ref"],
        "nonce": value["nonce"],
        "terminalStatus": value["terminal_status"],
        "issuedAt": value["issued_at"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("tool-server acknowledgement signs")
        .0
        .to_hex()
}

fn remove_receipt_node(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    let receipt_ids: Vec<String> = nodes
        .iter()
        .filter(|node| node["role"] == "receipt")
        .filter_map(|node| node["id"].as_str().map(ToOwned::to_owned))
        .collect();
    nodes.retain(|node| node["role"] != "receipt");
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .retain(|edge| {
            let from = edge["from"].as_str();
            let to = edge["to"].as_str();
            !receipt_ids.iter().any(|receipt_id| {
                from == Some(receipt_id.as_str()) || to == Some(receipt_id.as_str())
            })
        });
    rebind_graph(bundle, graph);
}

#[test]
fn side_effecting_runtime_claim_verifies_with_online_enforcement_evidence() {
    let bundle = load_runtime_security_fixture("valid-side-effecting-call");

    let report = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect("valid side-effecting runtime evidence should verify");

    assert_eq!(report.schema, "chio.transaction.runtime-security-report.v1");
    assert_eq!(report.id, "runtime-security-report-runtime-passport-valid");
    assert_eq!(report.issued_at, "2026-06-10T00:00:00Z");
    assert_eq!(report.verdict, "verified");
    assert!(report
        .verified_claims
        .contains(&"claim.runtime.execution_lease_valid".to_string()));
}

#[test]
fn side_effecting_runtime_claim_accepts_runtime_terminal_receipt_schema() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["schema"] = Value::String("chio.runtime.terminal-receipt.v1".to_string());
    });
    update_graph_node_schema(
        &mut bundle,
        "allow-receipt.json",
        "chio.runtime.terminal-receipt.v1",
    );

    let report = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect("runtime terminal receipt projection should verify");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.receipt_totality_complete".to_string()));
}

#[test]
fn side_effecting_runtime_claim_requires_execution_lease() {
    let bundle = load_runtime_security_fixture("missing-execution-lease");

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("missing execution lease must fail");

    assert!(error.to_string().contains("missing execution lease"));
}

#[test]
fn advisory_observation_cannot_authorize_runtime_execution() {
    let bundle = load_runtime_security_fixture("advisory-used-as-authorization");

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("advisory evidence must not authorize");

    assert!(error
        .to_string()
        .contains("advisory evidence cannot authorize"));
}

#[test]
fn advisory_observation_role_cannot_authorize_runtime_execution() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": "external-advisory-observation",
            "schema": "chio.runtime.observation.v1",
            "path": "advisory-observation.json",
            "sha256": "6666666666666666666666666666666666666666666666666666666666666666",
            "role": "advisory-observation"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": "external-advisory-observation",
            "to": "lease-runtime-valid",
            "predicate": "authorizes"
        }));
    rebind_graph(&mut bundle, graph);

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("advisory node role must not authorize");

    assert!(error
        .to_string()
        .contains("advisory evidence cannot authorize"));
}

#[test]
fn receipt_totality_accepts_denial_terminal_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["receipt_id"] = Value::String("receipt-runtime-denial".to_string());
        receipt["terminal_status"] = Value::String("denied_guard_request".to_string());
        receipt
            .as_object_mut()
            .test_expect("receipt is object")
            .remove("execution_lease_ref");
        receipt["policy_digest"] = Value::String(policy_digest);
    });

    let report = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect("denial terminal receipt should satisfy receipt totality");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.receipt_totality_complete".to_string()));
}

#[test]
fn receipt_totality_accepts_infrastructure_failure_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["receipt_id"] = Value::String("receipt-runtime-incident".to_string());
        receipt["terminal_status"] = Value::String("failed_tool_unreachable".to_string());
        receipt
            .as_object_mut()
            .test_expect("receipt is object")
            .remove("execution_lease_ref");
        receipt["incident_ref"] = Value::String("incident-tool-unreachable".to_string());
        receipt["policy_digest"] = Value::String(policy_digest);
    });

    let report = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect("infrastructure failure receipt should satisfy receipt totality");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.receipt_totality_complete".to_string()));
}

#[test]
fn receipt_totality_rejects_infrastructure_failure_without_incident_ref() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["receipt_id"] = Value::String("receipt-runtime-incident".to_string());
        receipt["terminal_status"] = Value::String("failed_tool_unreachable".to_string());
        receipt
            .as_object_mut()
            .test_expect("receipt is object")
            .remove("execution_lease_ref");
        receipt["policy_digest"] = Value::String(policy_digest);
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("infrastructure failure receipt must name an incident");

    assert!(error
        .to_string()
        .contains("failed terminal receipt missing incident"));
}

#[test]
fn receipt_totality_rejects_allowed_receipt_without_execution_lease_ref() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["policy_digest"] = Value::String(policy_digest);
        receipt
            .as_object_mut()
            .test_expect("receipt is object")
            .remove("execution_lease_ref");
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("allowed terminal receipt must bind an execution lease");

    assert!(error
        .to_string()
        .contains("allowed terminal receipt missing execution lease"));
}

#[test]
fn receipt_totality_rejects_missing_denial_receipt() {
    let negative_case = read_runtime_negative_case("missing-terminal-receipt");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    bundle.artifacts.remove("allow-receipt.json");
    remove_receipt_node(&mut bundle);

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("missing terminal receipt must fail receipt totality");

    assert!(error.to_string().contains(expected_failure(&negative_case)));
}

#[test]
fn receipt_totality_rejects_second_execution_lease_without_terminal_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["policy_digest"] = Value::String(policy_digest.clone());
        sign_runtime_lease_with_fixture_authority(lease);
    });
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["policy_digest"] = Value::String(policy_digest);
    });
    add_second_runtime_attempt_without_terminal_receipt(&mut bundle);

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("each side-effecting lease must have a terminal receipt");
    let error = error.to_string();

    assert!(
        error.contains("missing terminal receipt for execution lease"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_reused_nonce() {
    let negative_case = read_runtime_negative_case("reused-nonce");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_runtime_ack_replay(&mut bundle);

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("reused nonce must fail");

    assert!(error.to_string().contains(expected_failure(&negative_case)));
}

#[test]
fn side_effecting_runtime_claim_rejects_stale_revocation() {
    let negative_case = read_runtime_negative_case("stale-revocation");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(
        &mut bundle,
        "revocation-freshness-proof.json",
        |freshness| {
            freshness["fetched_at"] = negative_case["mutation"]["value"].clone();
        },
    );

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("stale revocation proof must fail");

    assert!(error.to_string().contains(expected_failure(&negative_case)));
}

#[test]
fn side_effecting_runtime_claim_rejects_future_revocation_freshness() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(
        &mut bundle,
        "revocation-freshness-proof.json",
        |freshness| {
            freshness["fetched_at"] = Value::String("2026-06-10T00:00:10Z".to_string());
        },
    );

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("future revocation proof must fail");

    assert!(error
        .to_string()
        .contains("revocation freshness fetched after lease issuance"));
}

#[test]
fn side_effecting_runtime_claim_rejects_tampered_revocation_signature() {
    let signing_key = Keypair::from_seed(&[43u8; 32]);
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(
        &mut bundle,
        "revocation-freshness-proof.json",
        |freshness| {
            freshness["oracle_id"] =
                Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
            freshness["signature"] =
                Value::String(sign_revocation_freshness(freshness, &signing_key));
        },
    );
    update_artifact(
        &mut bundle,
        "revocation-freshness-proof.json",
        |freshness| {
            freshness["signature"] = Value::String("00".repeat(64));
        },
    );

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("tampered revocation signature must fail");

    assert!(error
        .to_string()
        .contains("revocation freshness signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_expired_execution_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["expires_at"] = Value::String("2026-06-09T23:59:59Z".to_string());
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("expired execution lease must fail");

    assert!(error.to_string().contains("execution lease expired"));
}

#[test]
fn side_effecting_runtime_claim_rejects_read_only_execution_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["side_effect_class"] = Value::String("read-only".to_string());
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("read-only lease must not prove side-effecting runtime authority");

    assert!(error
        .to_string()
        .contains("execution lease side effect class is not governed"));
}

#[test]
fn side_effecting_runtime_claim_rejects_ack_outside_execution_lease() {
    let negative_case = read_runtime_negative_case("ack-outside-lease");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["issued_at"] = negative_case["mutation"]["value"].clone();
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("ack outside lease must fail");

    assert!(error.to_string().contains(expected_failure(&negative_case)));
}

#[test]
fn side_effecting_runtime_claim_rejects_revocation_stale_at_ack_time() {
    let ack_key = Keypair::from_seed(&[45u8; 32]);
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["issued_at"] = Value::String("2026-06-10T00:00:06Z".to_string());
        ack["signature"] = Value::String(sign_tool_server_ack(ack, &ack_key));
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("revocation freshness must cover tool acknowledgement time");

    assert!(error
        .to_string()
        .contains("revocation freshness stale at acknowledgement"));
}

#[test]
fn side_effecting_runtime_claim_rejects_sandbox_not_valid_for_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["expires_at"] = Value::String("2026-06-09T23:59:59Z".to_string());
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("sandbox outside lease must fail");

    assert!(error
        .to_string()
        .contains("sandbox attestation not valid for execution lease"));
}

#[test]
fn side_effecting_runtime_claim_rejects_tampered_sandbox_signature() {
    let signing_key = Keypair::from_seed(&[44u8; 32]);
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["attester"] =
            Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
        sandbox["signature"] = Value::String(sign_sandbox_attestation(sandbox, &signing_key));
    });
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["signature"] = Value::String("00".repeat(64));
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("tampered sandbox attestation signature must fail");

    assert!(error
        .to_string()
        .contains("sandbox attestation signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_tampered_tool_server_ack_signature() {
    let sandbox_key = Keypair::from_seed(&[44u8; 32]);
    let ack_key = Keypair::from_seed(&[45u8; 32]);
    let tool_server_id = format!("did:chio:{}", ack_key.public_key().to_hex());
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["tool_server_id"] = Value::String(tool_server_id.clone());
    });
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["tool_server_id"] = Value::String(tool_server_id.clone());
        sandbox["attester"] =
            Value::String(format!("did:chio:{}", sandbox_key.public_key().to_hex()));
        sandbox["signature"] = Value::String(sign_sandbox_attestation(sandbox, &sandbox_key));
    });
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["tool_server_id"] = Value::String(tool_server_id);
        ack["signature"] = Value::String(sign_tool_server_ack(ack, &ack_key));
    });
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["signature"] = Value::String("00".repeat(64));
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("tampered tool-server acknowledgement signature must fail");

    assert!(error
        .to_string()
        .contains("tool-server acknowledgement signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_forged_tool_server_bound_by_unsigned_lease() {
    let sandbox_key = Keypair::from_seed(&[44u8; 32]);
    let forged_ack_key = Keypair::from_seed(&[47u8; 32]);
    let forged_tool_server_id = format!("did:chio:{}", forged_ack_key.public_key().to_hex());
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["tool_server_id"] = Value::String(forged_tool_server_id.clone());
    });
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["tool_server_id"] = Value::String(forged_tool_server_id.clone());
        sandbox["attester"] =
            Value::String(format!("did:chio:{}", sandbox_key.public_key().to_hex()));
        sandbox["signature"] = Value::String(sign_sandbox_attestation(sandbox, &sandbox_key));
    });
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["tool_server_id"] = Value::String(forged_tool_server_id);
        ack["signature"] = Value::String(sign_tool_server_ack(ack, &forged_ack_key));
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("forged tool server must not be authorized by an unsigned lease");

    let error = error.to_string();
    assert!(
        error.contains("execution lease signature invalid"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_policy_digest_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["policy_digest"] = Value::String(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("policy digest mismatch must fail");

    assert!(error.to_string().contains("policy digest mismatch"));
}

#[test]
fn side_effecting_runtime_claim_rejects_sandbox_mismatch() {
    let negative_case = read_runtime_negative_case("sandbox-mismatch");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["tool_manifest_digest"] = negative_case["mutation"]["value"].clone();
    });

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("sandbox mismatch must fail");

    assert!(error.to_string().contains(expected_failure(&negative_case)));
}

#[test]
fn runtime_security_rejects_unverified_required_claim() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.unsupported_future_claim"]);

    let error = chio_control_plane::transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("unverified required claim must fail closed");

    assert!(error.to_string().contains("required claim not verified"));
}
