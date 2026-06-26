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

fn load_runtime_security_fixture(
    case_name: &str,
) -> chio_control_plane::transaction_passport::RuntimeSecurityBundle {
    let dir = fixture_dir(case_name);
    let passport_bytes = read_file(&dir, "transaction-passport.json");
    let passport = serde_json::from_slice(&passport_bytes).test_expect("passport parses");
    let evidence_graph_bytes = read_file(&dir, "evidence-graph.json");
    let verifier_policy_bytes = read_file(&dir, "verifier-policy.json");
    let evidence_graph: Value =
        serde_json::from_slice(&evidence_graph_bytes).test_expect("evidence graph parses");
    let mut artifacts = BTreeMap::new();
    for node in evidence_graph["nodes"]
        .as_array()
        .test_expect("evidence graph nodes array")
    {
        if let Some(artifact_path) = node.get("path").and_then(Value::as_str) {
            let path = dir.join(artifact_path);
            if path.is_file() {
                artifacts.insert(artifact_path.to_string(), read_file(&dir, artifact_path));
            }
        }
    }

    chio_control_plane::transaction_passport::RuntimeSecurityBundle {
        passport,
        evidence_graph_bytes,
        root_evidence_graph_bytes: None,
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
    resign_passport(bundle);
}

fn resign_passport(bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle) {
    let signing_key = Keypair::from_seed(&[7u8; 32]);
    bundle.passport.signature =
        chio_control_plane::transaction_passport::sign_transaction_passport(
            &bundle.passport,
            &signing_key,
        )
        .test_expect("runtime passport signs");
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
    update_claim_set_required_claims(bundle, &required_claims);
    rebind_policy(bundle, policy);
}

fn update_claim_set_required_claims(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
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
    let bytes = serde_json::to_vec_pretty(&claim_set).test_expect("claim set serializes");
    let digest = sha256_hex(&bytes);
    bundle.artifacts.insert("claim-set.json".to_string(), bytes);
    bundle.passport.claim_set_sha256 = digest.clone();
    update_graph_node_digest(bundle, "claim-set.json", &digest);
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
    let mut old_id = None;
    for node in nodes {
        if node["path"] == artifact_path {
            old_id = node["id"].as_str().map(std::string::ToString::to_string);
            node["id"] = Value::String(digest.to_string());
            node["sha256"] = Value::String(digest.to_string());
            break;
        }
    }
    let old_id = old_id.test_expect("graph node exists for artifact path");
    if old_id != digest {
        for edge in graph["edges"].as_array_mut().test_expect("graph has edges") {
            if edge["from"].as_str() == Some(old_id.as_str()) {
                edge["from"] = Value::String(digest.to_string());
            }
            if edge["to"].as_str() == Some(old_id.as_str()) {
                edge["to"] = Value::String(digest.to_string());
            }
        }
    }
    rebind_graph(bundle, graph);
}

fn graph_node_id_for_path(graph: &Value, artifact_path: &str) -> String {
    graph["nodes"]
        .as_array()
        .test_expect("graph has nodes")
        .iter()
        .find(|node| node["path"] == artifact_path)
        .and_then(|node| node["id"].as_str())
        .test_expect("graph node id exists for artifact path")
        .to_string()
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
    let receipt_node_id = graph_node_id_for_path(&graph, "allow-receipt.json");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": replay_digest.clone(),
            "schema": "chio.runtime.tool-server-ack.v1",
            "path": "tool-server-ack-replay.json",
            "sha256": replay_digest.clone(),
            "role": "tool-server-ack"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": replay_digest,
            "to": receipt_node_id,
            "predicate": "acknowledges",
            "evidence_class": "native-external-proof"
        }));
    rebind_graph(bundle, graph);
}

fn add_request_digest_binding(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    request_digest: &str,
) {
    let request = json!({
        "schema": "chio.request.digest.v1",
        "id": "request-runtime-valid",
        "method": "runtime.tool.call",
        "sha256": request_digest
    });
    let request_bytes = serde_json::to_vec_pretty(&request).test_expect("request serializes");
    let request_artifact_digest = sha256_hex(&request_bytes);
    bundle
        .artifacts
        .insert("request-digest.json".to_string(), request_bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let lease_node_id = graph_node_id_for_path(&graph, "execution-lease.json");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    let existing_request_ids: Vec<String> = nodes
        .iter()
        .filter(|node| node["role"] == "request")
        .filter_map(|node| node["id"].as_str().map(ToOwned::to_owned))
        .collect();
    nodes.retain(|node| node["role"] != "request");
    nodes.push(json!({
        "id": request_artifact_digest.clone(),
        "schema": "chio.request.digest.v1",
        "path": "request-digest.json",
        "sha256": request_artifact_digest.clone(),
        "role": "request"
    }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .retain(|edge| {
            let from = edge["from"].as_str();
            let to = edge["to"].as_str();
            !existing_request_ids.iter().any(|request_id| {
                from == Some(request_id.as_str()) || to == Some(request_id.as_str())
            })
        });
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": request_artifact_digest,
            "to": lease_node_id,
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    rebind_graph(bundle, graph);
}

fn add_route_plan_binding(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    route_plan_id: &str,
) {
    update_artifact(bundle, "execution-lease.json", |lease| {
        lease["route_plan_receipt_ref"] = Value::String("route-lease-runtime-valid".to_string());
        sign_runtime_lease_with_fixture_authority(lease);
    });
    let route_plan_signing_key = Keypair::from_seed(&[46u8; 32]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(bundle, "route-plan-receipt.json", |route_plan| {
        *route_plan = json!({
            "schema": "chio.swarm.route-plan-receipt.v1",
            "routePlanId": route_plan_id,
            "graphId": "runtime-route-graph-valid",
            "taskId": "runtime-tool-call",
            "selectedRoute": "mcp:runtime-tool-call",
            "candidateSetDigest": "3333333333333333333333333333333333333333333333333333333333333333",
            "registrySnapshotHash": "4444444444444444444444444444444444444444444444444444444444444444",
            "bridgeId": "mcp",
            "protocolTarget": "mcp://runtime-tool",
            "egressContractId": "mcp:egress-contract-runtime-valid",
            "egressConstraints": ["deny-private-network"],
            "attenuationDecision": "accepted",
            "policyDigest": policy_digest,
            "expiresAtUnixMs": 1800000300000_u64,
            "issuer": format!("did:chio:{}", route_plan_signing_key.public_key().to_hex())
        });
        route_plan["signature"] =
            Value::String(sign_runtime_route_plan(route_plan, &route_plan_signing_key));
    });
}

fn add_policy_activation_receipt(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    narrowing_or_widening: &str,
) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    let mut receipt = json!({
        "schema": "chio.policy.activation-receipt.v1",
        "policy_digest": bundle.passport.verifier_policy_sha256,
        "previous_policy_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "activation_epoch": "policy-epoch-runtime-valid",
        "activated_at": "2026-06-10T00:00:00Z",
        "activation_mode": "hot_reload",
        "narrowing_or_widening": narrowing_or_widening,
        "migration_rule": "remint_existing_authority",
        "issuer": format!("did:chio:{}", signing_key.public_key().to_hex())
    });
    receipt["signature"] = Value::String(sign_policy_activation_receipt(&receipt, &signing_key));
    let receipt_bytes =
        serde_json::to_vec_pretty(&receipt).test_expect("activation receipt serializes");
    let receipt_digest = sha256_hex(&receipt_bytes);
    bundle
        .artifacts
        .insert("policy-activation-receipt.json".to_string(), receipt_bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let trust_root_node_id = graph_node_id_for_path(&graph, "trust-root.json");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": receipt_digest.clone(),
            "schema": "chio.policy.activation-receipt.v1",
            "path": "policy-activation-receipt.json",
            "sha256": receipt_digest.clone(),
            "role": "policy-activation-receipt"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": trust_root_node_id,
            "to": receipt_digest,
            "predicate": "authorizes",
            "evidence_class": "digest-bound-reference"
        }));
    rebind_graph(bundle, graph);
}

fn add_attack_simulation_report(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    status: &str,
) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    let mut report = json!({
        "schema": "chio.runtime.attack-simulation-report.v1",
        "scenario_id": "attack-policy-hot-reload-widening",
        "attack_class": "policy-hot-reload-widening",
        "fixture_path": "fixtures/proof-room/runtime-security/policy-hot-reload-widening",
        "expected_denial_claim": "claim.runtime.policy_activation_no_widening",
        "actual_verifier_report_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "runtime_receipt_refs": ["receipt-runtime-valid"],
        "chaos_knobs": ["policy_reload"],
        "status": status,
        "simulator_version_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "issuer": format!("did:chio:{}", signing_key.public_key().to_hex())
    });
    report["signature"] = Value::String(sign_attack_simulation_report(&report, &signing_key));
    let report_bytes = serde_json::to_vec_pretty(&report).test_expect("attack report serializes");
    let report_digest = sha256_hex(&report_bytes);
    bundle
        .artifacts
        .insert("attack-simulation-report.json".to_string(), report_bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let trust_root_node_id = graph_node_id_for_path(&graph, "trust-root.json");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": report_digest.clone(),
            "schema": "chio.runtime.attack-simulation-report.v1",
            "path": "attack-simulation-report.json",
            "sha256": report_digest.clone(),
            "role": "runtime-attack-simulation-report"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": trust_root_node_id,
            "to": report_digest,
            "predicate": "authorizes",
            "evidence_class": "digest-bound-reference"
        }));
    rebind_graph(bundle, graph);
}

fn add_chaos_run_report(
    bundle: &mut chio_control_plane::transaction_passport::RuntimeSecurityBundle,
    status: &str,
) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    let mut report = json!({
        "schema": "chio.runtime.chaos-run-report.v1",
        "case_id": "policy-reload-during-dispatch",
        "failure_injected": "policy digest changes after lease mint and before tool ack",
        "expected_result": "reject unless reminted or activation receipt proves narrowing",
        "actual_verifier_report_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "runtime_receipt_refs": ["receipt-runtime-valid"],
        "deterministic_seed_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "status": status,
        "runner_version_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "issuer": format!("did:chio:{}", signing_key.public_key().to_hex())
    });
    report["signature"] = Value::String(sign_chaos_run_report(&report, &signing_key));
    let report_bytes = serde_json::to_vec_pretty(&report).test_expect("chaos report serializes");
    let report_digest = sha256_hex(&report_bytes);
    bundle
        .artifacts
        .insert("chaos-run-report.json".to_string(), report_bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let trust_root_node_id = graph_node_id_for_path(&graph, "trust-root.json");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": report_digest.clone(),
            "schema": "chio.runtime.chaos-run-report.v1",
            "path": "chaos-run-report.json",
            "sha256": report_digest.clone(),
            "role": "runtime-chaos-run-report"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": trust_root_node_id,
            "to": report_digest,
            "predicate": "authorizes",
            "evidence_class": "digest-bound-reference"
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
            "chio.runtime.execution-lease.v1",
            "execution-lease",
            lease,
        ),
        (
            revocation_path,
            "chio.runtime.revocation-freshness-proof.v1",
            "revocation-freshness-proof",
            revocation,
        ),
        (
            sandbox_path,
            "chio.runtime.sandbox-attestation.v1",
            "sandbox-attestation",
            sandbox,
        ),
        (
            ack_path,
            "chio.runtime.tool-server-ack.v1",
            "tool-server-ack",
            ack,
        ),
    ];

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("graph parses");
    let policy_node_id = graph_node_id_for_path(&graph, "verifier-policy.json");
    let trust_root_node_id = graph_node_id_for_path(&graph, "trust-root.json");
    let nodes = graph["nodes"].as_array_mut().test_expect("graph has nodes");
    let mut new_node_ids = BTreeMap::new();
    for (path, schema, role, value) in artifacts {
        let bytes = serde_json::to_vec_pretty(&value).test_expect("artifact serializes");
        let digest = sha256_hex(&bytes);
        bundle.artifacts.insert(path.to_string(), bytes);
        new_node_ids.insert(path, digest.clone());
        nodes.push(json!({
            "id": digest.clone(),
            "schema": schema,
            "path": path,
            "sha256": digest,
            "role": role
        }));
    }
    let lease_node_id = new_node_ids
        .get(lease_path)
        .test_expect("second lease node id")
        .clone();
    let revocation_node_id = new_node_ids
        .get(revocation_path)
        .test_expect("second revocation node id")
        .clone();
    let sandbox_node_id = new_node_ids
        .get(sandbox_path)
        .test_expect("second sandbox node id")
        .clone();
    let ack_node_id = new_node_ids
        .get(ack_path)
        .test_expect("second ack node id")
        .clone();
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .extend([
            json!({
                "from": policy_node_id,
                "to": lease_node_id.clone(),
                "predicate": "authorizes",
                "evidence_class": "chio-sidecar-proof"
            }),
            json!({
                "from": trust_root_node_id,
                "to": lease_node_id.clone(),
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            }),
            json!({
                "from": revocation_node_id,
                "to": lease_node_id.clone(),
                "predicate": "freshens",
                "evidence_class": "native-external-proof"
            }),
            json!({
                "from": sandbox_node_id,
                "to": lease_node_id.clone(),
                "predicate": "attests",
                "evidence_class": "native-external-proof"
            }),
            json!({
                "from": ack_node_id,
                "to": lease_node_id,
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

fn runtime_trusted_root_keys() -> Vec<chio_core::PublicKey> {
    vec![Keypair::from_seed(&[46u8; 32]).public_key()]
}

fn transaction_trusted_root_keys() -> Vec<chio_core::PublicKey> {
    vec![Keypair::from_seed(&[7u8; 32]).public_key()]
}

fn verify_runtime_security_fixture(
    bundle: &chio_control_plane::transaction_passport::RuntimeSecurityBundle,
) -> Result<
    chio_control_plane::transaction_passport::RuntimeSecurityReport,
    chio_control_plane::transaction_passport::TransactionPassportError,
> {
    chio_control_plane::transaction_passport::verify_runtime_security_claims_with_trust(
        bundle,
        &chio_control_plane::transaction_passport::RuntimeSecurityTrust {
            trusted_passport_signer_keys: transaction_trusted_root_keys(),
            trusted_root_signer_keys: runtime_trusted_root_keys(),
        },
    )
}

fn sign_execution_lease(value: &Value, keypair: &Keypair) -> String {
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
    keypair
        .sign_canonical(&body)
        .test_expect("execution lease signs")
        .0
        .to_hex()
}

fn sign_runtime_route_plan(value: &Value, keypair: &Keypair) -> String {
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
    keypair
        .sign_canonical(&body)
        .test_expect("route plan signs")
        .0
        .to_hex()
}

fn sign_policy_activation_receipt(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.policy.activation-receipt-signature.v1",
        "policyDigest": value["policy_digest"],
        "previousPolicyDigest": value["previous_policy_digest"],
        "activationEpoch": value["activation_epoch"],
        "activatedAt": value["activated_at"],
        "activationMode": value["activation_mode"],
        "narrowingOrWidening": value["narrowing_or_widening"],
        "migrationRule": value["migration_rule"],
        "issuer": value["issuer"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("policy activation receipt signs")
        .0
        .to_hex()
}

fn sign_attack_simulation_report(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.attack-simulation-report-signature.v1",
        "scenarioId": value["scenario_id"],
        "attackClass": value["attack_class"],
        "fixturePath": value["fixture_path"],
        "expectedDenialClaim": value["expected_denial_claim"],
        "actualVerifierReportDigest": value["actual_verifier_report_digest"],
        "runtimeReceiptRefs": value["runtime_receipt_refs"],
        "chaosKnobs": value["chaos_knobs"],
        "status": value["status"],
        "simulatorVersionDigest": value["simulator_version_digest"],
        "issuer": value["issuer"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("attack simulation report signs")
        .0
        .to_hex()
}

fn sign_chaos_run_report(value: &Value, keypair: &Keypair) -> String {
    let body = json!({
        "schema": "chio.runtime.chaos-run-report-signature.v1",
        "caseId": value["case_id"],
        "failureInjected": value["failure_injected"],
        "expectedResult": value["expected_result"],
        "actualVerifierReportDigest": value["actual_verifier_report_digest"],
        "runtimeReceiptRefs": value["runtime_receipt_refs"],
        "deterministicSeedDigest": value["deterministic_seed_digest"],
        "status": value["status"],
        "runnerVersionDigest": value["runner_version_digest"],
        "issuer": value["issuer"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("chaos run report signs")
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

fn sign_runtime_terminal_receipt_with_fixture_kernel(value: &mut Value) {
    let signing_key = Keypair::from_seed(&[23u8; 32]);
    value["kernel_key"] = Value::String(signing_key.public_key().to_hex());
    value["signature"] = Value::String(sign_runtime_terminal_receipt(value, &signing_key));
}

fn sign_runtime_terminal_receipt(value: &Value, keypair: &Keypair) -> String {
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
    keypair
        .sign_canonical(&body)
        .test_expect("terminal receipt signs")
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

    let report = verify_runtime_security_fixture(&bundle)
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

    let report = verify_runtime_security_fixture(&bundle)
        .test_expect("runtime terminal receipt projection should verify");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.receipt_totality_complete".to_string()));
}

#[test]
fn side_effecting_runtime_claim_requires_execution_lease() {
    let bundle = load_runtime_security_fixture("missing-execution-lease");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("missing execution lease must fail");

    assert!(error.to_string().contains("missing execution lease"));
}

#[test]
fn advisory_observation_cannot_authorize_runtime_execution() {
    let bundle = load_runtime_security_fixture("advisory-used-as-authorization");

    let error = verify_runtime_security_fixture(&bundle)
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
    let advisory_digest = "6666666666666666666666666666666666666666666666666666666666666666";
    let lease_node_id = graph_node_id_for_path(&graph, "execution-lease.json");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph has nodes")
        .push(json!({
            "id": advisory_digest,
            "schema": "chio.runtime.observation.v1",
            "path": "advisory-observation.json",
            "sha256": advisory_digest,
            "role": "advisory-observation"
        }));
    graph["edges"]
        .as_array_mut()
        .test_expect("graph has edges")
        .push(json!({
            "from": advisory_digest,
            "to": lease_node_id,
            "predicate": "authorizes"
        }));
    rebind_graph(&mut bundle, graph);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("advisory node role must not authorize");

    assert!(error
        .to_string()
        .contains("advisory evidence cannot authorize"));
}

#[test]
fn receipt_totality_rejects_denial_receipt_without_execution_lease_ref_when_lease_present() {
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
        sign_runtime_terminal_receipt_with_fixture_kernel(receipt);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("denial terminal receipt must cover the execution lease");

    assert!(
        error
            .to_string()
            .contains("missing terminal receipt for execution lease"),
        "{error}"
    );
}

#[test]
fn receipt_totality_accepts_denial_terminal_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["receipt_id"] = Value::String("receipt-runtime-denial".to_string());
        receipt["terminal_status"] = Value::String("denied_guard_request".to_string());
        receipt["policy_digest"] = Value::String(policy_digest);
        sign_runtime_terminal_receipt_with_fixture_kernel(receipt);
    });

    let report = verify_runtime_security_fixture(&bundle)
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
        receipt["incident_ref"] = Value::String("incident-tool-unreachable".to_string());
        receipt["policy_digest"] = Value::String(policy_digest);
        sign_runtime_terminal_receipt_with_fixture_kernel(receipt);
    });

    let report = verify_runtime_security_fixture(&bundle)
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

    let error = verify_runtime_security_fixture(&bundle)
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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("allowed terminal receipt must bind an execution lease");

    assert!(error
        .to_string()
        .contains("allowed terminal receipt missing execution lease"));
}

#[test]
fn receipt_totality_rejects_missing_denial_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.receipt_totality_complete"]);
    bundle.artifacts.remove("allow-receipt.json");
    remove_receipt_node(&mut bundle);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("missing terminal receipt must fail receipt totality");

    let error = error.to_string();
    assert!(
        error.contains("missing terminal receipt for execution lease"),
        "{error}"
    );
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
        sign_runtime_terminal_receipt_with_fixture_kernel(receipt);
    });
    add_second_runtime_attempt_without_terminal_receipt(&mut bundle);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("each side-effecting lease must have a terminal receipt");
    let error = error.to_string();

    assert!(
        error.contains("missing terminal receipt for execution lease"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_reused_nonce() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_runtime_ack_replay(&mut bundle);

    let error = verify_runtime_security_fixture(&bundle).test_expect_err("reused nonce must fail");

    let error = error.to_string();
    assert!(error.contains("reused nonce"), "{error}");
}

#[test]
fn side_effecting_runtime_claim_rejects_request_digest_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_request_digest_binding(
        &mut bundle,
        "3333333333333333333333333333333333333333333333333333333333333333",
    );

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("request binding must match");

    assert!(
        error
            .to_string()
            .contains("execution lease request digest mismatch"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_accepts_bound_route_plan_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_route_plan_binding(&mut bundle, "route-lease-runtime-valid");

    let report = verify_runtime_security_fixture(&bundle)
        .test_expect("execution lease should accept the bound route plan receipt");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.execution_lease_valid".to_string()));
}

#[test]
fn side_effecting_runtime_claim_rejects_route_plan_receipt_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_route_plan_binding(&mut bundle, "route-runtime-other");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("execution lease must bind the named route plan receipt");

    assert!(
        error
            .to_string()
            .contains("execution lease route plan receipt mismatch"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_widening_policy_activation_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_policy_activation_receipt(&mut bundle, "widening");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("widening policy activation must not expand in-flight authority");

    assert!(
        error
            .to_string()
            .contains("policy activation cannot widen in-flight authority"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_failed_attack_simulation_report() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_attack_simulation_report(&mut bundle, "failed");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("failed attack simulation report must fail runtime verification");

    assert!(
        error.to_string().contains("attack simulation did not pass"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_failed_chaos_run_report() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    add_chaos_run_report(&mut bundle, "failed");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("failed chaos run report must fail runtime verification");

    assert!(
        error.to_string().contains("chaos run did not pass"),
        "{error}"
    );
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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("stale revocation proof must fail");

    let error = error.to_string();
    assert!(error.contains("revocation freshness stale"), "{error}");
}

#[test]
fn side_effecting_runtime_claim_rejects_revocation_epoch_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["revocation_epoch_ref"] = Value::String("epoch-runtime-stale".to_string());
        sign_runtime_lease_with_fixture_authority(lease);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("execution lease must bind the revocation epoch");

    assert!(error
        .to_string()
        .contains("execution lease revocation epoch mismatch"));
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

    let error = verify_runtime_security_fixture(&bundle)
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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("tampered revocation signature must fail");

    assert!(error
        .to_string()
        .contains("revocation freshness signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_untrusted_revocation_oracle() {
    let signing_key = Keypair::from_seed(&[91u8; 32]);
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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("untrusted revocation oracle must fail");

    assert!(error
        .to_string()
        .contains("revocation freshness oracle is not trusted"));
}

#[test]
fn side_effecting_runtime_claim_rejects_expired_execution_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["expires_at"] = Value::String("2026-06-09T23:59:59Z".to_string());
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("expired execution lease must fail");

    assert!(error.to_string().contains("execution lease expired"));
}

#[test]
fn side_effecting_runtime_claim_rejects_read_only_execution_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["side_effect_class"] = Value::String("read-only".to_string());
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("read-only lease must not prove side-effecting runtime authority");

    assert!(error
        .to_string()
        .contains("execution lease side effect class is not governed"));
}

#[test]
fn side_effecting_runtime_claim_rejects_multi_invocation_execution_lease() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["max_invocations"] = Value::Number(2.into());
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting lease must be single invocation");

    assert!(error
        .to_string()
        .contains("execution lease max_invocations must be 1"));
}

#[test]
fn side_effecting_runtime_claim_rejects_ack_outside_execution_lease() {
    let negative_case = read_runtime_negative_case("ack-outside-lease");
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["issued_at"] = negative_case["mutation"]["value"].clone();
    });

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("ack outside lease must fail");

    let error = error.to_string();
    assert!(
        error.contains("acknowledgement outside execution lease"),
        "{error}"
    );
}

#[test]
fn side_effecting_runtime_claim_rejects_revocation_stale_at_ack_time() {
    let ack_key = Keypair::from_seed(&[45u8; 32]);
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["issued_at"] = Value::String("2026-06-10T00:00:06Z".to_string());
        ack["signature"] = Value::String(sign_tool_server_ack(ack, &ack_key));
    });

    let error = verify_runtime_security_fixture(&bundle)
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

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("sandbox outside lease must fail");

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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("tampered sandbox attestation signature must fail");

    assert!(error
        .to_string()
        .contains("sandbox attestation signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_untrusted_sandbox_attester() {
    let signing_key = Keypair::from_seed(&[92u8; 32]);
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["attester"] =
            Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
        sandbox["signature"] = Value::String(sign_sandbox_attestation(sandbox, &signing_key));
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("untrusted sandbox attester must fail");

    assert!(error
        .to_string()
        .contains("sandbox attester is not trusted"));
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

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("tampered tool-server acknowledgement signature must fail");

    assert!(error
        .to_string()
        .contains("tool-server acknowledgement signature invalid"));
}

#[test]
fn side_effecting_runtime_claim_rejects_untrusted_tool_server_ack() {
    let ack_key = Keypair::from_seed(&[47u8; 32]);
    let sandbox_key = Keypair::from_seed(&[44u8; 32]);
    let tool_server_id = format!("did:chio:{}", ack_key.public_key().to_hex());
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["tool_server_id"] = Value::String(tool_server_id.clone());
        sign_runtime_lease_with_fixture_authority(lease);
    });
    update_artifact(&mut bundle, "sandbox-attestation.json", |sandbox| {
        sandbox["tool_server_id"] = Value::String(tool_server_id.clone());
        sandbox["signature"] = Value::String(sign_sandbox_attestation(sandbox, &sandbox_key));
    });
    update_artifact(&mut bundle, "tool-server-ack.json", |ack| {
        ack["tool_server_id"] = Value::String(tool_server_id);
        ack["signature"] = Value::String(sign_tool_server_ack(ack, &ack_key));
    });

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("untrusted tool server must fail");

    assert!(error.to_string().contains("tool-server is not trusted"));
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

    let error = verify_runtime_security_fixture(&bundle)
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

    let error = verify_runtime_security_fixture(&bundle)
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

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("sandbox mismatch must fail");

    let error = error.to_string();
    assert!(error.contains("sandbox tool binding mismatch"), "{error}");
}

#[test]
fn runtime_security_rejects_unverified_required_claim() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_policy_required_claims(&mut bundle, vec!["claim.runtime.unsupported_future_claim"]);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("unverified required claim must fail closed");

    assert!(error.to_string().contains("required claim not verified"));
}
