use chio_test_support::prelude::*;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

fn fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/minimal-passport/{case_name}/transaction-passport.json"
    ))
}

fn runtime_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/runtime-security/{case_name}/transaction-passport.json"
    ))
}

fn enterprise_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/enterprise-export/{case_name}/transaction-passport.json"
    ))
}

fn agent_web_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/agent-web/{case_name}/transaction-passport.json"
    ))
}

fn trust_market_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/trust-market/{case_name}/transaction-passport.json"
    ))
}

fn public_settlement_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/public-settlement/{case_name}/transaction-passport.json"
    ))
}

fn commerce_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/commerce-payments/{case_name}/transaction-passport.json"
    ))
}

fn swarm_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/swarm-authority/{case_name}/transaction-passport.json"
    ))
}

fn disclosure_lineage_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/disclosure-lineage/{case_name}/transaction-passport.json"
    ))
}

fn write_file(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).test_expect("write test fixture");
}

fn copy_dir_all(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).test_expect("create destination dir");
    for entry in std::fs::read_dir(source).test_expect("read source dir") {
        let entry = entry.test_expect("read source entry");
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().test_expect("read source entry type");
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path);
        } else {
            std::fs::copy(entry.path(), destination_path).test_expect("copy source entry");
        }
    }
}

fn add_disclosure_crypto_context_report(bundle_dir: &std::path::Path) {
    let crypto_context_report_path = bundle_dir.join("crypto-context-report.json");
    let crypto_context_report = serde_json::json!({
        "schema": "chio.disclosure.crypto-context-report.v1",
        "id": "crypto-context-report-valid",
        "context_id": "crypto-context-valid",
        "artifact_ref": "disclosure-capsule-valid",
        "verdict": "verified",
        "evidence_class": "verifier_context",
        "cryptographic_proof_verified": true,
        "verified_claims": [
            "claim.disclosure.crypto_context_bound",
            "claim.disclosure.profile_context_policy_enforced"
        ],
        "rejected_checks": [],
        "disclosed_fields": ["capability_id", "tool_name"]
    });
    let crypto_context_report_bytes =
        serde_json::to_vec(&crypto_context_report).test_expect("serialize crypto report");
    std::fs::write(&crypto_context_report_path, &crypto_context_report_bytes)
        .test_expect("write crypto report");
    let crypto_context_report_digest = chio_core::sha256_hex(&crypto_context_report_bytes);

    let capsule_digest = chio_core::sha256_hex(
        &std::fs::read(bundle_dir.join("capsule.json")).test_expect("read capsule"),
    );
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes");
    nodes.retain(|node| {
        node.get("role").and_then(serde_json::Value::as_str)
            != Some("disclosure-crypto-context-report")
    });
    for node in nodes.iter_mut() {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("disclosure-capsule") {
            node["sha256"] = serde_json::Value::String(capsule_digest.clone());
        }
    }
    nodes.push(serde_json::json!({
        "id": "crypto-context-report",
        "schema": "chio.disclosure.crypto-context-report.v1",
        "path": "crypto-context-report.json",
        "sha256": crypto_context_report_digest,
        "role": "disclosure-crypto-context-report"
    }));
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
        .retain(|edge| {
            edge.get("to").and_then(serde_json::Value::as_str) != Some("crypto-context-report")
                && edge.get("from").and_then(serde_json::Value::as_str)
                    != Some("crypto-context-report")
        });
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
        .push(serde_json::json!({
            "from": "disclosure-capsule",
            "to": "crypto-context-report",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

fn remove_disclosure_crypto_context_report(bundle_dir: &std::path::Path) {
    let crypto_context_report_path = bundle_dir.join("crypto-context-report.json");
    if crypto_context_report_path.exists() {
        std::fs::remove_file(&crypto_context_report_path).test_expect("remove crypto report");
    }
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .retain(|node| {
            node.get("role").and_then(serde_json::Value::as_str)
                != Some("disclosure-crypto-context-report")
        });
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
        .retain(|edge| {
            edge.get("to").and_then(serde_json::Value::as_str) != Some("crypto-context-report")
                && edge.get("from").and_then(serde_json::Value::as_str)
                    != Some("crypto-context-report")
        });
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

fn set_disclosure_policy_required_claims(bundle_dir: &std::path::Path, required_claims: &[&str]) {
    let verifier_policy_path = bundle_dir.join("verifier-policy.json");
    let mut policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("parse verifier policy");
    policy["required_claims"] = serde_json::Value::Array(
        required_claims
            .iter()
            .map(|claim| serde_json::Value::String((*claim).to_string()))
            .collect(),
    );
    let policy_bytes = serde_json::to_vec(&policy).test_expect("serialize verifier policy");
    std::fs::write(&verifier_policy_path, &policy_bytes).test_expect("write verifier policy");
    set_passport_digest(
        bundle_dir,
        "verifier_policy_sha256",
        chio_core::sha256_hex(&policy_bytes),
    );
}

fn set_passport_digest(bundle_dir: &std::path::Path, digest_field: &str, digest: String) {
    let passport_path = bundle_dir.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("parse passport");
    passport[digest_field] = serde_json::Value::String(digest);
    std::fs::write(
        &passport_path,
        serde_json::to_vec(&passport).test_expect("serialize passport"),
    )
    .test_expect("write passport");
}

fn write_minimal_evidence_graph(bundle_dir: &std::path::Path, evidence_graph: serde_json::Value) {
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

fn refresh_minimal_evidence_graph_node_digest(bundle_dir: &std::path::Path, artifact_path: &str) {
    let artifact_bytes =
        std::fs::read(bundle_dir.join(artifact_path)).test_expect("read minimal artifact");
    let artifact_digest = chio_core::sha256_hex(&artifact_bytes);
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path) {
            node["sha256"] = serde_json::Value::String(artifact_digest.clone());
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

fn mutate_public_settlement_bundle(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let settlement_bundle_path = bundle_dir.join("settlement-proof-bundle.json");
    let mut settlement_bundle: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&settlement_bundle_path).test_expect("read settlement proof bundle"),
    )
    .test_expect("parse settlement proof bundle");
    mutate(&mut settlement_bundle);
    let settlement_bundle_bytes =
        serde_json::to_vec(&settlement_bundle).test_expect("serialize settlement proof bundle");
    std::fs::write(&settlement_bundle_path, &settlement_bundle_bytes)
        .test_expect("write settlement proof bundle");
    let settlement_bundle_digest = chio_core::sha256_hex(&settlement_bundle_bytes);

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
            node["sha256"] = serde_json::Value::String(settlement_bundle_digest.clone());
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

fn public_settlement_chain_snapshot_json() -> serde_json::Value {
    serde_json::json!({
        "chain_id": "eip155:8453",
        "observed_block_number": 12_345_678,
        "latest_block_number": 12_345_701,
        "max_block_lag": 128,
        "root_registry_address": "0x1000000000000000000000000000000000000001",
        "registry_root": "0x7957ab2da3ec75f08ced4377529cbd734388429ff60bbed4dae520308f017381",
        "block": {
            "block_number": 12_345_678,
            "block_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transaction_hashes": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ]
        },
        "escrow": {
            "escrow_id": "escrow-web3-1",
            "escrow_contract": "0x1000000000000000000000000000000000000002",
            "beneficiary_address": "0x2222222222222222222222222222222222222222",
            "locked_amount": {
                "units": 150,
                "currency": "USD"
            },
            "released_amount": {
                "units": 150,
                "currency": "USD"
            }
        },
        "bond": {
            "bond_vault_contract": "0x1000000000000000000000000000000000000003",
            "posted_amount": {
                "units": 150,
                "currency": "USD"
            },
            "minimum_required_amount": {
                "units": 150,
                "currency": "USD"
            }
        },
        "beneficiary_identity_binding": {
            "certificate": {
                "schema": "chio.key-binding-certificate.v1",
                "chio_identity": "did:chio:91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",
                "chio_public_key": "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",
                "chain_scope": ["eip155:8453"],
                "purpose": ["settle"],
                "settlement_address": "0x2222222222222222222222222222222222222222",
                "issued_at": 1_743_292_800,
                "expires_at": 1_774_828_800,
                "nonce": "beneficiary-identity-binding-0001"
            },
            "signature": "46b03d7b81e48864ab510ce269f4a6ec96a56b187b6575668ac4a83440e53c3b6b94ba112ed3604b07b12a10f20b8373cac214098efc41d2351b8180dde11f00"
        }
    })
}

fn assert_public_settlement_mutation_rejected(
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_stderr: &str,
) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);
    mutate_public_settlement_bundle(&bundle_dir, mutate);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains(expected_stderr),
        "stderr did not contain {expected_stderr:?}: {stderr}"
    );
}

fn set_agent_web_manifest_unsupported_claims(
    bundle_dir: &std::path::Path,
    manifest_path: &str,
    unsupported_claims: serde_json::Value,
) -> PathBuf {
    let manifest_path = bundle_dir.join(manifest_path);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("parse manifest");
    manifest["unsupported_claims"] = unsupported_claims;
    let manifest_bytes = serde_json::to_vec(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, &manifest_bytes).test_expect("write manifest");
    let manifest_digest = chio_core::sha256_hex(&manifest_bytes);

    let manifest_file_name = manifest_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .test_expect("manifest path has file name");
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some(manifest_file_name) {
            node["sha256"] = serde_json::Value::String(manifest_digest.clone());
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
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_digest);
    std::fs::write(
        &passport_path,
        serde_json::to_vec(&passport).test_expect("serialize passport"),
    )
    .test_expect("write passport");

    passport_path
}

fn mutate_commerce_event_log(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let event_log_path = bundle_dir.join("event-log.json");
    let mut event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("parse event log");
    mutate(&mut event_log);
    let event_log_bytes = serde_json::to_vec(&event_log).test_expect("serialize event log");
    std::fs::write(&event_log_path, &event_log_bytes).test_expect("write event log");
    let event_log_digest = chio_core::sha256_hex(&event_log_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["event_log_sha256"] = serde_json::Value::String(event_log_digest.clone());
    let order_context_bytes =
        serde_json::to_vec(&order_context).test_expect("serialize order context");
    std::fs::write(&order_context_path, &order_context_bytes).test_expect("write order context");
    let order_context_digest = chio_core::sha256_hex(&order_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        match node.get("path").and_then(serde_json::Value::as_str) {
            Some("event-log.json") => {
                node["sha256"] = serde_json::Value::String(event_log_digest.clone());
            }
            Some("order-context.json") => {
                node["sha256"] = serde_json::Value::String(order_context_digest.clone());
            }
            _ => {}
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

#[test]
fn proof_verify_accepts_minimal_passport_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("valid"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"schema\":\"chio.transaction.verifier-report.v1\""));
    assert!(stdout.contains("\"id\":\"verifier-report-passport-minimal-valid\""));
    assert!(stdout.contains("\"issued_at\":\"2026-06-10T00:00:00Z\""));
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains("\"passport_id\":\"passport-minimal-valid\""));
}

#[test]
fn proof_verify_accepts_minimal_passport_bundle_directory() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(workspace_root().join("fixtures/proof-room/minimal-passport/valid"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
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

    write_minimal_evidence_graph(
        &bundle_dir,
        serde_json::json!({
            "schema": "chio.transaction.evidence-graph.v1",
            "id": "evidence-graph-minimal-missing-governed-action",
            "issued_at": "2026-06-10T00:00:00Z",
            "nodes": [
                {
                    "id": "verifier-policy",
                    "schema": "chio.transaction.verifier-policy.v1",
                    "path": "verifier-policy.json",
                    "sha256": "3f562106e60d01c801571ab725ce3d9c8f5cf35451ae9e5d08c1fff1bf005bfe",
                    "role": "verifier-policy"
                }
            ],
            "edges": []
        }),
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_rejects_minimal_passport_missing_governed_action_artifact() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle_dir = tempdir.path().join("minimal-passport");
    copy_dir_all(&source, &bundle_dir);
    std::fs::remove_file(bundle_dir.join("kernel-receipt.json"))
        .test_expect("remove receipt artifact");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(workspace_root().join("fixtures/proof-room/minimal-passport/valid"))
        .arg("--out")
        .arg(&report_path)
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("unknown-passport-schema"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("unsupported transaction passport schema"));
}

#[test]
fn proof_verify_rejects_evidence_graph_digest_mismatch_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("evidence-graph-digest-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("evidence graph digest mismatch"));
}

#[test]
fn proof_verify_rejects_stale_capability_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("stale-capability"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("capability proof expired before evidence graph issuance"));
}

#[test]
fn proof_verify_accepts_runtime_passport_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_accepts_runtime_infrastructure_failure_receipt_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_accepts_agent_web_interop_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

        let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

        let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
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
    assert!(stdout.contains("\"posted_bond_amount\":{\"currency\":\"USD\",\"units\":150}"));
    assert!(stdout.contains("\"minimum_bond_amount\":{\"currency\":\"USD\",\"units\":150}"));
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ]);
        },
        "public settlement tx hash not included in block",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["dispute_snapshot"]["chain_event_tx_hashes"] = serde_json::json!([
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            ]);
        },
        "public settlement dispute event tx hash not included in block",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle["chain_snapshot"] = public_settlement_chain_snapshot_json();
            settlement_bundle["chain_snapshot"]
                .as_object_mut()
                .test_expect("chain snapshot object")
                .remove("beneficiary_identity_binding");
        },
        "public settlement beneficiary identity binding missing",
    );
    assert_public_settlement_mutation_rejected(
        |settlement_bundle| {
            settlement_bundle
                .as_object_mut()
                .test_expect("settlement proof bundle object")
                .remove("dispute_snapshot");
        },
        "public settlement dispute snapshot missing",
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

    let policy_path = bundle_dir.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("parse verifier policy");
    policy["required_claims"]
        .as_array_mut()
        .test_expect("required claims array")
        .push(serde_json::Value::String(
            "claim.public_settlement.future_claim_not_emitted".to_string(),
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
    std::fs::write(
        &passport_path,
        serde_json::to_vec(&passport).test_expect("serialize passport"),
    )
    .test_expect("write passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "required public settlement claim not verified: claim.public_settlement.future_claim_not_emitted"
    ));
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
    std::fs::write(
        &passport_path,
        serde_json::to_vec(&passport).test_expect("serialize passport"),
    )
    .test_expect("write passport");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(passport_path)
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    assert!(stdout.contains("\"claim.commerce.order_replay_consistent\""));
    assert!(stdout.contains("\"claim.commerce.payment_lifecycle_bound\""));
    assert!(stdout.contains("\"claim.commerce.mandate_allowance_bound\""));
}

#[test]
fn proof_verify_rejects_commerce_payment_wrong_merchant_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_rejects_commerce_event_log_invalid_timestamp() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle_dir = tempdir.path().join("commerce-payments");
    copy_dir_all(&source, &bundle_dir);
    mutate_commerce_event_log(&bundle_dir, |event_log| {
        event_log["events"][0]["occurred_at"] = serde_json::Value::String("not-a-timestamp".into());
    });

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    assert!(stdout.contains("\"taskCount\":3"));
    assert!(stdout.contains("\"continuationCount\":2"));
    assert!(stdout.contains("\"claim.swarm.task_graph_bound\""));
    assert!(stdout.contains("\"claim.swarm.continuation_fresh\""));
    assert!(stdout.contains("\"claim.swarm.attenuation_witness_chain_bound\""));
    assert!(stdout.contains("\"claim.swarm.route_plan_bound\""));
    assert!(stdout.contains("\"claim.swarm.join_receipt_bound\""));
    assert!(stdout.contains("\"claim.swarm.budget_pool_bound\""));
    assert!(stdout.contains("\"claim.swarm.revocation_epoch_bound\""));
}

#[test]
fn proof_verify_accepts_disclosure_lineage_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    assert!(stdout.contains("\"claim.disclosure.lineage_subgraph_bound\""));
    assert!(stdout.contains("\"claim.disclosure.leakage_ledger_complete\""));
}

#[test]
fn proof_verify_rejects_disclosure_lineage_missing_ledger_entry_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_accepts_disclosure_crypto_context_required_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_disclosure_crypto_context_report(&bundle_dir);
    set_disclosure_policy_required_claims(&bundle_dir, &["claim.disclosure.crypto_context_bound"]);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_rejects_disclosure_lineage_missing_crypto_context_report() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    remove_disclosure_crypto_context_report(&bundle_dir);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
fn proof_verify_rejects_policy_digest_mismatch_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(fixture_path("invalid-policy-digest-mismatch"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("verifier policy digest mismatch"));
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

    let passport = format!(
        "{{\"schema\":\"chio.transaction-passport.v1\",\"id\":\"passport-symlink-escape\",\"issued_at\":\"2026-06-10T00:00:00Z\",\"evidence_graph_sha256\":\"{}\",\"evidence_graph_path\":\"evidence-graph.json\",\"verifier_policy_sha256\":\"{}\",\"verifier_policy_path\":\"verifier-policy.json\"}}",
        chio_core::sha256_hex(evidence_graph.as_bytes()),
        chio_core::sha256_hex(verifier_policy.as_bytes())
    );
    let passport_path = bundle_dir.join("transaction-passport.json");
    write_file(&passport_path, &passport);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("proof")
        .arg("verify")
        .arg(runtime_fixture_path("missing-execution-lease"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("missing execution lease"));
}
