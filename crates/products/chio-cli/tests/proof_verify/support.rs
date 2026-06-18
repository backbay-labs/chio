use chio_test_support::prelude::*;
use std::path::PathBuf;

pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";
const AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS: &str = concat!(
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
    "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
    "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737,",
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
);
const AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

pub(crate) fn chio_with_agent_web_fixture_secret() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    command.env(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
        STANDARD_WEBHOOKS_VERIFIER_SECRET,
    );
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS,
    );
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS,
    );
    command
}

pub(crate) fn chio_with_agent_web_fixture_trust_without_webhooks_secret() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS,
    );
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS,
    );
    command.env_remove("CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET");
    command
}

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

pub(crate) fn fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/minimal-passport/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn runtime_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/runtime-security/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn enterprise_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/enterprise-export/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn agent_web_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/agent-web/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn trust_market_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/trust-market/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn public_settlement_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/public-settlement/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn commerce_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/commerce-payments/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn swarm_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/swarm-authority/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn disclosure_lineage_fixture_path(case_name: &str) -> PathBuf {
    workspace_root().join(format!(
        "fixtures/proof-room/disclosure-lineage/{case_name}/transaction-passport.json"
    ))
}

pub(crate) fn write_file(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).test_expect("write test fixture");
}

pub(crate) fn copy_dir_all(source: &std::path::Path, destination: &std::path::Path) {
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

pub(crate) fn add_disclosure_crypto_context_report(bundle_dir: &std::path::Path) {
    let crypto_context_report_path = bundle_dir.join("crypto-context-report.json");
    let mut crypto_context_report = serde_json::json!({
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
    sign_disclosure_crypto_context_report(&mut crypto_context_report);
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

fn sign_disclosure_crypto_context_report(report: &mut serde_json::Value) {
    let report_value: chio_selective_disclosure::DisclosureCryptoContextReport =
        serde_json::from_value(report.clone()).test_expect("parse crypto report");
    let signature = chio_selective_disclosure::sign_crypto_context_report(
        &report_value,
        &chio_core::Keypair::from_seed(&[29u8; 32]),
    )
    .test_expect("sign crypto report");
    report["signature"] = serde_json::Value::String(signature);
}

pub(crate) fn add_disclosure_crypto_context_verified_claim(
    bundle_dir: &std::path::Path,
    claim: &str,
) {
    let crypto_context_report_path = bundle_dir.join("crypto-context-report.json");
    let mut crypto_context_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&crypto_context_report_path).test_expect("read crypto report"),
    )
    .test_expect("parse crypto report");
    crypto_context_report["verified_claims"]
        .as_array_mut()
        .test_expect("verified claims are an array")
        .push(serde_json::Value::String(claim.to_string()));
    sign_disclosure_crypto_context_report(&mut crypto_context_report);
    let crypto_context_report_bytes =
        serde_json::to_vec(&crypto_context_report).test_expect("serialize crypto report");
    std::fs::write(&crypto_context_report_path, &crypto_context_report_bytes)
        .test_expect("write crypto report");
    let crypto_context_report_digest = chio_core::sha256_hex(&crypto_context_report_bytes);

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
            == Some("disclosure-crypto-context-report")
        {
            node["sha256"] = serde_json::Value::String(crypto_context_report_digest.clone());
        }
    }
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

pub(crate) fn remove_disclosure_crypto_context_report(bundle_dir: &std::path::Path) {
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

pub(crate) fn set_disclosure_policy_required_claims(
    bundle_dir: &std::path::Path,
    required_claims: &[&str],
) {
    set_verifier_policy_required_claims(bundle_dir, required_claims);
}

pub(crate) fn set_verifier_policy_required_claims(
    bundle_dir: &std::path::Path,
    required_claims: &[&str],
) {
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
    write_verifier_policy_and_refresh_digests(bundle_dir, policy);
}

pub(crate) fn add_verifier_policy_required_claim(bundle_dir: &std::path::Path, claim: &str) {
    let verifier_policy_path = bundle_dir.join("verifier-policy.json");
    let mut policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("parse verifier policy");
    policy["required_claims"]
        .as_array_mut()
        .test_expect("required claims are an array")
        .push(serde_json::Value::String(claim.to_string()));
    write_verifier_policy_and_refresh_digests(bundle_dir, policy);
}

fn write_verifier_policy_and_refresh_digests(
    bundle_dir: &std::path::Path,
    policy: serde_json::Value,
) {
    let verifier_policy_path = bundle_dir.join("verifier-policy.json");
    let policy_bytes = serde_json::to_vec(&policy).test_expect("serialize verifier policy");
    std::fs::write(&verifier_policy_path, &policy_bytes).test_expect("write verifier policy");
    let policy_digest = chio_core::sha256_hex(&policy_bytes);
    refresh_evidence_graph_verifier_policy_digest(bundle_dir, &policy_digest);
    set_passport_digest(bundle_dir, "verifier_policy_sha256", policy_digest);
}

fn refresh_evidence_graph_verifier_policy_digest(
    bundle_dir: &std::path::Path,
    policy_digest: &str,
) {
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    if !evidence_graph_path.exists() {
        return;
    }
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let mut updated = false;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
    {
        if node.get("role").and_then(serde_json::Value::as_str) == Some("verifier-policy") {
            node["sha256"] = serde_json::Value::String(policy_digest.to_string());
            updated = true;
        }
    }
    if updated {
        let evidence_graph_bytes =
            serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
        std::fs::write(&evidence_graph_path, &evidence_graph_bytes)
            .test_expect("write evidence graph");
        let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
        set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
    }
}

pub(crate) fn duplicate_first_verifier_policy_required_claim(bundle_dir: &std::path::Path) {
    let verifier_policy_path = bundle_dir.join("verifier-policy.json");
    let mut policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verifier_policy_path).test_expect("read verifier policy"),
    )
    .test_expect("parse verifier policy");
    let first_claim = policy["required_claims"]
        .as_array()
        .and_then(|claims| claims.first())
        .cloned()
        .test_expect("verifier policy has required claims");
    policy["required_claims"]
        .as_array_mut()
        .test_expect("required claims are an array")
        .push(first_claim);
    let policy_bytes = serde_json::to_vec(&policy).test_expect("serialize verifier policy");
    std::fs::write(&verifier_policy_path, &policy_bytes).test_expect("write verifier policy");
    set_passport_digest(
        bundle_dir,
        "verifier_policy_sha256",
        chio_core::sha256_hex(&policy_bytes),
    );
}

pub(crate) fn set_passport_digest(
    bundle_dir: &std::path::Path,
    digest_field: &str,
    digest: String,
) {
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

pub(crate) fn write_minimal_evidence_graph(
    bundle_dir: &std::path::Path,
    evidence_graph: serde_json::Value,
) {
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

pub(crate) fn refresh_minimal_evidence_graph_node_digest(
    bundle_dir: &std::path::Path,
    artifact_path: &str,
) {
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

pub(crate) fn write_swarm_json_artifact(
    bundle_dir: &std::path::Path,
    artifact_path: &str,
    artifact: &serde_json::Value,
) {
    let artifact_bytes = serde_json::to_vec(artifact).test_expect("serialize swarm artifact");
    std::fs::write(bundle_dir.join(artifact_path), artifact_bytes)
        .test_expect("write swarm artifact");
    refresh_minimal_evidence_graph_node_digest(bundle_dir, artifact_path);
}

pub(crate) fn expire_swarm_bundle_before_verification_time(bundle_dir: &std::path::Path) {
    let created_at_unix_ms = 1_700_000_000_000_u64;
    let expired_after_created_at_unix_ms = created_at_unix_ms + 600_000;

    let task_graph_path = bundle_dir.join("task-graph.json");
    let mut task_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&task_graph_path).test_expect("read task graph"))
            .test_expect("parse task graph");
    task_graph["createdAtUnixMs"] = serde_json::Value::Number(created_at_unix_ms.into());
    task_graph["expiresAtUnixMs"] =
        serde_json::Value::Number(expired_after_created_at_unix_ms.into());
    write_swarm_json_artifact(bundle_dir, "task-graph.json", &task_graph);

    let typed_task_graph: chio_swarm_authority::SwarmTaskGraph =
        serde_json::from_value(task_graph).test_expect("parse typed task graph");
    let task_graph_hash = chio_core::sha256_hex(
        &chio_core_types::canonical_json_bytes(&typed_task_graph)
            .test_expect("canonicalize task graph"),
    );

    for continuation_path in ["continuation-child-a.json", "continuation-child-b.json"] {
        let path = bundle_dir.join(continuation_path);
        let mut continuation: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).test_expect("read continuation"))
                .test_expect("parse continuation");
        continuation["graphSha256"] = serde_json::Value::String(task_graph_hash.clone());
        continuation["expiresAtUnixMs"] =
            serde_json::Value::Number(expired_after_created_at_unix_ms.into());
        write_swarm_json_artifact(bundle_dir, continuation_path, &continuation);
    }

    for route_path in ["route-child-a.json", "route-child-b.json"] {
        let path = bundle_dir.join(route_path);
        let mut route: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).test_expect("read route plan"))
                .test_expect("parse route plan");
        route["expiresAtUnixMs"] =
            serde_json::Value::Number(expired_after_created_at_unix_ms.into());
        write_swarm_json_artifact(bundle_dir, route_path, &route);
    }

    let revocation_path = bundle_dir.join("revocation-epoch.json");
    let mut revocation: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&revocation_path).test_expect("read revocation epoch"),
    )
    .test_expect("parse revocation epoch");
    revocation["validUntilUnixMs"] =
        serde_json::Value::Number(expired_after_created_at_unix_ms.into());
    write_swarm_json_artifact(bundle_dir, "revocation-epoch.json", &revocation);
}

pub(crate) fn mutate_public_settlement_bundle(
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

pub(crate) fn public_settlement_chain_snapshot_json() -> serde_json::Value {
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

pub(crate) fn assert_public_settlement_mutation_rejected(
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

pub(crate) fn set_agent_web_manifest_unsupported_claims(
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

pub(crate) fn mutate_commerce_event_log(
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
