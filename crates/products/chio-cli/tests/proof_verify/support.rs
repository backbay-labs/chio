use chio_test_support::prelude::*;
use std::path::PathBuf;

pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";
const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
const PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
);
const AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS: &str = concat!(
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
    "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
    "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737,",
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
);
const AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const SWARM_FIXTURE_TRUSTED_WITNESS_KEYS: &str =
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de";
const TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a,",
    "68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96"
);
const RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS: &str =
    "5b8649c0cfcdbe78a5ff962edfa48914dfd45af22afe358de1f4dd7e4567d5ca";
const ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS: &str =
    "f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d";
const ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS: &str =
    "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2";
const COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS: &str =
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";
const TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS: &str =
    "cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS: &str =
    "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS: &str =
    "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c";

pub(crate) fn chio_with_agent_web_fixture_secret() -> std::process::Command {
    let mut command = chio_with_transaction_fixture_roots();
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
    let mut command = chio_with_transaction_fixture_roots();
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

pub(crate) fn chio_with_trust_market_fixture_authority() -> std::process::Command {
    let mut command = chio_with_transaction_fixture_roots();
    command.env(
        "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
        TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS,
    );
    command
}

pub(crate) fn chio_with_transaction_fixture_roots() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    command.env(
        "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS",
        PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS,
    );
    command.env(
        "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
        TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS,
    );
    command.env(
        "CHIO_RUNTIME_TRUSTED_ROOT_KEYS",
        RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS,
    );
    command.env(
        "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS",
        ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS,
    );
    command.env(
        "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS",
        ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS,
    );
    command.env(
        "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
        COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
    );
    command.env(
        "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
        SWARM_FIXTURE_TRUSTED_WITNESS_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS",
        "eip155:8453,eip155:42161",
    );
    command.env("CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS", "1");
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
    if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("transaction-passport.json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(contents) {
            std::fs::write(path, json_bytes(value)).test_expect("write test fixture");
            return;
        }
    }
    std::fs::write(path, contents).test_expect("write test fixture");
}

fn json_bytes(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&sign_transaction_passport_if_needed(value))
        .test_expect("serialize test fixture")
}

pub(crate) fn write_json(path: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(path, json_bytes(value.clone())).test_expect("write test fixture");
}

fn sign_transaction_passport_if_needed(mut value: serde_json::Value) -> serde_json::Value {
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("chio.transaction-passport.v1")
    {
        return value;
    }

    let keypair = chio_core::Keypair::from_seed(&TEST_SIGNATURE_SEED);
    value["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    value["signature"] = serde_json::Value::String(String::new());
    let passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_value(value.clone()).test_expect("parse transaction passport");
    let signature =
        chio_control_plane::transaction_passport::sign_transaction_passport(&passport, &keypair)
            .test_expect("sign transaction passport");
    value["signature"] = serde_json::Value::String(signature);
    value
}

pub(crate) fn copy_dir_all(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).test_expect("create destination dir");
    for entry in std::fs::read_dir(source).test_expect("read source dir") {
        let entry = entry.test_expect("read source entry");
        let file_name = entry.file_name();
        if matches!(
            file_name.to_str(),
            Some("manifest.json" | "bundle-signature.dsse.json")
        ) {
            continue;
        }
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
        "projection_manifest_ref": "chio.bbs-projection.receipt.v1",
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

pub(crate) fn add_disclosure_crypto_verification_context(bundle_dir: &std::path::Path) {
    let verification_context_path = bundle_dir.join("verification-context.json");
    let verification_context = serde_json::json!({
        "schema": "chio.crypto.verification-context.v1",
        "context_id": "crypto-context-valid",
        "artifact_ref": "disclosure-capsule-valid",
        "proof_mechanism": "bbs",
        "issuer": "did:chio:issuer-bbs",
        "issuer_key_ref": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "key_state": {
            "schema": "chio.trust.key-state.v1",
            "key_ref": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "status": "active",
            "epoch": 7,
            "valid_from": 1766000000,
            "valid_until": 1766000900
        },
        "algorithm": "bbs-bls12381-sha256",
        "suite": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
        "hash_algorithm": "sha-256",
        "canonicalization": "jcs",
        "signature_ref": "bbs-proof",
        "verification_time": 1766000100,
        "revocation_snapshot": {
            "schema": "chio.trust.revocation-snapshot.v1",
            "snapshot_ref": "revocation-snapshot-buyer-auditor",
            "status": "fresh",
            "issued_at": 1766000050,
            "expires_at": 1766000350
        },
        "audience": "https://auditor.example/chio",
        "nonce_hex": "6e6f6e63652d63727970746f2d636f6e74657874",
        "nonce_replay_status": "fresh",
        "holder_binding_ref": "holder:buyer-agent",
        "holder_binding_status": "bound",
        "transparency_state": "anchored",
        "presentation_created_at": 1766000080
    });
    let verification_context_bytes =
        serde_json::to_vec(&verification_context).test_expect("serialize verification context");
    std::fs::write(&verification_context_path, &verification_context_bytes)
        .test_expect("write verification context");
    let verification_context_digest = chio_core::sha256_hex(&verification_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes");
    nodes.retain(|node| {
        node.get("role").and_then(serde_json::Value::as_str) != Some("crypto-verification-context")
    });
    nodes.push(serde_json::json!({
        "id": "crypto-verification-context",
        "schema": "chio.crypto.verification-context.v1",
        "path": "verification-context.json",
        "sha256": verification_context_digest,
        "role": "crypto-verification-context"
    }));
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

pub(crate) fn add_valid_disclosure_selective_disclosure_proof(bundle_dir: &std::path::Path) {
    let capsule_bytes =
        std::fs::read(bundle_dir.join("capsule.json")).test_expect("read disclosure capsule");
    let capsule_digest = chio_core::sha256_hex(&capsule_bytes);
    let keypair = chio_selective_disclosure::generate_bbs_keypair(
        b"chio-proof-verify-bbs-key-material-0001",
        b"chio-proof-verify",
    )
    .test_expect("generate bbs keypair");
    let projection = chio_selective_disclosure::Projection {
        version: chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1.to_string(),
        subject_sha256_hex: capsule_digest,
        messages: vec![
            chio_selective_disclosure::ProjectionMessage {
                index: 0,
                field: "capability_id".to_string(),
                encoding: "S".to_string(),
                bytes_hex: hex::encode(b"cap-disclosure-valid"),
                wholesale_only: false,
            },
            chio_selective_disclosure::ProjectionMessage {
                index: 1,
                field: "tool_name".to_string(),
                encoding: "S".to_string(),
                bytes_hex: hex::encode(b"read_refund_case"),
                wholesale_only: false,
            },
        ],
    };
    let signed = chio_selective_disclosure::sign_projection(&projection, &keypair)
        .test_expect("sign disclosure projection");
    let proof = chio_selective_disclosure::derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &chio_selective_disclosure::DisclosureSet(vec![0, 1]),
        b"nonce-crypto-context",
    )
    .test_expect("derive selective disclosure proof");
    let proof_bytes = serde_json::to_vec(&proof).test_expect("serialize disclosure proof");
    std::fs::write(
        bundle_dir.join("selective-disclosure-proof.json"),
        &proof_bytes,
    )
    .test_expect("write disclosure proof");
    let proof_digest = chio_core::sha256_hex(&proof_bytes);
    let transparency_leaf_hash = chio_core::sha256_hex(proof.subject_sha256_hex.as_bytes());
    let transparency_inclusion = serde_json::json!({
        "schema": chio_selective_disclosure::TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1,
        "proof_id": "transparency-inclusion-proof-disclosure-valid",
        "log_id": "transparency-log-fixture",
        "artifact_ref": proof.subject_sha256_hex.clone(),
        "root_hash": transparency_leaf_hash.clone(),
        "leaf_hash": transparency_leaf_hash,
        "tree_size": 1,
        "leaf_index": 0,
        "checkpoint": "transparency-log-fixture:1",
        "inclusion_path": [],
        "verified_at": 1766000100
    });
    write_json(
        &bundle_dir.join("transparency-inclusion-proof.json"),
        &transparency_inclusion,
    );
    let transparency_inclusion_digest = chio_core::sha256_hex(
        &std::fs::read(bundle_dir.join("transparency-inclusion-proof.json"))
            .test_expect("read transparency inclusion proof"),
    );
    let projection_manifest =
        chio_selective_disclosure::bbs_projection_manifest_from_projection(&projection);
    let projection_manifest_bytes =
        serde_json::to_vec(&projection_manifest).test_expect("serialize BBS projection manifest");
    std::fs::write(
        bundle_dir.join("bbs-projection-manifest.json"),
        &projection_manifest_bytes,
    )
    .test_expect("write BBS projection manifest");
    let projection_manifest_digest = chio_core::sha256_hex(&projection_manifest_bytes);

    let privacy_profile_path = bundle_dir.join("privacy-profile.json");
    let mut privacy_profile: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&privacy_profile_path).test_expect("read privacy profile"),
    )
    .test_expect("parse privacy profile");
    privacy_profile["allowed_issuer_keys"] =
        serde_json::json!([keypair.issuer_fingerprint.clone()]);
    let privacy_profile_bytes =
        serde_json::to_vec(&privacy_profile).test_expect("serialize privacy profile");
    std::fs::write(&privacy_profile_path, &privacy_profile_bytes)
        .test_expect("write privacy profile");
    let privacy_profile_digest = chio_core::sha256_hex(&privacy_profile_bytes);

    let verification_context_path = bundle_dir.join("verification-context.json");
    let mut verification_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verification_context_path).test_expect("read verification context"),
    )
    .test_expect("parse verification context");
    verification_context["issuer_key_ref"] =
        serde_json::Value::String(keypair.issuer_fingerprint.clone());
    verification_context["key_state"]["key_ref"] =
        serde_json::Value::String(keypair.issuer_fingerprint.clone());
    verification_context["nonce_hex"] = serde_json::Value::String(proof.proof_nonce_hex.clone());
    let verification_context_bytes =
        serde_json::to_vec(&verification_context).test_expect("serialize verification context");
    std::fs::write(&verification_context_path, &verification_context_bytes)
        .test_expect("write verification context");
    let verification_context_digest = chio_core::sha256_hex(&verification_context_bytes);

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes");
    nodes.retain(|node| {
        node.get("role").and_then(serde_json::Value::as_str) != Some("selective-disclosure-proof")
    });
    for node in nodes.iter_mut() {
        match node.get("role").and_then(serde_json::Value::as_str) {
            Some("disclosure-verifier-privacy-profile") => {
                node["sha256"] = serde_json::Value::String(privacy_profile_digest.clone());
            }
            Some("crypto-verification-context") => {
                node["sha256"] = serde_json::Value::String(verification_context_digest.clone());
            }
            _ => {}
        }
    }
    nodes.push(serde_json::json!({
        "id": "selective-disclosure-proof",
        "schema": "chio.attest.selective-disclosure-proof.v1",
        "path": "selective-disclosure-proof.json",
        "sha256": proof_digest,
        "role": "selective-disclosure-proof"
    }));
    nodes.retain(|node| {
        node.get("role").and_then(serde_json::Value::as_str) != Some("bbs-projection-manifest")
    });
    nodes.push(serde_json::json!({
        "id": "bbs-projection-manifest",
        "schema": "chio.bbs-projection.manifest.v1",
        "path": "bbs-projection-manifest.json",
        "sha256": projection_manifest_digest,
        "role": "bbs-projection-manifest"
    }));
    nodes.retain(|node| {
        node.get("role").and_then(serde_json::Value::as_str) != Some("transparency-inclusion-proof")
    });
    nodes.push(serde_json::json!({
        "id": "transparency-inclusion-proof",
        "schema": "chio.transparency.inclusion-proof.v1",
        "path": "transparency-inclusion-proof.json",
        "sha256": transparency_inclusion_digest,
        "role": "transparency-inclusion-proof"
    }));
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges");
    edges.retain(|edge| {
        edge.get("to").and_then(serde_json::Value::as_str) != Some("selective-disclosure-proof")
    });
    edges.push(serde_json::json!({
        "from": "crypto-verification-context",
        "to": "selective-disclosure-proof",
        "predicate": "verifies",
        "evidence_class": "cryptographic-proof"
    }));
    edges.push(serde_json::json!({
        "from": "bbs-projection-manifest",
        "to": "selective-disclosure-proof",
        "predicate": "defines",
        "evidence_class": "projection-manifest"
    }));
    edges.push(serde_json::json!({
        "from": "transparency-inclusion-proof",
        "to": "selective-disclosure-proof",
        "predicate": "anchors",
        "evidence_class": "transparency-inclusion"
    }));
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

pub(crate) fn add_disclosure_bbs_projection_manifest(
    bundle_dir: &std::path::Path,
    message_slots: serde_json::Value,
) {
    let proof_path = bundle_dir.join("selective-disclosure-proof.json");
    let proof: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&proof_path).test_expect("read BBS proof"))
            .test_expect("parse BBS proof");
    let proof_subject = proof
        .get("subject_sha256_hex")
        .and_then(serde_json::Value::as_str)
        .test_expect("BBS proof has subject digest");
    let manifest = serde_json::json!({
        "schema": "chio.bbs-projection.manifest.v1",
        "manifest_id": "chio.bbs-projection.receipt.v1",
        "artifact_ref": proof_subject,
        "canonicalization": "jcs",
        "hash_algorithm": "sha-256",
        "message_slots": message_slots,
        "hidden_predicates": []
    });
    let manifest_path = bundle_dir.join("bbs-projection-manifest.json");
    write_json(&manifest_path, &manifest);
    let manifest_digest = chio_core::sha256_hex(
        &std::fs::read(&manifest_path).test_expect("read BBS projection manifest"),
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
        node.get("role").and_then(serde_json::Value::as_str) != Some("bbs-projection-manifest")
    });
    nodes.push(serde_json::json!({
        "id": "bbs-projection-manifest",
        "schema": "chio.bbs-projection.manifest.v1",
        "path": "bbs-projection-manifest.json",
        "sha256": manifest_digest,
        "role": "bbs-projection-manifest"
    }));
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges");
    edges.retain(|edge| {
        edge.get("from").and_then(serde_json::Value::as_str) != Some("bbs-projection-manifest")
            && edge.get("to").and_then(serde_json::Value::as_str) != Some("bbs-projection-manifest")
    });
    edges.push(serde_json::json!({
        "from": "bbs-projection-manifest",
        "to": "selective-disclosure-proof",
        "predicate": "defines",
        "evidence_class": "projection-manifest"
    }));
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn add_bad_disclosure_transparency_inclusion_proof(bundle_dir: &std::path::Path) {
    let proof_path = bundle_dir.join("selective-disclosure-proof.json");
    let proof: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&proof_path).test_expect("read BBS proof"))
            .test_expect("parse BBS proof");
    let proof_subject = proof
        .get("subject_sha256_hex")
        .and_then(serde_json::Value::as_str)
        .test_expect("BBS proof has subject digest");
    let leaf_hash = chio_core::sha256_hex(proof_subject.as_bytes());
    let inclusion_proof = serde_json::json!({
        "schema": "chio.transparency.inclusion-proof.v1",
        "proof_id": "transparency-inclusion-proof-bad-root",
        "log_id": "transparency-log-fixture",
        "artifact_ref": proof_subject,
        "root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "leaf_hash": leaf_hash,
        "tree_size": 1,
        "leaf_index": 0,
        "checkpoint": "transparency-log-fixture:1",
        "inclusion_path": [],
        "verified_at": 1766000100
    });
    let inclusion_path = bundle_dir.join("transparency-inclusion-proof.json");
    write_json(&inclusion_path, &inclusion_proof);
    let inclusion_digest = chio_core::sha256_hex(
        &std::fs::read(&inclusion_path).test_expect("read transparency inclusion proof"),
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
        node.get("role").and_then(serde_json::Value::as_str) != Some("transparency-inclusion-proof")
    });
    nodes.push(serde_json::json!({
        "id": "transparency-inclusion-proof",
        "schema": "chio.transparency.inclusion-proof.v1",
        "path": "transparency-inclusion-proof.json",
        "sha256": inclusion_digest,
        "role": "transparency-inclusion-proof"
    }));
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges");
    edges.retain(|edge| {
        edge.get("from").and_then(serde_json::Value::as_str) != Some("transparency-inclusion-proof")
            && edge.get("to").and_then(serde_json::Value::as_str)
                != Some("transparency-inclusion-proof")
    });
    edges.push(serde_json::json!({
        "from": "transparency-inclusion-proof",
        "to": "selective-disclosure-proof",
        "predicate": "anchors",
        "evidence_class": "transparency-inclusion"
    }));
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );
}

pub(crate) fn remove_disclosure_crypto_verification_context(bundle_dir: &std::path::Path) {
    remove_disclosure_evidence_graph_node(bundle_dir, "crypto-verification-context");
}

pub(crate) fn remove_disclosure_selective_disclosure_proof(bundle_dir: &std::path::Path) {
    remove_disclosure_evidence_graph_node(bundle_dir, "selective-disclosure-proof");
}

fn remove_disclosure_evidence_graph_node(bundle_dir: &std::path::Path, node_id: &str) {
    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .retain(|node| node.get("id").and_then(serde_json::Value::as_str) != Some(node_id));
    evidence_graph["edges"]
        .as_array_mut()
        .test_expect("evidence graph edges")
        .retain(|edge| {
            edge.get("from").and_then(serde_json::Value::as_str) != Some(node_id)
                && edge.get("to").and_then(serde_json::Value::as_str) != Some(node_id)
        });
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    let evidence_graph_digest = chio_core::sha256_hex(&evidence_graph_bytes);
    set_passport_digest(bundle_dir, "evidence_graph_sha256", evidence_graph_digest);
}

pub(crate) fn sign_disclosure_crypto_context_report(report: &mut serde_json::Value) {
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

pub(crate) fn remove_disclosure_crypto_context_verified_claim(
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
        .retain(|verified_claim| verified_claim.as_str() != Some(claim));
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
    std::fs::write(&passport_path, json_bytes(passport)).test_expect("write passport");
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
    assert_public_settlement_mutation_rejected_with_codes(mutate, expected_stderr, &[]);
}

pub(crate) fn assert_public_settlement_mutation_rejected_with_codes(
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_stderr: &str,
    expected_codes: &[&str],
) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle_dir = tempdir.path().join("public-settlement");
    copy_dir_all(&source, &bundle_dir);
    mutate_public_settlement_bundle(&bundle_dir, mutate);

    let output = chio_with_transaction_fixture_roots()
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
    for expected_code in expected_codes {
        assert!(
            stderr.contains(expected_code),
            "stderr did not contain {expected_code:?}: {stderr}"
        );
    }
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
    let projection_id = manifest
        .get("projection_id")
        .and_then(serde_json::Value::as_str)
        .test_expect("Agent Web manifest has projection id")
        .to_string();
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
        if node.get("role").and_then(serde_json::Value::as_str) == Some("agent-web-proof-envelope")
        {
            let Some(envelope_path) = node.get("path").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let full_envelope_path = bundle_dir.join(envelope_path);
            let mut envelope: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&full_envelope_path).test_expect("read Agent Web envelope"),
            )
            .test_expect("parse Agent Web envelope");
            if envelope
                .get("projection_manifest_ref")
                .and_then(serde_json::Value::as_str)
                != Some(projection_id.as_str())
            {
                continue;
            }
            envelope["projection_manifest_sha256"] =
                serde_json::Value::String(manifest_digest.clone());
            sign_agent_web_fixture_envelope(&mut envelope);
            let envelope_bytes =
                serde_json::to_vec(&envelope).test_expect("serialize Agent Web envelope");
            std::fs::write(&full_envelope_path, &envelope_bytes)
                .test_expect("write Agent Web envelope");
            node["sha256"] = serde_json::Value::String(chio_core::sha256_hex(&envelope_bytes));
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
    std::fs::write(&passport_path, json_bytes(passport)).test_expect("write passport");

    passport_path
}

fn sign_agent_web_fixture_envelope(envelope: &mut serde_json::Value) {
    let keypair = chio_core::Keypair::from_seed(&[17u8; 32]);
    let public_key = keypair.public_key().to_hex();
    envelope["envelope_id"] = serde_json::Value::String(agent_web_envelope_id(envelope));
    let payload = agent_web_envelope_signature_payload(envelope);
    let canonical =
        chio_core_types::canonical_json_bytes(&payload).test_expect("canonical envelope payload");
    let signature = keypair.sign(&canonical).to_hex();
    envelope["signature"] =
        serde_json::Value::String(format!("sig-ed25519:{public_key}:{signature}"));
}

fn agent_web_envelope_signature_payload(envelope: &serde_json::Value) -> serde_json::Value {
    agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "envelope_id",
            "transaction_passport_ref",
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

fn agent_web_envelope_id(envelope: &serde_json::Value) -> String {
    let payload = agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "transaction_passport_ref",
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
        chio_core_types::canonical_json_bytes(&payload).test_expect("canonical envelope id");
    chio_core::sha256_hex(&canonical)
}

fn agent_web_envelope_payload(envelope: &serde_json::Value, fields: &[&str]) -> serde_json::Value {
    let object = envelope
        .as_object()
        .test_expect("Agent Web envelope is an object");
    let mut payload = serde_json::Map::new();
    for field in fields {
        payload.insert(
            (*field).to_string(),
            object
                .get(*field)
                .test_expect("Agent Web envelope has signed field")
                .clone(),
        );
    }
    serde_json::Value::Object(payload)
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
    seal_commerce_event_log_events(&mut event_log);
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

fn seal_commerce_event_log_events(event_log: &mut serde_json::Value) {
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        let event_object = event
            .as_object_mut()
            .test_expect("event log event is an object");
        event_object.remove("event_sha256");
        let canonical = chio_core_types::canonical_json_bytes(event)
            .test_expect("event log event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(chio_core::sha256_hex(&canonical));
    }
}

pub(crate) fn mutate_commerce_payment_lifecycle(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let payment_lifecycle_path = bundle_dir.join("payment-lifecycle.json");
    let mut payment_lifecycle: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&payment_lifecycle_path).test_expect("read payment lifecycle"),
    )
    .test_expect("parse payment lifecycle");
    mutate(&mut payment_lifecycle);
    sign_commerce_payment_lifecycle(&mut payment_lifecycle);
    let payment_lifecycle_bytes =
        serde_json::to_vec(&payment_lifecycle).test_expect("serialize payment lifecycle");
    std::fs::write(&payment_lifecycle_path, &payment_lifecycle_bytes)
        .test_expect("write payment lifecycle");
    let payment_lifecycle_digest = chio_core::sha256_hex(&payment_lifecycle_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(payment_lifecycle_digest.clone());
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
            Some("payment-lifecycle.json") => {
                node["sha256"] = serde_json::Value::String(payment_lifecycle_digest.clone());
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

pub(crate) fn mutate_commerce_mandate_ledger(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mandate_path = bundle_dir.join("mandate-allowance-ledger.json");
    let mut mandate_ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&mandate_path).test_expect("read mandate ledger"))
            .test_expect("parse mandate ledger");
    mutate(&mut mandate_ledger);
    let mandate_ledger_bytes =
        serde_json::to_vec(&mandate_ledger).test_expect("serialize mandate ledger");
    std::fs::write(&mandate_path, &mandate_ledger_bytes).test_expect("write mandate ledger");
    let mandate_ledger_digest = chio_core::sha256_hex(&mandate_ledger_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["mandate_ledger_sha256"] =
        serde_json::Value::String(mandate_ledger_digest.clone());
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
            Some("mandate-allowance-ledger.json") => {
                node["sha256"] = serde_json::Value::String(mandate_ledger_digest.clone());
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

pub(crate) fn mutate_commerce_provider_passport(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let provider_passport_path = bundle_dir.join("provider-passport.json");
    let mut provider_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&provider_passport_path).test_expect("read provider passport"),
    )
    .test_expect("parse provider passport");
    mutate(&mut provider_passport);
    let provider_passport_bytes =
        serde_json::to_vec(&provider_passport).test_expect("serialize provider passport");
    std::fs::write(&provider_passport_path, &provider_passport_bytes)
        .test_expect("write provider passport");
    let provider_passport_digest = chio_core::sha256_hex(&provider_passport_bytes);

    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    order_context["provider_passport_sha256"] =
        serde_json::Value::String(provider_passport_digest.clone());
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
            Some("provider-passport.json") => {
                node["sha256"] = serde_json::Value::String(provider_passport_digest.clone());
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

pub(crate) fn mutate_commerce_order_context(
    bundle_dir: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let order_context_path = bundle_dir.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("parse order context");
    mutate(&mut order_context);
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
        if node.get("path").and_then(serde_json::Value::as_str) == Some("order-context.json") {
            node["sha256"] = serde_json::Value::String(order_context_digest.clone());
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

fn sign_commerce_payment_lifecycle(payment_lifecycle: &mut serde_json::Value) {
    let keypair = chio_core::Keypair::from_seed(&TEST_SIGNATURE_SEED);
    payment_lifecycle["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    payment_lifecycle
        .as_object_mut()
        .test_expect("payment lifecycle object")
        .remove("signature");
    let (signature, _) = keypair
        .sign_canonical(payment_lifecycle)
        .test_expect("sign payment lifecycle");
    payment_lifecycle["signature"] = serde_json::Value::String(signature.to_hex());
}
