use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use chio_core_types::Keypair;

use crate::{
    dsse_pre_auth_encoding, proof_room_router as build_proof_room_router,
    proof_room_router_with_fixture_root as build_proof_room_router_with_fixture_root, sha256_hex,
    SourceVerifierContext, PROOF_ROOM_DSSE_PAYLOAD_TYPE,
};

pub(crate) const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
pub(crate) const TEST_RECEIPT_SEED: [u8; 32] = [23; 32];
pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";
const STANDARD_WEBHOOKS_FIXTURE_TIMESTAMP: u64 = 1_770_508_800;
pub(crate) const AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS: &str = concat!(
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
    "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
    "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
    "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21,",
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
);
pub(crate) const AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
pub(crate) const SWARM_FIXTURE_TRUSTED_WITNESS_KEYS: &str =
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de";
pub(crate) const PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS: &str = concat!(
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,",
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,",
    "a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869"
);
pub(crate) const PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
);
pub(crate) const TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a,",
    "68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96"
);
pub(crate) const RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS: &str =
    "5b8649c0cfcdbe78a5ff962edfa48914dfd45af22afe358de1f4dd7e4567d5ca";
pub(crate) const ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS: &str =
    "f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d";
pub(crate) const ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS: &str =
    "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2";
pub(crate) const COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS: &str =
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";
pub(crate) const COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
pub(crate) const COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
pub(crate) const TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS: &str =
    "cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS: &str =
    "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS: &str =
    "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID: &str =
    "chio.official-web3-contracts";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH: &str =
    "0x454a9a92b54a835a2776750196b171501bff6e5c02df1a192616194fc0a095cc";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xfc5d76d87b02096c6ae32ce644a2b98ca0bdf3c56700ad16731fad2062e6bd7f";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xd4f87cc63c00d0640c8f232c8fac5e5cb99bc6cf185ef912225e07fa438614cc";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH: &str =
    "0x03d8f545c330922a33db6473430c50eafd527e04474f31abee2dc1f8c6ab2d36";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH: &str =
    "0x17f7936469584b38404765ac44bd7e2384337983e4bc6448a3500d0637711f09";
pub(crate) const PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}";
pub(crate) const DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS: &str =
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa";

pub(crate) fn configure_agent_web_fixture_secret() {
    static NEXT_REPLAY_STORE: AtomicU64 = AtomicU64::new(0);
    let (verifier_now, max_age_seconds) = standard_webhooks_clock_env();
    std::env::set_var(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
        STANDARD_WEBHOOKS_VERIFIER_SECRET,
    );
    std::env::set_var(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS",
        verifier_now,
    );
    std::env::set_var(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS",
        max_age_seconds,
    );
    std::env::set_var(
        "CHIO_AGENT_WEB_REPLAY_STORE_PATH",
        std::env::temp_dir().join(format!(
            "chio-agent-web-proof-room-replay-{}-{}.sqlite",
            std::process::id(),
            NEXT_REPLAY_STORE.fetch_add(1, Ordering::Relaxed)
        )),
    );
    std::env::set_var(
        "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS,
    );
    std::env::set_var(
        "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS,
    );
    configure_proof_room_fixture_trust();
}

fn standard_webhooks_clock_env() -> (String, String) {
    let Ok(host_elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        panic!("host clock is before Unix epoch");
    };
    let host_now = host_elapsed.as_secs();
    let verifier_now = host_now.saturating_add(60);
    let max_age_seconds = verifier_now
        .saturating_sub(STANDARD_WEBHOOKS_FIXTURE_TIMESTAMP)
        .saturating_add(300);
    (verifier_now.to_string(), max_age_seconds.to_string())
}

pub(crate) fn configure_proof_room_fixture_trust() {
    std::env::set_var(
        "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS",
        PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
    );
    std::env::set_var(
        "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS",
        proof_room_fixture_trusted_bundle_signer_keys(),
    );
    std::env::set_var(
        "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
        TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS,
    );
    std::env::set_var(
        "CHIO_RUNTIME_TRUSTED_ROOT_KEYS",
        RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS,
    );
    std::env::set_var(
        "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS",
        ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS,
    );
    std::env::set_var(
        "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS",
        ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS,
    );
    std::env::set_var(
        "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS",
        PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
    );
    std::env::set_var(
        "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
        COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
    );
    std::env::set_var(
        "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
        COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS,
    );
    std::env::set_var(
        "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
        COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS,
    );
    std::env::set_var(
        "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS",
        DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
    );
    std::env::set_var(
        "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS",
        DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
    );
    std::env::set_var(
        "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
        SWARM_FIXTURE_TRUSTED_WITNESS_KEYS,
    );
    std::env::set_var(
        "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
        TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS",
        "eip155:8453,eip155:42161",
    );
    std::env::set_var("CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS", "1");
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON",
        PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON,
    );
    std::env::set_var(
        "CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS",
        "1743293560",
    );
}

pub(crate) fn proof_room_fixture_trusted_bundle_signer_keys() -> String {
    let test_bundle_signer = Keypair::from_seed(&TEST_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    format!("{PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS},{test_bundle_signer}")
}

pub(crate) fn swarm_fixture_trusted_witness_keys(
) -> Result<Vec<chio_core_types::PublicKey>, Box<dyn Error>> {
    Ok(vec![chio_core_types::PublicKey::from_hex(
        SWARM_FIXTURE_TRUSTED_WITNESS_KEYS,
    )?])
}

pub(crate) fn proof_room_router(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
) -> axum::Router {
    configure_agent_web_fixture_secret();
    match build_proof_room_router(bundle, ui_dir) {
        Ok(router) => router,
        Err(error) => panic!("proof room router builds: {error}"),
    }
}

pub(crate) fn proof_room_router_with_fixture_root(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
    fixture_root: std::path::PathBuf,
) -> axum::Router {
    configure_agent_web_fixture_secret();
    match build_proof_room_router_with_fixture_root(bundle, ui_dir, Some(fixture_root)) {
        Ok(router) => router,
        Err(error) => panic!("proof room router builds: {error}"),
    }
}

pub(crate) fn proof_room_router_with_repo_fixture_root(
    bundle: std::path::PathBuf,
    ui_dir: std::path::PathBuf,
) -> Result<axum::Router, Box<dyn Error>> {
    Ok(proof_room_router_with_fixture_root(
        bundle,
        ui_dir,
        repo_root()?.join("fixtures/proof-room"),
    ))
}

pub(crate) fn runtime_regeneration_context(
    tamper_report: bool,
) -> Result<SourceVerifierContext, Box<dyn Error>> {
    runtime_regeneration_context_with_options(tamper_report, false, false)
}

pub(crate) fn runtime_regeneration_context_with_workflow_step_mismatch(
) -> Result<SourceVerifierContext, Box<dyn Error>> {
    runtime_regeneration_context_with_options(false, true, true)
}

fn runtime_regeneration_context_with_options(
    tamper_report: bool,
    tamper_workflow_step: bool,
    bind_parity_hashes: bool,
) -> Result<SourceVerifierContext, Box<dyn Error>> {
    let passport_bytes = fs::read(
        repo_root()?.join("fixtures/proof-room/minimal-passport/valid/transaction-passport.json"),
    )?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)?;
    let proof_package = serde_json::json!({
        "schema": "test.runtime-proof-package.v1",
        "packageId": "runtime-proof-package-1"
    });
    let verifier_report = serde_json::json!({
        "schema": "test.runtime-verifier-report.v1",
        "verdict": "verified"
    });
    let workflow_receipt = serde_json::json!({
        "schema": "test.runtime-workflow-receipt.v1",
        "receiptId": "runtime-workflow-receipt-1"
    });
    let proof_package_bytes = json_bytes(&proof_package)?;
    let verifier_report_bytes = json_bytes(&verifier_report)?;
    let workflow_receipt_bytes = json_bytes(&workflow_receipt)?;
    let proof_package_sha256 = canonical_json_sha256(&proof_package)?;
    let verifier_report_sha256 = canonical_json_sha256(&verifier_report)?;
    let workflow_receipt_sha256 = canonical_json_sha256(&workflow_receipt)?;
    let source_record = serde_json::json!({
        "stepIndex": 0,
        "admissionReportSha256": "a".repeat(64),
        "toolReceiptSha256": "b".repeat(64),
        "bilateralDsseSha256": "c".repeat(64),
        "workflowStepSha256": "d".repeat(64)
    });
    let proof_report = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-report.v1",
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "proofPackageSha256": proof_package_sha256,
        "verifierReportSha256": verifier_report_sha256,
        "workflowReceiptSha256": workflow_receipt_sha256,
        "sourceRecords": [source_record.clone()],
        "checks": ["runtime_regeneration.source_records_bound"]
    });
    let proof_report_sha256 = canonical_json_sha256(&proof_report)?;
    let workflow_step_sha256 = if tamper_workflow_step {
        "9".repeat(64)
    } else {
        "d".repeat(64)
    };
    let workflow_report = serde_json::json!({
        "schema": "chio.runtime.workflow-run-report.v1",
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "admissionReportSha256": "a".repeat(64),
        "evidencePaths": ["proof-regeneration-report.json"],
        "stepEvidence": [{
            "schema": "chio.runtime.step-evidence.v1",
            "stepIndex": 0,
            "admissionId": "admission-1",
            "admissionReportSha256": "a".repeat(64),
            "toolReceiptId": "tool-receipt-1",
            "toolReceiptSha256": "b".repeat(64),
            "outputSha256": "e".repeat(64),
            "bilateralDsseSha256": "c".repeat(64),
            "workflowStepSha256": workflow_step_sha256,
            "consistencyAnchor": "anchor-1",
            "destructive": false
        }],
        "proofRegenerationReportSha256": proof_report_sha256
    });
    let workflow_report_bytes = json_bytes(&workflow_report)?;
    let workflow_report_sha256 = canonical_json_sha256(&workflow_report)?;
    let manifest = serde_json::json!({
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": "runtime-loopback-1",
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "workflowRunReportSha256": workflow_report_sha256,
        "proofRegenerationReportSha256": proof_report_sha256,
        "entries": [
            runtime_manifest_entry("proof_package", "runtime-proof-package.json", &proof_package_bytes),
            runtime_manifest_entry("verifier_report", "runtime-verifier-report.json", &verifier_report_bytes),
            runtime_manifest_entry("workflow_receipt", "runtime-workflow-receipt.json", &workflow_receipt_bytes),
            runtime_manifest_entry("proof_regeneration_report", "proof-regeneration-report.json", &json_bytes(&proof_report)?),
            runtime_manifest_entry("runtime_run_report", "runtime-workflow-run-report.json", &workflow_report_bytes)
        ]
    });
    let manifest_bytes = json_bytes(&manifest)?;
    let manifest_sha256 = canonical_json_sha256(&manifest)?;
    let proof_input = serde_json::json!({
        "schema": "chio.runtime.proof-regeneration-input.v1",
        "runId": "runtime-loopback-1",
        "evidenceManifestSha256": manifest_sha256,
        "workflowRunReportSha256": workflow_report_sha256,
        "admissionReportSha256": "a".repeat(64),
        "trustBundleSha256": "f".repeat(64),
        "verificationContextSha256": "1".repeat(64),
        "sourceRecords": [source_record]
    });
    let mut proof_report_for_artifact = proof_report;
    if tamper_report {
        proof_report_for_artifact["checks"]
            .as_array_mut()
            .ok_or("proof report checks missing")?
            .push(serde_json::Value::String(
                "runtime_regeneration.tampered".to_string(),
            ));
    }
    let proof_report_bytes = json_bytes(&proof_report_for_artifact)?;
    let proof_input_bytes = json_bytes(&proof_input)?;
    let parity_report = serde_json::json!({
        "schema": chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA,
        "runId": "runtime-loopback-1",
        "accepted": true,
        "generatedAtUnixMs": 1_800_000_000_000u64,
        "staticProofPackageSha256": if bind_parity_hashes { proof_package_sha256.clone() } else { "2".repeat(64) },
        "runtimeProofPackageSha256": if bind_parity_hashes { proof_package_sha256 } else { "2".repeat(64) },
        "staticVerifierReportSha256": if bind_parity_hashes { verifier_report_sha256.clone() } else { "3".repeat(64) },
        "runtimeVerifierReportSha256": if bind_parity_hashes { verifier_report_sha256 } else { "3".repeat(64) },
        "comparedFields": ["verified_claims"],
        "mismatches": []
    });
    let parity_report_bytes = json_bytes(&parity_report)?;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "runtime-proof-parity-report.json".to_string(),
        parity_report_bytes.clone(),
    );
    artifacts.insert(
        "proof-regeneration-report.json".to_string(),
        proof_report_bytes.clone(),
    );
    artifacts.insert(
        "proof-regeneration-input.json".to_string(),
        proof_input_bytes.clone(),
    );
    artifacts.insert(
        "runtime-evidence-manifest.json".to_string(),
        manifest_bytes.clone(),
    );
    artifacts.insert(
        "runtime-workflow-run-report.json".to_string(),
        workflow_report_bytes.clone(),
    );
    artifacts.insert(
        "runtime-proof-package.json".to_string(),
        proof_package_bytes,
    );
    artifacts.insert(
        "runtime-verifier-report.json".to_string(),
        verifier_report_bytes,
    );
    artifacts.insert(
        "runtime-workflow-receipt.json".to_string(),
        workflow_receipt_bytes,
    );

    let evidence_graph = serde_json::json!({
        "nodes": [
            runtime_graph_node("runtime-proof-parity-report", chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, "runtime-proof-parity-report.json", &parity_report_bytes),
            runtime_graph_node("runtime-proof-regeneration-report", "chio.runtime.proof-regeneration-report.v1", "proof-regeneration-report.json", &proof_report_bytes),
            runtime_graph_node("runtime-proof-regeneration-input", "chio.runtime.proof-regeneration-input.v1", "proof-regeneration-input.json", &proof_input_bytes),
            runtime_graph_node("runtime-evidence-manifest", "chio.runtime.evidence-manifest.v1", "runtime-evidence-manifest.json", &manifest_bytes),
            runtime_graph_node("runtime-workflow-run-report", "chio.runtime.workflow-run-report.v1", "runtime-workflow-run-report.json", &workflow_report_bytes),
            runtime_graph_node("runtime-proof-package", "test.runtime-proof-package.v1", "runtime-proof-package.json", artifacts.get("runtime-proof-package.json").ok_or("proof package missing")?),
            runtime_graph_node("runtime-verifier-report", "test.runtime-verifier-report.v1", "runtime-verifier-report.json", artifacts.get("runtime-verifier-report.json").ok_or("verifier report missing")?),
            runtime_graph_node("runtime-workflow-receipt", "test.runtime-workflow-receipt.v1", "runtime-workflow-receipt.json", artifacts.get("runtime-workflow-receipt.json").ok_or("workflow receipt missing")?)
        ]
    });

    Ok(SourceVerifierContext {
        passport,
        passport_report_path: String::new(),
        evidence_graph_bytes: json_bytes(&evidence_graph)?,
        claim_set_bytes: Vec::new(),
        verifier_policy_bytes: Vec::new(),
        artifacts,
    })
}

pub(crate) fn runtime_manifest_entry(role: &str, path: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "path": path,
        "sha256": super::sha256_hex(bytes),
        "byteCount": bytes.len()
    })
}

pub(crate) fn runtime_graph_node(
    role: &str,
    schema: &str,
    path: &str,
    bytes: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "schema": schema,
        "path": path,
        "sha256": super::sha256_hex(bytes)
    })
}

pub(crate) fn canonical_json_sha256(value: &serde_json::Value) -> Result<String, Box<dyn Error>> {
    let bytes = chio_core_types::crypto::canonical_json_bytes(value)?;
    Ok(super::sha256_hex(&bytes))
}

pub(crate) fn repo_root() -> Result<std::path::PathBuf, Box<dyn Error>> {
    configure_proof_room_fixture_trust();
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        path = path
            .parent()
            .ok_or("crate manifest directory has no repo parent")?
            .to_path_buf();
    }
    Ok(path)
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

pub(crate) fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let value = signed_transaction_passport_value(value)?;
    Ok([serde_json::to_vec_pretty(&value)?.as_slice(), b"\n"].concat())
}

fn signed_transaction_passport_value(
    value: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn Error>> {
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("chio.transaction-passport.v1")
    {
        return Ok(value.clone());
    }

    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    let mut passport = value.clone();
    passport["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    passport["signature"] = serde_json::Value::String(String::new());
    let typed: chio_transaction_passport::TransactionPassport =
        serde_json::from_value(passport.clone())?;
    passport["signature"] = serde_json::Value::String(
        chio_transaction_passport::sign_transaction_passport(&typed, &keypair)?,
    );
    Ok(passport)
}

pub(crate) fn refresh_bundle_signature(bundle: &Path) -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    sign_bundle_signature_with_key(bundle, &keypair)
}

pub(crate) fn write_ui_report_and_rehash_manifest(
    bundle: &Path,
    ui_report: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let ui_report_bytes = json_bytes(ui_report)?;
    fs::write(&ui_report_path, &ui_report_bytes)?;
    let ui_report_sha256 = crate::sha256_hex(&ui_report_bytes);

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        if artifact.get("path").and_then(serde_json::Value::as_str)
            == Some("ui/proof-room-static/load-report.json")
        {
            artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

fn trust_test_bundle_signer(bundle: &Path) -> Result<String, Box<dyn Error>> {
    let test_key_id = Keypair::from_seed(&TEST_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let trust_roots_path = bundle.join("artifacts/authority/trust-roots.json");
    let mut trust_roots: serde_json::Value = serde_json::from_slice(&fs::read(&trust_roots_path)?)?;
    let root = trust_roots["roots"]
        .as_array_mut()
        .and_then(|roots| roots.first_mut())
        .ok_or("trust roots missing")?;
    root["key_id"] = serde_json::Value::String(test_key_id.clone());
    root["key_digest"] = serde_json::Value::String(super::sha256_hex(test_key_id.as_bytes()));
    fs::write(&trust_roots_path, json_bytes(&trust_roots)?)?;
    sha256_file(&trust_roots_path)
}

pub(crate) fn sign_bundle_signature_with_key(
    bundle: &Path,
    keypair: &Keypair,
) -> Result<(), Box<dyn Error>> {
    let manifest_path = bundle.join("manifest.json");
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    signature["payloadRef"]["sha256"] = serde_json::Value::String(sha256_hex(&manifest_bytes));
    signature["signatures"][0]["keyid"] = serde_json::Value::String(keypair.public_key().to_hex());
    signature["signatures"][0]["sig"] =
        serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
    fs::write(&signature_path, json_bytes(&signature)?)?;
    Ok(())
}

pub(crate) fn remove_graph_node_and_rehash(
    bundle: &Path,
    artifact_path: &str,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

fn ensure_claim_set_artifact_row(
    manifest: &mut serde_json::Value,
    claim_set_sha256: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let artifacts = manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?;
    if artifacts.iter().any(|artifact| {
        artifact.get("path").and_then(serde_json::Value::as_str) == Some("roots/claim-set.json")
    }) {
        return Ok(());
    }
    let producer = artifacts
        .iter()
        .find(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                == Some("roots/transaction-passport.json")
        })
        .and_then(|artifact| artifact.get("producer"))
        .cloned()
        .unwrap_or_else(|| serde_json::Value::String("fixtures/proof-room".to_string()));
    artifacts.insert(
        2,
        serde_json::json!({
            "artifact_class": "transaction-root",
            "media_type": "application/json",
            "participates_in_primary_verdict": true,
            "path": "roots/claim-set.json",
            "producer": producer,
            "renderer_hint": "claim-set",
            "schema": "chio.transaction.claim-set.v1",
            "sensitivity_class": "public-fixture",
            "sha256": claim_set_sha256.unwrap_or_default()
        }),
    );
    Ok(())
}

pub(crate) fn remove_guard_report_capability_binding_and_rehash(
    bundle: &Path,
) -> Result<(), Box<dyn Error>> {
    let guard_report_path = bundle.join("artifacts/authority/guard-report.json");
    let mut guard_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&guard_report_path)?)?;
    guard_report
        .as_object_mut()
        .ok_or("guard report object missing")?
        .remove("capability_id");
    fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
    let guard_report_sha256 = sha256_file(&guard_report_path)?;
    update_evidence_graph_node_hash(
        bundle,
        "artifacts/authority/guard-report.json",
        &guard_report_sha256,
    )?;
    refresh_source_roots_and_manifest(
        bundle,
        Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
    )?;
    Ok(())
}

pub(crate) fn add_unexpected_field_to_bundle_artifact_and_rehash(
    bundle: &Path,
    artifact_relative_path: &str,
) -> Result<(), Box<dyn Error>> {
    let artifact_path = bundle.join(artifact_relative_path);
    let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
    artifact["ambient_authority"] = serde_json::Value::Bool(true);
    fs::write(&artifact_path, json_bytes(&artifact)?)?;
    let artifact_sha256 = sha256_file(&artifact_path)?;

    update_evidence_graph_node_hash(bundle, artifact_relative_path, &artifact_sha256)?;
    refresh_source_roots_and_manifest(bundle, Some((artifact_relative_path, artifact_sha256)))?;
    Ok(())
}

pub(crate) fn sign_first_run_receipt_projection(
    receipt: &mut serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    sign_first_run_receipt_projection_with_seed(receipt, TEST_RECEIPT_SEED)
}

pub(crate) fn sign_first_run_receipt_projection_with_seed(
    receipt: &mut serde_json::Value,
    seed: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::from_seed(&seed);
    receipt["kernel_key"] = serde_json::Value::String(keypair.public_key().to_hex());
    let mut signed_body = receipt.clone();
    signed_body
        .as_object_mut()
        .ok_or("receipt projection object missing")?
        .remove("signature");
    let (signature, _canonical) = keypair.sign_canonical(&signed_body)?;
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(())
}

pub(crate) fn update_evidence_graph_node_hash(
    bundle: &Path,
    artifact_relative_path: &str,
    artifact_sha256: &str,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    let Some(node) = evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .iter_mut()
        .find(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
        })
    else {
        return Ok(());
    };
    let old_node_id = node
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or("evidence graph node id missing")?
        .to_string();
    node["id"] = serde_json::Value::String(artifact_sha256.to_string());
    node["sha256"] = serde_json::Value::String(artifact_sha256.to_string());
    if old_node_id != artifact_sha256 {
        for edge in evidence_graph["edges"]
            .as_array_mut()
            .ok_or("evidence graph edges missing")?
        {
            if edge.get("from").and_then(serde_json::Value::as_str) == Some(old_node_id.as_str()) {
                edge["from"] = serde_json::Value::String(artifact_sha256.to_string());
            }
            if edge.get("to").and_then(serde_json::Value::as_str) == Some(old_node_id.as_str()) {
                edge["to"] = serde_json::Value::String(artifact_sha256.to_string());
            }
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    Ok(())
}

pub(crate) fn refresh_source_roots_and_manifest(
    bundle: &Path,
    extra_artifact_hash: Option<(&str, String)>,
) -> Result<(), Box<dyn Error>> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let trust_roots_path = "artifacts/authority/trust-roots.json";
    let trust_roots_sha256 = match extra_artifact_hash.as_ref() {
        Some((path, sha256)) if *path == trust_roots_path => Some(sha256.clone()),
        _ if bundle.join(trust_roots_path).is_file() => Some(trust_test_bundle_signer(bundle)?),
        _ => None,
    };
    if let Some(trust_roots_sha256) = &trust_roots_sha256 {
        update_evidence_graph_node_hash(bundle, trust_roots_path, trust_roots_sha256)?;
    }
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;
    let claim_set_path = bundle.join("roots/claim-set.json");
    let claim_set_sha256 = if claim_set_path.is_file() {
        Some(sha256_file(&claim_set_path)?)
    } else {
        None
    };

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    if let Some(claim_set_sha256) = &claim_set_sha256 {
        passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256.clone());
        passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    }
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    if let Some(claim_set_sha256) = &claim_set_sha256 {
        verifier_report["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256.clone());
        verifier_report["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    }
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if claim_set_sha256.is_some() {
        manifest["schema_versions"]["transaction_claim_set"] =
            serde_json::Value::String("chio.transaction.claim-set.v1".to_string());
        ensure_claim_set_artifact_row(&mut manifest, claim_set_sha256.as_deref())?;
    }
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("roots/claim-set.json") => {
                if let Some(claim_set_sha256) = &claim_set_sha256 {
                    artifact["sha256"] = serde_json::Value::String(claim_set_sha256.clone());
                }
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some("artifacts/authority/trust-roots.json") => {
                if let Some(trust_roots_sha256) = &trust_roots_sha256 {
                    artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
                }
            }
            Some(path) => {
                if let Some((extra_path, extra_hash)) = extra_artifact_hash.as_ref() {
                    if path == *extra_path {
                        artifact["sha256"] = serde_json::Value::String(extra_hash.to_string());
                    }
                }
            }
            None => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn add_required_claim_to_verifier_policy(
    bundle: &Path,
    claim: &str,
) -> Result<(), Box<dyn Error>> {
    let verifier_policy_path = bundle.join("roots/verifier-policy.json");
    let mut verifier_policy: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
    verifier_policy["required_claims"]
        .as_array_mut()
        .ok_or("verifier policy required_claims missing")?
        .push(serde_json::Value::String(claim.to_string()));
    fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;
    let trust_roots_sha256 = trust_test_bundle_signer(bundle)?;

    update_evidence_graph_node_hash(bundle, "verifier-policy.json", &verifier_policy_sha256)?;
    update_evidence_graph_node_hash(
        bundle,
        "artifacts/authority/trust-roots.json",
        &trust_roots_sha256,
    )?;
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    verifier_report["verifier_policy_sha256"] =
        serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("roots/verifier-policy.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some("artifacts/authority/trust-roots.json") => {
                artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn remove_verifier_policy_field_and_rehash(
    bundle: &Path,
    field: &str,
) -> Result<(), Box<dyn Error>> {
    let verifier_policy_path = bundle.join("roots/verifier-policy.json");
    let mut verifier_policy: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
    verifier_policy
        .as_object_mut()
        .ok_or("verifier policy object missing")?
        .remove(field);
    fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
    let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;

    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json") {
            node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    passport["verifier_policy_sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    verifier_report["verifier_policy_sha256"] =
        serde_json::Value::String(verifier_policy_sha256.clone());
    fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    let trust_roots_sha256 = trust_test_bundle_signer(bundle)?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("roots/verifier-policy.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            Some("artifacts/authority/trust-roots.json") => {
                artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(super::sha256_hex(&fs::read(path)?))
}
