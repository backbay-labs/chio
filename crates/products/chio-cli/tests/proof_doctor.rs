use chio_test_support::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";
const STANDARD_WEBHOOKS_FIXTURE_TIMESTAMP: u64 = 1_770_508_800;
const AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS: &str = concat!(
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
    "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
    "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
    "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21,",
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
);
const AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const SWARM_FIXTURE_TRUSTED_WITNESS_KEYS: &str =
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de";
const PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS: &str = concat!(
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,",
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,",
    "a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869"
);
const PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
);
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
const TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS: &str =
    "cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7";
const COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS: &str =
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";
const COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS: &str =
    "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS: &str =
    "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID: &str = "chio.official-web3-contracts";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH: &str =
    "0x454a9a92b54a835a2776750196b171501bff6e5c02df1a192616194fc0a095cc";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xfc5d76d87b02096c6ae32ce644a2b98ca0bdf3c56700ad16731fad2062e6bd7f";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xd4f87cc63c00d0640c8f232c8fac5e5cb99bc6cf185ef912225e07fa438614cc";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH: &str =
    "0x03d8f545c330922a33db6473430c50eafd527e04474f31abee2dc1f8c6ab2d36";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH: &str =
    "0x17f7936469584b38404765ac44bd7e2384337983e4bc6448a3500d0637711f09";
const PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}";
const DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS: &str =
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

fn unique_agent_web_replay_store_path() -> PathBuf {
    static NEXT_REPLAY_STORE: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "chio-agent-web-proof-doctor-replay-{}-{}.sqlite",
        std::process::id(),
        NEXT_REPLAY_STORE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run_proof_doctor_scenario(root: &Path, scenario: &str) -> std::process::Output {
    proof_doctor_command()
        .arg("proof")
        .arg("doctor")
        .arg("--scenario")
        .arg(scenario)
        .arg("--root")
        .arg(root)
        .arg("--json")
        .output()
        .test_expect("chio proof doctor runs")
}

fn run_proof_doctor(root: &Path) -> std::process::Output {
    run_proof_doctor_scenario(root, "single-call-authority")
}

fn run_proof_doctor_default_scenario(root: &Path) -> std::process::Output {
    proof_doctor_command()
        .arg("proof")
        .arg("doctor")
        .arg("--root")
        .arg(root)
        .arg("--json")
        .output()
        .test_expect("chio proof doctor runs")
}

fn proof_doctor_command() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    let (verifier_now, max_age_seconds) = standard_webhooks_clock_env();
    command.env(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
        STANDARD_WEBHOOKS_VERIFIER_SECRET,
    );
    command.env(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS",
        verifier_now,
    );
    command.env(
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS",
        max_age_seconds,
    );
    command.env(
        "CHIO_AGENT_WEB_REPLAY_STORE_PATH",
        unique_agent_web_replay_store_path(),
    );
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS,
    );
    command.env(
        "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
        AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS,
    );
    command.env(
        "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS",
        PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
    );
    command.env(
        "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS",
        proof_room_fixture_trusted_bundle_signer_keys(),
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
        "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS",
        PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
    );
    command.env(
        "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
        SWARM_FIXTURE_TRUSTED_WITNESS_KEYS,
    );
    command.env(
        "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
        TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS,
    );
    command.env(
        "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
        COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
    );
    command.env(
        "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
        COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS,
    );
    command.env(
        "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
        COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS,
    );
    command.env(
        "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS",
        DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
    );
    command.env(
        "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS",
        DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS,
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
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS",
        "eip155:8453,eip155:42161",
    );
    command.env("CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS", "1");
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON",
        PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON,
    );
    command.env(
        "CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS",
        "1743293560",
    );
    command
}

fn standard_webhooks_clock_env() -> (String, String) {
    let host_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("host clock is after Unix epoch")
        .as_secs();
    let verifier_now = host_now.saturating_add(60);
    let max_age_seconds = verifier_now
        .saturating_sub(STANDARD_WEBHOOKS_FIXTURE_TIMESTAMP)
        .saturating_add(300);
    (verifier_now.to_string(), max_age_seconds.to_string())
}

fn proof_room_fixture_trusted_bundle_signer_keys() -> String {
    let test_bundle_signer = chio_core::Keypair::from_seed(&TEST_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    format!("{PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS},{test_bundle_signer}")
}

fn copy_dir_all(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&source_path, &destination_path)?;
        } else {
            std::fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

#[test]
fn proof_doctor_accepts_single_call_authority_first_run_evidence() {
    let output = run_proof_doctor(&workspace_root());

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "single-call-authority");
    assert_eq!(report["verdict"], "passed");
    assert_eq!(
        report["checks"]
            .as_array()
            .test_expect("checks array")
            .len(),
        9
    );
    assert!(stdout.contains("valid_minimal_passport"));
    assert!(stdout.contains("invalid_policy_digest_mismatch"));
    assert!(stdout.contains("allow_receipt"));
    assert!(stdout.contains("denial_receipt"));
    assert!(stdout.contains("verifier_report"));
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("command_log"));
    assert!(stdout.contains("release_truth"));
    assert!(stdout.contains("docker_quickstart_evidence"));
}

#[test]
fn proof_doctor_defaults_to_single_call_authority_when_scenario_is_omitted() {
    let output = run_proof_doctor_default_scenario(&workspace_root());

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "single-call-authority");
    assert_eq!(report["verdict"], "passed");
}

#[test]
fn proof_doctor_report_carries_stable_diagnostic_codes() {
    let output = run_proof_doctor(&workspace_root());

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");

    let checks = report["checks"].as_array().test_expect("checks array");
    let diagnostic_codes = report["diagnostic_codes"]
        .as_array()
        .test_expect("diagnostic codes array");

    assert_eq!(
        report["check_count"].as_u64().test_expect("check count"),
        checks.len() as u64
    );
    assert_eq!(report["failed_count"], 0);
    assert_eq!(diagnostic_codes.len(), checks.len());

    let diagnostic_code_set = diagnostic_codes
        .iter()
        .map(|code| code.as_str().test_expect("diagnostic code string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(diagnostic_code_set.len(), checks.len());

    for check in checks {
        let code = check["code"].as_str().test_expect("check code");
        assert!(
            code.starts_with("proof.doctor.single-call-authority."),
            "unexpected diagnostic code: {code}"
        );
        assert!(
            diagnostic_code_set.contains(code),
            "top-level diagnostic code list missing {code}"
        );
    }
}

#[test]
fn proof_doctor_accepts_agent_web_interop_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "agent-web-interop");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "agent-web-interop");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("agent_web_interop"));
    assert!(stdout.contains("agent_web_external_digest_mismatch"));
    assert!(stdout.contains("agent_web_missing_required_signature"));
    assert!(stdout.contains("agent_web_cloudevents_specversion_mismatch"));
    assert!(stdout.contains("agent_web_graphql_http_draft_version_missing"));
    assert!(stdout.contains("agent_web_graphql_errors_projected_as_success"));
    assert!(stdout.contains("agent_web_mcp_authority_claim_not_limited"));
    assert!(stdout.contains("agent_web_sidecar_claim_marked_native"));
    assert!(stdout.contains("agent_web_unsupported_claim_not_limited"));
    assert!(stdout.contains("agent_web_x402_detached_from_order"));
    assert!(stdout.contains("agent_web_external_subject_schema_mismatch"));
    assert!(stdout.contains("agent_web_acp_client_unsupported_bridge_allowed"));
    assert!(stdout.contains("agent_web_email_send_missing_message_digest"));
    assert!(stdout.contains("agent_web_calendar_time_range_mismatch"));
    assert!(stdout.contains("agent_web_slack_failed_provider_response"));
    assert!(stdout.contains("agent_web_kubernetes_admission_uid_mismatch"));
    assert!(stdout.contains("agent_web_oci_tag_only_ref"));
    assert!(stdout.contains("agent_web_slsa_unverified_provenance"));
    assert!(stdout.contains("agent_web_a2a_authority_claim_not_limited"));
    assert!(stdout.contains("agent_web_ap2_detached_from_order"));
}

#[test]
fn proof_doctor_accepts_public_settlement_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "public-settlement");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "public-settlement");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("public_settlement_offline_finality"));
    assert!(stdout.contains("public_settlement_wrong_chain_id"));
    assert!(stdout.contains("public_settlement_finality_below_threshold"));
    assert!(stdout.contains("public_settlement_observed_execution_outside_window"));
    assert!(stdout.contains("public_settlement_missing_commerce_order_binding"));
    assert!(stdout.contains("public_settlement_order_evidence_mismatch"));
    assert!(stdout.contains("public_settlement_missing_oracle_evidence"));
    assert!(stdout.contains("public_settlement_refunded_posture_without_reversal"));
}

#[test]
fn proof_doctor_accepts_commerce_payments_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "commerce-payments");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "commerce-payments");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("commerce_payment_offline_psp"));
    assert!(stdout.contains("commerce_payment_wrong_merchant"));
    assert!(stdout.contains("commerce_expired_mandate"));
    assert!(stdout.contains("commerce_payment_before_budget"));
    assert!(stdout.contains("commerce_quote_evidence_mismatch"));
    assert!(stdout.contains("commerce_open_dispute_completed"));
    assert!(stdout.contains("commerce_fraud_declined"));
    assert!(stdout.contains("commerce_currency_mismatch"));
    assert!(stdout.contains("commerce_payment_amount_mismatch"));
    assert!(stdout.contains("commerce_mandate_occurrence_limit"));
}

#[test]
fn proof_doctor_accepts_runtime_security_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "runtime-security");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "runtime-security");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("runtime_side_effecting_call"));
    assert!(stdout.contains("runtime_missing_execution_lease"));
    assert!(stdout.contains("runtime_expired_execution_lease"));
    assert!(stdout.contains("runtime_advisory_used_as_authorization"));
    assert!(stdout.contains("runtime_ack_outside_lease"));
    assert!(stdout.contains("runtime_missing_terminal_receipt"));
    assert!(stdout.contains("runtime_reused_nonce"));
    assert!(stdout.contains("runtime_sandbox_mismatch"));
    assert!(stdout.contains("runtime_stale_revocation"));
}

#[test]
fn proof_doctor_accepts_swarm_authority_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "swarm-authority");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "swarm-authority");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("swarm_recursive_delegation"));
    assert!(stdout.contains("swarm_stale_continuation"));
    assert!(stdout.contains("swarm_budget_allocations_exceed_pool"));
    assert!(stdout.contains("swarm_graph_cycle"));
    assert!(stdout.contains("swarm_join_parent_set_mismatch"));
    assert!(stdout.contains("swarm_replayed_continuation_nonce"));
    assert!(stdout.contains("swarm_revoked_task"));
    assert!(stdout.contains("swarm_stale_route_plan"));
    assert!(stdout.contains("swarm_route_plan_mismatch"));
    assert!(stdout.contains("swarm_witness_child_scope_mismatch"));
}

#[test]
fn proof_doctor_accepts_disclosure_lineage_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "disclosure-lineage");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "disclosure-lineage");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("disclosure_lineage_valid_ledger"));
    assert!(stdout.contains("disclosure_lineage_missing_ledger_entry"));
    assert!(stdout.contains("disclosure_lineage_unknown_lineage_root"));
}

#[test]
fn proof_doctor_accepts_trust_market_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "trust-market");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "trust-market");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("trust_market_context_valid"));
    assert!(stdout.contains("trust_market_guarantee_wrong_beneficiary"));
    assert!(stdout.contains("trust_market_unsupported_guarantee_type"));
    assert!(stdout.contains("trust_market_unsupported_collateral_source"));
    assert!(stdout.contains("trust_market_guarantee_without_backing"));
    assert!(stdout.contains("trust_market_reputation_import_overweight"));
    assert!(stdout.contains("trust_market_required_unsupported_market_claim"));
    assert!(stdout.contains("trust_market_score_recompute_mismatch"));
    assert!(stdout.contains("trust_market_selected_provider_absent"));
    assert!(stdout.contains("trust_market_sla_wrong_order"));
    assert!(stdout.contains("trust_market_slash_authority_outside_jurisdiction"));
    assert!(stdout.contains("trust_market_stale_discovery"));
    assert!(stdout.contains("trust_market_stale_reputation"));
}

#[test]
fn proof_doctor_accepts_workflow_preflight_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "workflow-preflight");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "workflow-preflight");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("workflow_preflight_valid_child_scope"));
    assert!(stdout.contains("workflow_broader_child_scope"));
    assert!(stdout.contains("workflow_planning_artifact_claims_authority"));
}

#[test]
fn proof_doctor_accepts_enterprise_export_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "enterprise-export");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "enterprise-export");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("enterprise_export_autonomous_commerce"));
    assert!(stdout.contains("enterprise_export_claim_outside_coverage"));
    assert!(stdout.contains("enterprise_export_control_map_missing_gate"));
    assert!(stdout.contains("enterprise_export_coverage_order_mismatch"));
    assert!(stdout.contains("enterprise_export_coverage_subject_mismatch"));
    assert!(stdout.contains("enterprise_export_double_consumed_reserve"));
    assert!(stdout.contains("enterprise_export_duplicate_reserve_receipt_id"));
    assert!(stdout.contains("enterprise_export_export_bundle_digest_mismatch"));
    assert!(stdout.contains("enterprise_export_pii_overdisclosure"));
    assert!(stdout.contains("enterprise_export_insurance_copy_exceeds_actuarial_support"));
    assert!(stdout.contains("enterprise_export_market_slash_facility_reserve"));
    assert!(stdout.contains("enterprise_export_missing_approval_case"));
    assert!(stdout.contains("enterprise_export_risk_portfolio_capital_overallocated"));
    assert!(stdout.contains("enterprise_export_facility_lifecycle_final_state_mismatch"));
    assert!(stdout.contains("enterprise_export_open_appeal_claim_payout"));
    assert!(stdout.contains("enterprise_export_open_appeal_facility_closure"));
    assert!(stdout.contains("enterprise_export_open_appeal_reserve_release"));
    assert!(stdout.contains("enterprise_export_payout_amount_mismatch"));
    assert!(stdout.contains("enterprise_export_reverse_slash_without_prior_penalty"));
    assert!(stdout.contains("enterprise_export_settlement_counterparty_mismatch"));
    assert!(stdout.contains("enterprise_export_mixed_currency_risk"));
    assert!(stdout.contains("enterprise_export_actuarial_backtest_breach"));
    assert!(stdout.contains("enterprise_export_risk_capital_adequacy_breach"));
    assert!(stdout.contains("enterprise_export_risk_exposure_exceeds_capital"));
    assert!(stdout.contains("enterprise_export_risk_reserve_state_missing"));
    assert!(stdout.contains("enterprise_export_telemetry_digest_mismatch"));
}

#[test]
fn proof_doctor_accepts_proof_package_evidence() {
    let output = run_proof_doctor_scenario(&workspace_root(), "proof-package");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "proof-package");
    assert_eq!(report["verdict"], "passed");
    assert!(stdout.contains("minimal_passport_valid"));
    assert!(stdout.contains("runtime_side_effecting_call"));
    assert!(stdout.contains("fixture_commerce_offline_psp"));
    assert!(stdout.contains("fixture_workflow_preflight_valid"));
    assert!(stdout.contains("fixture_recursive_runtime_swarm"));
    assert!(stdout.contains("fixture_disclosure_lineage_ledger"));
    assert!(stdout.contains("public_settlement_offline_finality"));
    assert!(stdout.contains("agent_web_interop"));
    assert!(stdout.contains("agent_web_mcp_authority_claim_not_limited"));
    assert!(stdout.contains("agent_web_a2a_authority_claim_not_limited"));
    assert!(stdout.contains("fixture_enterprise_autonomous_commerce"));
    assert!(stdout.contains("fixture_enterprise_risk_portfolio_capital_overallocated"));
    assert!(stdout.contains("fixture_trust_market_context"));
    assert!(stdout.contains("runtime_missing_execution_lease"));
    assert!(stdout.contains("commerce_payment_wrong_merchant"));
    assert!(stdout.contains("fixture_workflow_preflight_broader_child_scope"));
    assert!(stdout.contains("swarm_stale_continuation"));
    assert!(stdout.contains("trust_market_stale_reputation"));
}

#[test]
fn proof_doctor_rejects_workflow_preflight_fixture_wrong_rejection_reason() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(&source, &destination).test_expect("copy proof fixtures");

    let wrong_reason = destination
        .join("workflow-preflight")
        .join("planning-artifact-claims-authority")
        .join("preflight-plan.json");
    let broader_child_scope = destination
        .join("workflow-preflight")
        .join("broader-child-scope")
        .join("preflight-plan.json");
    std::fs::copy(wrong_reason, broader_child_scope)
        .test_expect("replace workflow preflight fixture with wrong rejection");

    let output = run_proof_doctor_scenario(tempdir.path(), "proof-package");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("fixture_workflow_preflight_broader_child_scope"));
    assert!(stdout.contains("workflow preflight rejected for the wrong reason"));
    assert!(stdout.contains("outside parent scope"));
}

#[test]
fn proof_doctor_rejects_crypto_context_report_not_derived_from_context() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(&source, &destination).test_expect("copy proof fixtures");

    let context_path = destination
        .join("crypto-context")
        .join("valid-bbs-context")
        .join("verification-context.json");
    let context_bytes = std::fs::read(&context_path).test_expect("read verification context");
    let mut context: serde_json::Value =
        serde_json::from_slice(&context_bytes).test_expect("verification context parses");
    context["audience"] = serde_json::Value::String("https://attacker.example/chio".to_string());
    write_json(&context_path, &context);

    let output = run_proof_doctor_scenario(tempdir.path(), "proof-package");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("fixture_crypto_context_valid_bbs"));
    assert!(stdout.contains("crypto context check failed"));
    assert!(stdout.contains("disclosure_context_audience_mismatch"));
}

#[test]
fn proof_doctor_rejects_package_fixture_that_fails_for_wrong_reason() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(&source, &destination).test_expect("copy proof fixtures");

    std::fs::write(
        destination.join("runtime-security/stale-revocation/revocation-freshness-proof.json"),
        "{",
    )
    .test_expect("corrupt stale revocation fixture");

    let output = run_proof_doctor_scenario(tempdir.path(), "proof-package");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("fixture_runtime_stale_revocation"));
    assert!(stdout.contains("transaction passport failed for the wrong reason"));
    assert!(stdout.contains("proof-room.negative.revocation-freshness-stale"));
}

#[test]
fn proof_doctor_rejects_package_negative_fixture_without_expected_failure_metadata() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(&source, &destination).test_expect("copy proof fixtures");
    std::fs::remove_file(destination.join("runtime-security/negatives/stale-revocation.json"))
        .test_expect("remove stale revocation metadata");

    let output = run_proof_doctor_scenario(tempdir.path(), "proof-package");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("fixture_runtime_stale_revocation"));
    assert!(stdout.contains("missing expected failure metadata"));
}

#[test]
fn proof_doctor_fails_when_single_call_evidence_is_missing() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).test_expect("doctor report parses");
    assert_eq!(report["schema"], "chio.proof.doctor-report.v1");
    assert_eq!(report["scenario"], "single-call-authority");
    assert_eq!(report["verdict"], "failed");
    assert!(stdout.contains("missing"));
    assert!(stdout.contains("valid_minimal_passport"));
    assert!(stdout.contains("denial_receipt"));
}

#[test]
fn proof_doctor_rejects_proof_room_bundle_report_hash_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let manifest_path = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle")
        .join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    let negative_case = read_json(&workspace_root().join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/report-hash-mismatch.json",
    ));
    manifest["verifier_report_ref"]["sha256"] = negative_case["mutation"]["value"].clone();
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(
        manifest_path
            .parent()
            .test_expect("manifest path has bundle parent"),
    );

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("proof-room.report.hash-mismatch"));
}

#[test]
fn proof_doctor_rejects_docker_quickstart_release_truth_without_bound_evidence() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let manifest_path = bundle.join("manifest.json");
    let mut manifest = read_json(&manifest_path);
    manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .retain(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                != Some("artifacts/release/docker-quickstart-evidence.json")
        });
    manifest["advisory_artifacts"]
        .as_array_mut()
        .test_expect("manifest advisory artifacts array")
        .retain(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                != Some("artifacts/release/docker-quickstart-evidence.json")
        });
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("docker_quickstart_evidence"));
    assert!(stdout.contains("release truth requires Docker quickstart evidence"));
}

#[test]
fn proof_doctor_rejects_docker_quickstart_evidence_runtime_path_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let evidence_path = bundle.join("artifacts/release/docker-quickstart-evidence.json");
    let mut evidence = read_json(&evidence_path);
    evidence["bundle_path"] = serde_json::Value::String("/opt/chio/proof-room-bundle".to_string());
    write_json(&evidence_path, &evidence);

    let evidence_sha256 =
        chio_core::sha256_hex(&std::fs::read(&evidence_path).test_expect("read evidence"));
    let manifest_path = bundle.join("manifest.json");
    let mut manifest = read_json(&manifest_path);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .iter_mut()
        .find(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/release/docker-quickstart-evidence.json")
        })
        .test_expect("Docker evidence artifact");
    artifact["sha256"] = serde_json::Value::String(evidence_sha256);
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("docker_quickstart_evidence"));
    assert!(stdout.contains("Docker quickstart evidence bundle_path mismatch"));
}

#[test]
fn proof_doctor_rejects_docker_quickstart_evidence_missing_fixture_catalog_endpoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let evidence_path = bundle.join("artifacts/release/docker-quickstart-evidence.json");
    let mut evidence = read_json(&evidence_path);
    evidence["endpoints"]
        .as_array_mut()
        .test_expect("Docker evidence endpoints array")
        .retain(|endpoint| {
            endpoint.get("path").and_then(serde_json::Value::as_str)
                != Some("/proof-room-fixture-catalog.json")
        });
    write_json(&evidence_path, &evidence);

    let evidence_sha256 =
        chio_core::sha256_hex(&std::fs::read(&evidence_path).test_expect("read evidence"));
    let manifest_path = bundle.join("manifest.json");
    let mut manifest = read_json(&manifest_path);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .iter_mut()
        .find(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/release/docker-quickstart-evidence.json")
        })
        .test_expect("Docker evidence artifact");
    artifact["sha256"] = serde_json::Value::String(evidence_sha256);
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("docker_quickstart_evidence"));
    assert!(stdout
        .contains("Docker quickstart evidence endpoint missing: /proof-room-fixture-catalog.json"));
}

#[test]
fn proof_doctor_rejects_docker_quickstart_evidence_missing_domain_fixture_endpoint() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let evidence_path = bundle.join("artifacts/release/docker-quickstart-evidence.json");
    let mut evidence = read_json(&evidence_path);
    evidence["endpoints"]
        .as_array_mut()
        .test_expect("Docker evidence endpoints array")
        .retain(|endpoint| {
            endpoint.get("path").and_then(serde_json::Value::as_str)
                != Some("/proof-room-fixtures/commerce-offline-psp/verifier-report.json")
        });
    write_json(&evidence_path, &evidence);

    let evidence_sha256 =
        chio_core::sha256_hex(&std::fs::read(&evidence_path).test_expect("read evidence"));
    let manifest_path = bundle.join("manifest.json");
    let mut manifest = read_json(&manifest_path);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
        .iter_mut()
        .find(|artifact| {
            artifact.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/release/docker-quickstart-evidence.json")
        })
        .test_expect("Docker evidence artifact");
    artifact["sha256"] = serde_json::Value::String(evidence_sha256);
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("docker_quickstart_evidence"));
    assert!(stdout.contains(
        "Docker quickstart evidence endpoint missing: /proof-room-fixtures/commerce-offline-psp/verifier-report.json"
    ));
}

#[test]
fn proof_doctor_rejects_proof_room_bundle_missing_denial_receipt_claim_artifact() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let manifest_path = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle")
        .join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    let negative_case = read_json(&workspace_root().join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/missing-denial-receipt.json",
    ));
    let claim_id = negative_case["mutation"]["claim_id"]
        .as_str()
        .test_expect("negative case has claim id");
    let claims = manifest["claims"]
        .as_array_mut()
        .test_expect("manifest claims array");
    let claim = claims
        .iter_mut()
        .find(|claim| claim.get("claim_id").and_then(serde_json::Value::as_str) == Some(claim_id))
        .test_expect("claim exists in manifest");
    claim["required_artifacts"] = negative_case["mutation"]["required_artifacts"].clone();
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(
        manifest_path
            .parent()
            .test_expect("manifest path has bundle parent"),
    );

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains(
        negative_case["expected_failure_code"]
            .as_str()
            .test_expect("negative case has expected failure code")
    ));
}

#[test]
fn proof_doctor_rejects_proof_room_receipt_coverage_status_mismatch() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let manifest_path = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle")
        .join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    let negative_case = read_json(&workspace_root().join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/negatives/receipt-coverage-status-mismatch.json",
    ));
    let category = negative_case["mutation"]["category"]
        .as_str()
        .test_expect("negative case has category");
    let terminal_status = negative_case["mutation"]["terminal_status"]
        .as_str()
        .test_expect("negative case has terminal status");
    let coverage = manifest["receipt_coverage"]
        .as_array_mut()
        .test_expect("receipt coverage array");
    let coverage_entry = coverage
        .iter_mut()
        .find(|entry| entry.get("category").and_then(serde_json::Value::as_str) == Some(category))
        .test_expect("coverage category exists");
    coverage_entry["terminal_status"] = serde_json::Value::String(terminal_status.to_string());
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(
        manifest_path
            .parent()
            .test_expect("manifest path has bundle parent"),
    );

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains(
        negative_case["expected_failure_code"]
            .as_str()
            .test_expect("negative case has expected failure code")
    ));
}

#[test]
fn proof_doctor_rejects_proof_room_ui_report_with_unbacked_rendered_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let manifest_path = bundle.join("manifest.json");
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let ui_report_bytes = std::fs::read(&ui_report_path).test_expect("read UI report");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&ui_report_bytes).test_expect("UI report parses");
    ui_report["rendered_claims"]
        .as_array_mut()
        .test_expect("rendered claims array")
        .push(serde_json::json!({
            "claim_id": "claim.proof_room.invented_ui_claim",
            "source": "verifier/report.json",
            "verdict": "verified"
        }));
    let ui_report_json = serde_json::to_vec_pretty(&ui_report).test_expect("serialize UI report");
    std::fs::write(&ui_report_path, [&ui_report_json[..], b"\n"].concat())
        .test_expect("write UI report");
    let ui_report_hash =
        chio_core::sha256_hex(&std::fs::read(&ui_report_path).test_expect("read UI report hash"));

    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_hash.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str)
            == Some("ui/proof-room-static/load-report.json")
        {
            artifact["sha256"] = serde_json::Value::String(ui_report_hash.clone());
        }
    }
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("proof-room.ui-report.rendered-claim-unbacked"));
}

#[test]
fn proof_doctor_rejects_proof_room_ui_report_that_omits_manifest_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let manifest_path = bundle.join("manifest.json");
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let ui_report_bytes = std::fs::read(&ui_report_path).test_expect("read UI report");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&ui_report_bytes).test_expect("UI report parses");
    let rendered_claims = ui_report["rendered_claims"]
        .as_array_mut()
        .test_expect("rendered claims array");
    rendered_claims.retain(|claim| {
        claim.get("claim_id").and_then(serde_json::Value::as_str)
            != Some("claim.proof_room.verifier_report_bound")
    });
    let ui_report_json = serde_json::to_vec_pretty(&ui_report).test_expect("serialize UI report");
    std::fs::write(&ui_report_path, [&ui_report_json[..], b"\n"].concat())
        .test_expect("write UI report");
    let ui_report_hash =
        chio_core::sha256_hex(&std::fs::read(&ui_report_path).test_expect("read UI report hash"));

    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_hash.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str)
            == Some("ui/proof-room-static/load-report.json")
        {
            artifact["sha256"] = serde_json::Value::String(ui_report_hash.clone());
        }
    }
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("proof-room.ui-report.rendered-claim-missing"));
}

#[test]
fn proof_doctor_rejects_proof_room_ui_report_verdict_drift() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let bundle = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle");
    let manifest_path = bundle.join("manifest.json");
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let ui_report_bytes = std::fs::read(&ui_report_path).test_expect("read UI report");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&ui_report_bytes).test_expect("UI report parses");
    ui_report["verdict"] = serde_json::Value::String("failed".to_string());
    let ui_report_json = serde_json::to_vec_pretty(&ui_report).test_expect("serialize UI report");
    std::fs::write(&ui_report_path, [&ui_report_json[..], b"\n"].concat())
        .test_expect("write UI report");
    let ui_report_hash =
        chio_core::sha256_hex(&std::fs::read(&ui_report_path).test_expect("read UI report hash"));

    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_hash.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str)
            == Some("ui/proof-room-static/load-report.json")
        {
            artifact["sha256"] = serde_json::Value::String(ui_report_hash.clone());
        }
    }
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    refresh_bundle_signature(&bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("proof-room.ui-report.verdict-mismatch"));
}

#[test]
fn proof_doctor_rejects_unregistered_proof_room_claim() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room");
    let destination = tempdir.path().join("fixtures/proof-room");
    copy_dir_all(
        &source.join("minimal-passport"),
        &destination.join("minimal-passport"),
    )
    .test_expect("copy minimal-passport fixtures");
    copy_dir_all(&source.join("first-run"), &destination.join("first-run"))
        .test_expect("copy first-run fixtures");

    let manifest_path = destination
        .join("first-run")
        .join("single-call-authority")
        .join("proof-room-bundle")
        .join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).test_expect("read bundle manifest");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).test_expect("bundle manifest parses");
    manifest["claims"]
        .as_array_mut()
        .test_expect("manifest claims array")
        .push(serde_json::json!({
            "claim_id": "claim.proof_room.unregistered_demo_claim",
            "required_artifacts": ["ui/proof-room-static/load-report.json"],
            "checker": "chio proof doctor --scenario single-call-authority",
            "result": "verified",
            "proof_level": "fixture-evidence",
            "caveat": "",
            "source_refs": ["ui/proof-room-static/load-report.json"]
        }));
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).test_expect("serialize mutated manifest");
    std::fs::write(&manifest_path, [&manifest_json[..], b"\n"].concat())
        .test_expect("write mutated bundle manifest");
    let bundle = manifest_path
        .parent()
        .test_expect("manifest has bundle parent");
    refresh_bundle_signature(bundle);

    let output = run_proof_doctor(tempdir.path());

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("proof_room_bundle"));
    assert!(stdout.contains("proof-room.claim.unregistered"));
}

#[test]
fn proof_room_bundle_claims_are_registered_in_proof_registries() {
    let root = workspace_root();
    let manifest = read_json(&root.join(
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    ));
    let claim_registry = read_json(&root.join("spec/registries/claim-registry.v1.json"));
    let proof_manifest = read_json(&root.join("spec/registries/proof-manifest.v1.json"));

    let registered_claims = string_set_from_array(&claim_registry, "claims", "id");
    let proof_manifest_claims = string_set_from_array(&proof_manifest, "manifests", "claim_ref");
    let bundle_claims = manifest["claims"]
        .as_array()
        .test_expect("manifest claims array")
        .iter()
        .filter_map(|claim| claim.get("claim_id").and_then(serde_json::Value::as_str))
        .filter(|claim| claim.starts_with("claim.proof_room."))
        .collect::<BTreeSet<_>>();

    assert!(!bundle_claims.is_empty());
    for claim in bundle_claims {
        assert!(
            registered_claims.contains(claim),
            "proof room claim missing from claim registry: {claim}"
        );
        assert!(
            proof_manifest_claims.contains(claim),
            "proof room claim missing from proof manifest: {claim}"
        );
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).test_expect("json file reads");
    serde_json::from_slice(&bytes).test_expect("json file parses")
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(value).test_expect("serialize JSON");
    std::fs::write(path, [&bytes[..], b"\n"].concat()).test_expect("write JSON");
}

fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

fn sign_bundle_signature(bundle: &Path, signature: &mut serde_json::Value) {
    let manifest_bytes = std::fs::read(bundle.join("manifest.json")).test_expect("read manifest");
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    let keypair = chio_core::Keypair::from_seed(&TEST_SIGNATURE_SEED);
    signature["payloadRef"]["sha256"] =
        serde_json::Value::String(chio_core::sha256_hex(&manifest_bytes));
    signature["signatures"][0]["keyid"] = serde_json::Value::String(keypair.public_key().to_hex());
    signature["signatures"][0]["sig"] =
        serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
}

fn refresh_bundle_signature(bundle: &Path) {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature = read_json(&signature_path);
    sign_bundle_signature(bundle, &mut signature);
    write_json(&signature_path, &signature);
}

fn string_set_from_array<'a>(
    value: &'a serde_json::Value,
    array_field: &str,
    string_field: &str,
) -> BTreeSet<&'a str> {
    value[array_field]
        .as_array()
        .test_expect("registry array")
        .iter()
        .filter_map(|entry| entry.get(string_field).and_then(serde_json::Value::as_str))
        .collect()
}
