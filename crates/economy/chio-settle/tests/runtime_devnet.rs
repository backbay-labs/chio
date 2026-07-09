use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_anchor::{
    build_anchor_inclusion_proof_from_evidence_bundle, build_chain_anchor_record,
    confirm_root_publication, evm_anchor_devnet_rpc_egress_contract, prepare_root_publication,
    publish_root, EvmAnchorTarget,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::credit::{
    CapitalBookQuery, CapitalBookSourceKind, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionArtifact, CapitalExecutionInstructionSupportBoundary,
    CapitalExecutionIntendedState, CapitalExecutionRail, CapitalExecutionRailKind,
    CapitalExecutionReconciledState, CapitalExecutionRole, CapitalExecutionWindow,
};
use chio_core::crypto::Keypair;
use chio_core::hashing::sha256_hex;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::SignedExportEnvelope,
};
use chio_core::web3::identity::{
    SignedWeb3IdentityBinding, Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
};
use chio_core::web3::settlement::Web3SettlementLifecycleState;
use chio_core::web3::trust_profile::Web3SettlementPath;
use chio_kernel::checkpoint::{build_checkpoint, build_inclusion_proof};
use chio_kernel::evidence_export::{
    EvidenceChildReceiptScope, EvidenceExportBundle, EvidenceExportQuery,
    EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
};
use chio_settle::{
    confirm_transaction, estimate_call_gas, finalize_escrow_dispatch, inspect_finality,
    prepare_dual_sign_release, prepare_erc20_approval, prepare_escrow_refund,
    prepare_merkle_release, prepare_merkle_release_root_publication, prepare_web3_escrow_dispatch,
    project_escrow_execution_receipt, read_escrow_snapshot, static_validate_call, submit_call,
    DualSignReleaseInput, EscrowDispatchRequest, EscrowExecutionAmount, LocalDevnetDeployment,
    SettlementAnchorContentBinding, SettlementFinalityStatus,
};
use reqwest::Client;
use serde_json::{json, Value};

const OPERATOR_PRIVATE_KEY: &str =
    "0x1000000000000000000000000000000000000000000000000000000000000002";

use chio_test_support::prelude::*;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .test_expect("repo root")
}

fn runtime_devnet_prereqs_available() -> bool {
    let repo_root = repo_root();
    let contracts_dir = repo_root.join("contracts");
    if !contracts_dir.join("node_modules/ethers").exists()
        || !contracts_dir.join("node_modules/ganache").exists()
    {
        return false;
    }

    matches!(
        Command::new("node")
            .arg("--input-type=module")
            .arg("-e")
            .arg("await import('ethers'); await import('ganache');")
            .current_dir(&contracts_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

struct DevnetGuard {
    child: Child,
    deployment_path: PathBuf,
}

impl Drop for DevnetGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.deployment_path);
        if let Some(parent) = self.deployment_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn unique_runtime_devnet_deployment_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir()
        .join(format!(
            "chio-runtime-devnet-{}-{nanos}",
            std::process::id()
        ))
        .join(name)
}

async fn spawn_runtime_devnet(
    deployment_path: &Path,
    operator_ed_key_hash: &str,
    port: u16,
) -> Result<DevnetGuard, Box<dyn std::error::Error>> {
    let deployment_name = deployment_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("runtime devnet deployment filename missing")?;
    let deployment_dir = deployment_path
        .parent()
        .ok_or("runtime devnet deployment parent directory missing")?;
    std::fs::create_dir_all(deployment_dir)?;
    if deployment_path.exists() {
        std::fs::remove_file(deployment_path)?;
    }
    let mut child = Command::new("node")
        .arg("contracts/scripts/start-runtime-devnet.mjs")
        .current_dir(repo_root())
        .env("CHIO_DEVNET_PORT", port.to_string())
        .env("CHIO_RUNTIME_DEPLOYMENT_NAME", deployment_name)
        .env("CHIO_RUNTIME_DEPLOYMENT_DIR", deployment_dir)
        .env("CHIO_OPERATOR_ED_KEY_HASH", operator_ed_key_hash)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("runtime devnet exited early with status {status}").into());
        }
        if deployment_path.exists() {
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            return Err("timed out waiting for runtime devnet deployment".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("runtime devnet exited before RPC became ready: {status}").into());
        }
        let rpc_url = format!("http://127.0.0.1:{port}");
        if rpc_call(&rpc_url, "eth_getBlockByNumber", json!(["latest", false]))
            .await
            .is_ok()
        {
            break;
        }
        if start.elapsed() > Duration::from_secs(30) {
            return Err("timed out waiting for runtime devnet RPC readiness".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(DevnetGuard {
        child,
        deployment_path: deployment_path.to_path_buf(),
    })
}

async fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = Client::new()
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .send()
        .await?;
    let body: Value = response.json().await?;
    if let Some(error) = body.get("error") {
        return Err(format!("rpc error: {error}").into());
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| "rpc result missing".into())
}

async fn latest_block_timestamp(rpc_url: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let block = rpc_call(rpc_url, "eth_getBlockByNumber", json!(["latest", false])).await?;
    let timestamp = block
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or("latest block missing timestamp")?;
    Ok(u64::from_str_radix(timestamp.trim_start_matches("0x"), 16)?)
}

async fn advance_time(rpc_url: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    rpc_call(rpc_url, "evm_increaseTime", json!([seconds])).await?;
    rpc_call(rpc_url, "evm_mine", json!([])).await?;
    Ok(())
}

fn operator_binding(
    keypair: &Keypair,
    chain_id: &str,
    settlement_address: &str,
) -> SignedWeb3IdentityBinding {
    let certificate = Web3IdentityBindingCertificate {
        schema: chio_core::web3::identity::CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", keypair.public_key().to_hex()),
        chio_public_key: keypair.public_key(),
        chain_scope: vec![chain_id.to_string()],
        purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        settlement_address: settlement_address.to_string(),
        issued_at: 1_743_292_800,
        expires_at: 1_774_828_800,
        nonce: "runtime-devnet-binding".to_string(),
    };
    SignedWeb3IdentityBinding {
        signature: keypair
            .sign_canonical(&certificate)
            .test_expect("binding signature")
            .0,
        certificate,
    }
}

fn sample_capital_instruction(
    keypair: &Keypair,
    chain_id: &str,
    beneficiary_address: &str,
    instruction_id: &str,
    issued_at: u64,
    not_after: u64,
    amount_units: u64,
) -> chio_core::credit::SignedCapitalExecutionInstruction {
    let custodian = Keypair::from_seed(&[13u8; 32]);
    let custodian_id = custodian.public_key().to_hex();
    SignedExportEnvelope::sign(
        CapitalExecutionInstructionArtifact {
            schema: chio_core::credit::CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: instruction_id.to_string(),
            issued_at,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:facility:facility-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: Some(format!("governed-{instruction_id}")),
            completion_flow_row_id: Some(format!(
                "economic-completion-flow:governed-{instruction_id}"
            )),
            action: chio_core::credit::CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: amount_units,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::OperatorTreasury,
                    keypair,
                    issued_at.saturating_sub(10),
                    not_after,
                    Some("governed release".to_string()),
                )
                .test_expect("treasury authority proof"),
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::Custodian,
                    &custodian,
                    issued_at.saturating_sub(5),
                    not_after,
                    Some("official web3 stack".to_string()),
                )
                .test_expect("custodian authority proof"),
            ],
            execution_window: CapitalExecutionWindow {
                not_before: issued_at,
                not_after,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Web3,
                rail_id: "ganache-devnet-usdc".to_string(),
                custody_provider_id: custodian_id,
                source_account_ref: Some("vault:facility-main".to_string()),
                destination_account_ref: Some(beneficiary_address.to_string()),
                jurisdiction: Some(chain_id.to_string()),
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::NotObserved,
            related_instruction_id: None,
            observed_execution: None,
            support_boundary: CapitalExecutionInstructionSupportBoundary {
                capital_book_authoritative: true,
                external_execution_authoritative: false,
                automatic_dispatch_supported: true,
                custody_neutral_instruction_supported: false,
            },
            evidence_refs: Vec::new(),
            description: "release escrow over the runtime devnet".to_string(),
        },
        keypair,
    )
    .test_expect("capital instruction")
}

fn sample_receipt(
    keypair: &Keypair,
    capability_id: &str,
    receipt_id: &str,
    amount_units: u64,
    beneficiary_address: &str,
) -> ChioReceipt {
    sample_receipt_with_content_hash(
        keypair,
        capability_id,
        receipt_id,
        amount_units,
        beneficiary_address,
        sha256_hex(format!("settlement:{receipt_id}").as_bytes()),
    )
}

fn sample_receipt_with_content_hash(
    keypair: &Keypair,
    capability_id: &str,
    receipt_id: &str,
    amount_units: u64,
    beneficiary_address: &str,
    content_hash: String,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_743_292_800,
            capability_id: capability_id.to_string(),
            tool_server: "chio-settle".to_string(),
            tool_name: "release_escrow".to_string(),
            action: ToolCallAction::from_parameters(json!({
                "amount": amount_units,
                "currency": "USD",
                "to": beneficiary_address,
            }))
            .test_expect("receipt params"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash,
            policy_hash: sha256_hex(b"policy:web3"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_expect("receipt")
}

#[tokio::test]
async fn runtime_devnet_keeps_escrow_identity_stable_under_interleaving_and_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    if !runtime_devnet_prereqs_available() {
        eprintln!(
            "skipping runtime devnet integration test because node-based prerequisites are unavailable"
        );
        return Ok(());
    }

    let deployment_path = unique_runtime_devnet_deployment_path("runtime-devnet-drift.json");
    let operator_keypair = Keypair::from_seed_hex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    let operator_ed_key_hash = format!(
        "0x{}",
        hex::encode(
            alloy_primitives::keccak256(operator_keypair.public_key().as_bytes()).as_slice()
        )
    );
    let _devnet = spawn_runtime_devnet(&deployment_path, &operator_ed_key_hash, 8548).await?;

    let deployment = LocalDevnetDeployment::from_path(&deployment_path)?;
    let accounts = deployment
        .accounts
        .clone()
        .ok_or("runtime devnet accounts missing")?;
    let config = deployment.into_chain_config()?;
    let binding = operator_binding(
        &operator_keypair,
        &config.chain_id,
        &config.operator_address,
    );
    let instruction_key = Keypair::from_seed_hex(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )?;

    let approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        4_500_000,
    )?;
    let approval_tx = submit_call(&config, &approval.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit initial approval: {error}")))?;
    confirm_transaction(&config, &approval_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm initial approval: {error}")))?;

    let issued_at = latest_block_timestamp(&config.rpc_url).await?;
    let dispatch_a = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-drift-a".to_string(),
            issued_at,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-drift-a".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: sample_capital_instruction(
                &instruction_key,
                &config.chain_id,
                &accounts.beneficiary,
                "cei-drift-a",
                issued_at,
                issued_at + 7_200,
                150,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("drift-coverage-a".to_string()),
        },
        &binding,
    )
    .await?;
    let dispatch_b = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-drift-b".to_string(),
            issued_at,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-drift-b".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: sample_capital_instruction(
                &instruction_key,
                &config.chain_id,
                &accounts.beneficiary,
                "cei-drift-b",
                issued_at,
                issued_at + 7_200,
                300,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("drift-coverage-b".to_string()),
        },
        &binding,
    )
    .await?;

    let dispatch_b_tx = submit_call(&config, &dispatch_b.call).await?;
    let dispatch_b_receipt = confirm_transaction(&config, &dispatch_b_tx).await?;
    let finalized_b = finalize_escrow_dispatch(&dispatch_b, &dispatch_b_receipt)?;

    let dispatch_a_tx = submit_call(&config, &dispatch_a.call).await?;
    let dispatch_a_receipt = confirm_transaction(&config, &dispatch_a_tx).await?;
    let finalized_a = finalize_escrow_dispatch(&dispatch_a, &dispatch_a_receipt)?;

    assert_eq!(
        dispatch_a.expected_escrow_id, finalized_a.dispatch.escrow_id,
        "interleaving should not change the canonical escrow identity",
    );
    assert_eq!(
        dispatch_b.expected_escrow_id, finalized_b.dispatch.escrow_id,
        "interleaving should not change the second escrow identity either",
    );

    let snapshot_a = read_escrow_snapshot(&config, &finalized_a.dispatch.escrow_id).await?;
    assert_eq!(snapshot_a.deposited_minor_units, 1_500_000);
    let snapshot_b = read_escrow_snapshot(&config, &finalized_b.dispatch.escrow_id).await?;
    assert_eq!(snapshot_b.deposited_minor_units, 3_000_000);

    let replay_error = submit_call(&config, &dispatch_a.call)
        .await
        .test_expect_err("duplicate create must fail closed");
    assert!(
        replay_error.to_string().contains("already exists")
            || replay_error.to_string().contains("code"),
        "unexpected replay error: {replay_error}",
    );

    Ok(())
}

#[tokio::test]
async fn runtime_devnet_executes_merkle_refund_and_dual_sign_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    if !runtime_devnet_prereqs_available() {
        eprintln!(
            "skipping runtime devnet integration test because node-based prerequisites are unavailable"
        );
        return Ok(());
    }

    let deployment_path = unique_runtime_devnet_deployment_path("runtime-devnet-main.json");
    let operator_keypair = Keypair::from_seed_hex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    let operator_ed_key_hash = format!(
        "0x{}",
        hex::encode(
            alloy_primitives::keccak256(operator_keypair.public_key().as_bytes()).as_slice()
        )
    );
    let _devnet = spawn_runtime_devnet(&deployment_path, &operator_ed_key_hash, 8547).await?;

    let deployment = LocalDevnetDeployment::from_path(&deployment_path)?;
    let accounts = deployment
        .accounts
        .clone()
        .ok_or("runtime devnet accounts missing")?;
    let config = deployment.into_chain_config()?;
    let binding = operator_binding(
        &operator_keypair,
        &config.chain_id,
        &config.operator_address,
    );
    let instruction_key = Keypair::from_seed_hex(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )?;

    let issued_at = latest_block_timestamp(&config.rpc_url).await?;
    let create_amount = MonetaryAmount {
        units: 150,
        currency: "USD".to_string(),
    };
    let approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        1_500_000,
    )?;
    let approval_tx = submit_call(&config, &approval.call).await?;
    confirm_transaction(&config, &approval_tx).await?;

    let capital_instruction = sample_capital_instruction(
        &instruction_key,
        &config.chain_id,
        &accounts.beneficiary,
        "cei-runtime-1",
        issued_at,
        issued_at + 7_200,
        create_amount.units,
    );
    let prepared_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-runtime-1".to_string(),
            issued_at,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-runtime-1".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction,
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("runtime devnet merkle settlement".to_string()),
        },
        &binding,
    )
    .await?;
    let create_tx = submit_call(&config, &prepared_dispatch.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit escrow create: {error}")))?;
    let create_receipt = confirm_transaction(&config, &create_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm escrow create: {error}")))?;
    assert!(create_receipt.status);
    let prepared_dispatch = finalize_escrow_dispatch(&prepared_dispatch, &create_receipt)?;

    let execution_receipt_id = "exec-runtime-1";
    let settlement_reference = "settlement-runtime-1";
    let governed_receipt_id = prepared_dispatch
        .dispatch
        .capital_instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or("prepared dispatch missing governed receipt id")?;
    let receipt_content_hash =
        chio_core::web3::settlement::settlement_anchor_receipt_content_hash_parts(
            execution_receipt_id,
            settlement_reference,
            &prepared_dispatch.dispatch.dispatch_id,
            governed_receipt_id,
        )?;
    let receipt = sample_receipt_with_content_hash(
        &operator_keypair,
        "cap-runtime-1",
        governed_receipt_id,
        create_amount.units,
        &accounts.beneficiary,
        receipt_content_hash,
    );
    let canonical_receipt_id = receipt.id.clone();
    let receipt_bytes = canonical_json_bytes(&receipt.body())?;
    let receipt_leaf = receipt_bytes.clone();
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&receipt_leaf))?;
    let checkpoint = build_checkpoint(1, 1, 1, &[receipt_bytes], &operator_keypair)?;
    let inclusion = build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)?;
    let anchor_target = EvmAnchorTarget {
        chain_id: config.chain_id.clone(),
        rpc_url: config.rpc_url.clone(),
        contract_address: config.root_registry_contract.clone(),
        operator_address: config.operator_address.clone(),
        publisher_address: config.operator_address.clone(),
    };
    let publication = prepare_root_publication(&anchor_target, &checkpoint, &binding)?;
    let egress_contract = evm_anchor_devnet_rpc_egress_contract(&config.rpc_url)?;
    let publish_tx = publish_root(&publication, &egress_contract)
        .await
        .map_err(|error| std::io::Error::other(format!("publish receipt root: {error}")))?;
    let confirmed_anchor = confirm_root_publication(
        &anchor_target,
        &checkpoint,
        &binding,
        &publish_tx,
        &egress_contract,
    )
    .await
    .map_err(|error| std::io::Error::other(format!("confirm receipt root: {error}")))?;
    let chain_anchor = build_chain_anchor_record(&anchor_target, &checkpoint, &confirmed_anchor);
    let evidence_bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::default(),
        tool_receipts: vec![EvidenceToolReceiptRecord {
            seq: inclusion.receipt_seq,
            receipt,
        }],
        child_receipts: vec![],
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: vec![checkpoint],
        capability_lineage: vec![],
        inclusion_proofs: vec![inclusion],
        uncheckpointed_receipts: vec![],
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(0),
            oldest_live_receipt_timestamp: None,
        },
    };
    let anchor_proof = build_anchor_inclusion_proof_from_evidence_bundle(
        &evidence_bundle,
        &canonical_receipt_id,
        Some(chain_anchor),
        binding.clone(),
    )?;

    let merkle_release = prepare_merkle_release(
        &config,
        &prepared_dispatch.dispatch,
        &anchor_proof,
        &SettlementAnchorContentBinding {
            execution_receipt_id: execution_receipt_id.to_string(),
            settlement_reference: settlement_reference.to_string(),
        },
        EscrowExecutionAmount::Full,
    )?;
    let settlement_root_call = prepare_merkle_release_root_publication(
        &config,
        &prepared_dispatch.dispatch,
        &merkle_release,
        2,
        2,
    )?;
    let settlement_root_tx = submit_call(&config, &settlement_root_call)
        .await
        .map_err(|error| std::io::Error::other(format!("publish settlement root: {error}")))?;
    let settlement_root_receipt = confirm_transaction(&config, &settlement_root_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm settlement root: {error}")))?;
    assert!(settlement_root_receipt.status);
    let merkle_release_tx = submit_call(&config, &merkle_release.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit merkle release: {error}")))?;
    let merkle_receipt = confirm_transaction(&config, &merkle_release_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm merkle release: {error}")))?;
    assert!(merkle_receipt.status);
    let projection = project_escrow_execution_receipt(
        &config,
        chio_settle::ExecutionProjectionInput {
            dispatch: &prepared_dispatch.dispatch,
            tx_hash: &merkle_release_tx,
            execution_receipt_id: execution_receipt_id.to_string(),
            settlement_reference: settlement_reference.to_string(),
            observed_at: Some(merkle_receipt.observed_at),
            observed_amount: create_amount.clone(),
            anchor_proof: Some(&anchor_proof),
            identity_registry_evidence: None,
            identity_registry_evidence_binding: None,
            oracle_evidence: None,
            failure_reason: None,
            reversal_of: None,
            note: Some("runtime devnet merkle release".to_string()),
        },
    )
    .await?;
    assert_eq!(
        projection.receipt.lifecycle_state,
        Web3SettlementLifecycleState::Settled
    );
    assert_eq!(
        projection.finality.status,
        SettlementFinalityStatus::Finalized
    );

    let approval_refund = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        750_000,
    )?;
    let approval_refund_tx = submit_call(&config, &approval_refund.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit refund approval: {error}")))?;
    confirm_transaction(&config, &approval_refund_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm refund approval: {error}")))?;

    let now = latest_block_timestamp(&config.rpc_url).await?;
    let refund_instruction = sample_capital_instruction(
        &instruction_key,
        &config.chain_id,
        &accounts.beneficiary,
        "cei-runtime-timeout",
        now,
        now + 5,
        75,
    );
    let refund_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-runtime-timeout".to_string(),
            issued_at: now,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-runtime-timeout".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: refund_instruction,
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("runtime devnet refund path".to_string()),
        },
        &binding,
    )
    .await?;
    let refund_create_tx = submit_call(&config, &refund_dispatch.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit refund escrow create: {error}")))?;
    let refund_create_receipt = confirm_transaction(&config, &refund_create_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm refund escrow create: {error}")))?;
    let refund_dispatch = finalize_escrow_dispatch(&refund_dispatch, &refund_create_receipt)?;
    advance_time(&config.rpc_url, 10).await?;
    let refund_call =
        prepare_escrow_refund(&config, &refund_dispatch.dispatch, &accounts.outsider)?;
    let refund_tx = submit_call(&config, &refund_call.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit escrow refund: {error}")))?;
    let refund_receipt = confirm_transaction(&config, &refund_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm escrow refund: {error}")))?;
    assert!(refund_receipt.status);
    let timeout_projection = project_escrow_execution_receipt(
        &config,
        chio_settle::ExecutionProjectionInput {
            dispatch: &refund_dispatch.dispatch,
            tx_hash: &refund_tx,
            execution_receipt_id: "exec-runtime-timeout".to_string(),
            settlement_reference: "settlement-runtime-timeout".to_string(),
            observed_at: Some(refund_receipt.observed_at),
            observed_amount: MonetaryAmount {
                units: 75,
                currency: "USD".to_string(),
            },
            anchor_proof: None,
            identity_registry_evidence: None,
            identity_registry_evidence_binding: None,
            oracle_evidence: None,
            failure_reason: Some("escrow deadline elapsed before release".to_string()),
            reversal_of: None,
            note: Some("runtime devnet timeout refund".to_string()),
        },
    )
    .await?;
    assert_eq!(
        timeout_projection.receipt.lifecycle_state,
        Web3SettlementLifecycleState::TimedOut
    );

    let approval_dual = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        150_000_000,
    )?;
    let approval_dual_tx = submit_call(&config, &approval_dual.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit dual approval: {error}")))?;
    confirm_transaction(&config, &approval_dual_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm dual approval: {error}")))?;
    let high_value_instruction = sample_capital_instruction(
        &instruction_key,
        &config.chain_id,
        &accounts.beneficiary,
        "cei-runtime-dual",
        issued_at,
        issued_at + 7_200,
        15_000,
    );
    let dual_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-runtime-dual".to_string(),
            issued_at,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-runtime-dual".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: high_value_instruction,
            settlement_path: Web3SettlementPath::DualSignature,
            oracle_evidence_required_for_fx: false,
            note: Some("runtime devnet dual-sign path".to_string()),
        },
        &binding,
    )
    .await?;
    let dual_create_tx = submit_call(&config, &dual_dispatch.call)
        .await
        .map_err(|error| std::io::Error::other(format!("submit dual escrow create: {error}")))?;
    let dual_create_receipt = confirm_transaction(&config, &dual_create_tx)
        .await
        .map_err(|error| std::io::Error::other(format!("confirm dual escrow create: {error}")))?;
    let dual_dispatch = finalize_escrow_dispatch(&dual_dispatch, &dual_create_receipt)?;
    let dual_receipt = sample_receipt(
        &operator_keypair,
        "cap-runtime-dual",
        "rcpt-runtime-dual",
        15_000,
        &accounts.beneficiary,
    );
    let dual_sign_release = prepare_dual_sign_release(
        &config,
        &dual_dispatch.dispatch,
        &dual_receipt,
        &DualSignReleaseInput {
            operator_private_key_hex: OPERATOR_PRIVATE_KEY.to_string(),
            observed_amount: MonetaryAmount {
                units: 15_000,
                currency: "USD".to_string(),
            },
        },
    )
    .await?;
    assert_eq!(
        dual_sign_release
            .identity_registry_evidence
            .identity_registry_contract,
        config.identity_registry_contract
    );
    assert_eq!(
        dual_sign_release
            .identity_registry_evidence
            .operator_address,
        config.operator_address
    );
    assert_ne!(
        dual_sign_release.identity_registry_evidence.block_hash,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert!(dual_sign_release.identity_registry_evidence.block_number > 0);
    assert!(dual_sign_release.identity_registry_evidence.active);
    static_validate_call(&config, &dual_sign_release.call)
        .await
        .map_err(|error| std::io::Error::other(format!("validate dual release: {error}")))?;
    let gas = estimate_call_gas(&config, &dual_sign_release.call)
        .await
        .map_err(|error| std::io::Error::other(format!("estimate dual release: {error}")))?;
    assert!(gas > 0);
    let (_, dual_finality) = inspect_finality(
        &config,
        &dual_create_tx,
        dual_dispatch.dispatch.settlement_amount.units,
        Some(issued_at),
    )
    .await?;
    assert!(matches!(
        dual_finality.status,
        SettlementFinalityStatus::AwaitingDisputeWindow | SettlementFinalityStatus::Finalized
    ));

    Ok(())
}
