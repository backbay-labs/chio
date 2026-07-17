use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
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
    CreditBondArtifact, CreditBondDisposition, CreditBondFinding, CreditBondLifecycleState,
    CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport, CreditBondSupportBoundary,
    CreditBondTerms, CreditFacilityCapitalSource, CreditScorecardBand, CreditScorecardConfidence,
    CreditScorecardSummary, ExposureLedgerQuery, ExposureLedgerSummary, SignedCreditBond,
};
use chio_core::crypto::Keypair;
use chio_core::hashing::sha256_hex;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::SignedExportEnvelope,
};
use chio_core::web3::anchors::{
    AnchorInclusionProof, OracleConversionEvidence, CHIO_LINK_ORACLE_AUTHORITY,
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
use chio_link::config::{
    build_default_egress_contract, OracleBackendKind, PairConfig, PriceOracleConfig,
};
use chio_link::{ChioLinkOracle, ExchangeRate, OracleBackend, OracleFuture, PriceOracleError};
use chio_settle::{
    confirm_transaction, estimate_call_gas, finalize_bond_lock, finalize_escrow_dispatch,
    inspect_finality_for_receipt, observe_bond, prepare_bond_expiry, prepare_bond_impair,
    prepare_bond_lock, prepare_bond_proof_root_publication, prepare_dual_sign_release,
    prepare_erc20_approval, prepare_escrow_refund, prepare_web3_escrow_dispatch,
    project_escrow_execution_receipt, submit_call, BondLockRequest, DualSignReleaseInput,
    EscrowDispatchRequest, ExecutionProjectionInput, LocalDevnetDeployment, PreparedBondProofRoot,
    SettlementFinalityStatus, SettlementRecoveryAction,
};
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};

const OPERATOR_PRIVATE_KEY: &str =
    "0x1000000000000000000000000000000000000000000000000000000000000002";
const PARTNER_QUALIFICATION_SCHEMA: &str = "chio.web3-e2e-qualification.v1";
const PARTNER_SCENARIO_SCHEMA: &str = "chio.web3-e2e-scenario.v1";

use chio_test_support::prelude::*;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .test_expect("repo root")
}

struct DevnetGuard {
    child: Child,
    deployment_path: PathBuf,
}

impl Drop for DevnetGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.deployment_path);
        if let Some(parent) = self.deployment_path.parent() {
            let _ = fs::remove_dir(parent);
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

fn e2e_step<T, E: std::fmt::Display>(
    label: &'static str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|error| std::io::Error::other(format!("{label}: {error}")).into())
}

struct StaticBackend {
    kind: OracleBackendKind,
    pair: String,
    response: Result<ExchangeRate, PriceOracleError>,
}

impl StaticBackend {
    fn new(
        kind: OracleBackendKind,
        pair: impl Into<String>,
        response: Result<ExchangeRate, PriceOracleError>,
    ) -> Self {
        Self {
            kind,
            pair: pair.into(),
            response,
        }
    }
}

impl OracleBackend for StaticBackend {
    fn kind(&self) -> OracleBackendKind {
        self.kind
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        let response = if self.pair == pair.pair() {
            self.response.clone()
        } else {
            Err(PriceOracleError::NoPairAvailable {
                base: pair.base.clone(),
                quote: pair.quote.clone(),
            })
        };
        Box::pin(async move { response })
    }
}

fn output_root() -> PathBuf {
    if let Ok(path) = std::env::var("CHIO_WEB3_E2E_OUTPUT_DIR") {
        return PathBuf::from(path);
    }
    std::env::temp_dir().join("chio-web3-e2e-qualification")
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

fn write_json(path: &Path, value: &impl Serialize) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).test_expect("create output directory");
    }
    let payload = serde_json::to_vec_pretty(value).test_expect("serialize json output");
    fs::write(path, payload).test_expect("write json output");
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
    fs::create_dir_all(deployment_dir)?;
    if deployment_path.exists() {
        fs::remove_file(deployment_path)?;
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

async fn latest_block_number(rpc_url: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let block = rpc_call(rpc_url, "eth_getBlockByNumber", json!(["latest", false])).await?;
    let number = block
        .get("number")
        .and_then(Value::as_str)
        .ok_or("latest block missing number")?;
    Ok(u64::from_str_radix(number.trim_start_matches("0x"), 16)?)
}

async fn advance_time(rpc_url: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    rpc_call(rpc_url, "evm_increaseTime", json!([seconds])).await?;
    rpc_call(rpc_url, "evm_mine", json!([])).await?;
    Ok(())
}

async fn snapshot_chain(rpc_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let snapshot = rpc_call(rpc_url, "evm_snapshot", json!([])).await?;
    match snapshot {
        Value::String(value) => Ok(value),
        Value::Number(value) => Ok(value.to_string()),
        other => Err(format!("unexpected snapshot id: {other}").into()),
    }
}

async fn revert_chain(rpc_url: &str, snapshot_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let reverted = rpc_call(rpc_url, "evm_revert", json!([snapshot_id])).await?;
    if reverted.as_bool() != Some(true) {
        return Err(format!("snapshot revert failed for {snapshot_id}: {reverted}").into());
    }
    Ok(())
}

async fn mine_to_block(rpc_url: &str, block_number: u64) -> Result<(), Box<dyn std::error::Error>> {
    while latest_block_number(rpc_url).await? < block_number {
        rpc_call(rpc_url, "evm_mine", json!([])).await?;
    }
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
        nonce: "runtime-devnet-e2e-binding".to_string(),
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
            content_hash: sha256_hex(format!("settlement:{receipt_id}").as_bytes()),
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

fn sample_credit_bond(
    keypair: &Keypair,
    bond_id: &str,
    facility_id: &str,
    issued_at: u64,
    expires_at: u64,
    collateral_units: u64,
    reserve_units: u64,
) -> SignedCreditBond {
    SignedCreditBond::sign(
        CreditBondArtifact {
            schema: chio_core::credit::CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
            bond_id: bond_id.to_string(),
            issued_at,
            expires_at,
            lifecycle_state: CreditBondLifecycleState::Active,
            supersedes_bond_id: None,
            report: CreditBondReport {
                schema: chio_core::credit::CREDIT_BOND_REPORT_SCHEMA.to_string(),
                generated_at: issued_at,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                exposure: ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                scorecard: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.97,
                    anomaly_count: 0,
                    probationary: false,
                },
                disposition: CreditBondDisposition::Hold,
                prerequisites: CreditBondPrerequisites {
                    active_facility_required: false,
                    active_facility_met: true,
                    runtime_assurance_met: true,
                    certification_required: false,
                    certification_met: true,
                    currency_coherent: true,
                },
                support_boundary: CreditBondSupportBoundary::default(),
                latest_facility_id: Some(facility_id.to_string()),
                terms: Some(CreditBondTerms {
                    facility_id: facility_id.to_string(),
                    credit_limit: MonetaryAmount {
                        units: collateral_units.saturating_mul(10),
                        currency: "USD".to_string(),
                    },
                    collateral_amount: MonetaryAmount {
                        units: collateral_units,
                        currency: "USD".to_string(),
                    },
                    reserve_requirement_amount: MonetaryAmount {
                        units: reserve_units,
                        currency: "USD".to_string(),
                    },
                    outstanding_exposure_amount: MonetaryAmount {
                        units: 0,
                        currency: "USD".to_string(),
                    },
                    reserve_ratio_bps: 10_000,
                    coverage_ratio_bps: 10_000,
                    capital_source: CreditFacilityCapitalSource::OperatorInternal,
                }),
                findings: vec![CreditBondFinding {
                    code: CreditBondReasonCode::ReserveHeld,
                    description: "reserve state is held".to_string(),
                    evidence_refs: Vec::new(),
                }],
            },
        },
        keypair,
    )
    .test_expect("credit bond")
}

fn sample_rate(pair: &PairConfig, source: &str, numerator: u128, updated_at: u64) -> ExchangeRate {
    ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator: numerator,
        rate_denominator: 100,
        updated_at,
        fetched_at: updated_at.saturating_add(5),
        source: source.to_string(),
        feed_reference: pair
            .chainlink
            .as_ref()
            .map(|feed| feed.address.clone())
            .or_else(|| pair.pyth.as_ref().map(|feed| feed.id.clone()))
            .unwrap_or_else(|| "feed-unavailable".to_string()),
        max_age_seconds: pair.policy.max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: None,
        confidence_denominator: None,
    }
}

async fn build_fx_oracle_evidence(
    original_cost_units: u64,
    converted_cost_units: u64,
) -> Result<OracleConversionEvidence, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut config =
        PriceOracleConfig::base_arbitrum_default("http://127.0.0.1:8545", "http://127.0.0.1:9545");
    config.pyth.hermes_url = "http://127.0.0.1:9000".to_string();
    for chain in &mut config.operator.chains {
        chain.sequencer_uptime_feed = None;
    }
    config.egress_contract = build_default_egress_contract(&config.pyth, &config.operator.chains);
    config.egress_contract.deny_loopback = false;
    let eth_pair = config
        .pairs
        .iter()
        .find(|pair| pair.base == "ETH" && pair.quote == "USD")
        .cloned()
        .ok_or("ETH/USD pair missing from chio-link base config")?;
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        eth_pair.pair(),
        Ok(sample_rate(
            &eth_pair,
            "chainlink:twap",
            325_000,
            now.saturating_sub(30),
        )),
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None)?;
    let rate = oracle.refresh_pair("ETH", "USD").await?;
    Ok(rate.to_conversion_evidence(original_cost_units, "ETH", "USD", converted_cost_units, now)?)
}

async fn publish_anchor_proof(
    config: &chio_settle::SettlementChainConfig,
    binding: &SignedWeb3IdentityBinding,
    operator_keypair: &Keypair,
    capability_id: &str,
    receipt_id: &str,
    amount_units: u64,
    beneficiary_address: &str,
) -> Result<AnchorInclusionProof, Box<dyn std::error::Error>> {
    let receipt = sample_receipt(
        operator_keypair,
        capability_id,
        receipt_id,
        amount_units,
        beneficiary_address,
    );
    let canonical_receipt_id = receipt.id.clone();
    let receipt_bytes = canonical_json_bytes(&receipt.body())?;
    let receipt_leaf = receipt_bytes.clone();
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&receipt_leaf))?;
    let checkpoint = build_checkpoint(1, 1, 1, &[receipt_bytes], operator_keypair)?;
    let inclusion = build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)?;
    let anchor_target = EvmAnchorTarget {
        chain_id: config.chain_id.clone(),
        rpc_url: config.rpc_url.clone(),
        contract_address: config.root_registry_contract.clone(),
        operator_address: config.operator_address.clone(),
        publisher_address: config.operator_address.clone(),
    };
    let publication = prepare_root_publication(&anchor_target, &checkpoint, binding)?;
    let egress_contract = evm_anchor_devnet_rpc_egress_contract(&config.rpc_url)?;
    let publish_tx = e2e_step(
        "publish anchor root",
        publish_root(&publication, &egress_contract).await,
    )?;
    let confirmed_anchor = e2e_step(
        "confirm anchor root",
        confirm_root_publication(
            &anchor_target,
            &checkpoint,
            binding,
            &publish_tx,
            &egress_contract,
        )
        .await,
    )?;
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
    Ok(build_anchor_inclusion_proof_from_evidence_bundle(
        &evidence_bundle,
        &canonical_receipt_id,
        Some(chain_anchor),
        binding.clone(),
    )?)
}

#[tokio::test]
async fn web3_partner_qualification_emits_integrated_recovery_bundle(
) -> Result<(), Box<dyn std::error::Error>> {
    if !runtime_devnet_prereqs_available() {
        eprintln!(
            "skipping web3 runtime-devnet qualification test because node-based prerequisites are unavailable"
        );
        return Ok(());
    }

    let root = output_root();
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(root.join("scenarios"))?;

    let deployment_path = unique_runtime_devnet_deployment_path("runtime-devnet-e2e.json");
    let operator_keypair = Keypair::from_seed_hex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    let operator_ed_key_hash = format!(
        "0x{}",
        hex::encode(
            alloy_primitives::keccak256(operator_keypair.public_key().as_bytes()).as_slice()
        )
    );
    let _devnet = spawn_runtime_devnet(&deployment_path, &operator_ed_key_hash, 8549).await?;

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
    let bond_key = Keypair::from_seed_hex(
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )?;

    let generated_at = latest_block_timestamp(&config.rpc_url).await?;
    let anchor_proof = publish_anchor_proof(
        &config,
        &binding,
        &operator_keypair,
        "cap-e2e-anchor",
        "rcpt-e2e-anchor",
        250,
        &accounts.beneficiary,
    )
    .await?;
    let oracle_evidence = build_fx_oracle_evidence(46_153_846_153_846_153, 15_000).await?;

    let dual_amount = MonetaryAmount {
        units: 15_000,
        currency: "USD".to_string(),
    };
    let dual_approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        150_000_000,
    )?;
    let dual_approval_tx = e2e_step(
        "submit dual approval",
        submit_call(&config, &dual_approval.call).await,
    )?;
    e2e_step(
        "confirm dual approval",
        confirm_transaction(&config, &dual_approval_tx).await,
    )?;
    let dual_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-e2e-dual-fx".to_string(),
            issued_at: generated_at,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-e2e-dual-fx".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: sample_capital_instruction(
                &instruction_key,
                &config.chain_id,
                &accounts.beneficiary,
                "cei-e2e-dual-fx",
                generated_at,
                generated_at + 7_200,
                dual_amount.units,
            ),
            settlement_path: Web3SettlementPath::DualSignature,
            oracle_evidence_required_for_fx: true,
            note: Some("partner-visible FX-backed dual-sign settlement".to_string()),
        },
        &binding,
    )
    .await?;
    let dual_create_tx = e2e_step(
        "submit dual escrow create",
        submit_call(&config, &dual_dispatch.call).await,
    )?;
    let dual_create_receipt = e2e_step(
        "confirm dual escrow create",
        confirm_transaction(&config, &dual_create_tx).await,
    )?;
    let dual_dispatch = finalize_escrow_dispatch(&dual_dispatch, &dual_create_receipt)?;
    let dual_receipt = sample_receipt(
        &operator_keypair,
        "cap-e2e-dual-fx",
        "rcpt-e2e-dual-fx",
        dual_amount.units,
        &accounts.beneficiary,
    );
    let dual_release = prepare_dual_sign_release(
        &config,
        &dual_dispatch.dispatch,
        &dual_receipt,
        &DualSignReleaseInput {
            operator_private_key_hex: OPERATOR_PRIVATE_KEY.to_string(),
            observed_amount: dual_amount.clone(),
        },
    )
    .await?;
    assert_eq!(
        dual_release
            .identity_registry_evidence
            .identity_registry_contract,
        config.identity_registry_contract
    );
    assert_eq!(
        dual_release.identity_registry_evidence.operator_address,
        config.operator_address
    );
    assert_ne!(
        dual_release.identity_registry_evidence.block_hash,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert!(dual_release.identity_registry_evidence.block_number > 0);
    assert!(dual_release.identity_registry_evidence.active);
    let gas_estimate = estimate_call_gas(&config, &dual_release.call).await?;
    let dual_release_tx = e2e_step(
        "submit dual escrow release",
        submit_call(&config, &dual_release.call).await,
    )?;
    let dual_release_receipt = e2e_step(
        "confirm dual escrow release",
        confirm_transaction(&config, &dual_release_tx).await,
    )?;
    let dual_projection = project_escrow_execution_receipt(
        &config,
        ExecutionProjectionInput {
            dispatch: &dual_dispatch.dispatch,
            tx_hash: &dual_release_tx,
            execution_receipt_id: "exec-e2e-dual-fx".to_string(),
            settlement_reference: "settlement-e2e-dual-fx".to_string(),
            observed_at: Some(dual_release_receipt.observed_at.saturating_add(3_601)),
            observed_amount: dual_amount.clone(),
            anchor_proof: None,
            identity_registry_evidence: Some(
                dual_release.identity_registry_evidence.clone().into(),
            ),
            identity_registry_evidence_binding: Some(
                dual_release
                    .identity_registry_evidence_binding
                    .clone()
                    .into(),
            ),
            oracle_evidence: Some(&oracle_evidence),
            failure_reason: None,
            reversal_of: None,
            note: Some("FX-backed dual-sign execution".to_string()),
        },
    )
    .await?;
    assert_eq!(
        dual_projection.receipt.lifecycle_state,
        Web3SettlementLifecycleState::Settled
    );
    assert_eq!(
        dual_projection.finality.status,
        SettlementFinalityStatus::Finalized
    );
    assert_eq!(
        dual_projection
            .receipt
            .identity_registry_evidence
            .as_ref()
            .test_expect("dual-sign registry evidence")
            .operator_key_hash,
        dual_release.identity_registry_evidence.operator_key_hash
    );
    assert_eq!(
        dual_projection
            .receipt
            .oracle_evidence
            .as_ref()
            .test_expect("oracle evidence")
            .authority,
        CHIO_LINK_ORACLE_AUTHORITY
    );
    let dual_scenario = json!({
        "schema": PARTNER_SCENARIO_SCHEMA,
        "id": "fx-dual-sign-settlement",
        "status": "pass",
        "dispatchId": dual_projection.receipt.dispatch.dispatch_id,
        "escrowId": dual_projection.receipt.dispatch.escrow_id,
        "txHash": dual_release_tx,
        "gasEstimate": gas_estimate,
        "identityRegistryEvidence": dual_release.identity_registry_evidence,
        "finalityStatus": dual_projection.finality.status,
        "lifecycleState": dual_projection.receipt.lifecycle_state,
        "oracleAuthority": dual_projection.receipt.oracle_evidence.as_ref().map(|e| e.authority.clone()),
        "settledAmount": dual_projection.receipt.settled_amount,
    });
    write_json(
        &root.join("scenarios/fx-dual-sign-settlement.json"),
        &dual_scenario,
    );

    let refund_approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        750_000,
    )?;
    let refund_approval_tx = e2e_step(
        "submit refund approval",
        submit_call(&config, &refund_approval.call).await,
    )?;
    e2e_step(
        "confirm refund approval",
        confirm_transaction(&config, &refund_approval_tx).await,
    )?;
    let refund_now = latest_block_timestamp(&config.rpc_url).await?;
    let refund_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-e2e-timeout".to_string(),
            issued_at: refund_now,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-e2e-timeout".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: sample_capital_instruction(
                &instruction_key,
                &config.chain_id,
                &accounts.beneficiary,
                "cei-e2e-timeout",
                refund_now,
                refund_now + 5,
                75,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("partner-visible timeout refund".to_string()),
        },
        &binding,
    )
    .await?;
    let refund_create_tx = e2e_step(
        "submit refund escrow create",
        submit_call(&config, &refund_dispatch.call).await,
    )?;
    let refund_create_receipt = e2e_step(
        "confirm refund escrow create",
        confirm_transaction(&config, &refund_create_tx).await,
    )?;
    let refund_dispatch = finalize_escrow_dispatch(&refund_dispatch, &refund_create_receipt)?;
    advance_time(&config.rpc_url, 10).await?;
    let refund_call =
        prepare_escrow_refund(&config, &refund_dispatch.dispatch, &accounts.outsider)?;
    let refund_tx = e2e_step(
        "submit refund",
        submit_call(&config, &refund_call.call).await,
    )?;
    let refund_receipt = e2e_step(
        "confirm refund",
        confirm_transaction(&config, &refund_tx).await,
    )?;
    let refund_projection = project_escrow_execution_receipt(
        &config,
        ExecutionProjectionInput {
            dispatch: &refund_dispatch.dispatch,
            tx_hash: &refund_tx,
            execution_receipt_id: "exec-e2e-timeout".to_string(),
            settlement_reference: "settlement-e2e-timeout".to_string(),
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
            note: Some("timeout refund recovery".to_string()),
        },
    )
    .await?;
    assert_eq!(
        refund_projection.receipt.lifecycle_state,
        Web3SettlementLifecycleState::TimedOut
    );
    assert_eq!(
        refund_projection.recovery_action,
        Some(SettlementRecoveryAction::ExecuteRefund)
    );
    let refund_scenario = json!({
        "schema": PARTNER_SCENARIO_SCHEMA,
        "id": "timeout-refund-recovery",
        "status": "pass",
        "dispatchId": refund_projection.receipt.dispatch.dispatch_id,
        "escrowId": refund_projection.receipt.dispatch.escrow_id,
        "txHash": refund_tx,
        "finalityStatus": refund_projection.finality.status,
        "lifecycleState": refund_projection.receipt.lifecycle_state,
        "recoveryAction": refund_projection.recovery_action,
    });
    write_json(
        &root.join("scenarios/timeout-refund-recovery.json"),
        &refund_scenario,
    );

    let reorg_approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.depositor,
        &config.escrow_contract,
        900_000,
    )?;
    let reorg_approval_tx = e2e_step(
        "submit reorg approval",
        submit_call(&config, &reorg_approval.call).await,
    )?;
    e2e_step(
        "confirm reorg approval",
        confirm_transaction(&config, &reorg_approval_tx).await,
    )?;
    let snapshot_id = snapshot_chain(&config.rpc_url).await?;
    let reorg_now = latest_block_timestamp(&config.rpc_url).await?;
    let reorg_dispatch = prepare_web3_escrow_dispatch(
        &config,
        &EscrowDispatchRequest {
            dispatch_id: "dispatch-e2e-reorg".to_string(),
            issued_at: reorg_now,
            trust_profile_id: "chio.runtime-devnet".to_string(),
            contract_package_id: "chio.runtime-devnet-contracts".to_string(),
            capability_id: "cap-e2e-reorg".to_string(),
            depositor_address: accounts.depositor.clone(),
            beneficiary_address: accounts.beneficiary.clone(),
            capital_instruction: sample_capital_instruction(
                &instruction_key,
                &config.chain_id,
                &accounts.beneficiary,
                "cei-e2e-reorg",
                reorg_now,
                reorg_now + 7_200,
                90,
            ),
            settlement_path: Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: false,
            note: Some("canonical drift recovery".to_string()),
        },
        &binding,
    )
    .await?;
    let reorg_tx = e2e_step(
        "submit reorg escrow create",
        submit_call(&config, &reorg_dispatch.call).await,
    )?;
    let reorg_receipt = e2e_step(
        "confirm reorg escrow create",
        confirm_transaction(&config, &reorg_tx).await,
    )?;
    revert_chain(&config.rpc_url, &snapshot_id).await?;
    mine_to_block(&config.rpc_url, reorg_receipt.block_number).await?;
    let canonical_block = rpc_call(
        &config.rpc_url,
        "eth_getBlockByNumber",
        json!([format!("0x{:x}", reorg_receipt.block_number), false]),
    )
    .await?;
    let reorg_finality =
        inspect_finality_for_receipt(&config, &reorg_receipt, 90, Some(reorg_receipt.observed_at))
            .await?;
    assert_eq!(reorg_finality.status, SettlementFinalityStatus::Reorged);
    let reorg_scenario = json!({
        "schema": PARTNER_SCENARIO_SCHEMA,
        "id": "reorg-recovery",
        "status": "pass",
        "txHash": reorg_tx,
        "originalBlockNumber": reorg_receipt.block_number,
        "originalBlockHash": reorg_receipt.block_hash,
        "canonicalBlockHashAfterRevert": canonical_block.get("hash").and_then(Value::as_str),
        "finalityStatus": reorg_finality.status,
        "recoveryAction": SettlementRecoveryAction::ResubmitAfterReorg,
    });
    write_json(&root.join("scenarios/reorg-recovery.json"), &reorg_scenario);

    let impair_bond = sample_credit_bond(
        &bond_key,
        "cbd-e2e-impair",
        "cfd-e2e-impair",
        generated_at,
        generated_at + 7_200,
        400,
        400,
    );
    let impair_lock = prepare_bond_lock(
        &config,
        &BondLockRequest {
            principal_address: accounts.principal.clone(),
            bond: impair_bond,
        },
        &binding,
    )
    .await?;
    let impair_approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.principal,
        &config.bond_vault_contract,
        impair_lock.collateral_minor_units,
    )?;
    let impair_approval_tx = e2e_step(
        "submit impair approval",
        submit_call(&config, &impair_approval.call).await,
    )?;
    e2e_step(
        "confirm impair approval",
        confirm_transaction(&config, &impair_approval_tx).await,
    )?;
    let impair_lock_tx = e2e_step(
        "submit impair bond lock",
        submit_call(&config, &impair_lock.call).await,
    )?;
    let impair_lock_receipt = e2e_step(
        "confirm impair bond lock",
        confirm_transaction(&config, &impair_lock_tx).await,
    )?;
    let impair_lock = finalize_bond_lock(&impair_lock, &impair_lock_receipt)?;
    let impair_active = observe_bond(&config, &impair_lock.vault_id).await?;
    let impair_call = prepare_bond_impair(
        &config,
        &config.operator_address,
        &impair_active.snapshot,
        &MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        },
        std::slice::from_ref(&accounts.beneficiary),
        &[MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        }],
        &anchor_proof,
    )?;
    let impair_root_call = prepare_bond_proof_root_publication(
        &config,
        &impair_active.snapshot,
        PreparedBondProofRoot::Impair(&impair_call),
        2,
        2,
    )?;
    let impair_root_tx = e2e_step(
        "submit impair proof root",
        submit_call(&config, &impair_root_call).await,
    )?;
    let impair_root_receipt = e2e_step(
        "confirm impair proof root",
        confirm_transaction(&config, &impair_root_tx).await,
    )?;
    if !impair_root_receipt.status {
        return Err(std::io::Error::other("impair proof root publication reverted").into());
    }
    let impair_tx = e2e_step(
        "submit bond impair",
        submit_call(&config, &impair_call.call).await,
    )?;
    e2e_step(
        "confirm bond impair",
        confirm_transaction(&config, &impair_tx).await,
    )?;
    let impair_observation = observe_bond(&config, &impair_lock.vault_id).await?;
    assert_eq!(
        impair_active.status,
        chio_settle::BondLifecycleStatus::Active
    );
    assert_eq!(
        impair_observation.status,
        chio_settle::BondLifecycleStatus::Impaired
    );
    assert_eq!(
        impair_observation.recovery_action,
        Some(SettlementRecoveryAction::ManualReview)
    );
    let impair_scenario = json!({
        "schema": PARTNER_SCENARIO_SCHEMA,
        "id": "bond-impair-recovery",
        "status": "pass",
        "vaultId": impair_lock.vault_id,
        "statusBefore": impair_active.status,
        "statusAfter": impair_observation.status,
        "recoveryAction": impair_observation.recovery_action,
        "slashedMinorUnits": impair_observation.snapshot.slashed_minor_units,
    });
    write_json(
        &root.join("scenarios/bond-impair-recovery.json"),
        &impair_scenario,
    );

    let expiry_now = latest_block_timestamp(&config.rpc_url).await?;
    let expiry_bond = sample_credit_bond(
        &bond_key,
        "cbd-e2e-expiry",
        "cfd-e2e-expiry",
        expiry_now,
        expiry_now + 5,
        125,
        125,
    );
    let expiry_lock = prepare_bond_lock(
        &config,
        &BondLockRequest {
            principal_address: accounts.principal.clone(),
            bond: expiry_bond,
        },
        &binding,
    )
    .await?;
    let expiry_approval = prepare_erc20_approval(
        &config.settlement_token_address,
        &accounts.principal,
        &config.bond_vault_contract,
        expiry_lock.collateral_minor_units,
    )?;
    let expiry_approval_tx = e2e_step(
        "submit expiry approval",
        submit_call(&config, &expiry_approval.call).await,
    )?;
    e2e_step(
        "confirm expiry approval",
        confirm_transaction(&config, &expiry_approval_tx).await,
    )?;
    let expiry_lock_tx = e2e_step(
        "submit expiry bond lock",
        submit_call(&config, &expiry_lock.call).await,
    )?;
    let expiry_lock_receipt = e2e_step(
        "confirm expiry bond lock",
        confirm_transaction(&config, &expiry_lock_tx).await,
    )?;
    let expiry_lock = finalize_bond_lock(&expiry_lock, &expiry_lock_receipt)?;
    advance_time(&config.rpc_url, 10).await?;
    let expiry_call = prepare_bond_expiry(&config, &expiry_lock.vault_id, &accounts.outsider)?;
    let expiry_tx = e2e_step(
        "submit bond expiry",
        submit_call(&config, &expiry_call.call).await,
    )?;
    e2e_step(
        "confirm bond expiry",
        confirm_transaction(&config, &expiry_tx).await,
    )?;
    let expiry_observation = observe_bond(&config, &expiry_lock.vault_id).await?;
    assert_eq!(
        expiry_observation.status,
        chio_settle::BondLifecycleStatus::Expired
    );
    assert_eq!(expiry_observation.recovery_action, None);
    let expiry_scenario = json!({
        "schema": PARTNER_SCENARIO_SCHEMA,
        "id": "bond-expiry-recovery",
        "status": "pass",
        "vaultId": expiry_lock.vault_id,
        "statusAfter": expiry_observation.status,
        "recoveryAction": expiry_observation.recovery_action,
        "expired": expiry_observation.snapshot.expired,
    });
    write_json(
        &root.join("scenarios/bond-expiry-recovery.json"),
        &expiry_scenario,
    );

    let summary = json!({
        "schema": PARTNER_QUALIFICATION_SCHEMA,
        "generatedAt": generated_at,
        "chainId": config.chain_id,
        "network": config.network_name,
        "status": "pass",
        "claims": [
            "fx-backed settlement requires and carries chio-link oracle evidence",
            "dual-sign settlement executes on chain and projects finalized receipt truth",
            "timeout refund, canonical drift, bond impairment, and bond expiry remain explicit recovery surfaces",
            "the same evidence family stages cleanly into the hosted web3 release bundle"
        ],
        "localArtifacts": [
            "target/web3-e2e-qualification/partner-qualification.json",
            "target/web3-e2e-qualification/scenarios/fx-dual-sign-settlement.json",
            "target/web3-e2e-qualification/scenarios/timeout-refund-recovery.json",
            "target/web3-e2e-qualification/scenarios/reorg-recovery.json",
            "target/web3-e2e-qualification/scenarios/bond-impair-recovery.json",
            "target/web3-e2e-qualification/scenarios/bond-expiry-recovery.json"
        ],
        "hostedArtifacts": [
            "target/release-qualification/web3-runtime/e2e/partner-qualification.json",
            "target/release-qualification/web3-runtime/e2e/scenarios/fx-dual-sign-settlement.json",
            "target/release-qualification/web3-runtime/e2e/scenarios/timeout-refund-recovery.json",
            "target/release-qualification/web3-runtime/e2e/scenarios/reorg-recovery.json",
            "target/release-qualification/web3-runtime/e2e/scenarios/bond-impair-recovery.json",
            "target/release-qualification/web3-runtime/e2e/scenarios/bond-expiry-recovery.json"
        ]
    });
    write_json(&root.join("partner-qualification.json"), &summary);

    Ok(())
}
