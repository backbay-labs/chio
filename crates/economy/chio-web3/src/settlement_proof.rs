use serde::{Deserialize, Serialize};

use crate::credit::CapitalBookEvidenceKind;
use crate::error::Web3ContractError;
use crate::hashing::Hash;
use crate::identity::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3KeyBindingPurpose,
};
use crate::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementExecutionReceiptArtifact,
    Web3SettlementLifecycleState,
};
use crate::trust_profile::Web3SettlementPath;
use crate::validation::{ensure_money, ensure_non_empty};

pub const CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA: &str = "chio.web3-settlement-dispute.v1";
pub const CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA: &str =
    "chio.public-settlement-verifier-report.v1";

pub const CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED: &str =
    "claim.public_settlement.order_binding_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED: &str =
    "claim.public_settlement.chain_context_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED: &str =
    "claim.public_settlement.finality_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND: &str =
    "claim.public_settlement.oracle_conversion_bound";
pub const CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND: &str =
    "claim.public_settlement.dispute_posture_bound";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementProofBundle {
    pub schema: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub chain_id: String,
    pub settlement_receipt: Web3SettlementExecutionReceiptArtifact,
    pub chain_snapshot: PublicSettlementChainSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_snapshot: Option<PublicSettlementDisputeSnapshot>,
    pub required_confirmations: u32,
    pub observed_confirmations: u32,
    pub dispute_posture: PublicSettlementDisputePosture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementChainSnapshot {
    pub chain_id: String,
    pub observed_block_number: u64,
    pub latest_block_number: u64,
    pub max_block_lag: u64,
    pub root_registry_address: String,
    pub registry_root: String,
    pub escrow: PublicSettlementEscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<PublicSettlementBondSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<PublicSettlementBlockSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary_identity_binding: Option<SignedWeb3IdentityBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementEscrowSnapshot {
    pub escrow_id: String,
    pub escrow_contract: String,
    pub beneficiary_address: String,
    pub locked_amount: crate::capability::scope::MonetaryAmount,
    pub released_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBondSnapshot {
    pub bond_vault_contract: String,
    pub posted_amount: crate::capability::scope::MonetaryAmount,
    pub minimum_required_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBlockSnapshot {
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDisputeSnapshot {
    pub schema: String,
    pub dispute_id: String,
    pub posture: PublicSettlementDisputePosture,
    pub observed_at: u64,
    pub challenge_window_secs: u64,
    pub window_closed_at: u64,
    pub open_dispute_count: u32,
    pub linked_receipt_ids: Vec<String>,
    pub chain_event_tx_hashes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementDisputePosture {
    Undisputed,
    Challenged,
    Bonded,
    Slashed,
    Refunded,
    Appealed,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementVerifierReport {
    pub schema: String,
    pub id: String,
    pub verdict: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub recomputed_settlement_state: String,
    pub chain_context: PublicSettlementChainContext,
    pub finality_decision: PublicSettlementFinalityDecision,
    pub dispute_context: PublicSettlementDisputeContext,
    pub dispute_posture: PublicSettlementDisputePosture,
    pub verified_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementChainContext {
    pub chain_id: String,
    pub settlement_path: Web3SettlementPath,
    pub settlement_reference: String,
    pub observed_block_number: u64,
    pub registry_root: String,
    pub escrow_id: String,
    pub bond_vault_contract: String,
    pub posted_bond_amount: crate::capability::scope::MonetaryAmount,
    pub minimum_bond_amount: crate::capability::scope::MonetaryAmount,
    pub block_hash: String,
    pub anchor_tx_hash: String,
    pub settlement_tx_hash: String,
    pub beneficiary_address: String,
    pub beneficiary_chio_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDisputeContext {
    pub dispute_id: String,
    pub posture: PublicSettlementDisputePosture,
    pub observed_at: u64,
    pub challenge_window_secs: u64,
    pub window_closed_at: u64,
    pub open_dispute_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementFinalityDecision {
    pub status: String,
    pub required_confirmations: u32,
    pub observed_confirmations: u32,
}

pub fn verify_public_settlement_proof(
    bundle: &PublicSettlementProofBundle,
) -> Result<PublicSettlementVerifierReport, Web3ContractError> {
    validate_bundle_header(bundle)?;
    validate_web3_settlement_execution_receipt(&bundle.settlement_receipt)?;
    validate_order_binding(bundle)?;
    validate_chain_binding(bundle)?;
    validate_chain_snapshot(bundle)?;
    validate_finality(bundle)?;
    validate_dispute_posture(bundle)?;
    let bond = required_bond_snapshot(bundle)?;
    let block = required_block_snapshot(bundle)?;
    let chain_anchor = required_chain_anchor(bundle)?;
    let beneficiary_binding = required_beneficiary_identity_binding(bundle)?;
    let dispute_snapshot = required_dispute_snapshot(bundle)?;

    let mut verified_claims = Vec::new();
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED,
    );
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED,
    );
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED,
    );
    if bundle.settlement_receipt.oracle_evidence.is_some() {
        push_claim_once(
            &mut verified_claims,
            CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND,
        );
    }
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND,
    );

    Ok(PublicSettlementVerifierReport {
        schema: CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA.to_string(),
        id: format!("public-settlement-verifier-report-{}", bundle.bundle_id),
        verdict: "verified".to_string(),
        bundle_id: bundle.bundle_id.clone(),
        transaction_passport_id: bundle.transaction_passport_id.clone(),
        commerce_order_id: bundle.commerce_order_id.clone(),
        recomputed_settlement_state: settlement_state_id(bundle.settlement_receipt.lifecycle_state)
            .to_string(),
        chain_context: PublicSettlementChainContext {
            chain_id: bundle.chain_id.clone(),
            settlement_path: bundle.settlement_receipt.dispatch.settlement_path,
            settlement_reference: bundle.settlement_receipt.settlement_reference.clone(),
            observed_block_number: bundle.chain_snapshot.observed_block_number,
            registry_root: bundle.chain_snapshot.registry_root.clone(),
            escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
            bond_vault_contract: bond.bond_vault_contract.clone(),
            posted_bond_amount: bond.posted_amount.clone(),
            minimum_bond_amount: bond.minimum_required_amount.clone(),
            block_hash: block.block_hash.clone(),
            anchor_tx_hash: chain_anchor.tx_hash.clone(),
            settlement_tx_hash: bundle
                .settlement_receipt
                .observed_execution
                .external_reference_id
                .clone(),
            beneficiary_address: beneficiary_binding.certificate.settlement_address.clone(),
            beneficiary_chio_identity: beneficiary_binding.certificate.chio_identity.clone(),
        },
        finality_decision: PublicSettlementFinalityDecision {
            status: finality_report_status(bundle).to_string(),
            required_confirmations: bundle.required_confirmations,
            observed_confirmations: bundle.observed_confirmations,
        },
        dispute_context: PublicSettlementDisputeContext {
            dispute_id: dispute_snapshot.dispute_id.clone(),
            posture: dispute_snapshot.posture,
            observed_at: dispute_snapshot.observed_at,
            challenge_window_secs: dispute_snapshot.challenge_window_secs,
            window_closed_at: dispute_snapshot.window_closed_at,
            open_dispute_count: dispute_snapshot.open_dispute_count,
        },
        dispute_posture: bundle.dispute_posture,
        verified_claims,
    })
}

fn validate_bundle_header(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.schema != CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(bundle.schema.clone()));
    }
    ensure_non_empty(&bundle.bundle_id, "public_settlement.bundle_id")?;
    ensure_non_empty(
        &bundle.transaction_passport_id,
        "public_settlement.transaction_passport_id",
    )?;
    ensure_non_empty(
        &bundle.commerce_order_id,
        "public_settlement.commerce_order_id",
    )?;
    ensure_non_empty(&bundle.chain_id, "public_settlement.chain_id")?;
    if bundle.required_confirmations == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement proof requires a positive finality threshold".to_string(),
        ));
    }
    Ok(())
}

fn validate_chain_binding(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.settlement_receipt.dispatch.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "settlement chain id mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_chain_snapshot(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    let snapshot = &bundle.chain_snapshot;
    ensure_non_empty(
        &snapshot.chain_id,
        "public_settlement.chain_snapshot.chain_id",
    )?;
    ensure_non_empty(
        &snapshot.root_registry_address,
        "public_settlement.chain_snapshot.root_registry_address",
    )?;
    ensure_non_empty(
        &snapshot.registry_root,
        "public_settlement.chain_snapshot.registry_root",
    )?;
    if snapshot.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement chain snapshot chain id mismatch".to_string(),
        ));
    }
    if snapshot.max_block_lag == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot max_block_lag must be non-zero".to_string(),
        ));
    }
    if snapshot.latest_block_number < snapshot.observed_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot latest block precedes observed block".to_string(),
        ));
    }
    if snapshot.latest_block_number - snapshot.observed_block_number > snapshot.max_block_lag {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot is stale".to_string(),
        ));
    }

    let chain_anchor = required_chain_anchor(bundle)?;
    if snapshot.observed_block_number < chain_anchor.block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot predates anchored settlement block".to_string(),
        ));
    }
    if snapshot.root_registry_address != chain_anchor.contract_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement root registry address mismatch".to_string(),
        ));
    }
    let registry_root = Hash::from_hex(&snapshot.registry_root)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if registry_root != chain_anchor.anchored_merkle_root {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement registry root mismatch".to_string(),
        ));
    }

    validate_escrow_snapshot(bundle, &snapshot.escrow)?;
    validate_bond_snapshot(bundle, required_bond_snapshot(bundle)?)?;
    validate_block_snapshot(bundle, required_block_snapshot(bundle)?, chain_anchor)?;
    validate_beneficiary_identity_binding(bundle, required_beneficiary_identity_binding(bundle)?)?;
    Ok(())
}

fn required_chain_anchor(
    bundle: &PublicSettlementProofBundle,
) -> Result<&crate::anchors::Web3ChainAnchorRecord, Web3ContractError> {
    bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .and_then(|proof| proof.chain_anchor.as_ref())
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement chain snapshot requires a chain anchor".to_string(),
            )
        })
}

fn required_bond_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementBondSnapshot, Web3ContractError> {
    bundle.chain_snapshot.bond.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement bond snapshot missing".to_string())
    })
}

fn required_block_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementBlockSnapshot, Web3ContractError> {
    bundle.chain_snapshot.block.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement block snapshot missing".to_string())
    })
}

fn required_beneficiary_identity_binding(
    bundle: &PublicSettlementProofBundle,
) -> Result<&SignedWeb3IdentityBinding, Web3ContractError> {
    bundle
        .chain_snapshot
        .beneficiary_identity_binding
        .as_ref()
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement beneficiary identity binding missing".to_string(),
            )
        })
}

fn required_dispute_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementDisputeSnapshot, Web3ContractError> {
    bundle.dispute_snapshot.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement dispute snapshot missing".to_string())
    })
}

fn validate_beneficiary_identity_binding(
    bundle: &PublicSettlementProofBundle,
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    verify_web3_identity_binding(binding)?;
    let certificate = &binding.certificate;
    if !certificate.purpose.contains(&Web3KeyBindingPurpose::Settle) {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding requires settle purpose".to_string(),
        ));
    }
    if !certificate
        .chain_scope
        .iter()
        .any(|chain_id| chain_id == &bundle.chain_id)
    {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding chain mismatch".to_string(),
        ));
    }
    if certificate.settlement_address != bundle.settlement_receipt.dispatch.beneficiary_address {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding address mismatch".to_string(),
        ));
    }
    let settlement_observed_at = bundle.settlement_receipt.observed_execution.observed_at;
    if certificate.issued_at > settlement_observed_at
        || certificate.expires_at <= settlement_observed_at
    {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding not valid at settlement time"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_escrow_snapshot(
    bundle: &PublicSettlementProofBundle,
    escrow: &PublicSettlementEscrowSnapshot,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &escrow.escrow_id,
        "public_settlement.chain_snapshot.escrow.escrow_id",
    )?;
    ensure_non_empty(
        &escrow.escrow_contract,
        "public_settlement.chain_snapshot.escrow.escrow_contract",
    )?;
    ensure_non_empty(
        &escrow.beneficiary_address,
        "public_settlement.chain_snapshot.escrow.beneficiary_address",
    )?;
    let dispatch = &bundle.settlement_receipt.dispatch;
    if escrow.escrow_id != dispatch.escrow_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow id mismatch".to_string(),
        ));
    }
    if escrow.escrow_contract != dispatch.escrow_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow contract mismatch".to_string(),
        ));
    }
    if escrow.beneficiary_address != dispatch.beneficiary_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow beneficiary mismatch".to_string(),
        ));
    }
    if escrow.locked_amount.currency != dispatch.settlement_amount.currency
        || escrow.released_amount.currency != dispatch.settlement_amount.currency
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow currency mismatch".to_string(),
        ));
    }
    if escrow.locked_amount.units < dispatch.settlement_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow balance below required amount".to_string(),
        ));
    }
    if escrow.released_amount.units != bundle.settlement_receipt.settled_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow released amount mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_bond_snapshot(
    bundle: &PublicSettlementProofBundle,
    bond: &PublicSettlementBondSnapshot,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &bond.bond_vault_contract,
        "public_settlement.chain_snapshot.bond.bond_vault_contract",
    )?;
    ensure_money(
        &bond.posted_amount,
        "public_settlement.chain_snapshot.bond.posted_amount",
    )?;
    ensure_money(
        &bond.minimum_required_amount,
        "public_settlement.chain_snapshot.bond.minimum_required_amount",
    )?;

    let dispatch = &bundle.settlement_receipt.dispatch;
    if bond.bond_vault_contract != dispatch.bond_vault_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond vault mismatch".to_string(),
        ));
    }
    if bond.posted_amount.currency != dispatch.settlement_amount.currency
        || bond.minimum_required_amount.currency != dispatch.settlement_amount.currency
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond currency mismatch".to_string(),
        ));
    }
    if bond.minimum_required_amount.units < dispatch.settlement_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond minimum below settlement amount".to_string(),
        ));
    }
    if bond.posted_amount.units < bond.minimum_required_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond below policy".to_string(),
        ));
    }
    Ok(())
}

fn validate_block_snapshot(
    bundle: &PublicSettlementProofBundle,
    block: &PublicSettlementBlockSnapshot,
    chain_anchor: &crate::anchors::Web3ChainAnchorRecord,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &block.block_hash,
        "public_settlement.chain_snapshot.block.block_hash",
    )?;
    if block.transaction_hashes.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement block snapshot transaction list is empty".to_string(),
        ));
    }
    Hash::from_hex(&block.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    for transaction_hash in &block.transaction_hashes {
        ensure_non_empty(
            transaction_hash,
            "public_settlement.chain_snapshot.block.transaction_hashes",
        )?;
        Hash::from_hex(transaction_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    }
    if block.block_number != chain_anchor.block_number {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement block number mismatch".to_string(),
        ));
    }
    if block.block_hash != chain_anchor.block_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement block hash mismatch".to_string(),
        ));
    }
    if !block
        .transaction_hashes
        .iter()
        .any(|tx_hash| tx_hash == &chain_anchor.tx_hash)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement anchor tx hash missing from block".to_string(),
        ));
    }
    let settlement_tx_hash = &bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id;
    if !block
        .transaction_hashes
        .iter()
        .any(|tx_hash| tx_hash == settlement_tx_hash)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement tx hash not included in block".to_string(),
        ));
    }
    Ok(())
}

fn validate_order_binding(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    let mut has_order_ref = false;
    for evidence_ref in &bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .evidence_refs
    {
        if evidence_ref.kind != CapitalBookEvidenceKind::CommerceOrder {
            continue;
        }
        has_order_ref = true;
        if evidence_ref.reference_id != bundle.commerce_order_id {
            return Err(Web3ContractError::InvalidSettlement(
                "public settlement commerce order evidence mismatch".to_string(),
            ));
        }
    }

    if !has_order_ref {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement commerce order evidence missing".to_string(),
        ));
    }
    Ok(())
}

fn validate_finality(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.observed_confirmations < bundle.required_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "settlement finality below threshold".to_string(),
        ));
    }
    let snapshot_confirmations = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(bundle.chain_snapshot.observed_block_number)
        .saturating_add(1);
    if u64::from(bundle.observed_confirmations) > snapshot_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "public settlement observed confirmations exceed chain snapshot".to_string(),
        ));
    }
    Ok(())
}

fn validate_dispute_posture(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    let dispute = required_dispute_snapshot(bundle)?;
    validate_dispute_snapshot(bundle, dispute)?;
    if dispute.open_dispute_count > 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute blocks finality".to_string(),
        ));
    }
    match bundle.dispute_posture {
        PublicSettlementDisputePosture::Refunded
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::Reversed | Web3SettlementLifecycleState::TimedOut
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "refunded dispute posture requires reversed or timed out settlement".to_string(),
            ))
        }
        PublicSettlementDisputePosture::Slashed
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::ChargedBack | Web3SettlementLifecycleState::Reversed
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "slashed dispute posture requires charged back or reversed settlement".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn active_dispute_posture(posture: PublicSettlementDisputePosture) -> bool {
    matches!(
        posture,
        PublicSettlementDisputePosture::Challenged
            | PublicSettlementDisputePosture::Bonded
            | PublicSettlementDisputePosture::Appealed
    )
}

fn finality_report_status(bundle: &PublicSettlementProofBundle) -> &'static str {
    match bundle.settlement_receipt.lifecycle_state {
        Web3SettlementLifecycleState::Settled => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Closed => "closed",
            _ => "final",
        },
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Reversed => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "reversed",
        },
        Web3SettlementLifecycleState::ChargedBack => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "charged_back",
        },
        Web3SettlementLifecycleState::TimedOut => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            _ => "timed_out",
        },
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
        Web3SettlementLifecycleState::PendingDispatch
        | Web3SettlementLifecycleState::EscrowLocked => "not_final",
    }
}

fn validate_dispute_snapshot(
    bundle: &PublicSettlementProofBundle,
    dispute: &PublicSettlementDisputeSnapshot,
) -> Result<(), Web3ContractError> {
    if dispute.schema != CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(dispute.schema.clone()));
    }
    ensure_non_empty(&dispute.dispute_id, "public_settlement.dispute.dispute_id")?;
    if dispute.posture != bundle.dispute_posture {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement dispute posture mismatch".to_string(),
        ));
    }
    if dispute.challenge_window_secs == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute challenge window missing".to_string(),
        ));
    }
    let Some(expected_window_close) = bundle
        .settlement_receipt
        .observed_execution
        .observed_at
        .checked_add(dispute.challenge_window_secs)
    else {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window overflow".to_string(),
        ));
    };
    if dispute.window_closed_at < expected_window_close {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window closes before challenge period".to_string(),
        ));
    }
    if dispute.observed_at < dispute.window_closed_at {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute snapshot before challenge window close".to_string(),
        ));
    }
    for receipt_id in &dispute.linked_receipt_ids {
        ensure_non_empty(receipt_id, "public_settlement.dispute.linked_receipt_ids")?;
    }
    let block = required_block_snapshot(bundle)?;
    for tx_hash in &dispute.chain_event_tx_hashes {
        ensure_non_empty(tx_hash, "public_settlement.dispute.chain_event_tx_hashes")?;
        Hash::from_hex(tx_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
        if !block
            .transaction_hashes
            .iter()
            .any(|block_tx_hash| block_tx_hash == tx_hash)
        {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event tx hash not included in block".to_string(),
            ));
        }
    }
    if dispute.posture == PublicSettlementDisputePosture::Undisputed
        && dispute.open_dispute_count != 0
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement open dispute count mismatch".to_string(),
        ));
    }
    if active_dispute_posture(dispute.posture) && dispute.open_dispute_count == 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute missing".to_string(),
        ));
    }
    Ok(())
}

fn settlement_state_id(state: Web3SettlementLifecycleState) -> &'static str {
    match state {
        Web3SettlementLifecycleState::PendingDispatch => "pending_dispatch",
        Web3SettlementLifecycleState::EscrowLocked => "escrow_locked",
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Settled => "settled",
        Web3SettlementLifecycleState::Reversed => "reversed",
        Web3SettlementLifecycleState::ChargedBack => "charged_back",
        Web3SettlementLifecycleState::TimedOut => "timed_out",
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
    }
}

fn push_claim_once(target: &mut Vec<String>, claim: &str) {
    if !target.iter().any(|existing| existing == claim) {
        target.push(claim.to_string());
    }
}
