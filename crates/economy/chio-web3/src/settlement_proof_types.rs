use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::identity::SignedWeb3IdentityBinding;
use crate::settlement::Web3SettlementExecutionReceiptArtifact;
use crate::trust_profile::Web3SettlementPath;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementProofBundle {
    pub schema: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub order_binding: PublicSettlementOrderBinding,
    pub chain_id: String,
    pub settlement_receipt: Web3SettlementExecutionReceiptArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_provenance: Option<PublicSettlementDeploymentProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_witness: Option<PublicSettlementWitnessReport>,
    pub chain_snapshot: PublicSettlementChainSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_snapshot: Option<PublicSettlementDisputeSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_position_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarantee_decision_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_remedy_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_authority_ref: Option<String>,
    pub required_confirmations: u32,
    pub observed_confirmations: u32,
    pub dispute_posture: PublicSettlementDisputePosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_signature: Option<PublicSettlementBundleSignature>,
}

impl PublicSettlementProofBundle {
    pub fn has_trust_market_refs(&self) -> bool {
        self.collateral_position_ref.is_some()
            || self.guarantee_decision_ref.is_some()
            || self.sla_remedy_ref.is_some()
            || self.slash_authority_ref.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBundleSignature {
    pub algorithm: String,
    pub signer_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementOrderBinding {
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub chain_id: String,
    pub settlement_rail_id: String,
    pub custody_provider_id: String,
    pub settlement_reference: String,
    pub settlement_tx_hash: String,
    pub beneficiary_address: String,
    pub escrow_id: String,
    pub settlement_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDeploymentProvenance {
    pub provenance_id: String,
    pub chain_id: String,
    pub contract_package_id: String,
    pub reviewed_manifest_hash: String,
    pub approval_hash: String,
    pub create2_factory: String,
    pub salt_namespace: String,
    pub settlement_token_address: String,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementWitnessReport {
    pub witness_id: String,
    pub mode: PublicSettlementWitnessMode,
    pub body_hash: String,
    pub chain_id: String,
    pub registry_root: String,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry_operator: Option<PublicSettlementIdentityRegistryOperatorSnapshot>,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub settlement_token_address: String,
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
    pub anchor_tx_hash: String,
    pub anchored_merkle_root: String,
    pub anchored_checkpoint_seq: u64,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementWitnessMode {
    Live,
    VerifiedCache,
    Advisory,
}

#[derive(Debug, Clone, Default)]
pub struct PublicSettlementVerifierTrust {
    pub trusted_bundle_signer_keys: Vec<PublicKey>,
    pub trusted_capital_signer_keys: Vec<PublicKey>,
    pub trusted_anchor_kernel_keys: Vec<PublicKey>,
    pub trusted_beneficiary_identity_keys: Vec<PublicKey>,
    pub trusted_oracle_keys: Vec<PublicKey>,
    pub allowed_chain_ids: Vec<String>,
    pub mainnet_blocked: bool,
    pub minimum_confirmations: Option<u32>,
    pub expected_trust_market_context: Option<PublicSettlementTrustMarketContext>,
    pub independent_chain_head: Option<PublicSettlementIndependentChainHead>,
    pub trusted_dispute_event_blocks: Vec<PublicSettlementBlockSnapshot>,
    pub trusted_release_event_blocks: Vec<PublicSettlementBlockSnapshot>,
    pub trusted_release_event_logs: Vec<PublicSettlementReleaseEventLog>,
    pub trusted_refund_event_logs: Vec<PublicSettlementRefundEventLog>,
    pub verifier_now_unix_seconds: Option<u64>,
    pub trusted_runtime_codehashes: Option<PublicSettlementRuntimeCodehashTrust>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRuntimeCodehashTrust {
    pub contract_package_id: String,
    pub reviewed_manifest_hash: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_runtime_codehash: String,
    pub escrow_runtime_codehash: String,
    pub bond_vault_runtime_codehash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementIndependentChainHead {
    pub chain_id: String,
    pub observed_block_number: u64,
    pub observed_block_hash: String,
    pub latest_block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementChainSnapshot {
    pub chain_id: String,
    pub observed_block_number: u64,
    pub latest_block_number: u64,
    pub max_block_lag: u64,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry_operator: Option<PublicSettlementIdentityRegistryOperatorSnapshot>,
    pub registry_root: String,
    pub escrow: PublicSettlementEscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<PublicSettlementBondSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<PublicSettlementBlockSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary_identity_binding: Option<SignedWeb3IdentityBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementIdentityRegistryOperatorSnapshot {
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub operator_key_hash: String,
    pub settlement_key: String,
    pub operator_epoch: u64,
    pub active: bool,
    pub block_number: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementEscrowSnapshot {
    pub escrow_id: String,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub settlement_token_address: String,
    pub beneficiary_address: String,
    pub locked_amount: crate::capability::scope::MonetaryAmount,
    pub released_amount: crate::capability::scope::MonetaryAmount,
    pub refunded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_event: Option<PublicSettlementReleaseEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_event: Option<PublicSettlementRefundEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementReleaseEvent {
    pub escrow_id: String,
    pub release_tx_hash: String,
    pub receipt_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_amount: Option<crate::capability::scope::MonetaryAmount>,
    pub partial: bool,
    pub block: PublicSettlementBlockSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementReleaseEventKind {
    EscrowReleased,
    EscrowPartialRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementReleaseEventLog {
    pub contract_address: String,
    pub event: PublicSettlementReleaseEventKind,
    pub escrow_id: String,
    pub release_tx_hash: String,
    pub receipt_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_amount: Option<crate::capability::scope::MonetaryAmount>,
    pub block_number: u64,
    pub block_hash: String,
    pub log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRefundEvent {
    pub escrow_id: String,
    pub refund_tx_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    pub block: PublicSettlementBlockSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRefundEventLog {
    pub contract_address: String,
    pub escrow_id: String,
    pub refund_tx_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    pub block_number: u64,
    pub block_hash: String,
    pub log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBondSnapshot {
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_event_blocks: Vec<PublicSettlementBlockSnapshot>,
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
    pub public_witness: PublicSettlementWitnessContext,
    pub finality_decision: PublicSettlementFinalityDecision,
    pub dispute_context: PublicSettlementDisputeContext,
    pub dispute_posture: PublicSettlementDisputePosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_market_context: Option<PublicSettlementTrustMarketContext>,
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
pub struct PublicSettlementWitnessContext {
    pub witness_id: String,
    pub mode: PublicSettlementWitnessMode,
    pub body_hash: String,
    pub observed_at: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementTrustMarketContext {
    pub collateral_position_ref: String,
    pub guarantee_decision_ref: String,
    pub sla_remedy_ref: String,
    pub slash_authority_ref: String,
}
