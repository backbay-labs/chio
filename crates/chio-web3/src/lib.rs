//! Chio web3 settlement, anchoring, and official-chain contract types.
//!
//! These types freeze the first official web3 execution surface on top of the
//! Chio extension substrate. They define the trust profile, contract package,
//! chain configuration, anchoring proof bundle, oracle evidence envelope, and
//! web3 settlement lifecycle artifacts that later live-money work must honor.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical, capability, crypto, hashing, merkle, receipt};
pub use chio_credit as credit;

use std::collections::HashSet;

pub use chio_core_types::oracle::OracleConversionEvidence;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::MonetaryAmount;
use crate::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CapitalExecutionReconciledState,
    CreditBondLifecycleState, SignedCapitalExecutionInstruction, SignedCreditBond,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::crypto::{PublicKey, Signature};
use crate::hashing::Hash;
use crate::merkle::{leaf_hash, MerkleProof};
use crate::receipt::{ChioReceipt, SignedExportEnvelope};

pub const CHIO_KEY_BINDING_CERTIFICATE_SCHEMA: &str = "chio.key-binding-certificate.v1";
pub const CHIO_WEB3_TRUST_PROFILE_SCHEMA: &str = "chio.web3-trust-profile.v1";
pub const CHIO_WEB3_CONTRACT_PACKAGE_SCHEMA: &str = "chio.web3-contract-package.v1";
pub const CHIO_WEB3_CHAIN_CONFIGURATION_SCHEMA: &str = "chio.web3-chain-configuration.v1";
pub const CHIO_CHECKPOINT_STATEMENT_SCHEMA: &str = "chio.checkpoint_statement.v1";
pub const CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA: &str = "chio.anchor-inclusion-proof.v1";
pub const CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA: &str = "chio.oracle-conversion-evidence.v1";
pub const CHIO_LINK_ORACLE_AUTHORITY: &str = "chio_link_runtime_v1";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA: &str = "chio.web3-settlement-dispatch.v1";
pub const CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v1";
pub const CHIO_WEB3_QUALIFICATION_MATRIX_SCHEMA: &str = "chio.web3-qualification-matrix.v1";
pub const CHIO_LINK_CONTROL_STATE_SCHEMA: &str = "chio.link.control-state.v1";
pub const CHIO_LINK_CONTROL_TRACE_SCHEMA: &str = "chio.link.control-trace.v1";
pub const CHIO_ANCHOR_CONTROL_STATE_SCHEMA: &str = "chio.anchor.control-state.v1";
pub const CHIO_ANCHOR_CONTROL_TRACE_SCHEMA: &str = "chio.anchor.control-trace.v1";
pub const CHIO_SETTLE_CONTROL_STATE_SCHEMA: &str = "chio.settle.control-state.v1";
pub const CHIO_SETTLE_CONTROL_TRACE_SCHEMA: &str = "chio.settle.control-trace.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3KeyBindingPurpose {
    Anchor,
    Settle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3SettlementPath {
    DualSignature,
    MerkleProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3DisputePolicy {
    OffChainArbitration,
    TimeoutRefund,
    BondSlash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3FinalityMode {
    OptimisticL2,
    L1Finalized,
    SolanaConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3RegulatedRole {
    Operator,
    Custodian,
    PaymentInstitution,
    OracleOperator,
    Arbitrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3ContractKind {
    RootRegistry,
    Escrow,
    BondVault,
    IdentityRegistry,
    PriceResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3BindingLanguage {
    Rust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3ChainRole {
    Primary,
    Secondary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3SettlementLifecycleState {
    PendingDispatch,
    EscrowLocked,
    PartiallySettled,
    Settled,
    Reversed,
    ChargedBack,
    TimedOut,
    Failed,
    Reorged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3QualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3IdentityBindingCertificate {
    pub schema: String,
    pub chio_identity: String,
    pub chio_public_key: PublicKey,
    pub chain_scope: Vec<String>,
    pub purpose: Vec<Web3KeyBindingPurpose>,
    pub settlement_address: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWeb3IdentityBinding {
    pub certificate: Web3IdentityBindingCertificate,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3DisputeWindow {
    pub settlement_path: Web3SettlementPath,
    pub challenge_window_secs: u64,
    pub recovery_window_secs: u64,
    pub dispute_policy: Web3DisputePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainFinalityRule {
    pub chain_id: String,
    pub mode: Web3FinalityMode,
    pub min_confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3RegulatedRoleAssumption {
    pub role: Web3RegulatedRole,
    pub actor_id: String,
    pub responsibility: String,
    pub custody_boundary_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3TrustProfile {
    pub schema: String,
    pub profile_id: String,
    pub chio_contract_version: String,
    pub primary_chain_id: String,
    pub secondary_chain_ids: Vec<String>,
    pub operator_binding: SignedWeb3IdentityBinding,
    pub proof_bundle_required: bool,
    pub dispute_windows: Vec<Web3DisputeWindow>,
    pub finality_rules: Vec<Web3ChainFinalityRule>,
    pub regulated_roles: Vec<Web3RegulatedRoleAssumption>,
    pub custody_boundary_note: String,
    pub local_policy_activation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ContractInterface {
    pub contract_id: String,
    pub kind: Web3ContractKind,
    pub interface_name: String,
    pub abi_reference: String,
    pub implementation_reference: String,
    pub immutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3BindingTarget {
    pub language: Web3BindingLanguage,
    pub crate_path: String,
    pub module_name: String,
    pub contract_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ContractPackage {
    pub schema: String,
    pub package_id: String,
    pub version: String,
    pub chio_contract_version: String,
    pub contracts: Vec<Web3ContractInterface>,
    pub bindings: Vec<Web3BindingTarget>,
    pub deferred_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainDeployment {
    pub chain_id: String,
    pub network_name: String,
    pub role: Web3ChainRole,
    pub settlement_token_symbol: String,
    pub settlement_token_address: String,
    pub root_registry_address: String,
    pub escrow_address: String,
    pub bond_vault_address: String,
    pub identity_registry_address: String,
    pub price_resolver_address: String,
    pub operator_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainGasProfile {
    pub chain_id: String,
    pub publish_root_gas: u64,
    pub dual_sign_settlement_gas: u64,
    pub merkle_settlement_gas: u64,
    pub bond_release_gas: u64,
    pub price_read_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainConfiguration {
    pub schema: String,
    pub package_id: String,
    pub primary_chain_id: String,
    pub deployments: Vec<Web3ChainDeployment>,
    pub gas_profiles: Vec<Web3ChainGasProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ReceiptInclusion {
    pub checkpoint_seq: u64,
    pub merkle_root: Hash,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3CheckpointStatement {
    pub schema: String,
    pub checkpoint_seq: u64,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub tree_size: u64,
    pub merkle_root: Hash,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainAnchorRecord {
    pub chain_id: String,
    pub contract_address: String,
    pub operator_address: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub anchored_merkle_root: Hash,
    pub anchored_checkpoint_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3BitcoinAnchor {
    pub method: String,
    pub ots_proof_b64: String,
    pub bitcoin_block_height: u64,
    pub bitcoin_block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SuperRootInclusion {
    pub super_root: Hash,
    pub proof: MerkleProof,
    pub aggregated_checkpoint_start: u64,
    pub aggregated_checkpoint_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorInclusionProof {
    pub schema: String,
    pub receipt: ChioReceipt,
    pub receipt_inclusion: Web3ReceiptInclusion,
    pub checkpoint_statement: Web3CheckpointStatement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_anchor: Option<Web3ChainAnchorRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitcoin_anchor: Option<Web3BitcoinAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_root_inclusion: Option<Web3SuperRootInclusion>,
    pub key_binding_certificate: SignedWeb3IdentityBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SettlementSupportBoundary {
    pub real_dispatch_supported: bool,
    pub anchor_proof_required: bool,
    pub oracle_evidence_required_for_fx: bool,
    pub custody_boundary_explicit: bool,
    pub reversal_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SettlementDispatchArtifact {
    pub schema: String,
    pub dispatch_id: String,
    pub issued_at: u64,
    pub trust_profile_id: String,
    pub contract_package_id: String,
    pub chain_id: String,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<SignedCreditBond>,
    pub settlement_path: Web3SettlementPath,
    pub settlement_amount: MonetaryAmount,
    pub escrow_id: String,
    pub escrow_contract: String,
    pub bond_vault_contract: String,
    pub beneficiary_address: String,
    pub support_boundary: Web3SettlementSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedWeb3SettlementDispatch = SignedExportEnvelope<Web3SettlementDispatchArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SettlementExecutionReceiptArtifact {
    pub schema: String,
    pub execution_receipt_id: String,
    pub issued_at: u64,
    pub dispatch: Web3SettlementDispatchArtifact,
    pub observed_execution: crate::credit::CapitalExecutionObservation,
    pub lifecycle_state: Web3SettlementLifecycleState,
    pub settlement_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciled_anchor_proof: Option<AnchorInclusionProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_evidence: Option<OracleConversionEvidence>,
    pub settled_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversal_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedWeb3SettlementExecutionReceipt =
    SignedExportEnvelope<Web3SettlementExecutionReceiptArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3QualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    pub lifecycle_state: Web3SettlementLifecycleState,
    pub expected_outcome: Web3QualificationOutcome,
    pub observed_outcome: Web3QualificationOutcome,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3QualificationMatrix {
    pub schema: String,
    pub trust_profile_id: String,
    pub contract_package_id: String,
    pub cases: Vec<Web3QualificationCase>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Web3ContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate id or value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid binding: {0}")]
    InvalidBinding(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid settlement: {0}")]
    InvalidSettlement(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}

impl Web3ContractError {
    fn invalid_settlement(message: impl Into<String>) -> Self {
        Self::InvalidSettlement(message.into())
    }
}

pub fn validate_web3_identity_binding(
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    if binding.certificate.schema != CHIO_KEY_BINDING_CERTIFICATE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            binding.certificate.schema.clone(),
        ));
    }
    ensure_non_empty(&binding.certificate.chio_identity, "binding.chio_identity")?;
    ensure_non_empty(
        &binding.certificate.settlement_address,
        "binding.settlement_address",
    )?;
    ensure_non_empty(&binding.certificate.nonce, "binding.nonce")?;
    if binding.certificate.chain_scope.is_empty() {
        return Err(Web3ContractError::MissingField("binding.chain_scope"));
    }
    if binding.certificate.purpose.is_empty() {
        return Err(Web3ContractError::MissingField("binding.purpose"));
    }
    ensure_unique_strings(&binding.certificate.chain_scope, "binding.chain_scope")?;
    ensure_unique_copy_values(&binding.certificate.purpose, "binding.purpose")?;
    if binding.certificate.issued_at >= binding.certificate.expires_at {
        return Err(Web3ContractError::InvalidBinding(
            "identity binding issued_at must be earlier than expires_at".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_web3_identity_binding(
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    validate_web3_identity_binding(binding)?;
    let verified = binding
        .certificate
        .chio_public_key
        .verify_canonical(&binding.certificate, &binding.signature)
        .map_err(|error| Web3ContractError::InvalidBinding(error.to_string()))?;
    if !verified {
        return Err(Web3ContractError::InvalidBinding(
            "identity binding signature verification failed".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_web3_trust_profile(profile: &Web3TrustProfile) -> Result<(), Web3ContractError> {
    if profile.schema != CHIO_WEB3_TRUST_PROFILE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(profile.schema.clone()));
    }
    ensure_non_empty(&profile.profile_id, "web3_trust_profile.profile_id")?;
    ensure_non_empty(
        &profile.chio_contract_version,
        "web3_trust_profile.chio_contract_version",
    )?;
    ensure_non_empty(
        &profile.primary_chain_id,
        "web3_trust_profile.primary_chain_id",
    )?;
    ensure_non_empty(
        &profile.custody_boundary_note,
        "web3_trust_profile.custody_boundary_note",
    )?;
    validate_web3_identity_binding(&profile.operator_binding)?;
    ensure_unique_strings(
        &profile.secondary_chain_ids,
        "web3_trust_profile.secondary_chain_ids",
    )?;
    if profile
        .secondary_chain_ids
        .iter()
        .any(|chain_id| chain_id == &profile.primary_chain_id)
    {
        return Err(Web3ContractError::DuplicateValue(
            profile.primary_chain_id.clone(),
        ));
    }

    let mut known_chains = HashSet::new();
    known_chains.insert(profile.primary_chain_id.as_str());
    for chain_id in &profile.secondary_chain_ids {
        known_chains.insert(chain_id.as_str());
    }
    for chain_id in &profile.operator_binding.certificate.chain_scope {
        known_chains.insert(chain_id.as_str());
    }
    if !profile
        .operator_binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain_id| chain_id == &profile.primary_chain_id)
    {
        return Err(Web3ContractError::InvalidBinding(format!(
            "binding does not cover primary chain {}",
            profile.primary_chain_id
        )));
    }
    for chain_id in &profile.secondary_chain_ids {
        if !profile
            .operator_binding
            .certificate
            .chain_scope
            .iter()
            .any(|candidate| candidate == chain_id)
        {
            return Err(Web3ContractError::InvalidBinding(format!(
                "binding does not cover secondary chain {}",
                chain_id
            )));
        }
    }

    if !profile.local_policy_activation_required {
        return Err(Web3ContractError::InvalidBinding(
            "web3 trust profile must require explicit local policy activation".to_string(),
        ));
    }

    if profile.dispute_windows.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.dispute_windows",
        ));
    }
    let mut seen_paths = HashSet::new();
    for window in &profile.dispute_windows {
        if !seen_paths.insert(window.settlement_path) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "web3_trust_profile.dispute_windows:{:?}",
                window.settlement_path
            )));
        }
        if window.challenge_window_secs == 0 || window.recovery_window_secs == 0 {
            return Err(Web3ContractError::InvalidBinding(format!(
                "dispute window {:?} must have non-zero durations",
                window.settlement_path
            )));
        }
    }
    if profile.finality_rules.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.finality_rules",
        ));
    }
    let mut seen_finality = HashSet::new();
    for rule in &profile.finality_rules {
        ensure_non_empty(&rule.chain_id, "web3_trust_profile.finality_rules.chain_id")?;
        if rule.min_confirmations == 0 {
            return Err(Web3ContractError::InvalidBinding(format!(
                "finality rule {} must require at least one confirmation",
                rule.chain_id
            )));
        }
        if !seen_finality.insert(rule.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(rule.chain_id.clone()));
        }
    }
    for chain_id in [&profile.primary_chain_id]
        .into_iter()
        .chain(profile.secondary_chain_ids.iter())
    {
        if !seen_finality.contains(chain_id.as_str()) {
            return Err(Web3ContractError::UnknownReference(chain_id.clone()));
        }
    }

    if profile.regulated_roles.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.regulated_roles",
        ));
    }
    let mut saw_custodian = false;
    for role in &profile.regulated_roles {
        ensure_non_empty(
            &role.actor_id,
            "web3_trust_profile.regulated_roles.actor_id",
        )?;
        ensure_non_empty(
            &role.responsibility,
            "web3_trust_profile.regulated_roles.responsibility",
        )?;
        if !role.custody_boundary_explicit {
            return Err(Web3ContractError::InvalidBinding(format!(
                "regulated role {:?} must keep custody boundary explicit",
                role.role
            )));
        }
        if role.role == Web3RegulatedRole::Custodian {
            saw_custodian = true;
        }
    }
    if !saw_custodian {
        return Err(Web3ContractError::InvalidBinding(
            "web3 trust profile must record at least one custodian role".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_web3_contract_package(
    package: &Web3ContractPackage,
) -> Result<(), Web3ContractError> {
    if package.schema != CHIO_WEB3_CONTRACT_PACKAGE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(package.schema.clone()));
    }
    ensure_non_empty(&package.package_id, "web3_contract_package.package_id")?;
    ensure_non_empty(&package.version, "web3_contract_package.version")?;
    ensure_non_empty(
        &package.chio_contract_version,
        "web3_contract_package.chio_contract_version",
    )?;
    if package.contracts.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_contract_package.contracts",
        ));
    }
    if package.bindings.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_contract_package.bindings",
        ));
    }

    let mut contract_ids = HashSet::new();
    let mut contract_kinds = HashSet::new();
    for contract in &package.contracts {
        ensure_non_empty(
            &contract.contract_id,
            "web3_contract_package.contracts.contract_id",
        )?;
        ensure_non_empty(
            &contract.interface_name,
            "web3_contract_package.contracts.interface_name",
        )?;
        ensure_non_empty(
            &contract.abi_reference,
            "web3_contract_package.contracts.abi_reference",
        )?;
        ensure_non_empty(
            &contract.implementation_reference,
            "web3_contract_package.contracts.implementation_reference",
        )?;
        if !contract_ids.insert(contract.contract_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(
                contract.contract_id.clone(),
            ));
        }
        if !contract_kinds.insert(contract.kind) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "web3_contract_package.contract_kind:{:?}",
                contract.kind
            )));
        }
    }
    for required in [
        Web3ContractKind::RootRegistry,
        Web3ContractKind::Escrow,
        Web3ContractKind::BondVault,
        Web3ContractKind::IdentityRegistry,
        Web3ContractKind::PriceResolver,
    ] {
        if !contract_kinds.contains(&required) {
            return Err(Web3ContractError::UnknownReference(format!(
                "missing required contract kind {:?}",
                required
            )));
        }
    }

    for binding in &package.bindings {
        ensure_non_empty(
            &binding.crate_path,
            "web3_contract_package.bindings.crate_path",
        )?;
        ensure_non_empty(
            &binding.module_name,
            "web3_contract_package.bindings.module_name",
        )?;
        if binding.contract_ids.is_empty() {
            return Err(Web3ContractError::MissingField(
                "web3_contract_package.bindings.contract_ids",
            ));
        }
        ensure_unique_strings(
            &binding.contract_ids,
            "web3_contract_package.bindings.contract_ids",
        )?;
        for contract_id in &binding.contract_ids {
            if !contract_ids.contains(contract_id.as_str()) {
                return Err(Web3ContractError::UnknownReference(contract_id.clone()));
            }
        }
    }

    ensure_unique_strings(
        &package.deferred_capabilities,
        "web3_contract_package.deferred_capabilities",
    )?;

    Ok(())
}

pub fn validate_web3_chain_configuration(
    configuration: &Web3ChainConfiguration,
) -> Result<(), Web3ContractError> {
    if configuration.schema != CHIO_WEB3_CHAIN_CONFIGURATION_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            configuration.schema.clone(),
        ));
    }
    ensure_non_empty(
        &configuration.package_id,
        "web3_chain_configuration.package_id",
    )?;
    ensure_non_empty(
        &configuration.primary_chain_id,
        "web3_chain_configuration.primary_chain_id",
    )?;
    if configuration.deployments.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.deployments",
        ));
    }
    if configuration.gas_profiles.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_chain_configuration.gas_profiles",
        ));
    }

    let mut deployment_ids = HashSet::new();
    let mut primary_count = 0usize;
    for deployment in &configuration.deployments {
        ensure_non_empty(
            &deployment.chain_id,
            "web3_chain_configuration.deployments.chain_id",
        )?;
        ensure_non_empty(
            &deployment.network_name,
            "web3_chain_configuration.deployments.network_name",
        )?;
        ensure_non_empty(
            &deployment.settlement_token_symbol,
            "web3_chain_configuration.deployments.settlement_token_symbol",
        )?;
        for field in [
            &deployment.settlement_token_address,
            &deployment.root_registry_address,
            &deployment.escrow_address,
            &deployment.bond_vault_address,
            &deployment.identity_registry_address,
            &deployment.price_resolver_address,
            &deployment.operator_address,
        ] {
            ensure_non_empty(field, "web3_chain_configuration.deployments.addresses")?;
        }
        if !deployment_ids.insert(deployment.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(
                deployment.chain_id.clone(),
            ));
        }
        if deployment.role == Web3ChainRole::Primary {
            primary_count += 1;
            if deployment.chain_id != configuration.primary_chain_id {
                return Err(Web3ContractError::InvalidBinding(format!(
                    "primary deployment {} does not match primary_chain_id {}",
                    deployment.chain_id, configuration.primary_chain_id
                )));
            }
        }
    }
    if primary_count != 1 {
        return Err(Web3ContractError::InvalidBinding(
            "web3 chain configuration must declare exactly one primary deployment".to_string(),
        ));
    }

    let mut gas_profiles = HashSet::new();
    for gas in &configuration.gas_profiles {
        ensure_non_empty(
            &gas.chain_id,
            "web3_chain_configuration.gas_profiles.chain_id",
        )?;
        if !deployment_ids.contains(gas.chain_id.as_str()) {
            return Err(Web3ContractError::UnknownReference(gas.chain_id.clone()));
        }
        if !gas_profiles.insert(gas.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(gas.chain_id.clone()));
        }
        for metric in [
            gas.publish_root_gas,
            gas.dual_sign_settlement_gas,
            gas.merkle_settlement_gas,
            gas.bond_release_gas,
            gas.price_read_gas,
        ] {
            if metric == 0 {
                return Err(Web3ContractError::InvalidBinding(format!(
                    "gas profile {} must not contain zero-valued gas assumptions",
                    gas.chain_id
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_oracle_conversion_evidence(
    evidence: &OracleConversionEvidence,
) -> Result<(), Web3ContractError> {
    if evidence.schema != CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    for field in [
        &evidence.base,
        &evidence.quote,
        &evidence.authority,
        &evidence.source,
        &evidence.feed_address,
        &evidence.original_currency,
        &evidence.grant_currency,
    ] {
        ensure_non_empty(field, "oracle_conversion_evidence.field")?;
    }
    if evidence.authority != CHIO_LINK_ORACLE_AUTHORITY {
        return Err(Web3ContractError::InvalidProof(format!(
            "oracle conversion evidence authority {} is unsupported",
            evidence.authority
        )));
    }
    if evidence.rate_denominator == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence rate_denominator must be non-zero".to_string(),
        ));
    }
    if evidence.max_age_seconds == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence max_age_seconds must be non-zero".to_string(),
        ));
    }
    if evidence.original_cost_units == 0 || evidence.converted_cost_units == 0 {
        return Err(Web3ContractError::InvalidProof(
            "oracle conversion evidence cost units must be non-zero".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_anchor_inclusion_proof(
    proof: &AnchorInclusionProof,
) -> Result<(), Web3ContractError> {
    if proof.schema != CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(proof.schema.clone()));
    }
    validate_web3_identity_binding(&proof.key_binding_certificate)?;
    if proof.receipt.id.trim().is_empty() {
        return Err(Web3ContractError::MissingField(
            "anchor_inclusion.receipt.id",
        ));
    }
    if proof.receipt_inclusion.proof.tree_size == 0 {
        return Err(Web3ContractError::InvalidProof(
            "anchor inclusion proof tree_size must be non-zero".to_string(),
        ));
    }
    if proof.receipt_inclusion.proof.leaf_index >= proof.receipt_inclusion.proof.tree_size {
        return Err(Web3ContractError::InvalidProof(
            "anchor inclusion proof leaf_index exceeds tree_size".to_string(),
        ));
    }
    if proof.receipt_inclusion.checkpoint_seq != proof.checkpoint_statement.checkpoint_seq {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion checkpoint_seq must match checkpoint statement".to_string(),
        ));
    }
    if proof.receipt_inclusion.merkle_root != proof.checkpoint_statement.merkle_root {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion merkle_root must match checkpoint statement".to_string(),
        ));
    }
    if proof.checkpoint_statement.schema != CHIO_CHECKPOINT_STATEMENT_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            proof.checkpoint_statement.schema.clone(),
        ));
    }
    if proof.checkpoint_statement.batch_start_seq > proof.checkpoint_statement.batch_end_seq {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement batch_start_seq must be <= batch_end_seq".to_string(),
        ));
    }
    if proof.checkpoint_statement.tree_size == 0 {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement tree_size must be non-zero".to_string(),
        ));
    }
    if proof.checkpoint_statement.tree_size as usize != proof.receipt_inclusion.proof.tree_size {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement tree_size must match receipt inclusion proof".to_string(),
        ));
    }
    if let Some(chain_anchor) = proof.chain_anchor.as_ref() {
        ensure_non_empty(
            &chain_anchor.chain_id,
            "anchor_inclusion.chain_anchor.chain_id",
        )?;
        ensure_non_empty(
            &chain_anchor.contract_address,
            "anchor_inclusion.chain_anchor.contract_address",
        )?;
        ensure_non_empty(
            &chain_anchor.operator_address,
            "anchor_inclusion.chain_anchor.operator_address",
        )?;
        ensure_non_empty(
            &chain_anchor.tx_hash,
            "anchor_inclusion.chain_anchor.tx_hash",
        )?;
        ensure_non_empty(
            &chain_anchor.block_hash,
            "anchor_inclusion.chain_anchor.block_hash",
        )?;
        if chain_anchor.anchored_checkpoint_seq != proof.checkpoint_statement.checkpoint_seq {
            return Err(Web3ContractError::InvalidProof(
                "chain anchor checkpoint seq must match checkpoint statement".to_string(),
            ));
        }
        if chain_anchor.anchored_merkle_root != proof.checkpoint_statement.merkle_root {
            return Err(Web3ContractError::InvalidProof(
                "chain anchor root must match checkpoint statement".to_string(),
            ));
        }
        if chain_anchor.operator_address
            != proof.key_binding_certificate.certificate.settlement_address
        {
            return Err(Web3ContractError::InvalidBinding(
                "chain anchor operator address must match settlement binding".to_string(),
            ));
        }
        if !proof
            .key_binding_certificate
            .certificate
            .purpose
            .contains(&Web3KeyBindingPurpose::Anchor)
        {
            return Err(Web3ContractError::InvalidBinding(
                "anchor proof requires a binding certificate scoped to anchor".to_string(),
            ));
        }
        if !proof
            .key_binding_certificate
            .certificate
            .chain_scope
            .iter()
            .any(|chain_id| chain_id == &chain_anchor.chain_id)
        {
            return Err(Web3ContractError::InvalidBinding(format!(
                "binding certificate does not cover anchor chain {}",
                chain_anchor.chain_id
            )));
        }
    }
    if let Some(bitcoin_anchor) = proof.bitcoin_anchor.as_ref() {
        ensure_non_empty(
            &bitcoin_anchor.method,
            "anchor_inclusion.bitcoin_anchor.method",
        )?;
        ensure_non_empty(
            &bitcoin_anchor.ots_proof_b64,
            "anchor_inclusion.bitcoin_anchor.ots_proof_b64",
        )?;
        ensure_non_empty(
            &bitcoin_anchor.bitcoin_block_hash,
            "anchor_inclusion.bitcoin_anchor.bitcoin_block_hash",
        )?;
        if proof.super_root_inclusion.is_none() {
            return Err(Web3ContractError::InvalidProof(
                "Bitcoin anchor requires super-root inclusion metadata".to_string(),
            ));
        }
    }
    if let Some(super_root) = proof.super_root_inclusion.as_ref() {
        if super_root.aggregated_checkpoint_start > super_root.aggregated_checkpoint_end {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion checkpoint range must be ordered".to_string(),
            ));
        }
        if proof.checkpoint_statement.checkpoint_seq < super_root.aggregated_checkpoint_start
            || proof.checkpoint_statement.checkpoint_seq > super_root.aggregated_checkpoint_end
        {
            return Err(Web3ContractError::InvalidProof(
                "checkpoint statement must fall within the super-root aggregation range"
                    .to_string(),
            ));
        }
        if super_root.proof.tree_size == 0 {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion tree_size must be non-zero".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn verify_checkpoint_statement(
    statement: &Web3CheckpointStatement,
) -> Result<(), Web3ContractError> {
    let body = checkpoint_statement_body(statement);
    let verified = statement
        .kernel_key
        .verify_canonical(&body, &statement.signature)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if !verified {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement signature verification failed".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_anchor_inclusion_proof(
    proof: &AnchorInclusionProof,
) -> Result<(), Web3ContractError> {
    validate_anchor_inclusion_proof(proof)?;
    let receipt_verified = proof
        .receipt
        .verify_signature()
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if !receipt_verified {
        return Err(Web3ContractError::InvalidProof(
            "receipt signature verification failed".to_string(),
        ));
    }
    verify_web3_identity_binding(&proof.key_binding_certificate)?;
    verify_checkpoint_statement(&proof.checkpoint_statement)?;
    if proof.key_binding_certificate.certificate.chio_public_key != proof.receipt.kernel_key {
        return Err(Web3ContractError::InvalidBinding(
            "binding certificate public key must match receipt kernel_key".to_string(),
        ));
    }
    if proof.checkpoint_statement.kernel_key != proof.receipt.kernel_key {
        return Err(Web3ContractError::InvalidProof(
            "checkpoint statement kernel_key must match receipt kernel_key".to_string(),
        ));
    }

    let receipt_body = proof.receipt.body();
    let receipt_bytes = canonical_json_bytes(&receipt_body)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    let receipt_leaf = leaf_hash(&receipt_bytes);
    if !proof
        .receipt_inclusion
        .proof
        .verify_hash(receipt_leaf, &proof.receipt_inclusion.merkle_root)
    {
        return Err(Web3ContractError::InvalidProof(
            "receipt inclusion Merkle proof verification failed".to_string(),
        ));
    }
    if let Some(super_root) = proof.super_root_inclusion.as_ref() {
        if !super_root
            .proof
            .verify_hash(proof.receipt_inclusion.merkle_root, &super_root.super_root)
        {
            return Err(Web3ContractError::InvalidProof(
                "super-root inclusion verification failed".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_web3_settlement_dispatch(
    dispatch: &Web3SettlementDispatchArtifact,
) -> Result<(), Web3ContractError> {
    if dispatch.schema != CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            dispatch.schema.clone(),
        ));
    }
    for field in [
        &dispatch.dispatch_id,
        &dispatch.trust_profile_id,
        &dispatch.contract_package_id,
        &dispatch.chain_id,
        &dispatch.escrow_id,
        &dispatch.escrow_contract,
        &dispatch.bond_vault_contract,
        &dispatch.beneficiary_address,
    ] {
        ensure_non_empty(field, "web3_settlement_dispatch.field")?;
    }
    ensure_money(
        &dispatch.settlement_amount,
        "web3_settlement_dispatch.settlement_amount",
    )?;
    if !dispatch.support_boundary.real_dispatch_supported {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch must explicitly mark real dispatch as supported",
        ));
    }
    if !dispatch.support_boundary.custody_boundary_explicit {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch must keep custody boundaries explicit",
        ));
    }
    if dispatch.settlement_path == Web3SettlementPath::MerkleProof
        && !dispatch.support_boundary.anchor_proof_required
    {
        return Err(Web3ContractError::invalid_settlement(
            "Merkle-proof settlement dispatch must require anchor proof reconciliation",
        ));
    }
    if dispatch.capital_instruction.body.schema != CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            dispatch.capital_instruction.body.schema.clone(),
        ));
    }
    if dispatch.capital_instruction.body.action
        == CapitalExecutionInstructionAction::CancelInstruction
    {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch cannot use cancel_instruction as the primary action",
        ));
    }
    if dispatch.capital_instruction.body.rail.kind != CapitalExecutionRailKind::Web3 {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch requires capital_instruction rail.kind = web3",
        ));
    }
    let Some(amount) = dispatch.capital_instruction.body.amount.as_ref() else {
        return Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.amount",
        ));
    };
    if amount != &dispatch.settlement_amount {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch settlement_amount must match capital_instruction amount",
        ));
    }
    if dispatch.capital_instruction.body.reconciled_state
        != CapitalExecutionReconciledState::NotObserved
    {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch capital_instruction must remain unreconciled until execution receipt",
        ));
    }
    validate_transfer_completion_flow_binding(&dispatch.capital_instruction.body)?;
    if let Some(bond) = dispatch.bond.as_ref() {
        if bond.body.lifecycle_state != CreditBondLifecycleState::Active {
            return Err(Web3ContractError::invalid_settlement(
                "web3 settlement dispatch requires an active bond when bond backing is present",
            ));
        }
    }
    Ok(())
}

pub fn validate_web3_settlement_execution_receipt(
    receipt: &Web3SettlementExecutionReceiptArtifact,
) -> Result<(), Web3ContractError> {
    if receipt.schema != CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(receipt.schema.clone()));
    }
    ensure_non_empty(
        &receipt.execution_receipt_id,
        "web3_settlement_receipt.execution_receipt_id",
    )?;
    ensure_non_empty(
        &receipt.settlement_reference,
        "web3_settlement_receipt.settlement_reference",
    )?;
    validate_web3_settlement_dispatch(&receipt.dispatch)?;
    ensure_money(
        &receipt.observed_execution.amount,
        "web3_settlement_receipt.observed_amount",
    )?;
    ensure_money(
        &receipt.settled_amount,
        "web3_settlement_receipt.settled_amount",
    )?;
    if receipt.observed_execution.amount.currency != receipt.dispatch.settlement_amount.currency {
        return Err(Web3ContractError::invalid_settlement(
            "observed execution currency must match dispatch settlement currency",
        ));
    }
    if receipt.settled_amount.currency != receipt.dispatch.settlement_amount.currency {
        return Err(Web3ContractError::invalid_settlement(
            "settled amount currency must match dispatch settlement currency",
        ));
    }
    if receipt.observed_execution.amount != receipt.settled_amount {
        return Err(Web3ContractError::invalid_settlement(
            "observed execution amount must equal settled_amount",
        ));
    }
    if let Some(anchor_proof) = receipt.reconciled_anchor_proof.as_ref() {
        validate_anchor_inclusion_proof(anchor_proof)?;
        if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
            if chain_anchor.chain_id != receipt.dispatch.chain_id {
                return Err(Web3ContractError::invalid_settlement(
                    "anchor proof chain_id must match settlement dispatch chain_id",
                ));
            }
        }
    }
    if let Some(oracle_evidence) = receipt.oracle_evidence.as_ref() {
        validate_oracle_conversion_evidence(oracle_evidence)?;
    }
    if receipt
        .dispatch
        .support_boundary
        .oracle_evidence_required_for_fx
        && !matches!(
            receipt.lifecycle_state,
            Web3SettlementLifecycleState::TimedOut
                | Web3SettlementLifecycleState::Failed
                | Web3SettlementLifecycleState::Reorged
        )
        && receipt.oracle_evidence.is_none()
    {
        return Err(Web3ContractError::invalid_settlement(
            "receipt requires oracle_evidence for FX-sensitive settlement paths",
        ));
    }

    match receipt.lifecycle_state {
        Web3SettlementLifecycleState::PendingDispatch
        | Web3SettlementLifecycleState::EscrowLocked => {
            return Err(Web3ContractError::invalid_settlement(
                "execution receipts must record an observed terminal or reconciled lifecycle state",
            ));
        }
        Web3SettlementLifecycleState::PartiallySettled => {
            if receipt.settled_amount.units == 0
                || receipt.settled_amount.units >= receipt.dispatch.settlement_amount.units
            {
                return Err(Web3ContractError::invalid_settlement(
                    "partially_settled receipts must settle a non-zero amount smaller than the dispatch amount",
                ));
            }
        }
        Web3SettlementLifecycleState::Settled => {
            if receipt.settled_amount != receipt.dispatch.settlement_amount {
                return Err(Web3ContractError::invalid_settlement(
                    "settled receipts must match the dispatch settlement amount",
                ));
            }
        }
        Web3SettlementLifecycleState::Reversed | Web3SettlementLifecycleState::ChargedBack => {
            ensure_non_empty(
                receipt.reversal_of.as_deref().unwrap_or_default(),
                "web3_settlement_receipt.reversal_of",
            )?;
            if !receipt.dispatch.support_boundary.reversal_supported {
                return Err(Web3ContractError::invalid_settlement(
                    "receipt records reversal state but dispatch did not declare reversal support",
                ));
            }
        }
        Web3SettlementLifecycleState::TimedOut
        | Web3SettlementLifecycleState::Failed
        | Web3SettlementLifecycleState::Reorged => {
            ensure_non_empty(
                receipt.failure_reason.as_deref().unwrap_or_default(),
                "web3_settlement_receipt.failure_reason",
            )?;
        }
    }

    let must_have_anchor = receipt.dispatch.support_boundary.anchor_proof_required
        && !matches!(
            receipt.lifecycle_state,
            Web3SettlementLifecycleState::TimedOut | Web3SettlementLifecycleState::Failed
        );
    if must_have_anchor && receipt.reconciled_anchor_proof.is_none() {
        return Err(Web3ContractError::invalid_settlement(
            "receipt requires reconciled anchor proof for the selected settlement path",
        ));
    }

    Ok(())
}

pub fn validate_web3_qualification_matrix(
    matrix: &Web3QualificationMatrix,
) -> Result<(), Web3ContractError> {
    if matrix.schema != CHIO_WEB3_QUALIFICATION_MATRIX_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(matrix.schema.clone()));
    }
    ensure_non_empty(
        &matrix.trust_profile_id,
        "web3_qualification_matrix.trust_profile_id",
    )?;
    ensure_non_empty(
        &matrix.contract_package_id,
        "web3_qualification_matrix.contract_package_id",
    )?;
    if matrix.cases.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_qualification_matrix.cases",
        ));
    }
    let mut case_ids = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "web3_qualification_matrix.case.id")?;
        ensure_non_empty(&case.name, "web3_qualification_matrix.case.name")?;
        ensure_non_empty(&case.notes, "web3_qualification_matrix.case.notes")?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(case.id.clone()));
        }
        if case.requirement_ids.is_empty() {
            return Err(Web3ContractError::InvalidQualificationCase(format!(
                "case {} must cite at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "web3_qualification_matrix.case.requirement_ids",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct Web3CheckpointStatementBody {
    schema: String,
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: Hash,
    issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_checkpoint_sha256: Option<String>,
    kernel_key: PublicKey,
}

fn checkpoint_statement_body(statement: &Web3CheckpointStatement) -> Web3CheckpointStatementBody {
    Web3CheckpointStatementBody {
        schema: statement.schema.clone(),
        checkpoint_seq: statement.checkpoint_seq,
        batch_start_seq: statement.batch_start_seq,
        batch_end_seq: statement.batch_end_seq,
        tree_size: statement.tree_size,
        merkle_root: statement.merkle_root,
        issued_at: statement.issued_at,
        previous_checkpoint_sha256: statement.previous_checkpoint_sha256.clone(),
        kernel_key: statement.kernel_key.clone(),
    }
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), Web3ContractError> {
    if value.trim().is_empty() {
        return Err(Web3ContractError::MissingField(field));
    }
    if value.trim() != value {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate_transfer_completion_flow_binding(
    instruction: &crate::credit::CapitalExecutionInstructionArtifact,
) -> Result<(), Web3ContractError> {
    if instruction.action != CapitalExecutionInstructionAction::TransferFunds {
        return Ok(());
    }
    let governed_receipt_id =
        instruction
            .governed_receipt_id
            .as_deref()
            .ok_or(Web3ContractError::MissingField(
                "web3_settlement_dispatch.capital_instruction.governed_receipt_id",
            ))?;
    ensure_non_empty(
        governed_receipt_id,
        "web3_settlement_dispatch.capital_instruction.governed_receipt_id",
    )?;
    let completion_flow_row_id =
        instruction
            .completion_flow_row_id
            .as_deref()
            .ok_or(Web3ContractError::MissingField(
                "web3_settlement_dispatch.capital_instruction.completion_flow_row_id",
            ))?;
    ensure_non_empty(
        completion_flow_row_id,
        "web3_settlement_dispatch.capital_instruction.completion_flow_row_id",
    )?;
    let expected_row_id = format!("economic-completion-flow:{governed_receipt_id}");
    if completion_flow_row_id != expected_row_id {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch completion_flow_row_id must match governed_receipt_id",
        ));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], field: &'static str) -> Result<(), Web3ContractError> {
    let mut seen = HashSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(Web3ContractError::DuplicateValue(value.clone()));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(values: &[T], field: &'static str) -> Result<(), Web3ContractError>
where
    T: Eq + std::hash::Hash + Copy + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

fn ensure_money(amount: &MonetaryAmount, field: &'static str) -> Result<(), Web3ContractError> {
    if amount.units == 0 {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} must be non-zero"
        )));
    }
    if amount.currency.trim().is_empty() {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} currency is required"
        )));
    }
    if amount.currency.len() != 3
        || !amount
            .currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} currency must be a 3-letter uppercase code"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::capability::MonetaryAmount;
    use crate::credit::{
        CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery,
        CapitalBookSourceKind, CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction,
        CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
        CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionRole,
        CapitalExecutionWindow, SignedCapitalExecutionInstruction,
        CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
    };
    use crate::crypto::{sha256_hex, Keypair};
    use crate::merkle::MerkleTree;
    use crate::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};

    fn operator_keypair() -> Keypair {
        Keypair::from_seed(&[7u8; 32])
    }

    fn treasury_keypair() -> Keypair {
        Keypair::from_seed(&[9u8; 32])
    }

    fn sample_binding() -> SignedWeb3IdentityBinding {
        let operator = operator_keypair();
        let certificate = Web3IdentityBindingCertificate {
            schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
            chio_identity: format!("did:chio:{}", operator.public_key().to_hex()),
            chio_public_key: operator.public_key(),
            chain_scope: vec!["eip155:8453".to_string(), "eip155:42161".to_string()],
            purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
            settlement_address: "0x1111111111111111111111111111111111111111".to_string(),
            issued_at: 1_743_292_800,
            expires_at: 1_774_828_800,
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
        };
        let (signature, _) = operator.sign_canonical(&certificate).unwrap();
        SignedWeb3IdentityBinding {
            certificate,
            signature,
        }
    }

    fn sample_trust_profile() -> Web3TrustProfile {
        Web3TrustProfile {
            schema: CHIO_WEB3_TRUST_PROFILE_SCHEMA.to_string(),
            profile_id: "chio.official-web3-stack".to_string(),
            chio_contract_version: "2.0".to_string(),
            primary_chain_id: "eip155:8453".to_string(),
            secondary_chain_ids: vec!["eip155:42161".to_string()],
            operator_binding: sample_binding(),
            proof_bundle_required: true,
            dispute_windows: vec![
                Web3DisputeWindow {
                    settlement_path: Web3SettlementPath::DualSignature,
                    challenge_window_secs: 600,
                    recovery_window_secs: 3_600,
                    dispute_policy: Web3DisputePolicy::OffChainArbitration,
                },
                Web3DisputeWindow {
                    settlement_path: Web3SettlementPath::MerkleProof,
                    challenge_window_secs: 900,
                    recovery_window_secs: 86_400,
                    dispute_policy: Web3DisputePolicy::TimeoutRefund,
                },
            ],
            finality_rules: vec![
                Web3ChainFinalityRule {
                    chain_id: "eip155:8453".to_string(),
                    mode: Web3FinalityMode::OptimisticL2,
                    min_confirmations: 20,
                },
                Web3ChainFinalityRule {
                    chain_id: "eip155:42161".to_string(),
                    mode: Web3FinalityMode::L1Finalized,
                    min_confirmations: 12,
                },
            ],
            regulated_roles: vec![
                Web3RegulatedRoleAssumption {
                    role: Web3RegulatedRole::Operator,
                    actor_id: "chio-operator-main".to_string(),
                    responsibility: "Originates governed dispatch and maintains local policy activation."
                        .to_string(),
                    custody_boundary_explicit: true,
                },
                Web3RegulatedRoleAssumption {
                    role: Web3RegulatedRole::Custodian,
                    actor_id: "custodian-base-main".to_string(),
                    responsibility: "Holds settlement-side keys and custody accounts for the official stack."
                        .to_string(),
                    custody_boundary_explicit: true,
                },
                Web3RegulatedRoleAssumption {
                    role: Web3RegulatedRole::Arbitrator,
                    actor_id: "settlement-dispute-panel".to_string(),
                    responsibility: "Handles off-chain challenge and reversal review during dispute windows."
                        .to_string(),
                    custody_boundary_explicit: true,
                },
            ],
            custody_boundary_note:
                "Chio governs intent, proofs, and policy admission; custodians and payment institutions remain explicit operators of record."
                    .to_string(),
            local_policy_activation_required: true,
        }
    }

    fn sample_oracle_evidence() -> OracleConversionEvidence {
        OracleConversionEvidence {
            schema: CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA.to_string(),
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            authority: CHIO_LINK_ORACLE_AUTHORITY.to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            source: "chainlink".to_string(),
            feed_address: "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612".to_string(),
            updated_at: 1_743_292_740,
            max_age_seconds: 3_600,
            cache_age_seconds: 45,
            converted_cost_units: 300,
            original_cost_units: 100_000_000_000_000,
            original_currency: "ETH".to_string(),
            grant_currency: "USD".to_string(),
        }
    }

    fn sample_receipt() -> ChioReceipt {
        let operator = operator_keypair();
        let parameters = json!({
            "to": "0x2222222222222222222222222222222222222222",
            "amount": 150,
            "currency": "USDC"
        });
        let action = ToolCallAction::from_parameters(parameters).unwrap();
        let body = ChioReceiptBody {
            id: "rcpt-web3-1".to_string(),
            timestamp: 1_743_292_800,
            capability_id: "cap-web3-1".to_string(),
            tool_server: "chio-settle".to_string(),
            tool_name: "release_escrow".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"web3-settlement"),
            policy_hash: sha256_hex(b"policy-web3"),
            evidence: vec![],
            metadata: Some(json!({
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 150,
                    "currency": "USD",
                    "budget_remaining": 850,
                    "budget_total": 1000,
                    "delegation_depth": 1,
                    "root_budget_holder": "subject-1",
                    "payment_reference": "escrow-1",
                    "settlement_status": "pending",
                    "oracle_evidence": sample_oracle_evidence()
                }
            })),
            trust_level: chio_core_types::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: operator.public_key(),
        };
        ChioReceipt::sign(body, &operator).unwrap()
    }

    fn sample_anchor_inclusion_proof() -> AnchorInclusionProof {
        let operator = operator_keypair();
        let receipt = sample_receipt();
        let receipt_body = receipt.body();
        let receipt_bytes = canonical_json_bytes(&receipt_body).unwrap();
        let tree = MerkleTree::from_leaves(&[receipt_bytes]).unwrap();
        let merkle_root = tree.root();
        let inclusion = Web3ReceiptInclusion {
            checkpoint_seq: 1_042,
            merkle_root,
            proof: tree.inclusion_proof(0).unwrap(),
        };
        let mut statement = Web3CheckpointStatement {
            schema: CHIO_CHECKPOINT_STATEMENT_SCHEMA.to_string(),
            checkpoint_seq: 1_042,
            batch_start_seq: 104_101,
            batch_end_seq: 104_200,
            tree_size: 1,
            merkle_root,
            issued_at: 1_743_292_800,
            previous_checkpoint_sha256: None,
            kernel_key: operator.public_key(),
            signature: Signature::from_hex(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        };
        let body = checkpoint_statement_body(&statement);
        let (signature, _) = operator.sign_canonical(&body).unwrap();
        statement.signature = signature;

        AnchorInclusionProof {
            schema: CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA.to_string(),
            receipt,
            receipt_inclusion: inclusion,
            checkpoint_statement: statement,
            chain_anchor: Some(Web3ChainAnchorRecord {
                chain_id: "eip155:8453".to_string(),
                contract_address: "0x1000000000000000000000000000000000000001".to_string(),
                operator_address: "0x1111111111111111111111111111111111111111".to_string(),
                tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                block_number: 12_345_678,
                block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                anchored_merkle_root: merkle_root,
                anchored_checkpoint_seq: 1_042,
            }),
            bitcoin_anchor: None,
            super_root_inclusion: None,
            key_binding_certificate: sample_binding(),
        }
    }

    fn sample_capital_instruction() -> SignedCapitalExecutionInstruction {
        let signer = treasury_keypair();
        SignedCapitalExecutionInstruction::sign(
            crate::credit::CapitalExecutionInstructionArtifact {
                schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
                instruction_id: "cei-web3-1".to_string(),
                issued_at: 1_743_292_800,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                source_id: "capital-source:facility:facility-1".to_string(),
                source_kind: CapitalBookSourceKind::FacilityCommitment,
                governed_receipt_id: Some("rcpt-web3-1".to_string()),
                completion_flow_row_id: Some("economic-completion-flow:rcpt-web3-1".to_string()),
                action: CapitalExecutionInstructionAction::TransferFunds,
                owner_role: CapitalExecutionRole::OperatorTreasury,
                counterparty_role: CapitalExecutionRole::AgentCounterparty,
                counterparty_id: "subject-1".to_string(),
                amount: Some(MonetaryAmount {
                    units: 150,
                    currency: "USD".to_string(),
                }),
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 1_743_292_790,
                        expires_at: 1_743_293_800,
                        note: Some("governed release".to_string()),
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-base-main".to_string(),
                        approved_at: 1_743_292_795,
                        expires_at: 1_743_293_800,
                        note: Some("official web3 stack".to_string()),
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 1_743_292_800,
                    not_after: 1_743_293_800,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Web3,
                    rail_id: "base-mainnet-usdc".to_string(),
                    custody_provider_id: "custodian-base-main".to_string(),
                    source_account_ref: Some("vault:facility-main".to_string()),
                    destination_account_ref: Some(
                        "0x2222222222222222222222222222222222222222".to_string(),
                    ),
                    jurisdiction: Some("US".to_string()),
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
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rcpt-web3-1".to_string(),
                    observed_at: Some(1_743_292_800),
                    locator: Some("receipt:rcpt-web3-1".to_string()),
                }],
                description: "release escrow over the official web3 rail".to_string(),
            },
            &signer,
        )
        .unwrap()
    }

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        Web3SettlementDispatchArtifact {
            schema: CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
            dispatch_id: "dispatch-web3-1".to_string(),
            issued_at: 1_743_292_800,
            trust_profile_id: "chio.official-web3-stack".to_string(),
            contract_package_id: "chio.official-web3-contracts".to_string(),
            chain_id: "eip155:8453".to_string(),
            capital_instruction: sample_capital_instruction(),
            bond: None,
            settlement_path: Web3SettlementPath::MerkleProof,
            settlement_amount: MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
            escrow_id: "escrow-web3-1".to_string(),
            escrow_contract: "0x1000000000000000000000000000000000000002".to_string(),
            bond_vault_contract: "0x1000000000000000000000000000000000000003".to_string(),
            beneficiary_address: "0x2222222222222222222222222222222222222222".to_string(),
            support_boundary: Web3SettlementSupportBoundary {
                real_dispatch_supported: true,
                anchor_proof_required: true,
                oracle_evidence_required_for_fx: true,
                custody_boundary_explicit: true,
                reversal_supported: true,
            },
            note: Some(
                "Dispatches one governed escrow release over the official Base-first contract stack."
                    .to_string(),
            ),
        }
    }

    fn sample_execution_receipt() -> Web3SettlementExecutionReceiptArtifact {
        Web3SettlementExecutionReceiptArtifact {
            schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
            execution_receipt_id: "receipt-web3-1".to_string(),
            issued_at: 1_743_292_860,
            dispatch: sample_dispatch(),
            observed_execution: CapitalExecutionObservation {
                observed_at: 1_743_292_860,
                external_reference_id:
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                amount: MonetaryAmount {
                    units: 150,
                    currency: "USD".to_string(),
                },
            },
            lifecycle_state: Web3SettlementLifecycleState::Settled,
            settlement_reference: "settlement-web3-1".to_string(),
            reconciled_anchor_proof: Some(sample_anchor_inclusion_proof()),
            oracle_evidence: Some(sample_oracle_evidence()),
            settled_amount: MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
            reversal_of: None,
            failure_reason: None,
            note: Some(
                "Settled against an anchored receipt root and retained oracle provenance for the FX conversion."
                    .to_string(),
            ),
        }
    }

    #[test]
    fn trust_profile_requires_local_policy_activation() {
        let mut profile = sample_trust_profile();
        profile.local_policy_activation_required = false;
        assert!(matches!(
            validate_web3_trust_profile(&profile),
            Err(Web3ContractError::InvalidBinding(_))
        ));
    }

    #[test]
    fn identity_binding_signature_verifies() {
        verify_web3_identity_binding(&sample_binding()).unwrap();
    }

    #[test]
    fn identity_binding_rejects_padded_chain_scope() {
        let mut binding = sample_binding();
        binding.certificate.chain_scope[0] = " eip155:8453".to_string();
        assert!(matches!(
            validate_web3_identity_binding(&binding),
            Err(Web3ContractError::InvalidBinding(message))
                if message.contains("binding.chain_scope")
        ));
    }

    #[test]
    fn anchor_inclusion_proof_verifies_receipt_and_merkle_root() {
        verify_anchor_inclusion_proof(&sample_anchor_inclusion_proof()).unwrap();
    }

    #[test]
    fn oracle_evidence_requires_non_zero_denominator() {
        let mut evidence = sample_oracle_evidence();
        evidence.rate_denominator = 0;
        assert!(matches!(
            validate_oracle_conversion_evidence(&evidence),
            Err(Web3ContractError::InvalidProof(_))
        ));
    }

    #[test]
    fn oracle_evidence_rejects_unknown_authority() {
        let mut evidence = sample_oracle_evidence();
        evidence.authority = "unknown_authority".to_string();
        assert!(matches!(
            validate_oracle_conversion_evidence(&evidence),
            Err(Web3ContractError::InvalidProof(_))
        ));
    }

    #[test]
    fn web3_dispatch_requires_web3_rail_kind() {
        let mut dispatch = sample_dispatch();
        dispatch.capital_instruction.body.rail.kind = CapitalExecutionRailKind::Api;
        assert!(matches!(
            validate_web3_settlement_dispatch(&dispatch),
            Err(Web3ContractError::InvalidSettlement(_))
        ));
    }

    #[test]
    fn web3_dispatch_rejects_lowercase_settlement_currency() {
        let mut dispatch = sample_dispatch();
        dispatch.settlement_amount.currency = "usd".to_string();
        dispatch
            .capital_instruction
            .body
            .amount
            .as_mut()
            .unwrap()
            .currency = "usd".to_string();

        assert!(matches!(
            validate_web3_settlement_dispatch(&dispatch),
            Err(Web3ContractError::InvalidSettlement(message))
                if message.contains("currency")
        ));
    }

    #[test]
    fn web3_dispatch_requires_completion_flow_binding_for_transfers() {
        let mut dispatch = sample_dispatch();
        dispatch.capital_instruction.body.completion_flow_row_id = None;
        assert!(matches!(
            validate_web3_settlement_dispatch(&dispatch),
            Err(Web3ContractError::MissingField(
                "web3_settlement_dispatch.capital_instruction.completion_flow_row_id"
            ))
        ));
    }

    #[test]
    fn web3_dispatch_rejects_mismatched_completion_flow_binding() {
        let mut dispatch = sample_dispatch();
        dispatch.capital_instruction.body.completion_flow_row_id =
            Some("economic-completion-flow:other-receipt".to_string());
        assert!(matches!(
            validate_web3_settlement_dispatch(&dispatch),
            Err(Web3ContractError::InvalidSettlement(_))
        ));
    }

    #[test]
    fn merkle_settlement_receipt_requires_anchor_proof() {
        let mut receipt = sample_execution_receipt();
        receipt.reconciled_anchor_proof = None;
        assert!(matches!(
            validate_web3_settlement_execution_receipt(&receipt),
            Err(Web3ContractError::InvalidSettlement(_))
        ));
    }

    #[test]
    fn fx_sensitive_settlement_receipt_requires_oracle_evidence() {
        let mut receipt = sample_execution_receipt();
        receipt.oracle_evidence = None;
        assert!(matches!(
            validate_web3_settlement_execution_receipt(&receipt),
            Err(Web3ContractError::InvalidSettlement(_))
        ));
    }

    #[test]
    fn invalid_settlement_constructor_preserves_message() {
        let error = Web3ContractError::invalid_settlement("settlement amount must match");
        assert!(matches!(
            error,
            Web3ContractError::InvalidSettlement(message)
                if message == "settlement amount must match"
        ));
    }

    #[test]
    fn reference_artifacts_parse_and_validate() {
        let trust_profile: Web3TrustProfile = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_TRUST_PROFILE.json"
        ))
        .unwrap();
        let contract_package: Web3ContractPackage = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
        ))
        .unwrap();
        let chain_configuration: Web3ChainConfiguration = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
        ))
        .unwrap();
        let anchor_proof: AnchorInclusionProof = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
        ))
        .unwrap();
        let dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .unwrap();
        let receipt: Web3SettlementExecutionReceiptArtifact = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"
        ))
        .unwrap();
        let matrix: Web3QualificationMatrix = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json"
        ))
        .unwrap();

        validate_web3_trust_profile(&trust_profile).unwrap();
        verify_web3_identity_binding(&trust_profile.operator_binding).unwrap();
        validate_web3_contract_package(&contract_package).unwrap();
        validate_web3_chain_configuration(&chain_configuration).unwrap();
        validate_anchor_inclusion_proof(&anchor_proof).unwrap();
        verify_anchor_inclusion_proof(&anchor_proof).unwrap();
        validate_web3_settlement_dispatch(&dispatch).unwrap();
        validate_web3_settlement_execution_receipt(&receipt).unwrap();
        validate_web3_qualification_matrix(&matrix).unwrap();
    }
}
