use serde::{Deserialize, Serialize};

use crate::anchors::{
    expected_operator_key_hash, validate_oracle_conversion_evidence, verify_anchor_inclusion_proof,
    AnchorInclusionProof, OracleConversionEvidence,
};
use crate::canonical::canonical_json_bytes;
use crate::capability::scope::MonetaryAmount;
use crate::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CapitalExecutionReconciledState,
    CreditBondLifecycleState, SignedCapitalExecutionInstruction, SignedCreditBond,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::crypto::sha256_hex;
use crate::error::Web3ContractError;
use crate::hashing::Hash;
use crate::receipt::{
    body::ChioReceipt, lineage::SignedExportEnvelope,
    signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
};
use crate::trust_profile::Web3SettlementPath;
use crate::validation::{ensure_evm_address, ensure_money, ensure_non_empty, evm_addresses_match};

pub const CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA: &str = "chio.web3-settlement-dispatch.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA: &str = "chio.web3-settlement-dispatch.v2";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA: &str = CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA;
pub const CHIO_WEB3_SETTLEMENT_RECEIPT_V1_SCHEMA: &str =
    "chio.web3-settlement-execution-receipt.v1";
pub const CHIO_WEB3_SETTLEMENT_RECEIPT_V2_SCHEMA: &str =
    "chio.web3-settlement-execution-receipt.v2";
pub const CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA: &str = CHIO_WEB3_SETTLEMENT_RECEIPT_V2_SCHEMA;
pub const CHIO_LINK_CONTROL_STATE_SCHEMA: &str = "chio.link.control-state.v1";
pub const CHIO_LINK_CONTROL_TRACE_SCHEMA: &str = "chio.link.control-trace.v1";
pub const CHIO_SETTLE_CONTROL_STATE_SCHEMA: &str = "chio.settle.control-state.v1";
pub const CHIO_SETTLE_CONTROL_TRACE_SCHEMA: &str = "chio.settle.control-trace.v1";

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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub settlement_token_address: String,
    pub beneficiary_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operator_key_hash: String,
    pub support_boundary: Web3SettlementSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedWeb3SettlementDispatch = SignedExportEnvelope<Web3SettlementDispatchArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SettlementIdentityRegistryEvidence {
    pub chain_id: String,
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub block_number: u64,
    pub block_hash: String,
    pub observed_at: u64,
    pub operator_key_hash: String,
    pub settlement_key: String,
    pub registered_at: u64,
    pub operator_epoch: u64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3SettlementIdentityRegistryEvidenceBinding {
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub settlement_key: String,
}

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
    pub identity_registry_evidence: Option<Web3SettlementIdentityRegistryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry_evidence_binding: Option<Web3SettlementIdentityRegistryEvidenceBinding>,
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

pub fn validate_web3_settlement_dispatch(
    dispatch: &Web3SettlementDispatchArtifact,
) -> Result<(), Web3ContractError> {
    let dispatch_v2 = match dispatch.schema.as_str() {
        CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA => true,
        CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA => false,
        _ => {
            return Err(Web3ContractError::UnsupportedSchema(
                dispatch.schema.clone(),
            ))
        }
    };
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
    if dispatch_v2 {
        ensure_non_empty(
            &dispatch.settlement_token_address,
            "web3_settlement_dispatch.settlement_token_address",
        )?;
        ensure_evm_address(
            &dispatch.settlement_token_address,
            "web3_settlement_dispatch.settlement_token_address",
        )?;
        ensure_non_empty(
            &dispatch.operator_key_hash,
            "web3_settlement_dispatch.operator_key_hash",
        )?;
    }
    if !dispatch.operator_key_hash.is_empty() {
        let operator_key_hash = Hash::from_hex(&dispatch.operator_key_hash).map_err(|error| {
            Web3ContractError::invalid_settlement(format!(
                "web3 settlement dispatch operator_key_hash must be a 32-byte hex hash: {error}"
            ))
        })?;
        if dispatch_v2 && operator_key_hash == Hash::zero() {
            return Err(Web3ContractError::invalid_settlement(
                "web3 settlement dispatch operator_key_hash must not be zero",
            ));
        }
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
    let signature_valid = dispatch
        .capital_instruction
        .verify_signature()
        .map_err(|error| {
            Web3ContractError::invalid_settlement(format!(
                "capital instruction signature verification failed: {error}"
            ))
        })?;
    if !signature_valid {
        return Err(Web3ContractError::invalid_settlement(
            "capital instruction signature verification failed",
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
    let Some(destination_account_ref) = dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref
        .as_deref()
    else {
        return Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.rail.destination_account_ref",
        ));
    };
    ensure_non_empty(
        destination_account_ref,
        "web3_settlement_dispatch.capital_instruction.rail.destination_account_ref",
    )?;
    if !evm_addresses_match(destination_account_ref, &dispatch.beneficiary_address)? {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement dispatch beneficiary_address must match capital_instruction rail.destination_account_ref",
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
    dispatch
        .capital_instruction
        .body
        .validate()
        .map_err(|error| {
            Web3ContractError::invalid_settlement(format!(
                "capital instruction validation failed: {error}"
            ))
        })?;
    if let Some(bond) = dispatch.bond.as_ref() {
        let signature_valid = bond.verify_signature().map_err(|error| {
            Web3ContractError::invalid_settlement(format!(
                "credit bond signature verification failed: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(Web3ContractError::invalid_settlement(
                "credit bond signature verification failed",
            ));
        }
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
    let receipt_v2 = match receipt.schema.as_str() {
        CHIO_WEB3_SETTLEMENT_RECEIPT_V2_SCHEMA => true,
        CHIO_WEB3_SETTLEMENT_RECEIPT_V1_SCHEMA => false,
        _ => return Err(Web3ContractError::UnsupportedSchema(receipt.schema.clone())),
    };
    let dispatch_v2 = match receipt.dispatch.schema.as_str() {
        CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA => true,
        CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA => false,
        _ => {
            return Err(Web3ContractError::UnsupportedSchema(
                receipt.dispatch.schema.clone(),
            ))
        }
    };
    if receipt_v2 != dispatch_v2 {
        return Err(Web3ContractError::invalid_settlement(
            "web3 settlement receipt schema must match dispatch schema generation",
        ));
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
    let escrow_locked = receipt.lifecycle_state == Web3SettlementLifecycleState::EscrowLocked;
    ensure_receipt_money(
        &receipt.observed_execution.amount,
        "web3_settlement_receipt.observed_amount",
        escrow_locked,
    )?;
    ensure_non_empty(
        &receipt.observed_execution.external_reference_id,
        "web3_settlement_receipt.observed_execution.external_reference_id",
    )?;
    ensure_receipt_money(
        &receipt.settled_amount,
        "web3_settlement_receipt.settled_amount",
        escrow_locked,
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
    let has_transaction_reference = validate_observed_execution_reference(
        &receipt.dispatch.chain_id,
        &receipt.observed_execution.external_reference_id,
    )
    .is_ok();
    if receipt.lifecycle_state == Web3SettlementLifecycleState::Failed {
        if !has_transaction_reference
            && (receipt.observed_execution.amount.units != 0 || receipt.settled_amount.units != 0)
        {
            return Err(Web3ContractError::invalid_settlement(
                "failed settlement with non-zero amount requires transaction reference",
            ));
        }
    } else if !has_transaction_reference {
        validate_observed_execution_reference(
            &receipt.dispatch.chain_id,
            &receipt.observed_execution.external_reference_id,
        )?;
    }
    let execution_window = &receipt.dispatch.capital_instruction.body.execution_window;
    let observed_before_window =
        receipt.observed_execution.observed_at < execution_window.not_before;
    let observed_after_window = receipt.observed_execution.observed_at > execution_window.not_after;
    let timeout_refund_after_deadline =
        receipt.lifecycle_state == Web3SettlementLifecycleState::TimedOut && observed_after_window;
    if observed_before_window || (observed_after_window && !timeout_refund_after_deadline) {
        return Err(Web3ContractError::invalid_settlement(
            "observed execution timestamp falls outside dispatch execution window",
        ));
    }
    if let Some(anchor_proof) = receipt.reconciled_anchor_proof.as_ref() {
        verify_anchor_inclusion_proof(anchor_proof)?;
        validate_anchor_receipt_binding(receipt, &anchor_proof.receipt)?;
        if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
            if chain_anchor.chain_id != receipt.dispatch.chain_id {
                return Err(Web3ContractError::invalid_settlement(
                    "anchor proof chain_id must match settlement dispatch chain_id",
                ));
            }
            if dispatch_v2 {
                let dispatch_operator_key =
                    Hash::from_hex(&receipt.dispatch.operator_key_hash).map_err(|error| {
                        Web3ContractError::invalid_settlement(format!(
                            "web3 settlement dispatch operator_key_hash must be a 32-byte hex hash: {error}"
                        ))
                    })?;
                let anchor_operator_key =
                    Hash::from_hex(&chain_anchor.operator_key_hash).map_err(|error| {
                        Web3ContractError::invalid_settlement(format!(
                            "anchor proof operator_key_hash must be a 32-byte hex hash: {error}"
                        ))
                    })?;
                if dispatch_operator_key != anchor_operator_key {
                    return Err(Web3ContractError::invalid_settlement(
                        "dispatch operator_key_hash must match anchor proof operator_key_hash",
                    ));
                }
                let binding_operator_key = expected_operator_key_hash(
                    &anchor_proof
                        .key_binding_certificate
                        .certificate
                        .chio_public_key,
                )?;
                if dispatch_operator_key != binding_operator_key {
                    return Err(Web3ContractError::invalid_settlement(
                        "dispatch operator_key_hash must match binding certificate public key",
                    ));
                }
            }
        }
    }
    if let Some(oracle_evidence) = receipt.oracle_evidence.as_ref() {
        validate_oracle_conversion_evidence(oracle_evidence)?;
        if oracle_evidence.grant_currency != receipt.dispatch.settlement_amount.currency {
            return Err(Web3ContractError::invalid_settlement(
                "oracle conversion grant_currency must match settlement currency",
            ));
        }
    }
    if let Some(registry_evidence) = receipt.identity_registry_evidence.as_ref() {
        validate_identity_registry_evidence(receipt, registry_evidence)?;
        if let Some(binding) = receipt.identity_registry_evidence_binding.as_ref() {
            validate_identity_registry_evidence_binding(registry_evidence, binding)?;
        }
    } else if receipt.identity_registry_evidence_binding.is_some() {
        return Err(Web3ContractError::invalid_settlement(
            "identity_registry_evidence_binding requires identity_registry_evidence",
        ));
    }
    let requires_registry_evidence = receipt_v2
        && receipt.dispatch.settlement_path == Web3SettlementPath::DualSignature
        && matches!(
            receipt.lifecycle_state,
            Web3SettlementLifecycleState::Settled | Web3SettlementLifecycleState::PartiallySettled
        );
    if requires_registry_evidence && receipt.identity_registry_evidence.is_none() {
        return Err(Web3ContractError::invalid_settlement(
            "dual-sign settlement receipts require identity_registry_evidence",
        ));
    }
    if requires_registry_evidence && receipt.identity_registry_evidence_binding.is_none() {
        return Err(Web3ContractError::invalid_settlement(
            "dual-sign settlement receipts require identity_registry_evidence_binding",
        ));
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
                | Web3SettlementLifecycleState::EscrowLocked
        )
        && receipt.oracle_evidence.is_none()
    {
        return Err(Web3ContractError::invalid_settlement(
            "receipt requires oracle_evidence for FX-sensitive settlement paths",
        ));
    }

    match receipt.lifecycle_state {
        Web3SettlementLifecycleState::PendingDispatch => {
            return Err(Web3ContractError::invalid_settlement(
                "execution receipts must record an observed terminal or reconciled lifecycle state",
            ));
        }
        Web3SettlementLifecycleState::EscrowLocked => {
            if receipt.observed_execution.amount.units != 0 || receipt.settled_amount.units != 0 {
                return Err(Web3ContractError::invalid_settlement(
                    "escrow_locked execution receipts must not record durable settlement amount",
                ));
            }
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
            Web3SettlementLifecycleState::TimedOut
                | Web3SettlementLifecycleState::Failed
                | Web3SettlementLifecycleState::EscrowLocked
        );
    if must_have_anchor && receipt.reconciled_anchor_proof.is_none() {
        return Err(Web3ContractError::invalid_settlement(
            "receipt requires reconciled anchor proof for the selected settlement path",
        ));
    }

    Ok(())
}

fn validate_identity_registry_evidence(
    receipt: &Web3SettlementExecutionReceiptArtifact,
    evidence: &Web3SettlementIdentityRegistryEvidence,
) -> Result<(), Web3ContractError> {
    if evidence.chain_id != receipt.dispatch.chain_id {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence chain_id must match settlement dispatch chain_id",
        ));
    }
    ensure_non_zero_evm_address(
        &evidence.identity_registry_contract,
        "identity_registry_evidence.identity_registry_contract",
    )?;
    ensure_non_zero_evm_address(
        &evidence.operator_address,
        "identity_registry_evidence.operator_address",
    )?;
    ensure_non_zero_evm_address(
        &evidence.settlement_key,
        "identity_registry_evidence.settlement_key",
    )?;
    if evidence.block_number == 0 {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence block_number must be non-zero",
        ));
    }
    if evidence.observed_at == 0 {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence observed_at must be non-zero",
        ));
    }
    if evidence.registered_at == 0 {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence registered_at must be non-zero",
        ));
    }
    if evidence.operator_epoch == 0 {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence operator_epoch must be non-zero",
        ));
    }
    if !evidence.active {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence operator must be active",
        ));
    }
    let block_hash = Hash::from_hex(&evidence.block_hash).map_err(|error| {
        Web3ContractError::invalid_settlement(format!(
            "identity_registry_evidence.block_hash must be a 32-byte hex hash: {error}"
        ))
    })?;
    if block_hash.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence block_hash must be non-zero",
        ));
    }
    let evidence_operator_key = Hash::from_hex(&evidence.operator_key_hash).map_err(|error| {
        Web3ContractError::invalid_settlement(format!(
            "identity_registry_evidence.operator_key_hash must be a 32-byte hex hash: {error}"
        ))
    })?;
    let dispatch_operator_key =
        Hash::from_hex(&receipt.dispatch.operator_key_hash).map_err(|error| {
            Web3ContractError::invalid_settlement(format!(
                "web3 settlement dispatch operator_key_hash must be a 32-byte hex hash: {error}"
            ))
        })?;
    if evidence_operator_key != dispatch_operator_key {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence operator_key_hash must match dispatch operator_key_hash",
        ));
    }
    Ok(())
}

fn validate_identity_registry_evidence_binding(
    evidence: &Web3SettlementIdentityRegistryEvidence,
    binding: &Web3SettlementIdentityRegistryEvidenceBinding,
) -> Result<(), Web3ContractError> {
    ensure_non_zero_evm_address(
        &binding.identity_registry_contract,
        "identity_registry_evidence_binding.identity_registry_contract",
    )?;
    ensure_non_zero_evm_address(
        &binding.operator_address,
        "identity_registry_evidence_binding.operator_address",
    )?;
    ensure_non_zero_evm_address(
        &binding.settlement_key,
        "identity_registry_evidence_binding.settlement_key",
    )?;
    if !evm_addresses_match(
        &evidence.identity_registry_contract,
        &binding.identity_registry_contract,
    )? {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence contract must match binding",
        ));
    }
    if !evm_addresses_match(&evidence.operator_address, &binding.operator_address)? {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence operator must match binding",
        ));
    }
    if !evm_addresses_match(&evidence.settlement_key, &binding.settlement_key)? {
        return Err(Web3ContractError::invalid_settlement(
            "identity registry evidence settlement_key must match binding",
        ));
    }
    Ok(())
}

fn ensure_non_zero_evm_address(value: &str, field: &'static str) -> Result<(), Web3ContractError> {
    ensure_evm_address(value, field)?;
    if value
        .strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|byte| byte == b'0'))
    {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} must be non-zero"
        )));
    }
    Ok(())
}

fn validate_anchor_receipt_binding(
    receipt: &Web3SettlementExecutionReceiptArtifact,
    anchor_receipt: &ChioReceipt,
) -> Result<(), Web3ContractError> {
    let governed_receipt_id = receipt
        .dispatch
        .capital_instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.governed_receipt_id",
        ))?;
    let Some(receipt_nonce) = anchor_receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY))
        .and_then(serde_json::Value::as_str)
    else {
        return Err(Web3ContractError::invalid_settlement(
            "anchor proof receipt must carry signing nonce",
        ));
    };
    if receipt_nonce != governed_receipt_id {
        return Err(Web3ContractError::invalid_settlement(
            "anchor proof receipt must match governed receipt",
        ));
    }
    let expected_content_hash = settlement_anchor_receipt_content_hash(receipt)?;
    if anchor_receipt.content_hash != expected_content_hash {
        return Err(Web3ContractError::invalid_settlement(
            "anchor proof receipt content hash must bind settlement execution",
        ));
    }
    Ok(())
}

pub(crate) fn settlement_anchor_receipt_content_hash(
    receipt: &Web3SettlementExecutionReceiptArtifact,
) -> Result<String, Web3ContractError> {
    let governed_receipt_id = receipt
        .dispatch
        .capital_instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.governed_receipt_id",
        ))?;
    settlement_anchor_receipt_content_hash_parts(
        &receipt.execution_receipt_id,
        &receipt.settlement_reference,
        &receipt.dispatch.dispatch_id,
        governed_receipt_id,
    )
}

pub fn settlement_anchor_receipt_content_hash_parts(
    execution_receipt_id: &str,
    settlement_reference: &str,
    dispatch_id: &str,
    governed_receipt_id: &str,
) -> Result<String, Web3ContractError> {
    let body = SettlementAnchorReceiptBinding {
        execution_receipt_id,
        settlement_reference,
        dispatch_id,
        governed_receipt_id,
    };
    let bytes = canonical_json_bytes(&body).map_err(|error| {
        Web3ContractError::invalid_settlement(format!(
            "settlement anchor receipt binding canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

#[derive(Serialize)]
struct SettlementAnchorReceiptBinding<'a> {
    execution_receipt_id: &'a str,
    settlement_reference: &'a str,
    dispatch_id: &'a str,
    governed_receipt_id: &'a str,
}

fn validate_observed_execution_reference(
    chain_id: &str,
    reference_id: &str,
) -> Result<(), Web3ContractError> {
    if chain_id.starts_with("eip155:") && !is_eip155_transaction_hash(reference_id) {
        return Err(Web3ContractError::invalid_settlement(
            "observed execution reference must be an eip155 transaction hash",
        ));
    }
    Ok(())
}

fn is_eip155_transaction_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn ensure_receipt_money(
    amount: &MonetaryAmount,
    field: &'static str,
    allow_zero: bool,
) -> Result<(), Web3ContractError> {
    if amount.units == 0 && allow_zero {
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
        return Ok(());
    }
    ensure_money(amount, field)
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
