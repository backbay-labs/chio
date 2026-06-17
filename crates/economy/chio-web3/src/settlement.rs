use serde::{Deserialize, Serialize};

use crate::anchors::{
    validate_oracle_conversion_evidence, verify_anchor_inclusion_proof, AnchorInclusionProof,
    OracleConversionEvidence,
};
use crate::capability::scope::MonetaryAmount;
use crate::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CapitalExecutionReconciledState,
    CreditBondLifecycleState, SignedCapitalExecutionInstruction, SignedCreditBond,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::error::Web3ContractError;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::trust_profile::Web3SettlementPath;
use crate::validation::{ensure_money, ensure_non_empty};

pub const CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA: &str = "chio.web3-settlement-dispatch.v1";
pub const CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v1";
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
    ensure_non_empty(
        &receipt.observed_execution.external_reference_id,
        "web3_settlement_receipt.observed_execution.external_reference_id",
    )?;
    validate_observed_execution_reference(
        &receipt.dispatch.chain_id,
        &receipt.observed_execution.external_reference_id,
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
    let execution_window = &receipt.dispatch.capital_instruction.body.execution_window;
    if receipt.observed_execution.observed_at < execution_window.not_before
        || receipt.observed_execution.observed_at > execution_window.not_after
    {
        return Err(Web3ContractError::invalid_settlement(
            "observed execution timestamp falls outside dispatch execution window",
        ));
    }
    if let Some(anchor_proof) = receipt.reconciled_anchor_proof.as_ref() {
        verify_anchor_inclusion_proof(anchor_proof)?;
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
        if oracle_evidence.grant_currency != receipt.dispatch.settlement_amount.currency {
            return Err(Web3ContractError::invalid_settlement(
                "oracle conversion grant_currency must match settlement currency",
            ));
        }
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
