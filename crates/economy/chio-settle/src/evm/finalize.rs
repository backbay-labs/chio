//! EVM dispatch finalization and runtime settlement receipt builders.

use super::*;

pub fn finalize_escrow_dispatch(
    prepared: &PreparedEscrowCreate,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedEscrowCreate, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before escrow identity could be finalized",
            receipt.tx_hash
        )));
    }
    let escrow_id = extract_escrow_created_id(receipt, &prepared.call.to_address)?;
    let mut finalized = prepared.clone();
    finalized.expected_escrow_id = escrow_id.clone();
    finalized.dispatch.escrow_id = escrow_id;
    Ok(finalized)
}

pub fn finalize_bond_lock(
    prepared: &PreparedBondLock,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedBondLock, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before bond identity could be finalized",
            receipt.tx_hash
        )));
    }
    let (vault_id, bond_id_hash, facility_id_hash) =
        extract_bond_locked_identity(receipt, &prepared.call.to_address)?;
    if bond_id_hash != prepared.bond_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected bond {}, observed {}",
            prepared.bond_id_hash, bond_id_hash
        )));
    }
    if facility_id_hash != prepared.facility_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected facility {}, observed {}",
            prepared.facility_id_hash, facility_id_hash
        )));
    }
    let mut finalized = prepared.clone();
    finalized.vault_id = vault_id;
    Ok(finalized)
}

pub fn build_failure_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    failure_reference: String,
    failure_reason: String,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let amount = dispatch.settlement_amount.clone();
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: chio_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: failure_reference,
            amount: amount.clone(),
        },
        lifecycle_state: Web3SettlementLifecycleState::Failed,
        settlement_reference,
        reconciled_anchor_proof: None,
        identity_registry_evidence: None,
        identity_registry_evidence_binding: None,
        oracle_evidence: None,
        settled_amount: amount,
        reversal_of: None,
        failure_reason: Some(failure_reason),
        note: Some(
            "Runtime-marked failure after bounded retry or validation exhaustion.".to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}

pub fn build_reversal_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    tx_hash: String,
    observed_amount: MonetaryAmount,
    reversal_of: String,
    charged_back: bool,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: chio_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: tx_hash,
            amount: observed_amount.clone(),
        },
        lifecycle_state: if charged_back {
            Web3SettlementLifecycleState::ChargedBack
        } else {
            Web3SettlementLifecycleState::Reversed
        },
        settlement_reference,
        reconciled_anchor_proof: None,
        identity_registry_evidence: None,
        identity_registry_evidence_binding: None,
        oracle_evidence: None,
        settled_amount: observed_amount,
        reversal_of: Some(reversal_of),
        failure_reason: None,
        note: Some(
            "Runtime-projected compensating settlement after dispute or operator recovery."
                .to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}
