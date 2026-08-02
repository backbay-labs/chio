//! Chio settlement runtime over the official web3 contract family.
//!
//! `chio-settle` turns approved Chio capital instructions into real contract
//! calls, projects on-chain state back into the frozen web3 receipt family, and
//! exposes the bounded Solana-native settlement model used for Ed25519-first
//! parity checks.

#![forbid(unsafe_code)]
#![cfg(feature = "web3")]

mod automation;
mod ccip;
pub mod channel;
mod config;
mod evm;
#[cfg(feature = "cognition-market-experimental")]
mod finding_enforcement;
mod hook;
mod observe;
mod ops;
mod outcome_store;
mod payments;
mod retry;
mod solana;

use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

pub use automation::{
    assess_watchdog_execution, build_bond_watchdog_job, build_settlement_watchdog_job,
    SettlementAutomationExecution, SettlementAutomationOutcome, SettlementAutomationTriggerKind,
    SettlementWatchdogJob, SettlementWatchdogKind, CHIO_SETTLEMENT_AUTOMATION_JOB_SCHEMA,
};
pub use ccip::{
    prepare_ccip_settlement_message, reconcile_ccip_delivery, CcipDeliveryObservation,
    CcipLaneConfig, CcipMessageStatus, CcipReconciliationOutcome, CcipSettlementMessage,
    CcipSettlementPayload, CHIO_CCIP_SETTLEMENT_MESSAGE_SCHEMA,
};
pub use config::{
    settlement_devnet_rpc_egress_contract, DevnetContracts, DevnetMocks, EvidenceSubstrateMode,
    LocalDevnetDeployment, SettlementAmountTier, SettlementChainConfig, SettlementEvidenceConfig,
    SettlementOracleAuthority, SettlementOracleConfig, SettlementPolicyConfig,
};
pub use evm::{
    build_failure_receipt, build_reversal_receipt, confirm_transaction, estimate_call_gas,
    finalize_bond_lock, finalize_escrow_dispatch, prepare_authorized_channel_merkle_release,
    prepare_bond_expiry, prepare_bond_impair, prepare_bond_lock,
    prepare_bond_proof_root_publication, prepare_bond_release, prepare_dual_sign_release,
    prepare_erc20_approval, prepare_escrow_refund, prepare_merkle_release,
    prepare_merkle_release_root_publication, prepare_web3_escrow_dispatch, read_bond_snapshot,
    read_escrow_snapshot, scale_chio_amount_to_token_minor_units,
    scale_token_minor_units_to_chio_amount, static_validate_call, submit_call, BondLockRequest,
    DualSignReleaseInput, EscrowDispatchRequest, EscrowExecutionAmount, EscrowSnapshot,
    EvmBondSnapshot, EvmLogEntry, EvmSignature, EvmTransactionReceipt,
    PreparedAuthorizedChannelMerkleReleaseV1, PreparedBondExpiry, PreparedBondImpair,
    PreparedBondLock, PreparedBondProofRoot, PreparedBondRelease, PreparedDualSignRelease,
    PreparedErc20Approval, PreparedEscrowCreate, PreparedEscrowRefund, PreparedEvmCall,
    PreparedEvmSubmission, PreparedMerkleRelease, PreparedRootPublication,
    SettlementAnchorContentBinding,
};
#[cfg(feature = "cognition-market-experimental")]
pub use finding_enforcement::{
    dispatch_finding_impairment, plan_finding_impairment, recheck_finding_bond_observation,
    reconcile_finding_impairment, reobserve_finding_impairment, verify_finding_collateral_snapshot,
    verify_finding_enforcement, verify_finding_enforcement_for_reconciliation,
    FindingBondObservationRecheck, FindingBondObservationSource, FindingBondObservationVerdict,
    FindingEnforcementPins, FindingFinalityRequirement, FindingImpairmentAttempt,
    FindingImpairmentDestination, FindingImpairmentIntent, FindingImpairmentOutcome,
    FindingImpairmentPublishError, FindingImpairmentPublisher, FindingImpairmentQuarantine,
    FindingOperatorQualification, FindingVaultRejection, PlannedFindingImpairment,
    StoredImpairmentTransaction, VerifiedFindingEnforcement,
};
pub use hook::{
    SettlementFailureClass, SettlementFailureCode, SettlementFailureCodeParseError,
    SettlementFailureReason, SettlementHook, SettlementHookError, SettlementIdempotencyKey,
    SettlementObservation, SettlementOutcome, SettlementSkipReason, SETTLEMENT_OBSERVATION_SCHEMA,
    SETTLEMENT_OUTCOME_SCHEMA,
};
pub use observe::{
    inspect_finality, inspect_finality_for_receipt, observe_bond, project_escrow_execution_receipt,
    BondLifecycleObservation, BondLifecycleStatus, EscrowExecutionProjection,
    EscrowLifecycleStatus, ExecutionProjectionInput, SettlementFinalityAssessment,
    SettlementFinalityStatus, SettlementRecoveryAction,
};
pub use ops::{
    classify_settlement_lane, ensure_settlement_operation_allowed, SettlementAlertSeverity,
    SettlementControlChangeRecord, SettlementControlState, SettlementEmergencyControls,
    SettlementEmergencyMode, SettlementIncidentAlert, SettlementIndexerCursor,
    SettlementIndexerCursorInput, SettlementIndexerStatus, SettlementLaneRuntimeStatus,
    SettlementLaneRuntimeStatusInput, SettlementOperationKind, SettlementRecoveryRecord,
    SettlementRuntimeReport, SettlementRuntimeStatus, CHIO_SETTLE_RUNTIME_REPORT_SCHEMA,
};
pub use outcome_store::{
    validate_settlement_claim, SettlementAttemptClaim, SettlementClaimValidationError,
    SettlementOutcomeStore, SettlementRoute, SettlementRouteError, SettlementRouteErrorClass,
    SettlementRoutingInput, SettlementStoreBinding, MAX_SETTLEMENT_CLAIM_BATCH,
    MAX_SETTLEMENT_LEASE_MS, MAX_SETTLEMENT_WORKER_ID_BYTES,
};
pub use payments::{
    approval_binding_from_governed, build_x402_payment_requirements, evaluate_circle_nanopayment,
    prepare_paymaster_compatibility, prepare_transfer_with_authorization,
    validate_offchain_settlement_receipt, ApprovalBinding, CircleNanopaymentPolicy, Eip3009Domain,
    Eip3009NonceStore, Erc4337PaymasterPolicy, InMemoryEip3009NonceStore, NonceOutcome,
    OffchainSettlementReceiptArtifact, PreparedCircleNanopayment, PreparedPaymasterCompatibility,
    PreparedTransferWithAuthorization, RailBinding, TransferWithAuthorizationInput,
    X402PaymentRequirements, X402SettlementMode, CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA,
    DEFAULT_MAX_EIP3009_NONCE_ENTRIES,
};
pub use retry::{
    classify_attempt, DeadLetterRecord, RetryDecision, RetryPolicy, RetryPolicyError,
    DEFAULT_BACKOFF_CAP_MS, DEFAULT_BACKOFF_MULTIPLIER, DEFAULT_INITIAL_BACKOFF_MS,
    DEFAULT_MAX_RETRIES, SETTLE_DEAD_LETTER_SCHEMA,
};
pub use solana::{
    compare_commitments, prepare_solana_settlement, verify_solana_binding_and_receipt,
    CommitmentConsistencyReport, PreparedSolanaSettlement, SolanaSettlementConfig,
    SolanaSettlementRequest, SOLANA_ED25519_PROGRAM_ID,
};

pub const SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX: &str = "economic-completion-flow:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementCommitment {
    pub chain_id: String,
    pub lane_kind: String,
    pub capability_commitment: String,
    pub receipt_reference: String,
    pub operator_identity: String,
    pub settlement_amount: MonetaryAmount,
}

pub fn settlement_completion_flow_row_id(receipt_id: &str) -> Result<String, SettlementError> {
    if receipt_id.trim().is_empty() {
        return Err(SettlementError::invalid_input(
            "completion-flow binding requires a non-empty receipt id",
        ));
    }
    if receipt_id.trim() != receipt_id {
        return Err(SettlementError::invalid_input(
            "completion-flow receipt id must not contain surrounding whitespace",
        ));
    }
    Ok(format!(
        "{SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX}{receipt_id}"
    ))
}

pub fn settlement_completion_flow_receipt_id(row_id: &str) -> Result<&str, SettlementError> {
    let receipt_id = row_id
        .strip_prefix(SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX)
        .ok_or_else(|| {
            SettlementError::invalid_input(format!(
                "completion-flow row id `{row_id}` does not carry the expected prefix"
            ))
        })?;
    if receipt_id.trim().is_empty() {
        return Err(SettlementError::invalid_input(format!(
            "completion-flow row id `{row_id}` does not carry the expected prefix"
        )));
    }
    if receipt_id.trim() != receipt_id {
        return Err(SettlementError::invalid_input(
            "completion-flow row id receipt id must not contain surrounding whitespace",
        ));
    }
    Ok(receipt_id)
}

#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid dispatch: {0}")]
    InvalidDispatch(String),

    #[error("invalid binding: {0}")]
    InvalidBinding(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("verification error: {0}")]
    Verification(String),
}

impl SettlementError {
    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        settlement_completion_flow_receipt_id, settlement_completion_flow_row_id, SettlementError,
        SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn invalid_input_constructor_preserves_message() {
        let error = SettlementError::invalid_input("rpc_url must not be empty");
        assert!(matches!(
            error,
            SettlementError::InvalidInput(message) if message == "rpc_url must not be empty"
        ));
    }

    #[test]
    fn completion_flow_receipt_ids_reject_surrounding_whitespace() {
        let error = settlement_completion_flow_row_id(" receipt-1")
            .test_expect_err("padded receipt id rejected when building row id");
        assert!(error.to_string().contains("surrounding whitespace"));

        let row_id = format!("{SETTLEMENT_COMPLETION_FLOW_ROW_ID_PREFIX}receipt-1 ");
        let error = settlement_completion_flow_receipt_id(&row_id)
            .test_expect_err("padded receipt id rejected when parsing row id");
        assert!(error.to_string().contains("surrounding whitespace"));
    }
}
