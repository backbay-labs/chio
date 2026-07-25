use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionErrorDetail, AdmissionIdentifier, AdmissionOperationId,
    AdmissionOperationState, AdmissionReplayKey, AdmissionTerminalReplay,
    PersistedAdmissionOperationV1, SignedAdmissionTerminalProjectionV1, StoreMutationFence,
    UntrustedAdmissionRecoveryClaim,
};
use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalTransition};
use chio_kernel::tool_outcome::{
    PersistedMonetaryReleaseEvidenceV1, PersistedPostReturnEvaluationRecordV1,
    PersistedRawInvocationOutcomeV1, PersistedToolOutcomeRecordV1,
};
use serde::{Deserialize, Serialize};

use super::structured_budget::{
    StructuredBudgetAuthorizeRequest, StructuredBudgetAuthorizeResponse,
    StructuredBudgetMutationResponse, StructuredBudgetReconcileRequest,
};

const ADMISSION_AUTHORITY_REQUEST_SCHEMA: &str = "chio.admission-authority-request.v1";
const ADMISSION_AUTHORITY_RESPONSE_SCHEMA: &str = "chio.admission-authority-response.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionAuthorityAction {
    Status,
    Begin,
    LoadByOperationId,
    LoadByReplayKey,
    CompareAndSwap,
    ClaimRecovery,
    RevalidateRecoveryClaim,
    ListRecoverable,
    LoadTerminalReplay,
    RecordToolReturned,
    LookupToolOutcome,
    LoadRawInvocation,
    LookupPostReturnEvaluation,
    BeginPostReturnEvaluation,
    StagePostReturnEvaluation,
    FinalizePostReturn,
    LoadResolvedOutput,
    LoadPaymentJournal,
    AdvancePaymentJournal,
    BeginPaymentSettlement,
    AuthorizeBudgetAndCommitAdmission,
    CaptureInvocationAndCommitDispatch,
    CommitTerminalProjection,
    LoadAdmissionReceipt,
    ListAdmissionReceipts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityRequest {
    pub(crate) schema: String,
    pub(crate) expected_fence: Option<StoreMutationFence>,
    pub(crate) action: AdmissionAuthorityAction,
    pub(crate) payload: serde_json::Value,
}

impl AdmissionAuthorityRequest {
    pub(crate) fn new<T: Serialize>(
        expected_fence: Option<StoreMutationFence>,
        action: AdmissionAuthorityAction,
        payload: &T,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            schema: ADMISSION_AUTHORITY_REQUEST_SCHEMA.to_owned(),
            expected_fence,
            action,
            payload: serde_json::to_value(payload)?,
        })
    }

    pub(crate) fn schema_is_valid(&self) -> bool {
        self.schema == ADMISSION_AUTHORITY_REQUEST_SCHEMA
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionAuthorityErrorCode {
    InvalidRequest,
    Unavailable,
    Fenced,
    NotFound,
    Conflict,
    CasConflict,
    Invariant,
    OutcomeUnknown,
    Unsupported,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityWireError {
    pub(crate) code: AdmissionAuthorityErrorCode,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityResponse {
    pub(crate) schema: String,
    pub(crate) result: Option<AdmissionAuthorityResultWire>,
    pub(crate) error: Option<AdmissionAuthorityWireError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityResultWire {
    pub(crate) value: serde_json::Value,
}

impl AdmissionAuthorityResponse {
    pub(crate) fn success<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            schema: ADMISSION_AUTHORITY_RESPONSE_SCHEMA.to_owned(),
            result: Some(AdmissionAuthorityResultWire {
                value: serde_json::to_value(value)?,
            }),
            error: None,
        })
    }

    pub(crate) fn failure(code: AdmissionAuthorityErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema: ADMISSION_AUTHORITY_RESPONSE_SCHEMA.to_owned(),
            result: None,
            error: Some(AdmissionAuthorityWireError {
                code,
                message: message.into(),
            }),
        }
    }

    pub(crate) fn schema_is_valid(&self) -> bool {
        self.schema == ADMISSION_AUTHORITY_RESPONSE_SCHEMA
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn admission_authority_success_preserves_null_result() -> Result<(), Box<dyn std::error::Error>>
    {
        let response = AdmissionAuthorityResponse::success(&Option::<String>::None)?;
        let encoded = serde_json::to_vec(&response)?;
        let decoded: AdmissionAuthorityResponse = serde_json::from_slice(&encoded)?;
        let result = decoded
            .result
            .ok_or_else(|| std::io::Error::other("success result wrapper is absent"))?;

        assert_eq!(result.value, serde_json::Value::Null);
        assert!(decoded.error.is_none());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionAuthorityStatusWire {
    pub(crate) fence: StoreMutationFence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionBeginWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AdmissionBeginResultWire {
    Created {
        operation: PersistedAdmissionOperationV1,
    },
    ExactReplay {
        operation: PersistedAdmissionOperationV1,
        terminal_replay: Option<AdmissionTerminalReplay>,
    },
    Conflict {
        existing_operation_id: AdmissionOperationId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationIdWire {
    pub(crate) operation_id: AdmissionOperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplayKeyWire {
    pub(crate) replay_key: AdmissionReplayKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryClaimWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) claimant_id: AdmissionIdentifier,
    pub(crate) coordinator_lease_id: AdmissionIdentifier,
    pub(crate) coordinator_lease_epoch: u64,
    pub(crate) claimed_version: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) store_fence: StoreMutationFence,
}

impl RecoveryClaimWire {
    pub(crate) fn from_claim(claim: &UntrustedAdmissionRecoveryClaim) -> Self {
        Self {
            operation_id: claim.operation_id().clone(),
            claimant_id: claim.claimant_id().clone(),
            coordinator_lease_id: claim.coordinator_lease_id().clone(),
            coordinator_lease_epoch: claim.coordinator_lease_epoch(),
            claimed_version: claim.claimed_version(),
            expires_at_unix_ms: claim.expires_at_unix_ms(),
            store_fence: claim.store_fence().clone(),
        }
    }

    pub(crate) fn into_claim(
        self,
    ) -> Result<
        UntrustedAdmissionRecoveryClaim,
        chio_kernel::admission_operation::AdmissionOperationError,
    > {
        UntrustedAdmissionRecoveryClaim::new(
            self.operation_id,
            self.claimant_id,
            self.coordinator_lease_id,
            self.coordinator_lease_epoch,
            self.claimed_version,
            self.expires_at_unix_ms,
            self.store_fence,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionCommandWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) expected_version: u64,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) attachments: Vec<AdmissionAttachment>,
    pub(crate) next_state: Option<AdmissionOperationState>,
    pub(crate) terminal_replay: Option<AdmissionTerminalReplay>,
    pub(crate) last_error: Option<AdmissionErrorDetail>,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionDispatchCaptureWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) authority_id: String,
    pub(crate) authority_lease_id: String,
    pub(crate) authority_lease_epoch: u64,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionBudgetAuthorizeWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) budget: StructuredBudgetAuthorizeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) payment_journal: Option<PaymentJournalRecord>,
    pub(crate) authority_id: String,
    pub(crate) authority_lease_id: String,
    pub(crate) authority_lease_epoch: u64,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionPaymentAdvanceWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) expected: PaymentJournalRecord,
    pub(crate) transition: PaymentJournalTransition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) release_evidence: Option<PersistedMonetaryReleaseEvidenceV1>,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionPaymentSettlementBeginWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) expected: PaymentJournalRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transition: Option<PaymentJournalTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) release_evidence: Option<PersistedMonetaryReleaseEvidenceV1>,
    pub(crate) budget_reconcile: StructuredBudgetReconcileRequest,
    pub(crate) authority_id: String,
    pub(crate) authority_lease_id: String,
    pub(crate) authority_lease_epoch: u64,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionBudgetAuthorizeResultWire {
    pub(crate) budget: StructuredBudgetAuthorizeResponse,
    pub(crate) operation: PersistedAdmissionOperationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionDispatchCaptureResultWire {
    pub(crate) budget: StructuredBudgetMutationResponse,
    pub(crate) operation: PersistedAdmissionOperationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionPaymentSettlementResultWire {
    pub(crate) journal: PaymentJournalRecord,
    pub(crate) budget: StructuredBudgetMutationResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionCommandResultWire {
    pub(crate) applied: bool,
    pub(crate) operation: PersistedAdmissionOperationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRecoveryWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) expected_version: u64,
    pub(crate) claimant_id: AdmissionIdentifier,
    pub(crate) trusted_now_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) fence: StoreMutationFence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevalidateRecoveryClaimWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) claim: RecoveryClaimWire,
    pub(crate) trusted_now_unix_ms: u64,
    pub(crate) current_fence: StoreMutationFence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRecoverableWire {
    pub(crate) not_after_unix_ms: u64,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordToolReturnedWire {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) raw: PersistedRawInvocationOutcomeV1,
    pub(crate) record: PersistedToolOutcomeRecordV1,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolOutcomeInsertResultWire {
    pub(crate) inserted: bool,
    pub(crate) outcome: PersistedToolOutcomeRecordV1,
    pub(crate) operation: PersistedAdmissionOperationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeginPostReturnEvaluationWire {
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) record: PersistedPostReturnEvaluationRecordV1,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagePostReturnEvaluationWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) expected_version: u64,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) next: PersistedPostReturnEvaluationRecordV1,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizePostReturnWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) expected_evaluation_version: u64,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) terminal_evaluation: PersistedPostReturnEvaluationRecordV1,
    pub(crate) expected_outcome_version: u64,
    pub(crate) terminal_outcome: PersistedToolOutcomeRecordV1,
    pub(crate) resolved_output: Option<String>,
    pub(crate) active_fence: StoreMutationFence,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizePostReturnResultWire {
    pub(crate) evaluation: PersistedPostReturnEvaluationRecordV1,
    pub(crate) outcome: PersistedToolOutcomeRecordV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommitTerminalProjectionWire {
    pub(crate) projection: SignedAdmissionTerminalProjectionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionTerminalWire {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) state: AdmissionOperationState,
    pub(crate) replay: AdmissionTerminalReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptIdWire {
    pub(crate) receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListAdmissionReceiptsWire {
    pub(crate) after_receipt_id: Option<String>,
    pub(crate) limit: usize,
}
