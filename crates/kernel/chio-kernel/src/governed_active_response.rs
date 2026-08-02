use chio_core::capability::governance::{
    GovernedApprovalToken, GovernedTransactionIntent, GovernedTransactionIntentBody,
    ThresholdApprovalProposal, VerifiedApprovalSetBody, ACTIVE_RESPONSE_PLAN_TOOL_NAME,
    ACTIVE_RESPONSE_SERVER_ID,
};
use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_core::capability::token::CapabilityToken;
use chio_core::PublicKey;

use crate::admission_operation::{AdmissionOperationState, AdmissionOperationV1};
use crate::kernel::{
    current_unix_timestamp, current_unix_timestamp_ms, ChioKernel, DurableToolAdmission,
    VerifiedApprovalReservation,
};
use crate::{KernelError, ToolCallRequest};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedActiveResponseRequest {
    pub request_id: String,
    pub operator_capability: CapabilityToken,
    pub governed_intent: GovernedTransactionIntent,
    pub approval_tokens: Vec<GovernedApprovalToken>,
    pub threshold_approval_proposal: ThresholdApprovalProposal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_origin_kernel_id: Option<String>,
}

pub struct GovernedActiveResponseAdmission {
    admission: DurableToolAdmission,
    governed_intent_hash: String,
    operator_capability: VerifiedActiveResponseOperatorCapability,
    requirement: ThresholdApprovalRequirement,
    approval_set: VerifiedApprovalSetBody,
    approval_set_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActiveResponseOperatorCapability {
    pub capability_id: String,
    pub capability_digest: String,
    pub expires_at: u64,
    pub executor_subject: PublicKey,
}

impl core::fmt::Debug for GovernedActiveResponseAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GovernedActiveResponseAdmission")
            .field("operation_id", &self.operation_id())
            .field("state", &self.state())
            .field("governed_intent_hash", &self.governed_intent_hash)
            .field("operator_capability", &self.operator_capability)
            .field("requirement", &self.requirement)
            .field("approval_set", &self.approval_set)
            .field("approval_set_hash", &self.approval_set_hash)
            .finish()
    }
}

impl GovernedActiveResponseAdmission {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.admission.operation_id()
    }

    #[must_use]
    pub fn state(&self) -> AdmissionOperationState {
        self.admission.state()
    }

    #[must_use]
    pub fn operation(&self) -> &AdmissionOperationV1 {
        self.admission.operation()
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn approval_set_hash(&self) -> &str {
        &self.approval_set_hash
    }

    #[must_use]
    pub const fn operator_capability(&self) -> &VerifiedActiveResponseOperatorCapability {
        &self.operator_capability
    }

    #[must_use]
    pub const fn requirement(&self) -> &ThresholdApprovalRequirement {
        &self.requirement
    }

    #[must_use]
    pub const fn approval_set(&self) -> &VerifiedApprovalSetBody {
        &self.approval_set
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedActiveResponseDispatchCommit {
    Committed,
    AlreadyCommitted,
}

impl ChioKernel {
    pub fn admit_governed_active_response(
        &self,
        request: &GovernedActiveResponseRequest,
    ) -> Result<GovernedActiveResponseAdmission, KernelError> {
        self.admit_governed_active_response_at(
            request,
            current_unix_timestamp(),
            current_unix_timestamp_ms(),
        )
    }

    pub(crate) fn admit_governed_active_response_at(
        &self,
        request: &GovernedActiveResponseRequest,
        now_unix_seconds: u64,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedActiveResponseAdmission, KernelError> {
        let GovernedTransactionIntentBody::ActiveResponsePlan(plan) = &request.governed_intent.body
        else {
            return Err(KernelError::GovernedTransactionDenied(
                "governed active-response admission requires an active-response intent body"
                    .to_owned(),
            ));
        };
        self.verify_capability_full_pre_admit(
            &request.operator_capability,
            request.federated_origin_kernel_id.as_deref(),
            now_unix_seconds,
        )
        .map_err(KernelError::GovernedTransactionDenied)?;
        self.check_revocation(&request.operator_capability)?;
        self.validate_delegation_admission(&request.operator_capability)?;

        let tool_request = ToolCallRequest {
            request_id: request.request_id.clone(),
            capability: request.operator_capability.clone(),
            tool_name: ACTIVE_RESPONSE_PLAN_TOOL_NAME.to_owned(),
            server_id: ACTIVE_RESPONSE_SERVER_ID.to_owned(),
            agent_id: request.operator_capability.subject.to_hex(),
            arguments: plan.canonical_plan_body.clone(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(request.governed_intent.clone()),
            approval_token: None,
            approval_tokens: request.approval_tokens.clone(),
            threshold_approval_proposal: Some(request.threshold_approval_proposal.clone()),
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: request.federated_origin_kernel_id.clone(),
        };
        self.validate_active_response_intent(
            &tool_request,
            &request.operator_capability,
            &request.governed_intent,
            now_unix_seconds,
        )?;
        let governed_intent_hash = request.governed_intent.binding_hash().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed active-response intent: {error}"
            ))
        })?;
        let verified = self.validate_threshold_approval_set(
            &tool_request,
            &request.operator_capability,
            &governed_intent_hash,
            now_unix_seconds,
        )?;
        let approval_set_hash = verified
            .body
            .approval_set_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let requirement = verified.requirement.clone();
        let approval_set = verified.body.clone();
        let reservation = VerifiedApprovalReservation {
            threshold_proposal_hash: verified.body.threshold_proposal_hash.clone(),
            approval_set_hash: approval_set_hash.clone(),
            threshold_replay: Some(verified.replay),
        };
        let (mut admission, created_by_this_attempt) = self
            .begin_durable_active_response_admission(
                request,
                &governed_intent_hash,
                trusted_now_unix_ms,
            )?;
        if let Err(error) =
            self.reserve_durable_approval_set(&mut admission, &reservation, trusted_now_unix_ms)
        {
            if created_by_this_attempt {
                let _ = self.compensate_durable_admission_before_dispatch(
                    admission.operation(),
                    serde_json::json!({"cause": "active-response-approval-reservation-failed"}),
                    trusted_now_unix_ms,
                    None,
                );
            }
            return Err(error);
        }
        Ok(GovernedActiveResponseAdmission {
            admission,
            governed_intent_hash,
            operator_capability: VerifiedActiveResponseOperatorCapability {
                capability_id: plan.operator_capability_id.clone(),
                capability_digest: plan.operator_capability_hash.clone(),
                expires_at: plan.operator_capability_expires_at,
                executor_subject: plan.executor_subject.clone(),
            },
            requirement,
            approval_set,
            approval_set_hash,
        })
    }

    pub fn commit_governed_active_response_dispatch(
        &self,
        admission: &mut GovernedActiveResponseAdmission,
    ) -> Result<GovernedActiveResponseDispatchCommit, KernelError> {
        self.commit_governed_active_response_dispatch_at(admission, current_unix_timestamp_ms())
    }

    pub(crate) fn commit_governed_active_response_dispatch_at(
        &self,
        admission: &mut GovernedActiveResponseAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedActiveResponseDispatchCommit, KernelError> {
        if admission.admission.state() == AdmissionOperationState::DispatchCommitted {
            return Ok(GovernedActiveResponseDispatchCommit::AlreadyCommitted);
        }
        self.commit_durable_dispatch(&mut admission.admission, trusted_now_unix_ms)?;
        Ok(GovernedActiveResponseDispatchCommit::Committed)
    }

    pub fn cancel_governed_active_response(
        &self,
        admission: &GovernedActiveResponseAdmission,
    ) -> Result<(), KernelError> {
        self.compensate_durable_admission_before_dispatch(
            admission.admission.operation(),
            serde_json::json!({"cause": "active-response-cancelled"}),
            current_unix_timestamp_ms(),
            None,
        )
    }
}
