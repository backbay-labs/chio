use std::fmt;
use std::sync::{Arc, Mutex};

use chio_log_redact::redacted;
use serde::Serialize;
use tracing::warn;

#[path = "admission_coordinator/terminal.rs"]
mod terminal;
pub(crate) use terminal::DurableToolReturnInput;

use super::*;
use crate::admission_operation::{
    verified_outcome_unknown_after_dispatch_projection,
    verified_released_pre_dispatch_compensation_projection, AdmissionAttachment,
    AdmissionBeginResult, AdmissionCompensationStatus, AdmissionCompletedProjection,
    AdmissionDigest, AdmissionDispatchState, AdmissionIdentifier, AdmissionMutationGuard,
    AdmissionMutationSequencer, AdmissionOperationBindingInputV1, AdmissionOperationBindingV1,
    AdmissionOperationCommand, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionProjectionContext,
    AdmissionReceiptMetadataV1, AdmissionReceiptSchema, AdmissionRequestBindingV1,
    AdmissionTerminalProjection, AdmissionTerminalReplay, AuthenticatedRequestNamespace,
    ObservationAttemptZero, PaymentTerminalEvidence, ProviderAttemptBindingV1,
    QualifiedAdmissionOperationStoreExt, QualifiedChannelTerminalAuthority, SideEffectClass,
    StoreMutationFence, VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
    LOCAL_SYSTEM_TENANT_ID,
};
use crate::budget_store::{
    BudgetAdmissionBinding, BudgetCaptureInvocationRequest, BudgetEventAuthority,
    BudgetGuaranteeLevel, BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
};
use crate::receipt_store::QualifiedAdmissionProjectionStore;
use crate::supplemental_quota::{
    canonical_revocation_set_for_verified_claim, supplemental_authorization_artifact_digest,
    verify_supplemental_quota, CanonicalRevocationSet, KernelVerifiedSupplementalQuotaClaim,
    SupplementalQuotaError, SupplementalQuotaVerificationContext,
    BROKER_CAPABILITY_EXECUTION_PROFILE,
};
use crate::tool_outcome::{
    EvaluationModeV1, EvaluationPhaseV1, FrozenEvaluationStepV1, InvocationOutputV1,
    InvocationStreamLimitsV1, PostReturnEvaluationRecordV1, PostReturnEvaluationStateV1,
    PostReturnNormalizedRequestContextV1, QualifiedDurableOutcomeAuthority,
    QualifiedToolOutcomeStore, RawInvocationOutcomeV1, ResolvedToolOutcomeV1,
    SettlementDispositionV1, ToolOutcomeError, ToolOutcomeRecordV1, ToolOutcomeStoreError,
    ToolOutcomeTerminalEvidenceV1, ToolOutcomeTransitionV1, VerifiedContractualZeroCharge,
};

const RECOVERY_LEASE_DURATION_MS: u64 = 60_000;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone)]
pub(crate) struct DurableAdmissionRuntime {
    store: Arc<dyn QualifiedAdmissionProjectionStore>,
    outcome_store: Arc<dyn QualifiedToolOutcomeStore>,
    channel_terminal_authority: Option<Arc<dyn QualifiedChannelTerminalAuthority>>,
    fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
    mutation_sequencer: AdmissionMutationSequencer,
    startup_reconciled: Arc<Mutex<bool>>,
}

impl fmt::Debug for DurableAdmissionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAdmissionRuntime")
            .field("fence", &self.fence)
            .field("claimant_id", &self.claimant_id)
            .field(
                "channel_terminal_authority",
                &self.channel_terminal_authority.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl DurableAdmissionRuntime {
    pub(crate) fn new(
        store: Arc<dyn QualifiedAdmissionProjectionStore>,
        outcome_store: Arc<dyn QualifiedToolOutcomeStore>,
        fence: StoreMutationFence,
        kernel_id: &str,
    ) -> Result<Self, crate::admission_operation::AdmissionOperationError> {
        AdmissionIdentifier::try_new("store_uuid", fence.store_uuid.clone())?;
        AdmissionIdentifier::try_new("store_lease_id", fence.lease_id.clone())?;
        if fence.owner_epoch == 0 || fence.owner_epoch > I_JSON_MAX_SAFE_INTEGER {
            return Err(crate::admission_operation::AdmissionOperationError::InvalidStoreFence);
        }
        let claimant_id =
            AdmissionIdentifier::try_new("admission_claimant_id", format!("kernel:{kernel_id}"))?;
        Ok(Self {
            store,
            outcome_store,
            channel_terminal_authority: None,
            mutation_sequencer: AdmissionMutationSequencer::for_fence(&fence)?,
            startup_reconciled: Arc::new(Mutex::new(false)),
            fence,
            claimant_id,
        })
    }

    fn lock_mutations(&self) -> Result<AdmissionMutationGuard<'_>, KernelError> {
        self.mutation_sequencer
            .lock()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }

    pub(super) fn set_channel_terminal_authority(
        &mut self,
        authority: Arc<dyn QualifiedChannelTerminalAuthority>,
    ) {
        self.channel_terminal_authority = Some(authority);
    }

    fn refresh_trusted_time(&self, requested_unix_ms: u64) -> u64 {
        requested_unix_ms.max(current_unix_timestamp_ms()).max(1)
    }

    fn authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: self.fence.store_uuid.clone(),
            lease_id: self.fence.lease_id.clone(),
            lease_epoch: self.fence.owner_epoch,
        }
    }

    fn qualified_terminal_records(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(ToolOutcomeRecordV1, PostReturnEvaluationRecordV1), ToolOutcomeError> {
        let unavailable =
            || ToolOutcomeError::ReleaseAuthorityUnavailable("durable terminal outcome store");
        let outcome = self
            .outcome_store
            .lookup_by_operation(operation.binding().operation_id())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let evaluation = self
            .outcome_store
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        Ok((outcome, evaluation))
    }
}

impl QualifiedDurableOutcomeAuthority for DurableAdmissionRuntime {
    fn verify_terminal_outcome(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<ToolOutcomeTerminalEvidenceV1, ToolOutcomeError> {
        let (outcome, evaluation) = self.qualified_terminal_records(operation)?;
        ToolOutcomeTerminalEvidenceV1::from_records(operation, context, &outcome, &evaluation)
    }

    fn verify_contractual_zero_charge(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedContractualZeroCharge, ToolOutcomeError> {
        let (outcome, evaluation) = self.qualified_terminal_records(operation)?;
        VerifiedContractualZeroCharge::from_records(operation, context, &outcome, &evaluation)
    }
}

pub(crate) struct DurableToolAdmission {
    pub(super) operation: AdmissionOperationV1,
    aggregate_quota: Option<BudgetInvocationQuota>,
    supplemental_quota: Option<KernelVerifiedSupplementalQuotaClaim>,
}

impl DurableToolAdmission {
    pub(crate) fn operation(&self) -> &AdmissionOperationV1 {
        &self.operation
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.operation.binding().operation_id().as_str()
    }

    pub(crate) fn budget_hold_id(&self, grant_index: usize) -> String {
        format!("admission-budget:{}:{grant_index}", self.operation_id())
    }

    pub(crate) fn budget_authorize_event_id(&self, grant_index: usize) -> String {
        format!("{}:authorize", self.budget_hold_id(grant_index))
    }

    pub(crate) fn permits_grant(&self, grant_index: usize) -> bool {
        self.operation
            .budget_hold_id()
            .is_none_or(|hold_id| hold_id.as_str() == self.budget_hold_id(grant_index))
    }

    pub(crate) fn permits_matching_grant(&self, matching: &MatchingGrant<'_>) -> bool {
        self.permits_grant(matching.index)
            && if self.requires_payment() {
                matching
                    .grant
                    .max_cost_per_invocation
                    .as_ref()
                    .is_some_and(|amount| amount.units != 0)
            } else {
                matching.grant.max_cost_per_invocation.is_none()
                    && matching.grant.max_total_cost.is_none()
            }
    }

    pub(crate) fn can_resume_captured_hold(&self) -> bool {
        self.operation.state() == AdmissionOperationState::CapturePending
    }

    pub(crate) fn requires_payment(&self) -> bool {
        self.operation.binding().participant_requirements().payment
    }

    pub(crate) fn state(&self) -> AdmissionOperationState {
        self.operation.state()
    }

    pub(crate) fn supplemental_quota(&self) -> Option<&KernelVerifiedSupplementalQuotaClaim> {
        self.supplemental_quota.as_ref()
    }

    pub(crate) fn aggregate_quota(&self) -> Option<&BudgetInvocationQuota> {
        self.aggregate_quota.as_ref()
    }
}

#[derive(Serialize)]
struct ImmutableToolAdmissionRequest<'a> {
    schema: &'static str,
    server_id: &'a str,
    tool_name: &'a str,
    agent_id: &'a str,
    arguments: &'a serde_json::Value,
    governed_intent: &'a Option<chio_core::capability::governance::GovernedTransactionIntent>,
    model_metadata: &'a Option<chio_core::capability::scope::ModelMetadata>,
    federated_origin_kernel_id: &'a Option<String>,
    matching_grants: Vec<ImmutableMatchingGrant<'a>>,
    post_return_steps: &'a [FrozenEvaluationStepV1],
}

#[derive(Serialize)]
struct ImmutableActiveResponseAdmissionRequest<'a> {
    schema: &'static str,
    governed_intent: &'a chio_core::capability::governance::GovernedTransactionIntent,
    federated_origin_kernel_id: &'a Option<String>,
    governed_intent_hash: &'a str,
}

#[derive(Serialize)]
struct ImmutableMatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
}

struct DurablePostReturnPlan {
    hook_identities: Vec<crate::post_invocation::PostInvocationHookIdentity>,
    frozen_steps: Vec<FrozenEvaluationStepV1>,
}

fn immutable_tool_admission_request_hash(
    request: &ToolCallRequest,
    matching_grants: &[MatchingGrant<'_>],
    post_return_plan: &DurablePostReturnPlan,
) -> Result<AdmissionDigest, KernelError> {
    let immutable_request = ImmutableToolAdmissionRequest {
        schema: "chio.tool-admission-request.v1",
        server_id: &request.server_id,
        tool_name: &request.tool_name,
        agent_id: &request.agent_id,
        arguments: &request.arguments,
        governed_intent: &request.governed_intent,
        model_metadata: &request.model_metadata,
        federated_origin_kernel_id: &request.federated_origin_kernel_id,
        matching_grants: matching_grants
            .iter()
            .map(|matching| ImmutableMatchingGrant {
                index: matching.index,
                grant: matching.grant,
            })
            .collect(),
        post_return_steps: &post_return_plan.frozen_steps,
    };
    admission_digest("immutable_request_hash", &immutable_request)
}

impl ChioKernel {
    pub(crate) fn load_durable_admission_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(None);
        };
        runtime
            .store
            .load_chio_receipt(receipt_id)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }

    pub fn reconcile_durable_admission_receipt_projections(&self) -> Result<usize, KernelError> {
        const PAGE_LIMIT: usize = 256;

        if self.receipt_store.is_none() {
            return Ok(0);
        }
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let mut after_receipt_id = None;
        let mut reconciled = 0_usize;
        loop {
            let page = runtime
                .store
                .list_admission_receipts_after(after_receipt_id.as_deref(), PAGE_LIMIT)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            if page.is_empty() {
                return Ok(reconciled);
            }
            if page.len() > PAGE_LIMIT {
                return Err(KernelError::DurableAdmission(
                    "admission receipt store exceeded the requested page limit".to_owned(),
                ));
            }
            let mut previous = after_receipt_id.as_deref();
            for receipt in &page {
                if previous.is_some_and(|cursor| receipt.id.as_str() <= cursor) {
                    return Err(KernelError::DurableAdmission(
                        "admission receipt store returned a non-advancing page".to_owned(),
                    ));
                }
                self.materialize_durable_admission_receipt(receipt)?;
                previous = Some(receipt.id.as_str());
            }
            reconciled = reconciled.checked_add(page.len()).ok_or_else(|| {
                KernelError::DurableAdmission("admission receipt count overflow".to_owned())
            })?;
            after_receipt_id = page.last().map(|receipt| receipt.id.clone());
        }
    }

    pub fn reconcile_durable_admission_startup(&self) -> Result<usize, KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let mut reconciled = runtime.startup_reconciled.lock().map_err(|_| {
            KernelError::DurableAdmission("startup reconciliation lock is poisoned".to_owned())
        })?;
        if *reconciled {
            return Ok(0);
        }
        let operation_count = self.reconcile_recoverable_admissions()?;
        let receipt_count = self.reconcile_durable_admission_receipt_projections()?;
        let total = operation_count.checked_add(receipt_count).ok_or_else(|| {
            KernelError::DurableAdmission("startup reconciliation count overflow".to_owned())
        })?;
        *reconciled = true;
        Ok(total)
    }

    pub fn reconcile_recoverable_admissions(&self) -> Result<usize, KernelError> {
        const PAGE_LIMIT: usize = 256;

        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let trusted_now_unix_ms = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let mut reconciled = 0_usize;
        // An operation that cannot be reconciled is recorded and skipped rather
        // than abandoning the sweep, so one wedged operation cannot hold up every
        // other recoverable operation. The first failure is still returned once
        // the sweep finishes, so callers keep failing closed on it.
        let mut deferred_failure: Option<KernelError> = None;
        loop {
            let recoverable = runtime
                .store
                .list_recoverable(trusted_now_unix_ms, PAGE_LIMIT)
                .map_err(durable_store_error)?;
            if recoverable.len() > PAGE_LIMIT {
                return Err(KernelError::DurableAdmission(
                    "admission recovery store exceeded the requested page limit".to_owned(),
                ));
            }
            if recoverable.is_empty() {
                break;
            }
            let reconciled_before_page = reconciled;
            for operation in recoverable {
                match operation.state() {
                    AdmissionOperationState::DispatchCommitted => {
                        if let Err(error) = self.terminalize_dispatch_committed_admission(
                            &operation,
                            trusted_now_unix_ms,
                        ) {
                            warn!(
                                operation_id = %operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_terminalization_unresolved",
                                "failed to terminalize a dispatch-committed admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    AdmissionOperationState::Prepared
                    | AdmissionOperationState::BrokerAttemptRegistered
                    | AdmissionOperationState::BudgetAuthorized
                    | AdmissionOperationState::ApprovalReserved
                    | AdmissionOperationState::ReadyToDispatch
                    | AdmissionOperationState::CapturePending => {
                        // One operation that cannot be compensated must not abandon
                        // the rest of the page: it stays recoverable for a later
                        // sweep, and the remaining operations still reconcile.
                        if let Err(error) = self.compensate_durable_admission_before_dispatch(
                            &operation,
                            serde_json::json!({
                                "authority": "startup-recovery",
                                "cause": "no-authoritative-budget-participant"
                            }),
                            trusted_now_unix_ms,
                        ) {
                            warn!(
                                operation_id = %operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_compensation_unresolved",
                                "failed to compensate a recoverable admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    AdmissionOperationState::ApprovalRequired => {
                        deferred_failure.get_or_insert_with(|| {
                            KernelError::DurableAdmission(
                                "admission recovery store returned a quiescent approval-required operation"
                                    .to_owned(),
                            )
                        });
                    }
                    AdmissionOperationState::Finalizing => {
                        let mut admission = DurableToolAdmission {
                            operation,
                            aggregate_quota: None,
                            supplemental_quota: None,
                        };
                        let tool_return = self.load_durable_tool_return(&admission)?;
                        let Some(request) =
                            tool_return.recovery_request().map_err(tool_outcome_error)?
                        else {
                            self.claim_admission_recovery(
                                &admission.operation,
                                trusted_now_unix_ms,
                            )?;
                            continue;
                        };
                        if let Err(error) = self.finalize_durable_tool_return(
                            &mut admission,
                            &request,
                            &tool_return,
                        ) {
                            warn!(
                                operation_id = %admission.operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_finalization_unresolved",
                                "failed to finalize a recoverable admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    _ => {
                        self.claim_admission_recovery(&operation, trusted_now_unix_ms)?;
                    }
                }
            }
            if reconciled == reconciled_before_page {
                break;
            }
        }
        if let Some(error) = deferred_failure {
            return Err(error);
        }
        Ok(reconciled)
    }

    /// Terminalize a dispatch-committed admission whose outcome is unknown.
    ///
    /// Refuses when a durable tool outcome already exists, so this is a no-op on
    /// an operation whose return did land. Used both by startup recovery and by
    /// the post-dispatch drop path, where the evaluation future was cancelled
    /// after the dispatch commit and would otherwise strand the operation until
    /// the next process restart.
    pub(crate) fn terminalize_dispatch_committed_admission(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        if runtime
            .outcome_store
            .lookup_by_operation(operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .is_some()
        {
            return Err(KernelError::DurableAdmission(
                "dispatch-committed admission already has a durable tool outcome".to_owned(),
            ));
        }
        let lease = self.claim_admission_recovery(operation, trusted_now_unix_ms)?;
        let context = AdmissionProjectionContext {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.binding().request_id().clone(),
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        let projection = verified_outcome_unknown_after_dispatch_projection(operation, context)?;
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if terminal.operation_id != *operation.binding().operation_id()
            || terminal.state != AdmissionOperationState::OutcomeUnknownAfterDispatch
        {
            return Err(KernelError::DurableAdmission(
                "admission recovery committed a different terminal operation".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn begin_durable_tool_admission(
        &self,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        trusted_now_unix_ms: u64,
    ) -> Result<Option<DurableToolAdmission>, KernelError> {
        let aggregate_quota =
            self.verify_aggregate_quota_for_admission(request, trusted_now_unix_ms / 1_000)?;
        let cumulative_matching_grant_count = matching_grants
            .iter()
            .filter(|matching| {
                matching.grant.constraints.iter().any(|constraint| {
                    matches!(
                        constraint,
                        Constraint::RequireCumulativeApprovalAbove { .. }
                    )
                })
            })
            .count();
        // Only a grant that can serve this request may force the structured path. An
        // unrelated cumulative grant elsewhere in the capability must not withdraw an
        // otherwise exempt call.
        let requires_structured_admission = aggregate_quota.is_some()
            || request.supplemental_authorization.is_some()
            || cumulative_matching_grant_count != 0;
        if request.supplemental_authorization.is_some()
            && self.supplemental_quota_verifier.is_none()
        {
            return Err(KernelError::DurableAdmission(
                SupplementalQuotaError::MissingVerifier.to_string(),
            ));
        }
        let effect_class = if matching_grants.iter().all(|matching| {
            matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
        }) {
            SideEffectClass::Monetary
        } else if self
            .tool_servers
            .get(&request.server_id)
            .is_some_and(|server| server.tool_is_read_only(&request.tool_name))
        {
            SideEffectClass::ReadOnly
        } else {
            SideEffectClass::SideEffecting
        };
        if !self.durable_admission_mode.covers(effect_class) {
            if requires_structured_admission {
                return Err(KernelError::DurableAdmission(
                    "aggregate, cumulative, and supplemental authorization requires durable admission coverage"
                        .to_string(),
                ));
            }
            return Ok(None);
        }
        self.durable_stream_limits()?;
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            if self.config.allow_ephemeral_receipt_log && !requires_structured_admission {
                return Ok(None);
            }
            return Err(KernelError::DurableAdmission(
                "no qualified admission operation store is configured".to_string(),
            ));
        };
        let payment_required = effect_class == SideEffectClass::Monetary;
        if payment_required {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable monetary admission requires a qualified payment adapter".to_owned(),
                )
            })?;
            if adapter.rail_id().is_empty()
                || adapter.rail_id() == "unspecified"
                || adapter.rail_mode().is_none()
            {
                return Err(KernelError::DurableAdmission(
                    "durable monetary admission requires a recoverable payment rail identity"
                        .to_owned(),
                ));
            }
            // An output-digest grant is honored only after the tool returns,
            // which is past the prepay point on a final-settlement rail. Refuse
            // to begin a durable operation for it here, before any hold is
            // placed, rather than deny mid-flight and unwind a live payment.
            let requires_output_digest = matching_grants.iter().any(|matching| {
                matching
                    .grant
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, Constraint::OutputDigestSha256(_)))
            });
            if requires_output_digest
                && adapter.rail_mode() != Some(crate::payment::PaymentRailMode::ReversibleHold)
            {
                return Err(KernelError::DurableAdmission(
                    "output-digest delivery requires a reversible-hold payment rail".to_owned(),
                ));
            }
        }
        if self.execution_nonce_config.is_some() {
            return Err(KernelError::DurableAdmission(
                "durable execution nonces require an atomic admission participant".to_owned(),
            ));
        }
        let projection_capabilities = runtime.store.admission_projection_capabilities();
        let observer_required = self.settlement_observer.is_some();
        if !projection_capabilities.operation_terminal
            || !projection_capabilities.tool_outcome
            || (payment_required && !projection_capabilities.payment_terminal)
            || (observer_required && !projection_capabilities.observation_attempt_zero)
        {
            return Err(KernelError::DurableAdmission(
                "admission store lacks atomic terminal tool-outcome projection support".to_owned(),
            ));
        }
        let post_return_plan = self.durable_post_return_plan()?;

        let supplemental_authorization_artifact_digest = request
            .supplemental_authorization
            .as_ref()
            .map(|authorization| {
                supplemental_authorization_artifact_digest(
                    authorization.signed_extension.as_bytes(),
                )
            });
        let immutable_request_hash =
            immutable_tool_admission_request_hash(request, matching_grants, &post_return_plan)?;
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "tool action parameters are invalid: {error}"
                ))
            })?;
        let action_parameter_hash =
            AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?;
        let authorization_capability_hash =
            admission_digest("authorization_capability_hash", &request.capability)?;
        let policy_hash = AdmissionDigest::try_new("policy_hash", self.config.policy_hash.clone())
            .map_err(|_| {
                KernelError::DurableAdmission(
                    "durable admission requires a canonical SHA-256 policy hash".to_owned(),
                )
            })?;
        if cumulative_matching_grant_count != 0
            && cumulative_matching_grant_count != matching_grants.len()
        {
            return Err(KernelError::DurableAdmission(
                "matching grants disagree on cumulative approval requirements".to_owned(),
            ));
        }
        let matching_grant_requires_cumulative_approval = cumulative_matching_grant_count != 0;
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            approval: matching_grant_requires_cumulative_approval
                || request.approval_token.is_some()
                || !request.approval_tokens.is_empty(),
            payment: payment_required,
            observation_attempt_zero: observer_required,
            ..AdmissionParticipantRequirements::NONE
        };
        let coordinator_authority_id = AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            runtime.fence.store_uuid.clone(),
        )?;
        let namespace = match self.receipt_tenant_id_for_request(Some(&request.request_id)) {
            Some(tenant_id) => AuthenticatedRequestNamespace::from_authentication_context(
                coordinator_authority_id,
                tenant_id,
            )?,
            None => AuthenticatedRequestNamespace::for_local_system(coordinator_authority_id)?,
        };
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace,
            request_id: AdmissionIdentifier::try_new("request_id", request.request_id.clone())?,
            capability_id: AdmissionIdentifier::try_new(
                "capability_id",
                request.capability.id.clone(),
            )?,
            authorization_capability_hash,
            request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
                immutable_request_hash,
                action_parameter_hash,
                requirements,
            )?,
            policy_hash,
            effect_class,
        })?;
        let supplemental_quota = self.verify_supplemental_quota_for_admission(
            request,
            &binding,
            trusted_now_unix_ms / 1000,
        )?;
        let prepared = AdmissionOperationV1::prepare(binding, runtime.fence.owner_epoch)?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let operation = match runtime
            .store
            .begin(&prepared, &runtime.fence, trusted_now_unix_ms)
            .map_err(durable_store_error)?
        {
            AdmissionBeginResult::Created(operation) => operation,
            AdmissionBeginResult::ExactReplay { operation, .. }
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                        | AdmissionOperationState::ApprovalRequired
                        | AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                        | AdmissionOperationState::Finalizing
                        | AdmissionOperationState::Completed
                        | AdmissionOperationState::DeniedAfterDelivery
                ) =>
            {
                operation
            }
            AdmissionBeginResult::ExactReplay { operation, .. } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request replay is retained in state {:?}",
                    operation.state()
                )));
            }
            AdmissionBeginResult::Conflict {
                existing_operation_id,
            } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request id conflicts with retained operation {}",
                    existing_operation_id.as_str()
                )));
            }
        };
        let expected_operation_id = operation.binding().operation_id().as_str();
        let expected_attempt_id = format!("attempt:{expected_operation_id}");
        let expected_transport_id = format!("kernel-tool-server:{}", request.server_id);
        let operation = match operation.state() {
            AdmissionOperationState::Prepared => {
                let expected_attempt = ProviderAttemptBindingV1 {
                    operation_id: expected_operation_id.to_owned(),
                    attempt_id: expected_attempt_id,
                    transport_id: expected_transport_id,
                    transport_key_epoch: runtime.fence.owner_epoch,
                };
                expected_attempt.validate().map_err(|error| {
                    KernelError::DurableAdmission(format!(
                        "provider attempt binding is invalid: {error}"
                    ))
                })?;
                let mut attachments = Vec::with_capacity(2);
                if let Some(digest) = supplemental_authorization_artifact_digest.as_ref() {
                    attachments.push(AdmissionAttachment::SupplementalAuthorizationDigest(
                        AdmissionDigest::try_new(
                            "supplemental_authorization_digest",
                            digest.clone(),
                        )?,
                    ));
                }
                attachments.push(AdmissionAttachment::BrokerAttempt(expected_attempt));
                self.apply_admission_command(
                    operation,
                    attachments,
                    AdmissionOperationState::BrokerAttemptRegistered,
                    trusted_now_unix_ms,
                )?
            }
            _ if operation.provider_attempt().is_some_and(|attempt| {
                attempt.operation_id == expected_operation_id
                    && attempt.attempt_id == expected_attempt_id
                    && attempt.transport_id == expected_transport_id
                    && attempt.transport_key_epoch <= operation.coordinator_lease_epoch()
            }) =>
            {
                operation
            }
            _ => {
                return Err(KernelError::DurableAdmission(
                    "retained provider attempt does not match this dispatch".to_string(),
                ));
            }
        };
        if operation
            .supplemental_authorization_digest()
            .map(AdmissionDigest::as_str)
            != supplemental_authorization_artifact_digest.as_deref()
        {
            return Err(KernelError::DurableAdmission(
                "retained supplemental authorization digest does not match request".to_string(),
            ));
        }
        Ok(Some(DurableToolAdmission {
            operation,
            aggregate_quota,
            supplemental_quota,
        }))
    }

    pub(crate) fn begin_durable_active_response_admission(
        &self,
        request: &crate::governed_active_response::GovernedActiveResponseRequest,
        governed_intent_hash: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<(DurableToolAdmission, bool), KernelError> {
        let runtime = self.durable_runtime()?;
        if !runtime
            .store
            .admission_projection_capabilities()
            .operation_terminal
        {
            return Err(KernelError::DurableAdmission(
                "active-response admission store lacks atomic terminal projection support"
                    .to_owned(),
            ));
        }
        let immutable_request_hash = admission_digest(
            "immutable_request_hash",
            &ImmutableActiveResponseAdmissionRequest {
                schema: "chio.governed-active-response-admission.v1",
                governed_intent: &request.governed_intent,
                federated_origin_kernel_id: &request.federated_origin_kernel_id,
                governed_intent_hash,
            },
        )?;
        let authorization_capability_hash = admission_digest(
            "authorization_capability_hash",
            &request.operator_capability,
        )?;
        let policy_hash = AdmissionDigest::try_new("policy_hash", self.config.policy_hash.clone())
            .map_err(|_| {
                KernelError::DurableAdmission(
                    "durable admission requires a canonical SHA-256 policy hash".to_owned(),
                )
            })?;
        let requirements = AdmissionParticipantRequirements {
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let coordinator_authority_id = AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            runtime.fence.store_uuid.clone(),
        )?;
        let namespace = match self.receipt_tenant_id_for_request(Some(&request.request_id)) {
            Some(tenant_id) => AuthenticatedRequestNamespace::from_authentication_context(
                coordinator_authority_id,
                tenant_id,
            )?,
            None => AuthenticatedRequestNamespace::for_local_system(coordinator_authority_id)?,
        };
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::GovernedActiveResponse,
            namespace,
            request_id: AdmissionIdentifier::try_new("request_id", request.request_id.clone())?,
            capability_id: AdmissionIdentifier::try_new(
                "capability_id",
                request.operator_capability.id.clone(),
            )?,
            authorization_capability_hash,
            request_binding: AdmissionRequestBindingV1::new(immutable_request_hash, requirements)?,
            policy_hash,
            effect_class: SideEffectClass::SideEffecting,
        })?;
        let prepared = AdmissionOperationV1::prepare(binding, runtime.fence.owner_epoch)?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let (operation, created_by_this_attempt) = match runtime
            .store
            .begin(&prepared, &runtime.fence, trusted_now_unix_ms)
            .map_err(durable_store_error)?
        {
            AdmissionBeginResult::Created(operation) => (operation, true),
            AdmissionBeginResult::ExactReplay { operation, .. }
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::DispatchCommitted
                ) =>
            {
                (operation, false)
            }
            AdmissionBeginResult::ExactReplay { operation, .. } => {
                return Err(KernelError::DurableAdmission(format!(
                    "active-response request replay is retained in state {:?}",
                    operation.state()
                )));
            }
            AdmissionBeginResult::Conflict {
                existing_operation_id,
            } => {
                return Err(KernelError::DurableAdmission(format!(
                    "active-response request id conflicts with retained operation {}",
                    existing_operation_id.as_str()
                )));
            }
        };
        Ok((
            DurableToolAdmission {
                operation,
                aggregate_quota: None,
                supplemental_quota: None,
            },
            created_by_this_attempt,
        ))
    }

    fn durable_post_return_plan(&self) -> Result<DurablePostReturnPlan, KernelError> {
        let hook_identities = self
            .post_invocation_pipeline
            .durable_identities()
            .map_err(KernelError::DurableAdmission)?;
        let mut frozen_steps = Vec::with_capacity(hook_identities.len() + 1);
        frozen_steps.push(FrozenEvaluationStepV1 {
            phase: EvaluationPhaseV1::OutputGuard,
            position: 0,
            component_id: AdmissionIdentifier::try_new(
                "component_id",
                "kernel-output-materialization",
            )?,
            component_version: AdmissionIdentifier::try_new("component_version", "v1")?,
            implementation_digest: AdmissionDigest::try_new(
                "implementation_digest",
                sha256_hex(b"chio.kernel-output-materialization.v1"),
            )?,
            mode: EvaluationModeV1::Pure,
        });
        for (index, identity) in hook_identities.iter().enumerate() {
            let position = u32::try_from(index + 1).map_err(|_| {
                KernelError::DurableAdmission(
                    "post-invocation pipeline has too many durable steps".to_owned(),
                )
            })?;
            frozen_steps.push(FrozenEvaluationStepV1 {
                phase: EvaluationPhaseV1::OutputGuard,
                position,
                component_id: AdmissionIdentifier::try_new(
                    "component_id",
                    identity.component_id(),
                )?,
                component_version: AdmissionIdentifier::try_new(
                    "component_version",
                    identity.component_version(),
                )?,
                implementation_digest: AdmissionDigest::try_new(
                    "implementation_digest",
                    identity.implementation_digest(),
                )?,
                mode: EvaluationModeV1::Pure,
            });
        }
        Ok(DurablePostReturnPlan {
            hook_identities,
            frozen_steps,
        })
    }

    fn verify_supplemental_quota_for_admission(
        &self,
        request: &ToolCallRequest,
        binding: &AdmissionOperationBindingV1,
        now: u64,
    ) -> Result<Option<KernelVerifiedSupplementalQuotaClaim>, KernelError> {
        let Some(authorization) = request.supplemental_authorization.as_ref() else {
            return Ok(None);
        };
        let runtime = self.supplemental_quota_verifier.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(SupplementalQuotaError::MissingVerifier.to_string())
        })?;

        #[derive(Serialize)]
        struct ToolDestination<'a> {
            server_id: &'a str,
            tool_name: &'a str,
        }

        let normalized_destination = String::from_utf8(
            canonical_json_bytes(&ToolDestination {
                server_id: &request.server_id,
                tool_name: &request.tool_name,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let capability_digest = sha256_hex(
            &canonical_json_bytes(&request.capability)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        );
        let arguments_hash = sha256_hex(
            &canonical_json_bytes(&request.arguments)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        );
        let mut negotiated_features = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::DurableAdmission)?;
        if request.federated_origin_kernel_id.is_none() {
            negotiated_features
                .features
                .insert(BROKER_CAPABILITY_EXECUTION_PROFILE.to_string(), true);
        }
        let context = SupplementalQuotaVerificationContext {
            capability_id: request.capability.id.clone(),
            capability_digest,
            request_namespace_digest: binding.request_namespace_digest().as_str().to_string(),
            operation_id: binding.operation_id().as_str().to_string(),
            subject: request.capability.subject.clone(),
            request_id: request.request_id.clone(),
            normalized_destination,
            arguments_hash,
            negotiated_profile: BROKER_CAPABILITY_EXECUTION_PROFILE.to_string(),
            negotiated_features,
            verifier_binding: runtime.binding().clone(),
        };
        verify_supplemental_quota(
            Some(runtime.verifier()),
            authorization.signed_extension.as_bytes(),
            &context,
            now,
        )
        .map(Some)
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }

    fn verify_aggregate_quota_for_admission(
        &self,
        request: &ToolCallRequest,
        now: u64,
    ) -> Result<Option<BudgetInvocationQuota>, KernelError> {
        use chio_core::capability::aggregate_invocation::{
            verify_aggregate_invocation_budget, AggregateInvocationScope,
        };

        if request.capability.aggregate_invocation_budget.is_none() {
            return Ok(None);
        }
        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::DurableAdmission)?;
        let direct_root = self
            .negotiated_capability_root(&request.capability, &peer)
            .map_err(KernelError::DurableAdmission)?;
        let verified = verify_aggregate_invocation_budget(
            &request.capability,
            &self.trusted_issuer_keys(),
            direct_root.as_ref(),
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
        .ok_or_else(|| {
            KernelError::DurableAdmission(
                "aggregate invocation budget did not produce a verified quota".to_string(),
            )
        })?;
        let profile = match verified.scope {
            AggregateInvocationScope::Capability => {
                BudgetQuotaProfile::AggregateCapabilityInvocation
            }
            AggregateInvocationScope::DelegationFamily => {
                BudgetQuotaProfile::AggregateFamilyInvocation
            }
        };
        Ok(Some(BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile,
                owner_id: verified.owner_id,
                grant_index: None,
            },
            max_invocations: verified.max_invocations,
        }))
    }

    pub(crate) fn durable_budget_binding(
        &self,
        admission: &DurableToolAdmission,
        capability: &CapabilityToken,
    ) -> Result<(BudgetAdmissionBinding, BudgetEventAuthority), KernelError> {
        let runtime = self.durable_runtime()?;
        let ancestor_capability_ids = capability
            .delegation_chain
            .iter()
            .map(|link| link.capability_id.clone())
            .collect::<Vec<_>>();
        let revocation_set = match admission.supplemental_quota() {
            Some(claim) => canonical_revocation_set_for_verified_claim(
                &capability.id,
                &ancestor_capability_ids,
                claim,
            ),
            None => {
                let mut revocation_ids = Vec::with_capacity(ancestor_capability_ids.len() + 1);
                revocation_ids.push(capability.id.clone());
                revocation_ids.extend(ancestor_capability_ids);
                CanonicalRevocationSet::canonicalize(revocation_ids)
            }
        }
        .map_err(|error| {
            KernelError::DurableAdmission(format!("capability revocation set is invalid: {error}"))
        })?;
        let supplemental = admission.supplemental_quota();
        let last_observed_revocation = if supplemental.is_some() {
            let observation = self
                .revocation_store
                .observe_revocation(&capability.id)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            if observation.revoked {
                return Err(KernelError::DurableAdmission(
                    "supplemental authorization leaf capability is revoked".to_string(),
                ));
            }
            let commit = observation.commit.ok_or_else(|| {
                KernelError::DurableAdmission(
                    "supplemental authorization requires atomic revocation observation".to_string(),
                )
            })?;
            if !matches!(
                commit.guarantee_level,
                BudgetGuaranteeLevel::SingleNodeAtomic | BudgetGuaranteeLevel::HaLinearizable
            ) {
                return Err(KernelError::DurableAdmission(
                    "supplemental authorization revocation observation is not atomic".to_string(),
                ));
            }
            Some(commit)
        } else {
            None
        };
        let authorization_artifact_digests = supplemental
            .map(|claim| vec![claim.authorization_artifact_digest().to_string()])
            .unwrap_or_default();
        Ok((
            BudgetAdmissionBinding {
                operation_id: admission.operation_id().to_string(),
                revocation_set,
                authorization_artifact_digests,
                last_observed_revocation,
                supplemental_verifier_id: supplemental
                    .map(|claim| claim.verifier_binding().verifier_identity.clone()),
                supplemental_verifier_config_digest: supplemental
                    .map(|claim| claim.verifier_binding().configuration_digest.clone()),
                supplemental_authorization_artifact_digest: supplemental
                    .map(|claim| claim.authorization_artifact_digest().to_string()),
                supplemental_authorization_expires_at: supplemental
                    .map(KernelVerifiedSupplementalQuotaClaim::expires_at),
            },
            runtime.authority(),
        ))
    }

    pub(crate) fn authorize_durable_budget_hold(
        &self,
        admission: &mut DurableToolAdmission,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<crate::payment::PaymentJournalRecord>,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let expected = admission.operation.clone();
        let hold_id = request.hold_id.clone().ok_or_else(|| {
            KernelError::DurableAdmission(
                "combined durable authorization omitted its budget hold identity".to_owned(),
            )
        })?;
        if request.authority.as_ref() != Some(&runtime.authority()) {
            return Err(KernelError::DurableAdmission(
                "combined durable authorization authority does not match the admission fence"
                    .to_owned(),
            ));
        }
        let recovery_lease =
            self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let authorization = runtime
            .store
            .authorize_budget_and_commit_admission(
                &admission.operation,
                &recovery_lease,
                request,
                payment_journal,
                None,
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if authorization.operation.binding() != expected.binding() {
            return Err(KernelError::DurableAdmission(
                "combined durable authorization changed the immutable operation binding".to_owned(),
            ));
        }
        match &authorization.decision {
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_) => {
                if !matches!(
                    authorization.operation.state(),
                    AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                        | AdmissionOperationState::DispatchCommitted
                        | AdmissionOperationState::Finalizing
                        | AdmissionOperationState::Completed
                ) || authorization
                    .operation
                    .budget_hold_id()
                    .is_none_or(|bound| bound.as_str() != hold_id)
                {
                    return Err(KernelError::DurableAdmission(
                        "combined durable authorization returned an unbound operation".to_owned(),
                    ));
                }
            }
            crate::budget_store::BudgetAuthorizeHoldDecision::Denied(_)
            | crate::budget_store::BudgetAuthorizeHoldDecision::ApprovalRequired(_)
                if authorization.operation == expected => {}
            crate::budget_store::BudgetAuthorizeHoldDecision::AlreadyCaptured(_)
                if authorization.operation.state() == AdmissionOperationState::CapturePending
                    && authorization
                        .operation
                        .budget_hold_id()
                        .is_some_and(|bound| bound.as_str() == hold_id) => {}
            _ => {
                return Err(KernelError::DurableAdmission(format!(
                    "combined durable authorization returned incompatible operation state {:?}",
                    authorization.operation.state()
                )));
            }
        }
        admission.operation = authorization.operation;
        Ok(authorization.decision)
    }

    pub(crate) fn reserve_durable_approval_set(
        &self,
        admission: &mut DurableToolAdmission,
        verified: &VerifiedApprovalReservation,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let proposal_hash = AdmissionDigest::try_new(
            "threshold_proposal_hash",
            verified.threshold_proposal_hash.clone(),
        )?;
        let approval_set_hash =
            AdmissionDigest::try_new("approval_set_hash", verified.approval_set_hash.clone())?;
        if matches!(
            admission.operation.state(),
            AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
        ) {
            let proposal_matches =
                admission.operation.threshold_proposal_hash() == Some(&proposal_hash);
            let set_matches = admission.operation.approval_set_hash() == Some(&approval_set_hash);
            if proposal_matches && set_matches {
                return Ok(());
            }
            return Err(KernelError::DurableAdmission(
                "retained approval reservation does not match the verified approval set".to_owned(),
            ));
        }
        let required_source = match admission.operation.binding().kind() {
            AdmissionOperationKind::ToolDispatch => AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationKind::GovernedActiveResponse => AdmissionOperationState::Prepared,
            AdmissionOperationKind::GovernedEconomicMutation => {
                return Err(KernelError::DurableAdmission(
                    "economic mutation admission does not accept threshold approval sets"
                        .to_owned(),
                ));
            }
        };
        if admission.operation.state() != required_source {
            return Err(KernelError::DurableAdmission(format!(
                "approval reservation requires {required_source:?}, found {:?}",
                admission.operation.state()
            )));
        }
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let attachments = vec![
            AdmissionAttachment::ThresholdProposalHash(proposal_hash),
            AdmissionAttachment::ApprovalSetHash(approval_set_hash),
        ];
        admission.operation = if let Some(replay) = verified.threshold_replay.as_ref() {
            let expires_at_unix_ms = trusted_now_unix_ms
                .checked_add(RECOVERY_LEASE_DURATION_MS)
                .ok_or_else(|| {
                    KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
                })?;
            let lease = runtime
                .store
                .claim_recovery(
                    admission.operation.binding().operation_id(),
                    admission.operation.version(),
                    &runtime.claimant_id,
                    trusted_now_unix_ms,
                    expires_at_unix_ms,
                    &runtime.fence,
                )
                .map_err(durable_store_error)?;
            let command = AdmissionOperationCommand::new(
                admission.operation.binding().operation_id().clone(),
                admission.operation.version(),
                lease,
                attachments,
                Some(AdmissionOperationState::ApprovalReserved),
                None,
                None,
            )?;
            runtime
                .store
                .reserve_threshold_approval_and_commit_admission(
                    &command,
                    replay,
                    trusted_now_unix_ms,
                )
                .map(|result| result.into_operation())
                .map_err(durable_store_error)?
        } else {
            self.apply_admission_command(
                admission.operation.clone(),
                attachments,
                AdmissionOperationState::ApprovalReserved,
                trusted_now_unix_ms,
            )?
        };
        Ok(())
    }

    pub(crate) fn load_durable_payment_journal(
        &self,
        admission: &DurableToolAdmission,
    ) -> Result<crate::payment::PaymentJournalRecord, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let journal = runtime
            .store
            .load_payment_journal(admission.operation_id(), &runtime.fence)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable payment participant is absent for the admission operation".to_owned(),
                )
            })?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.operation_id != admission.operation_id() {
            return Err(KernelError::DurableAdmission(
                "durable payment participant changed operation identity".to_owned(),
            ));
        }
        Ok(journal)
    }

    pub(crate) fn advance_durable_payment_journal(
        &self,
        admission: &DurableToolAdmission,
        expected: &crate::payment::PaymentJournalRecord,
        transition: &crate::payment::PaymentJournalTransition,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::payment::PaymentJournalRecord, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let recovery_lease =
            self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let journal = runtime
            .store
            .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                operation: &admission.operation,
                recovery_lease: &recovery_lease,
                expected,
                transition,
                release_evidence: None,
                active_fence: &runtime.fence,
                trusted_now_unix_ms,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        Ok(journal)
    }

    pub(crate) fn mark_durable_capture_pending(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if matches!(
            admission.operation.state(),
            AdmissionOperationState::BudgetAuthorized | AdmissionOperationState::ApprovalReserved
        ) {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::ReadyToDispatch,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() == AdmissionOperationState::ReadyToDispatch {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::CapturePending,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "capture cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        Ok(())
    }

    pub(crate) fn commit_durable_dispatch(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if admission.operation.state() == AdmissionOperationState::DispatchCommitted {
            return Ok(());
        }
        if admission.operation.binding().kind() == AdmissionOperationKind::GovernedActiveResponse
            && admission.operation.state() == AdmissionOperationState::ApprovalReserved
        {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::ReadyToDispatch,
                trusted_now_unix_ms,
            )?;
        }
        let required_source = match admission.operation.binding().kind() {
            AdmissionOperationKind::ToolDispatch => AdmissionOperationState::CapturePending,
            AdmissionOperationKind::GovernedActiveResponse => {
                AdmissionOperationState::ReadyToDispatch
            }
            AdmissionOperationKind::GovernedEconomicMutation => {
                return Err(KernelError::DurableAdmission(
                    "economic mutation admission does not use dispatch commitment".to_owned(),
                ));
            }
        };
        if admission.operation.state() != required_source {
            return Err(KernelError::DurableAdmission(format!(
                "dispatch cannot commit from state {:?}; expected {required_source:?}",
                admission.operation.state()
            )));
        }
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            Vec::new(),
            AdmissionOperationState::DispatchCommitted,
            trusted_now_unix_ms,
        )?;
        Ok(())
    }

    pub(crate) fn compensate_durable_admission_before_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        verifier_policy: serde_json::Value,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let current = runtime
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "pre-dispatch admission disappeared during compensation".to_owned(),
                )
            })?;
        if &current != operation
            || current.state().is_terminal()
            || current.dispatch_commit().is_some()
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation operation changed".to_owned(),
            ));
        }
        let lease = self.claim_admission_recovery(&current, trusted_now_unix_ms)?;
        let context = AdmissionProjectionContext {
            operation_id: current.binding().operation_id().clone(),
            request_id: current.binding().request_id().clone(),
            expected_operation_version: current.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        if current
            .attachment(crate::admission_operation::AdmissionAttachmentKind::PaymentParticipant)
            .is_some()
        {
            let mut journal = runtime
                .store
                .load_payment_journal(current.binding().operation_id().as_str(), &runtime.fence)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "pre-dispatch payment journal disappeared".to_owned(),
                    )
                })?;
            if journal.state == crate::payment::PaymentJournalState::HoldPlaced {
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition:
                            &crate::payment::PaymentJournalTransition::CancelBeforeAuthorization,
                        release_evidence: None,
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            }
            if journal.state == crate::payment::PaymentJournalState::Authorized {
                // The rail hold was authorized before dispatch, so the tool never
                // ran and the authorization must be released rather than left held.
                // Drive the durable release the same way the live cleanup path does:
                // record the no-effect release authority, advance the journal to
                // Settling, release on the rail, then settle. The release proof is
                // built from the acquired-participant snapshot, which the terminal
                // compensation projection below also accepts.
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "authorized pre-dispatch hold has no configured payment adapter".to_owned(),
                    )
                })?;
                let authorization_id = journal.authorization_id.clone().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "authorized payment journal omitted its authorization".to_owned(),
                    )
                })?;
                let proof =
                    crate::tool_outcome::VerifiedPreDispatchNoEffect::from_qualified_released_operation_snapshot(
                        &current,
                        &context,
                        verifier_policy.clone(),
                    )
                    .map_err(tool_outcome_error)?;
                let evidence = crate::tool_outcome::MonetaryReleaseAuthority::NoEffect(
                    crate::tool_outcome::VerifiedNoEffectProof::BeforeDispatch(proof),
                )
                .evidence_bundle()
                .map_err(tool_outcome_error)?;
                let persisted = evidence.to_persisted();
                let authority = crate::payment::PaymentReleaseAuthorityBinding {
                    kind: crate::payment::PaymentReleaseAuthorityKind::PreDispatchNoEffect,
                    operation_id: persisted.operation_id.as_str().to_owned(),
                    operation_version: persisted.operation_version,
                    evidence_id: persisted.evidence_id.as_str().to_owned(),
                    evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                };
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition: &crate::payment::PaymentJournalTransition::BeginRelease {
                            authority,
                        },
                        release_evidence: Some(&evidence),
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                let result = adapter
                    .release(&authorization_id, current.binding().request_id().as_str())
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                if result.settlement_status != crate::payment::RailSettlementStatus::Released {
                    return Err(KernelError::DurableAdmission(
                        "pre-dispatch rail release was not confirmed".to_owned(),
                    ));
                }
                journal = runtime
                    .store
                    .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                        operation: &current,
                        recovery_lease: &lease,
                        expected: &journal,
                        transition:
                            &crate::payment::PaymentJournalTransition::SettlementCompleted {
                                transaction_id: result.transaction_id,
                            },
                        release_evidence: None,
                        active_fence: &runtime.fence,
                        trusted_now_unix_ms,
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            }
            let released = journal.state == crate::payment::PaymentJournalState::Settled
                && journal.settle_action == Some(crate::payment::PaymentSettleAction::Release);
            let cancelled_before_authorization = journal.state
                == crate::payment::PaymentJournalState::Closed
                && journal.authorization_id.is_none();
            if !released && !cancelled_before_authorization {
                return Err(KernelError::DurableAdmission(
                    "pre-dispatch payment release is not durable".to_owned(),
                ));
            }
        }
        let projection = verified_released_pre_dispatch_compensation_projection(
            &current,
            context,
            verifier_policy,
        )?;
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if terminal.operation_id != *current.binding().operation_id()
            || terminal.state != AdmissionOperationState::CompensatedBeforeDispatch
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation committed a different terminal operation".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn capture_and_commit_durable_dispatch(
        &self,
        admission: &mut DurableToolAdmission,
        capability: &CapabilityToken,
        budget_mutation: &mut PreExecutionBudgetMutation,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let charge = budget_mutation.durable_hold_result_mut().ok_or_else(|| {
            KernelError::DurableAdmission(
                "combined dispatch commit requires an authorized budget hold".to_owned(),
            )
        })?;
        let request = BudgetCaptureInvocationRequest {
            capability_id: capability.id.clone(),
            grant_index: charge.grant_index,
            hold_id: charge.budget_hold_id.clone(),
            event_id: charge.capture_invocation_event_id(),
            trusted_time: None,
            authority: charge.authorize_metadata.authority.clone(),
        };
        match admission.operation.state() {
            AdmissionOperationState::CapturePending => {
                let recovery_lease =
                    self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
                let capture = runtime
                    .store
                    .capture_invocation_and_commit_dispatch(
                        &admission.operation,
                        &recovery_lease,
                        request,
                        &runtime.fence,
                        trusted_now_unix_ms,
                    )
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                admission.operation = capture.operation;
                let mutation = match capture.decision {
                    crate::budget_store::BudgetInvocationCaptureDecision::Captured(mutation)
                    | crate::budget_store::BudgetInvocationCaptureDecision::AlreadyCaptured(
                        mutation,
                    ) => mutation,
                };
                charge.invocation_capture = Some(Box::new(mutation));
            }
            AdmissionOperationState::DispatchCommitted => {}
            state => {
                return Err(KernelError::DurableAdmission(format!(
                    "combined dispatch capture cannot resume from state {state:?}"
                )));
            }
        }
        Ok(())
    }

    fn claim_admission_recovery(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::admission_operation::AdmissionRecoveryLease, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)
    }

    pub(super) fn apply_admission_command(
        &self,
        operation: AdmissionOperationV1,
        attachments: Vec<AdmissionAttachment>,
        next_state: AdmissionOperationState,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionOperationV1, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_string())
            })?;
        let lease = runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            attachments,
            Some(next_state),
            None,
            None,
        )?;
        runtime
            .store
            .compare_and_swap(&command, trusted_now_unix_ms)
            .map(|result| result.into_operation())
            .map_err(durable_store_error)
    }

    fn durable_runtime(&self) -> Result<&DurableAdmissionRuntime, KernelError> {
        self.durable_admission_runtime.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "qualified admission operation store is unavailable".to_string(),
            )
        })
    }

    fn durable_stream_limits(&self) -> Result<InvocationStreamLimitsV1, KernelError> {
        InvocationStreamLimitsV1::new(
            self.config.max_stream_total_bytes,
            self.config.memory_budget.max_stream_chunks,
            self.config.max_stream_duration_secs,
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }
}

fn admission_digest(
    field: &'static str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, KernelError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| KernelError::DurableAdmission(format!("{field}: {error}")))?;
    AdmissionDigest::try_new(field, sha256_hex(&canonical)).map_err(KernelError::from)
}

fn invocation_output_to_server_output(output: &InvocationOutputV1) -> ToolServerOutput {
    let stream = |chunks: &[serde_json::Value]| ToolCallStream {
        chunks: chunks
            .iter()
            .cloned()
            .map(|data| ToolCallChunk { data })
            .collect(),
    };
    match output {
        InvocationOutputV1::Value { value } => ToolServerOutput::Value(value.clone()),
        InvocationOutputV1::CompleteStream { chunks } => {
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream(chunks)))
        }
        InvocationOutputV1::IncompleteStream { chunks, reason } => {
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete {
                stream: stream(chunks),
                reason: reason.clone(),
            })
        }
    }
}

fn durable_store_error(
    error: crate::admission_operation::AdmissionOperationStoreError,
) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}

fn durable_outcome_store_error(error: ToolOutcomeStoreError) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}

fn tool_outcome_error(error: crate::tool_outcome::ToolOutcomeError) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}
