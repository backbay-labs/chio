use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::budget_store::{BudgetReconcileHoldDecision, BudgetReverseHoldDecision};
use crate::{
    CapabilityToken, ChildRequestReceipt, PaymentAuthorization, PaymentCredentialDisposition,
    PreDispatchPaymentUnwindEvidence, ToolCallRequest,
};

use super::{
    current_unix_timestamp, merge_metadata_objects, project_runtime_admission_receipt_metadata,
    scope_pre_invocation_guard_evidence, ChioKernel, EvaluationReceiptContext, KernelError,
    PreExecutionBudgetMutation,
};

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";
const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

/// Describe an open hold retained after a dispatched evaluation was dropped.
///
/// The drop path cannot safely reverse the hold immediately because the tool
/// may already have committed its side effect. Recovery locates the open hold
/// from the budget store; this signed audit breadcrumb makes the retained hold
/// and its pending terminal action explicit.
fn pending_reversal_marker(hold_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "hold_id": hold_id,
        "terminal": {
            "disposition": "pending_reversal",
            "reason": reason,
        }
    })
}

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) evaluation_context: EvaluationReceiptContext,
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) runtime_admission_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
}

/// A single pre-dispatch cleanup step that failed. Collected so a signed fault
/// receipt can name the failing step, its redacted reason, and the hold /
/// reservation ids that step was unwinding, letting an operator locate a hold
/// or reservation that may be stuck without cross-referencing the top-level
/// admission metadata.
pub(crate) struct PreDispatchCleanupFault {
    pub(crate) step: &'static str,
    pub(crate) reason: String,
    /// Ids of the holds / reservations this step was releasing (budget hold id,
    /// payment authorization id, delegated child / parent capability id, or the
    /// reserved runtime lease / continuation ids). Empty when the failing step
    /// carries no locatable id.
    pub(crate) hold_ids: Vec<String>,
}

pub(crate) struct PreDispatchCleanup<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) cap: &'a CapabilityToken,
    pub(crate) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(crate) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(crate) payment_authorization_outcome_unknown: Option<&'a str>,
    pub(crate) payment_credential_disposition: PaymentCredentialDisposition,
    pub(crate) receipt_metadata: Option<serde_json::Value>,
    pub(crate) runtime_admission_metadata: Option<serde_json::Value>,
    pub(crate) budget_lease_acquired: bool,
}

pub(crate) struct PreDispatchCleanupOutcome {
    pub(crate) reverse: Option<BudgetReverseHoldDecision>,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) faults: Vec<PreDispatchCleanupFault>,
}

fn run_pre_dispatch_cleanup_step<T, E: std::fmt::Display>(
    panic_reason: &'static str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(redacted!(&error).to_string()),
        Err(_) => Err(panic_reason.to_string()),
    }
}

/// Extract the reserved runtime-admission lease / continuation ids carried in
/// the admission metadata so a runtime-admission release fault can name the
/// possibly-stuck reservations directly in its fault entry.
pub(crate) fn reserved_runtime_admission_ids(metadata: Option<&serde_json::Value>) -> Vec<String> {
    let Some(runtime) = metadata
        .and_then(|value| value.get("chio_runtime"))
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for key in [
        "reserved_destructive_lease_id",
        "reserved_treaty_continuation_id",
        "reserved_swarm_continuation_id",
    ] {
        if let Some(id) = runtime.get(key).and_then(serde_json::Value::as_str) {
            ids.push(id.to_string());
        }
    }
    ids
}

impl ChioKernel {
    pub(crate) fn cleanup_pre_dispatch_state(
        &self,
        cleanup: PreDispatchCleanup<'_>,
    ) -> PreDispatchCleanupOutcome {
        let release_metadata = cleanup.runtime_admission_metadata;
        let mut runtime_metadata =
            project_runtime_admission_receipt_metadata(release_metadata.as_ref()).unwrap_or(None);
        let mut faults = Vec::new();

        if release_metadata.is_some() {
            if let Err(reason) = run_pre_dispatch_cleanup_step(
                "runtime admission reservation release panicked",
                || self.release_runtime_admission_reservations(release_metadata.as_ref()),
            ) {
                warn!(
                    request_id = %cleanup.request.request_id,
                    reason = %redacted!(&reason),
                    "runtime admission reservation release failed during pre-dispatch cleanup"
                );
                let hold_ids = reserved_runtime_admission_ids(release_metadata.as_ref());
                runtime_metadata = merge_metadata_objects(
                    runtime_metadata,
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "reservation_release_failed": true,
                            "reservation_release_failure_reason": reason,
                        }
                    })),
                );
                faults.push(PreDispatchCleanupFault {
                    step: "runtime_admission_release",
                    reason,
                    hold_ids,
                });
            }
        }

        let charge = cleanup.budget_mutation.charge_result();
        let mut retain_budget_exposure = false;
        let mut retain_payment_authorization = false;
        let mut payment_unwind_outcome_unknown = false;
        let mut budget_reversal_outcome_unknown = false;
        let mut payment_unwind_evidence: Option<PreDispatchPaymentUnwindEvidence> = None;

        if let Some(reason) = cleanup.payment_authorization_outcome_unknown {
            retain_budget_exposure = charge.is_some();
            retain_payment_authorization = true;
            let mut hold_ids = cleanup
                .payment_authorization
                .map(|authorization| vec![authorization.authorization_id.clone()])
                .unwrap_or_default();
            if let Some(charge) = charge {
                hold_ids.push(charge.budget_hold_id.clone());
            }
            faults.push(PreDispatchCleanupFault {
                step: "payment_authorization",
                reason: reason.to_string(),
                hold_ids,
            });
        }

        if let Some(payment_authorization) = cleanup.payment_authorization {
            match run_pre_dispatch_cleanup_step(
                "payment adapter panicked during pre-dispatch unwind",
                || {
                    self.unwind_aborted_payment(
                        cleanup.request,
                        charge,
                        payment_authorization,
                        cleanup.payment_credential_disposition,
                    )
                },
            ) {
                Ok(evidence) => payment_unwind_evidence = Some(evidence),
                Err(reason) => {
                    retain_budget_exposure = charge.is_some();
                    retain_payment_authorization = true;
                    payment_unwind_outcome_unknown = true;
                    let mut hold_ids = vec![payment_authorization.authorization_id.clone()];
                    if let Some(charge) = charge {
                        hold_ids.push(charge.budget_hold_id.clone());
                    }
                    faults.push(PreDispatchCleanupFault {
                        step: "monetary_unwind",
                        reason,
                        hold_ids,
                    });
                }
            }
        }

        let skip_budget_reversal = retain_budget_exposure || retain_payment_authorization;
        let reverse = if skip_budget_reversal {
            None
        } else {
            match run_pre_dispatch_cleanup_step(
                "budget store panicked during pre-dispatch reversal",
                || self.reverse_pre_execution_budget_mutation(cleanup.cap, cleanup.budget_mutation),
            ) {
                Ok(reverse) => reverse,
                Err(reason) => {
                    let hold_ids = charge.map_or_else(
                        || vec![cleanup.cap.id.clone()],
                        |charge| vec![charge.budget_hold_id.clone()],
                    );
                    if charge.is_some() {
                        retain_budget_exposure = true;
                        budget_reversal_outcome_unknown = true;
                    }
                    faults.push(PreDispatchCleanupFault {
                        step: "budget_reversal",
                        reason,
                        hold_ids,
                    });
                    None
                }
            }
        };
        // Recompute after the reversal attempt: a failed or panicked reversal
        // changes `retain_budget_exposure` above. Using the pre-attempt snapshot
        // here would release delegated headroom and omit retention evidence while
        // the hold's outcome is still unknown.
        let retain_budget_mutation = retain_budget_exposure || retain_payment_authorization;

        if cleanup.budget_lease_acquired && !retain_budget_mutation {
            if let Err(reason) =
                run_pre_dispatch_cleanup_step("admitted capability budget release panicked", || {
                    self.release_admitted_capability_budget(cleanup.cap)
                })
            {
                let mut hold_ids = vec![cleanup.cap.id.clone()];
                if let Some(parent_link) = cleanup.cap.delegation_chain.last() {
                    hold_ids.push(parent_link.capability_id.clone());
                }
                faults.push(PreDispatchCleanupFault {
                    step: "child_budget_release",
                    reason,
                    hold_ids,
                });
            }
        }

        if retain_budget_mutation || retain_payment_authorization {
            let mut retained = serde_json::Map::new();
            retained.insert(
                "pre_dispatch_monetary_outcome_unknown".to_string(),
                serde_json::Value::Bool(true),
            );
            if let Some(charge) = charge.filter(|_| retain_budget_exposure) {
                retained.insert(
                    "retained_budget_hold_id".to_string(),
                    serde_json::json!(&charge.budget_hold_id),
                );
                retained.insert(
                    "retained_budget_exposure_units".to_string(),
                    serde_json::json!(charge.cost_charged),
                );
            }
            if cleanup.payment_authorization_outcome_unknown.is_some() {
                retained.insert(
                    "payment_authorization_outcome_unknown".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            if payment_unwind_outcome_unknown {
                retained.insert(
                    "payment_unwind_outcome_unknown".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            if budget_reversal_outcome_unknown {
                retained.insert(
                    "budget_reversal_outcome_unknown".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            if cleanup.payment_authorization_outcome_unknown.is_some()
                || payment_unwind_outcome_unknown
            {
                retained.insert(
                    "payment_credential_disposition".to_string(),
                    serde_json::json!(cleanup.payment_credential_disposition),
                );
            }
            if cleanup.budget_lease_acquired && retain_budget_mutation {
                retained.insert(
                    "retained_capability_budget_lease".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            if let Some(authorization) = cleanup
                .payment_authorization
                .filter(|_| retain_payment_authorization)
            {
                retained.insert(
                    "retained_payment_authorization_id".to_string(),
                    serde_json::json!(&authorization.authorization_id),
                );
                retained.insert(
                    "retained_payment_authorization_settled".to_string(),
                    serde_json::json!(authorization.settled),
                );
            }
            runtime_metadata = merge_metadata_objects(
                runtime_metadata,
                Some(serde_json::json!({ "chio_runtime": retained })),
            );
        }

        if cleanup.payment_credential_disposition
            == PaymentCredentialDisposition::RetentionOutcomeUnknown
        {
            runtime_metadata = merge_metadata_objects(
                runtime_metadata,
                Some(serde_json::json!({
                    "chio_runtime": {
                        "dispatch_credential_retention_outcome_unknown": true,
                        "dispatch_credential_disposition": cleanup
                            .payment_credential_disposition,
                    }
                })),
            );
        }

        if let Some(evidence) = payment_unwind_evidence {
            match serde_json::to_value(evidence) {
                Ok(evidence) => {
                    runtime_metadata = merge_metadata_objects(
                        runtime_metadata,
                        Some(serde_json::json!({
                            "chio_runtime": {
                                "pre_dispatch_payment_unwind": evidence,
                            }
                        })),
                    );
                }
                Err(error) => faults.push(PreDispatchCleanupFault {
                    step: "payment_unwind_receipt_evidence",
                    reason: redacted!(&error).to_string(),
                    hold_ids: Vec::new(),
                }),
            }
        }

        if !faults.is_empty() {
            let fault_entries = faults
                .iter()
                .map(|fault| {
                    serde_json::json!({
                        "step": fault.step,
                        "reason": fault.reason,
                        "hold_ids": fault.hold_ids,
                    })
                })
                .collect::<Vec<_>>();
            runtime_metadata = merge_metadata_objects(
                runtime_metadata,
                Some(serde_json::json!({
                    "chio_runtime": {
                        "pre_dispatch_cleanup_failed": true,
                        "pre_dispatch_cleanup_faults": fault_entries,
                    }
                })),
            );
        }

        let metadata = merge_metadata_objects(cleanup.receipt_metadata, runtime_metadata);
        let metadata = if let Some(charge) = charge.filter(|_| retain_budget_exposure) {
            self.merge_budget_receipt_metadata(
                metadata,
                self.budget_execution_receipt_metadata(charge, None, None),
            )
        } else {
            metadata
        };

        PreDispatchCleanupOutcome {
            reverse,
            metadata,
            faults,
        }
    }
}

pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    budget_mutation: &'a PreExecutionBudgetMutation,
    payment_authorization: Option<PaymentAuthorization>,
    payment_credential_disposition: PaymentCredentialDisposition,
    receipt_context: PostAdmissionReceiptContext,
    /// Signed child-request receipts buffered by the nested-flow bridge during
    /// dispatch. Owned by the guard (rather than the evaluation stack frame) so
    /// a post-dispatch drop can still flush them onto the append-only log,
    /// preserving receipt completeness for nested child operations.
    child_receipts: Vec<ChildRequestReceipt>,
    /// Signed child receipts whose durable append was attempted but returned an
    /// error or panicked. They must not be retried because a generic store
    /// cannot distinguish a pre-commit failure from a commit acknowledgement
    /// failure. The parent cancellation carries this evidence explicitly.
    child_receipts_with_unknown_append_outcome: Vec<ChildRequestReceipt>,
    child_receipt_persistence_failure_reason: Option<String>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `Ok(true)` from `admit_capability_budget`). `false` means the
    /// capability had no parent to admit against, so there is no lease to drop.
    /// When `true`, a pre-dispatch drop releases exactly this evaluation's one
    /// lease; the shared edge is freed only when the last holder releases, so an
    /// overlapping evaluation that still holds it keeps its share protected.
    /// Gates the step-4 child-budget release in `handle_pre_dispatch_drop`.
    budget_lease_acquired: bool,
    budget_reconcile_decision: std::sync::OnceLock<BudgetReconcileHoldDecision>,
    armed: bool,
    dispatch_started: bool,
}

impl<'a> PostAdmissionDropGuard<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel: &'a ChioKernel,
        request: &'a ToolCallRequest,
        cap: &'a CapabilityToken,
        matched_grant_index: Option<usize>,
        budget_mutation: &'a PreExecutionBudgetMutation,
        payment_authorization: Option<&'a PaymentAuthorization>,
        receipt_context: PostAdmissionReceiptContext,
        budget_lease_acquired: bool,
    ) -> Self {
        Self {
            kernel,
            request,
            cap,
            matched_grant_index,
            budget_mutation,
            payment_authorization: payment_authorization.cloned(),
            payment_credential_disposition: PaymentCredentialDisposition::NonePresent,
            receipt_context,
            child_receipts: Vec::new(),
            child_receipts_with_unknown_append_outcome: Vec::new(),
            child_receipt_persistence_failure_reason: None,
            budget_lease_acquired,
            budget_reconcile_decision: std::sync::OnceLock::new(),
            armed: true,
            dispatch_started: false,
        }
    }

    /// Borrow the buffered child-receipt sink so the nested-flow bridge can push
    /// signed child receipts into it while dispatch is in flight. The guard owns
    /// the buffer so a post-dispatch drop can still flush it (see
    /// `flush_buffered_child_receipts_from_drop`).
    pub(crate) fn child_receipts_mut(&mut self) -> &mut Vec<ChildRequestReceipt> {
        &mut self.child_receipts
    }

    /// Persist buffered children while retaining any suffix whose append was
    /// never attempted. An append with an unknown outcome is quarantined from
    /// retries and signed into the parent cancellation if evaluation aborts.
    pub(crate) fn flush_child_receipts(&mut self) -> Result<(), KernelError> {
        let result = self.kernel.record_child_receipts(
            &mut self.child_receipts,
            &mut self.child_receipts_with_unknown_append_outcome,
        );
        if let Err(error) = &result {
            self.child_receipt_persistence_failure_reason = Some(redacted!(error).to_string());
        }
        result
    }

    /// Persist the buffered child receipts on the normal path. This keeps the
    /// main-branch API while sharing the append-outcome quarantine used by the
    /// drop path, so an uncertain append is never retried.
    pub(crate) fn record_buffered_child_receipts(&mut self) -> Result<(), KernelError> {
        self.flush_child_receipts()
    }

    /// Mark that the tool-server dispatch await has been entered. After this
    /// point a dropped future may correspond to an executed side effect, so
    /// the drop path must record a cancellation receipt and fail closed on
    /// reservations.
    pub(crate) fn mark_dispatch_started(&mut self) {
        self.dispatch_started = true;
    }

    pub(crate) fn set_payment_authorization(
        &mut self,
        payment_authorization: Option<&PaymentAuthorization>,
    ) {
        self.payment_authorization = payment_authorization.cloned();
    }

    pub(crate) fn set_payment_credential_disposition(
        &mut self,
        disposition: PaymentCredentialDisposition,
    ) {
        self.payment_credential_disposition = disposition;
    }

    pub(crate) fn budget_reconcile_decision(
        &self,
    ) -> &std::sync::OnceLock<BudgetReconcileHoldDecision> {
        &self.budget_reconcile_decision
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// End lifecycle protection only after a terminal response succeeded or
    /// its parent receipt was durably appended. A failure before persistence
    /// starts leaves the guard armed so Drop can record a fail-closed
    /// cancellation. An ambiguous append remains armed so Drop can report the
    /// audit fault without attempting a contradictory terminal receipt.
    pub(crate) fn finish_terminal<T>(
        &mut self,
        result: Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        if result.is_ok()
            || self
                .receipt_context
                .evaluation_context
                .terminal_receipt_committed()
        {
            self.disarm();
        }
        result
    }

    /// Retain every state transition whose outcome became ambiguous after
    /// dispatch and identify the held exposure in the cancellation receipt.
    fn retain_post_dispatch_state(&self) -> Option<serde_json::Value> {
        let mut metadata = self.kernel.retain_post_dispatch_state(
            self.receipt_context.extra_metadata.clone(),
            self.receipt_context.runtime_admission_metadata.clone(),
            self.budget_mutation.charge_result(),
            self.budget_reconcile_decision.get(),
            self.payment_authorization.as_ref(),
        );
        if let Some(charge) = self
            .budget_mutation
            .charge_result()
            .filter(|_| self.budget_reconcile_decision.get().is_none())
        {
            metadata = self.kernel.merge_budget_receipt_metadata(
                metadata,
                serde_json::json!({
                    "budget_authority": pending_reversal_marker(
                        &charge.budget_hold_id,
                        POST_ADMISSION_DROP_REASON,
                    )
                }),
            );
        }
        if self.payment_credential_disposition == PaymentCredentialDisposition::NonePresent {
            return metadata;
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({
                "chio_runtime": {
                    "dispatch_credential_disposition": self.payment_credential_disposition,
                    "dispatch_credential_retention_outcome_unknown": self
                        .payment_credential_disposition
                        == PaymentCredentialDisposition::RetentionOutcomeUnknown,
                }
            })),
        )
    }

    /// Clean up a future dropped BEFORE tool-server dispatch. Runtime state and
    /// budget mutations are reversed when their external outcomes are known.
    /// An ambiguous payment authorization or unwind retains the local monetary
    /// exposure and delegated budget lease so retry capacity cannot reopen. A
    /// clean unwind records no receipt. Any fault records a signed receipt so a
    /// retained hold or reservation is visible in the append-only log.
    fn handle_pre_dispatch_drop(&self) {
        let outcome = self.kernel.cleanup_pre_dispatch_state(PreDispatchCleanup {
            request: self.request,
            cap: self.cap,
            budget_mutation: self.budget_mutation,
            payment_authorization: self.payment_authorization.as_ref(),
            payment_authorization_outcome_unknown: None,
            payment_credential_disposition: self.payment_credential_disposition,
            receipt_metadata: self.receipt_context.extra_metadata.clone(),
            runtime_admission_metadata: self.receipt_context.runtime_admission_metadata.clone(),
            budget_lease_acquired: self.budget_lease_acquired,
        });
        if outcome.faults.is_empty() {
            // No terminal receipt is emitted for a clean pre-dispatch drop, so
            // clear the durable intent explicitly. A bounded clear failure
            // leaves the row available to recovery rather than losing it.
            self.kernel
                .clear_dispatch_intent_for_non_dispatch_exit(self.request);
        } else {
            self.record_pre_dispatch_cleanup_fault_receipt(outcome.metadata);
        }
        #[cfg(debug_assertions)]
        if outcome.faults.is_empty() {
            if let Some(grant_index) = self.matched_grant_index {
                self.kernel
                    .debug_assert_reservation_conservation(&self.cap.id, grant_index);
            }
        }
    }

    /// Persist signed child receipts before the parent cancellation receipt.
    /// Only a suffix that never reached the store is retried. Receipts with an
    /// unknown append outcome remain owned by the guard as signed evidence.
    fn flush_buffered_child_receipts_from_drop(&mut self) -> Option<String> {
        if self.child_receipts.is_empty()
            && self.child_receipts_with_unknown_append_outcome.is_empty()
        {
            return None;
        }
        while !self.child_receipts.is_empty() {
            let pending_before = self.child_receipts.len();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.flush_child_receipts()
            }))
            .unwrap_or_else(|_| {
                Err(KernelError::Internal(
                    "buffered child receipt persistence panicked".to_string(),
                ))
            });
            if let Err(error) = result {
                self.child_receipt_persistence_failure_reason = Some(redacted!(&error).to_string());
                // An outcome-unknown receipt was removed from the retry queue
                // and quarantined. Continue with the untouched suffix, but stop
                // when the failure happened before any append was attempted.
                if self.child_receipts.len() >= pending_before {
                    break;
                }
            }
        }
        if self.child_receipts.is_empty()
            && self.child_receipts_with_unknown_append_outcome.is_empty()
        {
            return None;
        }
        let reason = self
            .child_receipt_persistence_failure_reason
            .clone()
            .unwrap_or_else(|| "child receipt append outcome is unknown".to_string());
        warn!(
            request_id = %self.request.request_id,
            reason = %redacted!(&reason),
            unpersisted_child_receipts = self.child_receipts.len(),
            append_outcome_unknown_child_receipts = self
                .child_receipts_with_unknown_append_outcome
                .len(),
            audit_fault = "post_admission_drop_child_receipts_unconfirmed",
            "nested child receipt persistence could not be fully confirmed"
        );
        Some(reason)
    }

    fn child_receipt_persistence_fault_metadata(&self, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "chio_runtime": {
                "child_receipt_persistence_failed": true,
                "child_receipt_persistence_failure_reason": reason,
                "unpersisted_child_receipt_count": self.child_receipts.len(),
                "unpersisted_signed_child_receipts": &self.child_receipts,
                "append_outcome_unknown_child_receipt_count": self
                    .child_receipts_with_unknown_append_outcome
                    .len(),
                "append_outcome_unknown_signed_child_receipts": &self
                    .child_receipts_with_unknown_append_outcome,
            }
        })
    }

    /// Record a signed cancellation receipt documenting a pre-dispatch cleanup
    /// fault. Best-effort from Drop: if even the receipt cannot be recorded,
    /// log with the `audit_fault` field. The failing steps and the reserved
    /// lease/continuation ids (carried in the admission metadata) are folded
    /// into the receipt so an operator can locate the stuck hold.
    fn record_pre_dispatch_cleanup_fault_receipt(&self, metadata: Option<serde_json::Value>) {
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.kernel.build_cancelled_response_with_metadata(
                self.request,
                &self.receipt_context.evaluation_context,
                PRE_DISPATCH_CLEANUP_FAULT_REASON,
                current_unix_timestamp(),
                self.matched_grant_index,
                metadata,
            )
        }))
        .unwrap_or_else(|_| {
            Err(KernelError::Internal(
                "pre-dispatch cleanup fault receipt recording panicked".to_string(),
            ))
        });
        if let Err(error) = result {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "pre_dispatch_cleanup_fault_receipt_unrecorded",
                "failed to record pre-dispatch cleanup fault receipt"
            );
        }
    }
}

impl PostAdmissionDropGuard<'_> {
    fn handle_drop(&mut self) {
        if !self.armed
            || self
                .receipt_context
                .evaluation_context
                .terminal_receipt_committed()
        {
            return;
        }

        if self
            .receipt_context
            .evaluation_context
            .terminal_receipt_append_started()
        {
            warn!(
                request_id = %self.request.request_id,
                audit_fault = "terminal_receipt_append_outcome_unknown",
                "skipped cancellation because terminal receipt persistence may have committed"
            );
            return;
        }

        if !self.dispatch_started {
            // Pre-dispatch drop (or a panic unwinding before dispatch).
            // Nothing was written to the tool server. Reverse local state when
            // external outcomes are known; ambiguous payment outcomes retain
            // spending exposure and record a signed cleanup-fault receipt.
            self.handle_pre_dispatch_drop();
            return;
        }

        // Child receipts precede the parent cancellation in the append-only log.
        let child_receipt_persistence_fault = self.flush_buffered_child_receipts_from_drop();

        // A side effect may have executed. Retain every reservation and
        // monetary exposure, then record their identifiers in the receipt.
        let mut receipt_metadata = self.retain_post_dispatch_state();
        if let Some(reason) = child_receipt_persistence_fault.as_deref() {
            receipt_metadata = merge_metadata_objects(
                receipt_metadata,
                Some(self.child_receipt_persistence_fault_metadata(reason)),
            );
        }

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.kernel.build_cancelled_response_with_metadata(
                self.request,
                &self.receipt_context.evaluation_context,
                POST_ADMISSION_DROP_REASON,
                current_unix_timestamp(),
                self.matched_grant_index,
                receipt_metadata,
            )
        }))
        .unwrap_or_else(|_| {
            Err(KernelError::Internal(
                "post-admission cancellation receipt recording panicked".to_string(),
            ))
        });
        if let Err(error) = result {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "post_admission_drop_receipt_unrecorded",
                "failed to record cancellation receipt for dropped post-admission invocation"
            );
        }
        #[cfg(debug_assertions)]
        if let Some(grant_index) = self.matched_grant_index {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.kernel
                    .debug_assert_reservation_conservation(&self.cap.id, grant_index);
            }));
        }
    }
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handle_drop();
        }));
        if result.is_err() {
            warn!(
                request_id = %self.request.request_id,
                audit_fault = "post_admission_drop_handler_panicked",
                "post-admission drop handler panicked"
            );
        }
    }
}
