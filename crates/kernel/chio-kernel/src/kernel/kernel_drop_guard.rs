use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::admission_operation::AdmissionOperationV1;
use crate::{CapabilityToken, ChildRequestReceipt, PaymentAuthorization, ToolCallRequest};

use super::{
    current_unix_timestamp, current_unix_timestamp_ms, merge_metadata_objects,
    scope_pre_invocation_guard_evidence, ChioKernel, KernelError, PreExecutionBudgetMutation,
    VerifiedGovernedPayeeBinding,
};

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";
const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
    pub(crate) verified_payee_binding: Option<VerifiedGovernedPayeeBinding>,
}

/// A single pre-dispatch cleanup step that failed. Collected so a signed fault
/// receipt can name the failing step, its redacted reason, and the hold /
/// reservation ids that step was unwinding, letting an operator locate a hold
/// or reservation that may be stuck without cross-referencing the top-level
/// admission metadata.
struct PreDispatchCleanupFault {
    step: &'static str,
    reason: String,
    /// Ids of the holds / reservations this step was releasing (budget hold id,
    /// payment authorization id, delegated child / parent capability id, or the
    /// reserved runtime lease / continuation ids). Empty when the failing step
    /// carries no locatable id.
    hold_ids: Vec<String>,
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

pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    budget_mutation: &'a PreExecutionBudgetMutation,
    payment_authorization: Option<&'a PaymentAuthorization>,
    receipt_context: PostAdmissionReceiptContext,
    /// Signed child-request receipts buffered by the nested-flow bridge during
    /// dispatch. Owned by the guard (rather than the evaluation stack frame) so
    /// a post-dispatch drop can still flush them onto the append-only log,
    /// preserving receipt-completeness for nested child operations.
    child_receipts: Vec<ChildRequestReceipt>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `Ok(true)` from `admit_capability_budget`). `false` means the
    /// capability had no parent to admit against, so there is no lease to drop.
    /// When `true`, a pre-dispatch drop releases exactly this evaluation's one
    /// lease; the shared edge is freed only when the last holder releases, so an
    /// overlapping evaluation that still holds it keeps its share protected.
    /// Gates the step-4 child-budget release in `handle_pre_dispatch_drop`.
    budget_lease_acquired: bool,
    durable_operation: Option<&'a AdmissionOperationV1>,
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
            payment_authorization,
            receipt_context,
            child_receipts: Vec::new(),
            budget_lease_acquired,
            durable_operation: None,
            armed: true,
            dispatch_started: false,
        }
    }

    pub(crate) fn with_durable_operation(
        mut self,
        operation: Option<&'a AdmissionOperationV1>,
    ) -> Self {
        self.durable_operation = operation;
        self
    }

    /// Borrow the buffered child-receipt sink so the nested-flow bridge can push
    /// signed child receipts into it while dispatch is in flight. The guard owns
    /// the buffer so a post-dispatch drop can still flush it (see
    /// `flush_buffered_child_receipts_from_drop`).
    pub(crate) fn child_receipts_mut(&mut self) -> &mut Vec<ChildRequestReceipt> {
        &mut self.child_receipts
    }

    /// Record the buffered child receipts on the normal (non-drop) path,
    /// removing each from the buffer only once it is durably persisted. If a
    /// bounded append fails, the not-yet-persisted receipts stay buffered so the
    /// still-armed drop path flushes them onto the append-only log instead of
    /// discarding them with the dropped future. The guard must stay armed until
    /// this returns `Ok`; the caller disarms only on success, so the disarmed
    /// drop then flushes an empty buffer and never double-records.
    pub(crate) fn record_buffered_child_receipts(&mut self) -> Result<(), KernelError> {
        while !self.child_receipts.is_empty() {
            self.kernel.record_child_receipt(&self.child_receipts[0])?;
            self.child_receipts.remove(0);
        }
        Ok(())
    }

    /// Mark that the tool-server dispatch await has been entered. After this
    /// point a dropped future may correspond to an executed side effect, so
    /// the drop path must record a cancellation receipt and fail closed on
    /// reservations.
    pub(crate) fn mark_dispatch_started(&mut self) {
        self.dispatch_started = true;
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Fully unwind a future dropped BEFORE tool-server dispatch. No side
    /// effect is possible, so every pre-execution mutation is reversed: the
    /// monetary hold, an invocation-only budget increment,
    /// runtime-admission reservations, and an admitted child/delegated
    /// capability budget share. A clean unwind records NO receipt
    /// (the intended receipt-free exit). If ANY step fails, a signed fault
    /// receipt is recorded so a stuck hold/reservation is on the
    /// append-only log rather than silently burned. Best-effort from Drop:
    /// each step is attempted independently and failures are collected.
    fn handle_pre_dispatch_drop(&self) {
        let mut faults: Vec<PreDispatchCleanupFault> = Vec::new();

        // 1. Monetary hold reversal (budget charge + payment release/refund).
        if self.budget_mutation.charge_result().is_some() {
            match self.kernel.unwind_pre_dispatch_monetary_invocation(
                self.request,
                self.cap,
                self.budget_mutation.charge_result(),
                self.payment_authorization,
            ) {
                Ok(_) => {}
                Err(error) => {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to unwind dropped pre-dispatch monetary invocation"
                    );
                    let mut hold_ids = Vec::new();
                    if let Some(charge) = self.budget_mutation.charge_result() {
                        hold_ids.push(charge.budget_hold_id.clone());
                    }
                    if let Some(authorization) = self.payment_authorization {
                        hold_ids.push(authorization.authorization_id.clone());
                    }
                    faults.push(PreDispatchCleanupFault {
                        step: "monetary_unwind",
                        reason,
                        hold_ids,
                    });
                }
            }
        }

        // 2. Invocation-only budget reversal. A non-monetary grant
        //    with `max_invocations` incremented the invocation counter at
        //    admission; reverse it so a never-dispatched call does not
        //    permanently consume a slot. Reuse the same primitive the
        //    pre-dispatch denial path uses, gated on the Invocation variant so
        //    a Charge (handled above) is not reversed twice.
        if matches!(
            self.budget_mutation,
            PreExecutionBudgetMutation::Invocation { .. }
                | PreExecutionBudgetMutation::InvocationHold(_)
        ) {
            match self
                .kernel
                .reverse_pre_execution_budget_mutation(self.cap, self.budget_mutation)
            {
                Ok(_) => {}
                Err(error) => {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to reverse dropped pre-dispatch invocation budget"
                    );
                    faults.push(PreDispatchCleanupFault {
                        step: "invocation_reversal",
                        reason,
                        hold_ids: self.budget_mutation.durable_hold_result().map_or_else(
                            || vec![self.cap.id.clone()],
                            |hold| vec![hold.budget_hold_id.clone()],
                        ),
                    });
                }
            }
        }

        // 3. Runtime-admission reservation release.
        if let Err(error) = self
            .kernel
            .release_runtime_admission_reservations(self.receipt_context.extra_metadata.as_ref())
        {
            let reason = redacted!(&error).to_string();
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                "failed to release runtime-admission reservations on pre-dispatch drop"
            );
            faults.push(PreDispatchCleanupFault {
                step: "runtime_admission_release",
                reason,
                // Name the reserved lease / continuation ids so an operator can
                // locate the possibly-stuck reservation from the fault entry.
                hold_ids: reserved_runtime_admission_ids(
                    self.receipt_context.extra_metadata.as_ref(),
                ),
            });
        }

        // 4. Admitted child/delegated capability budget lease release (Finding
        //    B), gated on this evaluation having acquired a lease. A delegated
        //    capability took a holder lease on its share of the parent budget at
        //    admission; drop it or the lease stays permanently recorded. Release
        //    ONLY when THIS evaluation acquired a lease (`budget_lease_acquired`).
        //    The release is reference-counted: it decrements the holder count
        //    and frees the edge (returning the share to the parent) only when
        //    this was the LAST holder. An overlapping evaluation that still holds
        //    the edge keeps its share, so an oversubscribing sibling stays
        //    denied. Fail-closed: an evaluation that never acquired a lease
        //    (`budget_lease_acquired == false`) releases nothing, because
        //    over-releasing (dropping a holder this evaluation never took) would
        //    free another evaluation's live share (a budget bypass), the worse
        //    failure. Mirrors the pre-dispatch denial path.
        if self.budget_lease_acquired {
            if let Err(error) = self.kernel.release_admitted_capability_budget(self.cap) {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to release admitted capability budget on pre-dispatch drop"
                );
                // Name the delegated child capability id and its parent so the
                // stuck sibling-sum share is locatable from the fault entry.
                let mut hold_ids = vec![self.cap.id.clone()];
                if let Some(parent_link) = self.cap.delegation_chain.last() {
                    hold_ids.push(parent_link.capability_id.clone());
                }
                faults.push(PreDispatchCleanupFault {
                    step: "child_budget_release",
                    reason,
                    hold_ids,
                });
            }
        }

        if faults.is_empty() {
            if let Some(operation) = self.durable_operation {
                if let Err(error) = self
                    .kernel
                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                        Some(operation),
                        None,
                        self.payment_authorization,
                    )
                {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to terminalize dropped pre-dispatch admission"
                    );
                    faults.push(PreDispatchCleanupFault {
                        step: "durable_admission_compensation",
                        reason,
                        hold_ids: vec![operation.binding().operation_id().as_str().to_owned()],
                    });
                }
            }
        }

        // 5. Fault receipt. Clean cleanup is receipt-free (the
        //    intended design); any fault records a signed receipt.
        if !faults.is_empty() {
            self.record_pre_dispatch_cleanup_fault_receipt(&faults);
        }
    }

    /// Flush the child receipts the nested-flow bridge buffered during dispatch
    /// onto the append-only log. The receipts are ALREADY SIGNED, so this
    /// persists each through the same synchronous per-receipt record path the
    /// normal exit uses. Called only from the post-dispatch drop branch (a child
    /// operation can only have run once dispatch started); a pre-dispatch drop
    /// leaves the buffer empty. Each receipt is recorded independently and a
    /// failure does NOT abandon the receipts queued behind it: a saturated or
    /// wedged writer that fails one bounded append must not discard the rest,
    /// which a stop-at-first-failure batch record would. Best-effort from Drop:
    /// a per-receipt failure logs an `audit_fault` and never panics, and the
    /// buffer is drained unconditionally so the guard cannot re-record on a
    /// later drop.
    fn flush_buffered_child_receipts_from_drop(&mut self) {
        for receipt in std::mem::take(&mut self.child_receipts) {
            if let Err(error) = self.kernel.record_child_receipt(&receipt) {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    audit_fault = "post_admission_drop_child_receipts_unrecorded",
                    "failed to flush a buffered nested child receipt on post-admission drop"
                );
            }
        }
    }

    /// Record a signed cancellation receipt documenting a pre-dispatch cleanup
    /// fault. Best-effort from Drop: if even the receipt cannot be recorded,
    /// log with the `audit_fault` field. The failing steps and the reserved
    /// lease/continuation ids (carried in the admission metadata) are folded
    /// into the receipt so an operator can locate the stuck hold.
    fn record_pre_dispatch_cleanup_fault_receipt(&self, faults: &[PreDispatchCleanupFault]) {
        let fault_entries: Vec<serde_json::Value> = faults
            .iter()
            .map(|fault| {
                serde_json::json!({
                    "step": fault.step,
                    "reason": fault.reason,
                    "hold_ids": fault.hold_ids,
                })
            })
            .collect();
        let metadata = merge_metadata_objects(
            self.receipt_context.extra_metadata.clone(),
            Some(serde_json::json!({
                "chio_runtime": {
                    "pre_dispatch_cleanup_failed": true,
                    "pre_dispatch_cleanup_faults": fault_entries,
                }
            })),
        );

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self
            .kernel
            .build_cancelled_response_with_metadata_and_payee_binding(
                self.request,
                PRE_DISPATCH_CLEANUP_FAULT_REASON,
                current_unix_timestamp(),
                self.matched_grant_index,
                metadata,
                self.receipt_context.verified_payee_binding.as_ref(),
            )
        {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "pre_dispatch_cleanup_fault_receipt_unrecorded",
                "failed to record pre-dispatch cleanup fault receipt"
            );
        }
    }
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        if !self.dispatch_started {
            // Pre-dispatch drop (or a panic unwinding before dispatch).
            // Nothing was written to the tool server, so no side effect is
            // possible: fully reverse every pre-execution mutation. A clean
            // unwind records NO cancellation receipt; a cleanup fault records
            // a signed fault receipt (see `handle_pre_dispatch_drop`).
            self.handle_pre_dispatch_drop();
            return;
        }

        // Flush the buffered nested child receipts FIRST. The child operations
        // completed and were signed before the parent evaluation was cancelled,
        // so on the append-only log they precede the parent cancellation
        // receipt recorded below. Without this flush the already-signed child
        // receipts would be discarded with the dropped future, leaving the
        // completed child requests off the log and breaking receipt-completeness.
        self.flush_buffered_child_receipts_from_drop();

        // Post-dispatch drop. The tool-server invoke was in flight; a side
        // effect MAY have executed. Fail closed: retain the runtime-
        // admission reservations (releasing a single-use destructive lease
        // here would license a replay) and ALWAYS record a cancellation
        // receipt so the executed-or-not side effect is on the append-only
        // log. The retained reservations are marked in the receipt metadata
        // so the burned lease is auditable and operator-recoverable.
        let receipt_metadata = self.kernel.ambiguous_dispatch_receipt_metadata(
            self.budget_mutation,
            self.payment_authorization,
            self.receipt_context.extra_metadata.clone(),
        );

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self
            .kernel
            .build_cancelled_response_with_metadata_and_payee_binding(
                self.request,
                POST_ADMISSION_DROP_REASON,
                current_unix_timestamp(),
                self.matched_grant_index,
                receipt_metadata,
                self.receipt_context.verified_payee_binding.as_ref(),
            )
        {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "post_admission_drop_receipt_unrecorded",
                "failed to record cancellation receipt for dropped post-admission invocation"
            );
        }

        // The dispatch commit landed but the return never did, so the operation
        // would stay non-terminal and reject every replay of this request id
        // until the next startup sweep. Terminalizing here refuses if a durable
        // outcome exists, so it cannot overwrite a return that did complete.
        if let Some(operation) = self.durable_operation {
            if let Err(error) = self
                .kernel
                .terminalize_dispatch_committed_admission(operation, current_unix_timestamp_ms())
            {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    audit_fault = "post_admission_drop_admission_unterminalized",
                    "failed to terminalize dropped post-dispatch admission"
                );
            }
        }
    }
}
