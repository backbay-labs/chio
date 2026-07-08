use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::{CapabilityToken, PaymentAuthorization, ToolCallRequest};

use super::{
    current_unix_timestamp, merge_metadata_objects, scope_pre_invocation_guard_evidence,
    ChioKernel, KernelError, PreExecutionBudgetMutation,
};

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";
const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
}

/// A single pre-dispatch cleanup step that failed. Collected so a signed fault
/// receipt can name the failing step and its redacted reason, letting an
/// operator locate a hold or reservation that may be stuck.
struct PreDispatchCleanupFault {
    step: &'static str,
    reason: String,
}

pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    budget_mutation: &'a PreExecutionBudgetMutation,
    payment_authorization: Option<&'a PaymentAuthorization>,
    receipt_context: PostAdmissionReceiptContext,
    armed: bool,
    dispatch_started: bool,
}

impl<'a> PostAdmissionDropGuard<'a> {
    pub(crate) fn new(
        kernel: &'a ChioKernel,
        request: &'a ToolCallRequest,
        cap: &'a CapabilityToken,
        matched_grant_index: Option<usize>,
        budget_mutation: &'a PreExecutionBudgetMutation,
        payment_authorization: Option<&'a PaymentAuthorization>,
        receipt_context: PostAdmissionReceiptContext,
    ) -> Self {
        Self {
            kernel,
            request,
            cap,
            matched_grant_index,
            budget_mutation,
            payment_authorization,
            receipt_context,
            armed: true,
            dispatch_started: false,
        }
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

    /// Reverse the pre-execution monetary hold, if any, and fold the
    /// reversal into the receipt metadata. Charge-gated: a `None`
    /// charge_result (every non-monetary grant) returns the base metadata
    /// unchanged. Errors are logged; a Drop impl cannot surface them.
    fn unwind_charge_from_drop(&self) -> Option<serde_json::Value> {
        let base = self.receipt_context.extra_metadata.clone();
        let Some(charge) = self.budget_mutation.charge_result() else {
            return base;
        };
        let unwind = self.kernel.unwind_aborted_monetary_invocation(
            self.request,
            self.cap,
            self.budget_mutation.charge_result(),
            self.payment_authorization,
        );
        match &unwind {
            Ok(Some(reverse)) => self.kernel.merge_budget_receipt_metadata(
                base,
                self.kernel
                    .budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
            ),
            Ok(None) => base,
            Err(error) => {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(error),
                    "failed to unwind dropped post-admission monetary invocation"
                );
                base
            }
        }
    }

    /// Fully unwind a future dropped BEFORE tool-server dispatch. No side
    /// effect is possible, so every pre-execution mutation is reversed: the
    /// monetary hold, an invocation-only budget increment (Finding A),
    /// runtime-admission reservations, and an admitted child/delegated
    /// capability budget share (Finding B). A clean unwind records NO receipt
    /// (the intended receipt-free exit). If ANY step fails, a signed fault
    /// receipt is recorded (Finding C) so a stuck hold/reservation is on the
    /// append-only log rather than silently burned. Best-effort from Drop:
    /// each step is attempted independently and failures are collected.
    fn handle_pre_dispatch_drop(&self) {
        let mut faults: Vec<PreDispatchCleanupFault> = Vec::new();

        // 1. Monetary hold reversal (budget charge + payment release/refund).
        if self.budget_mutation.charge_result().is_some() {
            if let Err(error) = self.kernel.unwind_aborted_monetary_invocation(
                self.request,
                self.cap,
                self.budget_mutation.charge_result(),
                self.payment_authorization,
            ) {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %reason,
                    "failed to unwind dropped pre-dispatch monetary invocation"
                );
                faults.push(PreDispatchCleanupFault {
                    step: "monetary_unwind",
                    reason,
                });
            }
        }

        // 2. Invocation-only budget reversal (Finding A). A non-monetary grant
        //    with `max_invocations` incremented the invocation counter at
        //    admission; reverse it so a never-dispatched call does not
        //    permanently consume a slot. Reuse the same primitive the
        //    pre-dispatch denial path uses, gated on the Invocation variant so
        //    a Charge (handled above) is not reversed twice.
        if matches!(
            self.budget_mutation,
            PreExecutionBudgetMutation::Invocation { .. }
        ) {
            if let Err(error) = self
                .kernel
                .reverse_pre_execution_budget_mutation(self.cap, self.budget_mutation)
            {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %reason,
                    "failed to reverse dropped pre-dispatch invocation budget"
                );
                faults.push(PreDispatchCleanupFault {
                    step: "invocation_reversal",
                    reason,
                });
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
                reason = %reason,
                "failed to release runtime-admission reservations on pre-dispatch drop"
            );
            faults.push(PreDispatchCleanupFault {
                step: "runtime_admission_release",
                reason,
            });
        }

        // 4. Admitted child/delegated capability budget release (Finding B). A
        //    delegated capability admitted its share of the parent budget at
        //    admission; release it or the share stays permanently recorded.
        //    Mirrors the pre-dispatch denial path.
        if let Err(error) = self.kernel.release_admitted_capability_budget(self.cap) {
            let reason = redacted!(&error).to_string();
            warn!(
                request_id = %self.request.request_id,
                reason = %reason,
                "failed to release admitted capability budget on pre-dispatch drop"
            );
            faults.push(PreDispatchCleanupFault {
                step: "child_budget_release",
                reason,
            });
        }

        // 5. Fault receipt (Finding C). Clean cleanup is receipt-free (the
        //    intended design); any fault records a signed receipt.
        if !faults.is_empty() {
            self.record_pre_dispatch_cleanup_fault_receipt(&faults);
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
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            PRE_DISPATCH_CLEANUP_FAULT_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            metadata,
        ) {
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

        // Charge-gated section: reverse the pre-execution monetary hold, if
        // any, folding the reversal into the post-dispatch receipt metadata.
        // Best-effort from a Drop context; a non-monetary grant returns the
        // base metadata unchanged.
        let reversed_metadata = self.unwind_charge_from_drop();

        // Post-dispatch drop. The tool-server invoke was in flight; a side
        // effect MAY have executed. Fail closed: retain the runtime-
        // admission reservations (releasing a single-use destructive lease
        // here would license a replay) and ALWAYS record a cancellation
        // receipt so the executed-or-not side effect is on the append-only
        // log (closes F02). The retained reservations are marked in the
        // receipt metadata so the burned lease is auditable and
        // operator-recoverable (closes the F08 audit gap).
        let receipt_metadata = self
            .kernel
            .mark_runtime_admission_reservations_retained_fail_closed(reversed_metadata);

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            POST_ADMISSION_DROP_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            receipt_metadata,
        ) {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "post_admission_drop_receipt_unrecorded",
                "failed to record cancellation receipt for dropped post-admission invocation"
            );
        }
    }
}

pub(crate) fn dispatch_error_precedes_tool_side_effect(error: &KernelError) -> bool {
    matches!(
        error,
        KernelError::ToolNotRegistered(_) | KernelError::UrlElicitationsRequired { .. }
    )
}
