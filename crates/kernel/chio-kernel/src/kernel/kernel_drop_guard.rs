use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::{CapabilityToken, PaymentAuthorization, ToolCallRequest};

use super::{
    current_unix_timestamp, scope_pre_invocation_guard_evidence, BudgetChargeResult, ChioKernel,
    KernelError,
};

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
}

pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    charge_result: Option<&'a BudgetChargeResult>,
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
        charge_result: Option<&'a BudgetChargeResult>,
        payment_authorization: Option<&'a PaymentAuthorization>,
        receipt_context: PostAdmissionReceiptContext,
    ) -> Self {
        Self {
            kernel,
            request,
            cap,
            matched_grant_index,
            charge_result,
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
        let Some(charge) = self.charge_result else {
            return base;
        };
        let unwind = self.kernel.unwind_aborted_monetary_invocation(
            self.request,
            self.cap,
            self.charge_result,
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
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // Charge-gated section: reverse the pre-execution monetary hold,
        // if any. Best-effort from a Drop context; a non-monetary grant
        // returns the base metadata unchanged.
        let reversed_metadata = self.unwind_charge_from_drop();

        if !self.dispatch_started {
            // Pre-dispatch drop (or a panic unwinding before dispatch).
            // Nothing was written to the tool server, so no side effect is
            // possible. Safe-release the runtime-admission reservations and
            // record NO cancellation receipt: there is no executed action
            // to audit, and the monetary hold is already reversed above.
            if let Err(error) = self.kernel.release_runtime_admission_reservations(
                self.receipt_context.extra_metadata.as_ref(),
            ) {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to release runtime-admission reservations on pre-dispatch drop"
                );
            }
            return;
        }

        // Post-dispatch drop. The tool-server invoke was in flight; a side
        // effect MAY have executed. Fail closed: retain the runtime-
        // admission reservations (releasing a single-use destructive lease
        // here would license a replay) and ALWAYS record a cancellation
        // receipt so the executed-or-not side effect is on the append-only
        // log (closes F02).
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            POST_ADMISSION_DROP_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            reversed_metadata,
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
