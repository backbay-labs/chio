use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::{CapabilityToken, PaymentAuthorization, ToolCallRequest};

use super::{
    current_unix_timestamp, scope_pre_invocation_guard_evidence, BudgetChargeResult, ChioKernel,
    KernelError,
};

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after monetary admission";

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
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let Some(charge) = self.charge_result else {
            return;
        };

        let unwind = self.kernel.unwind_aborted_monetary_invocation(
            self.request,
            self.cap,
            self.charge_result,
            self.payment_authorization,
        );
        let extra_metadata = match &unwind {
            Ok(Some(reverse)) => self.kernel.merge_budget_receipt_metadata(
                self.receipt_context.extra_metadata.clone(),
                self.kernel
                    .budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
            ),
            Ok(None) => self.receipt_context.extra_metadata.clone(),
            Err(error) => {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(error),
                    "failed to unwind dropped post-admission monetary invocation"
                );
                self.receipt_context.extra_metadata.clone()
            }
        };

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            POST_ADMISSION_DROP_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            extra_metadata,
        ) {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
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
