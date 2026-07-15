use super::*;

const EXECUTION_NONCE_PREFLIGHT_CLEANUP_FAULT_REASON: &str =
    "execution nonce preflight cleanup failed";

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) evaluation_context: &'a EvaluationReceiptContext,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) receipt_metadata: Option<serde_json::Value>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `admit_capability_budget` return). Only then may cleanup release
    /// one: the reference-counted release frees the shared edge only when the
    /// last holder releases, so an overlapping evaluation that still holds it
    /// keeps its share and an oversubscribing sibling stays denied.
    pub(super) budget_lease_acquired: bool,
}

impl ChioKernel {
    pub(super) fn cleanup_pre_admission_budget_state(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        receipt_metadata: Option<serde_json::Value>,
        runtime_admission_metadata: Option<serde_json::Value>,
    ) -> PreDispatchCleanupOutcome {
        self.cleanup_pre_dispatch_state(PreDispatchCleanup {
            request,
            cap,
            budget_mutation,
            payment_authorization: None,
            payment_authorization_outcome_unknown: None,
            payment_credential_disposition: PaymentCredentialDisposition::NonePresent,
            receipt_metadata,
            runtime_admission_metadata,
            budget_lease_acquired: false,
        })
    }

    pub(super) fn with_pre_invocation_guard_evidence<T>(
        &self,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
        build: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(evidence.to_vec());
        build()
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_dispatch_cleanup_deny_response_with_payment_outcome(
            denial,
            None,
            PaymentCredentialDisposition::NonePresent,
        )
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response_with_credentials(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        payment_credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_dispatch_cleanup_deny_response_with_payment_outcome(
            denial,
            None,
            payment_credential_disposition,
        )
    }

    pub(super) fn build_payment_authorization_outcome_unknown_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        outcome_unknown_reason: &str,
        payment_credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_dispatch_cleanup_deny_response_with_payment_outcome(
            denial,
            Some(outcome_unknown_reason),
            payment_credential_disposition,
        )
    }

    fn build_pre_dispatch_cleanup_deny_response_with_payment_outcome(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        outcome_unknown_reason: Option<&str>,
        payment_credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        let cleanup = self.cleanup_pre_dispatch_state(PreDispatchCleanup {
            request: denial.request,
            cap: denial.cap,
            budget_mutation: denial.budget_mutation,
            payment_authorization: denial.payment_authorization,
            payment_authorization_outcome_unknown: outcome_unknown_reason,
            payment_credential_disposition,
            receipt_metadata: denial.receipt_metadata,
            runtime_admission_metadata: denial.runtime_admission_metadata,
            budget_lease_acquired: denial.budget_lease_acquired,
        });

        if let (Some(charge), Some(reverse)) = (
            denial.budget_mutation.charge_result(),
            cleanup.reverse.as_ref(),
        ) {
            return self.build_pre_execution_monetary_deny_response_with_metadata(
                denial.request,
                denial.evaluation_context,
                denial.reason,
                denial.timestamp,
                charge,
                reverse.committed_cost_units_after,
                denial.cap,
                self.merge_budget_receipt_metadata(
                    cleanup.metadata,
                    self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
                ),
            );
        }

        self.build_deny_response_with_metadata(
            denial.request,
            denial.evaluation_context,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            cleanup.metadata,
        )
    }

    pub(super) fn build_pre_dispatch_cleanup_cancelled_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_dispatch_cleanup_cancelled_response_with_credentials(
            denial,
            PaymentCredentialDisposition::NonePresent,
        )
    }

    pub(super) fn build_pre_dispatch_cleanup_cancelled_response_with_credentials(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        payment_credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        let cleanup = self.cleanup_pre_dispatch_state(PreDispatchCleanup {
            request: denial.request,
            cap: denial.cap,
            budget_mutation: denial.budget_mutation,
            payment_authorization: denial.payment_authorization,
            payment_authorization_outcome_unknown: None,
            payment_credential_disposition,
            receipt_metadata: denial.receipt_metadata,
            runtime_admission_metadata: denial.runtime_admission_metadata,
            budget_lease_acquired: denial.budget_lease_acquired,
        });
        let metadata = match (
            denial.budget_mutation.charge_result(),
            cleanup.reverse.as_ref(),
        ) {
            (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                cleanup.metadata,
                self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
            ),
            _ => cleanup.metadata,
        };
        self.build_cancelled_response_with_metadata(
            denial.request,
            denial.evaluation_context,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            metadata,
        )
    }

    // The preflight-allow cleanup legitimately threads the full pre-dispatch
    // state (request, grant, capability, budget mutation, admission metadata,
    // and the budget-lease gate) needed to reverse it; grouping them into
    // a params struct would only rename the same inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_execution_nonce_preflight_allow_response_after_cleanup(
        &self,
        request: &ToolCallRequest,
        evaluation_context: &EvaluationReceiptContext,
        timestamp: u64,
        matched_grant_index: usize,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        receipt_metadata: Option<serde_json::Value>,
        runtime_admission_metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let cleanup = self.cleanup_pre_dispatch_state(PreDispatchCleanup {
            request,
            cap,
            budget_mutation,
            payment_authorization: None,
            payment_authorization_outcome_unknown: None,
            payment_credential_disposition: PaymentCredentialDisposition::NonePresent,
            receipt_metadata,
            runtime_admission_metadata,
            budget_lease_acquired,
        });
        let budget_metadata = match (budget_mutation.charge_result(), cleanup.reverse.as_ref()) {
            (Some(charge), Some(reverse)) => {
                Some(self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))))
            }
            _ => None,
        };
        let preflight_metadata = Some(serde_json::json!({
            "execution_nonce": {
                "stage": "preflight",
                "tool_dispatched": false
            }
        }));
        let metadata = merge_metadata_objects(
            merge_metadata_objects(cleanup.metadata, budget_metadata),
            preflight_metadata,
        );

        if !cleanup.faults.is_empty() {
            return self.build_deny_response_with_metadata(
                request,
                evaluation_context,
                EXECUTION_NONCE_PREFLIGHT_CLEANUP_FAULT_REASON,
                timestamp,
                Some(matched_grant_index),
                metadata,
            );
        }

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            evaluation_context,
            timestamp,
            Some(matched_grant_index),
            metadata,
        )
    }
}
