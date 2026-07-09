use super::*;

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    /// Whether THIS evaluation newly inserted the sibling-sum child admission
    /// (the `admit_capability_budget` return). Only then may cleanup release
    /// it: releasing an idempotent re-admit would free a still-valid sibling
    /// reservation and let an oversubscribing sibling bypass the parent cap.
    pub(super) admitted_new_child: bool,
}

impl ChioKernel {
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
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        if denial.admitted_new_child {
            self.release_admitted_capability_budget(denial.cap)
                .map_err(KernelError::DelegationInvalid)?;
        }
        let reverse = match denial.payment_authorization {
            Some(payment_authorization) => self.unwind_aborted_monetary_invocation(
                denial.request,
                denial.cap,
                denial.budget_mutation.charge_result(),
                Some(payment_authorization),
            )?,
            None => {
                self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?
            }
        };

        if let (Some(charge), Some(reverse)) =
            (denial.budget_mutation.charge_result(), reverse.as_ref())
        {
            return self.build_pre_execution_monetary_deny_response_with_metadata(
                denial.request,
                denial.reason,
                denial.timestamp,
                charge,
                reverse.committed_cost_units_after,
                denial.cap,
                self.merge_budget_receipt_metadata(
                    runtime_admission_metadata,
                    self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
                ),
            );
        }

        self.build_deny_response_with_metadata(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
        )
    }

    // The preflight-allow cleanup legitimately threads the full pre-dispatch
    // state (request, grant, capability, budget mutation, admission metadata,
    // and the admitted-new-child gate) needed to reverse it; grouping them into
    // a params struct would only rename the same inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_execution_nonce_preflight_allow_response_after_cleanup(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: usize,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_admission_metadata: Option<serde_json::Value>,
        admitted_new_child: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        // Release the sibling-sum child admission only when this evaluation
        // inserted it; an idempotent re-admit's reservation belongs to an
        // earlier evaluation (see `admit_capability_budget`).
        if admitted_new_child {
            self.release_admitted_capability_budget(cap)
                .map_err(KernelError::DelegationInvalid)?;
        }
        let reverse = self.reverse_pre_execution_budget_mutation(cap, budget_mutation)?;
        let budget_metadata = match (budget_mutation.charge_result(), reverse.as_ref()) {
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
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            preflight_metadata,
        );

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
        )
    }
}
