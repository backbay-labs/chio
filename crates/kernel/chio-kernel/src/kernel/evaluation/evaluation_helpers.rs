use super::*;

/// Reason recorded on the signed fault receipt when a runtime-admission
/// reservation release FAILS during a URL-elicitation pre-dispatch unwind. The
/// elicitation arm returns `Err(UrlElicitationsRequired)` and records no
/// terminal receipt, so this fault receipt is the only append-only entry that
/// locates the possibly-stuck lease.
const URL_ELICITATION_CLEANUP_FAULT_REASON: &str =
    "runtime-admission reservation release failed during URL-elicitation pre-dispatch cleanup";

/// Reason recorded on the signed fault receipt when a BUDGET cleanup step (the
/// sibling-sum child-budget lease release or the pre-execution budget reversal)
/// FAILS during a URL-elicitation pre-dispatch unwind. Like the runtime-release
/// fault, the elicitation arm returns `Err(UrlElicitationsRequired)` and records
/// no terminal receipt, so this fault receipt is the only append-only entry that
/// locates the stuck child share or invocation/budget slot.
const URL_ELICITATION_BUDGET_CLEANUP_FAULT_REASON: &str =
    "budget cleanup failed during URL-elicitation pre-dispatch cleanup";

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `admit_capability_budget` return). Only then may cleanup release
    /// one: the reference-counted release frees the shared edge only when the
    /// last holder releases, so an overlapping evaluation that still holds it
    /// keeps its share and an oversubscribing sibling stays denied.
    pub(super) budget_lease_acquired: bool,
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

    /// Release runtime-admission reservations during a URL-elicitation
    /// pre-dispatch unwind, recording a signed fault receipt when the release
    /// FAILS. The URL-elicitation arm returns `Err(UrlElicitationsRequired)` to
    /// propagate the elicitation payload and so records NO terminal receipt; a
    /// failed reservation release would therefore leave the stuck lease on NO
    /// append-only entry. When
    /// `release_runtime_admission_reservations_for_pre_dispatch_denial` folds a
    /// `reservation_release_failed` marker into the returned metadata, record a
    /// signed cancellation/fault receipt naming the stuck lease id(s) and the
    /// failure reason (the standard pre-dispatch fault-receipt shape) so an
    /// operator can locate the possibly-stuck reservation. Best-effort: a
    /// receipt-recording failure is logged with an `audit_fault` field. The
    /// caller still returns `Err(UrlElicitationsRequired)`, preserving the
    /// elicitation response.
    pub(super) fn release_runtime_admission_reservations_for_url_elicitation_cleanup(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        metadata: Option<serde_json::Value>,
        pre_invocation_guard_evidence: &[chio_core::receipt::metadata::GuardEvidence],
    ) {
        let released =
            self.release_runtime_admission_reservations_for_pre_dispatch_denial(metadata);
        let runtime = released
            .as_ref()
            .and_then(|value| value.get("chio_runtime"))
            .and_then(serde_json::Value::as_object);
        let release_failed = runtime
            .and_then(|runtime| runtime.get("reservation_release_failed"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !release_failed {
            return;
        }
        // The `released` metadata already carries the stuck lease's reserved
        // ids and the `reservation_release_failure_reason`; fold in an explicit
        // cleanup-fault entry (step + reason + hold_ids) mirroring the standard
        // pre-dispatch fault-receipt shape so the stuck lease is queryable.
        let reason = runtime
            .and_then(|runtime| runtime.get("reservation_release_failure_reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("runtime admission reservation release failed")
            .to_string();
        let hold_ids = reserved_runtime_admission_ids(released.as_ref());
        let fault_metadata = merge_metadata_objects(
            released,
            Some(serde_json::json!({
                "chio_runtime": {
                    "pre_dispatch_cleanup_failed": true,
                    "pre_dispatch_cleanup_faults": [{
                        "step": "url_elicitation_runtime_admission_release",
                        "reason": reason,
                        "hold_ids": hold_ids,
                    }],
                }
            })),
        );
        let _guard_evidence_scope =
            scope_pre_invocation_guard_evidence(pre_invocation_guard_evidence.to_vec());
        if let Err(error) = self.build_cancelled_response_with_metadata(
            request,
            URL_ELICITATION_CLEANUP_FAULT_REASON,
            current_unix_timestamp(),
            Some(matched_grant_index),
            fault_metadata,
        ) {
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&error),
                audit_fault = "url_elicitation_cleanup_reservation_release_unrecorded",
                "failed to record URL-elicitation cleanup reservation-release fault receipt"
            );
        }
    }

    /// Record a signed fault receipt for a BUDGET cleanup step that FAILED
    /// during the URL-elicitation pre-dispatch unwind (Fix: the child-budget
    /// lease release and the pre-execution budget reversal now RECORD-AND-
    /// CONTINUE instead of `?`-short-circuiting, so a transient budget-store
    /// failure cannot replace the `Err(UrlElicitationsRequired)` response). The
    /// arm returns the elicitation error and records no terminal receipt, so
    /// without this the stuck child share / budget slot would land on NO
    /// append-only entry. Best-effort: a receipt-recording failure is logged
    /// with an `audit_fault` field; the caller still returns the elicitation
    /// error.
    // The fault receipt legitimately needs the request, grant, failing step,
    // reason, stuck hold ids, admission metadata, and guard evidence to locate
    // the stuck reservation; grouping them into a params struct would only
    // rename the same inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_url_elicitation_budget_cleanup_fault(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        step: &'static str,
        reason: &str,
        hold_ids: Vec<String>,
        metadata: Option<serde_json::Value>,
        pre_invocation_guard_evidence: &[chio_core::receipt::metadata::GuardEvidence],
    ) {
        let fault_metadata = merge_metadata_objects(
            metadata,
            Some(serde_json::json!({
                "chio_runtime": {
                    "pre_dispatch_cleanup_failed": true,
                    "pre_dispatch_cleanup_faults": [{
                        "step": step,
                        "reason": reason,
                        "hold_ids": hold_ids,
                    }],
                }
            })),
        );
        let _guard_evidence_scope =
            scope_pre_invocation_guard_evidence(pre_invocation_guard_evidence.to_vec());
        if let Err(error) = self.build_cancelled_response_with_metadata(
            request,
            URL_ELICITATION_BUDGET_CLEANUP_FAULT_REASON,
            current_unix_timestamp(),
            Some(matched_grant_index),
            fault_metadata,
        ) {
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&error),
                audit_fault = "url_elicitation_budget_cleanup_fault_unrecorded",
                "failed to record URL-elicitation budget cleanup fault receipt"
            );
        }
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        if denial.budget_lease_acquired {
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
    // and the budget-lease gate) needed to reverse it; grouping them into
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
        budget_lease_acquired: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        // Release this evaluation's sibling-sum child-budget lease only when it
        // acquired one; the reference-counted release frees the shared edge
        // only when the last holder releases (see `admit_capability_budget`).
        if budget_lease_acquired {
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
