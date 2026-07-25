use super::*;
use crate::admission_operation::AdmissionOperationV1;
use crate::budget_store::BudgetReverseHoldDecision;
use crate::kernel::responses::ReservedHoldStamp;

const EXECUTION_NONCE_PREFLIGHT_RETRY_REASON: &str =
    "execution nonce preflight requires retry with presented nonce";
const EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON: &str =
    "pre-execution authorization reserved; present the minted execution nonce to the tool server";

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) durable_operation: Option<&'a AdmissionOperationV1>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    pub(super) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `admit_capability_budget` return). Only then may cleanup release
    /// one: the reference-counted release frees the shared edge only when the
    /// last holder releases, so an overlapping evaluation that still holds it
    /// keeps its share and an oversubscribing sibling stays denied.
    pub(super) budget_lease_acquired: bool,
}

pub(super) struct ExecutionNonceReservingResponse<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    pub(super) reserved_payment_reference: Option<String>,
    pub(super) budget_lease_acquired: bool,
}

struct CleanupReleaseOutcome {
    metadata: Option<serde_json::Value>,
    confirmed: bool,
}

impl ChioKernel {
    pub(crate) fn compensate_durable_admission_after_pre_dispatch_cleanup(
        &self,
        operation: Option<&AdmissionOperationV1>,
        reverse: Option<&BudgetReverseHoldDecision>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<(), KernelError> {
        let Some(operation) = operation else {
            return Ok(());
        };
        self.compensate_durable_admission_before_dispatch(
            operation,
            serde_json::json!({
                "authority": "kernel-confirmed-pre-dispatch-cleanup",
                "budget_hold_id": reverse.and_then(|decision| decision.hold_id.as_deref()),
                "budget_event_id": reverse
                    .and_then(|decision| decision.metadata.event_id.as_deref()),
                "payment_authorization_id": payment_authorization
                    .map(|authorization| authorization.authorization_id.as_str())
            }),
            current_unix_timestamp_ms(),
        )
    }

    pub(super) fn with_pre_invocation_guard_evidence<T>(
        &self,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
        build: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(evidence.to_vec());
        build()
    }

    fn release_budget_lease_with_evidence(
        &self,
        cap: &CapabilityToken,
        lease_acquired: bool,
        metadata: Option<serde_json::Value>,
    ) -> CleanupReleaseOutcome {
        if !lease_acquired {
            return CleanupReleaseOutcome {
                metadata,
                confirmed: true,
            };
        }
        match self.release_admitted_capability_budget(cap) {
            Ok(()) => CleanupReleaseOutcome {
                metadata,
                confirmed: true,
            },
            Err(error) => {
                warn!(
                    capability_id = %cap.id,
                    reason = %redacted!(&error),
                    "admitted capability budget lease release could not be confirmed"
                );
                CleanupReleaseOutcome {
                    metadata: merge_metadata_objects(
                        metadata,
                        Some(serde_json::json!({
                            "budget_authority": {
                                "lease_release_unconfirmed": true,
                                "lease_retained": true,
                                "lease_capability_id": cap.id
                            }
                        })),
                    ),
                    confirmed: false,
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_capture_replay_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: usize,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_admission_metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        let (runtime_metadata, _) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        let runtime_metadata = self
            .release_budget_lease_with_evidence(cap, budget_lease_acquired, runtime_metadata)
            .metadata;
        let metadata = match budget_mutation.charge_result() {
            Some(charge) => self.merge_budget_receipt_metadata(
                runtime_metadata,
                self.budget_execution_receipt_metadata(charge, None, None),
            ),
            None => runtime_metadata,
        };
        self.build_deny_response_with_metadata_and_payee_binding(
            request,
            reason,
            timestamp,
            Some(matched_grant_index),
            metadata,
            verified_payee_binding,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_definite_payment_denial_after_capture(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        durable_operation: Option<&AdmissionOperationV1>,
        runtime_admission_metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        let (runtime_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        let lease_release =
            self.release_budget_lease_with_evidence(cap, budget_lease_acquired, runtime_metadata);
        let runtime_metadata = lease_release.metadata;
        let charge = budget_mutation.charge_result().ok_or_else(|| {
            KernelError::Internal(
                "captured payment denial is missing its monetary budget hold".to_string(),
            )
        })?;
        let cancellation = match self.cancel_captured_monetary_before_dispatch(&cap.id, charge) {
            Ok(cancellation) => cancellation,
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&internal_reason),
                    "captured budget cancellation could not be confirmed"
                );
                return self.build_deny_response_with_metadata_and_payee_binding(
                    request,
                    "captured budget cancellation could not be confirmed",
                    timestamp,
                    Some(charge.grant_index),
                    self.ambiguous_cancellation_receipt_metadata(charge, runtime_metadata),
                    verified_payee_binding,
                );
            }
        };
        if runtime_release_confirmed && lease_release.confirmed {
            self.compensate_durable_admission_after_pre_dispatch_cleanup(
                durable_operation,
                Some(&cancellation),
                None,
            )?;
        }
        self.build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
            request,
            reason,
            timestamp,
            charge,
            cancellation.committed_cost_units_after,
            cap,
            self.merge_budget_receipt_metadata(
                runtime_metadata,
                self.budget_execution_receipt_metadata(
                    charge,
                    Some(("cancelled_before_dispatch", &cancellation)),
                    None,
                ),
            ),
            verified_payee_binding,
        )
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let (runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        let lease_release = self.release_budget_lease_with_evidence(
            denial.cap,
            denial.budget_lease_acquired,
            runtime_admission_metadata,
        );
        let runtime_admission_metadata = lease_release.metadata;
        let reverse_result = match denial.payment_authorization {
            Some(payment_authorization) => self.unwind_pre_dispatch_monetary_invocation(
                denial.request,
                denial.cap,
                denial.budget_mutation.charge_result(),
                Some(payment_authorization),
            ),
            None => self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation),
        };
        let reverse = match reverse_result {
            Ok(reverse) => reverse,
            Err(error) => {
                warn!(
                    request_id = %denial.request.request_id,
                    reason = %redacted!(&error),
                    "pre-dispatch cleanup could not be confirmed"
                );
                let metadata = match denial.budget_mutation.durable_hold_result() {
                    Some(charge) if charge.invocation_capture.is_some() => self
                        .captured_admission_retained_receipt_metadata(
                            charge,
                            runtime_admission_metadata,
                        ),
                    Some(charge) => self.merge_budget_receipt_metadata(
                        runtime_admission_metadata,
                        self.budget_execution_receipt_metadata(charge, None, None),
                    ),
                    None => runtime_admission_metadata,
                };
                let metadata = merge_metadata_objects(
                    metadata,
                    Some(serde_json::json!({
                        "budget_authority": {
                            "pre_dispatch_cleanup_unconfirmed": true,
                            "admission_release_unconfirmed": true,
                            "admission_may_be_retained": true,
                            "cleanup_mutation_kind": match denial.budget_mutation {
                                PreExecutionBudgetMutation::Charge(_) => "charge",
                                PreExecutionBudgetMutation::Invocation { .. }
                                | PreExecutionBudgetMutation::InvocationHold(_) => "invocation",
                                PreExecutionBudgetMutation::None => "none",
                            },
                            "cleanup_capability_id": denial.cap.id,
                            "cleanup_grant_index": denial.matched_grant_index,
                            "cleanup_hold_id": denial.budget_mutation.durable_hold_result()
                                .map(|charge| charge.budget_hold_id.as_str()),
                            "cleanup_attempt_event_id": denial.budget_mutation.durable_hold_result()
                                .map(BudgetChargeResult::reverse_event_id),
                            "cleanup_attempt_event_id_available": denial.budget_mutation
                                .durable_hold_result().is_some()
                        }
                    })),
                );
                let metadata = match denial.payment_authorization {
                    Some(authorization) => merge_metadata_objects(
                        metadata,
                        Some(serde_json::json!({
                            "financial": {
                                "payment_reference": authorization.authorization_id,
                                "payment_authorization_may_be_retained": true,
                                "payment_unwind_unconfirmed": true,
                                "payment_unwind_attempt_reference": denial.request.request_id
                            }
                        })),
                    ),
                    None => metadata,
                };
                return self.build_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    "pre-dispatch cleanup could not be confirmed",
                    denial.timestamp,
                    Some(denial.matched_grant_index),
                    metadata,
                    denial.verified_payee_binding,
                );
            }
        };
        if runtime_release_confirmed && lease_release.confirmed {
            self.compensate_durable_admission_after_pre_dispatch_cleanup(
                denial.durable_operation,
                reverse.as_ref(),
                denial.payment_authorization,
            )?;
        }

        if let (Some(charge), Some(reverse)) =
            (denial.budget_mutation.charge_result(), reverse.as_ref())
        {
            return self
                .build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    denial.reason,
                    denial.timestamp,
                    charge,
                    reverse.committed_cost_units_after,
                    denial.cap,
                    self.merge_budget_receipt_metadata(
                        runtime_admission_metadata,
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                            None,
                        ),
                    ),
                    denial.verified_payee_binding,
                );
        }

        self.build_deny_response_with_metadata_and_payee_binding(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
            denial.verified_payee_binding,
        )
    }

    pub(super) fn build_nonce_denial_after_monetary_cleanup(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let (runtime_metadata, _) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        let runtime_metadata = self
            .release_budget_lease_with_evidence(
                denial.cap,
                denial.budget_lease_acquired,
                runtime_metadata,
            )
            .metadata;
        let charge = denial.budget_mutation.charge_result().ok_or_else(|| {
            KernelError::Internal("monetary nonce cleanup is missing its budget hold".to_string())
        })?;

        let payment_release_metadata = match denial.payment_authorization {
            Some(authorization) => {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                let (release, expected_status) = if authorization.state.is_final() {
                    (
                        adapter.refund(
                            &authorization.authorization_id,
                            charge.cost_charged,
                            &charge.currency,
                            &denial.request.request_id,
                        ),
                        RailSettlementStatus::Refunded,
                    )
                } else {
                    (
                        adapter
                            .release(&authorization.authorization_id, &denial.request.request_id),
                        RailSettlementStatus::Released,
                    )
                };
                match release {
                    Ok(result) if result.settlement_status == expected_status => {
                        Some(serde_json::json!({
                            "financial": {
                                "payment_reference": authorization.authorization_id,
                                "payment_release_reference": result.transaction_id,
                                "payment_release_confirmed": true,
                                "payment_release_attempt_reference": denial.request.request_id
                            }
                        }))
                    }
                    Ok(result) => {
                        let status = match result.settlement_status {
                            RailSettlementStatus::Authorized => "authorized",
                            RailSettlementStatus::Captured => "captured",
                            RailSettlementStatus::Settled => "settled",
                            RailSettlementStatus::Pending => "pending",
                            RailSettlementStatus::Failed => "failed",
                            RailSettlementStatus::Released => "released",
                            RailSettlementStatus::Refunded => "refunded",
                        };
                        warn!(
                            request_id = %denial.request.request_id,
                            payment_status = status,
                            "payment release returned an unexpected result after nonce denial"
                        );
                        let metadata = merge_metadata_objects(
                            self.captured_admission_retained_receipt_metadata(
                                charge,
                                runtime_metadata,
                            ),
                            Some(serde_json::json!({
                                "financial": {
                                    "payment_reference": authorization.authorization_id,
                                    "payment_authorization_retained": true,
                                    "payment_release_reference": result.transaction_id,
                                    "payment_release_status": status,
                                    "payment_release_unconfirmed": true,
                                    "payment_release_attempt_reference": denial.request.request_id
                                }
                            })),
                        );
                        return self.build_deny_response_with_metadata_and_payee_binding(
                            denial.request,
                            "payment release could not be confirmed after execution nonce denial",
                            denial.timestamp,
                            Some(denial.matched_grant_index),
                            metadata,
                            denial.verified_payee_binding,
                        );
                    }
                    Err(error) => {
                        warn!(
                            request_id = %denial.request.request_id,
                            reason = %redacted!(&error),
                            "payment release could not be confirmed after nonce denial"
                        );
                        let metadata = merge_metadata_objects(
                            self.captured_admission_retained_receipt_metadata(
                                charge,
                                runtime_metadata,
                            ),
                            Some(serde_json::json!({
                                "financial": {
                                    "payment_reference": authorization.authorization_id,
                                    "payment_authorization_retained": true,
                                    "payment_release_unconfirmed": true,
                                    "payment_release_attempt_reference": denial.request.request_id
                                }
                            })),
                        );
                        return self.build_deny_response_with_metadata_and_payee_binding(
                            denial.request,
                            "payment release could not be confirmed after execution nonce denial",
                            denial.timestamp,
                            Some(denial.matched_grant_index),
                            metadata,
                            denial.verified_payee_binding,
                        );
                    }
                }
            }
            None => None,
        };

        let cancellation = match self
            .cancel_captured_monetary_before_dispatch(&denial.cap.id, charge)
        {
            Ok(cancellation) => cancellation,
            Err(error) => {
                warn!(
                    request_id = %denial.request.request_id,
                    reason = %redacted!(&error),
                    "captured budget cancellation could not be confirmed after nonce denial"
                );
                let metadata = merge_metadata_objects(
                    self.ambiguous_cancellation_receipt_metadata(charge, runtime_metadata),
                    payment_release_metadata,
                );
                return self.build_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    "captured budget cancellation could not be confirmed after execution nonce denial",
                    denial.timestamp,
                    Some(charge.grant_index),
                    metadata,
                    denial.verified_payee_binding,
                );
            }
        };

        self.build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
            denial.request,
            denial.reason,
            denial.timestamp,
            charge,
            cancellation.committed_cost_units_after,
            denial.cap,
            merge_metadata_objects(
                self.merge_budget_receipt_metadata(
                    runtime_metadata,
                    self.budget_execution_receipt_metadata(
                        charge,
                        Some(("cancelled_before_dispatch", &cancellation)),
                        None,
                    ),
                ),
                payment_release_metadata,
            ),
            denial.verified_payee_binding,
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
        durable_operation: Option<&AdmissionOperationV1>,
        runtime_admission_metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let (runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        // Release this evaluation's sibling-sum child-budget lease only when it
        // acquired one; the reference-counted release frees the shared edge
        // only when the last holder releases (see `admit_capability_budget`).
        let lease_release = self.release_budget_lease_with_evidence(
            cap,
            budget_lease_acquired,
            runtime_admission_metadata,
        );
        let runtime_admission_metadata = lease_release.metadata;
        let reverse = match self.reverse_pre_execution_budget_mutation(cap, budget_mutation) {
            Ok(reverse) => reverse,
            Err(error) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "execution nonce preflight cleanup could not be confirmed"
                );
                let budget_metadata = budget_mutation
                    .durable_hold_result()
                    .map(|charge| self.budget_execution_receipt_metadata(charge, None, None));
                let metadata = merge_metadata_objects(
                    merge_metadata_objects(runtime_admission_metadata, budget_metadata),
                    Some(serde_json::json!({
                        "execution_nonce": {
                            "stage": "preflight",
                            "tool_dispatched": false,
                            "cleanup_unconfirmed": true
                        },
                        "budget_authority": {
                            "admission_release_unconfirmed": true,
                            "admission_may_be_retained": true,
                            "cleanup_mutation_kind": match budget_mutation {
                                PreExecutionBudgetMutation::Charge(_) => "charge",
                                PreExecutionBudgetMutation::Invocation { .. }
                                | PreExecutionBudgetMutation::InvocationHold(_) => "invocation",
                                PreExecutionBudgetMutation::None => "none",
                            },
                            "cleanup_capability_id": cap.id,
                            "cleanup_grant_index": matched_grant_index,
                            "cleanup_hold_id": budget_mutation.durable_hold_result()
                                .map(|charge| charge.budget_hold_id.as_str()),
                            "cleanup_attempt_event_id": budget_mutation.durable_hold_result()
                                .map(BudgetChargeResult::reverse_event_id),
                            "cleanup_attempt_event_id_available": budget_mutation
                                .durable_hold_result().is_some()
                        }
                    })),
                );
                return self.build_deny_response_with_metadata(
                    request,
                    "execution nonce preflight cleanup could not be confirmed",
                    timestamp,
                    Some(matched_grant_index),
                    metadata,
                );
            }
        };
        let budget_metadata = match (budget_mutation.durable_hold_result(), reverse.as_ref()) {
            (Some(charge), Some(reverse)) => Some(self.budget_execution_receipt_metadata(
                charge,
                Some(("reversed", reverse)),
                None,
            )),
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

        if !runtime_release_confirmed || !lease_release.confirmed {
            return self.build_deny_response_with_metadata(
                request,
                "execution nonce preflight cleanup could not be confirmed",
                timestamp,
                Some(matched_grant_index),
                metadata,
            );
        }

        self.compensate_durable_admission_after_pre_dispatch_cleanup(
            durable_operation,
            reverse.as_ref(),
            None,
        )?;

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
            EXECUTION_NONCE_PREFLIGHT_RETRY_REASON,
            None,
        )
    }

    pub(super) fn build_execution_nonce_authorization_reserving_response(
        &self,
        reserving: ExecutionNonceReservingResponse<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let ExecutionNonceReservingResponse {
            request,
            timestamp,
            matched_grant_index,
            budget_mutation,
            runtime_admission_metadata,
            reserved_payment_reference,
            budget_lease_acquired,
        } = reserving;
        let (runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        if !runtime_release_confirmed {
            return self.build_deny_response_with_metadata(
                request,
                "execution nonce authorization cleanup could not be confirmed",
                timestamp,
                Some(matched_grant_index),
                runtime_admission_metadata,
            );
        }

        if matches!(budget_mutation, PreExecutionBudgetMutation::None) && budget_lease_acquired {
            self.release_admitted_capability_budget(&request.capability)
                .map_err(KernelError::DelegationInvalid)?;
        }

        let budget_metadata = budget_mutation
            .durable_hold_result()
            .map(|charge| self.budget_execution_receipt_metadata(charge, None, None));
        let metadata = merge_metadata_objects(
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            Some(serde_json::json!({
                "execution_nonce": {
                    "stage": "authorization",
                    "tool_dispatched": false,
                    "hold_disposition": "reserved"
                }
            })),
        );

        let reserved_hold = match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => Some(ReservedHoldStamp::Monetary {
                charge,
                payment_reference: reserved_payment_reference,
            }),
            PreExecutionBudgetMutation::InvocationHold(charge) => {
                Some(ReservedHoldStamp::Monetary {
                    charge,
                    payment_reference: reserved_payment_reference,
                })
            }
            PreExecutionBudgetMutation::Invocation { grant_index } => {
                Some(ReservedHoldStamp::Invocation {
                    hold_id: format!(
                        "budget-hold:{}:{}:{}",
                        request.request_id, request.capability.id, grant_index
                    ),
                    grant_index: *grant_index,
                })
            }
            PreExecutionBudgetMutation::None => None,
        };

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
            EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON,
            reserved_hold,
        )
    }
}
