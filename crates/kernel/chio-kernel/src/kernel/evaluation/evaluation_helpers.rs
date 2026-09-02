use super::*;
use crate::admission_operation::AdmissionOperationV1;
use crate::budget_store::BudgetReverseHoldDecision;
use crate::kernel::dispatch::PreDispatchMonetaryUnwindFailure;
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

pub(crate) struct OrdinaryRecoveryFinalization<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) output: ToolServerOutput,
    pub(crate) elapsed: Duration,
    pub(crate) timestamp: u64,
    pub(crate) matched_grant_index: usize,
    pub(crate) cost: FinalizeToolOutputCostContext<'a>,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(crate) payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub(crate) recovery: Option<&'a crate::finding_recovery::VerifiedFindingRecovery>,
}

struct CleanupReleaseOutcome {
    metadata: Option<serde_json::Value>,
    confirmed: bool,
}

/// True when a grant carries a delivery carrier constraint: a committed
/// output digest or a purchase marker.
fn grant_is_delivery_marked(grant: &chio_core::capability::scope::ToolGrant) -> bool {
    grant.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::OutputDigestSha256(_) | Constraint::RequireFindingPurchase(_)
        )
    })
}

/// Resolves the only grant that may carry a delivery for this call. The
/// selected grant is validated before durable admission, approval, guards,
/// or budget mutation, and callers restrict grant selection to the returned
/// index. Recovery applies the same rule to the recorded selection.
pub(crate) fn required_delivery_grant_index(
    matching_grants: &[MatchingGrant<'_>],
) -> Result<Option<usize>, &'static str> {
    let mut marked = matching_grants
        .iter()
        .filter(|matching| grant_is_delivery_marked(matching.grant));
    let Some(required) = marked.next() else {
        return Ok(None);
    };
    if marked.next().is_some() {
        return Err("delivery-marked grant candidates are ambiguous for this call");
    }
    if required
        .grant
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, Constraint::RequireFindingPurchase(_)))
        && matching_grants.len() != 1
    {
        return Err("a purchase-marked call requires exactly one matching grant");
    }
    if let Some(reason) = delivery_commitment_denial(required.grant) {
        return Err(reason);
    }
    Ok(Some(required.index))
}

/// Checks a recorded selection against the delivery policy derived from the
/// complete matching-grant set.
pub(crate) fn delivery_marked_selection_denial(
    matching_grants: &[MatchingGrant<'_>],
    matched_grant_index: usize,
) -> Option<&'static str> {
    match required_delivery_grant_index(matching_grants) {
        Err(reason) => Some(reason),
        Ok(Some(required)) if required != matched_grant_index => {
            Some("a delivery-marked grant cannot be bypassed by sibling grant selection")
        }
        Ok(_) => None,
    }
}

/// The validity rule for the selected grant's delivery commitment,
/// enforced before any hold is placed. A grant that fixes a delivery must
/// fix exactly one committed digest in canonical form: a second digest, a
/// non-canonical value, the fixed no-output content hash, or a purchase
/// marker missing its paired digest could otherwise run the tool and then
/// sign a receipt violating the registered delivery-contract schema, or
/// strand the operation in finalization with its hold open.
pub(crate) fn delivery_commitment_denial(
    grant: &chio_core::capability::scope::ToolGrant,
) -> Option<&'static str> {
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest.as_str())
        } else {
            None
        }
    });
    let first = digests.next();
    let ambiguous = digests.next().is_some();
    let Some(digest) = first else {
        let marked = grant
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::RequireFindingPurchase(_)));
        return marked
            .then_some("a purchase-marked grant requires exactly one committed output digest");
    };
    if ambiguous {
        return Some("a grant may commit at most one output digest");
    }
    if crate::admission_operation::AdmissionDigest::try_new(
        "expected_output_digest",
        digest.to_owned(),
    )
    .is_err()
    {
        return Some("a committed output digest must be canonical lowercase sha-256 hex");
    }
    if digest == chio_core::crypto::sha256_hex(b"null") {
        return Some("a committed output digest must not be the fixed no-output content hash");
    }
    None
}

impl ChioKernel {
    pub(crate) fn finalize_ordinary_recovery_response(
        &self,
        finalization: OrdinaryRecoveryFinalization<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let metadata = crate::kernel::delivery_contract::attach_finding_recovery_metadata(
            finalization.metadata,
            finalization.recovery,
        );
        if finalization.recovery.is_some() {
            return Err(KernelError::DurableAdmission(
                "finding recovery requires an atomic durable admission terminal projection"
                    .to_owned(),
            ));
        }
        self.with_pre_invocation_guard_evidence(finalization.guard_evidence, || {
            self.finalize_budgeted_tool_output_with_cost_and_metadata(
                finalization.request,
                finalization.output,
                finalization.elapsed,
                finalization.timestamp,
                finalization.matched_grant_index,
                finalization.cost,
                metadata,
                finalization.payee_binding,
            )
        })
    }

    pub(crate) fn compensate_durable_admission_after_pre_dispatch_cleanup(
        &self,
        operation: Option<&AdmissionOperationV1>,
        reverse: Option<&BudgetReverseHoldDecision>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<(), KernelError> {
        self.compensate_durable_admission_after_pre_dispatch_cleanup_with_payment_unwind(
            operation,
            reverse,
            payment_authorization,
            None,
        )
    }

    fn compensate_durable_admission_after_pre_dispatch_cleanup_with_payment_unwind(
        &self,
        operation: Option<&AdmissionOperationV1>,
        reverse: Option<&BudgetReverseHoldDecision>,
        payment_authorization: Option<&PaymentAuthorization>,
        payment_unwind: Option<&PreDispatchPaymentUnwindEvidence>,
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
            payment_unwind,
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

    pub(super) fn merge_dispatch_credential_disposition_metadata(
        &self,
        metadata: Option<serde_json::Value>,
        disposition: PaymentCredentialDisposition,
    ) -> Option<serde_json::Value> {
        if disposition == PaymentCredentialDisposition::NonePresent {
            return metadata;
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({
                "chio_runtime": {
                    "payment_credential_disposition": disposition,
                    "dispatch_credential_disposition": disposition,
                    "dispatch_credential_retention_outcome_unknown":
                        disposition == PaymentCredentialDisposition::RetentionOutcomeUnknown
                }
            })),
        )
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
        self.build_pre_dispatch_cleanup_deny_response_with_credentials(
            denial,
            PaymentCredentialDisposition::NonePresent,
        )
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response_with_credentials(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self.merge_dispatch_credential_disposition_metadata(
            denial.runtime_admission_metadata,
            credential_disposition,
        );
        let (runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        let lease_release = self.release_budget_lease_with_evidence(
            denial.cap,
            denial.budget_lease_acquired,
            runtime_admission_metadata,
        );
        let runtime_admission_metadata = lease_release.metadata;
        let reverse_result = match denial.payment_authorization {
            Some(payment_authorization) => self
                .unwind_pre_dispatch_monetary_invocation_with_evidence(
                    denial.request,
                    denial.cap,
                    denial.budget_mutation.charge_result(),
                    Some(payment_authorization),
                    credential_disposition,
                ),
            None => self
                .reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)
                .map(|reverse| (reverse, None))
                .map_err(PreDispatchMonetaryUnwindFailure::from),
        };
        let (reverse, unwind_evidence) = match reverse_result {
            Ok(result) => result,
            Err(failure) => {
                warn!(
                    request_id = %denial.request.request_id,
                    reason = %redacted!(&failure.error),
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
                let metadata = match failure.evidence {
                    Some(evidence) => merge_metadata_objects(
                        metadata,
                        Some(serde_json::json!({
                            "chio_runtime": {
                                "pre_dispatch_payment_unwind": evidence
                            }
                        })),
                    ),
                    None => match denial.payment_authorization {
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
                    },
                };
                return self.build_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    &format!(
                        "{}; pre-dispatch cleanup could not be confirmed: {}",
                        denial.reason, failure.error
                    ),
                    denial.timestamp,
                    Some(denial.matched_grant_index),
                    metadata,
                    denial.verified_payee_binding,
                );
            }
        };
        let runtime_admission_metadata = match unwind_evidence {
            Some(ref evidence) => merge_metadata_objects(
                runtime_admission_metadata,
                Some(serde_json::json!({
                    "chio_runtime": {
                        "pre_dispatch_payment_unwind": evidence
                    }
                })),
            ),
            None => runtime_admission_metadata,
        };
        if runtime_release_confirmed && lease_release.confirmed {
            self.compensate_durable_admission_after_pre_dispatch_cleanup_with_payment_unwind(
                denial.durable_operation,
                reverse.as_ref(),
                denial.payment_authorization,
                unwind_evidence.as_ref(),
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

    #[allow(dead_code)]
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

#[cfg(test)]
mod delivery_candidate_tests {
    use super::*;

    fn grant(constraints: Vec<Constraint>) -> ToolGrant {
        ToolGrant {
            server_id: "server".to_owned(),
            tool_name: "tool".to_owned(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn matching(index: usize, grant: &ToolGrant) -> MatchingGrant<'_> {
        MatchingGrant {
            index,
            grant,
            specificity: (0, 0, 0),
        }
    }

    #[test]
    fn delivery_candidate_policy_is_singular_closed_and_canonical() {
        let digest = chio_core::crypto::sha256_hex(b"delivery");
        let marked = grant(vec![Constraint::OutputDigestSha256(digest.clone())]);
        let sibling = grant(Vec::new());
        assert_eq!(
            required_delivery_grant_index(&[matching(3, &marked), matching(7, &sibling)]),
            Ok(Some(3))
        );
        assert_eq!(
            delivery_marked_selection_denial(&[matching(3, &marked), matching(7, &sibling)], 7,),
            Some("a delivery-marked grant cannot be bypassed by sibling grant selection")
        );

        let second = grant(vec![Constraint::OutputDigestSha256(digest)]);
        assert_eq!(
            required_delivery_grant_index(&[matching(3, &marked), matching(7, &second)]),
            Err("delivery-marked grant candidates are ambiguous for this call")
        );

        let malformed = grant(vec![Constraint::OutputDigestSha256("zz".to_owned())]);
        assert_eq!(
            required_delivery_grant_index(&[matching(3, &malformed)]),
            Err("a committed output digest must be canonical lowercase sha-256 hex")
        );
    }

    #[test]
    fn purchase_marked_delivery_requires_one_matching_grant() {
        let purchase = grant(vec![
            Constraint::OutputDigestSha256(chio_core::crypto::sha256_hex(b"delivery")),
            Constraint::RequireFindingPurchase(Box::new(
                chio_core::capability::scope::FindingPurchaseMarkerV1 {
                    finding_id: "finding-1".to_owned(),
                    listing_id: "listing-1".to_owned(),
                    settlement:
                        chio_core::capability::scope::FindingSettlementSelector::LocalReversibleHold,
                },
            )),
        ]);
        let sibling = grant(Vec::new());
        assert_eq!(
            required_delivery_grant_index(&[matching(1, &purchase), matching(2, &sibling)]),
            Err("a purchase-marked call requires exactly one matching grant")
        );
        assert_eq!(
            required_delivery_grant_index(&[matching(1, &purchase)]),
            Ok(Some(1))
        );
    }
}
