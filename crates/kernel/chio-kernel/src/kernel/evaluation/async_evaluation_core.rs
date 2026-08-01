use super::evaluation_helpers::{ExecutionNonceReservingResponse, PreDispatchCleanupDeny};
use super::*;
use crate::budget_store::BudgetInvocationCaptureDecision;

impl ChioKernel {
    pub(super) async fn evaluate_tool_call_async_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
        preflight_disposition: PreflightHoldDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        // Resolve tenant_id from the session's enterprise identity context
        // (if any) and install it for the remainder of this evaluation so
        // every receipt `build_and_sign_receipt` signs picks up the tag.
        let tenant_id = self.resolve_tenant_id_for_session(session_id);
        let _tenant_request_scope =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant_id.clone());
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);

        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;

        // Emergency kill switch: every evaluate path checks the flag
        // before receipt negotiation, capability validation, guard evaluation,
        // or budget mutation so a stopped kernel cannot be coerced into doing
        // any work or peer lookup.
        if self.is_emergency_stopped() {
            warn!(
                request_id = %request.request_id,
                "emergency stop active -- denying evaluate_tool_call"
            );
            return self.build_emergency_stop_deny_response_with_metadata(
                request,
                EMERGENCY_STOP_DENY_REASON,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        // RSS soft ceiling: shed new admissions before the OS OOM-kills the
        // mediator. Checked on the same atomic-load fast path as the emergency
        // stop, right after it.
        if self.is_rss_shedding() {
            warn!(
                request_id = %request.request_id,
                "rss soft ceiling exceeded -- shedding evaluate_tool_call"
            );
            // Receipt-totality: persist a signed deny receipt naming the shed
            // resource, like the emergency-stop fast path above, so the overload
            // denial has the same audit trail as every other admission decision.
            // The shed still returns Overloaded so the tower load-shed edge
            // surfaces backpressure; a receipt-persist failure is logged but must
            // not mask the shed decision (fail-closed).
            if let Err(receipt_error) = self.record_overload_shed_deny_receipt(
                request,
                crate::OverloadResource::Allocation,
                now,
                extra_metadata.clone(),
            ) {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&receipt_error.to_string()),
                    "failed to persist overload-shed deny receipt"
                );
            }
            return Err(KernelError::Overloaded {
                resource: crate::OverloadResource::Allocation,
            });
        }

        // Receipt-version negotiation is a TRUST-BOUNDARY admission check
        // that must run BEFORE any dispatch path. The admission snapshot is
        // scoped for every receipt builder below so persistence and federation cosign
        // use the peer/version/key material admitted before side effects.
        // PROTOCOL.md section 6 normative MUST.
        let receipt_admission = match self
            .kernel_receipt_admission_for_remote(request.federated_origin_kernel_id.as_deref(), now)
        {
            Ok(admission) => admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&msg),
                    "receipt federation admission failed pre-dispatch"
                );
                return self.build_negotiation_failclosed_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        };
        let _receipt_federation_request_scope = self
            .scope_receipt_federation_admission_for_request(
                &request.request_id,
                receipt_admission.clone(),
            );
        let _receipt_federation_scope = scope_receipt_federation_admission(Some(receipt_admission));

        self.validate_web3_evidence_prerequisites()?;

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call"
        );

        // Confirm durable persistence is healthy before any path that records a
        // receipt. Both the capability-rejection denials below and the
        // capability-lineage write persist through the receipt writer; against a
        // serving-closed writer that append fails and would surface its own error
        // (or a 500) instead of a clean signed fail-closed Deny. Gating here means
        // a degraded writer always produces the dedicated persistence Deny first.
        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_tcb_locks_healthy() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "tcb lock poisoned pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_revocation_durability_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "revocation durability unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(error) = request.validate_authorization_extensions() {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "authorization extension rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let cap = &request.capability;

        // Signature is verified first (no budget mutation); the actual
        // `admit_capability_budget` call is deferred until all
        // subsequent checks (time, revocation, delegation-admission,
        // subject, scope, guards) have passed. Otherwise a denied call
        // would still consume the parent's share, starving later valid
        // siblings.
        if let Err(reason) = self.verify_capability_full_pre_admit(
            cap,
            request.federated_origin_kernel_id.as_deref(),
            now,
        ) {
            let msg = format!("capability verification failed: {reason}");
            warn!(request_id = %request.request_id, msg = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let matching_grants = match resolve_required_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) {
            Ok(grants) => grants,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "DPoP verification failed");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        let reserving_preflight = matches!(
            preflight_disposition,
            PreflightHoldDisposition::ReserveForCaller
        ) && self.execution_nonce_preflight_required(request);
        if !reserving_preflight {
            if let Err(e) = self.ensure_registered_tool_target(request) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        self.reconcile_durable_admission_startup()?;
        let mut durable_admission = match self.begin_durable_tool_admission(
            request,
            &matching_grants,
            now_unix_ms,
        ) {
            Ok(admission) => admission,
            Err(error) => {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable admission denied");
                return self.build_deny_response_with_metadata(
                    request,
                    &reason,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        };

        if let Some(admission) = durable_admission.as_mut() {
            if let Some(response) = self.recover_durable_tool_admission(admission, request)? {
                return Ok(response);
            }
        }

        // Persistence was confirmed healthy at the pre-dispatch gate above, so the
        // writer-backed lineage write can run without racing a dead writer.
        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            self.compensate_durable_admission_after_pre_dispatch_cleanup(
                durable_admission
                    .as_ref()
                    .map(DurableToolAdmission::operation),
                None,
                None,
            )?;
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let mut budget_error = None;
        let mut budget_error_metadata = None;
        let mut governed_error = None;
        let mut guard_denial = None;
        let mut selected = None;
        for matching in &matching_grants {
            if durable_admission
                .as_ref()
                .is_some_and(|admission| !admission.permits_matching_grant(matching))
            {
                continue;
            }

            let validated_governed_admission = match self.validate_governed_transaction_pure(
                request,
                cap,
                matching.grant,
                GovernedValidationContext {
                    parent_context: None,
                    now,
                },
            ) {
                Ok(validated) => validated,
                Err(error) => {
                    governed_error.get_or_insert(error);
                    continue;
                }
            };
            let governed_call_chain_receipt_evidence = match self
                .governed_call_chain_receipt_evidence(
                    request,
                    cap,
                    None,
                    validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.call_chain_proof.clone()),
                ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    governed_error.get_or_insert(error);
                    continue;
                }
            };
            let no_budget_mutation = PreExecutionBudgetMutation::None;
            let mut guard_drop_guard = PostAdmissionDropGuard::new(
                self,
                request,
                cap,
                Some(matching.index),
                &no_budget_mutation,
                None,
                PostAdmissionReceiptContext {
                    extra_metadata: extra_metadata.clone(),
                    pre_invocation_guard_evidence: Vec::new(),
                    verified_payee_binding: validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.verified_payee_binding.clone()),
                },
                false,
            )
            .with_durable_operation(
                durable_admission
                    .as_ref()
                    .map(DurableToolAdmission::operation),
            );
            let guard_result = self
                .run_guards_within_budget(
                    request,
                    &cap.scope,
                    session_filesystem_roots,
                    Some(matching.index),
                )
                .await;
            guard_drop_guard.disarm();
            drop(guard_drop_guard);
            let pre_invocation_guard_evidence = match guard_result {
                Ok(evidence) => evidence,
                Err(error) => {
                    let msg = error.error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
                    guard_denial.get_or_insert(error);
                    continue;
                }
            };
            let runtime_admission = self.run_runtime_admission_hook(
                request,
                extra_metadata.as_ref(),
                now,
                now_unix_ms,
                Some(matching.index),
            );
            let runtime_metadata =
                merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
            if !runtime_admission.allowed {
                let msg = runtime_admission
                    .reason
                    .unwrap_or_else(|| "runtime admission denied".to_string());
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
                let (runtime_metadata, runtime_release_confirmed) = self
                    .release_runtime_admission_reservations_for_pre_dispatch_denial(
                        runtime_metadata,
                    );
                if runtime_release_confirmed {
                    self.compensate_durable_admission_after_pre_dispatch_cleanup(
                        durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        None,
                        None,
                    )?;
                }
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_runtime_admission_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(matching.index),
                            runtime_metadata,
                        )
                    },
                );
            }

            match self.check_and_increment_budget(
                request,
                cap,
                std::slice::from_ref(matching),
                self.execution_nonce_preflight_required(request),
                durable_admission.as_mut(),
                now_unix_ms,
            ) {
                Ok(BudgetAdmissionOutcome::Authorized {
                    grant_index,
                    mutation,
                }) => {
                    if let Err(error) = self.reserve_validated_governed_approval(
                        request,
                        validated_governed_admission.as_ref(),
                        durable_admission.as_mut(),
                        now_unix_ms,
                    ) {
                        let msg = error.to_string();
                        let reverse =
                            self.reverse_pre_execution_budget_mutation(cap, mutation.as_ref())?;
                        let (runtime_metadata, runtime_release_confirmed) = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                runtime_metadata,
                            );
                        if runtime_release_confirmed {
                            self.compensate_durable_admission_after_pre_dispatch_cleanup(
                                durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                reverse.as_ref(),
                                None,
                            )?;
                        }
                        return self.build_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(grant_index),
                            runtime_metadata,
                        );
                    }
                    selected = Some((
                        grant_index,
                        *mutation,
                        validated_governed_admission,
                        governed_call_chain_receipt_evidence,
                        pre_invocation_guard_evidence,
                        runtime_metadata,
                    ));
                    break;
                }
                Ok(BudgetAdmissionOutcome::PendingApproval {
                    grant_index,
                    proposal,
                }) => {
                    let (runtime_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            runtime_metadata,
                        );
                    if !runtime_release_confirmed {
                        // A retained runtime lease cannot be parked for approval:
                        // surface the stuck reservation as a fail-closed denial the
                        // same way an exhausted budget does, rather than telling the
                        // caller to collect approval for an operation whose
                        // pre-dispatch lease was never released.
                        budget_error = Some(KernelError::DurableAdmission(
                            "runtime admission reservation retained on pending approval"
                                .to_string(),
                        ));
                        budget_error_metadata = runtime_metadata;
                        break;
                    }
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pending_approval_response_with_metadata(
                                request,
                                &proposal,
                                now,
                                grant_index,
                                runtime_metadata,
                            )
                        },
                    );
                }
                Err(error @ KernelError::BudgetExhausted(_)) => {
                    let (runtime_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            runtime_metadata,
                        );
                    budget_error = Some(error);
                    if !runtime_release_confirmed {
                        budget_error_metadata = runtime_metadata;
                        break;
                    }
                }
                Err(error) => {
                    let msg = error.to_string();
                    let (runtime_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            runtime_metadata,
                        );
                    if runtime_release_confirmed {
                        self.compensate_durable_admission_after_pre_dispatch_cleanup(
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            None,
                            None,
                        )?;
                    }
                    let receipt_metadata = self.merge_budget_receipt_metadata(
                        runtime_metadata,
                        self.budget_backend_receipt_metadata()?,
                    );
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_monetary_deny_response_with_metadata(
                                request,
                                &msg,
                                now,
                                &matching_grants,
                                cap,
                                receipt_metadata,
                            )
                        },
                    );
                }
            }
        }

        let Some((
            matched_grant_index,
            mut budget_mutation,
            validated_governed_admission,
            governed_call_chain_receipt_evidence,
            pre_invocation_guard_evidence,
            extra_metadata,
        )) = selected
        else {
            // Guards are evaluated per grant, so a denial on one candidate only
            // decides the request once every later candidate has also failed.
            // A recorded budget denial still wins, since it carries the
            // stuck-reservation evidence the loop broke out to preserve.
            if budget_error.is_none() {
                if let Some(denial) = guard_denial {
                    let msg = denial.error.to_string();
                    self.compensate_durable_admission_after_pre_dispatch_cleanup(
                        durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        None,
                        None,
                    )?;
                    let receipt_metadata = self.merge_budget_receipt_metadata(
                        extra_metadata.clone(),
                        self.budget_backend_receipt_metadata()?,
                    );
                    return self.with_pre_invocation_guard_evidence(&denial.evidence, || {
                        self.build_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            &matching_grants,
                            cap,
                            receipt_metadata,
                        )
                    });
                }
            }
            let error = budget_error.or(governed_error).unwrap_or_else(|| {
                KernelError::DurableAdmission(
                    "retained budget hold does not identify a matching grant".to_string(),
                )
            });
            let msg = error.to_string();
            if durable_admission.as_ref().is_some_and(|admission| {
                admission.state()
                    == crate::admission_operation::AdmissionOperationState::BrokerAttemptRegistered
            }) {
                self.compensate_durable_admission_after_pre_dispatch_cleanup(
                    durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    None,
                    None,
                )?;
            }
            return self.build_monetary_deny_response_with_metadata(
                request,
                &msg,
                now,
                &matching_grants,
                cap,
                self.merge_budget_receipt_metadata(
                    merge_metadata_objects(extra_metadata.clone(), budget_error_metadata),
                    self.budget_backend_receipt_metadata()?,
                ),
            );
        };

        let _governed_runtime_attestation_receipt_scope =
            scope_governed_runtime_attestation_receipt_record(
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_runtime_attestation.clone()),
            );
        let verified_governed_payee_binding = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_payee_binding.clone());
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        // Capture whether THIS evaluation acquired a sibling-sum child-budget
        // holder lease. Every successful `admit_capability_budget` against a
        // parent takes one lease (fresh insert OR idempotent re-admit); a later
        // pre-dispatch cleanup releases exactly this evaluation's lease. The
        // reference-counted release frees the shared edge only when the last
        // holder releases, so an overlapping evaluation that still holds it
        // keeps its share and an oversubscribing sibling stays denied.
        let budget_lease_acquired = match self.admit_capability_budget(cap) {
            Ok(lease_acquired) => lease_acquired,
            Err(reason) => {
                let msg = format!("sibling-sum budget admission failed: {reason}");
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &msg,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: extra_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            // Admission failed: this evaluation acquired no
                            // lease, so there is nothing for cleanup to release.
                            budget_lease_acquired: false,
                        })
                    },
                );
            }
        };

        if self.execution_nonce_preflight_required(request) {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                match preflight_disposition {
                    PreflightHoldDisposition::ReverseForRetry => self
                        .build_execution_nonce_preflight_allow_response_after_cleanup(
                            request,
                            now,
                            matched_grant_index,
                            cap,
                            &budget_mutation,
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            extra_metadata,
                            budget_lease_acquired,
                        ),
                    PreflightHoldDisposition::ReserveForCaller => {
                        let settled_prepayment = match self.ensure_reserved_mustprepay_prepaid(
                            request,
                            budget_mutation.charge_result(),
                            durable_admission.as_ref(),
                            now_unix_ms,
                            verified_governed_payee_binding.as_ref(),
                        ) {
                            Ok(prepayment) => prepayment,
                            Err(error) => {
                                let reason = error.to_string();
                                warn!(
                                    request_id = %request.request_id,
                                    reason = %redacted!(&reason),
                                    "reserve-for-caller prepayment gate denied"
                                );
                                return self.build_pre_dispatch_cleanup_deny_response(
                                    PreDispatchCleanupDeny {
                                        request,
                                        reason: &reason,
                                        timestamp: now,
                                        matched_grant_index,
                                        cap,
                                        budget_mutation: &budget_mutation,
                                        payment_authorization: None,
                                        durable_operation: durable_admission
                                            .as_ref()
                                            .map(DurableToolAdmission::operation),
                                        runtime_admission_metadata: extra_metadata,
                                        verified_payee_binding: verified_governed_payee_binding
                                            .as_ref(),
                                        budget_lease_acquired,
                                    },
                                );
                            }
                        };
                        let reserved_payment_reference = settled_prepayment
                            .as_ref()
                            .and_then(|prepayment| prepayment.payment_reference.clone());
                        let response = self.build_execution_nonce_authorization_reserving_response(
                            ExecutionNonceReservingResponse {
                                request,
                                timestamp: now,
                                matched_grant_index,
                                budget_mutation: &budget_mutation,
                                runtime_admission_metadata: extra_metadata,
                                reserved_payment_reference,
                                budget_lease_acquired,
                            },
                        );
                        if response.is_err() {
                            if let Some(prepayment) = settled_prepayment.as_ref() {
                                self.refund_reserved_mustprepay_prepayment(
                                    request,
                                    &prepayment.authorization,
                                );
                            }
                        }
                        response
                    }
                }
            });
        }

        if let Err(error) = self.validate_required_execution_nonce(request, cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "execution nonce denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: extra_metadata,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }

        // A financial hold may not cross the tool-server dispatch boundary unless
        // a durable admission operation can arbitrate an ambiguous outcome after a
        // crash, cancellation, or deadline. This check uses the grant actually
        // selected above, rather than classifying the whole candidate set: a free
        // fallback must stay free, while a paid fallback may not inherit the
        // ephemeral escape from another candidate. Reserve-for-caller mediation
        // returns before this point and does not dispatch on this kernel.
        if !self.unsafe_ephemeral_financial_dispatch
            && durable_admission.is_none()
            && (budget_mutation.charge_result().is_some()
                || Self::is_governed_mustprepay_request(request))
        {
            let reason = "financial tool dispatch requires durable admission coverage";
            warn!(request_id = %request.request_id, reason, "financial dispatch denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: None,
                    runtime_admission_metadata: extra_metadata,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }

        if budget_mutation.charge_result().is_none() {
            if let Err(error) = self.reserve_presented_execution_nonce(request) {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "execution nonce denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &msg,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: extra_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        let Some(server) = self.tool_servers.get(&request.server_id).cloned() else {
            let error = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ));
            let reason = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&reason), "tool server error");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: extra_metadata,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        };
        if let Some(admission) = durable_admission.as_mut() {
            if let Err(error) = self.mark_durable_capture_pending(admission, now_unix_ms) {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable capture boundary could not be confirmed");
                return self.build_deny_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    self.retained_admission_receipt_metadata(
                        &budget_mutation,
                        extra_metadata.clone(),
                    ),
                );
            }
        }
        if budget_mutation.durable_hold_result().is_some() && durable_admission.is_none() {
            let capture = self.capture_invocation(cap, &mut budget_mutation);
            match capture {
                Ok(BudgetInvocationCaptureDecision::Captured(_)) => {}
                Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(_)) => {
                    let reason = "monetary invocation was already dispatched";
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_capture_replay_deny_response(
                                request,
                                reason,
                                now,
                                matched_grant_index,
                                cap,
                                &budget_mutation,
                                extra_metadata,
                                budget_lease_acquired,
                                verified_governed_payee_binding.as_ref(),
                            )
                        },
                    );
                }
                Err(error) => {
                    let internal_reason = error.to_string();
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&internal_reason),
                        "budget invocation capture could not be confirmed"
                    );
                    let reason = "budget invocation capture could not be confirmed";
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_deny_response_with_metadata(
                                request,
                                reason,
                                now,
                                Some(matched_grant_index),
                                self.ambiguous_invocation_capture_receipt_metadata(
                                    &budget_mutation,
                                    extra_metadata,
                                ),
                            )
                        },
                    );
                }
            }
        }

        let payment_authorization = match self.authorize_payment_if_needed(
            request,
            budget_mutation.charge_result(),
            durable_admission.as_ref(),
            now_unix_ms,
            verified_governed_payee_binding.as_ref(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&internal_reason), "payment denied");
                let error_code = match &error {
                    PaymentError::Unavailable(_) => "unavailable",
                    PaymentError::RailError(_) => "rail_error",
                    PaymentError::Declined(_) => "declined",
                    PaymentError::InsufficientFunds => "insufficient_funds",
                };
                let reason = format!("payment authorization failed: {error_code}");
                if matches!(
                    &error,
                    PaymentError::Declined(_) | PaymentError::InsufficientFunds
                ) {
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_definite_payment_denial_after_capture(
                                request,
                                &reason,
                                now,
                                cap,
                                &budget_mutation,
                                durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                extra_metadata,
                                budget_lease_acquired,
                                verified_governed_payee_binding.as_ref(),
                            )
                        },
                    );
                }
                let metadata = merge_metadata_objects(
                    self.retained_admission_receipt_metadata(&budget_mutation, extra_metadata),
                    Some(serde_json::json!({
                        "financial": {
                            "payment_authorization_ambiguous": true,
                            "payment_authorization_error_code": error_code,
                            "payment_attempt_reference": request.request_id
                        }
                    })),
                );
                let nonce_error = self.reserve_presented_execution_nonce(request).err();
                let denial_reason = nonce_error.as_ref().map_or(reason.as_str(), |_| {
                    "execution nonce denied after ambiguous payment authorization"
                });
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata_and_payee_binding(
                            request,
                            denial_reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
        };

        if budget_mutation.charge_result().is_some() {
            if let Err(error) = self.reserve_presented_execution_nonce(request) {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "execution nonce denied after payment authorization");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_nonce_denial_after_monetary_cleanup(PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: payment_authorization.as_ref(),
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: extra_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        if let Some(admission) = durable_admission.as_mut() {
            let commit = if budget_mutation.durable_hold_result().is_some() {
                self.capture_and_commit_durable_dispatch(
                    admission,
                    cap,
                    &mut budget_mutation,
                    now_unix_ms,
                )
            } else {
                self.commit_durable_dispatch(admission, now_unix_ms)
            };
            if let Err(error) = commit {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable dispatch commit could not be confirmed");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata_and_payee_binding(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.ambiguous_dispatch_receipt_metadata(
                                &budget_mutation,
                                payment_authorization.as_ref(),
                                extra_metadata,
                            ),
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
        }

        let tool_started_at = Instant::now();
        let has_monetary = budget_mutation.charge_result().is_some();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            &budget_mutation,
            payment_authorization.as_ref(),
            PostAdmissionReceiptContext {
                extra_metadata: extra_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
                verified_payee_binding: verified_governed_payee_binding.clone(),
            },
            budget_lease_acquired,
        )
        .with_durable_operation(
            durable_admission
                .as_ref()
                .map(DurableToolAdmission::operation),
        );
        post_admission_drop_guard.mark_dispatch_started();
        let dispatch_result = self
            .dispatch_resolved_server_within_budget(server, request, has_monetary)
            .await;
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                if durable_admission.is_none() {
                    let cleanup = self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                reason: "tool server requested URL elicitation before execution",
                                timestamp: now,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                payment_authorization: payment_authorization.as_ref(),
                                durable_operation: None,
                                runtime_admission_metadata: extra_metadata.clone(),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            })
                        },
                    );
                    if let Err(cleanup_error) = cleanup {
                        warn!(
                            request_id = %request.request_id,
                            reason = %redacted!(&cleanup_error),
                            audit_fault = "url_elicitation_cleanup_unrecorded",
                            "URL-elicitation cleanup could not be confirmed"
                        );
                    }
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error),
                        "tool call requires URL elicitation"
                    );
                    return Err(error);
                }
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    extra_metadata,
                );
                let receipt_result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_cancelled_response_with_metadata_and_payee_binding(
                            request,
                            "tool server requested URL elicitation after dispatch entry",
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    });
                if let Err(receipt_error) = receipt_result {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&receipt_error),
                        audit_fault = "url_elicitation_terminal_receipt_unrecorded",
                        "failed to record ambiguous URL-elicitation receipt"
                    );
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { reason, .. }) => {
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    extra_metadata.clone(),
                );
                let retained = metadata.is_some() || payment_authorization.is_some();
                self.note_retained_ambiguous_hold(retained);
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    retained_hold = retained,
                    "tool call cancelled"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_cancelled_response_with_metadata_and_payee_binding(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
            Err(KernelError::HotPathDeadlineExceeded { stage, budget_ms }) => {
                let reason = format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms");
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    extra_metadata.clone(),
                );
                let retained = metadata.is_some() || payment_authorization.is_some();
                self.note_retained_ambiguous_hold(retained);
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    retained_hold = retained,
                    "tool call deadline expired"
                );
                // Runtime and financial reservations remain retained because
                // the side effect is ambiguous.
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_cancelled_response_with_metadata_and_payee_binding(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    extra_metadata.clone(),
                );
                let retained = metadata.is_some() || payment_authorization.is_some();
                self.note_retained_ambiguous_hold(retained);
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    retained_hold = retained,
                    "tool call incomplete"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_incomplete_response_with_output_metadata_and_payee_binding(
                            request,
                            None,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
            Err(e) => {
                let msg = e.to_string();
                let deny_metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    extra_metadata.clone(),
                );
                let retained = deny_metadata.is_some() || payment_authorization.is_some();
                self.note_retained_ambiguous_hold(retained);
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), retained_hold = retained, "tool server error");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata_and_payee_binding(
                            request,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            deny_metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
        };
        let tool_elapsed = tool_started_at.elapsed();
        let durable_outcome = if let Some(admission) = durable_admission.as_mut() {
            let recorded_at_unix_ms = current_unix_timestamp_ms().max(now_unix_ms);
            match self.record_durable_tool_return(
                admission,
                DurableToolReturnInput {
                    request,
                    output: &tool_output,
                    reported_cost: reported_cost.clone(),
                    matched_grant_index,
                    elapsed: tool_elapsed,
                    extra_receipt_metadata: extra_metadata.clone(),
                    pre_invocation_guard_evidence: &pre_invocation_guard_evidence,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    trusted_now_unix_ms: recorded_at_unix_ms,
                },
            ) {
                Ok(outcome) => Some(outcome),
                Err(error) => {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error),
                        "tool return could not be durably recorded"
                    );
                    let deny_metadata = self.ambiguous_dispatch_receipt_metadata(
                        &budget_mutation,
                        payment_authorization.as_ref(),
                        extra_metadata.clone(),
                    );
                    let _ = self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_deny_response_with_metadata_and_payee_binding(
                                request,
                                &error.to_string(),
                                now,
                                Some(matched_grant_index),
                                deny_metadata,
                                verified_governed_payee_binding.as_ref(),
                            )
                        },
                    );
                    return Err(error);
                }
            }
        } else {
            None
        };
        if let (Some(admission), Some(outcome)) =
            (durable_admission.as_mut(), durable_outcome.as_ref())
        {
            return self.finalize_durable_tool_return(admission, request, outcome);
        }
        self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
            self.finalize_budgeted_tool_output_with_cost_and_metadata(
                request,
                tool_output,
                tool_elapsed,
                now,
                matched_grant_index,
                FinalizeToolOutputCostContext {
                    charge_result: budget_mutation.into_charge_result(),
                    reported_cost,
                    payment_authorization,
                    cap,
                },
                extra_metadata,
                verified_governed_payee_binding.as_ref(),
            )
        })
    }
}
