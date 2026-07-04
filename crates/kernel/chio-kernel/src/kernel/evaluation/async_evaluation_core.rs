use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;

impl ChioKernel {
    pub(super) async fn evaluate_tool_call_async_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
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

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

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

        let (matched_grant_index, budget_mutation) = match self.check_and_increment_budget(
            &request.request_id,
            cap,
            &matching_grants,
        ) {
            Ok(result) => result,
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                // For monetary budget exhaustion, build a denial receipt with financial metadata.
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    &matching_grants,
                    cap,
                    self.merge_budget_receipt_metadata(
                        extra_metadata.clone(),
                        self.budget_backend_receipt_metadata()?,
                    ),
                );
            }
        };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        let validated_governed_admission = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            budget_mutation.charge_result(),
            None,
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                    );
                }
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    extra_metadata.clone(),
                );
            }
        };
        let _governed_runtime_attestation_receipt_scope =
            scope_governed_runtime_attestation_receipt_record(
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_runtime_attestation.clone()),
            );
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(
                self.governed_call_chain_receipt_evidence(
                    request,
                    cap,
                    None,
                    validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.call_chain_proof.clone()),
                ),
            );

        let pre_invocation_guard_evidence = match self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            Ok(evidence) => evidence,
            Err(e) => {
                let msg = e.error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                        self.build_pre_execution_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            charge,
                            reverse.committed_cost_units_after,
                            cap,
                            self.merge_budget_receipt_metadata(
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                        )
                    });
                }
                return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        Some(matched_grant_index),
                        extra_metadata.clone(),
                    )
                });
            }
        };

        let runtime_admission = self.run_runtime_admission_hook(
            request,
            extra_metadata.as_ref(),
            now,
            now_unix_ms,
            Some(matched_grant_index),
        );
        let extra_metadata =
            merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
            let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
            if let (Some(charge), Some(reverse)) =
                (budget_mutation.charge_result(), reverse.as_ref())
            {
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            extra_metadata,
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                    )
                    },
                );
            }
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_runtime_admission_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    extra_metadata,
                )
            });
        }

        if let Err(reason) = self.admit_capability_budget(cap) {
            let msg = format!("sibling-sum budget admission failed: {reason}");
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    runtime_admission_metadata: extra_metadata,
                })
            });
        }

        if self.execution_nonce_preflight_required(request) {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    extra_metadata,
                )
            });
        }

        let payment_authorization = match self
            .authorize_payment_if_needed(request, budget_mutation.charge_result())
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let msg = format!("payment authorization failed: {error}");
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment denied");
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
                            runtime_admission_metadata: extra_metadata,
                        })
                    },
                );
            }
        };

        if let Err(error) = self.require_presented_execution_nonce(request, cap) {
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
                    payment_authorization: payment_authorization.as_ref(),
                    runtime_admission_metadata: extra_metadata,
                })
            });
        }

        let tool_started_at = Instant::now();
        let has_monetary = budget_mutation.charge_result().is_some();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            budget_mutation.charge_result(),
            payment_authorization.as_ref(),
            PostAdmissionReceiptContext {
                extra_metadata: extra_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
            },
        );
        let dispatch_result = self
            .dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary)
            .await;
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let _ = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                self.release_runtime_admission_reservations(extra_metadata.as_ref())?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { reason, .. }) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call cancelled"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            match (budget_mutation.charge_result(), unwind.as_ref()) {
                                (Some(charge), Some(reverse)) => self
                                    .merge_budget_receipt_metadata(
                                        extra_metadata.clone(),
                                        self.budget_execution_receipt_metadata(
                                            charge,
                                            Some(("reversed", reverse)),
                                        ),
                                    ),
                                _ => extra_metadata.clone(),
                            },
                        )
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_incomplete_response_with_output_and_metadata(
                            request,
                            None,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            match (budget_mutation.charge_result(), unwind.as_ref()) {
                                (Some(charge), Some(reverse)) => self
                                    .merge_budget_receipt_metadata(
                                        extra_metadata.clone(),
                                        self.budget_execution_receipt_metadata(
                                            charge,
                                            Some(("reversed", reverse)),
                                        ),
                                    ),
                                _ => extra_metadata.clone(),
                            },
                        )
                    },
                );
            }
            Err(e) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                if dispatch_error_precedes_tool_side_effect(&e) {
                    self.release_runtime_admission_reservations(extra_metadata.as_ref())?;
                }
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            match (budget_mutation.charge_result(), unwind.as_ref()) {
                                (Some(charge), Some(reverse)) => self
                                    .merge_budget_receipt_metadata(
                                        extra_metadata.clone(),
                                        self.budget_execution_receipt_metadata(
                                            charge,
                                            Some(("reversed", reverse)),
                                        ),
                                    ),
                                _ => extra_metadata.clone(),
                            },
                        )
                    },
                );
            }
        };
        self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
            self.finalize_budgeted_tool_output_with_cost_and_metadata(
                request,
                tool_output,
                tool_started_at.elapsed(),
                now,
                matched_grant_index,
                FinalizeToolOutputCostContext {
                    charge_result: budget_mutation.into_charge_result(),
                    reported_cost,
                    payment_authorization,
                    cap,
                },
                extra_metadata,
            )
        })
    }
}
