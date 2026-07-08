use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;

impl ChioKernel {
    pub(crate) fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_with_nested_flow_client_async(
            parent_context,
            request,
            client,
            extra_metadata,
        ))
    }

    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Install the parent session's tenant_id so every
        // receipt signed while this nested-flow evaluation is in flight
        // carries the correct tenant tag.
        let tenant_id = self.resolve_tenant_id_for_session(Some(&parent_context.session_id));
        let _tenant_request_scope =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant_id.clone());
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);

        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;

        // Emergency kill switch: the nested-flow path also
        // deny-fast before receipt negotiation so sampling/elicitation-bearing
        // tool calls cannot slip past while the kernel is stopped.
        if self.is_emergency_stopped() {
            warn!(
                request_id = %request.request_id,
                "emergency stop active -- denying evaluate_tool_call (nested flow)"
            );
            return self.build_emergency_stop_deny_response_with_metadata(
                request,
                EMERGENCY_STOP_DENY_REASON,
                now,
                None,
                None,
            );
        }

        // The pre-dispatch receipt-version admission gate must run on the
        // nested-flow path too. The admission snapshot is scoped for the
        // receipt builders below so a peer that expires during nested tool
        // execution does not change the already-admitted version or key.
        let receipt_admission = match self
            .kernel_receipt_admission_for_remote(request.federated_origin_kernel_id.as_deref(), now)
        {
            Ok(admission) => admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&msg),
                    "receipt federation admission failed pre-dispatch (nested flow)"
                );
                return self.build_negotiation_failclosed_deny_response_with_metadata(
                    request, &msg, now, None, None,
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
            "evaluating tool call with nested-flow bridge"
        );

        let cap = &request.capability;

        // Signature first; the budget admission is deferred until
        // after all subsequent checks pass, so a denied call no longer
        // consumes the parent's share.
        if let Err(reason) = self.verify_capability_full_pre_admit(
            cap,
            request.federated_origin_kernel_id.as_deref(),
            now,
        ) {
            let msg = format!("capability verification failed: {reason}");
            warn!(request_id = %request.request_id, msg = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
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
                return self.build_deny_response(request, &msg, now, None);
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
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
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
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    &matching_grants,
                    cap,
                    Some(self.budget_backend_receipt_metadata()?),
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
            Some(parent_context),
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
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                        )),
                    );
                }
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
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
                    Some(parent_context),
                    validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.call_chain_proof.clone()),
                ),
            );

        let session_roots =
            self.session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)?;

        let pre_invocation_guard_evidence = match self.run_guards(
            request,
            &cap.scope,
            Some(session_roots.as_slice()),
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
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            )),
                        )
                    });
                }
                return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                    self.build_deny_response(request, &msg, now, Some(matched_grant_index))
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
        let runtime_admission_metadata = runtime_admission.metadata.clone();
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
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
                            runtime_admission.metadata,
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
                    runtime_admission.metadata,
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
                    runtime_admission_metadata,
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
                    runtime_admission_metadata,
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
                            runtime_admission_metadata,
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
                    runtime_admission_metadata,
                })
            });
        }

        let tool_started_at = Instant::now();
        // RFC-0002: the tool-server lookup is hoisted above the drop-guard
        // construction so its failure can never early-return through `?`
        // while the guard is armed. ToolNotRegistered precedes any tool
        // side effect (dispatch_error_precedes_tool_side_effect), so this
        // arm releases runtime-admission reservations and records a deny
        // receipt, matching the async-core generic-error arm's disposition.
        let Some(server) = self.tool_servers.get(&request.server_id) else {
            let error = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ));
            let unwind = self.unwind_aborted_monetary_invocation(
                request,
                cap,
                budget_mutation.charge_result(),
                payment_authorization.as_ref(),
            )?;
            self.release_runtime_admission_reservations(runtime_admission_metadata.as_ref())?;
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    match (budget_mutation.charge_result(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            runtime_admission_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => runtime_admission_metadata.clone(),
                    },
                )
            });
        };
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            &budget_mutation,
            payment_authorization.as_ref(),
            PostAdmissionReceiptContext {
                extra_metadata: runtime_admission_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
            },
        );
        // Mark dispatch started before lending the child-receipt buffer to the
        // bridge: the bridge borrows the guard for the whole dispatch block, so
        // the `&mut self` call must happen first. There is no await between here
        // and the invoke below, so the future cannot be dropped in this window.
        post_admission_drop_guard.mark_dispatch_started();
        let tool_output_result = {
            let mut bridge = SessionNestedFlowBridge {
                sessions: &self.sessions,
                child_receipts: post_admission_drop_guard.child_receipts_mut(),
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                kernel_keypair: &self.config.keypair,
                client,
            };

            match server
                .invoke_stream(
                    &request.tool_name,
                    request.arguments.clone(),
                    Some(&mut bridge),
                )
                .await
            {
                Ok(Some(stream)) => Ok(ToolServerOutput::Stream(stream)),
                Ok(None) => server
                    .invoke(
                        &request.tool_name,
                        request.arguments.clone(),
                        Some(&mut bridge),
                    )
                    .await
                    .map(ToolServerOutput::Value),
                Err(error) => Err(error),
            }
        };
        post_admission_drop_guard.disarm();
        // Take the buffered child receipts out of the guard before dropping it.
        // The guard is now disarmed AND holds an empty buffer, so its Drop
        // records nothing and the receipts cannot be double-recorded.
        let child_receipts = post_admission_drop_guard.take_child_receipts();
        drop(post_admission_drop_guard);
        self.record_child_receipts(child_receipts)?;
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let _ = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                self.release_runtime_admission_reservations(runtime_admission_metadata.as_ref())?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                if request_id == parent_context.request_id {
                    self.with_session_mut(&parent_context.session_id, |session| {
                        session.request_cancellation(&parent_context.request_id)?;
                        Ok(())
                    })?;
                }
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
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                match (budget_mutation.charge_result(), unwind.as_ref()) {
                                    (Some(charge), Some(reverse)) => self
                                        .merge_budget_receipt_metadata(
                                            runtime_admission_metadata.clone(),
                                            self.budget_execution_receipt_metadata(
                                                charge,
                                                Some(("reversed", reverse)),
                                            ),
                                        ),
                                    _ => runtime_admission_metadata.clone(),
                                },
                            ),
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
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                match (budget_mutation.charge_result(), unwind.as_ref()) {
                                    (Some(charge), Some(reverse)) => self
                                        .merge_budget_receipt_metadata(
                                            runtime_admission_metadata.clone(),
                                            self.budget_execution_receipt_metadata(
                                                charge,
                                                Some(("reversed", reverse)),
                                            ),
                                        ),
                                    _ => runtime_admission_metadata.clone(),
                                },
                            ),
                        )
                    },
                );
            }
            Err(error) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                let released_pre_side_effect = dispatch_error_precedes_tool_side_effect(&error);
                if released_pre_side_effect {
                    self.release_runtime_admission_reservations(
                        runtime_admission_metadata.as_ref(),
                    )?;
                }
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        let deny_metadata = match (budget_mutation.charge_result(), unwind.as_ref())
                        {
                            (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                                runtime_admission_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                            _ => runtime_admission_metadata.clone(),
                        };
                        let deny_metadata = if released_pre_side_effect {
                            deny_metadata
                        } else {
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                deny_metadata,
                            )
                        };
                        self.build_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            deny_metadata,
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
                    reported_cost: None,
                    payment_authorization,
                    cap,
                },
                runtime_admission_metadata,
            )
        })
    }
}
