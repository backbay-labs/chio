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

        // RSS soft ceiling: shed new admissions before the OS OOM-kills the
        // mediator. The nested-flow path gates on the same atomic-load fast
        // path as the top-level evaluate, right after the emergency stop, so
        // sampling/elicitation-bearing tool calls cannot allocate and run after
        // the sampler raised the soft-ceiling flag.
        if self.is_rss_shedding() {
            warn!(
                request_id = %request.request_id,
                "rss soft ceiling exceeded -- shedding evaluate_tool_call (nested flow)"
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
        // A receipt-store read error while resolving the parent call-chain
        // receipt fails closed, but check_and_increment_budget above already
        // consumed the pre-execution budget (invocation count / monetary hold).
        // Route the error through the same reversal + deny path the governed and
        // guard denial branches use so a transient store failure never burns
        // quota or holds funds for a call that never dispatches.
        let governed_call_chain_receipt_evidence = match self.governed_call_chain_receipt_evidence(
            request,
            cap,
            Some(parent_context),
            validated_governed_admission
                .as_ref()
                .and_then(|admission| admission.call_chain_proof.clone()),
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed call-chain evidence lookup failed (nested flow)");
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
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        // The session's enforceable filesystem roots scope the guards below. A
        // parent session that was closed or evicted concurrently (or a poisoned
        // session lock) surfaces here as an error, but check_and_increment_budget
        // above already consumed the pre-execution budget (invocation count /
        // monetary hold). Route the error through the same reversal + deny path
        // the governed, call-chain, and guard denial branches use so a transient
        // session-lookup failure never burns quota or holds funds for a call that
        // never dispatches. The top-level async path is unaffected: it receives
        // session_filesystem_roots as a parameter.
        let session_roots = match self
            .session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)
        {
            Ok(roots) => roots,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "session filesystem roots lookup failed pre-dispatch (nested flow)");
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
        let runtime_admission_metadata =
            merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
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
                            runtime_admission_metadata.clone(),
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
                    runtime_admission_metadata,
                )
            });
        }

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
                            runtime_admission_metadata,
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
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    runtime_admission_metadata,
                    budget_lease_acquired,
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
                            budget_lease_acquired,
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
                    budget_lease_acquired,
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
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
            // ToolNotRegistered precedes any tool side effect, and no drop guard
            // is armed yet, so this arm owns the full unwind. Reverse ALL
            // pre-dispatch state (runtime-admission reservations, sibling-sum
            // capability admission, and the pre-execution budget mutation) so a
            // server that vanished between admission and lookup does not leak the
            // consumed child share / invocation slot onto later valid siblings.
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
                    budget_lease_acquired,
                })
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
            budget_lease_acquired,
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
                // UrlElicitationsRequired precedes any tool side effect
                // (dispatch_error_precedes_tool_side_effect == true): the tool
                // did not execute. The client completes the URL elicitations and
                // re-sends a FRESH tool call that re-admits from scratch; there
                // is no in-kernel resume that reuses this admission. The
                // post-admission drop guard is disarmed above, so this arm owns
                // the unwind and must reverse ALL pre-dispatch state: the
                // runtime-admission reservations, the sibling-sum capability
                // admission, and the pre-execution budget mutation (monetary
                // unwind or the invocation-slot / budget-charge reversal).
                // Reversing only the runtime reservations leaked a delegated
                // capability's admitted child share and a max_invocations
                // grant's consumed slot, wrongly starving the retry or later
                // valid siblings. The error is still returned so the
                // elicitations payload propagates to the edge, which registers
                // them and returns the url-elicitation-required response.
                // Finding 2 (codex round 8) / round 9: RELEASE the runtime-
                // reservation and CONTINUE the remaining cleanup rather than
                // `?`-short-circuiting, matching the generic pre-dispatch denial
                // path. A transient release failure must not leave the
                // invocation slot / child share consumed, nor replace the
                // elicitation response with an internal cleanup error. But if
                // the release FAILS the stuck lease must still land on the
                // append-only log: this arm returns Err(UrlElicitationsRequired)
                // and records no terminal receipt, so a discarded failure would
                // burn the lease silently. The helper records a signed fault
                // receipt naming the stuck lease on failure, and is a no-op on a
                // clean release; the elicitation error is still returned below.
                self.release_runtime_admission_reservations_for_url_elicitation_cleanup(
                    request,
                    matched_grant_index,
                    runtime_admission_metadata.clone(),
                    &pre_invocation_guard_evidence,
                );
                // Finding 1 (codex round 8) + refcount: release this
                // evaluation's sibling-sum child-budget lease ONLY when it
                // acquired one. The reference-counted release frees the shared
                // edge only when the last holder releases, so an overlapping
                // evaluation that still holds it keeps its share. RECORD-AND-
                // CONTINUE on failure (Fix #2): a transient budget-store failure
                // must not replace the Err(UrlElicitationsRequired) response, so
                // record a signed fault receipt naming the stuck child share and
                // keep unwinding rather than `?`-short-circuiting.
                if budget_lease_acquired {
                    if let Err(reason) = self.release_admitted_capability_budget(cap) {
                        let mut hold_ids = vec![cap.id.clone()];
                        if let Some(parent_link) = cap.delegation_chain.last() {
                            hold_ids.push(parent_link.capability_id.clone());
                        }
                        self.record_url_elicitation_budget_cleanup_fault(
                            request,
                            matched_grant_index,
                            "url_elicitation_child_budget_release",
                            &redacted!(&reason).to_string(),
                            hold_ids,
                            runtime_admission_metadata.clone(),
                            &pre_invocation_guard_evidence,
                        );
                    }
                }
                // Pre-execution budget reversal (monetary unwind or the
                // invocation-slot / budget-charge reversal). RECORD-AND-CONTINUE
                // on failure (Fix #2) so a budget-store fault does not mask the
                // elicitation error; the stuck slot lands a signed fault receipt.
                let budget_reversal = match payment_authorization.as_ref() {
                    Some(payment_authorization) => self
                        .unwind_aborted_monetary_invocation(
                            request,
                            cap,
                            budget_mutation.charge_result(),
                            Some(payment_authorization),
                        )
                        .map(|_| ()),
                    None => self
                        .reverse_pre_execution_budget_mutation(cap, &budget_mutation)
                        .map(|_| ()),
                };
                if let Err(reversal_error) = budget_reversal {
                    // Record the stuck MONETARY hold ids, not just the capability
                    // id (round-11): on the monetary-reversal-failure path the
                    // payment authorization id and the budget_hold_id are the
                    // actual holds that need manual recovery, so an operator can
                    // locate them from the signed fault alone.
                    let mut hold_ids = vec![cap.id.clone()];
                    if let Some(payment_authorization) = payment_authorization.as_ref() {
                        hold_ids.push(payment_authorization.authorization_id.clone());
                    }
                    if let Some(charge) = budget_mutation.charge_result() {
                        hold_ids.push(charge.budget_hold_id().to_string());
                    }
                    self.record_url_elicitation_budget_cleanup_fault(
                        request,
                        matched_grant_index,
                        "url_elicitation_budget_reversal",
                        &redacted!(&reversal_error).to_string(),
                        hold_ids,
                        runtime_admission_metadata,
                        &pre_invocation_guard_evidence,
                    );
                }
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
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                if dispatch_error_precedes_tool_side_effect(&error) {
                    // No tool side effect occurred. The post-admission drop guard
                    // is already disarmed, so this arm owns the unwind and must
                    // reverse ALL pre-dispatch state: the runtime-admission
                    // reservations, the sibling-sum capability admission, and the
                    // pre-execution budget mutation. Releasing only the runtime
                    // reservations leaks the consumed child share / invocation
                    // slot and wrongly starves later valid siblings or retries.
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
                                payment_authorization: payment_authorization.as_ref(),
                                runtime_admission_metadata,
                                budget_lease_acquired,
                            })
                        },
                    );
                }
                // A tool side effect may have executed: retain the runtime
                // admission reservations (fail-closed) and reverse only the
                // monetary charge.
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
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
                        let deny_metadata = self
                            .mark_runtime_admission_reservations_retained_fail_closed(
                                deny_metadata,
                            );
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
