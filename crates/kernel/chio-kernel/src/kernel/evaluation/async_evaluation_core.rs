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

        // Persistence was confirmed healthy at the pre-dispatch gate above, so the
        // writer-backed lineage write can run without racing a dead writer.
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
        // A receipt-store read error while resolving the parent call-chain
        // receipt fails closed, but check_and_increment_budget above already
        // consumed the pre-execution budget (invocation count / monetary hold).
        // Route the error through the same reversal + deny path the governed and
        // guard denial branches use so a transient store failure never burns
        // quota or holds funds for a call that never dispatches.
        let governed_call_chain_receipt_evidence = match self.governed_call_chain_receipt_evidence(
            request,
            cap,
            None,
            validated_governed_admission
                .as_ref()
                .and_then(|admission| admission.call_chain_proof.clone()),
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed call-chain evidence lookup failed");
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
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        let pre_invocation_guard_evidence = match self
            .run_guards_within_budget(
                request,
                &cap.scope,
                session_filesystem_roots,
                Some(matched_grant_index),
            )
            .await
        {
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
                            runtime_admission_metadata: extra_metadata,
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
                    extra_metadata,
                    budget_lease_acquired,
                )
            });
        }

        // For a side-effecting or monetary call, durably journal a dispatch
        // intent BEFORE the earliest possible effect (the prepaid authorize
        // below, or tool dispatch), so a crash in the effect-to-receipt window
        // leaves a durable trace to reconcile at the next boot. On failure,
        // reverse every pre-execution hold through the same pre-dispatch
        // unwind the admission and authorize arms use, then deny before any
        // effect. Read-only calls return None here and pay nothing.
        let has_monetary = budget_mutation.charge_result().is_some();
        let dispatch_intent =
            match self.record_dispatch_intent_if_side_effecting(request, has_monetary, now_unix_ms)
            {
                Ok(handle) => handle,
                Err(error) => {
                    let msg = error.to_string();
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&msg),
                        "dispatch intent write failed; denying before dispatch"
                    );
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
                                runtime_admission_metadata: extra_metadata.clone(),
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            };
        // Register the handle for the whole evaluation so whichever terminal
        // receipt commits first consumes the intent; the guard clears the
        // registration when this future finishes (or is dropped).
        let _dispatch_intent_scope =
            self.scope_dispatch_intent_for_request(&request.request_id, dispatch_intent);

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
                            budget_lease_acquired,
                        })
                    },
                );
            }
        };

        // Money path: bind the rail's authorization id to the open intent so a
        // monetary orphan names the exact reference an operator reconciles
        // against. Best-effort and bounded: the open intent already proves a
        // monetary attempt through its rail column, so a failed or timed-out
        // attach is logged and never fails the call.
        if let Some(authorization) = payment_authorization.as_ref() {
            if let Some(handle) = self.dispatch_intent_for_request(Some(&request.request_id)) {
                let budget = self.config.deadlines.receipt_append_budget();
                if let Err(error) = self.with_receipt_store(|store| {
                    Ok(store.attach_dispatch_intent_rail_ref_with_timeout(
                        &handle.request_id,
                        handle.tenant_id.as_deref(),
                        &authorization.authorization_id,
                        budget,
                    )?)
                }) {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error.to_string()),
                        "dispatch intent rail-ref attach failed"
                    );
                }
            }
        }

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
                    budget_lease_acquired,
                })
            });
        }

        let tool_started_at = Instant::now();
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
            },
            budget_lease_acquired,
        );
        post_admission_drop_guard.mark_dispatch_started();
        let dispatch_result = self.dispatch_within_budget(request, has_monetary).await;
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
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
                    extra_metadata.clone(),
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
                            extra_metadata.clone(),
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
                        extra_metadata,
                        &pre_invocation_guard_evidence,
                    );
                }
                // No tool effect ran and this arm records no terminal
                // receipt, so the journaled dispatch intent must be cleared
                // here: leaving it open would dead-letter a false orphan at
                // the next boot for a call that never executed.
                self.clear_dispatch_intent_for_non_dispatch_exit(request);
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
                            self.mark_runtime_admission_reservations_retained_fail_closed(
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
                            ),
                        )
                    },
                );
            }
            Err(KernelError::HotPathDeadlineExceeded { stage, budget_ms }) => {
                let reason = format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms");
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call deadline expired"
                );
                // A timed-out dispatch may already have applied its side effect,
                // so the runtime-admission reservation is NOT released; it is
                // retained and marked auditable, exactly as the cancellation arm
                // does. Releasing here would be fail-open: a single-use
                // destructive lease could be replayed after the destructive
                // action already executed.
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
                                            extra_metadata.clone(),
                                            self.budget_execution_receipt_metadata(
                                                charge,
                                                Some(("reversed", reverse)),
                                            ),
                                        ),
                                    _ => extra_metadata.clone(),
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
                                            extra_metadata.clone(),
                                            self.budget_execution_receipt_metadata(
                                                charge,
                                                Some(("reversed", reverse)),
                                            ),
                                        ),
                                    _ => extra_metadata.clone(),
                                },
                            ),
                        )
                    },
                );
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                if dispatch_error_precedes_tool_side_effect(&e) {
                    // No tool side effect occurred (e.g. ToolNotRegistered). The
                    // post-admission drop guard is already disarmed, so this arm
                    // owns the unwind and must reverse ALL pre-dispatch state:
                    // the runtime-admission reservations, the sibling-sum
                    // capability admission, and the pre-execution budget
                    // mutation. Releasing only the runtime reservations leaks the
                    // consumed child share / invocation slot and wrongly starves
                    // later valid siblings or retries under the same grant.
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
                                runtime_admission_metadata: extra_metadata,
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
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                            _ => extra_metadata.clone(),
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
                    reported_cost,
                    payment_authorization,
                    cap,
                },
                extra_metadata,
            )
        })
    }
}
