//! `ChioKernel` tool-call and plan evaluation path.
//!
//! Holds the synchronous and asynchronous evaluate entrypoints, the plan
//! evaluation helpers, and the long-form evaluation cores. Method bodies are
//! moved verbatim from `kernel/mod.rs`; the canonical receipt body and
//! signing sequence are unchanged.

use chio_log_redact::redacted;

use self::responses::FinalizeToolOutputCostContext;
use super::*;

impl ChioKernel {
    /// Open a new logical session for an agent and bind any capabilities that
    /// were issued during setup to that session.
    ///
    /// Design note: unlike the hosted-tool and nested-flow dispatch
    /// paths, this surface deliberately does NOT call
    /// [`Self::admit_capability_budget`] after the pre-admit verifier
    /// pass. Read-only resource/prompt operations
    /// (`subscribe_resource`, `read_resource`, `get_prompt`,
    /// `complete`) are not economic actions: they neither consume the
    /// caller's per-tool invocation budget nor reserve the caller's
    /// share against its parent in the sibling-sum registry.
    /// PROTOCOL.md section "Single-entry capability verifier" already
    /// authorises this split as MAY: the MUST is that every surface
    /// traverses `verify_capability_full` exactly once (which this
    /// helper does); the authoritative admit phase is reserved for
    /// surfaces that actually execute a side-effecting action against
    /// the budget.
    pub(crate) fn validate_non_tool_capability(
        &self,
        capability: &CapabilityToken,
        agent_id: &str,
    ) -> Result<(), KernelError> {
        // Emergency kill switch: resource/prompt operations that go
        // through this helper must also deny-fast so the kill switch applies
        // to every capability-backed surface, not just tool calls.
        if self.is_emergency_stopped() {
            return Err(KernelError::GuardDenied(
                EMERGENCY_STOP_DENY_REASON.to_string(),
            ));
        }
        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;
        self.verify_capability_full_pre_admit(capability, None, now)
            .map_err(KernelError::GuardDenied)?;
        self.check_revocation(capability)?;
        self.validate_delegation_admission(capability)?;
        check_subject_binding(capability, agent_id)?;
        Ok(())
    }

    /// Evaluate a tool call request.
    ///
    /// This is the kernel's main entry point. It performs the full validation
    /// pipeline:
    ///
    /// 1. Verify capability signature against known CA public keys.
    /// 2. Check time bounds (not expired, not-before satisfied).
    /// 3. Check revocation status of the capability and its delegation chain.
    /// 4. Verify the requested tool is within the capability's scope.
    /// 5. Check and decrement invocation budget.
    /// 6. Run all registered guards.
    /// 7. If all pass: forward to tool server, sign allow receipt.
    /// 8. If any fail: sign deny receipt.
    ///
    /// Every call -- whether allowed or denied -- produces exactly one signed
    /// receipt.
    pub async fn evaluate_tool_call(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_async_with_session_context(request, None, None, None)
            .await
    }

    pub async fn evaluate_tool_call_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_async_with_session_context(request, None, extra_metadata, None)
            .await
    }

    pub fn evaluate_tool_call_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    /// Crate-private sync entrypoint invoked by the
    /// [`crate::kernel::evaluator::ToolEvaluator`] default
    /// implementation. Wraps the long-form
    /// `evaluate_tool_call_sync_inner` so the trait body does
    /// not need to plumb the `session_filesystem_roots` /
    /// `extra_metadata` parameters; both default to `None` on this path,
    /// matching the previous direct delegation from
    /// `evaluate_tool_call`.
    pub(crate) fn evaluate_tool_call_sync(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    pub fn evaluate_tool_call_blocking_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, extra_metadata)
    }

    pub fn sign_planned_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_metadata(
            request,
            reason,
            current_unix_timestamp(),
            None,
            extra_metadata,
        )
    }

    /// Plan-level evaluation.
    ///
    /// Takes an ordered list of planned tool calls under a single
    /// capability token and evaluates every step INDEPENDENTLY against
    /// the pre-invocation portion of the evaluation pipeline: capability
    /// signature / time-bound / revocation / subject binding, the
    /// request-matching pass (scope + constraints + model constraint),
    /// and the registered guard pipeline. No tool-server dispatch, no
    /// budget mutation, no receipt emission, and no cross-step state
    /// propagation take place: this is a stateless pre-flight check.
    ///
    /// Dependencies between planned steps are advisory metadata only in
    /// v1: the kernel does not topologically sort the graph, refuse on
    /// cycles, or short-circuit downstream steps when an earlier step
    /// denies. Callers are expected to make that decision themselves
    /// once they have the per-step verdict list.
    ///
    /// Guards that require post-invocation output (response-shaping,
    /// streaming sanitizers, etc.) are inherently skipped because no
    /// tool output exists; every registered guard is
    /// invoked against the synthesised pre-flight request, matching the
    /// set of guards that run in `evaluate_tool_call` before dispatch.
    ///
    /// Receipt emission is deferred to a future phase. The kernel emits
    /// structured trace spans for the plan and every per-step verdict
    /// so operators can correlate plan evaluations with subsequent
    /// tool-call receipts.
    pub async fn evaluate_plan(
        &self,
        req: chio_core_types::PlanEvaluationRequest,
    ) -> chio_core_types::PlanEvaluationResponse {
        self.evaluate_plan_blocking(&req)
    }

    /// Synchronous variant of [`Self::evaluate_plan`] for substrate
    /// adapters that do not run on an async runtime.
    ///
    /// Plan evaluation never touches the network, so the async method
    /// is a thin wrapper over this blocking implementation.
    pub fn evaluate_plan_blocking(
        &self,
        req: &chio_core_types::PlanEvaluationRequest,
    ) -> chio_core_types::PlanEvaluationResponse {
        use chio_core_types::{PlanEvaluationResponse, PlanVerdict, StepVerdict, StepVerdictKind};

        debug!(
            plan_id = %req.plan_id,
            planner_capability_id = %req.planner_capability_id,
            step_count = req.steps.len(),
            "evaluating plan"
        );

        let mut step_verdicts = Vec::with_capacity(req.steps.len());

        // Reject capability-id mismatches once, up front: every step is
        // evaluated under the same token so a mismatch is fatal for the
        // whole plan. Fail-closed: every step is flagged denied.
        if req.planner_capability.id != req.planner_capability_id {
            let reason = format!(
                "planner_capability_id {} does not match embedded token id {}",
                req.planner_capability_id, req.planner_capability.id
            );
            for (index, _) in req.steps.iter().enumerate() {
                step_verdicts.push(StepVerdict {
                    step_index: index,
                    verdict: StepVerdictKind::Denied,
                    reason: Some(reason.clone()),
                    guard: None,
                });
            }
            let plan_verdict = if step_verdicts.is_empty() {
                PlanVerdict::FullyDenied
            } else {
                PlanEvaluationResponse::aggregate(&step_verdicts)
            };
            return PlanEvaluationResponse {
                plan_id: req.plan_id.clone(),
                plan_verdict,
                step_verdicts,
            };
        }

        // Emergency stop applies to plan evaluation too: a stopped kernel
        // must not leak any information about what the plan might allow.
        if self.is_emergency_stopped() {
            warn!(
                plan_id = %req.plan_id,
                "emergency stop active -- denying evaluate_plan"
            );
            for (index, _) in req.steps.iter().enumerate() {
                step_verdicts.push(StepVerdict {
                    step_index: index,
                    verdict: StepVerdictKind::Denied,
                    reason: Some(EMERGENCY_STOP_DENY_REASON.to_string()),
                    guard: None,
                });
            }
            let plan_verdict = if step_verdicts.is_empty() {
                PlanVerdict::FullyDenied
            } else {
                PlanEvaluationResponse::aggregate(&step_verdicts)
            };
            return PlanEvaluationResponse {
                plan_id: req.plan_id.clone(),
                plan_verdict,
                step_verdicts,
            };
        }

        for (index, step) in req.steps.iter().enumerate() {
            let verdict = self.evaluate_plan_step(req, step, index);
            step_verdicts.push(verdict);
        }

        let plan_verdict = PlanEvaluationResponse::aggregate(&step_verdicts);

        debug!(
            plan_id = %req.plan_id,
            plan_verdict = ?plan_verdict,
            "plan evaluation complete"
        );

        PlanEvaluationResponse {
            plan_id: req.plan_id.clone(),
            plan_verdict,
            step_verdicts,
        }
    }

    fn evaluate_plan_step(
        &self,
        req: &chio_core_types::PlanEvaluationRequest,
        step: &chio_core_types::PlannedToolCall,
        index: usize,
    ) -> chio_core_types::StepVerdict {
        use chio_core_types::{StepVerdict, StepVerdictKind};

        let now = current_unix_timestamp();
        let cap = &req.planner_capability;

        // Design note: plan-evaluation is a PREVIEW path -- it answers
        // "if this plan ran, would each step be allowed?" without
        // dispatching the underlying tool calls. Calling
        // [`Self::admit_capability_budget`] here would consume
        // sibling-sum budget for plans that may never execute, which
        // is the opposite of preview semantics. The pre-admit verifier
        // pass below covers the spec MUST (every surface traverses
        // `verify_capability_full` exactly once); the authoritative
        // admit phase is reserved for the actual hosted-tool /
        // nested-flow dispatch paths in
        // `evaluate_tool_call_*_with_session_context`.
        //
        // Capability-wide checks repeat per-step so a failure here is
        // still reflected in every step's verdict, keeping the per-step
        // output self-contained.
        if let Err(reason) = self.verify_capability_full_pre_admit(cap, None, now) {
            return StepVerdict {
                step_index: index,
                verdict: StepVerdictKind::Denied,
                reason: Some(format!("capability verification failed: {reason}")),
                guard: None,
            };
        }
        if let Err(error) = check_time_bounds(cap, now) {
            return StepVerdict {
                step_index: index,
                verdict: StepVerdictKind::Denied,
                reason: Some(error.to_string()),
                guard: None,
            };
        }
        if let Err(error) = self.check_revocation(cap) {
            return StepVerdict {
                step_index: index,
                verdict: StepVerdictKind::Denied,
                reason: Some(error.to_string()),
                guard: None,
            };
        }
        if let Err(error) = check_subject_binding(cap, &req.agent_id) {
            return StepVerdict {
                step_index: index,
                verdict: StepVerdictKind::Denied,
                reason: Some(error.to_string()),
                guard: None,
            };
        }

        // Synthesise a ToolCallRequest so the same request-matching and
        // guard machinery applies to plan steps as to runtime calls. No
        // DPoP / governed-intent / approval-token shape is carried: plan
        // evaluation is a pre-flight check and is not a substitute for
        // those runtime-only proofs.
        let synthesised = ToolCallRequest {
            request_id: step.request_id.clone(),
            capability: cap.clone(),
            tool_name: step.tool_name.clone(),
            server_id: step.server_id.clone(),
            agent_id: req.agent_id.clone(),
            arguments: step.parameters.clone(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: step.model_metadata.clone(),
            federated_origin_kernel_id: None,
        };

        let matching_grants = match resolve_matching_grants(
            cap,
            &synthesised.tool_name,
            &synthesised.server_id,
            &synthesised.arguments,
            synthesised.model_metadata.as_ref(),
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let error = KernelError::OutOfScope {
                    tool: synthesised.tool_name.clone(),
                    server: synthesised.server_id.clone(),
                };
                return StepVerdict {
                    step_index: index,
                    verdict: StepVerdictKind::Denied,
                    reason: Some(error.to_string()),
                    guard: None,
                };
            }
            Err(error) => {
                return StepVerdict {
                    step_index: index,
                    verdict: StepVerdictKind::Denied,
                    reason: Some(error.to_string()),
                    guard: None,
                };
            }
        };

        let matched_grant_index = matching_grants
            .first()
            .map(|matching| matching.index)
            .unwrap_or(0);

        // run_guards returns Ok(()) on allow and Err(GuardDenied(...))
        // on deny. Fail-closed: any guard error reads as a denial so the
        // caller still sees a per-step reason string.
        if let Err(error) =
            self.run_guards(&synthesised, &cap.scope, None, Some(matched_grant_index))
        {
            // Attempt to extract the offending guard name from the
            // canonical `guard "<name>" denied the request` format
            // emitted by run_guards.
            let message = error.to_string();
            let guard = extract_guard_name(&message);
            return StepVerdict {
                step_index: index,
                verdict: StepVerdictKind::Denied,
                reason: Some(message),
                guard,
            };
        }

        StepVerdict {
            step_index: index,
            verdict: StepVerdictKind::Allowed,
            reason: None,
            guard: None,
        }
    }

    #[doc(hidden)]
    fn evaluate_tool_call_sync_inner(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            None,
        )
    }

    /// Evaluate a tool call sync path with access to the owning session,
    /// so the kernel can tag the resulting receipt with the session's
    /// tenant_id (multi-tenant receipt isolation).
    ///
    /// `session_id` is the session that authenticated the caller, used only
    /// to resolve the tenant from `auth_context().enterprise_identity`. The
    /// tenant_id is NEVER read from `request` itself -- accepting a caller-
    /// provided tenant would defeat the isolation guarantee.
    pub(crate) fn evaluate_tool_call_sync_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
        ))
    }

    async fn evaluate_tool_call_async_with_session_context(
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

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
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
            Err(e) => {
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

        let (matched_grant_index, charge_result) = match self.check_and_increment_budget(
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
            charge_result.as_ref(),
            None,
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
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
                                Some(("reversed", &reverse)),
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

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
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
                            Some(("reversed", &reverse)),
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

        let runtime_admission =
            self.run_runtime_admission_hook(request, now, now_unix_ms, Some(matched_grant_index));
        let extra_metadata =
            merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self
                    .build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
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
                                Some(("reversed", &reverse)),
                            ),
                        ),
                    );
            }
            return self.build_runtime_admission_deny_response_with_metadata(
                request,
                &msg,
                now,
                Some(matched_grant_index),
                extra_metadata,
            );
        }

        if let Err(reason) = self.admit_capability_budget(cap) {
            let msg = format!("sibling-sum budget admission failed: {reason}");
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            self.release_runtime_admission_reservations(extra_metadata.as_ref())?;
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
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
                            Some(("reversed", &reverse)),
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

        let payment_authorization = match self
            .authorize_payment_if_needed(request, charge_result.as_ref())
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let msg = format!("payment authorization failed: {error}");
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment denied");
                self.release_runtime_admission_reservations(extra_metadata.as_ref())?;
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
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
                                Some(("reversed", &reverse)),
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

        let tool_started_at = Instant::now();
        let has_monetary = charge_result.is_some();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            charge_result.as_ref(),
            payment_authorization.as_ref(),
            extra_metadata.clone(),
        );
        let dispatch_result = self
            .dispatch_tool_call_with_cost(request, has_monetary)
            .await;
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let _ = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
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
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call cancelled"
                );
                return self.build_cancelled_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => extra_metadata.clone(),
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                return self.build_incomplete_response_with_output_and_metadata(
                    request,
                    None,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => extra_metadata.clone(),
                    },
                );
            }
            Err(e) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                if dispatch_error_precedes_tool_side_effect(&e) {
                    self.release_runtime_admission_reservations(extra_metadata.as_ref())?;
                }
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => extra_metadata.clone(),
                    },
                );
            }
        };
        self.finalize_budgeted_tool_output_with_cost_and_metadata(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            FinalizeToolOutputCostContext {
                charge_result,
                reported_cost,
                payment_authorization,
                cap,
            },
            extra_metadata,
        )
    }

    pub(crate) fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_with_nested_flow_client_async(
            parent_context,
            request,
            client,
        ))
    }

    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
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

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
            Err(e) => {
                let msg = e.to_string();
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

        let (matched_grant_index, charge_result) = match self.check_and_increment_budget(
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
            charge_result.as_ref(),
            Some(parent_context),
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", &reverse)),
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

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            Some(session_roots.as_slice()),
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    charge,
                    reverse.committed_cost_units_after,
                    cap,
                    Some(
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", &reverse)),
                        ),
                    ),
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let runtime_admission =
            self.run_runtime_admission_hook(request, now, now_unix_ms, Some(matched_grant_index));
        let runtime_admission_metadata = runtime_admission.metadata.clone();
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self
                    .build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
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
                                Some(("reversed", &reverse)),
                            ),
                        ),
                    );
            }
            return self.build_runtime_admission_deny_response_with_metadata(
                request,
                &msg,
                now,
                Some(matched_grant_index),
                runtime_admission.metadata,
            );
        }

        if let Err(reason) = self.admit_capability_budget(cap) {
            let msg = format!("sibling-sum budget admission failed: {reason}");
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            self.release_runtime_admission_reservations(runtime_admission_metadata.as_ref())?;
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response_with_metadata(
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
                            Some(("reversed", &reverse)),
                        ),
                    ),
                );
            }
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                Some(matched_grant_index),
                runtime_admission_metadata.clone(),
            );
        }

        let payment_authorization = match self
            .authorize_payment_if_needed(request, charge_result.as_ref())
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let msg = format!("payment authorization failed: {error}");
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment denied");
                self.release_runtime_admission_reservations(runtime_admission_metadata.as_ref())?;
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
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
                                Some(("reversed", &reverse)),
                            ),
                        ),
                    );
                }
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    runtime_admission_metadata.clone(),
                );
            }
        };

        let tool_started_at = Instant::now();
        let mut child_receipts = Vec::new();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            charge_result.as_ref(),
            payment_authorization.as_ref(),
            runtime_admission_metadata.clone(),
        );
        let tool_output_result = {
            let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
                KernelError::ToolNotRegistered(format!(
                    "server \"{}\" / tool \"{}\"",
                    request.server_id, request.tool_name
                ))
            })?;
            let mut bridge = SessionNestedFlowBridge {
                sessions: &self.sessions,
                child_receipts: &mut child_receipts,
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
        drop(post_admission_drop_guard);
        self.record_child_receipts(child_receipts)?;
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let _ = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
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
                    charge_result.as_ref(),
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
                return self.build_cancelled_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            runtime_admission_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => runtime_admission_metadata.clone(),
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                return self.build_incomplete_response_with_output_and_metadata(
                    request,
                    None,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            runtime_admission_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => runtime_admission_metadata.clone(),
                    },
                );
            }
            Err(error) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                if dispatch_error_precedes_tool_side_effect(&error) {
                    self.release_runtime_admission_reservations(
                        runtime_admission_metadata.as_ref(),
                    )?;
                }
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                            runtime_admission_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                        _ => runtime_admission_metadata.clone(),
                    },
                );
            }
        };
        self.finalize_budgeted_tool_output_with_cost_and_metadata(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            FinalizeToolOutputCostContext {
                charge_result,
                reported_cost: None,
                payment_authorization,
                cap,
            },
            runtime_admission_metadata,
        )
    }
}
