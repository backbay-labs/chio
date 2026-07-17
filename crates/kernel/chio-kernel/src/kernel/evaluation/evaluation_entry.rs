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
        // RSS soft ceiling: shed new admissions before the OS OOM-kills the
        // mediator. The tool-call fast path sheds here; a
        // resource/prompt/completion or any other non-tool capability-backed
        // operation that flows through this helper must shed on the SAME soft
        // ceiling, or a large read_resource / prompt completion could still
        // allocate and execute under RSS pressure while tool calls are being shed.
        // Fail-closed: return Overloaded so the soft ceiling sheds ALL new
        // admissions uniformly and the tower load-shed edge surfaces backpressure.
        if self.is_rss_shedding() {
            return Err(KernelError::Overloaded {
                resource: crate::OverloadResource::Allocation,
            });
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
        self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            None,
            None,
            PreflightHoldDisposition::ReverseForRetry,
        )
        .await
    }

    pub async fn evaluate_tool_call_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            extra_metadata,
            None,
            PreflightHoldDisposition::ReverseForRetry,
        )
        .await
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
    /// Plan evaluation does not emit receipts. The kernel emits structured
    /// trace spans for the plan and every per-step verdict so operators can
    /// correlate plan evaluations with subsequent tool-call receipts.
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: step.model_metadata.clone(),
            federated_origin_kernel_id: None,
        };

        let matching_grants = match resolve_required_matching_grants(
            cap,
            &synthesised.tool_name,
            &synthesised.server_id,
            &synthesised.arguments,
            synthesised.model_metadata.as_ref(),
        ) {
            Ok(grants) => grants,
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

        // Fail-closed: any guard error reads as a denial so the caller still
        // sees a per-step reason string.
        if let Err(error) =
            self.run_guards(&synthesised, &cap.scope, None, Some(matched_grant_index))
        {
            // Attempt to extract the offending guard name from the
            // canonical `guard "<name>" denied the request` format
            // emitted by run_guards.
            let message = error.error.to_string();
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
}
