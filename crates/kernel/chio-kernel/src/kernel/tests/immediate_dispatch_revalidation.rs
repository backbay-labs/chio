struct ImmediateReadyMutationHook {
    mutable_state: std::sync::Arc<AtomicBool>,
    revalidations: std::sync::Arc<AtomicU64>,
    deny_during_revalidation: bool,
}

impl RuntimeAdmissionHook for ImmediateReadyMutationHook {
    fn name(&self) -> &str {
        "immediate-ready-mutation"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::allow(None))
    }

    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.mutable_state.store(true, Ordering::Release);
        std::task::Poll::Ready(())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.deny_during_revalidation && self.mutable_state.load(Ordering::Acquire) {
            return Err(KernelError::GuardDenied(
                "runtime trust state changed before dispatch".to_string(),
            ));
        }
        Ok(())
    }
}

struct ImmediateMutationGuard {
    mutable_state: std::sync::Arc<AtomicBool>,
    revalidations: std::sync::Arc<AtomicU64>,
}

struct LegacyDefaultGuard;

struct LegacyRuntimeAdmissionHook {
    evaluations: std::sync::Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for LegacyRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "legacy-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(None))
    }
}

impl Guard for LegacyDefaultGuard {
    fn name(&self) -> &str {
        "legacy-default-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
}

struct OptInFailingGuard;

impl Guard for OptInFailingGuard {
    fn name(&self) -> &str {
        "opt-in-failing-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        Err(KernelError::GuardDenied(
            "opted-in mutable guard changed before dispatch".to_string(),
        ))
    }
}

impl Guard for ImmediateMutationGuard {
    fn name(&self) -> &str {
        "immediate-mutation-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.mutable_state.load(Ordering::Acquire) {
            return Err(KernelError::GuardDenied(
                "guard trust state changed before dispatch".to_string(),
            ));
        }
        Ok(())
    }
}

fn immediate_revalidation_fixture(
    request_id: &str,
    mutable_state: std::sync::Arc<AtomicBool>,
    hook_revalidations: std::sync::Arc<AtomicU64>,
    deny_during_hook_revalidation: bool,
) -> (
    ChioKernel,
    CapabilityToken,
    ToolCallRequest,
    std::sync::Arc<AtomicU64>,
) {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "immediate-ready-server",
        vec!["mutate"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ImmediateReadyMutationHook {
        mutable_state,
        revalidations: hook_revalidations,
        deny_during_revalidation: deny_during_hook_revalidation,
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("immediate-ready-server", "mutate")]),
        300,
    );
    let request = make_request(request_id, &capability, "mutate", "immediate-ready-server");
    (kernel, capability, request, invocations)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_immediate_dispatch_revalidation_checks_opted_in_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    let hook_revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let guard_revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let (mut kernel, _capability, request, invocations) = immediate_revalidation_fixture(
        "hosted-immediate-ready-mutation",
        std::sync::Arc::clone(&mutable_state),
        std::sync::Arc::clone(&hook_revalidations),
        false,
    );
    kernel.add_guard(Box::new(ImmediateMutationGuard {
        mutable_state,
        revalidations: std::sync::Arc::clone(&guard_revalidations),
    }));

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("guard trust state changed before dispatch")));
    assert_eq!(guard_revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(hook_revalidations.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_immediate_dispatch_revalidation_checks_mutated_runtime_trust_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    let hook_revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let (kernel, capability, request, invocations) = immediate_revalidation_fixture(
        "nested-immediate-ready-mutation",
        mutable_state,
        std::sync::Arc::clone(&hook_revalidations),
        true,
    );
    let session_id = kernel.open_session(request.agent_id.clone(), vec![capability])?;
    kernel.activate_session(&session_id)?;
    let parent_context = make_operation_context(
        &session_id,
        "nested-immediate-ready-parent",
        &request.agent_id,
    );
    kernel.begin_session_request(&parent_context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(
            &parent_context,
            &request,
            &mut client,
            None,
        )
        .await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("runtime trust state changed before dispatch")));
    assert_eq!(hook_revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_credential_revalidation_preserves_legacy_runtime_admission_verdict(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "legacy-admission-server",
        vec!["mutate"],
        std::sync::Arc::clone(&invocations),
    )));
    let evaluations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(LegacyRuntimeAdmissionHook {
        evaluations: std::sync::Arc::clone(&evaluations),
    }));
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );

    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("legacy-admission-server", "mutate")]),
        300,
    );
    let mut request = make_request(
        "legacy-admission-forced-revalidation",
        &capability,
        "mutate",
        "legacy-admission-server",
    );
    let nonce_binding = binding_for_request(&capability, &request);
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &nonce_config);
    request.execution_nonce = Some(nonce.clone());

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(
        kernel
            .verify_presented_execution_nonce(&nonce, &nonce_binding)
            .is_err(),
        "the forced pass must preserve the allow verdict and commit the nonce"
    );
    Ok(())
}

#[test]
fn guard_dispatch_revalidation_is_opt_in_and_opted_in_errors_fail_closed() {
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    let hook_revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let (_kernel, _capability, request, _invocations) = immediate_revalidation_fixture(
        "guard-revalidation-contract",
        mutable_state,
        hook_revalidations,
        false,
    );
    let context = GuardContext {
        request: &request,
        scope: &request.capability.scope,
        agent_id: &request.agent_id,
        server_id: &request.server_id,
        session_filesystem_roots: None,
        matched_grant_index: Some(0),
    };

    let legacy = LegacyDefaultGuard;
    assert!(!legacy.requires_dispatch_revalidation());
    legacy.revalidate_before_dispatch(&context).unwrap();
    legacy
        .revalidate_required_before_dispatch(&context)
        .unwrap();

    let opted_in = OptInFailingGuard;
    assert!(opted_in.requires_dispatch_revalidation());
    assert!(matches!(
        opted_in.revalidate_required_before_dispatch(&context),
        Err(KernelError::GuardDenied(reason))
            if reason == "opted-in mutable guard changed before dispatch"
    ));
}

#[test]
fn nested_bridge_cancellation_blocks_next_child_and_drop_clears_dispatch_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let session_id = kernel.open_session(agent.public_key().to_hex(), Vec::new())?;
    kernel.activate_session(&session_id)?;
    let parent_context = make_operation_context(
        &session_id,
        "nested-bridge-cancelled-parent",
        &agent.public_key().to_hex(),
    );
    kernel.begin_session_request(&parent_context, OperationKind::ToolCall, true)?;
    kernel.mark_session_request_dispatch_started(
        Some(&session_id),
        parent_context.request_id.as_str(),
    )?;
    assert!(kernel
        .session(&session_id)
        .is_some_and(|session| session.is_request_dispatch_active(&parent_context.request_id)));

    let mut child_receipts = Vec::new();
    let mut client = NoopNestedFlowClient;
    let nested_interaction_observed = AtomicBool::new(false);
    {
        let mut bridge = SessionNestedFlowBridge {
            sessions: &kernel.sessions,
            child_receipts: &mut child_receipts,
            nested_interaction_observed: &nested_interaction_observed,
            parent_context: &parent_context,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            policy_hash: &kernel.config.policy_hash,
            kernel_keypair: &kernel.config.keypair,
            client: &mut client,
        };
        let cancellation: Result<(), KernelError> = Err(KernelError::RequestCancelled {
            request_id: parent_context.request_id.clone(),
            reason: "client cancelled between nested children".to_string(),
        });
        bridge.latch_matching_cancellation(&cancellation, None)?;

        let error = bridge
            .list_roots()
            .expect_err("a cancelled parent must block the next nested child");
        assert!(matches!(
            error,
            KernelError::RequestCancelled { request_id, reason }
                if request_id == parent_context.request_id
                    && reason == "client cancelled between nested children"
        ));
    }

    let child_error = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("nested-child-after-cancel"),
            OperationKind::ListRoots,
            None,
            false,
        )
        .expect_err("the atomic child-start boundary must retain parent cancellation");
    assert!(matches!(
        child_error,
        KernelError::RequestCancelled { request_id, reason }
            if request_id == parent_context.request_id
                && reason == "client cancelled between nested children"
    ));

    let session = kernel
        .session(&session_id)
        .ok_or_else(|| std::io::Error::other("test session missing"))?;
    assert!(!session.is_request_dispatch_active(&parent_context.request_id));
    assert!(session
        .inflight()
        .get(&parent_context.request_id)
        .is_some_and(|request| request.cancellation_requested));
    Ok(())
}

#[test]
fn cancelled_dispatch_start_preserves_authoritative_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let session_id = kernel.open_session(agent.public_key().to_hex(), Vec::new())?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "dispatch-start-reason",
        &agent.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    kernel.request_session_cancellation_with_reason(
        &session_id,
        &context.request_id,
        "cancelled before effect",
    )?;

    let error = kernel
        .mark_session_request_dispatch_started(Some(&session_id), context.request_id.as_str())
        .expect_err("cancelled request must not start dispatch");
    assert!(matches!(
        error,
        KernelError::RequestCancelled { request_id, reason }
            if request_id == context.request_id && reason == "cancelled before effect"
    ));
    Ok(())
}
