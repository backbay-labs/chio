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
