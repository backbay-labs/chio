struct RevocationWindowServer {
    id: String,
    tools: Vec<String>,
    started: std::sync::Arc<tokio::sync::Notify>,
    released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    release_notify: std::sync::Arc<tokio::sync::Notify>,
    invocations: std::sync::Arc<AtomicU64>,
}

struct PanickingDispatchExecutionNonceStore {
    panic_during_reserve: bool,
    panic_during_rollback: bool,
    reserve_calls: std::sync::Arc<AtomicU64>,
    rollback_calls: std::sync::Arc<AtomicU64>,
}

struct PanickingDispatchCredentialFixture {
    kernel: ChioKernel,
    capability: CapabilityToken,
    request: ToolCallRequest,
    reserve_calls: std::sync::Arc<AtomicU64>,
    rollback_calls: std::sync::Arc<AtomicU64>,
}

impl ExecutionNonceStore for PanickingDispatchExecutionNonceStore {
    fn reserve(&self, _nonce_id: &str) -> Result<bool, KernelError> {
        Ok(true)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        _nonce_id: &str,
        _nonce_expires_at: i64,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_calls.fetch_add(1, Ordering::SeqCst);
        if self.panic_during_reserve {
            panic!("sensitive execution nonce reserve panic payload");
        }
        Ok(true)
    }

    fn rollback_dispatch_reservation(
        &self,
        _nonce_id: &str,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.rollback_calls.fetch_add(1, Ordering::SeqCst);
        if self.panic_during_rollback {
            panic!("sensitive execution nonce rollback panic payload");
        }
        Ok(true)
    }
}

#[derive(Default)]
struct CapturingRuntimeTraceObserver {
    source_sequences: Mutex<Vec<u64>>,
}

impl RuntimeTraceObserver for CapturingRuntimeTraceObserver {
    fn observe(&self, event: RuntimeTraceEvent) {
        let source_sequence = match event {
            RuntimeTraceEvent::RevocationCommitted {
                source_sequence, ..
            }
            | RuntimeTraceEvent::RevocationAdmission {
                source_sequence, ..
            }
            | RuntimeTraceEvent::ReceiptAppended {
                source_sequence, ..
            } => source_sequence,
        };
        match self.source_sequences.lock() {
            Ok(mut source_sequences) => source_sequences.push(source_sequence),
            Err(poisoned) => poisoned.into_inner().push(source_sequence),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for RevocationWindowServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        while !self.released.load(Ordering::Acquire) {
            self.release_notify.notified().await;
        }
        Ok(serde_json::json!({"status": "completed"}))
    }
}

fn install_revocation_window_server(
    kernel: &mut ChioKernel,
    server: &str,
    tool: &str,
) -> (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<AtomicU64>,
) {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(RevocationWindowServer {
        id: server.to_string(),
        tools: vec![tool.to_string()],
        started: std::sync::Arc::clone(&started),
        released: std::sync::Arc::clone(&released),
        release_notify: std::sync::Arc::clone(&release_notify),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    (started, released, release_notify, invocations)
}

fn request_with_replayed_approval(
    request_id: &str,
) -> Result<
    (
        ChioKernel,
        Keypair,
        CapabilityToken,
        ToolCallRequest,
        crate::execution_nonce::NonceBinding,
    ),
    KernelError,
> {
    let server = "dispatch-credentials-server";
    let tool = "execute";
    let agent = make_keypair();
    let (mut kernel, capability) = make_dpop_kernel_and_cap(&agent, server, tool);
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );

    let arguments = serde_json::json!({"operation": "settle"});
    let mut request =
        make_request_with_arguments(request_id, &capability, tool, server, arguments.clone());
    let intent = make_governed_intent(
        "dispatch-credentials-intent",
        server,
        tool,
        "settle approved operation",
        1,
        "USD",
    );
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &capability.subject,
        &intent,
        request_id,
    ));
    request.governed_intent = Some(intent);
    request.dpop_proof = Some(make_dpop_proof(
        &agent,
        &capability,
        server,
        tool,
        &arguments,
        &format!("dpop-{request_id}"),
    ));
    let binding = binding_for_request(&capability, &request);
    request.execution_nonce = Some(mint_execution_nonce(
        &kernel.config.keypair,
        binding.clone(),
        &nonce_config,
        i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX),
    )?);

    kernel.consume_governed_approval_for_dispatch(&request)?;
    Ok((kernel, agent, capability, request, binding))
}

fn assert_earlier_credentials_remain_fresh(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    binding: &crate::execution_nonce::NonceBinding,
) -> Result<(), Box<dyn std::error::Error>> {
    let execution_nonce = request
        .execution_nonce
        .as_ref()
        .ok_or_else(|| std::io::Error::other("execution nonce missing"))?;
    kernel.verify_presented_execution_nonce(execution_nonce, binding)?;
    kernel.verify_dpop_for_request(request, capability)?;
    Ok(())
}

fn request_with_panicking_execution_nonce_store(
    request_id: &str,
    panic_during_reserve: bool,
    panic_during_rollback: bool,
) -> Result<PanickingDispatchCredentialFixture, KernelError> {
    let server = "dispatch-credential-panic-server";
    let tool = "execute";
    let agent = make_keypair();
    let (mut kernel, capability) = make_dpop_kernel_and_cap(&agent, server, tool);
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let reserve_calls = std::sync::Arc::new(AtomicU64::new(0));
    let rollback_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(PanickingDispatchExecutionNonceStore {
            panic_during_reserve,
            panic_during_rollback,
            reserve_calls: std::sync::Arc::clone(&reserve_calls),
            rollback_calls: std::sync::Arc::clone(&rollback_calls),
        }),
    );

    let arguments = serde_json::json!({"operation": "settle"});
    let mut request =
        make_request_with_arguments(request_id, &capability, tool, server, arguments.clone());
    request.dpop_proof = Some(make_dpop_proof(
        &agent,
        &capability,
        server,
        tool,
        &arguments,
        &format!("dpop-{request_id}"),
    ));
    let binding = binding_for_request(&capability, &request);
    request.execution_nonce = Some(mint_execution_nonce(
        &kernel.config.keypair,
        binding,
        &nonce_config,
        i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX),
    )?);

    Ok(PanickingDispatchCredentialFixture {
        kernel,
        capability,
        request,
        reserve_calls,
        rollback_calls,
    })
}

#[test]
fn dispatch_credential_reserve_panic_is_contained_and_rolled_back(
) -> Result<(), Box<dyn std::error::Error>> {
    let PanickingDispatchCredentialFixture {
        kernel,
        capability,
        request,
        reserve_calls,
        rollback_calls,
    } = request_with_panicking_execution_nonce_store("credential-reserve-panic", true, false)?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kernel.reserve_dispatch_credentials(&request, &capability, true, current_unix_timestamp())
    }));
    let Ok(Err(error)) = result else {
        panic!("reservation panic must become a fail-closed error");
    };
    let error = error.to_string();
    assert!(error.contains("execution nonce reservation panicked; denying fail-closed"));
    assert!(!error.contains("sensitive execution nonce reserve panic payload"));
    assert_eq!(reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rollback_calls.load(Ordering::SeqCst), 1);
    kernel.verify_dpop_for_request(&request, &capability)?;
    Ok(())
}

#[test]
fn dispatch_credential_rollback_panic_is_contained_and_aggregated(
) -> Result<(), Box<dyn std::error::Error>> {
    let PanickingDispatchCredentialFixture {
        kernel,
        capability,
        request,
        reserve_calls,
        rollback_calls,
    } = request_with_panicking_execution_nonce_store("credential-rollback-panic", false, true)?;
    let reservation = kernel.reserve_dispatch_credentials(
        &request,
        &capability,
        true,
        current_unix_timestamp(),
    )?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reservation.rollback_before_dispatch()
    }));
    let Ok(Err(error)) = result else {
        panic!("rollback panic must become a fail-closed error");
    };
    let error = error.to_string();
    assert!(error.contains("execution nonce reservation rollback panicked"));
    assert!(!error.contains("sensitive execution nonce rollback panic payload"));
    assert_eq!(reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rollback_calls.load(Ordering::SeqCst), 1);
    kernel.verify_dpop_for_request(&request, &capability)?;
    Ok(())
}

#[test]
fn dispatch_credential_drop_contains_rollback_panic_during_unwind(
) -> Result<(), Box<dyn std::error::Error>> {
    let PanickingDispatchCredentialFixture {
        kernel,
        capability,
        request,
        reserve_calls,
        rollback_calls,
    } = request_with_panicking_execution_nonce_store("credential-drop-panic", false, true)?;
    let reservation = kernel.reserve_dispatch_credentials(
        &request,
        &capability,
        true,
        current_unix_timestamp(),
    )?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _reservation = reservation;
        panic!("outer evaluation panic");
    }));
    let Err(payload) = result else {
        panic!("the outer evaluation panic must remain observable");
    };
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("outer evaluation panic")
    );
    assert_eq!(reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rollback_calls.load(Ordering::SeqCst), 1);
    kernel.verify_dpop_for_request(&request, &capability)?;
    Ok(())
}

#[test]
fn committed_dispatch_credential_retains_replay_marker_under_capacity_pressure(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "committed-credential-capacity-server";
    let tool = "execute";
    let agent = make_keypair();
    let (mut kernel, capability) = make_dpop_kernel_and_cap(&agent, server, tool);
    kernel.set_dpop_store(
        dpop::DpopNonceStore::new(1, Duration::from_secs(60)),
        dpop::DpopConfig::default(),
    );

    let arguments = serde_json::json!({"operation": "settle"});
    let mut committed_request = make_request_with_arguments(
        "committed-credential-capacity-first",
        &capability,
        tool,
        server,
        arguments.clone(),
    );
    committed_request.dpop_proof = Some(make_dpop_proof(
        &agent,
        &capability,
        server,
        tool,
        &arguments,
        "committed-credential-capacity-nonce-a",
    ));
    let reservation = kernel.reserve_dispatch_credentials(
        &committed_request,
        &capability,
        true,
        current_unix_timestamp(),
    )?;
    let _disposition = reservation.commit()?;

    assert!(kernel
        .verify_dpop_for_request(&committed_request, &capability)
        .is_err());

    let mut pressure_request = make_request_with_arguments(
        "committed-credential-capacity-second",
        &capability,
        tool,
        server,
        arguments.clone(),
    );
    pressure_request.dpop_proof = Some(make_dpop_proof(
        &agent,
        &capability,
        server,
        tool,
        &arguments,
        "committed-credential-capacity-nonce-b",
    ));
    let capacity_error = match kernel.reserve_dispatch_credentials(
        &pressure_request,
        &capability,
        true,
        current_unix_timestamp(),
    ) {
        Ok(_) => {
            return Err(std::io::Error::other(
                "capacity pressure accepted a new credential after commit",
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(capacity_error.to_string().contains("capacity exhausted"));
    assert!(kernel
        .verify_dpop_for_request(&committed_request, &capability)
        .is_err());
    Ok(())
}

#[test]
fn committed_approval_retains_signed_horizon_under_capacity_pressure(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "committed-approval-horizon-server";
    let tool = "execute";
    let agent = make_keypair();
    let (mut kernel, capability) = make_dpop_kernel_and_cap(&agent, server, tool);
    kernel
        .set_governed_approval_replay_store(Box::new(InMemoryGovernedApprovalReplayStore::new(1)));

    let intent = make_governed_intent(
        "committed-approval-horizon-intent",
        server,
        tool,
        "settle approved operation",
        1,
        "USD",
    );
    let mut committed_request = make_request_with_arguments(
        "committed-approval-horizon-first",
        &capability,
        tool,
        server,
        serde_json::json!({"operation": "settle"}),
    );
    committed_request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &capability.subject,
        &intent,
        &committed_request.request_id,
    ));
    committed_request.governed_intent = Some(intent.clone());

    let reservation = kernel.reserve_dispatch_credentials(
        &committed_request,
        &capability,
        false,
        current_unix_timestamp(),
    )?;
    let _disposition = reservation.commit()?;

    let replay_error = match kernel.reserve_dispatch_credentials(
        &committed_request,
        &capability,
        false,
        current_unix_timestamp(),
    ) {
        Ok(_) => return Err(std::io::Error::other("approval replay was accepted").into()),
        Err(error) => error,
    };
    assert!(replay_error
        .to_string()
        .contains("approval token has already been consumed"));

    let mut pressure_request = make_request_with_arguments(
        "committed-approval-horizon-second",
        &capability,
        tool,
        server,
        serde_json::json!({"operation": "settle"}),
    );
    pressure_request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &capability.subject,
        &intent,
        &pressure_request.request_id,
    ));
    pressure_request.governed_intent = Some(intent);
    let capacity_error = match kernel.reserve_dispatch_credentials(
        &pressure_request,
        &capability,
        false,
        current_unix_timestamp(),
    ) {
        Ok(_) => {
            return Err(
                std::io::Error::other("approval capacity pressure evicted a live marker").into(),
            );
        }
        Err(error) => error,
    };
    assert!(capacity_error.to_string().contains("capacity exhausted"));
    Ok(())
}

#[test]
fn governed_dispatch_without_replay_store_denies_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "unconfigured-approval-replay-server";
    let tool = "compute";
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(server, 1, "USD")));
    let agent = make_keypair();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        make_scope(vec![make_governed_monetary_grant(
            server, tool, 10, 100, "USD", 1,
        )]),
        300,
    )?;
    let request_id = "unconfigured-approval-replay-request";
    let intent = make_governed_intent(
        "unconfigured-approval-replay-intent",
        server,
        tool,
        "prove replay storage is mandatory",
        10,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &capability.subject,
        &intent,
        request_id,
    );

    let response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({"operation": "settle"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: Some(approval_token),
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("approval replay store not configured") && reason.contains("fail-closed")
    }));
    Ok(())
}

#[test]
fn hosted_url_elicitation_commits_credentials_without_rollback(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = request_with_panicking_execution_nonce_store(
        "hosted-url-credential-retained",
        false,
        true,
    )?;
    let dispatch_effects = std::sync::Arc::new(AtomicU64::new(0));
    fixture
        .kernel
        .register_tool_server(Box::new(UrlElicitationAfterDispatchServer::new(
            &fixture.request.server_id,
            vec![&fixture.request.tool_name],
            std::sync::Arc::clone(&dispatch_effects),
        )));

    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;

    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(dispatch_effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.rollback_calls.load(Ordering::SeqCst),
        0,
        "credentials must remain consumed once server dispatch was polled"
    );
    assert!(
        fixture
            .kernel
            .verify_dpop_for_request(&fixture.request, &fixture.capability)
            .is_err(),
        "the DPoP proof must not be reusable after an ambiguous dispatch"
    );
    assert_eq!(fixture.kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn nested_url_elicitation_commits_credentials_without_rollback(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = request_with_panicking_execution_nonce_store(
        "nested-url-credential-retained",
        false,
        true,
    )?;
    let dispatch_effects = std::sync::Arc::new(AtomicU64::new(0));
    fixture
        .kernel
        .register_tool_server(Box::new(UrlElicitationAfterDispatchServer::new(
            &fixture.request.server_id,
            vec![&fixture.request.tool_name],
            std::sync::Arc::clone(&dispatch_effects),
        )));
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        &fixture.request.request_id,
        &fixture.request.agent_id,
    );
    fixture
        .kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;

    let response = fixture.kernel.evaluate_tool_call_with_nested_flow_client(
        &context,
        &fixture.request,
        &mut client,
        None,
    )?;

    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(dispatch_effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.rollback_calls.load(Ordering::SeqCst),
        0,
        "nested credentials must remain consumed once server dispatch was polled"
    );
    assert!(
        fixture
            .kernel
            .verify_dpop_for_request(&fixture.request, &fixture.capability)
            .is_err(),
        "the nested DPoP proof must not be reusable after an ambiguous dispatch"
    );
    assert_eq!(fixture.kernel.receipt_log().len(), 1);
    fixture
        .kernel
        .complete_session_request(&session_id, &context.request_id)?;
    Ok(())
}
#[test]
fn terminal_allow_persistence_rechecks_revocation_at_append_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "revocation-append-boundary";
    let tool = "write";
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant(server, tool)]),
        300,
    );
    let request = make_request("revocation-append-boundary", &capability, tool, server);
    let evaluation_context = EvaluationReceiptContext::default();
    let output = ToolCallOutput::Value(serde_json::json!({"status": "completed"}));
    let receipt_content = receipt_content_for_output(Some(&output), None)?;
    let action = ToolCallAction::from_parameters(request.arguments.clone())?;
    let receipt = kernel.build_and_sign_receipt(ReceiptParams {
        evaluation_context: &evaluation_context,
        request_id: Some(&request.request_id),
        capability_id: &capability.id,
        tool_name: &request.tool_name,
        server_id: &request.server_id,
        decision: Decision::Allow,
        action,
        content_hash: receipt_content.content_hash,
        canonical_content: receipt_content.canonical_content,
        metadata: receipt_content.metadata,
        timestamp: current_unix_timestamp(),
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
    })?;

    kernel.revoke_capability(&capability.id)?;
    let result =
        kernel.record_chio_receipt_with_federation(&request, &receipt, &evaluation_context);

    assert!(matches!(
        result,
        Err(KernelError::CapabilityRevoked(ref capability_id))
            if capability_id == &capability.id
    ));
    assert!(kernel.receipt_log().is_empty());
    assert!(!evaluation_context.terminal_receipt_committed());
    Ok(())
}

#[test]
fn installing_runtime_trace_observer_starts_sequence_at_one(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("late-observer-server", "read")]),
        300,
    );
    let request = make_request(
        "late-observer-request",
        &capability,
        "read",
        "late-observer-server",
    );

    kernel.check_tool_call_revocation_admission(&request)?;
    kernel.record_chio_receipt(&make_signed_receipt(
        &kernel.config.keypair,
        "late-observer-receipt",
    ))?;
    kernel.revoke_capability(&capability.id)?;

    assert_eq!(kernel.runtime_trace_sequence.load(Ordering::SeqCst), 0);

    let observer = std::sync::Arc::new(CapturingRuntimeTraceObserver::default());
    kernel.set_runtime_trace_observer(observer.clone());
    let observed_capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("late-observer-server", "write")]),
        300,
    );
    kernel.revoke_capability(&observed_capability.id)?;

    let source_sequences = match observer.source_sequences.lock() {
        Ok(source_sequences) => source_sequences.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert_eq!(source_sequences, vec![1]);
    Ok(())
}

#[test]
fn hosted_late_approval_replay_rolls_back_earlier_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _agent, capability, request, binding) =
        request_with_replayed_approval("hosted-credential-rollback")?;

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("approval token has already been consumed")));
    assert_earlier_credentials_remain_fresh(&kernel, &request, &capability, &binding)
}

#[test]
fn nested_late_approval_replay_rolls_back_credentials_and_dispatch_claim(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, agent, capability, request, binding) =
        request_with_replayed_approval("nested-credential-rollback")?;
    let session_id = kernel.open_session(agent.public_key().to_hex(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;

    let response =
        kernel.evaluate_tool_call_with_nested_flow_client(&context, &request, &mut client, None)?;

    assert_eq!(response.verdict, Verdict::Deny);
    kernel.request_session_cancellation(&session_id, &context.request_id)?;
    assert_earlier_credentials_remain_fresh(&kernel, &request, &capability, &binding)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_revocation_during_dispatch_prevents_allow_finalization(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "revocation-window-hosted";
    let tool = "write";
    let mut kernel = make_kernel(make_config());
    let (started, released, release_notify, invocations) =
        install_revocation_window_server(&mut kernel, server, tool);
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant(server, tool)]),
        300,
    );
    let request = make_request("hosted-revocation-window", &capability, tool, server);
    let kernel = std::sync::Arc::new(kernel);
    let evaluation_kernel = std::sync::Arc::clone(&kernel);
    let evaluation =
        tokio::spawn(async move { evaluation_kernel.evaluate_tool_call(&request).await });

    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    kernel.revoke_capability(&capability.id)?;
    released.store(true, Ordering::Release);
    release_notify.notify_waiters();
    let response = tokio::time::timeout(Duration::from_secs(5), evaluation).await???;

    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(!response.receipt.is_allowed());
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("before allow finalization")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_revocation_during_dispatch_prevents_allow_finalization(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = "revocation-window-nested";
    let tool = "write";
    let mut kernel = make_kernel(make_config());
    let (started, released, release_notify, invocations) =
        install_revocation_window_server(&mut kernel, server, tool);
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant(server, tool)]),
        300,
    );
    let request = make_request("nested-revocation-window", &capability, tool, server);
    let session_id = kernel.open_session(agent.public_key().to_hex(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let kernel = std::sync::Arc::new(kernel);
    let evaluation_kernel = std::sync::Arc::clone(&kernel);
    let evaluation = tokio::spawn(async move {
        let mut client = NoopNestedFlowClient;
        evaluation_kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    kernel.revoke_capability(&capability.id)?;
    released.store(true, Ordering::Release);
    release_notify.notify_waiters();
    let response = tokio::time::timeout(Duration::from_secs(5), evaluation).await???;

    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(!response.receipt.is_allowed());
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("before allow finalization")));
    Ok(())
}
