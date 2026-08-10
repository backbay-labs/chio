struct NestedChildThenUrlElicitationServer {
    id: String,
    tool: String,
    invocations: std::sync::Arc<AtomicU64>,
    child_operations: std::sync::Arc<AtomicU64>,
}

struct NestedNotificationThenUrlElicitationServer;

struct CancellationPollThenUrlElicitationServer;

struct RevalidationReadyRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
}

struct NestedMutationExecutionNonceStore {
    inner: InMemoryExecutionNonceStore,
    mutable_state: std::sync::Arc<AtomicBool>,
}

impl ExecutionNonceStore for NestedMutationExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.inner.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.inner.reserve_until(nonce_id, nonce_expires_at)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.mutable_state.store(true, Ordering::Release);
        self.inner
            .reserve_for_dispatch(nonce_id, nonce_expires_at, reservation_id)
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.inner
            .rollback_dispatch_reservation(nonce_id, reservation_id)
    }
}

struct NestedReservationMutationGuard {
    mutable_state: std::sync::Arc<AtomicBool>,
    revalidations: std::sync::Arc<AtomicU64>,
}

impl Guard for NestedReservationMutationGuard {
    fn name(&self) -> &str {
        "nested-reservation-mutation"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.mutable_state.load(Ordering::Acquire) {
            return Err(KernelError::GuardDenied(
                "credential reservation invalidated mutable guard state".to_string(),
            ));
        }
        Ok(())
    }
}

impl RuntimeAdmissionHook for RevalidationReadyRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "nested-url-revalidation-ready"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": format!("admission-{}", context.request.request_id),
                "accepted": true,
                "reserved_destructive_lease_id": format!(
                    "lease-{}",
                    context.request.request_id
                ),
                "failure_code": null
            }
        }))))
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedChildThenUrlElicitationServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool.clone()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge missing".to_string()))?;
        let _ = bridge.list_roots();
        self.child_operations.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation requested after nested child work".to_string(),
            elicitations: Vec::new(),
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedNotificationThenUrlElicitationServer {
    fn server_id(&self) -> &str {
        "nested-notification-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["notify".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge missing".to_string()))?;
        bridge.notify_resources_list_changed()?;
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation requested after nested notification".to_string(),
            elicitations: Vec::new(),
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CancellationPollThenUrlElicitationServer {
    fn server_id(&self) -> &str {
        "nested-cancellation-poll-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["poll".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge missing".to_string()))?;
        bridge.poll_parent_cancellation()?;
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation requested after a cancellation poll".to_string(),
            elicitations: Vec::new(),
        })
    }
}

#[test]
fn nested_child_before_url_elicitation_is_terminal_and_consumes_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let child_operations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(NestedChildThenUrlElicitationServer {
        id: "nested-url-server".to_string(),
        tool: "mutate".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
        child_operations: std::sync::Arc::clone(&child_operations),
    }));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        RevalidationReadyRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
        },
    ));

    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );

    let agent_keypair = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_keypair,
        make_scope(vec![make_grant("nested-url-server", "mutate")]),
        300,
    );
    let request = make_request_with_arguments(
        "nested-child-before-url",
        &capability,
        "mutate",
        "nested-url-server",
        serde_json::json!({"record": "settlement"}),
    );
    let nonce_binding = binding_for_request(&capability, &request);
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &nonce_config);
    let session_id = kernel.open_session(
        agent_keypair.public_key().to_hex(),
        vec![capability.clone()],
    )?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        &request.request_id,
        &agent_keypair.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: Some(serde_json::to_value(&nonce)?),
        model_metadata: None,
        extra_metadata: None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_operation_with_nested_flow_client_async(
                &context,
                &operation,
                &mut client,
            )
            .await
    });

    assert!(matches!(
        result,
        Err(KernelError::UrlElicitationsRequired { .. })
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(child_operations.load(Ordering::SeqCst), 1);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime admission reservations must remain consumed after nested work"
    );
    let parent_receipts = kernel.receipt_log();
    assert_eq!(parent_receipts.len(), 1);
    let parent_receipt_entries = parent_receipts.receipts();
    let metadata = parent_receipt_entries[0]
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("parent receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert!(
        kernel
            .verify_presented_execution_nonce(&nonce, &nonce_binding)
            .is_err(),
        "the execution nonce must not be reusable after nested work"
    );

    assert!(matches!(
        &parent_receipts.receipts()[0].decision,
        Some(Decision::Cancelled { .. })
    ));
    let child_receipts = kernel.child_receipt_log();
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts.receipts()[0].parent_request_id, context.request_id);
    Ok(())
}

#[test]
fn nested_notification_before_url_elicitation_is_terminal_without_child_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedNotificationThenUrlElicitationServer));

    let agent_keypair = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_keypair,
        make_scope(vec![make_grant("nested-notification-server", "notify")]),
        300,
    );
    let request = make_request(
        "nested-notification-before-url",
        &capability,
        "notify",
        "nested-notification-server",
    );
    let session_id = kernel.open_session(
        agent_keypair.public_key().to_hex(),
        vec![capability.clone()],
    )?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        &request.request_id,
        &agent_keypair.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: request.server_id,
        tool_name: request.tool_name,
        arguments: request.arguments,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_operation_with_nested_flow_client_async(
                &context,
                &operation,
                &mut client,
            )
            .await
    });

    assert!(matches!(
        result,
        Err(KernelError::UrlElicitationsRequired { .. })
    ));
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(kernel.child_receipt_log().is_empty());
    Ok(())
}

#[test]
fn cancellation_poll_before_url_elicitation_records_ambiguous_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(CancellationPollThenUrlElicitationServer));

    let agent_keypair = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_keypair,
        make_scope(vec![make_grant("nested-cancellation-poll-server", "poll")]),
        300,
    );
    let request = make_request(
        "nested-poll-before-url",
        &capability,
        "poll",
        "nested-cancellation-poll-server",
    );
    let session_id = kernel.open_session(
        agent_keypair.public_key().to_hex(),
        vec![capability.clone()],
    )?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        &request.request_id,
        &agent_keypair.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert!(matches!(
        result,
        Err(KernelError::UrlElicitationsRequired { message, .. })
            if message == "URL elicitation requested after a cancellation poll"
    ));
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    assert!(matches!(
        &receipt_log.receipts()[0].decision,
        Some(Decision::Cancelled { .. })
    ));
    assert!(kernel.child_receipt_log().is_empty());
    Ok(())
}

#[test]
fn nested_flow_revalidates_after_credential_reservation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "nested-reservation-server",
        vec!["mutate"],
        std::sync::Arc::clone(&invocations),
    )));

    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(NestedMutationExecutionNonceStore {
            inner: InMemoryExecutionNonceStore::from_config(&nonce_config),
            mutable_state: std::sync::Arc::clone(&mutable_state),
        }),
    );
    let revalidations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.add_guard(Box::new(NestedReservationMutationGuard {
        mutable_state,
        revalidations: std::sync::Arc::clone(&revalidations),
    }));

    let agent_keypair = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_keypair,
        make_scope(vec![make_grant("nested-reservation-server", "mutate")]),
        300,
    );
    let request = make_request(
        "nested-post-reservation-revalidation",
        &capability,
        "mutate",
        "nested-reservation-server",
    );
    let nonce_binding = binding_for_request(&capability, &request);
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &nonce_config);
    let session_id = kernel.open_session(
        agent_keypair.public_key().to_hex(),
        vec![capability.clone()],
    )?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        &request.request_id,
        &agent_keypair.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: Some(serde_json::to_value(&nonce)?),
        model_metadata: None,
        extra_metadata: None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_operation_with_nested_flow_client_async(
                &context,
                &operation,
                &mut client,
            )
            .await
    })?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        revalidations.load(Ordering::SeqCst),
        1,
        "credential reservation must force a fresh mutable-state revalidation"
    );
    kernel.verify_presented_execution_nonce(&nonce, &nonce_binding)?;
    Ok(())
}
