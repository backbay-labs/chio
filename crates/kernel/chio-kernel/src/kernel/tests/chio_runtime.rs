// Chio runtime admission hook tests.
//
// These cover the generic pre-dispatch hook that Chio 7.0 uses to deny
// cross-vendor workflow steps before tool execution or federation side effects.

struct DenyingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct AllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct MetadataInspectingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct LiveReceiptAllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct ReleaseTrackingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    expected_request_id: &'static str,
    admission_id: &'static str,
    lease_id: &'static str,
    continuation_id: Option<&'static str>,
}

struct FailingReleaseRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    expected_request_id: &'static str,
    admission_id: &'static str,
    lease_id: &'static str,
}

struct FailingAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
}

struct UrlElicitationBeforeSideEffectServer {
    id: String,
    tools: Vec<String>,
    stream_attempts: std::sync::Arc<AtomicU64>,
}

struct CancellationAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

struct IncompleteAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

// A registered tool server whose dispatch succeeds but returns a
// successful-yet-incomplete stream (e.g. stream-limit truncation). Unlike
// `IncompleteAfterSideEffectServer` (which returns `Err(RequestIncomplete)`
// and lands in the RequestIncomplete error arm), this drives the
// `Ok(ToolServerStreamResult::Incomplete)` finalize path, where the
// runtime-admission lease is still consumed after the side effect.
struct IncompleteStreamAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

// A registered tool server (passes the pre-dispatch
// `ensure_registered_tool_target` check, so the runtime admission hook
// still fires and reserves) whose dispatch call itself fails with
// `KernelError::ToolNotRegistered`. This is the only way to exercise the
// generic-error arm's `dispatch_error_precedes_tool_side_effect(&e) ==
// true` branch: the pre-dispatch registration check denies an
// actually-unregistered server_id before the admission hook ever runs, so
// it can never reach that arm.
struct ToolNotRegisteredDispatchServer {
    id: String,
    tools: Vec<String>,
}

struct NoopNestedFlowClient;

impl RuntimeAdmissionHook for DenyingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chio-runtime-deny");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::deny(
            "chio runtime admission denied",
            Some(serde_json::json!({
                "chio_runtime": {
                    "admission_id": "adm-denied",
                    "accepted": false,
                    "failure_code": "test_runtime_deny"
                }
            })),
        ))
    }
}

impl RuntimeAdmissionHook for AllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chio-runtime-allow");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "adm-allowed",
                "accepted": true,
                "failure_code": null,
                "observe_only": true
            }
        }))))
    }
}

impl RuntimeAdmissionHook for MetadataInspectingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-metadata-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bridge = context
            .extra_metadata
            .and_then(|metadata| metadata.get("route"))
            .and_then(|route| route.get("bridge"))
            .and_then(serde_json::Value::as_str);
        if bridge == Some("mcp") {
            Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
                "chio_runtime": {
                    "admission_id": "adm-route-metadata",
                    "accepted": true,
                    "failure_code": null
                }
            }))))
        } else {
            Ok(RuntimeAdmissionDecision::deny(
                "route metadata missing from runtime admission context",
                Some(serde_json::json!({
                    "chio_runtime": {
                        "admission_id": "adm-route-metadata",
                        "accepted": false,
                        "failure_code": "route_metadata_missing"
                    }
                })),
            ))
        }
    }
}

impl RuntimeAdmissionHook for LiveReceiptAllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-live-receipt-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(context.matched_grant_index.is_some());
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": context.request.request_id,
                "accepted": true,
                "failure_code": null,
                "live_receipt_capture": true
            }
        }))))
    }
}

impl RuntimeAdmissionHook for ReleaseTrackingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-release-tracking-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, self.expected_request_id);
        assert_eq!(context.matched_grant_index, Some(0));
        let mut metadata = serde_json::json!({
            "chio_runtime": {
                "admission_id": self.admission_id,
                "accepted": true,
                "reserved_destructive_lease_id": self.lease_id,
                "failure_code": null
            }
        });
        if let Some(continuation_id) = self.continuation_id {
            metadata["chio_runtime"]["reserved_treaty_continuation_id"] =
                serde_json::json!(continuation_id);
        }
        Ok(RuntimeAdmissionDecision::allow(Some(metadata)))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            self.lease_id
        );
        if let Some(continuation_id) = self.continuation_id {
            assert_eq!(
                metadata["chio_runtime"]["reserved_treaty_continuation_id"],
                continuation_id
            );
        }
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl RuntimeAdmissionHook for FailingReleaseRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-failing-release-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, self.expected_request_id);
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": self.admission_id,
                "accepted": true,
                "reserved_destructive_lease_id": self.lease_id,
                "failure_code": null
            }
        }))))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            self.lease_id
        );
        self.releases.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "runtime reservation release failed".to_string(),
        ))
    }
}

impl NestedFlowClient for NoopNestedFlowClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(Vec::new())
    }

    fn create_message(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested createMessage request".to_string(),
        ))
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation request".to_string(),
        ))
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        _elicitation_id: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        _uri: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

impl FailingAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, invocations: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invocations,
        }
    }
}

impl UrlElicitationBeforeSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, stream_attempts: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            stream_attempts,
        }
    }
}

impl CancellationAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

impl IncompleteAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingAfterSideEffectServer {
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
        Err(KernelError::Internal(
            "destructive side effect committed before transport failure".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for UrlElicitationBeforeSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.stream_attempts.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation required before dispatch side effect".to_string(),
            elicitations: Vec::new(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after URL elicitation".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CancellationAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::RequestCancelled {
            request_id: "req-chio-runtime-cancelled".to_string().into(),
            reason: "cancelled after possible dispatch side effect".to_string(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after cancellation".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::RequestIncomplete(
            "incomplete after possible dispatch side effect".to_string(),
        ))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after incomplete request".to_string(),
        ))
    }
}

impl IncompleteStreamAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteStreamAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        // The destructive side effect committed, then the stream was
        // truncated. Dispatch returns Ok(Incomplete), so finalization (not
        // the RequestIncomplete error arm) builds the incomplete receipt.
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Incomplete {
            stream: ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: serde_json::json!({"partial": "vendor-ledger-7"}),
                }],
            },
            reason: "stream truncated after possible dispatch side effect".to_string(),
        }))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected non-stream invoke on incomplete-stream server".to_string(),
        ))
    }
}

impl ToolNotRegisteredDispatchServer {
    fn new(id: &str, tools: Vec<&str>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ToolNotRegisteredDispatchServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Err(KernelError::ToolNotRegistered(format!(
            "tool \"{tool_name}\" withdrawn from server roster before dispatch"
        )))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after tool-not-registered dispatch error".to_string(),
        ))
    }
}

// A registered tool server whose dispatch SUCCEEDS (returns Ok(Value)) after
// committing a destructive side effect. Used to exercise the post-invocation
// Block deny path: the tool has already run and its runtime-admission lease is
// retained (not released) when a POST-invocation output guard blocks the
// returned value.
struct SucceedingAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

impl SucceedingAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SucceedingAfterSideEffectServer {
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
        // The destructive side effect commits, then the tool returns a
        // successful value. A post-invocation output guard blocks this value
        // AFTER the fact, but the side effect is already durable.
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"record": "vendor-ledger-7", "status": "closed"}))
    }
}

// A post-invocation output guard that always blocks the returned value.
// Simulates an output guard that denies a tool response AFTER the tool has
// already executed (and committed a side effect).
struct BlockingPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for BlockingPostInvocationHook {
    fn name(&self) -> &str {
        "test-post-invocation-block"
    }

    fn inspect(
        &self,
        _ctx: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Block(
            "post-invocation output guard blocked destructive tool output".to_string(),
        )
    }
}

fn assert_package_valid_allow_receipt(
    response: &ToolCallResponse,
    request: &ToolCallRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.is_allowed());
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    assert!(
        response.receipt.verify_signature()?,
        "response receipt signature must verify"
    );

    let package = serde_json::to_vec(&response.receipt)?;
    let unpacked: ChioReceipt = serde_json::from_slice(&package)?;
    assert_eq!(unpacked.id, response.receipt.id);
    assert!(
        unpacked.verify_signature()?,
        "serialized receipt package must verify"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_denies_before_tool_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some("chio runtime admission denied"));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-denied");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "test_runtime_deny"
    );
    Ok(())
}

#[test]
fn chio_governed_request_without_runtime_hook_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify Chio admission fails closed without a hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-no-hook",
                "bundleSha256": "a".repeat(64)
            }
        })),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}


#[test]
fn chio_treaty_request_without_runtime_hook_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-treaty-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:treaty-no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify Chio treaty context fails closed without a hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioTreaty": {
                "treatyScopeId": "treaty-buyer-vendor",
                "treatyScopeSha256": "b".repeat(64),
                "ladderIntersectionId": "intersection-live-1",
                "ladderIntersectionSha256": "c".repeat(64),
                "actionClassId": "workflow.destructive.vendor_call"
            }
        })),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_denies_federated_call_before_dispatch_or_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("chio-runtime-deny-no-cosign");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some("chio runtime admission denied"));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "runtime admission denial must not request federation cosign"
    );
    assert!(
        response.receipt.verify_signature()?,
        "deny response receipt signature must verify"
    );
    assert!(response.receipt.is_denied());
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_eq!(kernel.receipt_log().receipts()[0].id, response.receipt.id);
    Ok(())
}

#[test]
fn federated_origin_without_runtime_hook_or_context_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-no-hook-no-context");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let kernel = kernel.with_federation_peers(vec![peer]);

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-federated-no-hook-no-context",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
    Ok(())
}

#[test]
fn chio_swarm_request_without_runtime_hook_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-swarm-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:swarm-no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify swarm authority fails closed without a runtime hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioSwarm": {
                "taskGraph": {
                    "id": "swarm-task-graph-runtime",
                    "sha256": "a".repeat(64)
                },
                "continuationToken": {
                    "id": "swarm-continuation-runtime",
                    "sha256": "b".repeat(64)
                }
            }
        })),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}


#[test]
fn session_tool_call_preserves_chio_swarm_runtime_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-swarm-session-no-hook",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent:chio:swarm-session-no-hook".to_string(),
            server_id: "srv-chio-runtime".to_string(),
            tool_name: "destructive_update".to_string(),
            purpose: "verify session swarm authority fails closed without a runtime hook"
                .to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioSwarm": {
                    "taskGraph": {
                        "id": "swarm-task-graph-runtime",
                        "sha256": "a".repeat(64)
                    },
                    "continuationToken": {
                        "id": "swarm-continuation-runtime",
                        "sha256": "b".repeat(64)
                    }
                }
            })),
        }),
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    }));

    let response = session_tool_call(kernel.evaluate_session_operation(&context, &operation)?)
        .ok_or_else(|| std::io::Error::other("tool call response missing"))?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_allows_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-allow",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let output = tool_call_value_output(response.output)
        .ok_or_else(|| std::io::Error::other("tool output missing"))?;
    assert_eq!(output["tool"], "destructive_update");
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("allow metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-allowed");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(metadata["chio_runtime"]["observe_only"], true);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-route-metadata",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-a"
        }
    });

    let response = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(metadata))?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_nested_flow_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-runtime-nested-route-metadata",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: Some(serde_json::json!({
            "route": {
                "bridge": "mcp",
                "protocolTarget": "mcp://provider-a"
            }
        })),
    };
    let mut client = NoopNestedFlowClient;

    let response =
        kernel.evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| "allow metadata missing".to_string())?;
    assert_eq!(metadata["route"]["bridge"], "mcp");
    assert_eq!(metadata["route"]["protocolTarget"], "mcp://provider-a");
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-route-metadata"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_does_not_release_destructive_lease_after_dispatch_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-dispatch-error",
            admission_id: "adm-dispatch-error",
            lease_id: "lease-dispatch-error",
            continuation_id: None,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-dispatch-error",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "destructive runtime leases must remain consumed after tool dispatch starts"
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("internal error: destructive side effect committed before transport failure")
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-dispatch-error");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-dispatch-error"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_releases_reservations_on_pre_side_effect_dispatch_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-url-elicitation",
            admission_id: "adm-url-elicitation",
            lease_id: "lease-url-elicitation",
            continuation_id: Some("continuation-url-elicitation"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-url-elicitation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("URL elicitation must surface to the caller");

    assert!(matches!(
        error,
        KernelError::UrlElicitationsRequired { .. }
    ));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime reservations must be released when dispatch fails before a tool side effect"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_ambiguous_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-cancelled",
            admission_id: "adm-cancelled",
            lease_id: "lease-cancelled",
            continuation_id: Some("continuation-cancelled"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-cancelled",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime reservations must stay consumed when cancellation does not prove absence of side effects"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_ambiguous_incomplete(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-incomplete",
            admission_id: "adm-incomplete",
            lease_id: "lease-incomplete",
            continuation_id: Some("continuation-incomplete"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime reservations must stay consumed when incompletion does not prove absence of side effects"
    );
    Ok(())
}

#[test]
fn chio_post_admission_drop_guard_retains_non_monetary_runtime_reservations(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-dropped",
            admission_id: "adm-dropped",
            lease_id: "lease-dropped",
            continuation_id: Some("continuation-dropped"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-dropped",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-dropped",
            "reserved_treaty_continuation_id": "continuation-dropped",
            "failure_code": null
        }
    });

    let mutation = PreExecutionBudgetMutation::None;
    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    );
    guard.mark_dispatch_started();
    drop(guard);

    assert_eq!(admission_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-dispatch drop cannot prove absence of side effects, so reservations stay consumed"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a post-dispatch drop must record exactly one cancellation receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    Ok(())
}

#[test]
fn chio_runtime_admission_releases_reservations_on_pre_dispatch_budget_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path: _path,
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-release");

    let allow_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-pre-dispatch-budget-allow".to_string(),
        capability: child_a,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_a_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?;
    assert_eq!(
        allow_response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-pre-dispatch-budget-deny",
            admission_id: "adm-pre-dispatch-budget-deny",
            lease_id: "lease-pre-dispatch-budget-deny",
            continuation_id: Some("continuation-pre-dispatch-budget-deny"),
        },
    ));

    let deny_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-pre-dispatch-budget-deny".to_string(),
        capability: child_b,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?;

    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime reservations must be released before tool dispatch starts"
    );
    let metadata = deny_response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-pre-dispatch-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-pre-dispatch-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_treaty_continuation_id"],
        "continuation-pre-dispatch-budget-deny"
    );
    Ok(())
}

#[test]
fn chio_runtime_release_failure_does_not_mask_pre_dispatch_budget_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path: _path,
    } = make_sibling_sum_monetary_fixture("chio-runtime-release-failure");

    let allow_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-release-failure-budget-allow".to_string(),
        capability: child_a,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_a_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?;
    assert_eq!(
        allow_response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        FailingReleaseRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-release-failure-budget-deny",
            admission_id: "adm-release-failure-budget-deny",
            lease_id: "lease-release-failure-budget-deny",
        },
    ));

    let deny_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-release-failure-budget-deny".to_string(),
        capability: child_b,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?;

    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime release must be attempted before the denial receipt is returned"
    );
    let metadata = deny_response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-release-failure-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-release-failure-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reservation_release_failed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["reservation_release_failure_reason"],
        "internal error: runtime reservation release failed"
    );
    Ok(())
}

#[test]
fn chio_runtime_live_parent_and_vendor_calls_expose_package_valid_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-live",
        vec!["parent_decision", "vendor_quote"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        LiveReceiptAllowingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![
            make_grant("srv-chio-live", "parent_decision"),
            make_grant("srv-chio-live", "vendor_quote"),
        ]),
        300,
    );
    let parent_request = make_request_with_arguments(
        "req-chio-live-parent",
        &cap,
        "parent_decision",
        "srv-chio-live",
        serde_json::json!({"workflow": "chio-7.8", "step": "parent"}),
    );
    let vendor_request = make_request_with_arguments(
        "req-chio-live-vendor-a",
        &cap,
        "vendor_quote",
        "srv-chio-live",
        serde_json::json!({"workflow": "chio-7.8", "step": "vendor-a"}),
    );

    let parent_response = kernel.evaluate_tool_call_blocking(&parent_request)?;
    let vendor_response = kernel.evaluate_tool_call_blocking(&vendor_request)?;

    assert_eq!(admission_calls.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
    assert_package_valid_allow_receipt(&parent_response, &parent_request)?;
    assert_package_valid_allow_receipt(&vendor_response, &vendor_request)?;

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 2);
    assert_eq!(receipt_log.receipts()[0].id, parent_response.receipt.id);
    assert_eq!(receipt_log.receipts()[1].id, vendor_response.receipt.id);
    assert_ne!(parent_response.receipt.id, vendor_response.receipt.id);
    Ok(())
}

// --- Drop-guard unwind tests ---

fn make_fabricated_drop_charge() -> BudgetChargeResult {
    BudgetChargeResult {
        grant_index: 0,
        cost_charged: 5,
        currency: "USD".to_string(),
        budget_total: 100,
        new_committed_cost_units: 5,
        budget_hold_id: "hold-drop-guard-tests".to_string(),
        authorize_metadata: BudgetCommitMetadata {
            authority: None,
            guarantee_level: crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: None,
            event_id: None,
        },
    }
}

/// Authorize a real, open budget hold that exactly matches the fabricated drop
/// charge (see `make_fabricated_drop_charge`). The drop-guard tests build a
/// fabricated `BudgetChargeResult`; without a matching open hold in the store,
/// the monetary reversal fails and records a fault receipt. Authorizing the hold
/// first models the real admission so the pre-dispatch monetary unwind is a
/// genuine, clean, receipt-free reversal.
fn authorize_fabricated_drop_hold(
    kernel: &ChioKernel,
    capability_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    kernel
        .with_budget_store(|store| {
            let decision =
                store.authorize_budget_hold(crate::budget_store::BudgetAuthorizeHoldRequest {
                    capability_id: capability_id.to_string(),
                    grant_index: 0,
                    max_invocations: None,
                    requested_exposure_units: 5,
                    max_cost_per_invocation: Some(100),
                    max_total_cost_units: Some(1_000),
                    hold_id: Some("hold-drop-guard-tests".to_string()),
                    event_id: Some("hold-drop-guard-tests:authorize".to_string()),
                    authority: None,
                    payment_journal: None,
                })?;
            assert!(
                matches!(
                    decision,
                    crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
                ),
                "fabricated drop hold must authorize"
            );
            Ok(())
        })
        .map_err(|error| -> Box<dyn std::error::Error> {
            format!("authorize fabricated drop hold: {error}").into()
        })?;
    Ok(())
}

#[test]
fn drop_pre_dispatch_releases_reservations_no_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-pre-dispatch-dropped",
            admission_id: "adm-pre-dispatch-dropped",
            lease_id: "lease-pre-dispatch-dropped",
            continuation_id: None,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-pre-dispatch-dropped",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-pre-dispatch-dropped",
            "failure_code": null
        }
    });

    // No mark_dispatch_started(): this models a future dropped (or a panic
    // unwinding) after admission but before the tool-server dispatch await
    // was entered. No side effect is possible, so the unwind is total.
    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "a pre-dispatch drop must safe-release runtime-admission reservations"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a pre-dispatch drop is the receipt-free fully-unwound exit"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_monetary_unwinds_without_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    // A MONETARY future dropped before dispatch takes the pre-dispatch branch: the
    // hold is reversed, reservations released, and no receipt is recorded.
    let mut kernel = make_kernel(make_config());
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone())).expect("install payment adapter");
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-monetary-pre-dispatch-drop",
            admission_id: "adm-monetary-pre-dispatch-drop",
            lease_id: "lease-monetary-pre-dispatch-drop",
            continuation_id: None,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-monetary-pre-dispatch-drop",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-monetary-pre-dispatch-drop",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-monetary-pre-dispatch-drop",
            "failure_code": null
        }
    });
    // Model the real admission behind the fabricated charge so the monetary
    // reversal is a genuine, clean unwind (an un-reversible fabricated hold would
    // otherwise record a fault receipt).
    authorize_fabricated_drop_hold(&kernel, &cap.id)?;
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());
    let authorization = PaymentAuthorization {
        authorization_id: "auth-monetary-pre-dispatch-drop".to_string(),
        settled: false,
        metadata: serde_json::json!({ "adapter": "tracking" }),
    };

    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        Some(&authorization),
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unsettled monetary authorization must be released on a pre-dispatch drop"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime reservations must be released on a pre-dispatch drop"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a monetary pre-dispatch drop is receipt-free: hold reversed, reservations released"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_reverses_invocation_budget() -> Result<(), Box<dyn std::error::Error>> {
    // A non-monetary grant with `max_invocations` increments an invocation counter
    // at admission. A future dropped BEFORE dispatch must reverse that increment so
    // a never-dispatched call does not permanently consume the slot.
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-invocation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    // Model admission consuming the single invocation slot for grant 0.
    let admitted =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(admitted, "admission must consume the single invocation slot");

    let mutation = PreExecutionBudgetMutation::Invocation { grant_index: 0 };
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    // The slot must be free again: a retry increment succeeds.
    let retry =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        retry,
        "a pre-dispatch drop must reverse the invocation increment so the slot is reusable"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a clean invocation reversal on a pre-dispatch drop is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_releases_admitted_child_budget() -> Result<(), Box<dyn std::error::Error>> {
    // A delegated capability admitted its share of the parent budget at admission.
    // A future dropped BEFORE dispatch must release that share or the child's claim
    // is permanently recorded.
    let SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        path: _path,
        ..
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-child-budget");

    // Admit child_a's share. In the fixture (parent share 5000 bps, each child
    // 4000 bps) child_a alone fits but child_a + child_b does not.
    kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;

    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-child-budget",
        &child_a,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &child_a,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        // Genuinely-new admission (child_a inserted above): the drop MUST
        // release it, so child_b can admit. Verifies no under-release leak.
        true,
    ));

    // child_a's share must have been released: child_b can now admit within
    // the parent budget.
    let readmit = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit.is_ok(),
        "a pre-dispatch drop must release child_a's admitted share so child_b admits: {readmit:?}"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a clean child-budget release on a pre-dispatch drop is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_overlapping_readmit_keeps_sibling_denied(
) -> Result<(), Box<dyn std::error::Error>> {
    // Refcount model: two OVERLAPPING evaluations hold the SAME delegated child
    // edge. An EARLIER evaluation admits child_a (lease 1). A SECOND overlapping
    // evaluation idempotently re-admits the same child_a (lease 2) and is then
    // DROPPED before dispatch. The drop releases only the SECOND evaluation's lease
    // (holders 2 -> 1); it must NOT free the edge the first evaluation still holds,
    // so an oversubscribing sibling child_b stays DENIED. A non-refcounted release
    // would free child_a's only edge and wrongly admit child_b.
    let SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        path: _path,
        ..
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-overlapping-readmit");

    // Earlier evaluation: fresh admission of child_a (4000 of 5000 bps).
    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission of child_a must acquire a lease");

    // Second overlapping evaluation: the idempotent re-admit takes a second
    // lease on the same edge (holders 2).
    let second = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(
        second,
        "an idempotent re-admit of child_a must also acquire a lease (holders 2)"
    );

    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-overlapping-readmit",
        &child_a,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let mutation = PreExecutionBudgetMutation::None;
    // The second evaluation's future is dropped before dispatch. It acquired a
    // lease, so the refcounted release drops ONE holder (holders 2 -> 1) and
    // leaves the edge intact.
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &child_a,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    // child_a's share is still held by the first evaluation (holders 1), so an
    // oversubscribing sibling child_b (4000 + 4000 > 5000 bps) stays DENIED.
    let sibling = kernel.admit_capability_budget(&child_b);
    assert!(
        sibling.is_err(),
        "the second evaluation's drop must release only its own lease, leaving \
         child_a's share held by the first evaluation, so child_b stays denied: {sibling:?}"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a pre-dispatch drop whose refcounted release does not free the edge is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_records_receipt_on_cleanup_fault() -> Result<(), Box<dyn std::error::Error>> {
    // When a pre-dispatch cleanup step FAILS, the drop must record a signed receipt
    // documenting the fault so a stuck hold/reservation lands on the append-only
    // log rather than being silently burned.
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-cleanup-fault",
        admission_id: "adm-pre-dispatch-cleanup-fault",
        lease_id: "lease-pre-dispatch-cleanup-fault",
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-cleanup-fault",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-pre-dispatch-cleanup-fault",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-pre-dispatch-cleanup-fault",
            "failure_code": null
        }
    });

    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "the failing runtime-admission release must be attempted"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a failed pre-dispatch cleanup must record exactly one signed fault receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("pre-dispatch cleanup fault receipt missing"))?;
    assert!(receipt.is_cancelled());
    let receipt_metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    assert_eq!(
        receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_failed"],
        true
    );
    // The reserved lease id must survive alongside the fault annotation so an
    // operator can locate the possibly-stuck reservation.
    assert_eq!(
        receipt_metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-pre-dispatch-cleanup-fault"
    );
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    assert!(
        faults
            .iter()
            .any(|fault| fault["step"] == "runtime_admission_release"),
        "the fault list must name the failing runtime-admission release step: {faults:?}"
    );
    Ok(())
}

struct ParkingServer {
    id: String,
    tools: Vec<String>,
    started: std::sync::Arc<tokio::sync::Notify>,
    invocations: std::sync::Arc<AtomicU64>,
}

impl ParkingServer {
    fn new(
        id: &str,
        tools: Vec<&str>,
        started: std::sync::Arc<tokio::sync::Notify>,
        invocations: std::sync::Arc<AtomicU64>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            started,
            invocations,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ParkingServer {
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
        // notify_one() stores a permit if the waiter has not yet called
        // .notified().await, avoiding the lost-wakeup race that
        // notify_waiters() has when the waiter has not yet polled.
        self.started.notify_one();
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_non_monetary_post_dispatch_records_cancellation_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&started),
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-non-monetary-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .map_err(|_| std::io::Error::other("parking tool server was never invoked"))?;
    eval.abort();
    assert!(eval.await.is_err(), "aborted evaluation must not complete");

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "dropped non-monetary post-admission future must record exactly one receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    assert!(
        receipt.verify_signature()?,
        "drop receipt signature must verify"
    );
    Ok(())
}

#[test]
fn nested_flow_drop_post_dispatch_records_cancellation_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&started),
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-dropped",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced =
            tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "nested dispatch must have been entered before the drop"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "nested-flow drop must record exactly one receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("nested drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the nested drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    Ok(())
}

// A registered tool server whose dispatch first performs a nested CHILD
// operation through the bridge (which buffers a signed child receipt into the
// parent evaluation's `child_receipts` sink) and then either parks forever or
// returns normally. Exercises receipt completeness for buffered child receipts
// across a post-dispatch parent drop, and the no-double-record property on the
// normal exit.
struct NestedChildOpServer {
    id: String,
    tools: Vec<String>,
    child_ops: std::sync::Arc<AtomicU64>,
    park: bool,
}

impl NestedChildOpServer {
    fn new(
        id: &str,
        tools: Vec<&str>,
        child_ops: std::sync::Arc<AtomicU64>,
        park: bool,
    ) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            child_ops,
            park,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedChildOpServer {
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
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        // Perform a nested child operation so a signed child receipt is
        // buffered. The child op's own result is irrelevant: completing it
        // (success or failure) is what records the signed receipt.
        if let Some(bridge) = nested_flow_bridge {
            let _ = bridge.list_roots();
            self.child_ops.fetch_add(1, Ordering::SeqCst);
        }
        if self.park {
            std::future::pending::<Result<serde_json::Value, KernelError>>().await
        } else {
            Ok(serde_json::json!({"status": "ok"}))
        }
    }
}

// Normal nested-flow exit: the buffered child receipt must be recorded exactly
// once (no double-record between the normal `record_buffered_child_receipts`
// flush and the disarmed drop guard) and the parent receipt must be a
// non-cancellation.
#[test]
fn nested_flow_normal_path_records_child_receipt_exactly_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-normal",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-normal",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run once"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the normal nested-flow exit records exactly one parent receipt"
    );
    assert!(
        !receipt_log
            .get(0)
            .ok_or_else(|| std::io::Error::other("parent receipt missing"))?
            .is_cancelled(),
        "the normal-path parent receipt must not be a cancellation"
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered child receipt must be recorded exactly once on the normal path"
    );
    Ok(())
}

/// A durable store whose bounded child-receipt append always times out, to
/// drive the child-receipt persistence timeout that follows nested dispatch.
/// Parent (chio) receipt appends succeed so the fail-closed cancellation
/// receipt can still be persisted.
struct ChildAppendTimeoutStore;

impl ReceiptStore for ChildAppendTimeoutStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt_with_timeout(
        &self,
        _receipt: &ChildRequestReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        Err(ReceiptStoreError::Timeout {
            operation: "append_child_receipt".to_string(),
            timeout_ms: 0,
        })
    }
}

// A saturated commit writer that times out the buffered child-receipt append
// after nested dispatch must not strand the admission. The evaluation must run
// the abort cleanup and record a signed cancellation receipt, rather than
// returning the timeout with the admission holds still held and no terminal
// receipt on the log.
#[test]
fn nested_flow_child_receipt_timeout_records_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendTimeoutStore))?;
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-timeout",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-timeout",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert!(
        child_ops.load(Ordering::SeqCst) >= 1,
        "the nested child op must have run before the child-receipt append"
    );
    assert!(
        result.is_err(),
        "a child-receipt append timeout must surface as an error"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the abort cleanup records exactly one terminal receipt on the timeout"
    );
    assert!(
        receipt_log
            .get(0)
            .ok_or_else(|| std::io::Error::other("terminal receipt missing"))?
            .is_cancelled(),
        "the terminal receipt must be a signed cancellation"
    );
    Ok(())
}

/// A durable store whose bounded child-receipt append fails closed on its first
/// call and succeeds afterward, modeling a commit writer that is momentarily
/// saturated during the normal record path but has drained before the drop-path
/// flush retries. Parent (chio) receipt appends always succeed.
struct ChildAppendFailsOnceStore {
    child_appends: std::sync::Arc<AtomicU64>,
}

impl ReceiptStore for ChildAppendFailsOnceStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt_with_timeout(
        &self,
        _receipt: &ChildRequestReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if self.child_appends.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ReceiptStoreError::Timeout {
                operation: "append_child_receipt".to_string(),
                timeout_ms: 0,
            });
        }
        Ok(Some(1))
    }
}

// A commit writer that times out the buffered child-receipt append on the
// normal record path, then drains, must not lose the already-signed child
// receipt. The still-armed drop path retries the flush, so the completed child
// operation lands on the append-only log. Draining the guard buffer before the
// append succeeded would leave the drop-path retry with nothing to flush and
// strand the child receipt.
#[test]
fn nested_flow_transient_child_append_timeout_preserves_child_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let child_appends = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendFailsOnceStore {
        child_appends: std::sync::Arc::clone(&child_appends),
    }))?;
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        false,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-retry",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-retry",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run once before the child-receipt append"
    );
    assert!(
        result.is_err(),
        "the first child-receipt append timeout must surface as an error"
    );
    assert_eq!(
        child_appends.load(Ordering::SeqCst),
        2,
        "the normal path times out once and the drop path retries the append"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the abort cleanup records exactly one signed cancellation receipt"
    );
    assert!(
        receipt_log
            .get(0)
            .ok_or_else(|| std::io::Error::other("terminal receipt missing"))?
            .is_cancelled(),
        "the terminal receipt must be a signed cancellation"
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered child receipt must be preserved and flushed on the drop-path retry, not lost"
    );
    Ok(())
}

// A tool server whose dispatch performs TWO nested child operations (buffering
// two already-signed child receipts) and then parks forever. Dropping the
// parked parent future exercises the drop-path flush with more than one
// buffered receipt, so a failure on the first append must not discard the
// second.
struct TwoChildOpParkingServer {
    id: String,
    tools: Vec<String>,
    child_ops: std::sync::Arc<AtomicU64>,
}

impl TwoChildOpParkingServer {
    fn new(id: &str, tools: Vec<&str>, child_ops: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            child_ops,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for TwoChildOpParkingServer {
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
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        // Two nested child ops buffer two distinct signed child receipts (each
        // list_roots mints a fresh nonce-suffixed child request id).
        if let Some(bridge) = nested_flow_bridge {
            let _ = bridge.list_roots();
            let _ = bridge.list_roots();
            self.child_ops.fetch_add(2, Ordering::SeqCst);
        }
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }
}

// Post-dispatch parent drop with more than one buffered child receipt where the
// first bounded append fails closed. The drop path records each receipt
// independently, so the second already-signed receipt must still land on the
// append-only log rather than being discarded with the failed first append. A
// stop-at-first-failure batch record would lose it.
#[test]
fn nested_flow_drop_path_preserves_child_receipts_after_a_first_append_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let child_appends = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ChildAppendFailsOnceStore {
        child_appends: std::sync::Arc::clone(&child_appends),
    }))?;
    kernel.register_tool_server(Box::new(TwoChildOpParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-drop-multi",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-drop-multi",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        2,
        "both nested child ops must have run before the drop"
    );
    // The first buffered receipt's bounded append fails closed; the second must
    // still be attempted. A batch record that stopped at the first failure
    // would leave this at 1.
    assert_eq!(
        child_appends.load(Ordering::SeqCst),
        2,
        "the drop path must attempt every buffered child receipt, not stop at the first failure"
    );
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the child receipt queued behind the failed append must be preserved on the drop-path flush"
    );
    Ok(())
}

// Post-dispatch parent drop: the already-signed buffered child receipt must be
// flushed onto the append-only log alongside the parent cancellation receipt.
// Without the drop-path flush the child receipt is discarded with the dropped
// future, violating receipt-completeness for nested child operations.
#[test]
fn nested_flow_drop_post_dispatch_flushes_buffered_child_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let child_ops = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedChildOpServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&child_ops),
        true,
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-nested-child-dropped",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-chio-nested-child-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
        assert!(
            raced.is_err(),
            "parked nested dispatch must be dropped by the timeout"
        );
    });

    assert_eq!(
        child_ops.load(Ordering::SeqCst),
        1,
        "the nested child op must have run before the drop"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "the parent cancellation receipt must be recorded on drop"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("parent cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    let Some(Decision::Cancelled { reason }) = &receipt.decision else {
        return Err("expected a cancelled decision on the nested drop receipt".into());
    };
    assert_eq!(reason, "tool evaluation future dropped after admission");
    let child_receipt_log = kernel.child_receipt_log();
    assert_eq!(
        child_receipt_log.len(),
        1,
        "the buffered signed child receipt must be flushed on post-dispatch drop, not discarded"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_post_dispatch_retains_and_marks_reservations(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ParkingServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&started),
        std::sync::Arc::clone(&invocations),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-drop-retained",
            admission_id: "adm-drop-retained",
            lease_id: "lease-drop-retained",
            continuation_id: Some("continuation-drop-retained"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-drop-retained",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .map_err(|_| std::io::Error::other("parking tool server was never invoked"))?;
    eval.abort();
    assert!(eval.await.is_err(), "aborted evaluation must not complete");

    // Retention: the mock hook's release_reserved was never called, so the
    // consumed lease stays consumed (a retry would be rejected with
    // destructive_lease_replay by the real store, per
    // chio-runtime-core/src/store/memory.rs:136-151).
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-dispatch drop must retain runtime-admission reservations"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("drop receipt missing"))?;
    assert!(receipt.is_cancelled());
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("drop receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-drop-retained"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-drop-retained"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-drop-retained"
    );
    assert!(
        metadata["chio_runtime"]
            .get("retained_swarm_continuation_id")
            .is_none(),
        "no swarm continuation was reserved by this fixture, so the retained \
         marker for it must be absent"
    );
    Ok(())
}

#[test]
fn request_cancelled_marks_reservations_retained(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-cancel-marked",
            admission_id: "adm-cancel-marked",
            lease_id: "lease-cancel-marked",
            continuation_id: Some("continuation-cancel-marked"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-cancel-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "ambiguous cancellation must retain reservations"
    );
    assert!(response.receipt.is_cancelled());
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("cancel receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-cancel-marked"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-cancel-marked"
    );
    Ok(())
}

#[test]
fn request_incomplete_marks_reservations_retained(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-incomplete-marked",
            admission_id: "adm-incomplete-marked",
            lease_id: "lease-incomplete-marked",
            continuation_id: Some("continuation-incomplete-marked"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "ambiguous incompletion must retain reservations"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-incomplete-marked"
    );
    Ok(())
}

#[test]
fn incomplete_stream_output_marks_reservations_retained(
) -> Result<(), Box<dyn std::error::Error>> {
    // Dispatch succeeds but returns Ok(ToolServerStreamResult::Incomplete)
    // (e.g. stream-limit truncation). This is finalized via
    // finalize_budgeted_tool_output_with_cost_and_metadata / the shared
    // finalize path, NOT the RequestIncomplete error arm. The
    // runtime-admission lease is still consumed after the side effect, so
    // the incomplete receipt must carry the retained marker so the burned
    // lease is auditable and recoverable from the signed receipt alone.
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-incomplete-stream-marked",
            admission_id: "adm-incomplete-stream-marked",
            lease_id: "lease-incomplete-stream-marked",
            continuation_id: Some("continuation-incomplete-stream-marked"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-incomplete-stream-marked",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "an incomplete stream after a side effect must retain reservations"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("incomplete-stream receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-incomplete-stream-marked"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-incomplete-stream-marked"
    );
    Ok(())
}

#[test]
fn post_invocation_block_marks_reservations_retained(
) -> Result<(), Box<dyn std::error::Error>> {
    // A runtime-admitted call dispatches successfully (a destructive side
    // effect commits) and returns a value, but a POST-invocation output guard
    // blocks the returned value AFTER dispatch. Because the tool already ran,
    // the runtime-admission lease is retained (not released), so the deny
    // receipt must carry the retained marker + reserved ids to keep the burned
    // lease auditable and recoverable from the signed receipt alone, matching
    // the incomplete-stream and RequestIncomplete arms.
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SucceedingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    kernel.add_post_invocation_hook(Box::new(BlockingPostInvocationHook));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-post-invocation-block",
            admission_id: "adm-post-invocation-block",
            lease_id: "lease-post-invocation-block",
            continuation_id: Some("continuation-post-invocation-block"),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-post-invocation-block",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        side_effects.load(Ordering::SeqCst),
        1,
        "tool must have dispatched (side effect committed) before the post-invocation block"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a post-invocation block after a side effect must retain reservations"
    );
    let metadata = response.receipt.metadata.ok_or_else(|| {
        std::io::Error::other("post-invocation block receipt metadata missing")
    })?;
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_destructive_lease_id"],
        "lease-post-invocation-block"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_treaty_continuation_id"],
        "continuation-post-invocation-block"
    );
    Ok(())
}

#[test]
fn generic_error_pre_side_effect_releases_without_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    // A registered tool server whose dispatch call fails with
    // ToolNotRegistered (e.g. the tool was withdrawn from its roster
    // between admission and dispatch). The server_id itself IS registered,
    // so the pre-dispatch `ensure_registered_tool_target` check passes and
    // the runtime admission hook fires and reserves normally; the failure
    // surfaces only from the dispatch call itself, landing in the
    // generic-error arm. ToolNotRegistered precedes any side effect, so
    // reservations are RELEASED and the deny receipt must NOT carry the
    // retained marker.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "req-chio-runtime-tool-not-registered",
            admission_id: "adm-tool-not-registered",
            lease_id: "lease-tool-not-registered",
            continuation_id: None,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chio-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-tool-not-registered",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("destructive_update")));
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "ToolNotRegistered precedes any side effect, so reservations are released"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny receipt metadata missing"))?;
    let runtime = metadata["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block missing"))?;
    assert!(
        !runtime.contains_key("reservations_retained_fail_closed"),
        "a released reservation must not be marked as retained"
    );
    assert!(!runtime.contains_key("retained_destructive_lease_id"));
    Ok(())
}

#[test]
fn dispatch_not_registered_releases_full_budget_state() -> Result<(), Box<dyn std::error::Error>> {
    // When a registered server's dispatch fails with ToolNotRegistered (no tool
    // side effect), the async generic-error arm must reverse ALL pre-dispatch
    // budget state, not just runtime-admission reservations. A max_invocations
    // grant consumes an invocation slot at admission via check_and_increment_budget,
    // and unwind_aborted_monetary_invocation is a no-op for a non-monetary
    // Invocation mutation, so the slot must be released here or a valid retry under
    // the same grant would be wrongly denied for budget exhaustion even though
    // nothing ever dispatched.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-dispatch-not-registered-full-budget-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);

    // The single invocation slot consumed at admission must be free again: the
    // dispatch produced no side effect, so the pre-execution increment is
    // reversed and a retry re-admits.
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "a pre-side-effect dispatch error must reverse the invocation increment so a retry re-admits"
    );
    Ok(())
}

#[test]
fn dispatch_not_registered_releases_full_budget_state_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Mirror of dispatch_not_registered_releases_full_budget_state for the
    // nested-flow evaluation arm. Its generic-error arm must route a
    // pre-side-effect dispatch error through the full pre-dispatch cleanup,
    // releasing the pre-execution budget mutation (and the sibling-sum capability
    // admission), not just the runtime-admission reservations.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-dispatch-not-registered-full-budget-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-dispatch-not-registered-full-budget-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;
    assert_eq!(response.verdict, Verdict::Deny);

    // The nested-flow arm must also reverse the invocation increment on a
    // pre-side-effect dispatch error so the slot is reusable.
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "the nested-flow pre-side-effect dispatch error must reverse the invocation increment so a retry re-admits"
    );
    Ok(())
}

#[test]
fn url_elicitation_required_releases_full_budget_state() -> Result<(), Box<dyn std::error::Error>> {
    // UrlElicitationsRequired is classified by
    // dispatch_error_precedes_tool_side_effect() as a no-side-effect dispatch
    // error, exactly like ToolNotRegistered. The tool never runs; the client
    // completes the URL elicitations and re-sends a FRESH tool call that
    // re-admits from scratch, so ALL pre-dispatch budget state must be reversed.
    // A max_invocations grant consumes an invocation slot at admission, and
    // unwind_aborted_monetary_invocation is a no-op for a non-monetary
    // Invocation mutation, so the slot must be released here or the authorize
    // -> retry could never re-admit under the same grant. The async arm returns
    // Err(UrlElicitationsRequired) (so the elicitations payload propagates to
    // the edge), not a Deny response, so the slot reusability is asserted
    // directly against the budget store.
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-full-budget-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "URL elicitation must surface as an error to the caller"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );

    // The single invocation slot consumed at admission must be free again: no
    // side effect occurred, so the pre-execution increment is reversed and a
    // retry (after the client completes the elicitations) re-admits.
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "UrlElicitationsRequired precedes any side effect, so the invocation increment must be reversed for the retry to re-admit"
    );
    Ok(())
}

#[test]
fn url_elicitation_required_releases_full_budget_state_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Mirror of url_elicitation_required_releases_full_budget_state for the
    // nested-flow evaluation arm, which carried the same leak: it released only
    // the runtime-admission reservations on a UrlElicitationsRequired dispatch
    // error, leaking the pre-execution budget mutation (and the sibling-sum
    // capability admission).
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-full-budget-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-full-budget-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested-flow URL elicitation must surface as an error to the caller"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );

    // The nested-flow arm must also reverse the invocation increment on a
    // UrlElicitationsRequired dispatch error so the slot is reusable.
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "the nested-flow UrlElicitationsRequired must reverse the invocation increment so a retry re-admits"
    );
    Ok(())
}

/// Sibling-sum delegation fixture whose child capabilities target a tool server
/// that returns `UrlElicitationsRequired` before any side effect. Parent share
/// is 5000 bps and each child claims 4000 bps, so child_a alone fits but
/// child_a + child_b oversubscribes the parent. Mirrors
/// `make_sibling_sum_invocation_fixture` but swaps the tool server so the
/// evaluation reaches dispatch and surfaces the URL-elicitation error.
fn make_sibling_sum_url_fixture(prefix: &str) -> SiblingSumInvocationFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "url-srv",
        vec!["compute"],
        stream_attempts,
    )));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_grant("url-srv", "compute");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_grant("url-srv", "compute")]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel.set_capability_trust_root(
        kernel.config.keypair.public_key(),
        scope_hash(&parent_scope).unwrap(),
    );

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel,
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel,
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

#[test]
fn url_elicitation_idempotent_readmit_preserves_sibling_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    // Refcount: admit_capability_budget takes a holder lease per evaluation. An
    // earlier evaluation holds child_a's edge (lease 1). A second overlapping
    // evaluation that hits UrlElicitationsRequired takes a second lease and releases
    // only that one on cleanup (holders 2 -> 1); it must NOT free child_a's edge
    // while the earlier holder remains, or the oversubscribing sibling child_b would
    // admit while child_a is still valid.
    let SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp: _child_a_kp,
        path: _path,
        ..
    } = make_sibling_sum_url_fixture("chio-runtime-url-idempotent-readmit");

    // Earlier evaluation holds child_a's edge (lease 1) for the duration.
    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission must acquire child_a's lease");

    // Second overlapping evaluation on the SAME child_a hits
    // UrlElicitationsRequired; its internal admit takes (and its cleanup drops)
    // a second lease, leaving the earlier holder's share intact.
    let request = make_request_with_arguments(
        "req-url-idempotent-readmit-async",
        &child_a,
        "compute",
        "url-srv",
        serde_json::json!({}),
    );
    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the delegated child must reach dispatch and surface UrlElicitationsRequired: {result:?}"
    );

    // child_a's edge is still held by the earlier evaluation, so the
    // oversubscribing sibling child_b (4000 + 4000 > 5000 parent share) must
    // still be DENIED.
    let readmit_b = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit_b.is_err(),
        "the second evaluation's cleanup must drop only its own lease, leaving child_a held so child_b stays oversubscribed: {readmit_b:?}"
    );
    Ok(())
}

#[test]
fn url_elicitation_idempotent_readmit_preserves_sibling_budget_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the async idempotent-readmit test: the nested arm's
    // UrlElicitationsRequired cleanup must also drop only its own holder lease,
    // leaving the earlier holder's sibling reservation intact.
    let SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        path: _path,
        ..
    } = make_sibling_sum_url_fixture("chio-runtime-url-idempotent-readmit-nested");

    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission must acquire child_a's lease");

    let session_id = kernel.open_session(child_a_kp.public_key().to_hex(), vec![child_a.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-idempotent-readmit-nested",
        &child_a_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-idempotent-readmit-nested",
        &child_a,
        "compute",
        "url-srv",
        serde_json::json!({}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested delegated child must surface UrlElicitationsRequired: {result:?}"
    );

    let readmit_b = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit_b.is_err(),
        "the nested second evaluation's cleanup must drop only its own lease, leaving child_a held: {readmit_b:?}"
    );
    Ok(())
}

#[test]
fn url_elicitation_release_failure_continues_full_budget_cleanup(
) -> Result<(), Box<dyn std::error::Error>> {
    // A runtime-reservation release failure during the UrlElicitationsRequired
    // cleanup must be RECORDED and the remaining cleanup (the invocation-slot
    // reversal) must still run. The response must stay Err(UrlElicitationsRequired)
    // (not an internal cleanup error) so the elicitations payload still reaches the
    // edge.
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-release-failure-async",
        admission_id: "adm-url-elicitation-release-failure",
        lease_id: "lease-url-elicitation-release-failure",
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-release-failure-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "a runtime-release failure must not replace the elicitation with an internal cleanup error: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "the failing runtime-admission release must be attempted"
    );
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "cleanup must CONTINUE past the runtime-release failure and reverse the invocation slot"
    );
    // The arm returns Err(UrlElicitationsRequired) and records no terminal receipt,
    // so a failed runtime-admission release would otherwise leave the stuck lease
    // with NO append-only entry. A signed fault receipt naming the stuck lease must
    // be recorded.
    assert_url_elicitation_release_fault_recorded(
        &kernel,
        "lease-url-elicitation-release-failure",
    )?;
    Ok(())
}

#[test]
fn url_elicitation_release_failure_continues_full_budget_cleanup_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the async continue-on-release-failure test.
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-url-elicitation-release-failure-nested",
        admission_id: "adm-url-elicitation-release-failure-nested",
        lease_id: "lease-url-elicitation-release-failure-nested",
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-release-failure-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-release-failure-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested runtime-release failure must not mask the elicitation error: {result:?}"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "the failing runtime-admission release must be attempted"
    );
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        slot_reusable,
        "the nested cleanup must CONTINUE past the release failure and reverse the invocation slot"
    );
    // Nested mirror: the stuck lease must land a signed fault receipt on the
    // append-only log even though the arm returns Err(UrlElicitationsRequired).
    assert_url_elicitation_release_fault_recorded(
        &kernel,
        "lease-url-elicitation-release-failure-nested",
    )?;
    Ok(())
}

/// Assert that a failed runtime-admission release during a URL-elicitation
/// pre-dispatch unwind recorded a signed cancellation fault receipt naming the
/// stuck `lease_id`. Shared by the async and nested-flow release-failure tests.
fn assert_url_elicitation_release_fault_recorded(
    kernel: &ChioKernel,
    lease_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt_log = kernel.receipt_log();
    let receipts = receipt_log.receipts();
    let fault_receipt = receipts
        .iter()
        .find(|receipt| {
            receipt.is_cancelled()
                && receipt.metadata.as_ref().is_some_and(|metadata| {
                    metadata["chio_runtime"]["reservation_release_failed"] == true
                })
        })
        .ok_or_else(|| {
            std::io::Error::other(
                "a failed URL-elicitation runtime-admission release must record a signed fault receipt",
            )
        })?;
    let receipt_metadata = fault_receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    // The stuck lease id must survive so an operator can locate the reservation.
    assert_eq!(
        receipt_metadata["chio_runtime"]["reserved_destructive_lease_id"],
        lease_id
    );
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    assert!(
        faults.iter().any(|fault| {
            fault["step"] == "url_elicitation_runtime_admission_release"
                && fault["hold_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == lease_id))
        }),
        "the fault must name the URL-elicitation release step and the stuck lease id: {faults:?}"
    );
    Ok(())
}

/// A [`BudgetStore`] wrapper that fails the pre-execution BUDGET reversal
/// (`reverse_charge_cost`) so a URL-elicitation cleanup exercises the
/// record-and-continue budget path. All other operations delegate to a real
/// in-memory store so admission still increments the invocation slot.
struct FailingReverseBudgetStore {
    inner: InMemoryBudgetStore,
}

impl FailingReverseBudgetStore {
    fn new() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
        }
    }
}

impl BudgetStore for FailingReverseBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        // Injected transient budget-store fault on the reversal path.
        Err(BudgetStoreError::Invariant(
            "injected reverse_charge_cost failure".to_string(),
        ))
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }
}

/// Assert that a failed BUDGET reversal during a URL-elicitation pre-dispatch
/// unwind recorded a signed cancellation fault receipt naming the `step` and
/// the stuck `hold_id`. Shared by the async and nested-flow tests.
fn assert_url_elicitation_budget_cleanup_fault_recorded(
    kernel: &ChioKernel,
    step: &str,
    hold_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt_log = kernel.receipt_log();
    let found = receipt_log.receipts().iter().any(|receipt| {
        receipt.is_cancelled()
            && receipt.metadata.as_ref().is_some_and(|metadata| {
                metadata["chio_runtime"]["pre_dispatch_cleanup_failed"] == true
                    && metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
                        .as_array()
                        .is_some_and(|faults| {
                            faults.iter().any(|fault| {
                                fault["step"] == step
                                    && fault["hold_ids"].as_array().is_some_and(|ids| {
                                        ids.iter().any(|id| id == hold_id)
                                    })
                            })
                        })
            })
    });
    assert!(
        found,
        "a failed URL-elicitation budget reversal must record a signed fault receipt naming step `{step}` and the stuck hold `{hold_id}`"
    );
    Ok(())
}

#[test]
fn url_elicitation_budget_reversal_failure_preserves_elicitation_async(
) -> Result<(), Box<dyn std::error::Error>> {
    // A transient BUDGET-store failure while reversing the pre-execution invocation
    // slot during a UrlElicitationsRequired cleanup must be RECORDED and the arm
    // must still return Err(UrlElicitationsRequired) (not the internal budget error)
    // so the elicitations payload still reaches the edge. A bare `?` on
    // reverse_pre_execution_budget_mutation would instead replace the elicitation
    // error with the budget error.
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel.set_budget_store_handle(std::sync::Arc::new(FailingReverseBudgetStore::new()));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-budget-reversal-failure-async",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "a budget-reversal failure must not replace the elicitation with an internal cleanup error: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "url_elicitation_budget_reversal",
        &cap.id,
    )?;
    Ok(())
}

#[test]
fn url_elicitation_budget_reversal_failure_preserves_elicitation_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the async budget-reversal-failure test (both arms).
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel.set_budget_store_handle(std::sync::Arc::new(FailingReverseBudgetStore::new()));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-budget-reversal-failure-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-budget-reversal-failure-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested budget-reversal failure must not mask the elicitation error: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the error came from dispatch, not admission"
    );
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "url_elicitation_budget_reversal",
        &cap.id,
    )?;
    Ok(())
}

#[test]
fn drop_pre_dispatch_cleanup_fault_receipt_includes_monetary_hold_id(
) -> Result<(), Box<dyn std::error::Error>> {
    // When a pre-dispatch drop hits a monetary cleanup failure, the fault entry
    // must name the budget hold id it was unwinding so an operator can locate the
    // possibly-stuck hold from the fault receipt alone. The fabricated charge has no
    // matching open hold in the store, so the monetary reversal fails and records a
    // fault.
    let kernel = make_kernel(make_config());

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-monetary-cleanup-fault-hold-id",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    // Charge WITHOUT authorizing the matching hold: the monetary reversal fails
    // and records a monetary_unwind fault (no mark_dispatch_started, so this is
    // the pre-dispatch drop branch).
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        true,
    ));

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a failed monetary pre-dispatch cleanup must record exactly one fault receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("monetary cleanup fault receipt missing"))?;
    let receipt_metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    let monetary_fault = faults
        .iter()
        .find(|fault| fault["step"] == "monetary_unwind")
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault entry missing"))?;
    let hold_ids = monetary_fault["hold_ids"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault must carry hold_ids"))?;
    assert!(
        hold_ids
            .iter()
            .any(|id| id == "hold-drop-guard-tests"),
        "the monetary_unwind fault must name the budget hold id: {hold_ids:?}"
    );
    Ok(())
}

#[test]
fn retained_marker_requires_a_real_reservation() -> Result<(), Box<dyn std::error::Error>> {
    // A `chio_runtime` block that merely carries a route / observe-only key with NO
    // reserved lease id must NOT be marked `reservations_retained_fail_closed`.
    // There is nothing to burn, so the marker would send an operator hunting for a
    // lease that never existed.
    let kernel = make_kernel(make_config());

    // (a) chio_runtime present, but no reserved_* id: NOT marked retained; the
    // metadata is returned unchanged.
    let route_only = serde_json::json!({
        "chio_runtime": { "admission_id": "adm-observe-only", "accepted": true }
    });
    let marked = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(route_only))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    let runtime = marked["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block must be preserved"))?;
    assert!(
        !runtime.contains_key("reservations_retained_fail_closed"),
        "metadata with no real reservation must not be marked retained: {runtime:?}"
    );
    assert!(!runtime.contains_key("retained_destructive_lease_id"));

    // (b) an empty reserved id is not a real reservation either.
    let empty_id = serde_json::json!({
        "chio_runtime": { "reserved_destructive_lease_id": "" }
    });
    let marked_empty = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(empty_id))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    assert!(
        !marked_empty["chio_runtime"]
            .as_object()
            .is_some_and(|runtime| runtime.contains_key("reservations_retained_fail_closed")),
        "an empty reserved id is not a real reservation"
    );

    // (c) a real, non-empty reserved lease id IS marked retained and copied so
    // an operator can burn/recover the stuck lease from the signed receipt.
    let real = serde_json::json!({
        "chio_runtime": { "reserved_destructive_lease_id": "lease-real-42" }
    });
    let marked_real = kernel
        .mark_runtime_admission_reservations_retained_fail_closed(Some(real))
        .ok_or_else(|| std::io::Error::other("metadata must be returned"))?;
    let runtime_real = marked_real["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block must be preserved"))?;
    assert_eq!(
        runtime_real["reservations_retained_fail_closed"],
        serde_json::Value::Bool(true),
        "a real reserved lease must be marked retained"
    );
    assert_eq!(
        runtime_real["retained_destructive_lease_id"], "lease-real-42",
        "the stuck lease id must be copied for operator recovery"
    );
    Ok(())
}

/// A [`PaymentAdapter`] that authorizes cleanly but FAILS on release, so a
/// monetary UrlElicitationsRequired cleanup exercises the payment-release
/// failure arm of `unwind_aborted_monetary_invocation`. The authorization id is
/// deterministic so a test can assert it lands in the recorded fault's `hold_ids`.
struct FailingReleasePaymentAdapter;

impl PaymentAdapter for FailingReleasePaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_failing_release".to_string(),
            settled: false,
            metadata: serde_json::json!({ "adapter": "failing-release" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("capture should not run".to_string()))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "injected payment release failure".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("refund should not run".to_string()))
    }
}

#[test]
fn url_elicitation_monetary_reversal_failure_records_monetary_hold_ids_async(
) -> Result<(), Box<dyn std::error::Error>> {
    // When a MONETARY request hits UrlElicitationsRequired and the payment release
    // fails during cleanup, the append-only fault must name the stuck MONETARY hold
    // (the payment authorization id), not just the capability id, so an operator can
    // locate the hold to recover from the signed fault alone.
    let mut kernel = make_kernel(make_monetary_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel.set_payment_adapter(Box::new(FailingReleasePaymentAdapter)).expect("install payment adapter");

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-url-elicitation-monetary-reversal-failure-async",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "a monetary reversal failure must not replace the elicitation: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the reversal ran on the monetary arm"
    );
    // The stuck payment authorization id must land in the fault hold_ids.
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "url_elicitation_budget_reversal",
        "auth_failing_release",
    )?;
    Ok(())
}

#[test]
fn url_elicitation_monetary_reversal_failure_records_monetary_hold_ids_nested_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the async monetary-reversal-failure test: the
    // nested arm must ALSO name the stuck payment authorization id in the fault.
    let mut kernel = make_kernel(make_monetary_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel.set_payment_adapter(Box::new(FailingReleasePaymentAdapter)).expect("install payment adapter");

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-url-elicitation-monetary-reversal-failure-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-url-elicitation-monetary-reversal-failure-nested",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the nested monetary reversal failure must not mask the elicitation: {result:?}"
    );
    assert_eq!(
        stream_attempts.load(Ordering::SeqCst),
        1,
        "dispatch must have been attempted so the reversal ran on the monetary arm"
    );
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "url_elicitation_budget_reversal",
        "auth_failing_release",
    )?;
    Ok(())
}
