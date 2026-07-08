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
// true` branch: after Task 3's pre-dispatch hoist, an actually-unregistered
// server_id is denied before the admission hook ever runs, so it can never
// reach that arm.
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

    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        None,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
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

// --- RFC-0002 drop-guard unwind tests ---

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
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        None,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
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
    // Flag-drop delta shipped unconditionally (program decision 2026-07-07):
    // a MONETARY future dropped before dispatch used to record a
    // drop-cancellation receipt; it now takes the pre-dispatch branch
    // instead - hold reversed, reservations released, no receipt.
    let mut kernel = make_kernel(make_config());
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
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
    let charge = make_fabricated_drop_charge();
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
        Some(&charge),
        Some(&authorization),
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
        },
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
