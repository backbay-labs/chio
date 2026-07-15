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

struct InvalidReceiptMetadataRuntimeAdmissionHook {
    releases: std::sync::Arc<AtomicU64>,
}

struct MetadataInspectingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct LiveReceiptAllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct ControllableReadinessAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    readiness_polls: std::sync::Arc<AtomicU64>,
    readiness_started: std::sync::Arc<tokio::sync::Notify>,
    ready: AtomicBool,
    readiness_registrations: Mutex<
        std::collections::HashMap<
            RuntimeAdmissionReadinessToken,
            (std::task::Waker, std::sync::Arc<()>),
        >,
    >,
    readiness_unregistrations: AtomicU64,
}

impl ControllableReadinessAdmissionHook {
    fn new() -> Self {
        Self {
            calls: std::sync::Arc::new(AtomicU64::new(0)),
            releases: std::sync::Arc::new(AtomicU64::new(0)),
            readiness_polls: std::sync::Arc::new(AtomicU64::new(0)),
            readiness_started: std::sync::Arc::new(tokio::sync::Notify::new()),
            ready: AtomicBool::new(false),
            readiness_registrations: Mutex::new(std::collections::HashMap::new()),
            readiness_unregistrations: AtomicU64::new(0),
        }
    }

    fn allow_dispatch(&self) {
        self.ready.store(true, Ordering::SeqCst);
        let registrations = match self.readiness_registrations.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for (waker, _probe) in registrations.into_values() {
            waker.wake();
        }
    }

    fn readiness_registration_probes(&self) -> Vec<std::sync::Weak<()>> {
        match self.readiness_registrations.lock() {
            Ok(guard) => guard
                .values()
                .map(|(_waker, probe)| std::sync::Arc::downgrade(probe))
                .collect(),
            Err(poisoned) => poisoned
                .into_inner()
                .values()
                .map(|(_waker, probe)| std::sync::Arc::downgrade(probe))
                .collect(),
        }
    }
}

#[derive(Default)]
struct CountingRevocationAdmissionTraceObserver {
    admissions: AtomicU64,
}

impl RuntimeTraceObserver for CountingRevocationAdmissionTraceObserver {
    fn observe(&self, event: RuntimeTraceEvent) {
        if matches!(event, RuntimeTraceEvent::RevocationAdmission { .. }) {
            self.admissions.fetch_add(1, Ordering::SeqCst);
        }
    }
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

struct DenyingRetainedReservationAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    retained: std::sync::Arc<AtomicBool>,
    expected_request_id: &'static str,
}

struct FailingAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
}

struct UrlElicitationAfterDispatchServer {
    id: String,
    tools: Vec<String>,
    dispatch_effects: std::sync::Arc<AtomicU64>,
}

struct UrlElicitationAfterStreamFallbackServer {
    id: String,
    tools: Vec<String>,
    invoke_effects: std::sync::Arc<AtomicU64>,
    invoke_with_cost_effects: std::sync::Arc<AtomicU64>,
}

struct MetadataIsolationReadinessHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    released_metadata: std::sync::Arc<Mutex<Vec<serde_json::Value>>>,
    revalidated_metadata: std::sync::Arc<Mutex<Vec<Option<serde_json::Value>>>>,
    admission_metadata: Option<serde_json::Value>,
    ready: bool,
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

// A registered server that returns a misleading typed error after dispatch is
// polled. The kernel must not treat the untrusted error variant as provenance.
struct ToolNotRegisteredAfterDispatchServer {
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

impl RuntimeAdmissionHook for InvalidReceiptMetadataRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-invalid-receipt-metadata-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "adm-invalid-receipt-metadata",
                "accepted": true,
                "reserved_destructive_lease_id": "lease-invalid-receipt-metadata",
                "failure_code": null
            },
            "provenance": {
                "otel": {
                    "trace_id": "not-a-trace-id",
                    "span_id": "0123456789abcdef"
                }
            }
        }))))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            "lease-invalid-receipt-metadata"
        );
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
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

impl RuntimeAdmissionHook for ControllableReadinessAdmissionHook {
    fn name(&self) -> &str {
        "test-controllable-readiness-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": format!("adm-{}", context.request.request_id),
                "accepted": true,
                "reserved_destructive_lease_id": format!(
                    "lease-{}",
                    context.request.request_id
                ),
                "failure_code": null
            }
        }))))
    }

    fn poll_ready_before_dispatch_with_token(
        &self,
        _request: &ToolCallRequest,
        token: RuntimeAdmissionReadinessToken,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.readiness_polls.fetch_add(1, Ordering::SeqCst);
        self.readiness_started.notify_one();
        if self.ready.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(());
        }

        let mut registrations = match self.readiness_registrations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        registrations
            .entry(token)
            .and_modify(|(waker, _probe)| waker.clone_from(cx.waker()))
            .or_insert_with(|| (cx.waker().clone(), std::sync::Arc::new(())));
        if self.ready.load(Ordering::SeqCst) {
            registrations.remove(&token);
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }

    fn unregister_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        token: RuntimeAdmissionReadinessToken,
    ) {
        match self.readiness_registrations.lock() {
            Ok(mut guard) => {
                guard.remove(&token);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&token);
            }
        }
        self.readiness_unregistrations
            .fetch_add(1, Ordering::SeqCst);
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

fn assert_readiness_denial_released_pre_dispatch_state(
    kernel: &ChioKernel,
    cap: &CapabilityToken,
    hook: &ControllableReadinessAdmissionHook,
    invocations: &AtomicU64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    assert!(hook.readiness_polls.load(Ordering::SeqCst) >= 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        hook.releases.load(Ordering::SeqCst),
        1,
        "pre-dispatch denial must release runtime admission reservations"
    );
    let retry =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        retry,
        "pre-dispatch denial must reverse the invocation budget increment"
    );
    Ok(())
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

impl RuntimeAdmissionHook for DenyingRetainedReservationAdmissionHook {
    fn name(&self) -> &str {
        "test-denying-retained-reservation-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, self.expected_request_id);
        assert!(self.retained.load(Ordering::SeqCst));
        Ok(RuntimeAdmissionDecision::deny(
            "runtime admission denied after ambiguous release",
            Some(serde_json::json!({
                "chio_runtime": {
                    "admission_id": context.request.request_id,
                    "accepted": false,
                    "reserved_destructive_lease_id": "lease-denied-retained",
                    "reservation_release_failed": true,
                    "reservation_release_failure_reason": "release callback panicked"
                }
            })),
        ))
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        self.retained.store(false, Ordering::SeqCst);
        Ok(())
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

impl UrlElicitationAfterDispatchServer {
    fn new(id: &str, tools: Vec<&str>, dispatch_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            dispatch_effects,
        }
    }
}

impl UrlElicitationAfterStreamFallbackServer {
    fn new(
        id: &str,
        tools: Vec<&str>,
        invoke_effects: std::sync::Arc<AtomicU64>,
        invoke_with_cost_effects: std::sync::Arc<AtomicU64>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invoke_effects,
            invoke_with_cost_effects,
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
impl ToolServerConnection for UrlElicitationAfterDispatchServer {
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
        self.dispatch_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation returned after dispatch was polled".to_string(),
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
impl ToolServerConnection for UrlElicitationAfterStreamFallbackServer {
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
        self.invoke_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation returned from invoke after stream fallback".to_string(),
            elicitations: Vec::new(),
        })
    }

    async fn invoke_with_cost(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.invoke_with_cost_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation returned from invoke_with_cost after stream fallback"
                .to_string(),
            elicitations: Vec::new(),
        })
    }
}

impl RuntimeAdmissionHook for MetadataIsolationReadinessHook {
    fn name(&self) -> &str {
        "test-metadata-isolation-readiness-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(
            self.admission_metadata.clone(),
        ))
    }

    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if self.ready {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }

    fn revalidate_before_dispatch(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        let metadata = context.admission_metadata.cloned();
        match self.revalidated_metadata.lock() {
            Ok(mut revalidated) => revalidated.push(metadata),
            Err(poisoned) => poisoned.into_inner().push(metadata),
        }
        Ok(())
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        match self.released_metadata.lock() {
            Ok(mut released) => released.push(metadata.clone()),
            Err(poisoned) => poisoned.into_inner().push(metadata.clone()),
        }
        Ok(())
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

impl ToolNotRegisteredAfterDispatchServer {
    fn new(id: &str, tools: Vec<&str>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ToolNotRegisteredAfterDispatchServer {
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

fn assert_no_runtime_retention_claim(
    metadata: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(runtime) = metadata
        .get("chio_runtime")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    for key in [
        "reservations_retained_fail_closed",
        "retained_destructive_lease_id",
        "retained_treaty_continuation_id",
        "retained_swarm_continuation_id",
    ] {
        assert!(
            !runtime.contains_key(key),
            "untrusted metadata must not create runtime retention claim {key}"
        );
    }
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
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
fn runtime_admission_denial_does_not_retry_ambiguous_reservation_release(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let retained = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        DenyingRetainedReservationAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            retained: std::sync::Arc::clone(&retained),
            expected_request_id: "req-runtime-deny-retained",
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
        "req-runtime-deny-retained",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(retained.load(Ordering::SeqCst));
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-denied-retained"
    );
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    Ok(())
}

#[test]
fn nested_runtime_admission_denial_does_not_retry_ambiguous_reservation_release(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let retained = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        DenyingRetainedReservationAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            retained: std::sync::Arc::clone(&retained),
            expected_request_id: "req-nested-runtime-deny-retained",
        },
    ));

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
        "req-nested-runtime-deny-retained",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-nested-runtime-deny-retained",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(retained.load(Ordering::SeqCst));
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-denied-retained"
    );
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn chio_treaty_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn chio_swarm_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn session_tool_call_preserves_chio_swarm_runtime_context() -> Result<(), Box<dyn std::error::Error>>
{
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn runtime_admission_metadata_with_foreign_namespace_denies_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        InvalidReceiptMetadataRuntimeAdmissionHook {
            releases: std::sync::Arc::clone(&releases),
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
        "req-invalid-runtime-admission-metadata",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("runtime admission metadata rejected")
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert!(metadata.get("provenance").is_none());
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-invalid-receipt-metadata"
    );
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn runtime_admission_readiness_timeout_rejects_invalid_durations(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let zero = kernel.set_runtime_admission_readiness_timeout(Duration::ZERO);
    assert!(matches!(zero, Err(KernelError::InvalidConstraint(_))));
    let fractional = kernel.set_runtime_admission_readiness_timeout(Duration::from_micros(1_500));
    assert!(matches!(fractional, Err(KernelError::InvalidConstraint(_))));
    let overflow = kernel.set_runtime_admission_readiness_timeout(Duration::from_secs(u64::MAX));
    assert!(matches!(overflow, Err(KernelError::InvalidConstraint(_))));
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(1))?;
    Ok(())
}

#[test]
fn runtime_admission_readiness_revalidation_covers_expiry_and_emergency_stop(
) -> Result<(), Box<dyn std::error::Error>> {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-readiness-security-recheck",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let expiry_error = kernel
        .revalidate_tool_call_after_runtime_readiness(
            &request,
            false,
            cap.expires_at.saturating_add(1),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("expired capability was re-admitted"))?;
    assert!(expiry_error.contains("expired"));

    kernel.emergency_stop("test post-readiness stop")?;
    let emergency_error = kernel
        .revalidate_tool_call_after_runtime_readiness(&request, false, current_unix_timestamp())
        .err()
        .ok_or_else(|| std::io::Error::other("emergency-stopped kernel re-admitted request"))?;
    assert_eq!(emergency_error, EMERGENCY_STOP_DENY_REASON);
    Ok(())
}

#[test]
fn runtime_admission_readiness_dpop_revalidation_is_fresh_but_non_consuming(
) -> Result<(), Box<dyn std::error::Error>> {
    let agent_kp = make_keypair();
    let server = "srv-chio-runtime-dpop";
    let tool = "destructive_update";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);
    let arguments = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let proof = make_dpop_proof(
        &agent_kp,
        &cap,
        server,
        tool,
        &arguments,
        "nonce-readiness-recheck",
    );
    let request = ToolCallRequest {
        request_id: "req-chio-runtime-readiness-dpop".to_string(),
        capability: cap.clone(),
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: arguments.clone(),
        dpop_proof: Some(proof),
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    kernel.revalidate_tool_call_after_runtime_readiness(
        &request,
        true,
        current_unix_timestamp(),
    )?;
    kernel.revalidate_tool_call_after_runtime_readiness(
        &request,
        true,
        current_unix_timestamp(),
    )?;
    kernel.verify_dpop_for_request(&request, &cap)?;
    let replay_error = kernel
        .verify_dpop_for_request(&request, &cap)
        .err()
        .ok_or_else(|| std::io::Error::other("replayed DPoP proof was accepted"))?;
    assert!(replay_error.to_string().contains("replay"));

    let mut stale_body = make_dpop_proof(
        &agent_kp,
        &cap,
        server,
        tool,
        &arguments,
        "nonce-readiness-stale",
    )
    .body;
    stale_body.issued_at = 0;
    let mut stale_request = request.clone();
    stale_request.dpop_proof = Some(dpop::DpopProof::sign(stale_body, &agent_kp)?);
    let stale_error = kernel
        .revalidate_tool_call_after_runtime_readiness(
            &stale_request,
            true,
            current_unix_timestamp(),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("stale DPoP proof was re-admitted"))?;
    assert!(stale_error.contains("DPoP proof verification failed"));
    Ok(())
}

#[test]
fn runtime_admission_readiness_timeout_works_without_tokio_time_driver(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(25))?;
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-chio-runtime", "destructive_update");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let request = make_request_with_arguments(
        "req-chio-runtime-no-time-driver",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;

    let response = runtime.block_on(kernel.evaluate_tool_call(&request))?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("runtime admission readiness timed out after 25ms")
    );
    assert_readiness_denial_released_pre_dispatch_state(
        &kernel,
        &cap,
        hook.as_ref(),
        invocations.as_ref(),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_admission_pending_readiness_dispatches_after_ready_and_unregisters(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-ready-after-pending",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let evaluate = kernel.evaluate_tool_call(&request);
    let make_ready = async {
        tokio::time::timeout(Duration::from_secs(2), hook.readiness_started.notified())
            .await
            .map_err(|_| KernelError::Internal("runtime readiness was never polled".to_string()))?;
        let probes = hook.readiness_registration_probes();
        if probes.len() != 1 || probes[0].upgrade().is_none() {
            return Err(KernelError::Internal(
                "runtime readiness registration was not retained while pending".to_string(),
            ));
        }
        hook.allow_dispatch();
        Ok::<_, KernelError>(probes)
    };
    let (response, probes) = tokio::join!(evaluate, make_ready);
    let response = response?;
    let probes = probes?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    assert!(hook.readiness_polls.load(Ordering::SeqCst) >= 1);
    assert_eq!(hook.readiness_unregistrations.load(Ordering::SeqCst), 1);
    assert!(hook.readiness_registration_probes().is_empty());
    assert!(probes.into_iter().all(|probe| probe.upgrade().is_none()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_public_session_evaluation_while_readiness_pending_clears_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-readiness-drop-session-wrapper",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;
    let mut evaluation = Box::pin(
        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
            &context,
            &operation,
            &mut client,
        ),
    );
    tokio::select! {
        biased;
        response = &mut evaluation => panic!("evaluation unexpectedly completed: {response:?}"),
        _ = hook.readiness_started.notified() => {}
    }
    let probes = hook.readiness_registration_probes();
    assert_eq!(probes.len(), 1);
    assert!(kernel
        .session(&session_id)
        .is_some_and(|session| !session.inflight().is_empty()));

    drop(evaluation);

    assert!(kernel
        .session(&session_id)
        .is_some_and(|session| session.inflight().is_empty()));
    assert_eq!(hook.readiness_unregistrations.load(Ordering::SeqCst), 1);
    assert!(probes.into_iter().all(|probe| probe.upgrade().is_none()));
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(matches!(
        kernel.request_session_cancellation(&session_id, &context.request_id),
        Err(KernelError::Session(
            SessionError::RequestNotInflight { .. }
        ))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_public_session_evaluation_during_dispatch_clears_dispatch_claim(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "srv-pending-session-drop".to_string(),
        started: std::sync::Arc::clone(&started),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-pending-session-drop", "compute")]),
        300,
    );
    let session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-dispatch-drop-session-wrapper",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "srv-pending-session-drop".to_string(),
        tool_name: "compute".to_string(),
        arguments: serde_json::json!({"work": "pending"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;
    let mut evaluation = Box::pin(
        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
            &context,
            &operation,
            &mut client,
        ),
    );
    tokio::select! {
        biased;
        response = &mut evaluation => panic!("evaluation unexpectedly completed: {response:?}"),
        _ = started.notified() => {}
    }
    assert!(matches!(
        kernel.request_session_cancellation(&session_id, &context.request_id),
        Err(KernelError::Session(
            SessionError::RequestNotCancellable { .. }
        ))
    ));

    drop(evaluation);

    assert!(kernel
        .session(&session_id)
        .is_some_and(|session| session.inflight().is_empty()));
    assert!(matches!(
        kernel.request_session_cancellation(&session_id, &context.request_id),
        Err(KernelError::Session(
            SessionError::RequestNotInflight { .. }
        ))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_admission_rechecks_revocation_after_readiness_wait(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());
    let trace = std::sync::Arc::new(CountingRevocationAdmissionTraceObserver::default());
    kernel.set_runtime_trace_observer(trace.clone());

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-chio-runtime", "destructive_update");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let request = make_request_with_arguments(
        "req-chio-runtime-revoked-while-pending",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let evaluate = kernel.evaluate_tool_call(&request);
    let revoke = async {
        tokio::time::timeout(Duration::from_secs(2), hook.readiness_started.notified())
            .await
            .map_err(|_| KernelError::Internal("runtime readiness was never polled".to_string()))?;
        let result = kernel.revoke_capability(&cap.id);
        hook.allow_dispatch();
        result
    };
    let (response, revocation) = tokio::join!(evaluate, revoke);
    revocation?;
    let response = response?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some(
            format!(
                "guard denied the request: capability has been revoked: {}",
                cap.id
            )
            .as_str()
        )
    );
    assert_eq!(
        trace.admissions.load(Ordering::SeqCst),
        1,
        "post-readiness revocation recheck must not emit a duplicate admission trace"
    );
    assert_readiness_denial_released_pre_dispatch_state(
        &kernel,
        &cap,
        hook.as_ref(),
        invocations.as_ref(),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_runtime_admission_rechecks_revocation_after_readiness_wait(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-chio-runtime", "destructive_update");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-runtime-nested-revoked-while-pending",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: cap.clone(),
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;

    let evaluate = kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
        &context,
        &operation,
        &mut client,
    );
    let revoke = async {
        tokio::time::timeout(Duration::from_secs(2), hook.readiness_started.notified())
            .await
            .map_err(|_| {
                KernelError::Internal("nested runtime readiness was never polled".to_string())
            })?;
        let result = kernel.revoke_capability(&cap.id);
        hook.allow_dispatch();
        result
    };
    let (response, revocation) = tokio::join!(evaluate, revoke);
    revocation?;
    let response = response?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some(
            format!(
                "guard denied the request: capability has been revoked: {}",
                cap.id
            )
            .as_str()
        )
    );
    assert_readiness_denial_released_pre_dispatch_state(
        &kernel,
        &cap,
        hook.as_ref(),
        invocations.as_ref(),
    )?;
    Ok(())
}

#[test]
fn runtime_admission_readiness_timeout_releases_pre_dispatch_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(25))?;
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-chio-runtime", "destructive_update");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let request = make_request_with_arguments(
        "req-chio-runtime-readiness-timeout",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("runtime admission readiness timed out after 25ms")
    );
    assert_readiness_denial_released_pre_dispatch_state(
        &kernel,
        &cap,
        hook.as_ref(),
        invocations.as_ref(),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_runtime_admission_readiness_timeout_releases_pre_dispatch_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(25))?;
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let hook = std::sync::Arc::new(ControllableReadinessAdmissionHook::new());
    kernel.set_runtime_admission_hook(hook.clone());

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-chio-runtime", "destructive_update");
    grant.max_invocations = Some(1);
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-runtime-nested-readiness-timeout",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: cap.clone(),
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
            &context,
            &operation,
            &mut client,
        ),
    )
    .await??;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("runtime admission readiness timed out after 25ms")
    );
    assert_readiness_denial_released_pre_dispatch_state(
        &kernel,
        &cap,
        hook.as_ref(),
        invocations.as_ref(),
    )?;
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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

    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    )?;

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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-dispatch-error",
        admission_id: "adm-dispatch-error",
        lease_id: "lease-dispatch-error",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-dispatch-error"
    );
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-dispatch-error"
    );
    Ok(())
}

#[test]
fn server_url_elicitation_is_terminal_and_retains_runtime_reservations(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invoke_effects = std::sync::Arc::new(AtomicU64::new(0));
    let invoke_with_cost_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationAfterStreamFallbackServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invoke_effects),
        std::sync::Arc::clone(&invoke_with_cost_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-url-elicitation",
        admission_id: "adm-url-elicitation",
        lease_id: "lease-url-elicitation",
        continuation_id: Some("continuation-url-elicitation"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-url-elicitation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(matches!(
        response.receipt.decision,
        Some(Decision::Incomplete { .. })
    ));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invoke_effects.load(Ordering::SeqCst), 1);
    assert_eq!(invoke_with_cost_effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "a server-returned URL error cannot prove that dispatch had no side effect"
    );
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_outcome_unknown"],
        true
    );
    assert_eq!(
        metadata["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    assert_eq!(kernel.receipt_log().len(), 1);
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-cancelled",
        admission_id: "adm-cancelled",
        lease_id: "lease-cancelled",
        continuation_id: Some("continuation-cancelled"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete",
        admission_id: "adm-incomplete",
        lease_id: "lease-incomplete",
        continuation_id: Some("continuation-incomplete"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-dropped",
        admission_id: "adm-dropped",
        lease_id: "lease-dropped",
        continuation_id: Some("continuation-dropped"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: Some(metadata.clone()),
            runtime_admission_metadata: Some(metadata),
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
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-budget-deny",
        admission_id: "adm-pre-dispatch-budget-deny",
        lease_id: "lease-pre-dispatch-budget-deny",
        continuation_id: Some("continuation-pre-dispatch-budget-deny"),
    }));

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
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-release-failure-budget-deny",
        admission_id: "adm-release-failure-budget-deny",
        lease_id: "lease-release-failure-budget-deny",
    }));

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
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
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
            replayed_event: false,
        },
    }
}

/// Authorize a real, open budget hold that exactly matches the fabricated drop
/// charge (see `make_fabricated_drop_charge`). The drop-guard tests build a
/// fabricated `BudgetChargeResult`; without a matching open hold in the store,
/// the monetary reversal fails and records a fault receipt. Authorizing the
/// hold first models the real admission so the
/// pre-dispatch monetary unwind is a genuine, clean, receipt-free reversal.
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
fn drop_pre_dispatch_releases_reservations_no_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-dropped",
        admission_id: "adm-pre-dispatch-dropped",
        lease_id: "lease-pre-dispatch-dropped",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: Some(metadata.clone()),
            runtime_admission_metadata: Some(metadata),
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
fn drop_pre_dispatch_monetary_unwinds_without_receipt() -> Result<(), Box<dyn std::error::Error>> {
    // Flag-drop delta shipped unconditionally (program decision 2026-07-07):
    // a MONETARY future dropped before dispatch used to record a
    // drop-cancellation receipt; it now takes the pre-dispatch branch
    // instead - hold reversed, reservations released, no receipt.
    let mut kernel = make_kernel(make_config());
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-monetary-pre-dispatch-drop",
        admission_id: "adm-monetary-pre-dispatch-drop",
        lease_id: "lease-monetary-pre-dispatch-drop",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
    // reversal is a genuine, clean unwind. An un-reversible fabricated hold
    // would record a fault receipt.
    authorize_fabricated_drop_hold(&kernel, &cap.id)?;
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());
    let authorization = PaymentAuthorization {
        authorization_id: "auth-monetary-pre-dispatch-drop".to_string(),
        settled: false,
        settlement_transaction_id: None,
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: Some(metadata.clone()),
            runtime_admission_metadata: Some(metadata),
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
    // A non-monetary grant with `max_invocations` increments an invocation
    // counter at admission. A future dropped BEFORE
    // dispatch must reverse that increment so a never-dispatched call does not
    // permanently consume the slot.
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
    assert!(
        admitted,
        "admission must consume the single invocation slot"
    );

    let mutation = PreExecutionBudgetMutation::Invocation { grant_index: 0 };
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
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
    // A delegated capability admitted its share of the parent budget at
    // admission. A future dropped BEFORE dispatch must
    // release that share or the child's claim is permanently recorded.
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
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
    // Refcount model (replaces the old boolean-owner gate). Two OVERLAPPING
    // evaluations hold the SAME delegated child edge. An EARLIER evaluation
    // admits child_a (lease 1). A SECOND overlapping evaluation idempotently
    // re-admits the same child_a (lease 2) and is then DROPPED before dispatch.
    // The drop releases only the SECOND evaluation's lease (holders 2 -> 1); it
    // must NOT free the edge the first evaluation still holds, so an
    // oversubscribing sibling child_b stays DENIED. RED under a non-refcounted
    // release (the drop would free child_a's only edge and child_b would
    // wrongly admit); GREEN with the refcount.
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
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
    // When a pre-dispatch cleanup step fails, the drop must record a signed
    // receipt documenting the fault so a stuck
    // hold/reservation lands on the append-only log rather than being silently
    // burned.
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: Some(metadata.clone()),
            runtime_admission_metadata: Some(metadata),
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

#[test]
fn execution_nonce_preflight_cleanup_fault_denies_without_minting_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-nonce-preflight-cleanup-fault",
        admission_id: "adm-nonce-preflight-cleanup-fault",
        lease_id: "lease-nonce-preflight-cleanup-fault",
    }));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request(
        "req-nonce-preflight-cleanup-fault",
        &cap,
        "read_file",
        "srv-a",
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("execution nonce preflight cleanup failed")
    );
    assert!(response.execution_nonce.is_none());
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["pre_dispatch_cleanup_failed"],
        true
    );
    assert_eq!(metadata["execution_nonce"]["stage"], "preflight");
    assert_eq!(metadata["execution_nonce"]["tool_dispatched"], false);
    assert_eq!(kernel.receipt_log().len(), 1);
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), eval).await;
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
// across a post-dispatch parent drop, and the no-double-record
// property on the normal exit.
struct NestedChildOpServer {
    id: String,
    tools: Vec<String>,
    child_ops: std::sync::Arc<AtomicU64>,
    park: bool,
}

#[derive(Clone, Copy)]
enum ChildWriteFailure {
    Never,
    AppendThenError(u64),
    Always,
}

struct LifecycleFaultReceiptStore {
    events: std::sync::Arc<Mutex<Vec<String>>>,
    child_attempts: AtomicU64,
    child_failure: ChildWriteFailure,
    receipt_seq: Option<u64>,
    checkpoint_fails: bool,
    parent_error_after_record: AtomicBool,
}

impl LifecycleFaultReceiptStore {
    fn new(
        events: std::sync::Arc<Mutex<Vec<String>>>,
        child_failure: ChildWriteFailure,
        receipt_seq: Option<u64>,
        checkpoint_fails: bool,
    ) -> Self {
        Self {
            events,
            child_attempts: AtomicU64::new(0),
            child_failure,
            receipt_seq,
            checkpoint_fails,
            parent_error_after_record: AtomicBool::new(false),
        }
    }

    fn fail_next_parent_after_record(self) -> Self {
        self.parent_error_after_record.store(true, Ordering::SeqCst);
        self
    }

    fn record_event(&self, event: String) -> Result<(), ReceiptStoreError> {
        self.events
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("receipt event lock poisoned".to_string()))?
            .push(event);
        Ok(())
    }

    fn append_parent(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let kind = match receipt.decision.as_ref() {
            Some(Decision::Allow) => "allow",
            Some(Decision::Deny { .. }) => "deny",
            Some(Decision::Cancelled { .. }) => "cancelled",
            Some(Decision::Incomplete { .. }) => "incomplete",
            None => "none",
        };
        self.record_event(format!("parent:{kind}:recorded"))?;
        if self.parent_error_after_record.swap(false, Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "parent receipt acknowledgement failed after append".to_string(),
            ));
        }
        Ok(())
    }

    fn append_child(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        let attempt = self.child_attempts.fetch_add(1, Ordering::SeqCst);
        let (fails, outcome) = match self.child_failure {
            ChildWriteFailure::Never => (false, "recorded"),
            ChildWriteFailure::AppendThenError(failed_attempt) if attempt == failed_attempt => {
                (true, "recorded_then_failed")
            }
            ChildWriteFailure::AppendThenError(_) => (false, "recorded"),
            ChildWriteFailure::Always => (true, "failed"),
        };
        self.record_event(format!("child:{}:{outcome}", receipt.request_id.as_str()))?;
        if fails {
            Err(ReceiptStoreError::Conflict(
                "child receipt write unavailable".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

impl ReceiptStore for LifecycleFaultReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_parent(receipt)
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_parent(receipt)?;
        Ok(self.receipt_seq)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.append_child(receipt)
    }

    fn append_child_receipt_returning_seq(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_child(receipt)?;
        Ok(self.receipt_seq)
    }

    fn create_next_receipt_checkpoint(
        &self,
        _max_batch: u64,
        _keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        if self.checkpoint_fails {
            return Err(ReceiptStoreError::Canonical(
                "checkpoint creation failed after append".to_string(),
            ));
        }
        Err(ReceiptStoreError::Conflict(
            "checkpoint creation was not configured".to_string(),
        ))
    }
}

fn signed_drop_guard_child_receipt(
    kernel: &ChioKernel,
    parent_request_id: &str,
    child_request_id: &str,
) -> Result<ChildRequestReceipt, KernelError> {
    let mut context = OperationContext::new(
        SessionId::new("session-drop-guard-receipts"),
        RequestId::new(child_request_id),
        "agent-drop-guard-receipts".to_string(),
    );
    context.parent_request_id = Some(RequestId::new(parent_request_id));
    build_child_request_receipt(
        &kernel.config.policy_hash,
        &kernel.config.keypair,
        &context,
        OperationKind::ListRoots,
        OperationTerminalState::Completed,
        serde_json::json!({"outcome": "completed"}),
    )
}

impl NestedChildOpServer {
    fn new(id: &str, tools: Vec<&str>, child_ops: std::sync::Arc<AtomicU64>, park: bool) -> Self {
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
// once (no double-record between the normal `record_child_receipts` flush and
// the disarmed drop guard) and the parent receipt must be a non-cancellation.
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

#[test]
fn child_receipt_ambiguous_append_is_not_retried_but_unattempted_suffix_is(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::AppendThenError(1),
        None,
        false,
    )))?;
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-child-partial-retry",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );
    let first =
        signed_drop_guard_child_receipt(&kernel, &request.request_id, "req-child-partial-first")?;
    let second =
        signed_drop_guard_child_receipt(&kernel, &request.request_id, "req-child-partial-second")?;
    let third =
        signed_drop_guard_child_receipt(&kernel, &request.request_id, "req-child-partial-third")?;
    let budget_mutation = PreExecutionBudgetMutation::None;
    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        None,
        &budget_mutation,
        None,
        PostAdmissionReceiptContext {
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        false,
    );
    guard.child_receipts_mut().extend([first, second, third]);
    guard.mark_dispatch_started();
    assert!(guard.flush_child_receipts().is_err());
    drop(guard);

    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(
        recorded_events,
        vec![
            "child:req-child-partial-first:recorded",
            "child:req-child-partial-second:recorded_then_failed",
            "child:req-child-partial-third:recorded",
            "parent:cancelled:recorded",
        ]
    );
    assert_eq!(kernel.child_receipt_log().len(), 2);
    assert_eq!(kernel.receipt_log().len(), 1);
    let parent = kernel
        .receipt_log()
        .get(0)
        .cloned()
        .ok_or_else(|| std::io::Error::other("parent cancellation receipt missing"))?;
    assert!(parent.is_cancelled());
    let runtime = parent
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_runtime"))
        .ok_or_else(|| std::io::Error::other("child persistence metadata missing"))?;
    assert_eq!(runtime["unpersisted_child_receipt_count"], 0);
    assert_eq!(runtime["append_outcome_unknown_child_receipt_count"], 1);
    let unknown: ChildRequestReceipt =
        serde_json::from_value(runtime["append_outcome_unknown_signed_child_receipts"][0].clone())?;
    assert_eq!(unknown.request_id.as_str(), "req-child-partial-second");
    assert!(unknown.verify_signature()?);
    Ok(())
}

#[test]
fn child_receipt_append_error_is_signed_into_parent_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::Always,
        None,
        false,
    )))?;
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-child-persistent-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );
    let child =
        signed_drop_guard_child_receipt(&kernel, &request.request_id, "req-child-persistent")?;
    let budget_mutation = PreExecutionBudgetMutation::None;
    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        None,
        &budget_mutation,
        None,
        PostAdmissionReceiptContext {
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        false,
    );
    guard.child_receipts_mut().push(child);
    guard.mark_dispatch_started();
    assert!(guard.flush_child_receipts().is_err());
    drop(guard);

    let parent = kernel
        .receipt_log()
        .get(0)
        .cloned()
        .ok_or_else(|| std::io::Error::other("parent cancellation receipt missing"))?;
    assert!(parent.is_cancelled());
    let runtime = parent
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_runtime"))
        .ok_or_else(|| std::io::Error::other("child persistence metadata missing"))?;
    assert_eq!(runtime["child_receipt_persistence_failed"], true);
    assert_eq!(runtime["unpersisted_child_receipt_count"], 0);
    assert_eq!(runtime["append_outcome_unknown_child_receipt_count"], 1);
    let embedded: ChildRequestReceipt =
        serde_json::from_value(runtime["append_outcome_unknown_signed_child_receipts"][0].clone())?;
    assert_eq!(embedded.request_id.as_str(), "req-child-persistent");
    assert!(embedded.verify_signature()?);
    assert_eq!(kernel.child_receipt_log().len(), 0);
    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(
        recorded_events,
        vec![
            "child:req-child-persistent:failed",
            "parent:cancelled:recorded",
        ]
    );
    Ok(())
}

#[test]
fn checkpoint_failure_after_child_append_does_not_retry_committed_child(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut config = make_config();
    config.checkpoint_batch_size = 1;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::Never,
        Some(1),
        true,
    )))?;
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-child-checkpoint-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );
    let child =
        signed_drop_guard_child_receipt(&kernel, &request.request_id, "req-child-checkpoint")?;
    let budget_mutation = PreExecutionBudgetMutation::None;
    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        None,
        &budget_mutation,
        None,
        PostAdmissionReceiptContext {
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
        },
        false,
    );
    guard.child_receipts_mut().push(child);
    guard.mark_dispatch_started();
    assert!(guard.flush_child_receipts().is_err());
    drop(guard);

    assert_eq!(kernel.child_receipt_log().len(), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(
        recorded_events,
        vec![
            "child:req-child-checkpoint:recorded",
            "parent:cancelled:recorded",
        ]
    );
    Ok(())
}

#[test]
fn parent_append_acknowledgement_failure_does_not_add_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut kernel = make_kernel(make_config());
    let store = LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::Never,
        None,
        false,
    )
    .fail_next_parent_after_record();
    kernel.set_receipt_store(Box::new(store))?;
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-parent-append-acknowledgement-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );

    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert!(kernel.receipt_log().is_empty());
    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(recorded_events, vec!["parent:allow:recorded"]);
    Ok(())
}

#[test]
fn parent_checkpoint_failure_after_append_does_not_add_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut config = make_config();
    config.checkpoint_batch_size = 1;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::Never,
        Some(1),
        true,
    )))?;
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-parent-checkpoint-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );

    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    assert_eq!(
        receipt_log
            .get(0)
            .and_then(|receipt| receipt.decision.as_ref()),
        Some(&Decision::Allow)
    );
    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(recorded_events, vec!["parent:allow:recorded"]);
    Ok(())
}

#[test]
fn nested_parent_checkpoint_failure_after_append_does_not_add_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let events = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut config = make_config();
    config.checkpoint_batch_size = 1;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(LifecycleFaultReceiptStore::new(
        std::sync::Arc::clone(&events),
        ChildWriteFailure::Never,
        Some(1),
        true,
    )))?;
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
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
        "req-nested-parent-checkpoint-failure",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-nested-parent-checkpoint-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7"}),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });

    assert!(result.is_err());
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    assert_eq!(
        receipt_log
            .get(0)
            .and_then(|receipt| receipt.decision.as_ref()),
        Some(&Decision::Allow)
    );
    let recorded_events = events
        .lock()
        .map_err(|_| std::io::Error::other("receipt event lock poisoned"))?
        .clone();
    assert_eq!(recorded_events, vec!["parent:allow:recorded"]);
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-drop-retained",
        admission_id: "adm-drop-retained",
        lease_id: "lease-drop-retained",
        continuation_id: Some("continuation-drop-retained"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn request_cancelled_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-cancel-marked",
        admission_id: "adm-cancel-marked",
        lease_id: "lease-cancel-marked",
        continuation_id: Some("continuation-cancel-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn request_incomplete_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete-marked",
        admission_id: "adm-incomplete-marked",
        lease_id: "lease-incomplete-marked",
        continuation_id: Some("continuation-incomplete-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn incomplete_stream_output_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>>
{
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-incomplete-stream-marked",
        admission_id: "adm-incomplete-stream-marked",
        lease_id: "lease-incomplete-stream-marked",
        continuation_id: Some("continuation-incomplete-stream-marked"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
fn caller_metadata_cannot_claim_incomplete_stream_retention(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request(
        "req-caller-incomplete-stream-retention",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );

    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_destructive_lease_id": "caller-controlled-lease",
                "reservations_retained_fail_closed": true,
                "retained_destructive_lease_id": "caller-controlled-lease",
                "retained_budget_hold_id": "caller-controlled-budget-hold",
                "retained_payment_authorization_id": "caller-controlled-payment"
            },
            "financial": {
                "cost_charged": 0,
                "currency": "FAKE"
            },
            "attribution": {
                "subject_key": "caller-controlled-subject"
            },
            "custom_context": "preserved"
        })),
    )?;

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert!(response.receipt.is_incomplete());
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_no_runtime_retention_claim(metadata)?;
    assert!(metadata.get("financial").is_none());
    assert_ne!(
        metadata["attribution"]["subject_key"],
        "caller-controlled-subject"
    );
    assert_eq!(metadata["custom_context"], "preserved");
    Ok(())
}

#[test]
fn post_invocation_block_marks_reservations_retained() -> Result<(), Box<dyn std::error::Error>> {
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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-post-invocation-block",
        admission_id: "adm-post-invocation-block",
        lease_id: "lease-post-invocation-block",
        continuation_id: Some("continuation-post-invocation-block"),
    }));

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

    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_swarm_continuation_id": "caller-controlled-swarm",
                "retained_swarm_continuation_id": "caller-controlled-swarm"
            }
        })),
    )?;

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
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("post-invocation block receipt metadata missing"))?;
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
    assert!(metadata["chio_runtime"]
        .get("retained_swarm_continuation_id")
        .is_none());
    Ok(())
}

#[test]
fn caller_metadata_cannot_claim_post_invocation_retention() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SucceedingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));
    kernel.add_post_invocation_hook(Box::new(BlockingPostInvocationHook));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request(
        "req-caller-post-invocation-retention",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );

    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_treaty_continuation_id": "caller-controlled-continuation"
            }
        })),
    )?;

    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("deny receipt metadata missing"))?;
    assert_no_runtime_retention_claim(metadata)?;
    Ok(())
}

#[test]
fn caller_metadata_cannot_claim_retention_after_final_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request(
        "req-caller-final-revocation-retention",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );
    kernel.revoke_capability(&cap.id)?;

    let response = kernel.build_allow_response_with_metadata(
        ReceiptResponseContext {
            request: &request,
            evaluation_context: &EvaluationReceiptContext::default(),
            timestamp: current_unix_timestamp(),
            matched_grant_index: Some(0),
            extra_metadata: Some(serde_json::json!({
                "chio_runtime": {
                    "reserved_swarm_continuation_id": "caller-controlled-swarm"
                }
            })),
        },
        ToolCallOutput::Value(serde_json::json!({"status": "committed"})),
        None,
    )?;

    assert_eq!(response.verdict, Verdict::Deny);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("revocation deny metadata missing"))?;
    assert_no_runtime_retention_claim(metadata)?;
    Ok(())
}

#[test]
fn server_supplied_tool_not_registered_retains_post_dispatch_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredAfterDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-tool-not-registered",
        admission_id: "adm-tool-not-registered",
        lease_id: "lease-tool-not-registered",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
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
        0,
        "an untrusted server cannot make post-dispatch state reversible by choosing an error variant"
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny receipt metadata missing"))?;
    let runtime = metadata["chio_runtime"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("chio_runtime block missing"))?;
    assert_eq!(runtime["reservations_retained_fail_closed"], true);
    assert_eq!(
        runtime["retained_destructive_lease_id"],
        "lease-tool-not-registered"
    );
    assert_eq!(runtime["post_dispatch_outcome_unknown"], true);
    Ok(())
}

#[test]
fn server_supplied_tool_not_registered_retains_invocation_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredAfterDispatchServer::new(
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

    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "post-dispatch invocation exposure must remain consumed despite the server-supplied error type"
    );
    Ok(())
}

#[test]
fn nested_server_supplied_tool_not_registered_retains_invocation_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ToolNotRegisteredAfterDispatchServer::new(
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

    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "nested post-dispatch invocation exposure must remain consumed despite the server-supplied error type"
    );
    Ok(())
}

#[test]
fn url_elicitation_after_dispatch_retains_full_budget_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let dispatch_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationAfterDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&dispatch_effects),
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

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(dispatch_effects.load(Ordering::SeqCst), 1);
    let usage = kernel
        .with_budget_store(|store| Ok(store.get_usage(&cap.id, 0)?))?
        .ok_or_else(|| std::io::Error::other("retained invocation usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "a server-returned URL error must retain the admitted invocation"
    );
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_outcome_unknown"],
        true
    );
    assert_eq!(kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn nested_url_elicitation_after_dispatch_retains_full_budget_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let dispatch_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationAfterDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&dispatch_effects),
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(dispatch_effects.load(Ordering::SeqCst), 1);
    let usage = kernel
        .with_budget_store(|store| Ok(store.get_usage(&cap.id, 0)?))?
        .ok_or_else(|| std::io::Error::other("retained nested invocation usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    let slot_reusable =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        !slot_reusable,
        "a nested server-returned URL error must retain the admitted invocation"
    );
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(
        kernel.child_receipt_log().is_empty(),
        "server-local effects are ambiguous even without a nested child receipt"
    );
    Ok(())
}

#[test]
fn monetary_url_elicitation_retains_budget_and_payment_exposure(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let invoke_effects = std::sync::Arc::new(AtomicU64::new(0));
    let invoke_with_cost_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationAfterStreamFallbackServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invoke_effects),
        std::sync::Arc::clone(&invoke_with_cost_effects),
    )));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 300)?;
    let mut request = ToolCallRequest {
        request_id: "req-monetary-url-unknown".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    attach_fresh_payment_execution_nonce(&mut kernel, &cap, &mut request);

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(invoke_effects.load(Ordering::SeqCst), 0);
    assert_eq!(invoke_with_cost_effects.load(Ordering::SeqCst), 1);
    let usage = kernel
        .with_budget_store(|store| Ok(store.get_usage(&cap.id, 0)?))?
        .ok_or_else(|| std::io::Error::other("retained monetary usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert_eq!(usage.committed_cost_units()?, 100);
    assert_eq!(payment.authorized.load(Ordering::SeqCst), 1);
    assert_eq!(payment.released.load(Ordering::SeqCst), 0);
    assert_eq!(payment.refunded.load(Ordering::SeqCst), 0);

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    let runtime = &metadata["chio_runtime"];
    assert_eq!(runtime["post_dispatch_outcome_unknown"], true);
    assert_eq!(runtime["retained_budget_exposure_units"], 100);
    assert_eq!(
        runtime["retained_payment_authorization_id"],
        "auth_tracking"
    );
    assert_eq!(runtime["retained_payment_authorization_settled"], false);
    assert!(runtime["retained_budget_hold_id"]
        .as_str()
        .is_some_and(|hold_id| !hold_id.is_empty()));

    let mut retry = request;
    retry.request_id = "req-monetary-url-retry".to_string();
    let retry_response = kernel.evaluate_tool_call_blocking(&retry)?;
    assert_eq!(retry_response.verdict, Verdict::Deny);
    assert_eq!(
        invoke_with_cost_effects.load(Ordering::SeqCst),
        1,
        "retained exposure must deny a retry before a second dispatch"
    );
    Ok(())
}

#[test]
fn nested_monetary_server_error_retains_budget_and_payment_exposure(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(FailingMonetaryServer {
        id: "cost-srv".to_string(),
    }));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 300)?;
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-nested-monetary-server-error",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let mut request = ToolCallRequest {
        request_id: context.request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    attach_fresh_payment_execution_nonce(&mut kernel, &cap, &mut request);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;
    assert_eq!(response.verdict, Verdict::Deny);
    let usage = kernel
        .with_budget_store(|store| Ok(store.get_usage(&cap.id, 0)?))?
        .ok_or_else(|| std::io::Error::other("retained nested monetary usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert_eq!(payment.authorized.load(Ordering::SeqCst), 1);
    assert_eq!(payment.released.load(Ordering::SeqCst), 0);
    assert_eq!(payment.refunded.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("nested deny receipt metadata missing"))?;
    let runtime = &metadata["chio_runtime"];
    assert_eq!(runtime["post_dispatch_outcome_unknown"], true);
    assert_eq!(runtime["retained_budget_exposure_units"], 100);
    assert_eq!(
        runtime["retained_payment_authorization_id"],
        "auth_tracking"
    );
    assert_eq!(runtime["retained_payment_authorization_settled"], false);
    Ok(())
}

#[test]
fn settled_payment_authorization_is_retained_without_refund_after_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::settled();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let invoke_effects = std::sync::Arc::new(AtomicU64::new(0));
    let invoke_with_cost_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationAfterStreamFallbackServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invoke_effects),
        std::sync::Arc::clone(&invoke_with_cost_effects),
    )));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 300)?;
    let mut request = ToolCallRequest {
        request_id: "req-settled-payment-url-unknown".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    attach_fresh_payment_execution_nonce(&mut kernel, &cap, &mut request);

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(invoke_effects.load(Ordering::SeqCst), 0);
    assert_eq!(invoke_with_cost_effects.load(Ordering::SeqCst), 1);
    assert_eq!(payment.authorized.load(Ordering::SeqCst), 1);
    assert_eq!(payment.released.load(Ordering::SeqCst), 0);
    assert_eq!(payment.refunded.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("incomplete receipt metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["retained_payment_authorization_id"],
        "auth_tracking"
    );
    assert_eq!(
        metadata["chio_runtime"]["retained_payment_authorization_settled"],
        true
    );
    Ok(())
}

#[test]
fn caller_reserved_ids_do_not_trigger_release_when_hook_reserved_nothing(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(10))?;
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let released_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    let revalidated_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(MetadataIsolationReadinessHook {
        calls: std::sync::Arc::clone(&calls),
        releases: std::sync::Arc::clone(&releases),
        released_metadata: std::sync::Arc::clone(&released_metadata),
        revalidated_metadata,
        admission_metadata: None,
        ready: false,
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
    let request = make_request(
        "req-caller-reserved-id-no-hook-reservation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_destructive_lease_id": "caller-controlled-lease"
            }
        })),
    )?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let released = match released_metadata.lock() {
        Ok(released) => released.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert!(released.is_empty());
    Ok(())
}

#[test]
fn release_receives_only_trusted_hook_reservation_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.set_runtime_admission_readiness_timeout(Duration::from_millis(10))?;
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let released_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    let revalidated_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    let trusted_metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "trusted-admission",
            "accepted": true,
            "reserved_destructive_lease_id": "trusted-lease"
        }
    });
    kernel.set_runtime_admission_hook(std::sync::Arc::new(MetadataIsolationReadinessHook {
        calls: std::sync::Arc::clone(&calls),
        releases: std::sync::Arc::clone(&releases),
        released_metadata: std::sync::Arc::clone(&released_metadata),
        revalidated_metadata,
        admission_metadata: Some(trusted_metadata.clone()),
        ready: false,
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
    let request = make_request(
        "req-caller-injected-extra-reserved-id",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_treaty_continuation_id": "caller-controlled-continuation"
            }
        })),
    )?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let released = match released_metadata.lock() {
        Ok(released) => released.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert_eq!(released, vec![trusted_metadata]);
    Ok(())
}

#[test]
fn revalidation_receives_only_trusted_hook_reservation_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment));
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let released_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    let revalidated_metadata = std::sync::Arc::new(Mutex::new(Vec::new()));
    let trusted_metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "trusted-revalidation-admission",
            "accepted": true,
            "reserved_destructive_lease_id": "trusted-revalidation-lease"
        }
    });
    kernel.set_runtime_admission_hook(std::sync::Arc::new(MetadataIsolationReadinessHook {
        calls: std::sync::Arc::clone(&calls),
        releases: std::sync::Arc::clone(&releases),
        released_metadata,
        revalidated_metadata: std::sync::Arc::clone(&revalidated_metadata),
        admission_metadata: Some(trusted_metadata.clone()),
        ready: true,
    }));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 300)?;
    let mut request = ToolCallRequest {
        request_id: "req-caller-injected-revalidation-id".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    attach_fresh_payment_execution_nonce(&mut kernel, &cap, &mut request);
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "chio_runtime": {
                "reserved_treaty_continuation_id": "caller-controlled-revalidation-id"
            },
            "financial": {
                "cost_charged": 0,
                "currency": "FAKE",
                "budget_total": 0,
                "settlement_status": "settled"
            },
            "budget_authority": {
                "hold_id": "caller-controlled-budget-hold"
            },
            "governed_transaction": {
                "intent_hash": "caller-controlled-intent"
            },
            "attribution": {
                "subject_key": "caller-controlled-subject"
            },
            "custom_context": "preserved"
        })),
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    let revalidated = match revalidated_metadata.lock() {
        Ok(revalidated) => revalidated.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert!(!revalidated.is_empty());
    assert!(
        revalidated
            .iter()
            .all(|metadata| metadata.as_ref() == Some(&trusted_metadata)),
        "revalidation must never receive caller-injected reservation ids"
    );
    let receipt_metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("allow receipt metadata missing"))?;
    assert_eq!(receipt_metadata["financial"]["cost_charged"], 100);
    assert_eq!(receipt_metadata["financial"]["currency"], "USD");
    assert_eq!(receipt_metadata["financial"]["budget_total"], 1_000);
    assert_ne!(
        receipt_metadata["budget_authority"]["hold_id"],
        "caller-controlled-budget-hold"
    );
    assert_eq!(
        receipt_metadata["attribution"]["subject_key"],
        agent_kp.public_key().to_hex()
    );
    assert!(receipt_metadata.get("governed_transaction").is_none());
    assert_eq!(receipt_metadata["custom_context"], "preserved");
    assert_eq!(
        receipt_metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "trusted-revalidation-lease"
    );
    assert!(receipt_metadata["chio_runtime"]
        .get("reserved_treaty_continuation_id")
        .is_none());
    Ok(())
}

#[test]
fn drop_pre_dispatch_cleanup_fault_receipt_includes_monetary_hold_id(
) -> Result<(), Box<dyn std::error::Error>> {
    // The fabricated charge has no matching open hold, forcing a fault receipt.
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
    // and records a budget_reversal fault (no mark_dispatch_started, so this is
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
            evaluation_context: EvaluationReceiptContext::default(),
            extra_metadata: None,
            runtime_admission_metadata: None,
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
        .find(|fault| fault["step"] == "budget_reversal")
        .ok_or_else(|| std::io::Error::other("budget_reversal fault entry missing"))?;
    let hold_ids = monetary_fault["hold_ids"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("budget_reversal fault must carry hold_ids"))?;
    assert!(
        hold_ids.iter().any(|id| id == "hold-drop-guard-tests"),
        "the budget_reversal fault must name the budget hold id: {hold_ids:?}"
    );
    Ok(())
}

#[test]
fn retained_marker_requires_a_real_reservation() -> Result<(), Box<dyn std::error::Error>> {
    // Metadata without a reserved lease must not claim one was retained.
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
