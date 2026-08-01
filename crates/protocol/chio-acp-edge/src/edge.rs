// The ACP edge server, its deferred-task state, and the explicit
// compatibility-only passthrough wrapper.

#[derive(Debug, Clone)]
struct DeferredAcpTask {
    owner_agent_id: String,
    request: CrossProtocolExecutionRequest,
    task: AcpInvocationTask,
    result: Option<AcpInvocationResult>,
    expires_at_ms: u64,
}

/// The ACP edge server.
///
/// Maps Chio tools to ACP capabilities and routes invocations through
/// the kernel guard pipeline.
pub struct ChioAcpEdge {
    capabilities: Vec<AcpCapability>,
    capability_fidelity: BTreeMap<String, BridgeFidelity>,
    /// Maps capability ID to authoritative target binding metadata.
    capability_bindings: BTreeMap<String, CapabilityBinding>,
    task_counter: Cell<u64>,
    tasks: RefCell<BTreeMap<String, DeferredAcpTask>>,
}

/// Explicit compatibility-only surface for config-preview and direct ACP passthrough flows.
///
/// Callers must opt into this wrapper to reach the non-authoritative path.
#[cfg(any(test, feature = "compatibility-surface"))]
pub struct ChioAcpEdgeCompatibility<'a> {
    edge: &'a ChioAcpEdge,
}

fn validate_execution_context(execution: &AcpKernelExecutionContext) -> Result<(), AcpEdgeError> {
    validate_execution_agent_id(&execution.agent_id)?;
    if execution.approval_token.is_some() && !execution.approval_tokens.is_empty() {
        return Err(AcpEdgeError::InvalidRequest(
            "ACP execution must not mix singular and threshold approval tokens".to_string(),
        ));
    }
    if execution.approval_tokens.len()
        > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
    {
        return Err(AcpEdgeError::InvalidRequest(
            format!(
                "ACP threshold approval set exceeds {} tokens",
                chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
            ),
        ));
    }
    if execution.approval_tokens.is_empty() != execution.threshold_approval_proposal.is_none() {
        return Err(AcpEdgeError::InvalidRequest(
            "ACP threshold approval tokens and proposal must be supplied together".to_string(),
        ));
    }
    Ok(())
}

fn validate_execution_agent_id(agent_id: &str) -> Result<(), AcpEdgeError> {
    if agent_id.trim().is_empty() {
        return Err(AcpEdgeError::InvalidRequest(
            "ACP execution agent_id must not be empty".to_string(),
        ));
    }
    if agent_id.trim() != agent_id {
        return Err(AcpEdgeError::InvalidRequest(
            "ACP execution agent_id must not include leading or trailing whitespace".to_string(),
        ));
    }
    if agent_id.chars().any(|character| character.is_control()) {
        return Err(AcpEdgeError::InvalidRequest(
            "ACP execution agent_id must not include control characters".to_string(),
        ));
    }
    Ok(())
}

fn reject_request_bound_artifacts_without_stable_request_id(
    execution: &AcpKernelExecutionContext,
) -> Result<(), AcpEdgeError> {
    if execution.approval_token.is_none()
        && execution.approval_tokens.is_empty()
        && execution.supplemental_authorization.is_none()
        && execution.execution_nonce.is_none()
    {
        return Ok(());
    }
    Err(AcpEdgeError::InvalidRequest(
        "ACP request-bound authorization artifacts and execution nonces require \
         invoke_with_request_id or start_stream_with_request_id"
            .to_string(),
    ))
}

impl ChioAcpEdge {
    /// Create a new ACP edge from Chio tool manifests.
    pub fn new(config: AcpEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, AcpEdgeError> {
        let mut capabilities = BTreeMap::new();
        let mut capability_fidelity = BTreeMap::new();
        let mut capability_bindings = BTreeMap::new();
        let mut capability_sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for manifest in &manifests {
            chio_manifest::validate_manifest(manifest)?;
        }

        for manifest in &manifests {
            for tool in &manifest.tools {
                let cap_id = tool.name.clone();
                let source = format!("{}/{}", manifest.server_id, tool.name);
                let sources = capability_sources.entry(cap_id.clone()).or_default();
                sources.insert(source);

                if sources.len() > 1 {
                    capability_fidelity.insert(
                        cap_id.clone(),
                        BridgeFidelity::Unsupported {
                            reason: capability_collision_reason(&cap_id, sources),
                        },
                    );
                    capabilities.remove(&cap_id);
                    capability_bindings.remove(&cap_id);
                    continue;
                }

                if capability_fidelity.contains_key(&cap_id) {
                    continue;
                }

                let target_protocol =
                    target_protocol_for_tool_with_registry(tool, &authoritative_target_registry())
                        .map_err(AcpEdgeError::InvalidRequest)?;
                let category = infer_acp_category(tool, config.default_category);
                let fidelity = evaluate_bridge_fidelity(tool, category, target_protocol);
                capability_fidelity.insert(cap_id.clone(), fidelity.clone());

                if fidelity.published_by_default() {
                    capabilities.insert(
                        cap_id.clone(),
                        AcpCapability {
                            id: cap_id.clone(),
                            name: cap_id.clone(),
                            description: tool.description.clone(),
                            category,
                            requires_permission: config.require_permission || tool.has_side_effects,
                            bridge_fidelity: fidelity,
                        },
                    );

                    capability_bindings.insert(
                        cap_id,
                        CapabilityBinding {
                            target_protocol,
                            server_id: manifest.server_id.clone(),
                            tool_name: tool.name.clone(),
                        },
                    );
                }
            }
        }

        Ok(Self {
            capabilities: capabilities.into_values().collect(),
            capability_fidelity,
            capability_bindings,
            task_counter: Cell::new(0),
            tasks: RefCell::new(BTreeMap::new()),
        })
    }

    fn next_task_id(&self) -> String {
        let next = self.task_counter.get() + 1;
        self.task_counter.set(next);
        format!("acp-task-{next}")
    }

    fn prune_deferred_tasks(&self) {
        let now = current_unix_millis();
        self.tasks
            .borrow_mut()
            .retain(|_, task| task.expires_at_ms > now);
    }

    fn ensure_deferred_task_capacity(&self) -> Result<(), AcpEdgeError> {
        self.prune_deferred_tasks();
        let active_count = self
            .tasks
            .borrow()
            .values()
            .filter(|task| !task.task.status.is_terminal())
            .count();
        if active_count >= MAX_DEFERRED_ACP_TASKS {
            return Err(AcpEdgeError::InvalidRequest(
                "too many deferred tasks are retained".to_string(),
            ));
        }
        Ok(())
    }

    fn capability_binding(&self, capability_id: &str) -> Result<CapabilityBinding, AcpEdgeError> {
        self.capability_bindings
            .get(capability_id)
            .cloned()
            .ok_or_else(|| AcpEdgeError::ToolNotFound(capability_id.to_string()))
    }

    fn build_execution_request(
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
        binding: &CapabilityBinding,
        target_protocol: DiscoveryProtocol,
        ids: AcpRequestIds,
    ) -> Result<CrossProtocolExecutionRequest, AcpEdgeError> {
        Ok(CrossProtocolExecutionRequest {
            origin_request_id: ids.origin_request_id,
            kernel_request_id: ids.kernel_request_id,
            target_protocol,
            target_server_id: binding.server_id.clone(),
            target_tool_name: binding.tool_name.clone(),
            agent_id: execution.agent_id.clone(),
            arguments: arguments.clone(),
            capability: execution.capability.clone(),
            source_envelope: build_acp_source_envelope(capability_id, arguments)?,
            dpop_proof: execution.dpop_proof.clone(),
            execution_nonce: execution.execution_nonce.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            approval_tokens: execution.approval_tokens.clone(),
            threshold_approval_proposal: execution.threshold_approval_proposal.clone(),
            supplemental_authorization: execution.supplemental_authorization.clone(),
            model_metadata: execution.model_metadata.clone(),
        })
    }

    fn dpop_proof_matches_kernel_permission_preview(
        kernel: &ChioKernel,
        proof: &dpop::DpopProof,
        capability: &CapabilityToken,
        binding: &CapabilityBinding,
        arguments: &Value,
    ) -> bool {
        kernel
            .verify_dpop_for_permission_preview(
                proof,
                capability,
                &binding.server_id,
                &binding.tool_name,
                arguments,
            )
            .is_ok()
    }

    /// List all capabilities.
    pub fn capabilities(&self) -> &[AcpCapability] {
        &self.capabilities
    }

    /// Get a capability by ID.
    pub fn capability(&self, id: &str) -> Option<&AcpCapability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// Get the truthful bridge fidelity classification for a capability ID,
    /// including unpublished capabilities that were gated from discovery.
    pub fn bridge_fidelity(&self, id: &str) -> Option<&BridgeFidelity> {
        self.capability_fidelity.get(id)
    }

    /// List all capability IDs.
    pub fn capability_ids(&self) -> Vec<String> {
        self.capabilities.iter().map(|c| c.id.clone()).collect()
    }

    /// Access the explicit compatibility-only ACP surface.
    #[cfg(any(test, feature = "compatibility-surface"))]
    pub fn compatibility(&self) -> ChioAcpEdgeCompatibility<'_> {
        ChioAcpEdgeCompatibility { edge: self }
    }

    /// Evaluate a permission request against an explicit capability token.
    ///
    /// This is a truthful permission preview for deployments that already have
    /// authenticated capability context but are not yet dispatching the tool call
    /// itself. DPoP-required grants need kernel policy context and fail closed
    /// here; use [`evaluate_permission_with_kernel`](Self::evaluate_permission_with_kernel)
    /// for kernel-backed previews.
    pub fn evaluate_permission(
        &self,
        request: &PermissionRequest,
        execution: &AcpKernelExecutionContext,
    ) -> PermissionDecision {
        self.evaluate_permission_with_dpop_policy(request, execution, None)
    }

    /// Evaluate a permission request against the same kernel DPoP policy that
    /// authoritative invocation will use.
    pub fn evaluate_permission_with_kernel(
        &self,
        request: &PermissionRequest,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> PermissionDecision {
        self.evaluate_permission_with_dpop_policy(request, execution, Some(kernel))
    }

    fn evaluate_permission_with_dpop_policy(
        &self,
        request: &PermissionRequest,
        execution: &AcpKernelExecutionContext,
        kernel: Option<&ChioKernel>,
    ) -> PermissionDecision {
        if validate_execution_context(execution).is_err() {
            return PermissionDecision::Deny;
        }

        let Some(binding) = self.capability_bindings.get(&request.capability_id) else {
            return PermissionDecision::Deny;
        };

        if !matches!(execution.capability.verify_signature(), Ok(true)) {
            return PermissionDecision::Deny;
        }
        if !execution.capability.is_valid_at(current_unix_timestamp()) {
            return PermissionDecision::Deny;
        }
        if execution.capability.subject.to_hex() != execution.agent_id {
            return PermissionDecision::Deny;
        }

        let model_metadata = execution.model_metadata.as_ref();
        let matches_request = match capability_matches_request_with_model_metadata(
            &execution.capability,
            &binding.tool_name,
            &binding.server_id,
            &request.arguments,
            model_metadata,
        ) {
            Ok(matches) => matches,
            Err(_) => return PermissionDecision::Deny,
        };
        if !matches_request {
            return PermissionDecision::Deny;
        }

        let requires_dpop = match capability_request_requires_dpop_with_model_metadata(
            &execution.capability,
            &binding.tool_name,
            &binding.server_id,
            &request.arguments,
            model_metadata,
        ) {
            Ok(requires) => requires,
            Err(_) => return PermissionDecision::Deny,
        };
        if requires_dpop {
            let Some(proof) = execution.dpop_proof.as_ref() else {
                return PermissionDecision::Deny;
            };
            let Some(kernel) = kernel else {
                return PermissionDecision::Deny;
            };
            if !Self::dpop_proof_matches_kernel_permission_preview(
                kernel,
                proof,
                &execution.capability,
                binding,
                &request.arguments,
            ) {
                return PermissionDecision::Deny;
            }
        }

        PermissionDecision::Allow
    }

    /// Evaluate a permission request using the config-only passthrough preview path.
    ///
    /// This helper does not consult the Chio kernel and does not imply that a
    /// later invocation would produce a signed receipt.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn evaluate_permission_passthrough(&self, request: &PermissionRequest) -> PermissionDecision {
        let Some(cap) = self.capability(&request.capability_id) else {
            return PermissionDecision::Deny;
        };

        if cap.requires_permission {
            PermissionDecision::Deny
        } else {
            PermissionDecision::Allow
        }
    }

    /// Invoke a capability through the Chio kernel.
    ///
    /// The caller is responsible for registering the bound tool server with the
    /// provided kernel. Successful and denied outcomes both surface a signed Chio
    /// receipt in the returned metadata.
    pub fn invoke(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.capability_binding(capability_id)?;
        let request_suffix = current_unix_timestamp();
        let request = Self::build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{capability_id}-{request_suffix}"),
                kernel_request_id: format!("acp-{capability_id}-{request_suffix}"),
            },
        )?;
        let orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Invoke a capability with the stable request ID bound into threshold approvals.
    pub fn invoke_with_request_id(
        &self,
        request_id: &str,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        validate_execution_context(execution)?;
        let binding = self.capability_binding(capability_id)?;
        let request = Self::build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{request_id}"),
                kernel_request_id: request_id.to_string(),
            },
        )?;
        let orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Drive the kernel-backed ACP projection with a pending verdict for unit tests.
    ///
    /// The helper first executes the normal orchestrator path, then feeds a pending
    /// kernel response through the same receipt-sink mapper used by `invoke`.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn project_pending_approval_for_test(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
        reason: impl Into<String>,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.capability_binding(capability_id)?;
        let request_suffix = current_unix_timestamp();
        let request = Self::build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{capability_id}-pending-{request_suffix}"),
                kernel_request_id: format!("acp-{capability_id}-pending-{request_suffix}"),
            },
        )?;
        let mut orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        let reason = reason.into();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.output = None;
        orchestrated.response.reason = Some(reason.clone());
        orchestrated.response.terminal_state = OperationTerminalState::Incomplete { reason };
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Invoke a capability through the shared MCP target executor.
    ///
    /// This is the first non-native authoritative bridge path: ACP request
    /// semantics are projected onto an MCP `tools/call` execution surface while
    /// the underlying Chio receipt remains authoritative.
    pub fn invoke_with_mcp_target(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.capability_binding(capability_id)?;
        let request_suffix = current_unix_timestamp();
        let request = Self::build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            DiscoveryProtocol::Mcp,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{capability_id}-{request_suffix}"),
                kernel_request_id: format!("acp-mcp-{capability_id}-{request_suffix}"),
            },
        )?;
        let orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Invoke a capability through the explicit direct tool-server passthrough.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not confuse it with the
    /// signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn invoke_passthrough(
        &self,
        capability_id: &str,
        arguments: Value,
        server: &dyn ToolServerConnection,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        let binding = self
            .capability_bindings
            .get(capability_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(capability_id.to_string()))?;

        let invoke_result = match crate::block_on_tool_server_invoke(server.invoke(
            &binding.tool_name,
            arguments,
            None,
        )) {
            Ok(inner) => inner,
            Err(bridge_err) => {
                // Fail-closed mirror of the kernel sync-bridge gate:
                // current-thread runtime detected, refuse to deadlock.
                let msg = bridge_err.to_string();
                return Ok(AcpInvocationResult {
                    success: false,
                    data: Value::Null,
                    error: Some(msg.clone()),
                    metadata: Some(passthrough_metadata(Some(&msg))),
                });
            }
        };
        match invoke_result {
            Ok(result) => Ok(AcpInvocationResult {
                success: true,
                data: result,
                error: None,
                metadata: Some(passthrough_metadata(None)),
            }),
            Err(error) => Ok(AcpInvocationResult {
                success: false,
                data: Value::Null,
                error: Some(error.to_string()),
                metadata: Some(passthrough_metadata(Some(&error.to_string()))),
            }),
        }
    }

    /// Handle a JSON-RPC ACP request through the Chio kernel.
    ///
    /// `session/request_permission` becomes a capability-aware preview, while
    /// `tool/invoke` produces receipt-bearing kernel decisions.
    pub fn handle_jsonrpc(
        &self,
        message: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> AcpJsonRpcResponse {
        let AcpJsonRpcEnvelope { id, method, params } =
            match Self::parse_jsonrpc_envelope(&message) {
                Ok(envelope) => envelope,
                Err(response) => return AcpJsonRpcResponse::from_optional(response),
            };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_known_method(
            &id,
            &method,
            &params,
            ACP_JSONRPC_KNOWN_METHODS,
        ) {
            return AcpJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "session/list_capabilities" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": serde_json::to_value(&self.capabilities)
                            .unwrap_or(Value::Null),
                        "metadata": authoritative_surface_metadata(),
                    }
                })
            }
            "session/request_permission" => {
                let request = match Self::jsonrpc_permission_request(&params) {
                    Ok(request) => request,
                    Err(error) => {
                        return AcpJsonRpcResponse::from_optional(
                            should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                        )
                    }
                };
                if let Err(error) = validate_execution_context(execution) {
                    return AcpJsonRpcResponse::from_optional(
                        should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                    );
                }
                let decision = self.evaluate_permission_with_kernel(&request, kernel, execution);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "decision": serde_json::to_value(decision)
                            .unwrap_or(Value::Null),
                        "metadata": permission_preview_metadata("capability_preview", false)
                    }
                })
            }
            "tool/invoke" => {
                let (capability_id, arguments) =
                    match Self::jsonrpc_invocation_params(&params, "tool/invoke") {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            return AcpJsonRpcResponse::from_optional(
                                should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                            )
                        }
                    };
                if let Err(error) = validate_execution_context(execution) {
                    return AcpJsonRpcResponse::from_optional(
                        should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                    );
                }
                match self.invoke(&capability_id, arguments, kernel, execution) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": serde_json::to_value(&result)
                            .unwrap_or(Value::Null)
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": error.to_string()
                        }
                    }),
                }
            }
            "tool/stream" => self.handle_jsonrpc_stream(id, params, execution),
            "tool/cancel" => self.handle_jsonrpc_cancel(id, params, execution),
            "tool/resume" => self.handle_jsonrpc_resume(id, params, kernel, execution),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        AcpJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    /// Handle a JSON-RPC ACP request through the direct passthrough path.
    ///
    /// This compatibility helper exposes config-preview and direct tool
    /// invocation, but marks both as non-authoritative.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_passthrough(
        &self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> AcpJsonRpcResponse {
        let AcpJsonRpcEnvelope { id, method, params } =
            match Self::parse_jsonrpc_envelope(&message) {
                Ok(envelope) => envelope,
                Err(response) => return AcpJsonRpcResponse::from_optional(response),
            };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_known_method(
            &id,
            &method,
            &params,
            ACP_JSONRPC_KNOWN_METHODS,
        ) {
            return AcpJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "session/list_capabilities" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": serde_json::to_value(&self.capabilities)
                            .unwrap_or(Value::Null),
                        "metadata": compatibility_surface_metadata(),
                    }
                })
            }
            "session/request_permission" => {
                let request = match Self::jsonrpc_permission_request(&params) {
                    Ok(request) => request,
                    Err(error) => {
                        return AcpJsonRpcResponse::from_optional(
                            should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                        )
                    }
                };
                let decision = self.evaluate_permission_passthrough(&request);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "decision": serde_json::to_value(decision)
                            .unwrap_or(Value::Null),
                        "metadata": permission_preview_metadata("config_preview", true)
                    }
                })
            }
            "tool/invoke" => {
                let (capability_id, arguments) =
                    match Self::jsonrpc_invocation_params(&params, "tool/invoke") {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            return AcpJsonRpcResponse::from_optional(
                                should_respond.then_some(Self::jsonrpc_error_response(id, error)),
                            )
                        }
                    };
                match self.invoke_passthrough(&capability_id, arguments, server) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": serde_json::to_value(&result)
                            .unwrap_or(Value::Null)
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": error.to_string()
                        }
                    }),
                }
            }
            "tool/stream" => lifecycle_not_supported_error(
                id,
                "tool/stream",
                true,
                "ACP compatibility mode also exposes only blocking `tool/invoke`; streamed tool output is collected into the final invocation payload",
            ),
            "tool/cancel" => lifecycle_not_supported_error(
                id,
                "tool/cancel",
                true,
                "ACP compatibility mode does not expose cancel lifecycle for `tool/invoke`",
            ),
            "tool/resume" => lifecycle_not_supported_error(
                id,
                "tool/resume",
                true,
                "ACP compatibility mode does not expose resume lifecycle for `tool/invoke`",
            ),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        AcpJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    fn handle_jsonrpc_stream(
        &self,
        id: Value,
        params: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let (capability_id, arguments) =
            match Self::jsonrpc_invocation_params(&params, "tool/stream") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }
        match self.start_stream_task(&capability_id, arguments, execution) {
            Ok(task) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null)
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn handle_jsonrpc_cancel(
        &self,
        id: Value,
        params: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let task_id = match Self::jsonrpc_task_id_params(&params, "tool/cancel") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }
        match self.cancel_stream_task(&task_id, execution) {
            Ok(task) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null)
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn handle_jsonrpc_resume(
        &self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let task_id = match Self::jsonrpc_task_id_params(&params, "tool/resume") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }
        match self.resume_stream_task(&task_id, kernel, execution) {
            Ok((task, result)) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null),
                    "result": result
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn start_stream_task(
        &self,
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        self.start_stream_task_with_optional_request_id(capability_id, arguments, execution, None)
    }

    /// Start an authoritative deferred task under the caller's stable request ID.
    pub fn start_stream_with_request_id(
        &self,
        request_id: &str,
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        validate_execution_context(execution)?;
        self.start_stream_task_with_optional_request_id(
            capability_id,
            arguments,
            execution,
            Some(request_id),
        )
    }

    fn start_stream_task_with_optional_request_id(
        &self,
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
        request_id: Option<&str>,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        let binding = self.capability_binding(capability_id)?;
        self.ensure_deferred_task_capacity()?;
        let task_id = self.next_task_id();
        let expires_at_ms = current_unix_millis().saturating_add(DEFERRED_ACP_TASK_TTL_MILLIS);
        let kernel_request_id =
            request_id.map_or_else(|| format!("acp-stream-{task_id}"), str::to_string);
        let request = Self::build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: task_id.clone(),
                kernel_request_id,
            },
        )?;
        let task = AcpInvocationTask {
            id: task_id.clone(),
            status: AcpTaskStatus::Working,
            status_message: Some("Task accepted for authoritative deferred execution.".to_string()),
            metadata: Some(pending_stream_task_metadata("cross_protocol_orchestrator")),
        };
        self.tasks.borrow_mut().insert(
            task_id,
            DeferredAcpTask {
                owner_agent_id: execution.agent_id.clone(),
                request,
                task: task.clone(),
                result: None,
                expires_at_ms,
            },
        );
        Ok(task)
    }

    fn cancel_stream_task(
        &self,
        task_id: &str,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        validate_execution_context(execution)?;
        self.prune_deferred_tasks();
        let mut tasks = self.tasks.borrow_mut();
        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
        if task.owner_agent_id != execution.agent_id {
            return Err(AcpEdgeError::AccessDenied(
                "task is not owned by the current agent".to_string(),
            ));
        }
        match task.task.status {
            AcpTaskStatus::Working => {
                task.task.status = AcpTaskStatus::Cancelled;
                task.task.status_message = Some("Task cancelled by caller.".to_string());
                task.task.metadata = Some(cancelled_stream_task_metadata(
                    "cross_protocol_orchestrator",
                ));
                Ok(task.task.clone())
            }
            AcpTaskStatus::Cancelled => Ok(task.task.clone()),
            status => Err(AcpEdgeError::InvalidRequest(format!(
                "cannot cancel task in terminal status `{status:?}`"
            ))),
        }
    }

    fn resume_stream_task(
        &self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<(AcpInvocationTask, Value), AcpEdgeError> {
        validate_execution_context(execution)?;
        self.prune_deferred_tasks();
        let task_snapshot = {
            let tasks = self.tasks.borrow();
            let task = tasks
                .get(task_id)
                .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
            if task.owner_agent_id != execution.agent_id {
                return Err(AcpEdgeError::AccessDenied(
                    "task is not owned by the current agent".to_string(),
                ));
            }
            task.clone()
        };

        if task_snapshot.task.status == AcpTaskStatus::Working {
            let orchestrated = execute_orchestrated_acp_request(kernel, task_snapshot.request)?;
            let result = acp_invocation_result_from_orchestrated(orchestrated);
            let status = if result.success {
                AcpTaskStatus::Completed
            } else {
                AcpTaskStatus::Failed
            };
            let mut tasks = self.tasks.borrow_mut();
            if let Some(task) = tasks.get_mut(task_id) {
                task.task.status = status;
                task.task.status_message = result.error.clone();
                task.task.metadata = result.metadata.clone();
                task.result = Some(result.clone());
                let task_view = task.task.clone();
                let result_value = serde_json::to_value(&result).unwrap_or(Value::Null);
                return Ok((task_view, result_value));
            }
        }

        let tasks = self.tasks.borrow();
        let task = tasks
            .get(task_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
        Ok((
            task.task.clone(),
            task.result
                .as_ref()
                .map(|result| serde_json::to_value(result).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
        ))
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
impl ChioAcpEdgeCompatibility<'_> {
    /// Evaluate a permission request using the config-only passthrough preview path.
    ///
    /// This compatibility helper does not consult the Chio kernel and does not
    /// imply that a later invocation would produce a signed receipt.
    pub fn preview_permission(&self, request: &PermissionRequest) -> PermissionDecision {
        self.edge.evaluate_permission_passthrough(request)
    }

    /// Invoke a capability through the explicit direct tool-server passthrough.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not confuse it with the
    /// signed-receipt authority path.
    pub fn invoke(
        &self,
        capability_id: &str,
        arguments: Value,
        server: &dyn ToolServerConnection,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        self.edge
            .invoke_passthrough(capability_id, arguments, server)
    }

    /// Handle a JSON-RPC ACP request through the direct passthrough path.
    ///
    /// This compatibility helper exposes config-preview and direct tool
    /// invocation, but marks both as non-authoritative.
    pub fn handle_jsonrpc(
        &self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> AcpJsonRpcResponse {
        self.edge.handle_jsonrpc_passthrough(message, server)
    }
}
