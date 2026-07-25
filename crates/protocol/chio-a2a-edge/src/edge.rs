// The A2A edge server, its deferred-task state, and the explicit
// compatibility-only passthrough wrapper.

#[derive(Debug, Clone)]
struct DeferredA2aTask {
    owner_agent_id: String,
    request: CrossProtocolExecutionRequest,
    response: TaskResponse,
    expires_at_ms: u64,
}

/// The A2A edge server.
///
/// Wraps a set of Chio tool manifests and exposes them as A2A skills.
pub struct ChioA2aEdge {
    config: A2aEdgeConfig,
    skills: Vec<A2aSkillEntry>,
    skill_fidelity: BTreeMap<String, BridgeFidelity>,
    /// Maps skill ID to authoritative target binding metadata.
    skill_bindings: BTreeMap<String, SkillBinding>,
    /// Maps ambiguous unqualified tool names to the qualified published IDs.
    ambiguous_skill_ids: BTreeMap<String, Vec<String>>,
    task_counter: u64,
    tasks: BTreeMap<String, DeferredA2aTask>,
}

/// Explicit compatibility-only surface for direct A2A passthrough behavior.
///
/// This wrapper exists so non-authoritative flows are opt-in and visually
/// distinct from the default receipt-bearing kernel path.
#[cfg(any(test, feature = "compatibility-surface"))]
pub struct ChioA2aEdgeCompatibility<'a> {
    edge: &'a mut ChioA2aEdge,
}

fn validate_execution_context(execution: &A2aKernelExecutionContext) -> Result<(), A2aEdgeError> {
    validate_execution_agent_id(&execution.agent_id)?;
    if execution.approval_token.is_some() && !execution.approval_tokens.is_empty() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution must not mix singular and threshold approval tokens".to_string(),
        ));
    }
    if execution.approval_tokens.len()
        > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
    {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "A2A threshold approval set exceeds {} tokens",
            chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        )));
    }
    if execution.approval_tokens.is_empty() != execution.threshold_approval_proposal.is_none() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A threshold approval tokens and proposal must be supplied together".to_string(),
        ));
    }
    Ok(())
}

fn validate_execution_agent_id(agent_id: &str) -> Result<(), A2aEdgeError> {
    if agent_id.trim().is_empty() {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not be empty".to_string(),
        ));
    }
    if agent_id.trim() != agent_id {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not include leading or trailing whitespace".to_string(),
        ));
    }
    if agent_id.chars().any(|character| character.is_control()) {
        return Err(A2aEdgeError::InvalidRequest(
            "A2A execution agent_id must not include control characters".to_string(),
        ));
    }
    Ok(())
}

fn reject_request_bound_artifacts_without_stable_request_id(
    execution: &A2aKernelExecutionContext,
) -> Result<(), A2aEdgeError> {
    if execution.approval_token.is_none()
        && execution.approval_tokens.is_empty()
        && execution.supplemental_authorization.is_none()
        && execution.execution_nonce.is_none()
    {
        return Ok(());
    }
    Err(A2aEdgeError::InvalidRequest(
        "A2A request-bound authorization artifacts and execution nonces require \
         handle_send_message_with_request_id or handle_stream_message_with_request_id"
            .to_string(),
    ))
}

impl ChioA2aEdge {
    /// Create a new A2A edge from Chio tool manifests.
    pub fn new(config: A2aEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, A2aEdgeError> {
        config.validate_for_agent_card()?;

        let mut skills = Vec::new();
        let mut skill_fidelity = BTreeMap::new();
        let mut skill_bindings = BTreeMap::new();
        let mut ambiguous_skill_ids = BTreeMap::new();
        let mut tool_name_counts = BTreeMap::new();
        let mut published_id_counts = BTreeMap::new();

        for manifest in &manifests {
            chio_manifest::validate_manifest(manifest)?;
        }

        for manifest in &manifests {
            for tool in &manifest.tools {
                *tool_name_counts.entry(tool.name.clone()).or_insert(0usize) += 1;
            }
        }

        for manifest in &manifests {
            for tool in &manifest.tools {
                let mut skill_candidate = build_skill_candidate(
                    manifest,
                    tool,
                    tool_name_counts.get(&tool.name).copied().unwrap_or(0) > 1,
                )?;

                let published_id_count = published_id_counts
                    .entry(skill_candidate.published_id.clone())
                    .or_insert(0usize);
                *published_id_count += 1;
                if *published_id_count > 1 {
                    skill_candidate.published_id =
                        format!("{}#{}", skill_candidate.published_id, published_id_count);
                    skill_candidate.display_name =
                        format!("{} #{}", skill_candidate.display_name, published_id_count);
                    skill_candidate
                        .tags
                        .push("chio:ordinal-qualified".to_string());
                    skill_candidate.description = format!(
                        "{} This published id is ordinal-qualified because multiple manifests expose the same server-qualified tool id.",
                        skill_candidate.description
                    );
                }

                if let Some(alias) = &skill_candidate.lookup_alias {
                    ambiguous_skill_ids
                        .entry(alias.clone())
                        .or_insert_with(Vec::new)
                        .push(skill_candidate.published_id.clone());
                }

                skill_fidelity.insert(
                    skill_candidate.published_id.clone(),
                    skill_candidate.fidelity.clone(),
                );
                if skill_candidate.fidelity.published_by_default() {
                    skills.push(A2aSkillEntry {
                        id: skill_candidate.published_id.clone(),
                        name: skill_candidate.display_name.clone(),
                        description: skill_candidate.description.clone(),
                        tags: skill_candidate.tags.clone(),
                        examples: None,
                        input_modes: vec!["text".to_string()],
                        output_modes: vec!["text".to_string()],
                        bridge_fidelity: skill_candidate.fidelity.clone(),
                    });
                }

                if let Some(binding) = skill_candidate.binding {
                    skill_bindings.insert(skill_candidate.published_id, binding);
                }
            }
        }

        for qualified_ids in ambiguous_skill_ids.values_mut() {
            qualified_ids.sort();
            qualified_ids.dedup();
        }

        for (tool_name, qualified_ids) in &ambiguous_skill_ids {
            skill_fidelity.insert(
                tool_name.clone(),
                BridgeFidelity::Unsupported {
                    reason: format!(
                        "skill id collides across manifests; use one of the qualified ids: {}",
                        qualified_ids.join(", ")
                    ),
                },
            );
        }

        skills.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(Self {
            config,
            skills,
            skill_fidelity,
            skill_bindings,
            ambiguous_skill_ids,
            task_counter: 0,
            tasks: BTreeMap::new(),
        })
    }

    fn resolve_skill_binding(&self, skill_id: &str) -> Result<SkillBinding, A2aEdgeError> {
        if let Some(binding) = self.skill_bindings.get(skill_id) {
            return Ok(binding.clone());
        }

        if let Some(qualified_ids) = self.ambiguous_skill_ids.get(skill_id) {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "skill id '{skill_id}' is ambiguous across manifests; use one of: {}",
                qualified_ids.join(", ")
            )));
        }

        Err(A2aEdgeError::ToolNotFound(skill_id.to_string()))
    }

    #[cfg(any(test, feature = "compatibility-surface"))]
    fn jsonrpc_stream_not_supported(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": "message/stream is not supported on the compatibility A2A surface"
            }
        })
    }

    fn jsonrpc_error_response(id: Value, error: A2aEdgeError) -> Value {
        let (code, message) = match error {
            A2aEdgeError::ToolNotFound(message) | A2aEdgeError::InvalidRequest(message) => {
                (-32602, message)
            }
            other => (-32603, other.to_string()),
        };

        Self::jsonrpc_error_payload(id, code, &message)
    }

    fn jsonrpc_error_payload(id: Value, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        })
    }

    /// Generate the A2A Agent Card for `/.well-known/agent-card.json`.
    pub fn agent_card(&self) -> AgentCard {
        AgentCard {
            name: self.config.agent_name.clone(),
            description: self.config.agent_description.clone(),
            version: self.config.agent_version.clone(),
            supported_interfaces: vec![AgentInterface {
                url: self.config.endpoint_url.clone(),
                protocol_binding: self.config.protocol_binding.clone(),
                protocol_version: "1.0".to_string(),
            }],
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: self.skills.clone(),
        }
    }

    /// Serialize the Agent Card as JSON.
    pub fn agent_card_json(&self) -> Result<String, A2aEdgeError> {
        serde_json::to_string_pretty(&self.agent_card())
            .map_err(|e| A2aEdgeError::InvalidRequest(e.to_string()))
    }

    /// List all skill IDs.
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.id.clone()).collect()
    }

    /// Get a skill entry by ID.
    pub fn skill(&self, id: &str) -> Option<&A2aSkillEntry> {
        self.skills.iter().find(|s| s.id == id)
    }

    /// Get the truthful bridge fidelity classification for a skill ID,
    /// including unpublished skills that were gated from discovery.
    pub fn bridge_fidelity(&self, id: &str) -> Option<&BridgeFidelity> {
        self.skill_fidelity.get(id)
    }

    /// Access the explicit compatibility-only passthrough surface.
    #[cfg(any(test, feature = "compatibility-surface"))]
    pub fn compatibility(&mut self) -> ChioA2aEdgeCompatibility<'_> {
        ChioA2aEdgeCompatibility { edge: self }
    }

    /// Allocate a new task ID.
    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("a2a-task-{}", self.task_counter)
    }

    fn prune_deferred_tasks(&mut self) {
        let now = unix_now_millis();
        self.tasks.retain(|_, task| task.expires_at_ms > now);
    }

    fn ensure_deferred_task_capacity(&mut self) -> Result<(), A2aEdgeError> {
        self.prune_deferred_tasks();
        let active_count = self
            .tasks
            .values()
            .filter(|task| !task.response.status.is_terminal())
            .count();
        if active_count >= MAX_DEFERRED_A2A_TASKS {
            return Err(A2aEdgeError::InvalidRequest(
                "too many deferred tasks are retained".to_string(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_execution_request(
        binding: SkillBinding,
        skill_id: &str,
        source_request: &SendMessageRequest,
        arguments: Value,
        execution: &A2aKernelExecutionContext,
        origin_request_id: String,
        kernel_request_id: String,
    ) -> Result<CrossProtocolExecutionRequest, A2aEdgeError> {
        Ok(CrossProtocolExecutionRequest {
            origin_request_id,
            kernel_request_id,
            target_protocol: binding.target_protocol,
            target_server_id: binding.server_id,
            target_tool_name: binding.tool_name,
            agent_id: execution.agent_id.clone(),
            arguments,
            capability: execution.capability.clone(),
            source_envelope: build_a2a_source_envelope(skill_id, source_request)?,
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

    /// Handle a SendMessage request by routing it through the Chio kernel.
    ///
    /// The caller is responsible for registering the bound tool server with the
    /// provided kernel. Successful and denied decisions both carry a signed Chio
    /// receipt in the returned metadata.
    pub fn handle_send_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id();
        let request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let orchestrated = execute_orchestrated_a2a_request(kernel, request)?;
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Handle a SendMessage request under the caller's stable request ID.
    ///
    /// `SendMessageRequest` carries no identifier of its own, so request-bound
    /// authorization artifacts (threshold approval sets and supplemental
    /// authorization) can only be pre-minted when the caller supplies the ID the
    /// kernel will check them against.
    pub fn handle_send_message_with_request_id(
        &mut self,
        request_id: &str,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id();
        let execution_request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            task_id.clone(),
            request_id.to_string(),
        )?;
        let orchestrated = execute_orchestrated_a2a_request(kernel, execution_request)?;
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Drive the kernel-backed A2A projection with a pending verdict for unit tests.
    ///
    /// The helper first executes the normal orchestrator path, then feeds a pending
    /// kernel response through the same receipt-sink mapper used by `handle_send_message`.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn project_pending_approval_for_test(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        reason: impl Into<String>,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        let binding = self.resolve_skill_binding(skill_id)?;
        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id();
        let request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            arguments,
            execution,
            task_id.clone(),
            format!("a2a-{task_id}"),
        )?;
        let mut orchestrated = execute_orchestrated_a2a_request(kernel, request)?;
        let reason = reason.into();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.output = None;
        orchestrated.response.reason = Some(reason.clone());
        orchestrated.response.terminal_state = OperationTerminalState::Incomplete { reason };
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Start an authoritative deferred task for A2A streaming/task lifecycle.
    pub fn handle_stream_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        reject_request_bound_artifacts_without_stable_request_id(execution)?;
        self.handle_stream_message_with_optional_request_id(skill_id, request, execution, None)
    }

    /// Start an authoritative deferred task under the caller's stable request ID.
    pub fn handle_stream_message_with_request_id(
        &mut self,
        request_id: &str,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        validate_execution_context(execution)?;
        self.handle_stream_message_with_optional_request_id(
            skill_id,
            request,
            execution,
            Some(request_id),
        )
    }

    fn handle_stream_message_with_optional_request_id(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
        request_id: Option<&str>,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let binding = self.resolve_skill_binding(skill_id)?;
        self.ensure_deferred_task_capacity()?;
        let task_id = self.next_task_id();
        let expires_at_ms = unix_now_millis().saturating_add(DEFERRED_A2A_TASK_TTL_MILLIS);
        let kernel_request_id =
            request_id.map_or_else(|| format!("a2a-stream-{task_id}"), str::to_string);
        let orchestrated_request = Self::build_execution_request(
            binding,
            skill_id,
            request,
            extract_arguments_from_message(&request.message)?,
            execution,
            task_id.clone(),
            kernel_request_id,
        )?;

        let response = TaskResponse {
            id: task_id.clone(),
            status: TaskStatus::Working,
            status_message: Some("Task accepted for authoritative deferred execution.".to_string()),
            message: None,
            metadata: Some(pending_task_metadata(
                "cross_protocol_orchestrator",
                "deferred_task_poll",
            )),
        };
        self.tasks.insert(
            task_id,
            DeferredA2aTask {
                owner_agent_id: execution.agent_id.clone(),
                request: orchestrated_request,
                response: response.clone(),
                expires_at_ms,
            },
        );
        Ok(response)
    }

    /// Handle a SendMessage request through the explicit direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not mistake it for the
    /// signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_send_message_passthrough(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let tool_name = {
            let binding = self.resolve_skill_binding(skill_id)?;
            binding.tool_name
        };

        let arguments = extract_arguments_from_message(&request.message)?;
        let task_id = self.next_task_id();

        let invoke_result =
            match crate::block_on_tool_server_invoke(server.invoke(&tool_name, arguments, None)) {
                Ok(inner) => inner,
                Err(bridge_err) => {
                    // Fail-closed mirror of the kernel sync-bridge gate:
                    // current-thread runtime detected, refuse to deadlock.
                    let msg = bridge_err.to_string();
                    return Ok(TaskResponse {
                        id: task_id,
                        status: TaskStatus::Failed,
                        status_message: Some(msg.clone()),
                        message: None,
                        metadata: Some(passthrough_metadata(Some(&msg))),
                    });
                }
            };
        match invoke_result {
            Ok(result) => {
                let response_parts = result_to_parts(&result);
                Ok(TaskResponse {
                    id: task_id,
                    status: TaskStatus::Completed,
                    status_message: None,
                    message: Some(A2aMessage {
                        role: "agent".to_string(),
                        parts: response_parts,
                        metadata: None,
                    }),
                    metadata: Some(passthrough_metadata(None)),
                })
            }
            Err(error) => Ok(TaskResponse {
                id: task_id,
                status: TaskStatus::Failed,
                status_message: Some(error.to_string()),
                message: None,
                metadata: Some(passthrough_metadata(Some(&error.to_string()))),
            }),
        }
    }

    /// Handle a JSON-RPC A2A request through the Chio kernel.
    ///
    /// This is the receipt-bearing path for production deployments that have
    /// already authenticated the caller and resolved a capability token.
    pub fn handle_jsonrpc(
        &mut self,
        message: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> A2aJsonRpcResponse {
        let A2aJsonRpcEnvelope { id, method, params } =
            match Self::parse_jsonrpc_envelope(&message) {
                Ok(envelope) => envelope,
                Err(response) => return A2aJsonRpcResponse::from_optional(response),
            };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_supported_method(
            &id,
            &method,
            &params,
            &["message/send", "message/stream", "task/get", "task/cancel"],
        ) {
            return A2aJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "message/send" => self.handle_jsonrpc_send_message(id, params, kernel, execution),
            "message/stream" => self.handle_jsonrpc_stream_message(id, params, execution),
            "task/get" => self.handle_jsonrpc_task_get(id, params, kernel, execution),
            "task/cancel" => self.handle_jsonrpc_task_cancel(id, params, execution),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        A2aJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    /// Handle a JSON-RPC A2A request through the direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. Its result
    /// payload carries explicit passthrough metadata so it is not confused with
    /// the signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_passthrough(
        &mut self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> A2aJsonRpcResponse {
        let A2aJsonRpcEnvelope { id, method, params } =
            match Self::parse_jsonrpc_envelope(&message) {
                Ok(envelope) => envelope,
                Err(response) => return A2aJsonRpcResponse::from_optional(response),
            };
        let should_respond = id.is_some();
        let id = id.unwrap_or(Value::Null);
        if let Err(response) = Self::ensure_jsonrpc_params_object_for_supported_method(
            &id,
            &method,
            &params,
            &["message/send", "message/stream"],
        ) {
            return A2aJsonRpcResponse::from_optional(should_respond.then_some(response));
        }

        let response = match method.as_str() {
            "message/send" => self.handle_jsonrpc_send_message_passthrough(id, params, server),
            "message/stream" => self.jsonrpc_stream_not_supported(id),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        };
        A2aJsonRpcResponse::from_optional(should_respond.then_some(response))
    }

    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_send_message_passthrough(
        &mut self,
        id: Value,
        params: Value,
        server: &dyn ToolServerConnection,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_send_message_passthrough(&skill_id, &request, server) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_send_message(
        &mut self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_send_message(&skill_id, &request, kernel, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_stream_message(
        &mut self,
        id: Value,
        params: Value,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        let (skill_id, request) =
            match self.parse_jsonrpc_send_message_params(params, "SendStreamingMessage") {
                Ok(parsed) => parsed,
                Err(error) => return Self::jsonrpc_error_response(id, error),
            };

        match self.handle_stream_message(&skill_id, &request, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn handle_jsonrpc_task_get(
        &mut self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        self.prune_deferred_tasks();
        let task_id = match Self::parse_jsonrpc_task_id_params(&params, "task/get") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }

        match self.resolve_task(&task_id, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(A2aEdgeError::InvalidRequest(_)) if self.tasks.contains_key(&task_id) => {
                self.complete_task(&task_id, kernel, execution, id)
            }
            Err(error) => Self::jsonrpc_error_response(id, error),
        }
    }

    fn complete_task(
        &mut self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
        id: Value,
    ) -> Value {
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }
        let Some(task) = self.tasks.get(task_id).cloned() else {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::ToolNotFound(task_id.to_string()),
            );
        };
        if task.owner_agent_id != execution.agent_id {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest("task is not owned by the current agent".to_string()),
            );
        }
        if task.response.status != TaskStatus::Working {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
            });
        }

        let orchestrated = match execute_orchestrated_a2a_request(kernel, task.request) {
            Ok(orchestrated) => orchestrated,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        let response = task_response_from_orchestrated(task_id.to_string(), orchestrated);
        let response = match self.tasks.get_mut(task_id) {
            Some(task) if task.response.status == TaskStatus::Working => {
                task.response = response;
                task.response.clone()
            }
            Some(task) => task.response.clone(),
            None => {
                return Self::jsonrpc_error_response(
                    id,
                    A2aEdgeError::ToolNotFound(task_id.to_string()),
                );
            }
        };
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": serde_json::to_value(&response).unwrap_or(Value::Null)
        })
    }

    fn handle_jsonrpc_task_cancel(
        &mut self,
        id: Value,
        params: Value,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        self.prune_deferred_tasks();
        let task_id = match Self::parse_jsonrpc_task_id_params(&params, "task/cancel") {
            Ok(task_id) => task_id,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        if let Err(error) = validate_execution_context(execution) {
            return Self::jsonrpc_error_response(id, error);
        }

        let Some(task) = self.tasks.get_mut(&task_id) else {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::ToolNotFound(task_id.to_string()),
            );
        };
        if task.owner_agent_id != execution.agent_id {
            return Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest("task is not owned by the current agent".to_string()),
            );
        }
        match task.response.status {
            TaskStatus::Working => {
                task.response.status = TaskStatus::Cancelled;
                task.response.status_message = Some("Task cancelled by caller.".to_string());
                task.response.metadata = Some(cancelled_task_metadata(
                    "cross_protocol_orchestrator",
                    "deferred_task_poll",
                ));
                let response = task.response.clone();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": serde_json::to_value(&response).unwrap_or(Value::Null)
                })
            }
            TaskStatus::Cancelled => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
            }),
            status => Self::jsonrpc_error_response(
                id,
                A2aEdgeError::InvalidRequest(format!(
                    "cannot cancel task in terminal status `{status:?}`"
                )),
            ),
        }
    }

    fn resolve_task(
        &self,
        task_id: &str,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let task = self
            .tasks
            .get(task_id)
            .ok_or_else(|| A2aEdgeError::ToolNotFound(task_id.to_string()))?;
        if task.owner_agent_id != execution.agent_id {
            return Err(A2aEdgeError::InvalidRequest(
                "task is not owned by the current agent".to_string(),
            ));
        }
        match task.response.status {
            TaskStatus::Working => Err(A2aEdgeError::InvalidRequest(
                "task is pending deferred execution".to_string(),
            )),
            _ => Ok(task.response.clone()),
        }
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
impl ChioA2aEdgeCompatibility<'_> {
    /// Handle a SendMessage request through the explicit direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not mistake it for the
    /// signed-receipt authority path.
    pub fn handle_send_message_compatibility(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        self.edge
            .handle_send_message_passthrough(skill_id, request, server)
    }

    /// Handle a JSON-RPC A2A request through the direct passthrough path.
    ///
    /// This compatibility helper does not invoke the Chio kernel. Its result
    /// payload carries explicit passthrough metadata so it is not confused with
    /// the signed-receipt authority path.
    pub fn handle_jsonrpc_compatibility(
        &mut self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> A2aJsonRpcResponse {
        self.edge.handle_jsonrpc_passthrough(message, server)
    }

}
