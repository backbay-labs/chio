use super::*;

impl ChioMcpEdge {
    pub(super) fn handle_request(&mut self, id: Value, method: &str, params: Value) -> Value {
        match method {
            "initialize" => self.handle_initialize(id, params),
            "ping" => jsonrpc_result(id, json!({})),
            "tools/list" => self.handle_tools_list(id, params),
            "tools/call" => self.handle_tools_call(id, params),
            "tasks/list" => self.handle_tasks_list(id, params),
            "tasks/get" => self.handle_tasks_get(id, params),
            "tasks/result" => self.handle_tasks_result(id, params),
            "tasks/cancel" => self.handle_tasks_cancel(id, params),
            "resources/list" => self.handle_resources_list(id, params),
            "resources/read" => self.handle_resources_read(id, params),
            "resources/subscribe" => self.handle_resources_subscribe(id, params),
            "resources/unsubscribe" => self.handle_resources_unsubscribe(id, params),
            "resources/templates/list" => self.handle_resource_templates_list(id, params),
            "prompts/list" => self.handle_prompts_list(id, params),
            "prompts/get" => self.handle_prompts_get(id, params),
            "completion/complete" => self.handle_completion(id, params),
            "logging/setLevel" => self.handle_logging_set_level(id, params),
            _ => jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found"),
        }
    }

    // Reader/writer transport variant dispatched from `handle_jsonrpc_with_transport`.
    pub(super) fn handle_request_with_transport<R: BufRead + Send, W: Write + Send>(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        match method {
            "tools/call" => self.handle_tools_call_with_transport(id, params, reader, writer),
            "tasks/result" => self.handle_tasks_result_with_transport(id, params, reader, writer),
            _ => self.handle_request(id, method, params),
        }
    }

    pub(super) fn handle_request_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        match method {
            "tools/call" => self
                .handle_tools_call_with_transport_channel(id, params, client_rx, cancel_rx, writer),
            "tasks/result" => self.handle_tasks_result_with_transport_channel(
                id, params, client_rx, cancel_rx, writer,
            ),
            _ => self.handle_request(id, method, params),
        }
    }

    pub(super) fn handle_known_notification(
        &mut self,
        method: &str,
        params: Value,
    ) -> Option<Value> {
        if !known_notification_params_are_object(method, &params) {
            return None;
        }

        self.handle_notification(method, params)
    }

    pub(super) fn handle_notification(&mut self, method: &str, _params: Value) -> Option<Value> {
        match method {
            "notifications/initialized" => {
                let session_id = match &self.state {
                    EdgeState::WaitingForInitialized { session_id } => session_id.clone(),
                    _ => return None,
                };
                if let Err(error) = self.kernel.activate_session(&session_id) {
                    return Some(jsonrpc_error(
                        Value::Null,
                        JSONRPC_INTERNAL_ERROR,
                        &format!("failed to activate session: {error}"),
                    ));
                }
                self.state = EdgeState::Ready {
                    session_id: session_id.clone(),
                };
                if self
                    .kernel
                    .session(&session_id)
                    .is_some_and(|session| session.peer_capabilities().supports_roots)
                {
                    self.queue_roots_refresh(session_id, "initialized");
                }
                None
            }
            "notifications/roots/list_changed" => {
                if let EdgeState::Ready { session_id } = &self.state {
                    if self.kernel.session(session_id).is_some_and(|session| {
                        session.peer_capabilities().supports_roots
                            && session.peer_capabilities().roots_list_changed
                    }) {
                        self.queue_roots_refresh(session_id.clone(), "list_changed");
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub(super) fn handle_initialize(&mut self, id: Value, params: Value) -> Value {
        if !matches!(self.state, EdgeState::Uninitialized) {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_REQUEST,
                "initialize may only be called once",
            );
        }
        let selected_protocol_version = match negotiate_protocol_version(&id, &params) {
            Ok(version) => version,
            Err(error) => return error,
        };

        let session_id = match self
            .kernel
            .open_session(self.agent_id.clone(), self.capabilities.clone())
        {
            Ok(session_id) => session_id,
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to open session: {error}"),
                );
            }
        };
        if let Err(error) = self
            .kernel
            .set_session_auth_context(&session_id, self.session_auth_context.clone())
        {
            return jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to persist session auth context: {error}"),
            );
        }
        let peer_capabilities = parse_peer_capabilities(&params);
        if let Err(error) = self
            .kernel
            .set_session_peer_capabilities(&session_id, peer_capabilities)
        {
            return jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to persist peer capabilities: {error}"),
            );
        }
        self.state = EdgeState::WaitingForInitialized { session_id };

        let mut capabilities = serde_json::Map::new();
        capabilities.insert(
            "tools".to_string(),
            json!({
                "listChanged": self.config.tools_list_changed
            }),
        );
        if self.kernel.resource_provider_count() > 0 {
            capabilities.insert(
                "resources".to_string(),
                json!({
                    "subscribe": self.config.resources_subscribe,
                    "listChanged": self.config.resources_list_changed,
                }),
            );
        }
        if self.kernel.prompt_provider_count() > 0 {
            capabilities.insert(
                "prompts".to_string(),
                json!({
                    "listChanged": self.config.prompts_list_changed,
                }),
            );
        }
        if self.has_completion_support() {
            capabilities.insert("completions".to_string(), json!({}));
        }
        if self.config.logging_enabled {
            capabilities.insert("logging".to_string(), json!({}));
        }
        let mut experimental = serde_json::Map::new();
        experimental.insert(
            CHIO_TOOL_STREAMING_CAPABILITY_KEY.to_string(),
            json!({
                "toolCallChunkNotifications": true,
            }),
        );
        experimental.insert(
            CHIO_PROTOCOL_CAPABILITY_KEY.to_string(),
            json!({
                "supportedProtocolVersions": SUPPORTED_MCP_PROTOCOL_VERSIONS,
                "selectedProtocolVersion": selected_protocol_version,
                "compatibility": "exact_match",
                "downgradeBehavior": "reject",
                "errorRegistry": {
                    "schema": CHIO_ERROR_REGISTRY_SCHEMA,
                    "path": "spec/errors/chio-error-registry.v1.json",
                }
            }),
        );
        capabilities.insert("experimental".to_string(), Value::Object(experimental));
        capabilities.insert(
            "tasks".to_string(),
            json!({
                "list": {},
                "cancel": {},
                "requests": {
                    "tools": {
                        "call": {},
                    }
                }
            }),
        );

        jsonrpc_result(
            id,
            json!({
                "protocolVersion": selected_protocol_version,
                "capabilities": Value::Object(capabilities),
                "serverInfo": {
                    "name": self.config.server_name,
                    "version": self.config.server_version,
                }
            }),
        )
    }

    pub(super) fn handle_tools_list(&mut self, id: Value, params: Value) -> Value {
        if !matches!(self.state, EdgeState::Ready { .. }) {
            return jsonrpc_error(
                id,
                JSONRPC_SERVER_NOT_INITIALIZED,
                "tools/list requires initialize followed by notifications/initialized",
            );
        }

        let cursor = match params.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor)) => Some(cursor.clone()),
            Some(_) => {
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor must be a string");
            }
        };

        let start = match cursor.as_deref() {
            None => 0,
            Some(cursor) => match cursor.parse::<usize>() {
                Ok(parsed) => parsed,
                Err(_) => {
                    return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor must be numeric")
                }
            },
        };

        let visible_tools = self.visible_tools();
        if start > visible_tools.len() {
            return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
        }

        let page_size = self.config.page_size.max(1);
        let end = (start + page_size).min(visible_tools.len());
        let next_cursor = (end < visible_tools.len()).then(|| end.to_string());
        let tools = visible_tools[start..end]
            .iter()
            .map(|binding| serde_json::to_value(&binding.tool).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        jsonrpc_result(
            id,
            json!({
                "tools": tools,
                "nextCursor": next_cursor,
            }),
        )
    }

    pub(super) fn handle_resources_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResources)
        {
            Ok(SessionOperationResponse::ResourceList { resources }) => resources,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list resources: {error}"),
                )
            }
        };

        paginate_response(
            id,
            start,
            self.config.page_size,
            serialize_resources(response),
        )
    }

    pub(super) fn handle_resource_templates_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResourceTemplates)
        {
            Ok(SessionOperationResponse::ResourceTemplateList { templates }) => templates,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list resource templates: {error}"),
                )
            }
        };

        paginate_named_response(
            id,
            start,
            self.config.page_size,
            "resourceTemplates",
            serialize_resource_templates(response),
        )
    }

    pub(super) fn handle_resources_read(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "resources/read requires a uri")
            }
        };

        let capability = match select_capability_for_resource(&self.capabilities, &uri) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.resources",
                    json!({
                        "event": "resource_denied",
                        "uri": uri,
                    }),
                );
                return jsonrpc_error(id, -32002, "Resource not found");
            }
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::ReadResource(ReadResourceOperation { capability, uri });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::ResourceRead { contents }) => jsonrpc_result(
                id,
                json!({
                    "contents": serialize_resource_contents(contents),
                }),
            ),
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => {
                let reason = match &receipt.decision {
                    Some(Decision::Deny { reason, .. }) => reason.clone(),
                    _ => "filesystem-backed resource read denied".to_string(),
                };
                let uri = receipt
                    .action
                    .parameters
                    .get("uri")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.resources",
                    json!({
                        "event": "resource_root_denied",
                        "uri": uri,
                        "reason": reason,
                    }),
                );
                jsonrpc_error_with_data(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!("resource read denied: {reason}"),
                    Some(json!({
                        "receipt": receipt,
                    })),
                )
            }
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => match error {
                chio_kernel::KernelError::OutOfScopeResource { .. }
                | chio_kernel::KernelError::ResourceNotRegistered(_) => {
                    jsonrpc_error(id, -32002, "Resource not found")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to read resource: {error}"),
                ),
            },
        }
    }

    pub(super) fn handle_resources_subscribe(&mut self, id: Value, params: Value) -> Value {
        if !self.config.resources_subscribe {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "resources/subscribe requires a uri",
                )
            }
        };

        let capability = match select_capability_for_resource_subscription(&self.capabilities, &uri)
        {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.resources",
                    json!({
                        "event": "resource_subscription_denied",
                        "uri": uri,
                    }),
                );
                return jsonrpc_error(id, -32002, "Resource not found");
            }
        };

        match self
            .kernel
            .subscribe_session_resource(&session_id, &capability, &self.agent_id, &uri)
        {
            Ok(()) => jsonrpc_result(id, json!({})),
            Err(error) => match error {
                chio_kernel::KernelError::OutOfScopeResource { .. }
                | chio_kernel::KernelError::ResourceNotRegistered(_) => {
                    jsonrpc_error(id, -32002, "Resource not found")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to subscribe to resource: {error}"),
                ),
            },
        }
    }

    pub(super) fn handle_resources_unsubscribe(&mut self, id: Value, params: Value) -> Value {
        if !self.config.resources_subscribe {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "resources/unsubscribe requires a uri",
                )
            }
        };

        match self.kernel.unsubscribe_session_resource(&session_id, &uri) {
            Ok(()) => jsonrpc_result(id, json!({})),
            Err(error) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to unsubscribe from resource: {error}"),
            ),
        }
    }

    pub(super) fn handle_prompts_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let response = match self
            .kernel
            .evaluate_session_operation(&context, &SessionOperation::ListPrompts)
        {
            Ok(SessionOperationResponse::PromptList { prompts }) => prompts,
            Ok(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "unexpected kernel response type",
                )
            }
            Err(error) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to list prompts: {error}"),
                )
            }
        };

        paginate_named_response(
            id,
            start,
            self.config.page_size,
            "prompts",
            serialize_prompts(response),
        )
    }

    pub(super) fn handle_prompts_get(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let prompt_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name.to_string(),
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "prompts/get requires a prompt name",
                )
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let capability = match select_capability_for_prompt(&self.capabilities, &prompt_name) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.prompts",
                    json!({
                        "event": "prompt_denied",
                        "prompt": prompt_name,
                    }),
                );
                return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "unknown prompt");
            }
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::GetPrompt(GetPromptOperation {
            capability,
            prompt_name,
            arguments,
        });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::PromptGet { prompt }) => jsonrpc_result(
                id,
                serde_json::to_value(prompt).unwrap_or_else(|_| json!({})),
            ),
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => match error {
                chio_kernel::KernelError::OutOfScopePrompt { .. }
                | chio_kernel::KernelError::PromptNotRegistered(_) => {
                    jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "unknown prompt")
                }
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    &format!("failed to get prompt: {error}"),
                ),
            },
        }
    }

    pub(super) fn handle_completion(&mut self, id: Value, params: Value) -> Value {
        if !self.has_completion_support() {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };

        let reference = match parse_completion_reference(&params) {
            Ok(reference) => reference,
            Err(response) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, &response),
        };
        let argument = match parse_completion_argument(&params) {
            Ok(argument) => argument,
            Err(response) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, &response),
        };
        let context_arguments = params
            .get("context")
            .and_then(|context| context.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let capability = match &reference {
            CompletionReference::Prompt { name } => {
                select_capability_for_prompt(&self.capabilities, name)
            }
            CompletionReference::Resource { uri } => {
                select_capability_for_resource_pattern(&self.capabilities, uri)
            }
        };
        let Some(capability) = capability else {
            self.emit_log(
                LogLevel::Warning,
                "chio.mcp.completion",
                json!({
                    "event": "completion_denied",
                    "reference": &reference,
                    "argument": &argument.name,
                }),
            );
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "completion target is not authorized",
            );
        };

        let request_id = self.next_request_id();
        let context =
            match build_operation_context(&id, session_id, request_id, &self.agent_id, &params) {
                Ok(context) => context,
                Err(response) => return response,
            };
        let operation = SessionOperation::Complete(CompleteOperation {
            capability,
            reference,
            argument,
            context_arguments,
        });

        match self.kernel.evaluate_session_operation(&context, &operation) {
            Ok(SessionOperationResponse::Completion { completion }) => jsonrpc_result(
                id,
                json!({
                    "completion": serde_json::to_value(completion).unwrap_or_else(|_| json!({})),
                }),
            ),
            Ok(_) => jsonrpc_error(
                id,
                JSONRPC_INTERNAL_ERROR,
                "unexpected kernel response type",
            ),
            Err(error) => {
                self.emit_log(
                    LogLevel::Error,
                    "chio.mcp.completion",
                    json!({
                        "event": "completion_failed",
                        "error": error.to_string(),
                    }),
                );
                match error {
                    chio_kernel::KernelError::OutOfScopePrompt { .. }
                    | chio_kernel::KernelError::OutOfScopeResource { .. }
                    | chio_kernel::KernelError::PromptNotRegistered(_)
                    | chio_kernel::KernelError::ResourceNotRegistered(_) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "completion target not found")
                    }
                    _ => jsonrpc_error(
                        id,
                        JSONRPC_INTERNAL_ERROR,
                        &format!("failed to complete argument: {error}"),
                    ),
                }
            }
        }
    }

    pub(super) fn handle_logging_set_level(&mut self, id: Value, params: Value) -> Value {
        if !self.config.logging_enabled {
            return jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, "method not found");
        }

        let level = match params.get("level").and_then(Value::as_str) {
            Some(level) => match LogLevel::parse(level) {
                Some(level) => level,
                None => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "invalid log level"),
            },
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "logging/setLevel requires a level",
                )
            }
        };

        self.minimum_log_level = level;
        self.emit_log(
            LogLevel::Info,
            "chio.mcp.logging",
            json!({
                "event": "log_level_updated",
                "level": level.as_str(),
            }),
        );
        jsonrpc_result(id, json!({}))
    }
}
