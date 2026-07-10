use super::*;

impl ChioMcpEdge {
    pub fn create_message<R: BufRead + Send, W: Write + Send>(
        &mut self,
        parent_context: &OperationContext,
        operation: CreateMessageOperation,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<CreateMessageResult, AdapterError> {
        match &self.state {
            EdgeState::Ready { session_id } if session_id == &parent_context.session_id => {}
            _ => {
                return Err(AdapterError::NestedFlowDenied(
                    "sampling requires a ready MCP session".to_string(),
                ))
            }
        }

        let child_request_id = RequestId::new(self.next_request_id());
        let child_context = self
            .kernel
            .begin_child_request(
                parent_context,
                child_request_id,
                OperationKind::CreateMessage,
                None,
                true,
            )
            .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))?;

        let result = (|| {
            self.kernel
                .validate_sampling_request(&child_context, &operation)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))?;

            self.emit_log(
                LogLevel::Info,
                "chio.mcp.sampling",
                json!({
                    "event": "sampling_request_started",
                    "requestId": child_context.request_id.as_str(),
                    "parentRequestId": parent_context.request_id.as_str(),
                    "toolCount": operation.tools.len(),
                }),
            );

            let params = serde_json::to_value(&operation).map_err(|error| {
                AdapterError::ParseError(format!(
                    "failed to serialize sampling/createMessage params: {error}"
                ))
            })?;
            let result =
                self.send_client_request(reader, writer, "sampling/createMessage", params)?;
            let message: CreateMessageResult = serde_json::from_value(result).map_err(|error| {
                AdapterError::ParseError(format!(
                    "failed to parse sampling/createMessage result: {error}"
                ))
            })?;

            self.emit_log(
                LogLevel::Info,
                "chio.mcp.sampling",
                json!({
                    "event": "sampling_request_completed",
                    "requestId": child_context.request_id.as_str(),
                    "parentRequestId": parent_context.request_id.as_str(),
                    "model": message.model.clone(),
                    "stopReason": message.stop_reason.clone(),
                }),
            );

            Ok(message)
        })();

        self.kernel
            .complete_session_request(&child_context.session_id, &child_context.request_id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "failed to complete sampling child request {}: {error}",
                    child_context.request_id
                ))
            })?;

        result
    }

    pub(super) fn process_pending_actions_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        while let Some(action) = self.pending_actions.pop() {
            match action {
                EdgeAction::RefreshRoots { session_id, reason } => {
                    if let Err(error) =
                        self.refresh_roots_from_client_with_channel(&session_id, client_rx, writer)
                    {
                        self.emit_log(
                            LogLevel::Warning,
                            "chio.mcp.roots",
                            json!({
                                "event": "roots_refresh_failed",
                                "reason": reason,
                                "error": error.to_string(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub(super) fn queue_roots_refresh(&mut self, session_id: SessionId, reason: &'static str) {
        if self.pending_actions.iter().any(|action| {
            matches!(
                action,
                EdgeAction::RefreshRoots {
                    session_id: pending_session_id,
                    ..
                } if pending_session_id == &session_id
            )
        }) {
            return;
        }

        self.pending_actions
            .push(EdgeAction::RefreshRoots { session_id, reason });
    }

    pub(super) fn refresh_roots_from_client_with_channel<W: Write>(
        &mut self,
        session_id: &SessionId,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let result =
            self.send_client_request_with_channel(client_rx, writer, "roots/list", json!({}))?;
        let roots_value = result.get("roots").cloned().ok_or_else(|| {
            AdapterError::ParseError("roots/list response missing 'roots'".into())
        })?;
        let roots: Vec<RootDefinition> = serde_json::from_value(roots_value)
            .map_err(|error| AdapterError::ParseError(format!("failed to parse roots: {error}")))?;

        self.kernel
            .replace_session_roots(session_id, roots.clone())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to update session roots: {error}"))
            })?;

        self.emit_log(
            LogLevel::Info,
            "chio.mcp.roots",
            json!({
                "event": "roots_refreshed",
                "rootCount": roots.len(),
            }),
        );
        Ok(())
    }

    pub(super) fn send_client_request<R: BufRead + Send, W: Write + Send>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        method: &str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.client_request_counter += 1;
        let request_id = format!("edge-client-{}", self.client_request_counter);
        write_jsonrpc_line(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }),
        )?;

        loop {
            let message = read_jsonrpc_line(reader)?;
            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    return Err(adapter_jsonrpc_error(error));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(AdapterError::McpError {
                    code: -32800,
                    message: cancellation_reason(&message),
                    data: None,
                });
            }

            if message.get("method").is_some() {
                let response = self.handle_jsonrpc_with_transport(message, reader, writer);
                for notification in self.take_pending_notifications() {
                    write_jsonrpc_line(writer, &notification)?;
                }
                if let Some(response) = response {
                    write_jsonrpc_line(writer, &response)?;
                }
                continue;
            }

            return Err(AdapterError::ParseError(
                "outer MCP client sent an unexpected response while a child request was in flight"
                    .into(),
            ));
        }
    }

    pub(super) fn send_client_request_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        writer: &mut W,
        method: &str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.client_request_counter += 1;
        let request_id = format!("edge-client-{}", self.client_request_counter);
        write_jsonrpc_line(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }),
        )?;

        loop {
            let message = next_client_message(client_rx)?;
            if message.get("id") == Some(&Value::String(request_id.clone()))
                && message.get("method").is_none()
            {
                if let Some(error) = message.get("error") {
                    return Err(adapter_jsonrpc_error(error));
                }

                return message.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }

            if cancellation_matches_request(&message, &request_id) {
                return Err(AdapterError::McpError {
                    code: -32800,
                    message: cancellation_reason(&message),
                    data: None,
                });
            }

            if message.get("method").is_some() {
                self.deferred_client_messages.push(message);
                continue;
            }

            return Err(AdapterError::ParseError(
                "outer MCP client sent an unexpected response while a child request was in flight"
                    .into(),
            ));
        }
    }

    pub(super) fn next_request_id(&mut self) -> String {
        self.request_counter += 1;
        format!("mcp-edge-req-{}", self.request_counter)
    }

    pub(super) fn visible_tools(&self) -> Vec<&ExposedToolBinding> {
        self.tools
            .iter()
            .filter(|binding| tool_is_authorized(&self.capabilities, binding))
            .collect()
    }

    pub(super) fn ready_session_id(&self, id: &Value) -> Result<SessionId, Value> {
        match &self.state {
            EdgeState::Ready { session_id } => Ok(session_id.clone()),
            _ => Err(jsonrpc_error(
                id.clone(),
                JSONRPC_SERVER_NOT_INITIALIZED,
                "operation requires initialize followed by notifications/initialized",
            )),
        }
    }

    pub(super) fn has_completion_support(&self) -> bool {
        self.config.completion_enabled.unwrap_or_else(|| {
            self.kernel.resource_provider_count() > 0 || self.kernel.prompt_provider_count() > 0
        })
    }

    pub(super) fn peer_supports_chio_tool_streaming(&self, session_id: &SessionId) -> bool {
        self.kernel
            .session(session_id)
            .map(|session| session.peer_capabilities().supports_chio_tool_streaming)
            .unwrap_or(false)
    }

    pub(super) fn emit_log(&mut self, level: LogLevel, logger: &str, data: Value) {
        self.emit_log_with_related_task(level, logger, data, None);
    }

    pub(super) fn emit_log_with_related_task(
        &mut self,
        level: LogLevel,
        logger: &str,
        data: Value,
        related_task_id: Option<&str>,
    ) {
        if !self.config.logging_enabled || level < self.minimum_log_level {
            return;
        }

        self.pending_notifications
            .push(attach_related_task_meta_to_message(
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": level.as_str(),
                        "logger": logger,
                        "data": data,
                    }
                }),
                related_task_id,
            ));
    }

    pub(super) fn current_ready_session_id(&self) -> Option<SessionId> {
        match &self.state {
            EdgeState::Ready { session_id } => Some(session_id.clone()),
            _ => None,
        }
    }

    pub(super) fn queue_session_tool_server_event(&mut self, event: ToolServerEvent) {
        let Some(session_id) = self.current_ready_session_id() else {
            return;
        };
        if let Err(error) = self
            .kernel
            .queue_session_tool_server_event(&session_id, event)
        {
            self.emit_log(
                LogLevel::Warning,
                "chio.mcp.runtime",
                json!({
                    "event": "session_late_event_queue_failed",
                    "error": error.to_string(),
                }),
            );
            return;
        }
        self.flush_session_late_events(&session_id);
    }

    pub(super) fn flush_session_late_events(&mut self, session_id: &SessionId) {
        let late_events = match self.kernel.drain_session_late_events(session_id) {
            Ok(late_events) => late_events,
            Err(error) => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.runtime",
                    json!({
                        "event": "session_late_event_drain_failed",
                        "error": error.to_string(),
                    }),
                );
                return;
            }
        };

        for event in late_events {
            match event {
                LateSessionEvent::ElicitationCompleted {
                    elicitation_id,
                    related_task_id,
                } => self
                    .pending_notifications
                    .push(make_elicitation_completion_notification(
                        &elicitation_id,
                        related_task_id.as_deref(),
                    )),
                LateSessionEvent::ResourceUpdated { uri } => {
                    if self.config.resources_subscribe {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/updated",
                            "params": {
                                "uri": uri,
                            }
                        }));
                    }
                }
                LateSessionEvent::ResourcesListChanged => {
                    if self.config.resources_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/list_changed",
                        }));
                    }
                }
                LateSessionEvent::ToolsListChanged => {
                    if self.config.tools_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/tools/list_changed",
                        }));
                    }
                }
                LateSessionEvent::PromptsListChanged => {
                    if self.config.prompts_list_changed {
                        self.pending_notifications.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/prompts/list_changed",
                        }));
                    }
                }
            }
        }
    }

    pub fn notify_resource_updated(&mut self, uri: &str) {
        self.queue_session_tool_server_event(ToolServerEvent::ResourceUpdated {
            uri: uri.to_string(),
        });
    }

    pub fn notify_resources_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::ResourcesListChanged);
    }

    pub fn notify_tools_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::ToolsListChanged);
    }

    pub fn notify_prompts_list_changed(&mut self) {
        self.queue_session_tool_server_event(ToolServerEvent::PromptsListChanged);
    }

    pub fn notify_elicitation_completed(&mut self, elicitation_id: &str) {
        self.queue_session_tool_server_event(ToolServerEvent::ElicitationCompleted {
            elicitation_id: elicitation_id.to_string(),
        });
    }

    pub(super) fn take_deferred_client_message(&mut self) -> Option<Value> {
        if self.deferred_client_messages.is_empty() {
            None
        } else {
            Some(self.deferred_client_messages.remove(0))
        }
    }

    pub(super) fn take_pending_notifications(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending_notifications)
    }

    pub(super) fn flush_pending_notifications<W: Write>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        for notification in self.take_pending_notifications() {
            write_jsonrpc_line(writer, &notification)?;
        }
        Ok(())
    }

    pub(super) fn forward_tool_server_events(&mut self) {
        let Some(session_id) = self.current_ready_session_id() else {
            return;
        };
        if let Err(error) = self.kernel.queue_session_tool_server_events(&session_id) {
            self.emit_log(
                LogLevel::Warning,
                "chio.mcp.runtime",
                json!({
                    "event": "tool_server_event_queue_failed",
                    "error": error.to_string(),
                }),
            );
            return;
        }
        self.flush_session_late_events(&session_id);
    }

    pub(super) fn forward_runtime_events(&mut self) {
        self.forward_tool_server_events();
        self.forward_upstream_notifications();
    }

    pub(super) fn forward_upstream_notifications(&mut self) {
        let Some(transport) = self.upstream_transport.as_ref() else {
            return;
        };

        for notification in transport.drain_notifications() {
            self.handle_upstream_transport_notification(notification);
        }
    }

    pub(super) fn handle_upstream_transport_notification(&mut self, notification: Value) {
        match notification.get("method").and_then(Value::as_str) {
            Some("notifications/resources/updated") => {
                if let Some(uri) = notification
                    .get("params")
                    .and_then(|params| params.get("uri"))
                    .and_then(Value::as_str)
                {
                    self.queue_session_tool_server_event(ToolServerEvent::ResourceUpdated {
                        uri: uri.to_string(),
                    });
                } else {
                    self.emit_log(
                        LogLevel::Warning,
                        "chio.mcp.resources",
                        json!({
                            "event": "wrapped_resource_notification_invalid",
                            "notification": notification,
                        }),
                    );
                }
            }
            Some("notifications/resources/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::ResourcesListChanged)
            }
            Some("notifications/tools/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::ToolsListChanged)
            }
            Some("notifications/prompts/list_changed") => {
                self.queue_session_tool_server_event(ToolServerEvent::PromptsListChanged)
            }
            Some("notifications/elicitation/complete") => {
                if let Some(elicitation_id) = notification
                    .get("params")
                    .and_then(|params| params.get("elicitationId"))
                    .and_then(Value::as_str)
                {
                    self.queue_session_tool_server_event(ToolServerEvent::ElicitationCompleted {
                        elicitation_id: elicitation_id.to_string(),
                    });
                } else {
                    self.emit_log(
                        LogLevel::Warning,
                        "chio.mcp.elicitation",
                        json!({
                            "event": "wrapped_elicitation_completion_invalid",
                            "notification": notification,
                        }),
                    );
                }
            }
            Some(method) => {
                self.emit_log(
                    LogLevel::Debug,
                    "chio.mcp.upstream",
                    json!({
                        "event": "wrapped_notification_ignored",
                        "method": method,
                    }),
                );
            }
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.upstream",
                    json!({
                        "event": "wrapped_notification_invalid",
                    }),
                );
            }
        }
    }
}
