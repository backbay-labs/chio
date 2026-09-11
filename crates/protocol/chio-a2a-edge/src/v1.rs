// A2A 1.0 protobuf JSON binding. The legacy tool-shaped API remains separate.

struct A2aV1Task {
    owner: String,
    message_id: String,
    request: Value,
    task: Value,
    expires_at_ms: u64,
}

fn v1_identifier(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        !text.is_empty()
            && text.len() <= 256
            && text.trim() == *text
            && !text.chars().any(char::is_control)
    })
}

impl ChioA2aEdge {
    /// Publish an A2A 1.0 Agent Card without private wire-type extensions.
    /// This binding serves blocking messages and retained task lookup.
    pub fn agent_card_v1(&self) -> Value {
        json!({
            "name": self.config.agent_name, "description": self.config.agent_description,
            "version": self.config.agent_version,
            "supportedInterfaces": [{"url": self.config.endpoint_url,
                "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "capabilities": {"streaming": false, "pushNotifications": false},
            "defaultInputModes": ["application/json"],
            "defaultOutputModes": ["application/json", "text/plain"],
            "skills": self.skills.iter().map(|skill| json!({
                "id": skill.id, "name": skill.name, "description": skill.description,
                "tags": skill.tags,
                "inputModes": ["application/json"],
                "outputModes": ["application/json", "text/plain"]
            })).collect::<Vec<_>>()
        })
    }

    /// Execute official A2A 1.0 JSON-RPC through the same kernel authority path.
    /// The caller must authenticate the connection and supply its execution context.
    /// Task lookup is owner-scoped, bounded to 128 records and retained for five minutes.
    /// Receipts remain in the kernel's configured durable receipt store.
    pub fn handle_v1_jsonrpc(
        &mut self,
        message: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> A2aJsonRpcResponse {
        let envelope = match Self::parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(response) => return A2aJsonRpcResponse::from_optional(response),
        };
        let Some(id) = envelope.id else {
            return A2aJsonRpcResponse::notification();
        };
        let error = |code, reason: &str| {
            A2aJsonRpcResponse::response(Self::jsonrpc_error_payload(id.clone(), code, reason))
        };
        if id.is_null() || !envelope.params.is_object() {
            return error(
                -32600,
                "A2A requires a request ID and an object of parameters",
            );
        }
        if let Err(reason) = validate_execution_context(execution) {
            return error(-32602, &reason.to_string());
        }
        self.v1_tasks
            .retain(|_, task| task.expires_at_ms > unix_now_millis());
        let params = envelope.params;
        match envelope.method.as_str() {
            "GetTask" | "CancelTask" => {
                let Some(task_id) = v1_identifier(&params["id"]) else {
                    return error(-32602, "id must be a nonempty task identifier");
                };
                let Some(task) = self
                    .v1_tasks
                    .get(task_id)
                    .filter(|task| task.owner == execution.agent_id)
                else {
                    return error(-32001, "Task not found");
                };
                if envelope.method == "CancelTask" {
                    return error(
                        -32002,
                        "The blocking task has already reached its terminal outcome",
                    );
                }
                A2aJsonRpcResponse::response(json!({"jsonrpc":"2.0", "id":id, "result":task.task}))
            }
            "SendMessage" => {
                let incoming = &params["message"];
                let Some(message_id) = v1_identifier(&incoming["messageId"]) else {
                    return error(-32602, "message.messageId must be a nonempty identifier");
                };
                if incoming["role"] != "ROLE_USER" && incoming["role"] != 1 {
                    return error(-32602, "message.role must be ROLE_USER");
                }
                if incoming.get("taskId").is_some_and(|value| value != "") {
                    return error(
                        -32004,
                        "This tool agent accepts new tasks, not task continuations",
                    );
                }
                if params["configuration"]["returnImmediately"] == true {
                    return error(
                        -32004,
                        "This binding completes SendMessage before returning",
                    );
                }
                if params["configuration"]
                    .get("taskPushNotificationConfig")
                    .is_some()
                {
                    return error(-32003, "Push notifications are not supported");
                }
                if params.to_string().len() > 65_536 {
                    return error(-32602, "Message exceeds 65536 encoded bytes");
                }
                // An identical message retry returns its own original result. A changed
                // payload under that message ID must never dispatch or consume budget.
                if let Some(task) = self
                    .v1_tasks
                    .values()
                    .find(|task| task.owner == execution.agent_id && task.message_id == message_id)
                {
                    if task.request != params {
                        return error(
                            -32602,
                            "messageId was already used for different parameters",
                        );
                    }
                    return A2aJsonRpcResponse::response(json!({"jsonrpc":"2.0", "id":id,
                        "result":{"task":task.task}}));
                }
                if self.v1_tasks.len() >= 128 {
                    return error(
                        -32004,
                        "Task retention is full; wait for retained tasks to expire",
                    );
                }
                let context_id = match incoming.get("contextId") {
                    Some(value) if value != "" => match v1_identifier(value) {
                        Some(value) => value.to_string(),
                        None => return error(-32602, "contextId is invalid"),
                    },
                    _ => format!("a2a-context-{message_id}"),
                };
                let Some(parts) = incoming["parts"]
                    .as_array()
                    .filter(|parts| !parts.is_empty())
                else {
                    return error(-32602, "message.parts must contain text or structured data");
                };
                let mut converted = Vec::with_capacity(parts.len());
                for part in parts {
                    match (part.get("text"), part.get("data")) {
                        (Some(Value::String(text)), None)
                            if part.get("raw").is_none() && part.get("url").is_none() =>
                        {
                            converted.push(A2aPart::Text { text: text.clone() })
                        }
                        (None, Some(data))
                            if data.is_object()
                                && part.get("raw").is_none()
                                && part.get("url").is_none() =>
                        {
                            converted.push(A2aPart::Data { data: data.clone() })
                        }
                        _ => {
                            return error(
                                -32005,
                                "Each part must contain only text or an object-valued data payload",
                            )
                        }
                    }
                }
                let skill = match self.resolve_jsonrpc_target_skill_id(&params) {
                    Ok(skill) => skill,
                    Err(reason) => return error(-32602, &reason.to_string()),
                };
                let request = SendMessageRequest {
                    message: A2aMessage {
                        role: "user".into(),
                        parts: converted,
                        metadata: incoming.get("metadata").cloned(),
                    },
                    metadata: params.get("metadata").cloned(),
                };
                let request_id = format!("a2a-message:{}:{message_id}", execution.agent_id);
                let result = match self.handle_send_message_with_request_id(
                    &request_id,
                    &skill,
                    &request,
                    kernel,
                    execution,
                ) {
                    Ok(result) => result,
                    Err(reason) => return error(-32603, &reason.to_string()),
                };
                let state = match result.status {
                    TaskStatus::Completed => "TASK_STATE_COMPLETED",
                    TaskStatus::Failed => "TASK_STATE_FAILED",
                    TaskStatus::Cancelled => "TASK_STATE_CANCELED",
                    TaskStatus::Working => "TASK_STATE_INPUT_REQUIRED",
                };
                let mut task = json!({"id":result.id, "contextId":context_id,
                    "status":{"state":state}, "metadata":result.metadata.unwrap_or_else(|| json!({}))});
                if let Some(reason) = result.status_message {
                    task["status"]["message"] = json!({"messageId":format!("{}-status",result.id),
                        "contextId":context_id, "taskId":result.id,
                        "role":"ROLE_AGENT", "parts":[{"text":reason}]});
                }
                if let Some(output) = result.message {
                    let parts: Vec<Value> = output
                        .parts
                        .into_iter()
                        .map(|part| match part {
                            A2aPart::Text { text } => json!({"text":text}),
                            A2aPart::Data { data } => json!({"data":data}),
                        })
                        .collect();
                    task["artifacts"] = json!([{"artifactId":format!("{}-output",result.id),
                        "name":"Tool result", "parts":parts}]);
                }
                self.v1_tasks.insert(
                    result.id,
                    A2aV1Task {
                        owner: execution.agent_id.clone(),
                        message_id: message_id.to_string(),
                        request: params,
                        task: task.clone(),
                        expires_at_ms: unix_now_millis().saturating_add(300_000),
                    },
                );
                A2aJsonRpcResponse::response(
                    json!({"jsonrpc":"2.0", "id":id, "result":{"task":task}}),
                )
            }
            "SendStreamingMessage" => error(-32004, "Streaming is not advertised by this binding"),
            _ => error(-32601, "Method not found"),
        }
    }
}
