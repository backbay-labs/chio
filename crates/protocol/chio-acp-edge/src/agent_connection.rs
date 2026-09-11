/// An ACP connection exposing one Chio tool as a bounded text-prompt agent.
///
/// Hosts own the stdio transport and authenticated execution context. Prompts
/// execute through the kernel. This connection advertises no filesystem,
/// terminal, MCP-server, session-load, or multimodal support.
pub struct AcpAgentConnection {
    edge: ChioAcpEdge,
    prompt_capability: String,
    prompt_argument: String,
    initialized: bool,
    sessions: BTreeMap<String, String>,
    prompt_counter: u64,
}

impl AcpAgentConnection {
    pub fn new(
        edge: ChioAcpEdge,
        prompt_capability: String,
        prompt_argument: String,
    ) -> Result<Self, AcpEdgeError> {
        if edge.capability(&prompt_capability).is_none() {
            return Err(AcpEdgeError::InvalidRequest(
                "Prompt capability is not advertised by this edge".into(),
            ));
        }
        if prompt_argument.is_empty()
            || prompt_argument.len() > 128
            || prompt_argument.chars().any(char::is_whitespace)
            || prompt_argument.chars().any(char::is_control)
        {
            return Err(AcpEdgeError::InvalidRequest(
                "Prompt argument must be a nonempty field name".into(),
            ));
        }
        Ok(Self {
            edge,
            prompt_capability,
            prompt_argument,
            initialized: false,
            sessions: BTreeMap::new(),
            prompt_counter: 0,
        })
    }

    /// Return ACP notifications followed by the correlated JSON-RPC response.
    /// This synchronous surface is intended for bounded blocking tools. A cancel
    /// arriving after a completed prompt has no active operation to interrupt.
    pub fn handle_jsonrpc(
        &mut self,
        message: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Vec<Value> {
        let envelope = match ChioAcpEdge::parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(response) => return response.into_iter().collect(),
        };
        let Some(id) = envelope.id else {
            return Vec::new();
        };
        let error = |code, reason: &str| {
            vec![ChioAcpEdge::jsonrpc_protocol_error_response(
                id.clone(),
                code,
                reason,
            )]
        };
        if id.is_null() || !envelope.params.is_object() {
            return error(-32600, "ACP requests require an ID and object parameters");
        }
        if let Err(reason) = validate_execution_context(execution) {
            return error(-32602, &reason.to_string());
        }
        let params = envelope.params;
        let result = |value: Value| vec![json!({"jsonrpc":"2.0", "id":id, "result":value})];
        match envelope.method.as_str() {
            "initialize" => {
                if self.initialized {
                    return error(-32600, "This connection is already initialized");
                }
                if params["protocolVersion"].as_u64().is_none() {
                    return error(-32602, "protocolVersion must be an unsigned integer");
                }
                self.initialized = true;
                result(json!({"protocolVersion":1, "agentCapabilities":{
                    "loadSession":false, "promptCapabilities":{"image":false,"audio":false,"embeddedContext":false},
                    "mcpCapabilities":{"http":false,"sse":false}}, "authMethods":[],
                    "agentInfo":{"name":"chio-tool-agent","version":env!("CARGO_PKG_VERSION")}}))
            }
            _ if !self.initialized => error(-32600, "Initialize the ACP connection first"),
            "session/new" => {
                if !params["cwd"]
                    .as_str()
                    .is_some_and(|cwd| std::path::Path::new(cwd).is_absolute())
                {
                    return error(-32602, "cwd must be an absolute path");
                }
                if !params["mcpServers"].as_array().is_some_and(Vec::is_empty) {
                    return error(
                        -32602,
                        "This agent does not accept client-supplied MCP servers",
                    );
                }
                if self.sessions.len() >= 64 {
                    return error(-32603, "This connection has reached its 64-session limit");
                }
                let session_id = format!(
                    "acp-{}",
                    chio_core::crypto::Keypair::generate().public_key().to_hex()
                );
                self.sessions
                    .insert(session_id.clone(), execution.agent_id.clone());
                result(json!({"sessionId":session_id}))
            }
            "session/prompt" => {
                let Some(session_id) = params["sessionId"].as_str() else {
                    return error(-32602, "sessionId is required");
                };
                if self.sessions.get(session_id) != Some(&execution.agent_id) {
                    return error(-32602, "Session not found for this caller");
                }
                let Some(parts) = params["prompt"]
                    .as_array()
                    .filter(|parts| !parts.is_empty())
                else {
                    return error(-32602, "prompt must contain at least one text block");
                };
                let mut text = String::new();
                for part in parts {
                    let Some(content) = part["text"].as_str().filter(|_| part["type"] == "text")
                    else {
                        return error(-32602, "Only text prompt blocks are supported");
                    };
                    let separator = usize::from(!text.is_empty());
                    if text.len() + separator > 65_536
                        || content.len() > 65_536_usize.saturating_sub(text.len() + separator)
                    {
                        return error(-32602, "Prompt exceeds 65536 UTF-8 bytes");
                    }
                    if separator != 0 {
                        text.push('\n');
                    }
                    text.push_str(content);
                }
                let Some(counter) = self.prompt_counter.checked_add(1) else {
                    return error(
                        -32603,
                        "Prompt identity space is exhausted; start a new connection",
                    );
                };
                self.prompt_counter = counter;
                // JSON-RPC IDs are correlation IDs and may be reused after a response.
                // Each new prompt therefore gets its own stable kernel operation ID.
                let request_id = format!("acp-prompt:{session_id}:{counter}");
                let arguments = json!({(self.prompt_argument.clone()):text});
                let invocation = match self.edge.invoke_with_request_id(
                    &request_id,
                    &self.prompt_capability,
                    arguments.clone(),
                    kernel,
                    execution,
                ) {
                    Ok(invocation) => invocation,
                    Err(reason) => return error(-32603, &reason.to_string()),
                };
                let metadata = invocation.metadata.unwrap_or_else(|| json!({}));
                let display = if invocation.success {
                    invocation.data.to_string()
                } else {
                    invocation
                        .error
                        .unwrap_or_else(|| "The tool did not complete".into())
                };
                vec![
                    json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":session_id,
                        "update":{"sessionUpdate":"tool_call","toolCallId":request_id,
                            "title":self.prompt_capability,"kind":"other",
                            "status":if invocation.success {"completed"} else {"failed"},
                            "rawInput":arguments,"rawOutput":invocation.data,"_meta":metadata}}}),
                    json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":session_id,
                        "update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":display}}}}),
                    json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":"end_turn","_meta":metadata}}),
                ]
            }
            _ => error(-32601, "Method not found"),
        }
    }
}
