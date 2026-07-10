use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};

use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition,
};
use chio_kernel::NestedFlowBridge;
use serde_json::json;
use tracing::{debug, warn};

use crate::edge::{AdapterError, McpServerCapabilities, McpToolInfo, McpToolResult, McpTransport};

use super::handlers::{
    forward_upstream_notification, respond_to_upstream_nested_flow,
    respond_to_upstream_roots_without_bridge, service_active_request_runtime,
};
use super::nested_flow::NestedFlowTaskRuntime;
use super::utils::{
    adapter_jsonrpc_error, is_nested_flow_notification, proxy_client_capabilities, read_line,
    remove_chio_auth_env, send_line, MAX_STDIO_MCP_BUFFERED_MESSAGES, MCP_PROTOCOL_VERSION,
    UPSTREAM_REQUEST_POLL_INTERVAL,
};

struct TransportInner {
    child: Child,
    writer: std::process::ChildStdin,
    next_id: u64,
}

enum RequestMessage {
    Message(serde_json::Value),
    ReadError(String),
}

/// Spawns an MCP server as a subprocess and communicates via stdio.
///
/// MCP uses newline-delimited JSON-RPC over stdin/stdout. Each message is a
/// single JSON object terminated by `\n`. The transport handles the
/// `initialize` handshake automatically on construction.
///
/// The child process is killed on drop if it is still running.
pub struct StdioMcpTransport {
    inner: Mutex<TransportInner>,
    active_request: Arc<Mutex<Option<mpsc::SyncSender<RequestMessage>>>>,
    notification_tx: mpsc::SyncSender<serde_json::Value>,
    notification_rx: Mutex<mpsc::Receiver<serde_json::Value>>,
    capabilities: McpServerCapabilities,
}

impl StdioMcpTransport {
    /// Spawn the MCP server subprocess and perform the initialize handshake.
    ///
    /// `command` is the binary to run (e.g. `"npx"`, `"python"`).
    /// `args` are passed as command-line arguments.
    pub fn spawn(command: &str, args: &[&str]) -> Result<Self, AdapterError> {
        let mut child_command = Command::new(command);
        child_command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        remove_chio_auth_env(&mut child_command);

        let mut child = child_command.spawn().map_err(|e| {
            AdapterError::ConnectionFailed(format!("failed to spawn {command}: {e}"))
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdout not captured".into()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdin not captured".into()))?;

        // Spawn a thread to drain stderr so the child never blocks on a full
        // stderr pipe. We log lines at warn level.
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    match line {
                        Ok(text) => warn!(target: "chio_mcp_adapter::stderr", "{text}"),
                        Err(_) => break,
                    }
                }
            });
        }

        let active_request = Arc::new(Mutex::new(None::<mpsc::SyncSender<RequestMessage>>));
        let (notification_tx, notification_rx) =
            mpsc::sync_channel(MAX_STDIO_MCP_BUFFERED_MESSAGES);
        let reader_notification_tx = notification_tx.clone();
        let reader_active_request = Arc::clone(&active_request);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let message = match read_line(&mut reader) {
                    Ok(message) => message,
                    Err(error) => {
                        if let Ok(mut active_request) = reader_active_request.lock() {
                            if let Some(sender) = active_request.take() {
                                let _ =
                                    sender.try_send(RequestMessage::ReadError(error.to_string()));
                            }
                        }
                        break;
                    }
                };

                let active_sender = reader_active_request
                    .lock()
                    .ok()
                    .and_then(|active_request| active_request.clone());
                if let Some(sender) = active_sender {
                    if sender
                        .try_send(RequestMessage::Message(message.clone()))
                        .is_ok()
                    {
                        continue;
                    }
                    if let Ok(mut active_request) = reader_active_request.lock() {
                        active_request.take();
                    }
                }

                if message.get("id").is_none() {
                    if reader_notification_tx.try_send(message).is_err() {
                        warn!(
                            target: "chio_mcp_adapter::transport",
                            "dropping upstream MCP notification because the bounded queue is full"
                        );
                    }
                } else {
                    warn!(target: "chio_mcp_adapter::transport", "unexpected upstream message without an active request: {message}");
                }
            }
        });

        let mut transport = Self {
            inner: Mutex::new(TransportInner {
                child,
                writer: stdin,
                next_id: 1,
            }),
            active_request,
            notification_tx,
            notification_rx: Mutex::new(notification_rx),
            capabilities: McpServerCapabilities::default(),
        };

        let initialize_result = transport.initialize()?;
        transport.capabilities = McpServerCapabilities::from_initialize_result(&initialize_result);

        Ok(transport)
    }

    /// Send the MCP `initialize` handshake followed by the
    /// `notifications/initialized` notification.
    fn initialize(&self) -> Result<serde_json::Value, AdapterError> {
        let params = json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": proxy_client_capabilities(),
            "clientInfo": {
                "name": "chio-mcp-adapter",
                "version": "0.1.0"
            }
        });

        let result = self.send_request("initialize", params)?;
        debug!("MCP initialize response: {result}");

        // Send the initialized notification (no id, no response expected).
        self.send_notification("notifications/initialized", json!({}))?;

        Ok(result)
    }

    /// Send a JSON-RPC request and wait for the matching response.
    ///
    /// Notifications (messages without an `id` field) received while waiting
    /// are either forwarded through the active nested-flow bridge or logged
    /// and skipped.
    fn send_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.send_request_with_nested_flow(method, params, None)
    }

    fn send_request_with_nested_flow(
        &self,
        method: &str,
        params: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, AdapterError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;
        let mut nested_flow_bridge = nested_flow_bridge;
        let (request_tx, request_rx) = mpsc::sync_channel(MAX_STDIO_MCP_BUFFERED_MESSAGES);

        {
            let mut active_request = self
                .active_request
                .lock()
                .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;
            if active_request.is_some() {
                return Err(AdapterError::ConnectionFailed(
                    "concurrent upstream MCP requests are not supported".into(),
                ));
            }
            *active_request = Some(request_tx);
        }

        let id = inner.next_id;
        inner.next_id += 1;
        let mut nested_task_runtime = NestedFlowTaskRuntime::default();
        let request_id = json!(id);

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let result = (|| {
            send_line(&mut inner.writer, &request)?;

            // Read routed messages until we get a response with a matching id.
            loop {
                let response = match request_rx.recv_timeout(UPSTREAM_REQUEST_POLL_INTERVAL) {
                    Ok(RequestMessage::Message(response)) => response,
                    Ok(RequestMessage::ReadError(error)) => {
                        return Err(AdapterError::ConnectionFailed(error));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        service_active_request_runtime(
                            &mut nested_flow_bridge,
                            &mut nested_task_runtime,
                            &mut inner.writer,
                            &request_id,
                        )?;
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(AdapterError::ConnectionFailed(
                            "upstream MCP reader disconnected".into(),
                        ));
                    }
                };

                if response.get("method").is_some() && response.get("id").is_some() {
                    let method = response
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let Some(bridge) = nested_flow_bridge.as_deref_mut() else {
                        if respond_to_upstream_roots_without_bridge(&mut inner.writer, &response)? {
                            continue;
                        }
                        return Err(AdapterError::NestedFlowDenied(format!(
                            "upstream server requested {method} without an active nested-flow bridge"
                        )));
                    };
                    respond_to_upstream_nested_flow(
                        &mut inner.writer,
                        &response,
                        bridge,
                        &mut nested_task_runtime,
                    )?;
                    service_active_request_runtime(
                        &mut nested_flow_bridge,
                        &mut nested_task_runtime,
                        &mut inner.writer,
                        &request_id,
                    )?;
                    continue;
                }

                if response.get("id").is_none() {
                    if is_nested_flow_notification(&response) {
                        let Some(bridge) = nested_flow_bridge.as_deref_mut() else {
                            self.queue_notification(response)?;
                            continue;
                        };
                        forward_upstream_notification(&response, bridge)?;
                    } else {
                        self.queue_notification(response)?;
                    }
                    service_active_request_runtime(
                        &mut nested_flow_bridge,
                        &mut nested_task_runtime,
                        &mut inner.writer,
                        &request_id,
                    )?;
                    continue;
                }

                if response["id"] != request_id {
                    debug!("MCP response id mismatch (expected {id}): {response}");
                    service_active_request_runtime(
                        &mut nested_flow_bridge,
                        &mut nested_task_runtime,
                        &mut inner.writer,
                        &request_id,
                    )?;
                    continue;
                }

                if let Some(err) = response.get("error") {
                    return Err(adapter_jsonrpc_error(err));
                }

                return response.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }
        })();

        if let Ok(mut active_request) = self.active_request.lock() {
            active_request.take();
        }

        result
    }

    fn queue_notification(&self, message: serde_json::Value) -> Result<(), AdapterError> {
        self.notification_tx
            .try_send(message)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    AdapterError::ConnectionFailed("upstream notification queue is full".into())
                }
                mpsc::TrySendError::Disconnected(_) => AdapterError::ConnectionFailed(
                    "upstream notification queue disconnected".into(),
                ),
            })
    }

    /// Send a JSON-RPC notification (no id, no response expected).
    fn send_notification(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<(), AdapterError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;

        let notification = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });

        send_line(&mut inner.writer, &notification)
    }

    /// Gracefully shut down the MCP server by killing the child process.
    pub fn shutdown(&self) -> Result<(), AdapterError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;

        let _ = inner.child.kill();
        let _ = inner.child.wait();
        Ok(())
    }
}

impl McpTransport for StdioMcpTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        self.capabilities.clone()
    }

    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        let mut notifications = Vec::new();
        let Ok(notification_rx) = self.notification_rx.lock() else {
            return notifications;
        };

        while let Ok(notification) = notification_rx.try_recv() {
            notifications.push(notification);
        }

        notifications
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        let result = self.send_request("tools/list", json!({}))?;

        let tools_value = result.get("tools").ok_or_else(|| {
            AdapterError::ParseError("tools/list response missing 'tools'".into())
        })?;

        let tools: Vec<McpToolInfo> = serde_json::from_value(tools_value.clone())
            .map_err(|e| AdapterError::ParseError(format!("failed to parse tool list: {e}")))?;

        Ok(tools)
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.call_tool_with_nested_flow(tool_name, arguments, None)
    }

    fn call_tool_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<McpToolResult, AdapterError> {
        let params = json!({
            "name": tool_name,
            "arguments": arguments,
        });

        let result =
            self.send_request_with_nested_flow("tools/call", params, nested_flow_bridge)?;

        let tool_result: McpToolResult = serde_json::from_value(result)
            .map_err(|e| AdapterError::ParseError(format!("failed to parse tool result: {e}")))?;

        Ok(tool_result)
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        let result = self.send_request("resources/list", json!({}))?;
        let resources_value = result.get("resources").ok_or_else(|| {
            AdapterError::ParseError("resources/list response missing 'resources'".into())
        })?;
        serde_json::from_value(resources_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resources: {error}"))
        })
    }

    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        let result = self.send_request("resources/templates/list", json!({}))?;
        let templates_value = result.get("resourceTemplates").ok_or_else(|| {
            AdapterError::ParseError(
                "resources/templates/list response missing 'resourceTemplates'".into(),
            )
        })?;
        serde_json::from_value(templates_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource templates: {error}"))
        })
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        let result = self.send_request("resources/read", json!({ "uri": uri }))?;
        let contents_value = result.get("contents").ok_or_else(|| {
            AdapterError::ParseError("resources/read response missing 'contents'".into())
        })?;
        let contents = serde_json::from_value(contents_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource contents: {error}"))
        })?;
        Ok(Some(contents))
    }

    fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        let result = self.send_request("prompts/list", json!({}))?;
        let prompts_value = result.get("prompts").ok_or_else(|| {
            AdapterError::ParseError("prompts/list response missing 'prompts'".into())
        })?;
        serde_json::from_value(prompts_value.clone())
            .map_err(|error| AdapterError::ParseError(format!("failed to parse prompts: {error}")))
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        let result = self.send_request(
            "prompts/get",
            json!({
                "name": name,
                "arguments": arguments,
            }),
        )?;
        let prompt = serde_json::from_value(result).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse prompt result: {error}"))
        })?;
        Ok(Some(prompt))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        let result = self.send_request(
            "completion/complete",
            json!({
                "ref": {
                    "type": "ref/prompt",
                    "name": name,
                },
                "argument": {
                    "name": argument_name,
                    "value": value,
                },
                "context": {
                    "arguments": context,
                }
            }),
        )?;
        let completion_value = result.get("completion").ok_or_else(|| {
            AdapterError::ParseError("completion/complete response missing 'completion'".into())
        })?;
        let completion = serde_json::from_value(completion_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse prompt completion: {error}"))
        })?;
        Ok(Some(completion))
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        let result = self.send_request(
            "completion/complete",
            json!({
                "ref": {
                    "type": "ref/resource",
                    "uri": uri,
                },
                "argument": {
                    "name": argument_name,
                    "value": value,
                },
                "context": {
                    "arguments": context,
                }
            }),
        )?;
        let completion_value = result.get("completion").ok_or_else(|| {
            AdapterError::ParseError("completion/complete response missing 'completion'".into())
        })?;
        let completion = serde_json::from_value(completion_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource completion: {error}"))
        })?;
        Ok(Some(completion))
    }
}

impl Drop for StdioMcpTransport {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
    }
}
