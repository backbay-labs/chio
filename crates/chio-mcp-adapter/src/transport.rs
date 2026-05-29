//! Stdio-based MCP transport.
//!
//! Spawns an MCP server as a subprocess and communicates via newline-delimited
//! JSON-RPC over stdin/stdout. This is the standard MCP transport mechanism.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, TaskOwnershipSnapshot,
};
use chio_kernel::{KernelError, NestedFlowBridge};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, warn};

use crate::{AdapterError, McpServerCapabilities, McpToolInfo, McpToolResult, McpTransport};
use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition,
};

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const UPSTREAM_REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(20);
const TASK_POLL_INTERVAL_MILLIS: u64 = 500;
const MAX_BACKGROUND_TASKS_PER_TICK: usize = 8;
const MAX_STDIO_MCP_FRAME_BYTES: usize = 1024 * 1024;
const MAX_STDIO_MCP_BUFFERED_MESSAGES: usize = 128;
const RELATED_TASK_META_KEY: &str = "io.modelcontextprotocol/related-task";

struct TransportInner {
    child: Child,
    writer: std::process::ChildStdin,
    next_id: u64,
}

enum RequestMessage {
    Message(serde_json::Value),
    ReadError(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestedTask {
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NestedFlowTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
enum NestedFlowTaskOperation {
    CreateMessage(CreateMessageOperation),
    CreateElicitation(CreateElicitationOperation),
}

#[derive(Debug, Clone)]
enum NestedFlowTaskFinalOutcome {
    Result(serde_json::Value),
    Error { code: i64, message: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NestedFlowTask {
    task_id: String,
    status: NestedFlowTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    created_at: String,
    last_updated_at: String,
    ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval: Option<u64>,
    ownership: TaskOwnershipSnapshot,
    owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_request_id: Option<String>,
    #[serde(skip)]
    operation: NestedFlowTaskOperation,
    #[serde(skip)]
    final_outcome: Option<NestedFlowTaskFinalOutcome>,
}

impl NestedFlowTask {
    fn new_create_message(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateMessageOperation,
        ttl: Option<u64>,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateMessage(operation),
            final_outcome: None,
        }
    }

    fn new_create_elicitation(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateElicitationOperation,
        ttl: Option<u64>,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateElicitation(operation),
            final_outcome: None,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            NestedFlowTaskStatus::Completed
                | NestedFlowTaskStatus::Failed
                | NestedFlowTaskStatus::Cancelled
        )
    }

    fn touch(&mut self) {
        self.last_updated_at = iso8601_now();
    }

    fn mark_completed(&mut self, result: serde_json::Value) {
        self.status = NestedFlowTaskStatus::Completed;
        self.status_message = Some("The operation completed successfully.".to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Result(result));
        self.touch();
    }

    fn mark_failed(&mut self, code: i64, message: String) {
        self.status = NestedFlowTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error { code, message });
        self.touch();
    }

    fn mark_cancelled(&mut self, reason: &str) {
        self.status = NestedFlowTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error {
            code: -32800,
            message: reason.to_string(),
        });
        self.touch();
    }
}

#[derive(Debug, Default)]
struct NestedFlowTaskRuntime {
    task_counter: u64,
    tasks: BTreeMap<String, NestedFlowTask>,
    pending_background_tasks: Vec<String>,
}

impl NestedFlowTaskRuntime {
    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("nested-client-task-{}", self.task_counter)
    }

    fn create_message_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateMessageOperation,
        requested_task: RequestedTask,
    ) -> serde_json::Value {
        let task_id = self.next_task_id();
        let task = NestedFlowTask::new_create_message(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
        );
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        json!({ "task": task_view })
    }

    fn create_elicitation_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateElicitationOperation,
        requested_task: RequestedTask,
    ) -> serde_json::Value {
        let task_id = self.next_task_id();
        let task = NestedFlowTask::new_create_elicitation(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
        );
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        json!({ "task": task_view })
    }

    fn handle_tasks_list(
        &self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let start = match parse_cursor(params) {
            Ok(start) => start,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let tasks = self.tasks.values().cloned().collect::<Vec<_>>();
        if start > tasks.len() {
            return json_rpc_error(id, -32602, "cursor is out of range");
        }

        let end = (start + 50).min(tasks.len());
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        json_rpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
            }),
        )
    }

    fn handle_tasks_get(
        &self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };

        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    fn handle_tasks_cancel(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get_mut(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };
        if task.is_terminal() {
            return json_rpc_error(
                id,
                -32602,
                &format!(
                    "Cannot cancel task: already in terminal status '{}'",
                    nested_flow_task_status_label(task.status)
                ),
            );
        }

        task.mark_cancelled("The task was cancelled by request.");
        self.pending_background_tasks
            .retain(|pending| pending != &task_id);
        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    fn handle_tasks_result(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<serde_json::Value, AdapterError> {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return Ok(json_rpc_error(id, -32602, &message)),
        };

        self.pending_background_tasks
            .retain(|pending| pending != &task_id);

        if !self.tasks.contains_key(&task_id) {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        }

        if !self
            .tasks
            .get(&task_id)
            .is_some_and(NestedFlowTask::is_terminal)
        {
            self.execute_task(&task_id, nested_flow_bridge, writer)?;
        }

        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        };

        let response = match task.final_outcome.clone() {
            Some(NestedFlowTaskFinalOutcome::Result(result)) => json_rpc_result(
                id,
                attach_related_task_meta_to_result(
                    result,
                    build_related_task_meta(
                        &task.task_id,
                        Some(&task.owner_request_id),
                        task.parent_request_id.as_deref(),
                    ),
                ),
            ),
            Some(NestedFlowTaskFinalOutcome::Error { code, message }) => {
                json_rpc_error(id, code, &message)
            }
            None => json_rpc_error(id, -32603, "task result unavailable"),
        };

        Ok(response)
    }

    fn process_background_tasks(
        &mut self,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            if !self.tasks.contains_key(&task_id) {
                continue;
            }

            if self
                .tasks
                .get(&task_id)
                .is_some_and(NestedFlowTask::is_terminal)
            {
                continue;
            }

            self.execute_task(&task_id, nested_flow_bridge, writer)?;
            if let Some(task) = self.tasks.get(&task_id) {
                send_line(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/tasks/status",
                        "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
                    }),
                )?;
            }
        }
        Ok(())
    }

    fn execute_task(
        &mut self,
        task_id: &str,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        _writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        let Some(mut task) = self.tasks.remove(task_id) else {
            return Ok(());
        };

        if !task.is_terminal() {
            match task.operation.clone() {
                NestedFlowTaskOperation::CreateMessage(operation) => {
                    match nested_flow_bridge.create_message(operation) {
                        Ok(result) => {
                            let result = serde_json::to_value(result).map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize sampling/createMessage result: {error}"
                                ))
                            })?;
                            task.mark_completed(result);
                        }
                        Err(error) => {
                            task.mark_failed(map_nested_flow_error_code(&error), error.to_string());
                        }
                    }
                }
                NestedFlowTaskOperation::CreateElicitation(operation) => {
                    match nested_flow_bridge.create_elicitation(operation) {
                        Ok(result) => {
                            let result = serde_json::to_value(result).map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize elicitation/create result: {error}"
                                ))
                            })?;
                            task.mark_completed(result);
                        }
                        Err(error) => {
                            task.mark_failed(map_nested_flow_error_code(&error), error.to_string());
                        }
                    }
                }
            }
        }

        self.tasks.insert(task_id.to_string(), task);
        Ok(())
    }
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
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
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

fn proxy_client_capabilities() -> serde_json::Value {
    json!({
        "roots": {
            "listChanged": true,
        },
        "sampling": {
            "context": {},
            "tools": {},
        },
        "elicitation": {
            "form": {},
            "url": {}
        },
        "tasks": {
            "list": {},
            "cancel": {},
            "requests": {
                "sampling": {
                    "createMessage": {}
                },
                "elicitation": {
                    "create": {}
                }
            }
        }
    })
}

fn respond_to_upstream_roots_without_bridge(
    writer: &mut impl Write,
    message: &serde_json::Value,
) -> Result<bool, AdapterError> {
    if message.get("method").and_then(serde_json::Value::as_str) != Some("roots/list") {
        return Ok(false);
    }

    let id = message
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    send_line(writer, &json_rpc_result(id, json!({ "roots": [] })))?;
    Ok(true)
}

fn respond_to_upstream_nested_flow(
    writer: &mut impl Write,
    message: &serde_json::Value,
    nested_flow_bridge: &mut dyn NestedFlowBridge,
    nested_task_runtime: &mut NestedFlowTaskRuntime,
) -> Result<(), AdapterError> {
    let id = message
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = message
        .get("method")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdapterError::ParseError("upstream request missing method".into()))?;
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    let response = match method {
        "roots/list" => match nested_flow_bridge.list_roots() {
            Ok(roots) => json_rpc_result(id, json!({ "roots": roots })),
            Err(error) => {
                json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
            }
        },
        "sampling/createMessage" => {
            let operation: CreateMessageOperation = serde_json::from_value(params.clone())
                .map_err(|error| {
                    AdapterError::ParseError(format!(
                        "failed to parse sampling/createMessage params: {error}"
                    ))
                })?;
            if let Some(task) = parse_requested_task(&params)? {
                let owner_request_id = jsonrpc_request_id_label(&id);
                let parent_request_id = nested_flow_bridge.parent_request_id().to_string();
                json_rpc_result(
                    id,
                    nested_task_runtime.create_message_task(
                        owner_request_id,
                        parent_request_id,
                        operation,
                        task,
                    ),
                )
            } else {
                match nested_flow_bridge.create_message(operation) {
                    Ok(result) => {
                        let result = serde_json::to_value::<CreateMessageResult>(result).map_err(
                            |error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize sampling/createMessage result: {error}"
                                ))
                            },
                        )?;
                        json_rpc_result(id, result)
                    }
                    Err(error) => {
                        json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
                    }
                }
            }
        }
        "elicitation/create" => {
            let operation = parse_create_elicitation_operation(&params)?;
            if let Some(task) = parse_requested_task(&params)? {
                let owner_request_id = jsonrpc_request_id_label(&id);
                let parent_request_id = nested_flow_bridge.parent_request_id().to_string();
                json_rpc_result(
                    id,
                    nested_task_runtime.create_elicitation_task(
                        owner_request_id,
                        parent_request_id,
                        operation,
                        task,
                    ),
                )
            } else {
                match nested_flow_bridge.create_elicitation(operation) {
                    Ok(result) => {
                        let result = serde_json::to_value::<CreateElicitationResult>(result)
                            .map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize elicitation/create result: {error}"
                                ))
                            })?;
                        json_rpc_result(id, result)
                    }
                    Err(error) => {
                        json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
                    }
                }
            }
        }
        "tasks/list" => nested_task_runtime.handle_tasks_list(id, &params),
        "tasks/get" => nested_task_runtime.handle_tasks_get(id, &params),
        "tasks/cancel" => nested_task_runtime.handle_tasks_cancel(id, &params),
        "tasks/result" => {
            nested_task_runtime.handle_tasks_result(id, &params, nested_flow_bridge, writer)?
        }
        _ => json_rpc_error(id, -32601, "method not found"),
    };

    send_line(writer, &response)
}

fn forward_upstream_notification(
    message: &serde_json::Value,
    nested_flow_bridge: &mut dyn NestedFlowBridge,
) -> Result<(), AdapterError> {
    let Some(method) = message.get("method").and_then(serde_json::Value::as_str) else {
        debug!("MCP notification without method: {message}");
        return Ok(());
    };

    match method {
        "notifications/resources/updated" => {
            let uri = message
                .get("params")
                .and_then(|params| params.get("uri"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AdapterError::ParseError(
                        "notifications/resources/updated missing params.uri".into(),
                    )
                })?;
            nested_flow_bridge
                .notify_resource_updated(uri)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))
        }
        "notifications/elicitation/complete" => {
            let elicitation_id = message
                .get("params")
                .and_then(|params| params.get("elicitationId"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AdapterError::ParseError(
                        "notifications/elicitation/complete missing params.elicitationId".into(),
                    )
                })?;
            nested_flow_bridge
                .notify_elicitation_completed(elicitation_id)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))
        }
        "notifications/resources/list_changed" => nested_flow_bridge
            .notify_resources_list_changed()
            .map_err(|error| AdapterError::NestedFlowDenied(error.to_string())),
        _ => {
            debug!("MCP notification ignored: {message}");
            Ok(())
        }
    }
}

fn parse_requested_task(params: &serde_json::Value) -> Result<Option<RequestedTask>, AdapterError> {
    let Some(task) = params.get("task").cloned() else {
        return Ok(None);
    };
    serde_json::from_value(task).map(Some).map_err(|_| {
        AdapterError::ParseError("task must be an object with an optional numeric ttl".into())
    })
}

fn parse_create_elicitation_operation(
    params: &serde_json::Value,
) -> Result<CreateElicitationOperation, AdapterError> {
    let mut normalized = params.clone();
    if normalized.get("mode").is_none() {
        if let Some(object) = normalized.as_object_mut() {
            object.insert("mode".to_string(), json!("form"));
        }
    }

    serde_json::from_value(normalized).map_err(|error| {
        AdapterError::ParseError(format!(
            "failed to parse elicitation/create params: {error}"
        ))
    })
}

fn parse_cursor(params: &serde_json::Value) -> Result<usize, String> {
    let cursor = match params.get("cursor") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err("cursor must be a string".to_string()),
    };

    match cursor.as_deref() {
        None => Ok(0),
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| "cursor must be numeric".to_string()),
    }
}

fn parse_task_id(params: &serde_json::Value) -> Result<String, String> {
    params
        .get("taskId")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "taskId must be a string".to_string())
}

fn nested_flow_task_status_label(status: NestedFlowTaskStatus) -> &'static str {
    match status {
        NestedFlowTaskStatus::Working => "working",
        NestedFlowTaskStatus::Completed => "completed",
        NestedFlowTaskStatus::Failed => "failed",
        NestedFlowTaskStatus::Cancelled => "cancelled",
    }
}

fn iso8601_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn build_related_task_meta(
    task_id: &str,
    owner_request_id: Option<&str>,
    parent_request_id: Option<&str>,
) -> serde_json::Value {
    json!({
        "taskId": task_id,
        "ownerRequestId": owner_request_id,
        "parentRequestId": parent_request_id,
    })
}

fn attach_related_task_meta_to_result(
    mut result: serde_json::Value,
    related_task_meta: serde_json::Value,
) -> serde_json::Value {
    if let Some(object) = result.as_object_mut() {
        let meta = object
            .entry("_meta".to_string())
            .or_insert_with(|| json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(RELATED_TASK_META_KEY.to_string(), related_task_meta);
        }
    }
    result
}

fn is_nested_flow_notification(message: &serde_json::Value) -> bool {
    matches!(
        message.get("method").and_then(serde_json::Value::as_str),
        Some(
            "notifications/resources/updated"
                | "notifications/resources/list_changed"
                | "notifications/elicitation/complete"
        )
    )
}

fn map_nested_flow_error_code(error: &KernelError) -> i64 {
    match error {
        KernelError::SamplingNotAllowedByPolicy
        | KernelError::SamplingNotNegotiated
        | KernelError::SamplingContextNotSupported
        | KernelError::SamplingToolUseNotAllowedByPolicy
        | KernelError::SamplingToolUseNotNegotiated
        | KernelError::ElicitationNotAllowedByPolicy
        | KernelError::ElicitationNotNegotiated
        | KernelError::ElicitationFormNotSupported
        | KernelError::ElicitationUrlNotSupported
        | KernelError::InvalidChildRequestParent
        | KernelError::RootsNotNegotiated => -32002,
        KernelError::UrlElicitationsRequired { .. } => -32042,
        KernelError::RequestCancelled { .. } => -32800,
        _ => -32603,
    }
}

fn json_rpc_result(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn json_rpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn adapter_jsonrpc_error(error: &serde_json::Value) -> AdapterError {
    AdapterError::McpError {
        code: error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-32603),
        message: error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown JSON-RPC error")
            .to_string(),
        data: error.get("data").cloned(),
    }
}

fn service_active_request_runtime(
    nested_flow_bridge: &mut Option<&mut dyn NestedFlowBridge>,
    nested_task_runtime: &mut NestedFlowTaskRuntime,
    writer: &mut impl Write,
    request_id: &serde_json::Value,
) -> Result<(), AdapterError> {
    let Some(bridge) = nested_flow_bridge.as_deref_mut() else {
        return Ok(());
    };

    nested_task_runtime.process_background_tasks(bridge, writer)?;
    match bridge.poll_parent_cancellation() {
        Ok(()) => Ok(()),
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) => {
            let _ = send_upstream_cancellation(writer, request_id, &reason);
            Err(AdapterError::RequestCancelled {
                request_id: cancelled_request_id,
                reason,
            })
        }
        Err(error) => Err(AdapterError::ConnectionFailed(error.to_string())),
    }
}

/// Write a JSON value as a single newline-terminated line to the writer.
fn send_line(writer: &mut impl Write, value: &serde_json::Value) -> Result<(), AdapterError> {
    let line = serde_json::to_string(value)
        .map_err(|e| AdapterError::ParseError(format!("failed to serialize JSON-RPC: {e}")))?;
    debug!("-> {line}");
    writer
        .write_all(line.as_bytes())
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to write to stdin: {e}")))?;
    writer
        .write_all(b"\n")
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to write newline: {e}")))?;
    writer
        .flush()
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to flush stdin: {e}")))?;
    Ok(())
}

fn send_upstream_cancellation(
    writer: &mut impl Write,
    request_id: &serde_json::Value,
    reason: &str,
) -> Result<(), AdapterError> {
    send_line(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": request_id,
                "reason": reason,
            }
        }),
    )
}

fn jsonrpc_request_id_label(request_id: &serde_json::Value) -> String {
    match request_id {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Read a single newline-terminated JSON line from the reader.
fn read_line(reader: &mut impl BufRead) -> Result<serde_json::Value, AdapterError> {
    let Some(line) = read_bounded_line(reader, MAX_STDIO_MCP_FRAME_BYTES)? else {
        return Err(AdapterError::ConnectionFailed(
            "MCP server closed stdout (EOF)".into(),
        ));
    };

    debug!("<- {}", line.trim_end());

    serde_json::from_str(line.trim())
        .map_err(|e| AdapterError::ParseError(format!("invalid JSON from MCP server: {e}")))
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> Result<Option<String>, AdapterError> {
    let mut bytes = Vec::new();
    loop {
        let (take, has_newline, exceeds_limit) = {
            let available = reader.fill_buf().map_err(|e| {
                AdapterError::ConnectionFailed(format!("failed to read from stdout: {e}"))
            })?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                break;
            }

            let take = match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => index + 1,
                None => available.len(),
            };
            let has_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
            let exceeds_limit = bytes.len().saturating_add(take) > max_bytes;
            if !exceeds_limit {
                bytes.extend_from_slice(&available[..take]);
            }
            (take, has_newline, exceeds_limit)
        };

        reader.consume(take);
        if exceeds_limit {
            return Err(AdapterError::ParseError(format!(
                "MCP JSON-RPC frame exceeded {max_bytes} bytes"
            )));
        }

        if has_newline {
            break;
        }
    }

    String::from_utf8(bytes).map(Some).map_err(|error| {
        AdapterError::ParseError(format!("MCP JSON-RPC frame was not UTF-8: {error}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::session::ElicitationAction;
    use chio_core::RequestId;

    struct MockNestedFlowBridge;

    impl NestedFlowBridge for MockNestedFlowBridge {
        fn parent_request_id(&self) -> &RequestId {
            static REQUEST_ID: std::sync::OnceLock<RequestId> = std::sync::OnceLock::new();
            REQUEST_ID.get_or_init(|| RequestId::new("parent-1"))
        }

        fn list_roots(&mut self) -> Result<Vec<chio_core::RootDefinition>, KernelError> {
            unreachable!("not used in these tests")
        }

        fn create_message(
            &mut self,
            _operation: CreateMessageOperation,
        ) -> Result<CreateMessageResult, KernelError> {
            Ok(CreateMessageResult {
                role: "assistant".to_string(),
                content: json!({
                    "type": "text",
                    "text": "sampled"
                }),
                model: "gpt-test".to_string(),
                stop_reason: Some("end_turn".to_string()),
            })
        }

        fn create_elicitation(
            &mut self,
            _operation: CreateElicitationOperation,
        ) -> Result<CreateElicitationResult, KernelError> {
            Ok(CreateElicitationResult {
                action: ElicitationAction::Accept,
                content: None,
            })
        }

        fn notify_elicitation_completed(
            &mut self,
            _elicitation_id: &str,
        ) -> Result<(), KernelError> {
            Ok(())
        }

        fn notify_resource_updated(&mut self, _uri: &str) -> Result<(), KernelError> {
            Ok(())
        }

        fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
            Ok(())
        }
    }

    #[test]
    fn send_line_produces_newline_delimited_json() {
        let mut buf: Vec<u8> = Vec::new();
        let value = json!({"jsonrpc": "2.0", "id": 1, "method": "test", "params": {}});
        send_line(&mut buf, &value).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'), "must end with newline");

        // The line before the newline must be valid JSON.
        let trimmed = output.trim_end();
        let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap();
        assert_eq!(parsed["method"], "test");
    }

    #[test]
    fn read_line_parses_json() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
        let mut reader = BufReader::new(&input[..]);
        let value = read_line(&mut reader).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ok"], true);
    }

    #[test]
    fn read_line_eof_returns_error() {
        let input = b"";
        let mut reader = BufReader::new(&input[..]);
        let err = read_line(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionFailed(_)),
            "expected ConnectionFailed, got: {err}"
        );
    }

    #[test]
    fn read_line_invalid_json_returns_error() {
        let input = b"not json\n";
        let mut reader = BufReader::new(&input[..]);
        let err = read_line(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn read_line_rejects_oversized_frame() {
        let input = format!("{}\n", "x".repeat(MAX_STDIO_MCP_FRAME_BYTES + 1));
        let mut reader = BufReader::new(input.as_bytes());
        let err = match read_line(&mut reader) {
            Ok(value) => panic!("oversized frame must fail closed, got: {value}"),
            Err(err) => err,
        };
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError for oversized frame, got: {err}"
        );
    }

    #[test]
    fn proxy_client_capabilities_use_object_valued_mcp_capabilities() {
        let capabilities = proxy_client_capabilities();

        assert_eq!(capabilities["roots"]["listChanged"], true);
        assert_eq!(capabilities["sampling"]["context"], json!({}));
        assert_eq!(capabilities["sampling"]["tools"], json!({}));
        assert!(capabilities["sampling"].get("includeContext").is_none());
        assert_eq!(capabilities["elicitation"]["form"], json!({}));
        assert_eq!(capabilities["elicitation"]["url"], json!({}));
        assert_eq!(capabilities["tasks"]["list"], json!({}));
        assert_eq!(
            capabilities["tasks"]["requests"]["sampling"]["createMessage"],
            json!({})
        );
        assert_eq!(
            capabilities["tasks"]["requests"]["elicitation"]["create"],
            json!({})
        );
    }

    /// Full round-trip test using a mock MCP server script.
    ///
    /// The "server" is a small shell pipeline that reads JSON-RPC requests
    /// from stdin and writes canned responses to stdout.
    #[test]
    fn stdio_transport_with_mock_server() {
        // A small Python script that acts as a minimal MCP server.
        let script = r#"
import sys, json

def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)

    # Handle initialize
    if msg.get("method") == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-server", "version": "0.0.1"}
            }
        })
        continue

    # Handle notifications (no id) -- just ignore
    if "id" not in msg:
        continue

    # Handle tools/list
    if msg.get("method") == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": "startup-roots",
            "method": "roots/list",
            "params": {}
        })
        while True:
            nested = json.loads(sys.stdin.readline())
            if nested.get("id") != "startup-roots" or nested.get("method"):
                continue
            assert nested["result"]["roots"] == []
            break
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echoes input",
                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}
                    }
                ]
            }
        })
        continue

    # Handle tools/call
    if msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"]["arguments"]
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "content": [{"type": "text", "text": f"echo: {args.get('text', '')}"}],
                "isError": False
            }
        })
        continue

    # Unknown method
    respond({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "error": {"code": -32601, "message": f"unknown method: {msg.get('method')}"}
    })
"#;

        // Write the script to a temp file.
        let dir = std::env::temp_dir().join("chio-mcp-test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let script_path = dir.join("mock_mcp_server.py");
        std::fs::write(&script_path, script).expect("write mock script");

        let transport =
            StdioMcpTransport::spawn("python3", &[script_path.to_str().expect("path to str")])
                .expect("spawn mock server");

        let tools = transport.list_tools().expect("list_tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description.as_deref(), Some("Echoes input"));

        let result = transport
            .call_tool("echo", json!({"text": "hello"}))
            .expect("call_tool");
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0]["type"], "text");
        assert_eq!(result.content[0]["text"], "echo: hello");

        transport.shutdown().expect("shutdown");

        let _ = std::fs::remove_file(&script_path);
    }

    #[test]
    fn background_tick_can_complete_multiple_nested_flow_tasks() {
        let mut runtime = NestedFlowTaskRuntime::default();
        let parent_request_id = RequestId::new("parent-1");
        let task_a = runtime.create_message_task(
            "nested-upstream-1".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_b = runtime.create_message_task(
            "2".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_id_a = task_a["task"]["taskId"].as_str().unwrap().to_string();
        let task_id_b = task_b["task"]["taskId"].as_str().unwrap().to_string();
        assert_eq!(task_a["task"]["ownership"]["workOwner"], "task");
        assert_eq!(
            task_a["task"]["ownership"]["resultStreamOwner"],
            "request_stream"
        );
        assert_eq!(
            task_a["task"]["ownership"]["statusNotificationOwner"],
            "session_notification_stream"
        );
        assert_eq!(task_a["task"]["ownership"]["terminalStateOwner"], "task");
        assert_eq!(task_a["task"]["ownerRequestId"], "nested-upstream-1");
        assert_eq!(task_a["task"]["parentRequestId"], "parent-1");
        assert_eq!(task_b["task"]["ownerRequestId"], "2");
        assert_eq!(task_b["task"]["parentRequestId"], "parent-1");

        let mut bridge = MockNestedFlowBridge;
        let mut writer = Vec::new();
        runtime
            .process_background_tasks(&mut bridge, &mut writer)
            .unwrap();

        assert!(runtime.tasks.get(&task_id_a).unwrap().is_terminal());
        assert!(runtime.tasks.get(&task_id_b).unwrap().is_terminal());

        let output = String::from_utf8(writer).unwrap();
        let status_count = output
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| message["method"] == "notifications/tasks/status")
            .count();
        assert_eq!(status_count, 2);
    }

    #[test]
    fn tasks_result_includes_nested_task_lineage_in_related_task_meta() {
        let mut runtime = NestedFlowTaskRuntime::default();
        let parent_request_id = RequestId::new("parent-1");
        let created = runtime.create_message_task(
            "nested-upstream-7".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_id = created["task"]["taskId"].as_str().unwrap().to_string();

        let mut bridge = MockNestedFlowBridge;
        let mut writer = Vec::new();
        let response = runtime
            .handle_tasks_result(
                json!(9),
                &json!({ "taskId": task_id }),
                &mut bridge,
                &mut writer,
            )
            .unwrap();

        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            "nested-client-task-1"
        );
        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"],
            "nested-upstream-7"
        );
        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"],
            "parent-1"
        );
    }
}
