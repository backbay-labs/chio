use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::{AdapterError, McpTransport};
use chio_core::capability::{CapabilityToken, ModelMetadata, Operation};
use chio_core::receipt::Decision;
use chio_core::session::{
    CompleteOperation, CompletionArgument, CompletionReference, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, ElicitationAction,
    GetPromptOperation, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, ReadResourceOperation, RequestId, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, RootDefinition, SessionAuthContext, SessionId, SessionOperation,
    SessionTransport, TaskOwnershipSnapshot, ToolCallOperation,
};
use chio_cross_protocol::{
    route_selection_metadata, BridgeError, CrossProtocolTargetExecution,
    CrossProtocolTargetRequest, DiscoveryProtocol, TargetExecutionHop, TargetProtocolExecutor,
};
use chio_kernel::{
    ChioKernel, LateSessionEvent, NestedFlowClient, PeerCapabilities, SessionOperationResponse,
    ToolCallOutput, ToolCallRequest, ToolCallResponse, ToolCallStream, ToolServerEvent, Verdict,
};
use chio_manifest::{LatencyHint, ToolDefinition, ToolManifest};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[path = "runtime/nested_flow.rs"]
mod nested_flow;
#[path = "runtime/protocol.rs"]
mod protocol;

use nested_flow::*;
use protocol::*;

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &[MCP_PROTOCOL_VERSION];
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
const JSONRPC_SERVER_NOT_INITIALIZED: i64 = -32002;
const JSONRPC_URL_ELICITATION_REQUIRED: i64 = -32042;
const CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED: i64 = 1000;
const CHIO_ERROR_INVALID_REQUEST_SHAPE: i64 = 1002;
const CLIENT_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const CHIO_TOOL_STREAMING_CAPABILITY_KEY: &str = "chioToolStreaming";
const CHIO_PROTOCOL_CAPABILITY_KEY: &str = "chioProtocol";
const CHIO_ERROR_REGISTRY_SCHEMA: &str = "chio.error-registry.v1";
const CHIO_TOOL_STREAM_KEY: &str = "chioToolStream";
const CHIO_TOOL_STREAMING_NOTIFICATION_METHOD: &str = "notifications/chio/tool_call_chunk";
const TASK_POLL_INTERVAL_MILLIS: u64 = 500;
const MAX_BACKGROUND_TASKS_PER_TICK: usize = 8;
const RELATED_TASK_META_KEY: &str = "io.modelcontextprotocol/related-task";

#[derive(Debug, Clone)]
pub struct McpEdgeConfig {
    pub server_name: String,
    pub server_version: String,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub completion_enabled: Option<bool>,
    pub resources_subscribe: bool,
    pub resources_list_changed: bool,
    pub prompts_list_changed: bool,
    pub logging_enabled: bool,
}

impl Default for McpEdgeConfig {
    fn default() -> Self {
        Self {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size: 50,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        }
    }
}

/// Bridge-only request for projecting an Chio tool invocation through MCP session semantics.
#[derive(Debug, Clone)]
pub struct BridgeMcpToolCallRequest {
    pub request_id: String,
    pub capability: CapabilityToken,
    pub server_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub agent_id: String,
    pub model_metadata: Option<ModelMetadata>,
    pub route_selection_metadata: Option<Value>,
    pub peer_supports_chio_tool_streaming: bool,
}

/// Bridge-only MCP tool-call execution result.
#[derive(Debug)]
pub struct BridgeMcpToolCall {
    pub response: ToolCallResponse,
    pub mcp_result: Value,
    pub notifications: Vec<Value>,
}

/// Default non-native protocol executor for MCP target projections.
#[derive(Debug, Default, Clone, Copy)]
pub struct McpTargetExecutor {
    pub peer_supports_chio_tool_streaming: bool,
}

impl TargetProtocolExecutor for McpTargetExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let bridge = execute_bridge_mcp_tool_call(
            request.kernel,
            BridgeMcpToolCallRequest {
                request_id: request.execution.kernel_request_id.clone(),
                capability: request.execution.capability.clone(),
                server_id: request.execution.target_server_id.clone(),
                tool_name: request.execution.target_tool_name.clone(),
                arguments: request.execution.arguments.clone(),
                agent_id: request.execution.agent_id.clone(),
                model_metadata: request.execution.model_metadata.clone(),
                route_selection_metadata: Some(route_selection_metadata(request.route_selection)?),
                peer_supports_chio_tool_streaming: self.peer_supports_chio_tool_streaming,
            },
        )
        .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?;
        let receipt_id = bridge.response.receipt.id.clone();

        Ok(CrossProtocolTargetExecution {
            response: bridge.response,
            protocol_result: Some(bridge.mcp_result),
            protocol_notifications: bridge.notifications,
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Mcp,
                    request_id: format!("{}:mcp", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                },
            ],
        })
    }
}

pub async fn execute_bridge_mcp_tool_call_async(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let BridgeMcpToolCallRequest {
        request_id,
        capability,
        server_id,
        tool_name,
        arguments,
        agent_id,
        model_metadata,
        route_selection_metadata,
        peer_supports_chio_tool_streaming,
    } = request;
    let kernel_request = ToolCallRequest {
        request_id: request_id.clone(),
        capability,
        tool_name,
        server_id,
        agent_id,
        arguments,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata,
        federated_origin_kernel_id: None,
    };
    let response = kernel
        .evaluate_tool_call_with_metadata(&kernel_request, route_selection_metadata)
        .await
        .map_err(|error| AdapterError::KernelRuntime(error.to_string()))?;

    bridge_mcp_tool_call_from_response(response, &request_id, peer_supports_chio_tool_streaming)
}

pub fn execute_bridge_mcp_tool_call(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| {
                handle.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
            })
        }
        Ok(_) => {
            let kernel_request = ToolCallRequest {
                request_id: request.request_id.clone(),
                capability: request.capability.clone(),
                tool_name: request.tool_name.clone(),
                server_id: request.server_id.clone(),
                agent_id: request.agent_id.clone(),
                arguments: request.arguments.clone(),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: request.model_metadata.clone(),
                federated_origin_kernel_id: None,
            };
            let response = kernel
                .evaluate_tool_call_blocking_with_metadata(
                    &kernel_request,
                    request.route_selection_metadata.clone(),
                )
                .map_err(|error| AdapterError::KernelRuntime(error.to_string()))?;
            bridge_mcp_tool_call_from_response(
                response,
                &request.request_id,
                request.peer_supports_chio_tool_streaming,
            )
        }
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| AdapterError::KernelRuntime(error.to_string()))?;
            runtime.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
        }
    }
}

fn bridge_mcp_tool_call_from_response(
    response: ToolCallResponse,
    request_id: &str,
    peer_supports_chio_tool_streaming: bool,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let mut notifications = Vec::new();
    let mcp_result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
        pending_notifications: &mut notifications,
        request_id: &json!(request_id),
        output: response.output.clone(),
        reason: response.reason.clone(),
        verdict: response.verdict,
        terminal_state: &response.terminal_state,
        peer_supports_chio_tool_streaming,
        related_task_id: None,
    });

    Ok(BridgeMcpToolCall {
        response,
        mcp_result,
        notifications,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl LogLevel {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            "alert" => Some(Self::Alert),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }
}

fn chio_protocol_error_payload(
    code: i64,
    name: &str,
    transient: bool,
    retry_strategy: &str,
    guidance: &str,
) -> Value {
    json!({
        "code": code,
        "name": name,
        "category": "protocol",
        "transient": transient,
        "retry": {
            "strategy": retry_strategy,
            "guidance": guidance,
        }
    })
}

fn jsonrpc_protocol_error(args: JsonRpcProtocolErrorArgs<'_>) -> Value {
    let JsonRpcProtocolErrorArgs {
        id,
        jsonrpc_code,
        message,
        chio_code,
        name,
        retry_strategy,
        guidance,
        context,
    } = args;
    let mut data = serde_json::Map::new();
    data.insert(
        "chioError".to_string(),
        chio_protocol_error_payload(chio_code, name, false, retry_strategy, guidance),
    );
    if let Some(context) = context.and_then(|value| value.as_object().cloned()) {
        for (key, value) in context {
            data.insert(key, value);
        }
    }
    jsonrpc_error_with_data(id, jsonrpc_code, message, Some(Value::Object(data)))
}

fn negotiate_protocol_version(id: &Value, params: &Value) -> Result<&'static str, Value> {
    let Some(requested) = params.get("protocolVersion") else {
        return Ok(MCP_PROTOCOL_VERSION);
    };
    let Some(requested) = requested.as_str() else {
        return Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
            id: id.clone(),
            jsonrpc_code: JSONRPC_INVALID_REQUEST,
            message: "initialize.params.protocolVersion must be a string",
            chio_code: CHIO_ERROR_INVALID_REQUEST_SHAPE,
            name: "invalid_request_shape",
            retry_strategy: "do_not_retry",
            guidance: "correct the initialize request shape before retrying",
            context: Some(json!({
                "parameter": "protocolVersion"
            })),
        }));
    };
    if SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&requested) {
        Ok(MCP_PROTOCOL_VERSION)
    } else {
        Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
            id: id.clone(),
            jsonrpc_code: JSONRPC_INVALID_REQUEST,
            message: "unsupported protocolVersion",
            chio_code: CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED,
            name: "protocol_version_unsupported",
            retry_strategy: "do_not_retry_until_version_change",
            guidance: "retry only after selecting one of the server's supported protocol versions",
            context: Some(json!({
                "requestedProtocolVersion": requested,
                "supportedProtocolVersions": SUPPORTED_MCP_PROTOCOL_VERSIONS,
            })),
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpExposedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outputSchema"
    )]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
}

#[derive(Debug, Clone)]
struct ExposedToolBinding {
    tool: McpExposedTool,
    server_id: String,
    tool_name: String,
}

#[derive(Debug, Clone)]
enum EdgeState {
    Uninitialized,
    WaitingForInitialized { session_id: SessionId },
    Ready { session_id: SessionId },
}

#[derive(Debug, Clone)]
enum EdgeAction {
    RefreshRoots {
        session_id: SessionId,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EdgeTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeTask {
    task_id: String,
    status: EdgeTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    created_at: String,
    last_updated_at: String,
    ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval: Option<u64>,
    ownership: TaskOwnershipSnapshot,
    owner_session_id: String,
    owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_request_id: Option<String>,
    #[serde(skip)]
    session_id: SessionId,
    #[serde(skip)]
    context: OperationContext,
    #[serde(skip)]
    operation: ToolCallOperation,
    #[serde(skip)]
    final_outcome: Option<EdgeTaskFinalOutcome>,
    #[serde(skip)]
    background_ready_at_ms: u64,
}

#[derive(Debug, Clone)]
enum EdgeTaskFinalOutcome {
    Result(Value),
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

enum ToolCallEdgeOutcome {
    Result(Value),
    Cancelled {
        reason: String,
    },
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

struct JsonRpcProtocolErrorArgs<'a> {
    id: Value,
    jsonrpc_code: i64,
    message: &'a str,
    chio_code: i64,
    name: &'a str,
    retry_strategy: &'a str,
    guidance: &'a str,
    context: Option<Value>,
}

struct ToolCallRequestContext<'a> {
    id: &'a Value,
    session_id: &'a SessionId,
    context: &'a OperationContext,
    operation: &'a ToolCallOperation,
    related_task_id: Option<&'a str>,
}

struct KernelToolResultArgs<'a> {
    client_request_id: &'a Value,
    session_id: &'a SessionId,
    output: Option<ToolCallOutput>,
    reason: Option<String>,
    verdict: Verdict,
    terminal_state: &'a OperationTerminalState,
    related_task_id: Option<&'a str>,
}

impl EdgeTask {
    fn new(
        task_id: String,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        ttl: Option<u64>,
        background_start_delay_millis: u64,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: EdgeTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_session_id: session_id.to_string(),
            owner_request_id: context.request_id.to_string(),
            parent_request_id: context.parent_request_id.clone().map(|id| id.to_string()),
            session_id,
            context,
            operation,
            final_outcome: None,
            background_ready_at_ms: unix_now_millis() + background_start_delay_millis,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            EdgeTaskStatus::Completed | EdgeTaskStatus::Failed | EdgeTaskStatus::Cancelled
        )
    }

    fn touch(&mut self) {
        self.last_updated_at = iso8601_now();
    }

    fn mark_completed(&mut self, result: Value) {
        self.status = if tool_result_is_error(&result) {
            EdgeTaskStatus::Failed
        } else {
            EdgeTaskStatus::Completed
        };
        self.status_message = task_status_message(&self.status, &result);
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(result));
        self.touch();
    }

    fn mark_cancelled(&mut self, reason: &str) {
        self.status = EdgeTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(tool_error_result(reason)));
        self.touch();
    }

    fn mark_jsonrpc_error(&mut self, code: i64, message: String, data: Option<Value>) {
        self.status = EdgeTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(EdgeTaskFinalOutcome::JsonRpcError {
            code,
            message,
            data,
        });
        self.touch();
    }

    fn record_outcome(&mut self, outcome: ToolCallEdgeOutcome) {
        match outcome {
            ToolCallEdgeOutcome::Result(result) => self.mark_completed(result),
            ToolCallEdgeOutcome::Cancelled { reason } => self.mark_cancelled(&reason),
            ToolCallEdgeOutcome::JsonRpcError {
                code,
                message,
                data,
            } => self.mark_jsonrpc_error(code, message, data),
        }
    }

    fn background_ready(&self) -> bool {
        unix_now_millis() >= self.background_ready_at_ms
    }
}

pub struct ChioMcpEdge {
    config: McpEdgeConfig,
    kernel: ChioKernel,
    agent_id: String,
    session_auth_context: SessionAuthContext,
    capabilities: Vec<CapabilityToken>,
    tools: Vec<ExposedToolBinding>,
    tool_index: BTreeMap<String, usize>,
    request_counter: u64,
    client_request_counter: u64,
    state: EdgeState,
    minimum_log_level: LogLevel,
    pending_actions: Vec<EdgeAction>,
    pending_notifications: Vec<Value>,
    deferred_client_messages: Vec<Value>,
    task_counter: u64,
    tasks: BTreeMap<String, EdgeTask>,
    pending_background_tasks: Vec<String>,
    upstream_transport: Option<Arc<dyn McpTransport>>,
}

impl ChioMcpEdge {
    pub fn new(
        config: McpEdgeConfig,
        kernel: ChioKernel,
        agent_id: String,
        capabilities: Vec<CapabilityToken>,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, AdapterError> {
        let mut tool_index = BTreeMap::new();
        let mut tools = Vec::new();

        for manifest in manifests {
            for tool in manifest.tools {
                if tool_index.contains_key(&tool.name) {
                    return Err(AdapterError::ManifestError(
                        chio_manifest::ManifestError::DuplicateToolName(tool.name),
                    ));
                }

                let exposed_name = tool.name.clone();
                let binding = ExposedToolBinding {
                    tool: manifest_tool_to_mcp_tool(tool),
                    server_id: manifest.server_id.clone(),
                    tool_name: exposed_name.clone(),
                };
                tool_index.insert(exposed_name, tools.len());
                tools.push(binding);
            }
        }

        Ok(Self {
            config,
            kernel,
            agent_id,
            session_auth_context: SessionAuthContext::stdio_anonymous(),
            capabilities,
            tools,
            tool_index,
            request_counter: 0,
            client_request_counter: 0,
            state: EdgeState::Uninitialized,
            minimum_log_level: LogLevel::Info,
            pending_actions: Vec::new(),
            pending_notifications: Vec::new(),
            deferred_client_messages: Vec::new(),
            task_counter: 0,
            tasks: BTreeMap::new(),
            pending_background_tasks: Vec::new(),
            upstream_transport: None,
        })
    }

    pub fn attach_upstream_transport(&mut self, transport: Arc<dyn McpTransport>) {
        self.upstream_transport = Some(transport);
    }

    pub fn set_session_auth_context(&mut self, auth_context: SessionAuthContext) {
        self.session_auth_context = auth_context;
    }

    pub fn restore_ready_session(
        &mut self,
        session_id: SessionId,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), AdapterError> {
        if !matches!(self.state, EdgeState::Uninitialized) {
            return Err(AdapterError::ParseError(
                "restore_ready_session requires an uninitialized MCP edge".to_string(),
            ));
        }

        let restored_session_id = self
            .kernel
            .open_session_with_id(session_id, self.agent_id.clone(), self.capabilities.clone())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to restore session: {error}"))
            })?;
        self.kernel
            .set_session_auth_context(&restored_session_id, self.session_auth_context.clone())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "failed to restore session auth context: {error}"
                ))
            })?;
        self.kernel
            .set_session_peer_capabilities(&restored_session_id, peer_capabilities)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "failed to restore session peer capabilities: {error}"
                ))
            })?;
        self.kernel
            .activate_session(&restored_session_id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "failed to activate restored session: {error}"
                ))
            })?;
        self.state = EdgeState::Ready {
            session_id: restored_session_id.clone(),
        };
        if self
            .kernel
            .session(&restored_session_id)
            .is_some_and(|session| session.peer_capabilities().supports_roots)
        {
            self.queue_roots_refresh(restored_session_id, "restore");
        }
        Ok(())
    }

    pub fn handle_jsonrpc(&mut self, message: Value) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => Some(self.handle_request(id, method, params)),
            None => self.handle_notification(method, params),
        }
    }

    /// Advance in-process background work and return any queued notifications.
    ///
    /// This is the session-owned late-event surface for embedders that drive the
    /// edge directly via `handle_jsonrpc` instead of a transport loop.
    pub fn drain_runtime_notifications(&mut self) -> Result<Vec<Value>, AdapterError> {
        let _ = self.process_background_tasks()?;
        self.forward_runtime_events();
        Ok(self.take_pending_notifications())
    }

    // Retained for embedders that drive the edge through a custom transport
    // loop instead of the default session-owned path.
    #[allow(dead_code)]
    fn handle_jsonrpc_with_transport<R: BufRead, W: Write>(
        &mut self,
        message: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => {
                Some(self.handle_request_with_transport(id, method, params, reader, writer))
            }
            None => self.handle_notification(method, params),
        }
    }

    fn handle_jsonrpc_with_transport_channel<W: Write>(
        &mut self,
        message: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Option<Value> {
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "invalid jsonrpc envelope",
            ));
        }

        let method = match message.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(jsonrpc_error(
                    message.get("id").cloned().unwrap_or(Value::Null),
                    JSONRPC_INVALID_REQUEST,
                    "request missing method",
                ))
            }
        };

        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match message.get("id").cloned() {
            Some(id) => Some(self.handle_request_with_transport_channel(
                id, method, params, client_rx, cancel_rx, writer,
            )),
            None => self.handle_notification(method, params),
        }
    }

    pub fn serve_stdio<R: BufRead + Send + 'static, W: Write>(
        &mut self,
        reader: R,
        mut writer: W,
    ) -> Result<(), AdapterError> {
        let (client_tx, client_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = mpsc::channel();
        std::thread::spawn(move || pump_client_messages(reader, client_tx, cancel_tx));

        self.serve_inbound_loop(&client_rx, &cancel_rx, &mut writer)
    }

    pub fn serve_message_channels<W: Write>(
        &mut self,
        client_rx: mpsc::Receiver<Value>,
        mut writer: W,
    ) -> Result<(), AdapterError> {
        let (inbound_tx, inbound_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = mpsc::channel();
        std::thread::spawn(move || pump_channel_messages(client_rx, inbound_tx, cancel_tx));

        self.serve_inbound_loop(&inbound_rx, &cancel_rx, &mut writer)
    }

    fn serve_inbound_loop<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        loop {
            self.forward_runtime_events();
            self.flush_pending_notifications(writer)?;

            if let Some(message) = self.take_deferred_client_message() {
                let response = self
                    .handle_jsonrpc_with_transport_channel(message, client_rx, cancel_rx, writer);
                self.process_pending_actions_with_channel(client_rx, writer)?;
                self.forward_runtime_events();
                self.flush_pending_notifications(writer)?;
                if let Some(response) = response {
                    write_jsonrpc_line(writer, &response)?;
                }
                self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                continue;
            }

            match client_rx.recv_timeout(CLIENT_IDLE_POLL_INTERVAL) {
                Ok(ClientInbound::Message(message)) => {
                    let response = self.handle_jsonrpc_with_transport_channel(
                        message, client_rx, cancel_rx, writer,
                    );
                    self.process_pending_actions_with_channel(client_rx, writer)?;
                    self.forward_runtime_events();
                    self.flush_pending_notifications(writer)?;
                    if let Some(response) = response {
                        write_jsonrpc_line(writer, &response)?;
                    }
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                }
                Ok(ClientInbound::ParseError(error)) => {
                    write_jsonrpc_line(
                        writer,
                        &jsonrpc_error(Value::Null, -32700, &format!("invalid JSON: {error}")),
                    )?;
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                }
                Ok(ClientInbound::ReadError(error)) => {
                    return Err(AdapterError::ConnectionFailed(format!(
                        "failed to read MCP edge request: {error}"
                    )));
                }
                Ok(ClientInbound::Closed) => {
                    self.forward_runtime_events();
                    self.flush_pending_notifications(writer)?;
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.service_background_runtime_with_channel(client_rx, cancel_rx, writer)?;
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }

    fn handle_request(&mut self, id: Value, method: &str, params: Value) -> Value {
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

    // Retained for embedders that drive the edge through a custom transport
    // loop instead of the default session-owned path.
    #[allow(dead_code)]
    fn handle_request_with_transport<R: BufRead, W: Write>(
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

    fn handle_request_with_transport_channel<W: Write>(
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

    fn handle_notification(&mut self, method: &str, _params: Value) -> Option<Value> {
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

    fn handle_initialize(&mut self, id: Value, params: Value) -> Value {
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

        let session_id = self
            .kernel
            .open_session(self.agent_id.clone(), self.capabilities.clone());
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

    fn handle_tools_list(&mut self, id: Value, params: Value) -> Value {
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

    fn prepare_tool_call_request(
        &mut self,
        id: &Value,
        params: &Value,
    ) -> Result<(SessionId, OperationContext, ToolCallOperation), Value> {
        let session_id = match &self.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_SERVER_NOT_INITIALIZED,
                    "tools/call requires initialize followed by notifications/initialized",
                ))
            }
        };

        let tool_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "tools/call requires a tool name",
                ))
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let model_metadata = parse_request_model_metadata(id, params)?;

        let Some(&tool_index) = self.tool_index.get(tool_name) else {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "unknown tool",
            ));
        };
        let binding = self.tools[tool_index].clone();

        let capability = match select_capability_for_request(
            &self.capabilities,
            &binding.tool_name,
            &binding.server_id,
            &arguments,
            model_metadata.as_ref(),
        ) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_denied",
                        "tool": binding.tool_name,
                        "server": binding.server_id,
                    }),
                );
                return Err(jsonrpc_result(
                    id.clone(),
                    tool_error_result("tool is not authorized by the active capability set"),
                ));
            }
        };

        let request_id = self.next_request_id();
        let context =
            build_operation_context(id, session_id.clone(), request_id, &self.agent_id, params)?;

        Ok((
            session_id,
            context,
            ToolCallOperation {
                capability,
                server_id: binding.server_id,
                tool_name: binding.tool_name,
                arguments,
                model_metadata,
            },
        ))
    }

    fn evaluate_tool_call_operation(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let operation = SessionOperation::ToolCall(operation.clone());
        match self.kernel.evaluate_session_operation(context, &operation) {
            Ok(SessionOperationResponse::ToolCall(response)) => self
                .tool_result_for_kernel_response(KernelToolResultArgs {
                    client_request_id: id,
                    session_id,
                    output: response.output,
                    reason: response.reason,
                    verdict: response.verdict,
                    terminal_state: &response.terminal_state,
                    related_task_id,
                }),
            Ok(
                SessionOperationResponse::RootList { .. }
                | SessionOperationResponse::ResourceList { .. }
                | SessionOperationResponse::ResourceRead { .. }
                | SessionOperationResponse::ResourceReadDenied { .. }
                | SessionOperationResponse::ResourceTemplateList { .. }
                | SessionOperationResponse::PromptList { .. }
                | SessionOperationResponse::PromptGet { .. }
                | SessionOperationResponse::Completion { .. }
                | SessionOperationResponse::CapabilityList { .. }
                | SessionOperationResponse::Heartbeat,
            ) => ToolCallEdgeOutcome::JsonRpcError {
                code: JSONRPC_INTERNAL_ERROR,
                message: "unexpected kernel response type".to_string(),
                data: None,
            },
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        }
    }

    fn evaluate_tool_call_operation_with_transport<R: BufRead, W: Write>(
        &mut self,
        request: ToolCallRequestContext<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = EdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            reader,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    fn evaluate_tool_call_operation_with_transport_channel<W: Write>(
        &mut self,
        request: ToolCallRequestContext<'_>,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = QueuedEdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            client_rx,
            cancel_rx,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("mcp-edge-task-{}", self.task_counter)
    }

    fn create_tool_call_task(
        &mut self,
        id: Value,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        requested_task: RequestedTask,
        queue_background: bool,
    ) -> Value {
        let task_id = self.next_task_id();
        let task = EdgeTask::new(
            task_id.clone(),
            session_id,
            context,
            operation,
            requested_task.ttl,
            self.background_task_start_delay_millis(),
        );
        let task_view = task.clone();
        self.tasks.insert(task_id, task);
        if queue_background {
            self.pending_background_tasks
                .push(task_view.task_id.clone());
        }
        jsonrpc_result(id, json!({ "task": task_view }))
    }

    fn background_task_start_delay_millis(&self) -> u64 {
        match self.session_auth_context.transport {
            SessionTransport::StreamableHttp => TASK_POLL_INTERVAL_MILLIS,
            SessionTransport::InProcess | SessionTransport::Stdio => 0,
        }
    }

    fn handle_tools_call(&mut self, id: Value, params: Value) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation(&id, &session_id, &context, &operation, None),
        )
    }

    // Retained for embedders that drive the edge through a custom transport
    // loop instead of the default session-owned path.
    #[allow(dead_code)]
    fn handle_tools_call_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                false,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                reader,
                writer,
            ),
        )
    }

    fn handle_tools_call_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                client_rx,
                cancel_rx,
                writer,
            ),
        )
    }

    fn handle_tasks_list(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let tasks = self
            .tasks
            .values()
            .filter(|task| task.session_id == session_id)
            .cloned()
            .collect::<Vec<_>>();
        if start > tasks.len() {
            return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
        }

        let page_size = self.config.page_size.max(1);
        let end = (start + page_size).min(tasks.len());
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        jsonrpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
                "total": tasks.len(),
            }),
        )
    }

    fn handle_tasks_get(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        jsonrpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    fn handle_tasks_cancel(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(mut task) = self.tasks.remove(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            self.tasks.insert(task_id, task);
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }
        if task.is_terminal() {
            let status = task.status;
            let task_view = task.clone();
            self.tasks.insert(task_id, task);
            return match status {
                EdgeTaskStatus::Cancelled => jsonrpc_result(
                    id,
                    serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
                ),
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!(
                        "cannot cancel task: already in terminal status '{}'",
                        edge_task_status_label(status)
                    ),
                ),
            };
        }

        task.mark_cancelled("task cancelled by client");
        self.dequeue_background_task(&task_id);
        let task_view = task.clone();
        self.queue_task_status_notification(&task_view);
        self.tasks.insert(task_id, task);
        jsonrpc_result(
            id,
            serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
        )
    }

    fn handle_tasks_result(&mut self, id: Value, params: Value) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation(
                &id,
                &session_id,
                &task.context,
                &task.operation,
                Some(task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_tasks_result_with_transport<R: BufRead, W: Write>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task_id.as_str()),
                },
                reader,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_tasks_result_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task_id.as_str()),
                },
                client_rx,
                cancel_rx,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    fn handle_resources_list(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_resource_templates_list(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_resources_read(&mut self, id: Value, params: Value) -> Value {
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
                    Decision::Deny { reason, .. } => reason.clone(),
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

    fn handle_resources_subscribe(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_resources_unsubscribe(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_prompts_list(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_prompts_get(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_completion(&mut self, id: Value, params: Value) -> Value {
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

    fn handle_logging_set_level(&mut self, id: Value, params: Value) -> Value {
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

    pub fn create_message<R: BufRead, W: Write>(
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

    // Retained for embedders that drive the edge through a custom transport
    // loop instead of the default session-owned path.
    #[allow(dead_code)]
    fn process_pending_actions<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        while let Some(action) = self.pending_actions.pop() {
            match action {
                EdgeAction::RefreshRoots { session_id, reason } => {
                    if let Err(error) = self.refresh_roots_from_client(&session_id, reader, writer)
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

    fn process_pending_actions_with_channel<W: Write>(
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

    fn queue_roots_refresh(&mut self, session_id: SessionId, reason: &'static str) {
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

    // Retained for embedders that drive the edge through a custom transport
    // loop instead of the default session-owned path.
    #[allow(dead_code)]
    fn refresh_roots_from_client<R: BufRead, W: Write>(
        &mut self,
        session_id: &SessionId,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let result = self.send_client_request(reader, writer, "roots/list", json!({}))?;
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

    fn refresh_roots_from_client_with_channel<W: Write>(
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

    fn send_client_request<R: BufRead, W: Write>(
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

    fn send_client_request_with_channel<W: Write>(
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

    fn next_request_id(&mut self) -> String {
        self.request_counter += 1;
        format!("mcp-edge-req-{}", self.request_counter)
    }

    fn visible_tools(&self) -> Vec<&ExposedToolBinding> {
        self.tools
            .iter()
            .filter(|binding| tool_is_authorized(&self.capabilities, binding))
            .collect()
    }

    fn ready_session_id(&self, id: &Value) -> Result<SessionId, Value> {
        match &self.state {
            EdgeState::Ready { session_id } => Ok(session_id.clone()),
            _ => Err(jsonrpc_error(
                id.clone(),
                JSONRPC_SERVER_NOT_INITIALIZED,
                "operation requires initialize followed by notifications/initialized",
            )),
        }
    }

    fn has_completion_support(&self) -> bool {
        self.config.completion_enabled.unwrap_or_else(|| {
            self.kernel.resource_provider_count() > 0 || self.kernel.prompt_provider_count() > 0
        })
    }

    fn peer_supports_chio_tool_streaming(&self, session_id: &SessionId) -> bool {
        self.kernel
            .session(session_id)
            .map(|session| session.peer_capabilities().supports_chio_tool_streaming)
            .unwrap_or(false)
    }

    fn tool_result_for_kernel_response(
        &mut self,
        args: KernelToolResultArgs<'_>,
    ) -> ToolCallEdgeOutcome {
        let KernelToolResultArgs {
            client_request_id,
            session_id,
            output,
            reason,
            verdict,
            terminal_state,
            related_task_id,
        } = args;
        let peer_supports_chio_tool_streaming = self.peer_supports_chio_tool_streaming(session_id);
        let result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
            pending_notifications: &mut self.pending_notifications,
            request_id: client_request_id,
            output,
            reason,
            verdict,
            terminal_state,
            peer_supports_chio_tool_streaming,
            related_task_id,
        });

        if let Some(reason) = cancellation_reason_from_tool_result(&result) {
            return ToolCallEdgeOutcome::Cancelled { reason };
        }

        match terminal_state {
            OperationTerminalState::Cancelled { reason } => ToolCallEdgeOutcome::Cancelled {
                reason: reason.clone(),
            },
            _ => ToolCallEdgeOutcome::Result(result),
        }
    }

    fn tool_call_error_outcome(
        &mut self,
        session_id: &SessionId,
        error: chio_kernel::KernelError,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        match error {
            chio_kernel::KernelError::RequestCancelled { reason, .. } => {
                ToolCallEdgeOutcome::Cancelled { reason }
            }
            chio_kernel::KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                if let Err(register_error) = self.kernel.register_session_required_url_elicitations(
                    session_id,
                    &elicitations,
                    related_task_id,
                ) {
                    self.emit_log_with_related_task(
                        LogLevel::Warning,
                        "chio.mcp.elicitation",
                        json!({
                            "event": "session_elicitation_registration_failed",
                            "error": register_error.to_string(),
                        }),
                        related_task_id,
                    );
                }
                ToolCallEdgeOutcome::JsonRpcError {
                    code: JSONRPC_URL_ELICITATION_REQUIRED,
                    message,
                    data: Some(json!({ "elicitations": elicitations })),
                }
            }
            other => ToolCallEdgeOutcome::Result(tool_error_result(&other.to_string())),
        }
    }

    fn persist_accepted_url_elicitations(
        &mut self,
        session_id: &SessionId,
        accepted_url_elicitations: Vec<AcceptedUrlElicitation>,
    ) {
        for accepted in accepted_url_elicitations {
            if let Err(error) = self.kernel.register_session_pending_url_elicitation(
                session_id,
                accepted.elicitation_id,
                accepted.related_task_id,
            ) {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.elicitation",
                    json!({
                        "event": "session_elicitation_registration_failed",
                        "error": error.to_string(),
                    }),
                );
            }
        }
    }

    fn emit_log(&mut self, level: LogLevel, logger: &str, data: Value) {
        self.emit_log_with_related_task(level, logger, data, None);
    }

    fn emit_log_with_related_task(
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

    fn current_ready_session_id(&self) -> Option<SessionId> {
        match &self.state {
            EdgeState::Ready { session_id } => Some(session_id.clone()),
            _ => None,
        }
    }

    fn queue_session_tool_server_event(&mut self, event: ToolServerEvent) {
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

    fn flush_session_late_events(&mut self, session_id: &SessionId) {
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

    fn queue_task_status_notification(&mut self, task: &EdgeTask) {
        self.pending_notifications.push(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks/status",
            "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
        }));
    }

    fn take_deferred_client_message(&mut self) -> Option<Value> {
        if self.deferred_client_messages.is_empty() {
            None
        } else {
            Some(self.deferred_client_messages.remove(0))
        }
    }

    fn dequeue_background_task(&mut self, task_id: &str) {
        self.pending_background_tasks
            .retain(|pending| pending != task_id);
    }

    fn process_background_tasks_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &Value::String(task.task_id.clone()),
                    session_id: &task.session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task.task_id.as_str()),
                },
                client_rx,
                cancel_rx,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    fn process_background_tasks(&mut self) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation(
                &Value::String(task.task_id.clone()),
                &task.session_id,
                &task.context,
                &task.operation,
                Some(task.task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    fn service_background_runtime_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let _ = self.process_background_tasks_with_channel(client_rx, cancel_rx, writer)?;
        self.process_pending_actions_with_channel(client_rx, writer)?;
        self.forward_runtime_events();
        self.flush_pending_notifications(writer)?;
        Ok(())
    }

    fn take_pending_notifications(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending_notifications)
    }

    fn flush_pending_notifications<W: Write>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        for notification in self.take_pending_notifications() {
            write_jsonrpc_line(writer, &notification)?;
        }
        Ok(())
    }

    fn forward_tool_server_events(&mut self) {
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

    fn forward_runtime_events(&mut self) {
        self.forward_tool_server_events();
        self.forward_upstream_notifications();
    }

    fn forward_upstream_notifications(&mut self) {
        let Some(transport) = self.upstream_transport.as_ref() else {
            return;
        };

        for notification in transport.drain_notifications() {
            self.handle_upstream_transport_notification(notification);
        }
    }

    fn handle_upstream_transport_notification(&mut self, notification: Value) {
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

#[cfg(test)]
#[path = "runtime/runtime_tests.rs"]
mod runtime_tests;
