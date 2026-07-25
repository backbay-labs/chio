use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::{AdapterError, McpTransport};
use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::{ModelMetadata, Operation},
    supplemental_authorization::OpaqueSupplementalAuthorization,
    token::CapabilityToken,
};
use chio_core::receipt::decision::Decision;
use chio_core::session::{
    CompleteOperation, CompletionArgument, CompletionReference, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, ElicitationAction,
    GetPromptOperation, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, ReadResourceOperation, RequestId, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, RootDefinition, SessionAuthContext, SessionId, SessionOperation,
    SessionTransport, TaskOwnershipSnapshot, ToolCallOperation,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::{
    kernel_tool_call_request, metadata_with_source_receipt_context, CrossProtocolTargetExecution,
    CrossProtocolTargetRequest, TargetExecutionHop, TargetProtocolExecutor,
};
use chio_cross_protocol::routing::route_selection_metadata;
use chio_kernel::{
    ChioKernel, LateSessionEvent, NestedFlowClient, PeerCapabilities, SessionOperationResponse,
    SignedExecutionNonce, ToolCallOutput, ToolCallRequest, ToolCallResponse, ToolCallStream,
    ToolServerEvent, Verdict,
};
use chio_manifest::ToolManifest;
#[cfg(test)]
use chio_manifest::{LatencyHint, ToolDefinition};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[path = "runtime/discovery.rs"]
mod discovery;
#[path = "runtime/errors.rs"]
mod errors;
#[path = "runtime/framing.rs"]
pub(crate) mod framing;
#[path = "runtime/jsonrpc.rs"]
mod jsonrpc;
#[path = "runtime/nested_flow.rs"]
mod nested_flow;
#[path = "runtime/protocol.rs"]
mod protocol;
#[path = "runtime/receipts.rs"]
mod receipts;
#[path = "runtime/requests.rs"]
mod requests;
#[path = "runtime/runtime_flow.rs"]
mod runtime_flow;
#[path = "runtime/state.rs"]
mod state;
#[path = "runtime/tasks.rs"]
mod tasks;
#[path = "runtime/tool_calls.rs"]
pub(crate) mod tool_calls;

pub use discovery::McpExposedTool;
use discovery::{build_exposed_tool_bindings, ExposedToolBinding};
use jsonrpc::negotiate_protocol_version;
use nested_flow::*;
use protocol::*;
use state::{EdgeAction, EdgeState, LogLevel};
use tasks::{EdgeTask, EdgeTaskFinalOutcome, EdgeTaskStatus, ToolCallEdgeOutcome};
#[cfg(test)]
use tool_calls::{
    execute_bridge_mcp_tool_call, execute_bridge_mcp_tool_call_async, BridgeMcpToolCall,
    BridgeMcpToolCallRequest,
};

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
const MAX_DEFERRED_MCP_TASKS: usize = 1024;
const DEFAULT_MCP_TASK_TTL_MILLIS: u64 = 5 * 60 * 1000;
const MAX_MCP_TASK_TTL_MILLIS: u64 = 60 * 60 * 1000;

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

pub struct ChioMcpEdge {
    config: McpEdgeConfig,
    kernel: ChioKernel,
    agent_id: String,
    session_auth_context: SessionAuthContext,
    capabilities: Vec<CapabilityToken>,
    tools: Vec<ExposedToolBinding>,
    tool_index: BTreeMap<String, usize>,
    initial_session_id: Option<SessionId>,
    child_request_counter: u64,
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
        let (tools, tool_index) = build_exposed_tool_bindings(manifests)?;

        Ok(Self {
            config,
            kernel,
            agent_id,
            session_auth_context: SessionAuthContext::stdio_anonymous(),
            capabilities,
            tools,
            tool_index,
            initial_session_id: None,
            child_request_counter: 0,
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

    pub fn set_initial_session_id(&mut self, session_id: SessionId) -> Result<(), AdapterError> {
        if !matches!(self.state, EdgeState::Uninitialized) {
            return Err(AdapterError::ParseError(
                "initial session id must be configured before MCP initialization".to_string(),
            ));
        }
        self.initial_session_id = Some(session_id);
        Ok(())
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
        let JsonRpcEnvelope { id, method, params } = match parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(response) => return Some(response),
        };
        match id {
            Some(id) => {
                if let Err(response) = ensure_known_request_params_object(&id, &method, &params) {
                    return Some(response);
                }
                Some(self.handle_request(id, &method, params))
            }
            None => self.handle_known_notification(&method, params),
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

    // Reader/writer transport variant: used by the blocking `send_client_request`
    // loop that drives nested client requests over an owned reader/writer pair.
    fn handle_jsonrpc_with_transport<R: BufRead + Send, W: Write + Send>(
        &mut self,
        message: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Option<Value> {
        let JsonRpcEnvelope { id, method, params } = match parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(response) => return Some(response),
        };
        match id {
            Some(id) => {
                if let Err(response) = ensure_known_request_params_object(&id, &method, &params) {
                    return Some(response);
                }
                Some(self.handle_request_with_transport(id, &method, params, reader, writer))
            }
            None => self.handle_known_notification(&method, params),
        }
    }

    fn handle_jsonrpc_with_transport_channel<W: Write>(
        &mut self,
        message: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Option<Value> {
        let JsonRpcEnvelope { id, method, params } = match parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(response) => return Some(response),
        };
        match id {
            Some(id) => {
                if let Err(response) = ensure_known_request_params_object(&id, &method, &params) {
                    return Some(response);
                }
                Some(self.handle_request_with_transport_channel(
                    id, &method, params, client_rx, cancel_rx, writer,
                ))
            }
            None => self.handle_known_notification(&method, params),
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
}

#[cfg(test)]
#[path = "runtime/execution_nonce_tests.rs"]
mod execution_nonce_tests;

#[cfg(test)]
#[path = "runtime/runtime_tests.rs"]
mod runtime_tests;

#[cfg(test)]
#[path = "runtime/source_receipt_tests.rs"]
mod source_receipt_tests;
