//! # chio-a2a-edge
//!
//! Edge crate that exposes Chio tools as A2A (Agent-to-Agent) skills. This is
//! the reverse direction from `chio-a2a-adapter`: instead of consuming a remote
//! A2A server, this crate *serves* Chio tools to A2A clients.
//!
//! Responsibilities:
//!
//! 1. Publish an A2A Agent Card at `/.well-known/agent-card.json`.
//! 2. Accept `SendMessage` requests and route them through the Chio kernel by
//!    default.
//! 3. Expose a truthful blocking `message/send` surface plus deferred
//!    receipt-bearing `message/stream` task lifecycle.
//! 4. Evaluate `BridgeFidelity` per tool to signal translation quality.
//!
//! Kernel-backed entrypoints produce signed Chio receipts. Explicit passthrough
//! compatibility helpers remain available for bounded migration and tests, but
//! they are not the authoritative Chio trust path. The authoritative streaming
//! surface is truthful but bounded: `message/stream` creates a deferred task,
//! `task/get` resolves the terminal receipt-bearing result, and `task/cancel`
//! can cancel a deferred task before execution.

use std::collections::BTreeMap;

use chio_core::capability::{
    CapabilityToken, GovernedApprovalToken, GovernedTransactionIntent, ModelMetadata,
};
use chio_cross_protocol::{
    runtime_lifecycle_contract, runtime_lifecycle_metadata, semantic_hints_for_tool,
    target_protocol_for_tool_with_registry, BridgeError, BridgeFidelity, CapabilityBridge,
    CrossProtocolCapabilityRef, CrossProtocolExecutionRequest, CrossProtocolOrchestrator,
    DiscoveryProtocol, OpenAiTargetExecutor, OrchestratedToolCall, RuntimeLifecycleSurface,
    TargetProtocolRegistry,
};
#[cfg(any(test, feature = "compatibility-surface"))]
use chio_kernel::ToolServerConnection;
use chio_kernel::{dpop, ChioKernel, ToolCallOutput, Verdict as KernelVerdict};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::McpTargetExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(feature = "otel")]
pub mod otel;

/// Errors produced by the A2A edge.
#[derive(Debug, thiserror::Error)]
pub enum A2aEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest construction failed.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),

    /// Cross-protocol orchestration failed.
    #[error("bridge error: {0}")]
    Bridge(#[from] chio_cross_protocol::BridgeError),
}

/// Configuration for the A2A edge.
#[derive(Debug, Clone)]
pub struct A2aEdgeConfig {
    /// Name to advertise in the Agent Card.
    pub agent_name: String,
    /// Description for the Agent Card.
    pub agent_description: String,
    /// Version of the agent.
    pub agent_version: String,
    /// URL where the A2A endpoint is hosted.
    pub endpoint_url: String,
    /// Protocol binding (default: "JSONRPC").
    pub protocol_binding: String,
}

impl Default for A2aEdgeConfig {
    fn default() -> Self {
        Self {
            agent_name: "Chio A2A Edge".to_string(),
            agent_description: "Chio-governed tools exposed as A2A skills".to_string(),
            agent_version: "0.1.0".to_string(),
            endpoint_url: "http://localhost:8080".to_string(),
            protocol_binding: "JSONRPC".to_string(),
        }
    }
}

/// A skill entry in the A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSkillEntry {
    /// Skill identifier (matches the Chio tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what the skill does.
    pub description: String,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Example inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Input modes supported.
    pub input_modes: Vec<String>,
    /// Output modes supported.
    pub output_modes: Vec<String>,
    /// Fidelity assessment.
    pub bridge_fidelity: BridgeFidelity,
}

/// An A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent name.
    pub name: String,
    /// Agent description.
    pub description: String,
    /// Agent version.
    pub version: String,
    /// Supported interfaces.
    pub supported_interfaces: Vec<AgentInterface>,
    /// Capabilities.
    pub capabilities: AgentCapabilities,
    /// Default input modes.
    pub default_input_modes: Vec<String>,
    /// Default output modes.
    pub default_output_modes: Vec<String>,
    /// Skills (tools exposed as A2A skills).
    pub skills: Vec<A2aSkillEntry>,
}

/// An A2A interface definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// URL for the A2A endpoint.
    pub url: String,
    /// Protocol binding.
    pub protocol_binding: String,
    /// Protocol version.
    pub protocol_version: String,
}

/// A2A agent capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether streaming is supported.
    #[serde(default)]
    pub streaming: bool,
    /// Whether push notifications are supported.
    #[serde(default)]
    pub push_notifications: bool,
    /// Whether state transition history is tracked.
    #[serde(default)]
    pub state_transition_history: bool,
}

/// An A2A SendMessage request (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    /// The message to send.
    pub message: A2aMessage,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// An A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    /// Role of the message sender.
    pub role: String,
    /// Message parts.
    pub parts: Vec<A2aPart>,
    /// Optional message metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A single part of an A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum A2aPart {
    /// A text part.
    #[serde(rename = "text")]
    Text { text: String },
    /// A structured data part.
    #[serde(rename = "data")]
    Data { data: Value },
}

/// A2A task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

/// An A2A task response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    /// Task identifier.
    pub id: String,
    /// Current status.
    pub status: TaskStatus,
    /// Optional status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// The result message (present when completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    /// Chio metadata such as signed receipts when the kernel path is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone)]
struct DeferredA2aTask {
    owner_agent_id: String,
    request: CrossProtocolExecutionRequest,
    response: TaskResponse,
}

/// Execution context required for kernel-mediated A2A invocations.
#[derive(Debug, Clone)]
pub struct A2aKernelExecutionContext {
    /// The signed capability token authorizing this invocation.
    pub capability: CapabilityToken,
    /// The authenticated calling agent identifier.
    pub agent_id: String,
    /// Optional DPoP proof when the matched grant requires sender binding.
    pub dpop_proof: Option<dpop::DpopProof>,
    /// Optional governed transaction intent carried with this invocation.
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token for governed transaction execution.
    pub approval_token: Option<GovernedApprovalToken>,
    /// Optional metadata about the model that originated this invocation.
    pub model_metadata: Option<ModelMetadata>,
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

struct A2aCapabilityBridge;

static MCP_TARGET_EXECUTOR: McpTargetExecutor = McpTargetExecutor {
    peer_supports_chio_tool_streaming: false,
};
static OPENAI_TARGET_EXECUTOR: OpenAiTargetExecutor = OpenAiTargetExecutor;

#[derive(Debug, Clone)]
struct SkillBinding {
    target_protocol: DiscoveryProtocol,
    server_id: String,
    tool_name: String,
}

#[derive(Debug, Clone)]
struct SkillCandidate {
    published_id: String,
    lookup_alias: Option<String>,
    display_name: String,
    description: String,
    tags: Vec<String>,
    fidelity: BridgeFidelity,
    binding: Option<SkillBinding>,
}

impl CapabilityBridge for A2aCapabilityBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::A2a
    }

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError> {
        request
            .pointer("/metadata/chio/capabilityRef")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let chio_metadata = ensure_chio_metadata(envelope)?;
        chio_metadata.insert(
            "capabilityRef".to_string(),
            serde_json::to_value(cap_ref)
                .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
        );
        Ok(())
    }

    fn protocol_context(&self, request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(request
            .pointer("/metadata/chio/targetSkillId")
            .and_then(Value::as_str)
            .map(|skill_id| json!({ "targetSkillId": skill_id })))
    }
}

impl ChioA2aEdge {
    /// Create a new A2A edge from Chio tool manifests.
    pub fn new(config: A2aEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, A2aEdgeError> {
        let mut skills = Vec::new();
        let mut skill_fidelity = BTreeMap::new();
        let mut skill_bindings = BTreeMap::new();
        let mut ambiguous_skill_ids = BTreeMap::new();
        let mut tool_name_counts = BTreeMap::new();
        let mut published_id_counts = BTreeMap::new();

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
        let binding = self.resolve_skill_binding(skill_id)?;

        let arguments = extract_arguments_from_message(&request.message);
        let task_id = self.next_task_id();
        let request = CrossProtocolExecutionRequest {
            origin_request_id: task_id.clone(),
            kernel_request_id: format!("a2a-{task_id}"),
            target_protocol: binding.target_protocol,
            target_server_id: binding.server_id,
            target_tool_name: binding.tool_name,
            agent_id: execution.agent_id.clone(),
            arguments,
            capability: execution.capability.clone(),
            source_envelope: build_a2a_source_envelope(skill_id, request)?,
            dpop_proof: execution.dpop_proof.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            model_metadata: execution.model_metadata.clone(),
        };
        let orchestrated = execute_orchestrated_a2a_request(kernel, request)?;
        Ok(task_response_from_orchestrated(task_id, orchestrated))
    }

    /// Start an authoritative deferred task for A2A streaming/task lifecycle.
    pub fn handle_stream_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let binding = self.resolve_skill_binding(skill_id)?;
        let task_id = self.next_task_id();
        let orchestrated_request = CrossProtocolExecutionRequest {
            origin_request_id: task_id.clone(),
            kernel_request_id: format!("a2a-stream-{task_id}"),
            target_protocol: binding.target_protocol,
            target_server_id: binding.server_id,
            target_tool_name: binding.tool_name,
            agent_id: execution.agent_id.clone(),
            arguments: extract_arguments_from_message(&request.message),
            capability: execution.capability.clone(),
            source_envelope: build_a2a_source_envelope(skill_id, request)?,
            dpop_proof: execution.dpop_proof.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            model_metadata: execution.model_metadata.clone(),
        };

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

        let arguments = extract_arguments_from_message(&request.message);
        let task_id = self.next_task_id();

        match server.invoke(&tool_name, arguments, None) {
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

    /// Back-compat alias for callers that already adopted the explicit kernel helper name.
    pub fn handle_send_message_with_kernel(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Result<TaskResponse, A2aEdgeError> {
        self.handle_send_message(skill_id, request, kernel, execution)
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
    ) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
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
        }
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
    ) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
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
        }
    }

    /// Back-compat alias for callers that already adopted the explicit kernel helper name.
    pub fn handle_jsonrpc_with_kernel(
        &mut self,
        message: Value,
        kernel: &ChioKernel,
        execution: &A2aKernelExecutionContext,
    ) -> Value {
        self.handle_jsonrpc(message, kernel, execution)
    }

    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_send_message_passthrough(
        &mut self,
        id: Value,
        params: Value,
        server: &dyn ToolServerConnection,
    ) -> Value {
        let skill_id_from_metadata = params
            .get("metadata")
            .and_then(|m| m.get("chio"))
            .and_then(|a| a.get("targetSkillId"))
            .and_then(Value::as_str)
            .map(String::from);

        let skill_id = skill_id_from_metadata.or_else(|| {
            // Try to find a single skill if there's only one
            if self.skills.len() == 1 {
                self.skills.first().map(|s| s.id.clone())
            } else {
                None
            }
        });

        let Some(skill_id) = skill_id else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "metadata.chio.targetSkillId is required when multiple skills are exposed"
                }
            });
        };

        let request = match serde_json::from_value::<SendMessageRequest>(params.clone()) {
            Ok(req) => req,
            Err(e) => {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32602,
                        "message": format!("invalid SendMessage request: {e}")
                    }
                });
            }
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
        let skill_id_from_metadata = params
            .get("metadata")
            .and_then(|m| m.get("chio"))
            .and_then(|a| a.get("targetSkillId"))
            .and_then(Value::as_str)
            .map(String::from);

        let skill_id = skill_id_from_metadata.or_else(|| {
            if self.skills.len() == 1 {
                self.skills.first().map(|s| s.id.clone())
            } else {
                None
            }
        });

        let Some(skill_id) = skill_id else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "metadata.chio.targetSkillId is required when multiple skills are exposed"
                }
            });
        };

        let request = match serde_json::from_value::<SendMessageRequest>(params.clone()) {
            Ok(req) => req,
            Err(error) => {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32602,
                        "message": format!("invalid SendMessage request: {error}")
                    }
                });
            }
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
        let skill_id_from_metadata = params
            .get("metadata")
            .and_then(|m| m.get("chio"))
            .and_then(|a| a.get("targetSkillId"))
            .and_then(Value::as_str)
            .map(String::from);

        let skill_id = skill_id_from_metadata.or_else(|| {
            if self.skills.len() == 1 {
                self.skills.first().map(|s| s.id.clone())
            } else {
                None
            }
        });

        let Some(skill_id) = skill_id else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "metadata.chio.targetSkillId is required when multiple skills are exposed"
                }
            });
        };

        let request = match serde_json::from_value::<SendMessageRequest>(params.clone()) {
            Ok(req) => req,
            Err(error) => {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32602,
                        "message": format!("invalid SendStreamingMessage request: {error}")
                    }
                });
            }
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
        let Some(task_id) = params.get("taskId").and_then(Value::as_str) else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "task/get requires params.taskId"
                }
            });
        };

        match self.resolve_task(task_id, execution) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
            }),
            Err(A2aEdgeError::InvalidRequest(_)) if self.tasks.contains_key(task_id) => {
                self.complete_task(task_id, kernel, execution, id)
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

        let orchestrated = match execute_orchestrated_a2a_request(kernel, task.request) {
            Ok(orchestrated) => orchestrated,
            Err(error) => return Self::jsonrpc_error_response(id, error),
        };
        let response = task_response_from_orchestrated(task_id.to_string(), orchestrated);
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.response = response.clone();
        }
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
        let Some(task_id) = params.get("taskId").and_then(Value::as_str) else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "task/cancel requires params.taskId"
                }
            });
        };

        let Some(task) = self.tasks.get_mut(task_id) else {
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
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": serde_json::to_value(&task.response).unwrap_or(Value::Null)
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

    /// Back-compat alias for older callers. Prefer
    /// [`handle_send_message_compatibility`] to make the non-authoritative
    /// passthrough surface explicit at the call site.
    #[deprecated(
        note = "use handle_send_message_compatibility to make the non-authoritative passthrough surface explicit"
    )]
    pub fn handle_send_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        self.handle_send_message_compatibility(skill_id, request, server)
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
    ) -> Value {
        self.edge.handle_jsonrpc_passthrough(message, server)
    }

    /// Back-compat alias for older callers. Prefer
    /// [`handle_jsonrpc_compatibility`] to make the non-authoritative
    /// passthrough surface explicit at the call site.
    #[deprecated(
        note = "use handle_jsonrpc_compatibility to make the non-authoritative passthrough surface explicit"
    )]
    pub fn handle_jsonrpc(&mut self, message: Value, server: &dyn ToolServerConnection) -> Value {
        self.handle_jsonrpc_compatibility(message, server)
    }
}

/// Evaluate how faithfully an Chio tool maps to A2A semantics.
fn evaluate_bridge_fidelity(
    tool: &ToolDefinition,
    target_protocol: DiscoveryProtocol,
) -> BridgeFidelity {
    let registry = authoritative_target_registry();
    let hints = semantic_hints_for_tool(tool);
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::A2aAuthoritative);
    if !hints.publish {
        return BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string(),
        };
    }
    if !registry.supports_target_protocol(target_protocol) {
        return BridgeFidelity::Unsupported {
            reason: format!(
                "A2A authoritative execution does not yet have a registered `{target_protocol}` target executor"
            ),
        };
    }
    if hints.approval_required {
        return BridgeFidelity::Unsupported {
            reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string(),
        };
    }
    let mut caveats = Vec::new();
    if tool.has_side_effects {
        caveats.push(
            "A2A publication cannot project protocol-native permission prompts; callers must rely on Chio capability enforcement".to_string(),
        );
    }
    if hints.streams_output {
        caveats.push(format!(
            "stream-capable tools execute through `{}` deferred tasks; output is surfaced on follow-up `{}` rather than incremental transport updates",
            lifecycle.stream_entrypoint, lifecycle.follow_up_entrypoint
        ));
        caveats.push(
            "stream chunks are collated into the terminal task payload instead of pushed as incremental A2A events".to_string(),
        );
    }
    if hints.partial_output {
        caveats.push(
            "partial output is preserved only in the terminal task payload, not incremental updates"
                .to_string(),
        );
    }
    if hints.supports_cancellation {
        caveats.push(format!(
            "cancellation is available only for deferred `{}` tasks; blocking `{}` remains terminal",
            lifecycle.stream_entrypoint, lifecycle.blocking_entrypoint
        ));
    }

    if caveats.is_empty() {
        BridgeFidelity::Lossless
    } else {
        BridgeFidelity::Adapted { caveats }
    }
}

fn build_skill_candidate(
    manifest: &ToolManifest,
    tool: &ToolDefinition,
    requires_qualification: bool,
) -> Result<SkillCandidate, A2aEdgeError> {
    let target_protocol =
        target_protocol_for_tool_with_registry(tool, &authoritative_target_registry())
            .map_err(A2aEdgeError::InvalidRequest)?;
    let fidelity = evaluate_bridge_fidelity(tool, target_protocol);
    let (published_id, lookup_alias, display_name, mut tags, description) =
        if requires_qualification {
            (
            format!("{}::{}", manifest.server_id, tool.name),
            Some(tool.name.clone()),
            format!("{} ({})", tool.name, manifest.server_id),
            vec!["chio:collision-qualified".to_string()],
            format!(
                "{} Published under a server-qualified skill id because this tool name collides across manifests.",
                tool.description
            ),
        )
        } else {
            (
                tool.name.clone(),
                None,
                tool.name.clone(),
                vec![],
                tool.description.clone(),
            )
        };

    if !fidelity.published_by_default() {
        tags.push("chio:publication-gated".to_string());
    }
    if target_protocol != DiscoveryProtocol::Native {
        tags.push(format!("chio:target-protocol:{target_protocol}"));
    }

    Ok(SkillCandidate {
        binding: fidelity.published_by_default().then(|| SkillBinding {
            target_protocol,
            server_id: manifest.server_id.clone(),
            tool_name: tool.name.clone(),
        }),
        published_id,
        lookup_alias,
        display_name,
        description,
        tags,
        fidelity,
    })
}

fn execute_orchestrated_a2a_request(
    kernel: &ChioKernel,
    request: CrossProtocolExecutionRequest,
) -> Result<OrchestratedToolCall, A2aEdgeError> {
    let registry = authoritative_target_registry();
    if !registry.supports_target_protocol(request.target_protocol) {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "A2A authoritative execution does not have a registered `{}` target executor",
            request.target_protocol
        )));
    }

    CrossProtocolOrchestrator::new(kernel)
        .with_registry(registry)
        .execute(&A2aCapabilityBridge, request)
        .map_err(Into::into)
}

fn authoritative_target_registry() -> TargetProtocolRegistry<'static> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native)
        .with_executor(&MCP_TARGET_EXECUTOR)
        .with_executor(&OPENAI_TARGET_EXECUTOR)
}

/// Extract arguments from A2A message parts.
fn extract_arguments_from_message(message: &A2aMessage) -> Value {
    let mut text_parts = Vec::new();
    let mut data_part = None;

    for part in &message.parts {
        match part {
            A2aPart::Text { text } => text_parts.push(text.clone()),
            A2aPart::Data { data } => data_part = Some(data.clone()),
        }
    }

    if let Some(data) = data_part {
        data
    } else {
        json!({
            "message": text_parts.join("\n"),
        })
    }
}

/// Convert a tool result to A2A message parts.
fn result_to_parts(result: &Value) -> Vec<A2aPart> {
    if let Some(text) = result.as_str() {
        vec![A2aPart::Text {
            text: text.to_string(),
        }]
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        content
            .iter()
            .filter_map(|c| {
                c.get("text")
                    .and_then(Value::as_str)
                    .map(|t| A2aPart::Text {
                        text: t.to_string(),
                    })
            })
            .collect()
    } else if result.is_object() || result.is_array() {
        vec![A2aPart::Data {
            data: result.clone(),
        }]
    } else {
        vec![A2aPart::Text {
            text: result.to_string(),
        }]
    }
}

fn task_response_from_orchestrated(
    task_id: String,
    orchestrated: OrchestratedToolCall,
) -> TaskResponse {
    let mut metadata = orchestrated.metadata();
    let response = orchestrated.response;
    annotate_authoritative_a2a_metadata(&mut metadata, response.output.as_ref());
    let receipt_metadata = Some(metadata);

    match response.verdict {
        KernelVerdict::Allow => TaskResponse {
            id: task_id,
            status: TaskStatus::Completed,
            status_message: None,
            message: Some(A2aMessage {
                role: "agent".to_string(),
                parts: kernel_output_to_parts(response.output.as_ref()),
                metadata: None,
            }),
            metadata: receipt_metadata,
        },
        KernelVerdict::Deny | KernelVerdict::PendingApproval => TaskResponse {
            id: task_id,
            status: TaskStatus::Failed,
            status_message: response.reason,
            message: None,
            metadata: receipt_metadata,
        },
    }
}

fn pending_task_metadata(authority_path: &str, message_stream: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "pending",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "compatibilityOnly": false,
            "claimEligible": true,
            "receiptBearing": false,
            "receiptPending": true,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": message_stream,
                "taskGet": "supported",
                "taskCancel": "supported"
            }
        }
    })
}

fn cancelled_task_metadata(authority_path: &str, message_stream: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "cancelled",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "compatibilityOnly": false,
            "claimEligible": true,
            "receiptBearing": false,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": message_stream,
                "taskGet": "supported",
                "taskCancel": "supported"
            }
        }
    })
}

fn kernel_output_to_parts(output: Option<&ToolCallOutput>) -> Vec<A2aPart> {
    match output {
        Some(ToolCallOutput::Value(value)) => result_to_parts(value),
        Some(ToolCallOutput::Stream(stream)) => stream
            .chunks
            .iter()
            .flat_map(|chunk| result_to_parts(&chunk.data))
            .collect(),
        None => vec![],
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
fn passthrough_metadata(reason: Option<&str>) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "passthrough",
            "capabilityId": Value::Null,
            "authorityPath": "passthrough_compatibility",
            "authoritative": false,
            "compatibilityOnly": true,
            "claimEligible": false,
            "receiptBearing": false,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aCompatibility),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": "unsupported"
            },
            "reason": reason,
        }
    })
}

fn annotate_authoritative_a2a_metadata(metadata: &mut Value, output: Option<&ToolCallOutput>) {
    let Some(chio_metadata) = metadata.get_mut("chio").and_then(Value::as_object_mut) else {
        return;
    };

    chio_metadata.insert(
        "lifecycle".to_string(),
        json!({
            "messageSend": "blocking_terminal_task",
            "messageStream": "deferred_task_poll",
            "taskGet": "supported",
            "taskCancel": "supported"
        }),
    );
    chio_metadata.insert(
        "a2aSurface".to_string(),
        Value::String("authoritative_blocking_send".to_string()),
    );
    chio_metadata.insert(
        "runtimeLifecycle".to_string(),
        runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
    );

    if matches!(output, Some(ToolCallOutput::Stream(_))) {
        chio_metadata.insert(
            "streamProjection".to_string(),
            Value::String("collated_final_message".to_string()),
        );
    }
}

fn build_a2a_source_envelope(
    skill_id: &str,
    request: &SendMessageRequest,
) -> Result<Value, A2aEdgeError> {
    let mut envelope = serde_json::to_value(request)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    let chio_metadata = ensure_chio_metadata(&mut envelope)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    chio_metadata.insert(
        "targetSkillId".to_string(),
        Value::String(skill_id.to_string()),
    );
    Ok(envelope)
}

fn ensure_chio_metadata(
    envelope: &mut Value,
) -> Result<&mut serde_json::Map<String, Value>, BridgeError> {
    let Some(object) = envelope.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "request envelope must be a JSON object".to_string(),
        ));
    };
    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| json!({}));
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "metadata must be a JSON object".to_string(),
        ));
    };
    let chio = metadata_obj
        .entry("chio".to_string())
        .or_insert_with(|| json!({}));
    chio.as_object_mut().ok_or_else(|| {
        BridgeError::InvalidRequest("metadata.chio must be a JSON object".to_string())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream,
        ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_manifest::LatencyHint;

    struct MockToolServer {
        server_id: String,
        tools: Vec<String>,
        response: Value,
    }

    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            &self.server_id
        }

        fn tool_names(&self) -> Vec<String> {
            self.tools.clone()
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(self.response.clone())
        }
    }

    struct FailingToolServer;

    impl ToolServerConnection for FailingToolServer {
        fn server_id(&self) -> &str {
            "fail-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["fail_tool".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::ToolServerError("simulated failure".into()))
        }
    }

    struct StreamingToolServer;

    impl ToolServerConnection for StreamingToolServer {
        fn server_id(&self) -> &str {
            "stream-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["stream".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(json!({"result": "fallback"}))
        }

        fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: vec![
                    ToolCallChunk {
                        data: json!("chunk-1"),
                    },
                    ToolCallChunk {
                        data: json!({"content": [{"type": "text", "text": "chunk-2"}]}),
                    },
                ],
            })))
        }
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test Server".to_string(),
            description: Some("Test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "echo".to_string(),
                    description: "Echo input".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write".to_string(),
                    description: "Write data".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
            ],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec!["echo".to_string(), "write".to_string()],
            response: json!({"result": "ok"}),
        }
    }

    fn stream_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "stream-srv".to_string(),
            name: "Stream Server".to_string(),
            description: Some("Streaming test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "stream".to_string(),
                description: "Stream output".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-streaming": true,
                    "x-chio-partial-output": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "stream".to_string(),
        }
    }

    fn approval_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "approve-srv".to_string(),
            name: "Approval Server".to_string(),
            description: Some("Approval test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "approve".to_string(),
                description: "Approval-gated operation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-approval-required": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "approve".to_string(),
        }
    }

    fn cancellation_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "cancel-srv".to_string(),
            name: "Cancellation Server".to_string(),
            description: Some("Cancel test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "cancel_me".to_string(),
                description: "Requires cancellation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-cancellation": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "cancel".to_string(),
        }
    }

    fn mcp_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "MCP Target Server".to_string(),
            description: Some("MCP target binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Echo via MCP target executor".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "mcp"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "mcp-target".to_string(),
        }
    }

    fn openai_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "OpenAI Target Server".to_string(),
            description: Some("OpenAI target binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Echo via OpenAI target executor".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "open_ai"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "openai-target".to_string(),
        }
    }

    fn invalid_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Invalid Target Server".to_string(),
            description: Some("Invalid protocol binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Invalid binding".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "smtp"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "invalid-target".to_string(),
        }
    }

    fn hidden_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "hidden-srv".to_string(),
            name: "Hidden Server".to_string(),
            description: Some("Hidden test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "hidden".to_string(),
                description: "Hidden from publication".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-publish": false
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "hidden".to_string(),
        }
    }

    fn text_message(text: &str) -> SendMessageRequest {
        SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![A2aPart::Text {
                    text: text.to_string(),
                }],
                metadata: None,
            },
            metadata: None,
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs()
    }

    fn test_kernel_config() -> KernelConfig {
        let keypair = Keypair::generate();
        KernelConfig {
            ca_public_keys: vec![keypair.public_key()],
            keypair,
            max_delegation_depth: 8,
            policy_hash: "policy-a2a-test".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> chio_core::capability::CapabilityToken {
        let now = unix_now();
        chio_core::capability::CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{server_id}-{tool_name}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: now.saturating_sub(30),
                expires_at: now + 300,
                delegation_chain: vec![],
            },
            issuer,
        )
        .expect("capability should sign")
    }

    // ---- Agent Card tests ----

    #[test]
    fn agent_card_has_correct_name() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "Chio A2A Edge");
    }

    #[test]
    fn agent_card_has_correct_version() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.version, "0.1.0");
    }

    #[test]
    fn agent_card_includes_all_skills() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.skills.len(), 2);
        assert!(card.skills.iter().any(|s| s.id == "echo"));
        assert!(card.skills.iter().any(|s| s.id == "write"));
    }

    #[test]
    fn agent_card_has_interface() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

    #[test]
    fn agent_card_json_serializes() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let json_str = edge.agent_card_json().unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["name"], "Chio A2A Edge");
    }

    #[test]
    fn agent_card_custom_config() {
        let config = A2aEdgeConfig {
            agent_name: "My Agent".to_string(),
            agent_description: "Custom agent".to_string(),
            agent_version: "2.0.0".to_string(),
            endpoint_url: "https://myagent.com".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
        };
        let edge = ChioA2aEdge::new(config, vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "My Agent");
        assert_eq!(card.description, "Custom agent");
        assert!(card.capabilities.streaming);
        assert_eq!(card.supported_interfaces[0].url, "https://myagent.com");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn read_only_tool_has_lossless_fidelity() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let skill = edge.skill("echo").unwrap();
        assert_eq!(skill.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn side_effect_tool_has_adapted_fidelity_with_permission_caveat() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let skill = edge.skill("write").unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("permission prompts") || c.contains("capability enforcement")));
    }

    #[test]
    fn approval_required_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![approval_manifest()]).unwrap();
        assert!(edge.skill("approve").is_none());
        assert_eq!(
            edge.bridge_fidelity("approve"),
            Some(&BridgeFidelity::Unsupported {
                reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string()
            })
        );
    }

    #[test]
    fn cancellation_tool_is_adapted_with_truthful_caveats() {
        let edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![cancellation_manifest()]).unwrap();
        let skill = edge.skill("cancel_me").unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c
                .contains("cancellation is available only for deferred `message/stream` tasks")));
    }

    #[test]
    fn hidden_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![hidden_manifest()]).unwrap();
        assert!(edge.skill("hidden").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    #[test]
    fn streaming_tool_is_adapted_with_truthful_caveats() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).unwrap();
        let skill = edge.skill("stream").unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats.iter().any(|c| c.contains("deferred tasks")));
        assert!(caveats.iter().any(|c| c.contains("terminal task payload")));
    }

    // ---- Skill lookup tests ----

    #[test]
    fn skill_ids_returns_all() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let ids = edge.skill_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn skill_returns_none_for_unknown() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert!(edge.skill("nonexistent").is_none());
    }

    // ---- SendMessage tests ----

    #[test]
    fn send_message_completes_successfully() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("hello");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        assert!(response.message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_returns_task_id() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("test");
        let r1 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .unwrap();
        let r2 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .unwrap();
        assert_ne!(r1.id, r2.id);
        assert!(r1.id.starts_with("a2a-task-"));
    }

    #[test]
    fn send_message_unknown_skill_errors() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("test");
        let err = edge
            .compatibility()
            .handle_send_message_compatibility("nonexistent", &request, &server)
            .unwrap_err();
        assert!(matches!(err, A2aEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn send_message_server_failure_returns_failed_task() {
        let server = FailingToolServer;
        // Need a manifest for the failing server
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).unwrap();
        let request = text_message("test");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("fail_tool", &request, &server)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        assert!(response.status_message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_with_kernel_emits_signed_receipt_metadata() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        let metadata = response
            .metadata
            .expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("a2a")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["lifecycle"]["messageSend"].as_str(),
            Some("blocking_terminal_task")
        );
        assert_eq!(
            metadata["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("deferred_task_poll")
        );
        assert_eq!(
            metadata["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_authoritative")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-echo")
        );
    }

    #[test]
    fn send_message_with_kernel_denial_still_returns_receipt_metadata() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("write", &text_message("blocked"), &kernel, &execution)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response.metadata.expect("deny path should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    }

    #[test]
    fn pending_approval_is_not_reported_as_completed() {
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let request = text_message("blocked pending approval");
        let mut orchestrated = execute_orchestrated_a2a_request(
            &kernel,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-pending".to_string(),
                kernel_request_id: "a2a-a2a-task-pending".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: extract_arguments_from_message(&request.message),
                capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
                source_envelope: build_a2a_source_envelope("echo", &request).unwrap(),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
            },
        )
        .unwrap();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.reason = Some("approval required".to_string());

        let response = task_response_from_orchestrated("task-pending".to_string(), orchestrated);
        let metadata = response
            .metadata
            .expect("pending approval should attach metadata");

        assert_eq!(response.status, TaskStatus::Failed);
        assert_eq!(
            response.status_message.as_deref(),
            Some("approval required")
        );
        assert!(response.message.is_none());
        assert_eq!(
            metadata["chio"]["decision"].as_str(),
            Some("pending_approval")
        );
    }

    #[test]
    fn send_message_kernel_failure_still_returns_receipt_metadata() {
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(FailingToolServer));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "fail-srv", "fail_tool"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("fail_tool", &text_message("boom"), &kernel, &execution)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response
            .metadata
            .expect("kernel failure should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
    }

    // ---- Message extraction tests ----

    #[test]
    fn extract_text_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: "hello world".to_string(),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["message"], "hello world");
    }

    #[test]
    fn extract_data_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!({"key": "value"}),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn extract_prefers_data_over_text() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![
                A2aPart::Text {
                    text: "hello".to_string(),
                },
                A2aPart::Data {
                    data: json!({"priority": "high"}),
                },
            ],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["priority"], "high");
    }

    // ---- Result conversion tests ----

    #[test]
    fn result_text_to_parts() {
        let parts = result_to_parts(&json!("hello"));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text part"),
        }
    }

    #[test]
    fn result_object_to_data_parts() {
        let parts = result_to_parts(&json!({"key": "value"}));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Data { data } => assert_eq!(data["key"], "value"),
            _ => panic!("expected data part"),
        }
    }

    #[test]
    fn result_content_array_to_text_parts() {
        let parts = result_to_parts(&json!({
            "content": [
                {"type": "text", "text": "part1"},
                {"type": "text", "text": "part2"},
            ]
        }));
        assert_eq!(parts.len(), 2);
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_send_message_single_skill() {
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1); // Only "echo"
                m
            }],
        )
        .unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_send_message_with_skill_id() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    },
                    "metadata": {
                        "chio": {"targetSkillId": "echo"}
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_missing_skill_id_with_multiple_skills_errors() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("error").is_some());
    }

    #[test]
    fn jsonrpc_unknown_method_returns_error() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "unknown/method",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn jsonrpc_passthrough_marks_compatibility_path() {
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
                m
            }],
        )
        .unwrap();
        let server = test_server();
        let response = edge.compatibility().handle_jsonrpc_compatibility(
            // This explicit compatibility wrapper remains available for bounded
            // migrations, but it is not the receipt-bearing trust path.
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &server,
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("unsupported")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_compatibility")
        );
    }

    #[test]
    fn jsonrpc_send_with_streaming_tool_collates_output_into_final_message() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            response["result"]["metadata"]["chio"]["streamProjection"].as_str(),
            Some("collated_final_message")
        );
        let parts = response["result"]["message"]["parts"]
            .as_array()
            .expect("stream response should contain parts");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "chunk-1");
        assert_eq!(parts[1]["text"], "chunk-2");
    }

    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_task_get_resolves_result() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["result"]["status"].as_str(), Some("working"));
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"].as_str(),
            Some("message/stream")
        );
        let task_id = response["result"]["id"]
            .as_str()
            .expect("message/stream should return task id")
            .to_string();
        assert_eq!(
            response["result"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
        assert_eq!(
            resolved["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        let parts = resolved["result"]["message"]["parts"]
            .as_array()
            .expect("resolved task should contain parts");
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn jsonrpc_task_cancel_marks_stream_task_cancelled() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = response["result"]["id"].as_str().unwrap().to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));
        assert_eq!(
            cancelled["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn authoritative_send_uses_protocol_aware_target_binding() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![mcp_target_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .unwrap();

        let metadata = response.metadata.unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["a2a", "mcp", "native"])
        );
    }

    #[test]
    fn authoritative_send_supports_openai_target_binding() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![openai_target_manifest()]).unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .unwrap();

        let metadata = response.metadata.unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn invalid_target_protocol_metadata_fails_closed() {
        let error =
            match ChioA2aEdge::new(A2aEdgeConfig::default(), vec![invalid_target_manifest()]) {
                Ok(_) => panic!("expected invalid target protocol metadata to fail"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- Error type tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = A2aEdgeError::ToolNotFound("missing".into());
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = A2aEdgeError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = A2aEdgeError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Duplicate skill handling ----

    #[test]
    fn duplicate_skills_across_manifests_receive_qualified_ids() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).unwrap();
        assert_eq!(edge.skill_ids().len(), 4);
        assert!(edge.skill("test-srv::echo").is_some());
        assert!(edge.skill("test-srv::echo#2").is_some());
        assert!(edge.skill("test-srv::write").is_some());
        assert!(edge.skill("test-srv::write#2").is_some());
        assert_eq!(
            edge.bridge_fidelity("echo"),
            Some(&BridgeFidelity::Unsupported {
                reason: "skill id collides across manifests; use one of the qualified ids: test-srv::echo, test-srv::echo#2".to_string()
            })
        );
    }

    #[test]
    fn ambiguous_unqualified_skill_id_returns_guidance() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).unwrap();
        let server = test_server();
        let error = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &text_message("hello"), &server)
            .unwrap_err();

        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request");
        };
        assert!(message.contains("ambiguous"));
        assert!(message.contains("test-srv::echo"));
        assert!(message.contains("test-srv::echo#2"));
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_has_reasonable_values() {
        let config = A2aEdgeConfig::default();
        assert!(!config.agent_name.is_empty());
        assert_eq!(config.protocol_binding, "JSONRPC");
    }

    // ---- TaskStatus serde ----

    #[test]
    fn task_status_serializes_correctly() {
        let json = serde_json::to_value(TaskStatus::Completed).unwrap();
        assert_eq!(json, "completed");
        let json = serde_json::to_value(TaskStatus::Failed).unwrap();
        assert_eq!(json, "failed");
    }

    #[test]
    fn bridge_fidelity_serializes_correctly() {
        let json = serde_json::to_value(BridgeFidelity::Lossless).unwrap();
        assert_eq!(json, json!({"kind": "lossless"}));
        let json = serde_json::to_value(BridgeFidelity::Adapted {
            caveats: vec!["stream collated".to_string()],
        })
        .unwrap();
        assert_eq!(
            json,
            json!({"kind": "adapted", "caveats": ["stream collated"]})
        );
        let json = serde_json::to_value(BridgeFidelity::Unsupported {
            reason: "needs cancellation".to_string(),
        })
        .unwrap();
        assert_eq!(
            json,
            json!({"kind": "unsupported", "reason": "needs cancellation"})
        );
    }
}
