//! # chio-acp-edge
//!
//! Edge crate that exposes Chio tools as ACP (Agent Client Protocol)
//! capabilities. This allows ACP-compatible editors and IDEs to access Chio
//! tools over ACP-shaped permission and invocation surfaces.
//!
//! Responsibilities:
//!
//! 1. Map Chio tool definitions to ACP capability advertisements.
//! 2. Intercept ACP `session/request_permission` calls.
//! 3. Expose truthful ACP lifecycle semantics: permission preview, blocking
//!    `tool/invoke`, and deferred-task `tool/stream` / `tool/cancel` /
//!    `tool/resume`.
//! 4. Route outward invocation through the Chio kernel by default while keeping
//!    explicit passthrough compatibility helpers.
//! 5. Evaluate `BridgeFidelity` per tool.
//!
//! Kernel-backed entrypoints emit signed Chio receipts. Direct passthrough
//! helpers remain available for compatibility and tests but are not sufficient
//! for full cross-protocol attestation claims.

#[cfg(feature = "fuzz")]
pub mod fuzz;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

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
use chio_kernel::{
    capability_matches_request, dpop, ChioKernel, ToolCallOutput, Verdict as KernelVerdict,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::McpTargetExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Errors produced by the ACP edge.
#[derive(Debug, thiserror::Error)]
pub enum AcpEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Access was denied.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The kernel reported an error.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),

    /// Cross-protocol orchestration failed.
    #[error("bridge error: {0}")]
    Bridge(#[from] chio_cross_protocol::BridgeError),
}

/// An ACP capability advertisement derived from an Chio tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapability {
    /// Capability identifier (matches the Chio tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the capability.
    pub description: String,
    /// The ACP category this maps to (e.g., "tool", "fs", "terminal").
    pub category: AcpCategory,
    /// Whether the capability requires explicit permission.
    pub requires_permission: bool,
    /// Fidelity assessment for this mapping.
    pub bridge_fidelity: BridgeFidelity,
}

/// ACP capability categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpCategory {
    /// General tool invocation.
    Tool,
    /// Filesystem operations.
    Filesystem,
    /// Terminal/command execution.
    Terminal,
    /// Browser-based operations.
    Browser,
}

/// Configuration for the ACP edge.
#[derive(Debug, Clone)]
pub struct AcpEdgeConfig {
    /// Whether to require explicit permission for all tools.
    pub require_permission: bool,
    /// Default ACP category for unmapped tools.
    pub default_category: AcpCategory,
}

impl Default for AcpEdgeConfig {
    fn default() -> Self {
        Self {
            require_permission: true,
            default_category: AcpCategory::Tool,
        }
    }
}

/// An ACP permission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    /// The capability ID being requested.
    pub capability_id: String,
    /// Arguments for the invocation.
    pub arguments: Value,
}

/// An ACP permission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    /// Permission granted.
    Allow,
    /// Permission denied.
    Deny,
}

/// Result of an ACP tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpInvocationResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The result data.
    pub data: Value,
    /// Optional error message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Chio metadata such as signed receipts when the kernel path is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpInvocationTask {
    pub id: String,
    pub status: AcpTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone)]
struct DeferredAcpTask {
    owner_agent_id: String,
    request: CrossProtocolExecutionRequest,
    task: AcpInvocationTask,
    result: Option<AcpInvocationResult>,
}

/// Execution context required for kernel-mediated ACP invocations.
#[derive(Debug, Clone)]
pub struct AcpKernelExecutionContext {
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

/// The ACP edge server.
///
/// Maps Chio tools to ACP capabilities and routes invocations through
/// the kernel guard pipeline.
pub struct ChioAcpEdge {
    capabilities: Vec<AcpCapability>,
    capability_fidelity: BTreeMap<String, BridgeFidelity>,
    /// Maps capability ID to authoritative target binding metadata.
    capability_bindings: BTreeMap<String, CapabilityBinding>,
    task_counter: Cell<u64>,
    tasks: RefCell<BTreeMap<String, DeferredAcpTask>>,
}

/// Explicit compatibility-only surface for config-preview and direct ACP passthrough flows.
///
/// Callers must opt into this wrapper to reach the non-authoritative path.
#[cfg(any(test, feature = "compatibility-surface"))]
pub struct ChioAcpEdgeCompatibility<'a> {
    edge: &'a ChioAcpEdge,
}

struct AcpCapabilityBridge;

static MCP_TARGET_EXECUTOR: McpTargetExecutor = McpTargetExecutor {
    peer_supports_chio_tool_streaming: false,
};
static OPENAI_TARGET_EXECUTOR: OpenAiTargetExecutor = OpenAiTargetExecutor;

#[derive(Debug, Clone)]
struct CapabilityBinding {
    target_protocol: DiscoveryProtocol,
    server_id: String,
    tool_name: String,
}

struct AcpRequestIds {
    origin_request_id: String,
    kernel_request_id: String,
}

impl CapabilityBridge for AcpCapabilityBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Acp
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
            .get("capabilityId")
            .and_then(Value::as_str)
            .map(|capability_id| json!({ "capabilityId": capability_id })))
    }
}

impl ChioAcpEdge {
    /// Create a new ACP edge from Chio tool manifests.
    pub fn new(config: AcpEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, AcpEdgeError> {
        let mut capabilities = BTreeMap::new();
        let mut capability_fidelity = BTreeMap::new();
        let mut capability_bindings = BTreeMap::new();
        let mut capability_sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let cap_id = tool.name.clone();
                let source = format!("{}/{}", manifest.server_id, tool.name);
                let sources = capability_sources.entry(cap_id.clone()).or_default();
                sources.insert(source);

                if sources.len() > 1 {
                    capability_fidelity.insert(
                        cap_id.clone(),
                        BridgeFidelity::Unsupported {
                            reason: capability_collision_reason(&cap_id, sources),
                        },
                    );
                    capabilities.remove(&cap_id);
                    capability_bindings.remove(&cap_id);
                    continue;
                }

                if capability_fidelity.contains_key(&cap_id) {
                    continue;
                }

                let target_protocol =
                    target_protocol_for_tool_with_registry(tool, &authoritative_target_registry())
                        .map_err(AcpEdgeError::InvalidRequest)?;
                let category = infer_acp_category(tool, config.default_category);
                let fidelity = evaluate_bridge_fidelity(tool, category, target_protocol);
                capability_fidelity.insert(cap_id.clone(), fidelity.clone());

                if fidelity.published_by_default() {
                    capabilities.insert(
                        cap_id.clone(),
                        AcpCapability {
                            id: cap_id.clone(),
                            name: cap_id.clone(),
                            description: tool.description.clone(),
                            category,
                            requires_permission: config.require_permission || tool.has_side_effects,
                            bridge_fidelity: fidelity,
                        },
                    );

                    capability_bindings.insert(
                        cap_id,
                        CapabilityBinding {
                            target_protocol,
                            server_id: manifest.server_id.clone(),
                            tool_name: tool.name.clone(),
                        },
                    );
                }
            }
        }

        Ok(Self {
            capabilities: capabilities.into_values().collect(),
            capability_fidelity,
            capability_bindings,
            task_counter: Cell::new(0),
            tasks: RefCell::new(BTreeMap::new()),
        })
    }

    fn next_task_id(&self) -> String {
        let next = self.task_counter.get() + 1;
        self.task_counter.set(next);
        format!("acp-task-{next}")
    }

    fn capability_binding(&self, capability_id: &str) -> Result<CapabilityBinding, AcpEdgeError> {
        self.capability_bindings
            .get(capability_id)
            .cloned()
            .ok_or_else(|| AcpEdgeError::ToolNotFound(capability_id.to_string()))
    }

    fn build_execution_request(
        &self,
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
        binding: &CapabilityBinding,
        target_protocol: DiscoveryProtocol,
        ids: AcpRequestIds,
    ) -> Result<CrossProtocolExecutionRequest, AcpEdgeError> {
        Ok(CrossProtocolExecutionRequest {
            origin_request_id: ids.origin_request_id,
            kernel_request_id: ids.kernel_request_id,
            target_protocol,
            target_server_id: binding.server_id.clone(),
            target_tool_name: binding.tool_name.clone(),
            agent_id: execution.agent_id.clone(),
            arguments: arguments.clone(),
            capability: execution.capability.clone(),
            source_envelope: build_acp_source_envelope(capability_id, arguments)?,
            dpop_proof: execution.dpop_proof.clone(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            model_metadata: execution.model_metadata.clone(),
        })
    }

    /// List all capabilities.
    pub fn capabilities(&self) -> &[AcpCapability] {
        &self.capabilities
    }

    /// Get a capability by ID.
    pub fn capability(&self, id: &str) -> Option<&AcpCapability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// Get the truthful bridge fidelity classification for a capability ID,
    /// including unpublished capabilities that were gated from discovery.
    pub fn bridge_fidelity(&self, id: &str) -> Option<&BridgeFidelity> {
        self.capability_fidelity.get(id)
    }

    /// List all capability IDs.
    pub fn capability_ids(&self) -> Vec<String> {
        self.capabilities.iter().map(|c| c.id.clone()).collect()
    }

    /// Access the explicit compatibility-only ACP surface.
    #[cfg(any(test, feature = "compatibility-surface"))]
    pub fn compatibility(&self) -> ChioAcpEdgeCompatibility<'_> {
        ChioAcpEdgeCompatibility { edge: self }
    }

    /// Evaluate a permission request against an explicit capability token.
    ///
    /// This is a truthful permission preview for deployments that already have
    /// authenticated capability context but are not yet dispatching the tool
    /// call itself.
    pub fn evaluate_permission(
        &self,
        request: &PermissionRequest,
        execution: &AcpKernelExecutionContext,
    ) -> PermissionDecision {
        let Some(binding) = self.capability_bindings.get(&request.capability_id) else {
            return PermissionDecision::Deny;
        };

        if !matches!(execution.capability.verify_signature(), Ok(true)) {
            return PermissionDecision::Deny;
        }
        if !execution.capability.is_valid_at(current_unix_timestamp()) {
            return PermissionDecision::Deny;
        }
        if execution.capability.subject.to_hex() != execution.agent_id {
            return PermissionDecision::Deny;
        }

        match capability_matches_request(
            &execution.capability,
            &binding.tool_name,
            &binding.server_id,
            &request.arguments,
        ) {
            Ok(true) => PermissionDecision::Allow,
            Ok(false) | Err(_) => PermissionDecision::Deny,
        }
    }

    /// Evaluate a permission request using the legacy config-only preview path.
    ///
    /// This helper does not consult the Chio kernel and does not imply that a
    /// later invocation would produce a signed receipt.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn evaluate_permission_passthrough(&self, request: &PermissionRequest) -> PermissionDecision {
        let Some(cap) = self.capability(&request.capability_id) else {
            return PermissionDecision::Deny;
        };

        if cap.requires_permission {
            PermissionDecision::Deny
        } else {
            PermissionDecision::Allow
        }
    }

    /// Back-compat alias for callers that already adopted the explicit capability-preview name.
    pub fn evaluate_permission_with_capability(
        &self,
        request: &PermissionRequest,
        execution: &AcpKernelExecutionContext,
    ) -> PermissionDecision {
        self.evaluate_permission(request, execution)
    }

    /// Invoke a capability through the Chio kernel.
    ///
    /// The caller is responsible for registering the bound tool server with the
    /// provided kernel. Successful and denied outcomes both surface a signed Chio
    /// receipt in the returned metadata.
    pub fn invoke(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        let binding = self.capability_binding(capability_id)?;
        let request_suffix = current_unix_timestamp();
        let request = self.build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{capability_id}-{request_suffix}"),
                kernel_request_id: format!("acp-{capability_id}-{request_suffix}"),
            },
        )?;
        let orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Invoke a capability through the shared MCP target executor.
    ///
    /// This is the first non-native authoritative bridge path: ACP request
    /// semantics are projected onto an MCP `tools/call` execution surface while
    /// the underlying Chio receipt remains authoritative.
    pub fn invoke_with_mcp_target(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        let binding = self.capability_binding(capability_id)?;
        let request_suffix = current_unix_timestamp();
        let request = self.build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            DiscoveryProtocol::Mcp,
            AcpRequestIds {
                origin_request_id: format!("acp-request-{capability_id}-{request_suffix}"),
                kernel_request_id: format!("acp-mcp-{capability_id}-{request_suffix}"),
            },
        )?;
        let orchestrated = execute_orchestrated_acp_request(kernel, request)?;
        Ok(acp_invocation_result_from_orchestrated(orchestrated))
    }

    /// Invoke a capability through the explicit direct tool-server passthrough.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not confuse it with the
    /// signed-receipt authority path.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn invoke_passthrough(
        &self,
        capability_id: &str,
        arguments: Value,
        server: &dyn ToolServerConnection,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        let binding = self
            .capability_bindings
            .get(capability_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(capability_id.to_string()))?;

        match server.invoke(&binding.tool_name, arguments, None) {
            Ok(result) => Ok(AcpInvocationResult {
                success: true,
                data: result,
                error: None,
                metadata: Some(passthrough_metadata(None)),
            }),
            Err(error) => Ok(AcpInvocationResult {
                success: false,
                data: Value::Null,
                error: Some(error.to_string()),
                metadata: Some(passthrough_metadata(Some(&error.to_string()))),
            }),
        }
    }

    /// Back-compat alias for callers that already adopted the explicit kernel helper name.
    pub fn invoke_with_kernel(
        &self,
        capability_id: &str,
        arguments: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        self.invoke(capability_id, arguments, kernel, execution)
    }

    /// Handle a JSON-RPC ACP request through the Chio kernel.
    ///
    /// `session/request_permission` becomes a capability-aware preview, while
    /// `tool/invoke` produces receipt-bearing kernel decisions.
    pub fn handle_jsonrpc(
        &self,
        message: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "session/list_capabilities" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": serde_json::to_value(&self.capabilities)
                            .unwrap_or(Value::Null),
                        "metadata": authoritative_surface_metadata(),
                    }
                })
            }
            "session/request_permission" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let request = PermissionRequest {
                    capability_id: cap_id.to_string(),
                    arguments: params
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                };
                let decision = self.evaluate_permission(&request, execution);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "decision": serde_json::to_value(decision)
                            .unwrap_or(Value::Null),
                        "metadata": permission_preview_metadata("capability_preview", false)
                    }
                })
            }
            "tool/invoke" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.invoke(cap_id, arguments, kernel, execution) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": serde_json::to_value(&result)
                            .unwrap_or(Value::Null)
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": error.to_string()
                        }
                    }),
                }
            }
            "tool/stream" => self.handle_jsonrpc_stream(id, params, execution),
            "tool/cancel" => self.handle_jsonrpc_cancel(id, params, execution),
            "tool/resume" => self.handle_jsonrpc_resume(id, params, kernel, execution),
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

    /// Handle a JSON-RPC ACP request through the direct passthrough path.
    ///
    /// This compatibility helper keeps the old config-preview and direct tool
    /// invocation behavior, but marks both as non-authoritative.
    #[cfg(any(test, feature = "compatibility-surface"))]
    fn handle_jsonrpc_passthrough(
        &self,
        message: Value,
        server: &dyn ToolServerConnection,
    ) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "session/list_capabilities" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": serde_json::to_value(&self.capabilities)
                            .unwrap_or(Value::Null),
                        "metadata": compatibility_surface_metadata(),
                    }
                })
            }
            "session/request_permission" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let request = PermissionRequest {
                    capability_id: cap_id.to_string(),
                    arguments: params
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                };
                let decision = self.evaluate_permission_passthrough(&request);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "decision": serde_json::to_value(decision)
                            .unwrap_or(Value::Null),
                        "metadata": permission_preview_metadata("config_preview", true)
                    }
                })
            }
            "tool/invoke" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.invoke_passthrough(cap_id, arguments, server) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": serde_json::to_value(&result)
                            .unwrap_or(Value::Null)
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": error.to_string()
                        }
                    }),
                }
            }
            "tool/stream" => lifecycle_not_supported_error(
                id,
                "tool/stream",
                true,
                "ACP compatibility mode also exposes only blocking `tool/invoke`; streamed tool output is collected into the final invocation payload",
            ),
            "tool/cancel" => lifecycle_not_supported_error(
                id,
                "tool/cancel",
                true,
                "ACP compatibility mode does not expose cancel lifecycle for `tool/invoke`",
            ),
            "tool/resume" => lifecycle_not_supported_error(
                id,
                "tool/resume",
                true,
                "ACP compatibility mode does not expose resume lifecycle for `tool/invoke`",
            ),
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
        &self,
        message: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        self.handle_jsonrpc(message, kernel, execution)
    }

    fn handle_jsonrpc_stream(
        &self,
        id: Value,
        params: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let cap_id = params
            .get("capabilityId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match self.start_stream_task(cap_id, arguments, execution) {
            Ok(task) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null)
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn handle_jsonrpc_cancel(
        &self,
        id: Value,
        params: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let Some(task_id) = params.get("taskId").and_then(Value::as_str) else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "tool/cancel requires params.taskId"
                }
            });
        };
        match self.cancel_stream_task(task_id, execution) {
            Ok(task) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null)
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn handle_jsonrpc_resume(
        &self,
        id: Value,
        params: Value,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Value {
        let Some(task_id) = params.get("taskId").and_then(Value::as_str) else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "tool/resume requires params.taskId"
                }
            });
        };
        match self.resume_stream_task(task_id, kernel, execution) {
            Ok((task, result)) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "task": serde_json::to_value(&task).unwrap_or(Value::Null),
                    "result": result
                }
            }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": error.to_string()
                }
            }),
        }
    }

    fn start_stream_task(
        &self,
        capability_id: &str,
        arguments: Value,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        let binding = self.capability_binding(capability_id)?;
        let task_id = self.next_task_id();
        let request = self.build_execution_request(
            capability_id,
            arguments,
            execution,
            &binding,
            binding.target_protocol,
            AcpRequestIds {
                origin_request_id: task_id.clone(),
                kernel_request_id: format!("acp-stream-{task_id}"),
            },
        )?;
        let task = AcpInvocationTask {
            id: task_id.clone(),
            status: AcpTaskStatus::Working,
            status_message: Some("Task accepted for authoritative deferred execution.".to_string()),
            metadata: Some(pending_stream_task_metadata("cross_protocol_orchestrator")),
        };
        self.tasks.borrow_mut().insert(
            task_id,
            DeferredAcpTask {
                owner_agent_id: execution.agent_id.clone(),
                request,
                task: task.clone(),
                result: None,
            },
        );
        Ok(task)
    }

    fn cancel_stream_task(
        &self,
        task_id: &str,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpInvocationTask, AcpEdgeError> {
        let mut tasks = self.tasks.borrow_mut();
        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
        if task.owner_agent_id != execution.agent_id {
            return Err(AcpEdgeError::AccessDenied(
                "task is not owned by the current agent".to_string(),
            ));
        }
        match task.task.status {
            AcpTaskStatus::Working => {
                task.task.status = AcpTaskStatus::Cancelled;
                task.task.status_message = Some("Task cancelled by caller.".to_string());
                task.task.metadata = Some(cancelled_stream_task_metadata(
                    "cross_protocol_orchestrator",
                ));
                Ok(task.task.clone())
            }
            AcpTaskStatus::Cancelled => Ok(task.task.clone()),
            status => Err(AcpEdgeError::InvalidRequest(format!(
                "cannot cancel task in terminal status `{status:?}`"
            ))),
        }
    }

    fn resume_stream_task(
        &self,
        task_id: &str,
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<(AcpInvocationTask, Value), AcpEdgeError> {
        let task_snapshot = {
            let tasks = self.tasks.borrow();
            let task = tasks
                .get(task_id)
                .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
            if task.owner_agent_id != execution.agent_id {
                return Err(AcpEdgeError::AccessDenied(
                    "task is not owned by the current agent".to_string(),
                ));
            }
            task.clone()
        };

        if task_snapshot.task.status == AcpTaskStatus::Working {
            let orchestrated = execute_orchestrated_acp_request(kernel, task_snapshot.request)?;
            let result = acp_invocation_result_from_orchestrated(orchestrated);
            let status = if result.success {
                AcpTaskStatus::Completed
            } else {
                AcpTaskStatus::Failed
            };
            let mut tasks = self.tasks.borrow_mut();
            if let Some(task) = tasks.get_mut(task_id) {
                task.task.status = status;
                task.task.status_message = result.error.clone();
                task.task.metadata = result.metadata.clone();
                task.result = Some(result.clone());
                return Ok((
                    task.task.clone(),
                    serde_json::to_value(&result).unwrap_or(Value::Null),
                ));
            }
        }

        let tasks = self.tasks.borrow();
        let task = tasks
            .get(task_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(task_id.to_string()))?;
        Ok((
            task.task.clone(),
            task.result
                .as_ref()
                .map(|result| serde_json::to_value(result).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
        ))
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
impl ChioAcpEdgeCompatibility<'_> {
    /// Evaluate a permission request using the legacy config-only preview path.
    ///
    /// This compatibility helper does not consult the Chio kernel and does not
    /// imply that a later invocation would produce a signed receipt.
    pub fn preview_permission(&self, request: &PermissionRequest) -> PermissionDecision {
        self.edge.evaluate_permission_passthrough(request)
    }

    /// Invoke a capability through the explicit direct tool-server passthrough.
    ///
    /// This compatibility helper does not invoke the Chio kernel. It returns
    /// explicit passthrough metadata so callers do not confuse it with the
    /// signed-receipt authority path.
    pub fn invoke(
        &self,
        capability_id: &str,
        arguments: Value,
        server: &dyn ToolServerConnection,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        self.edge
            .invoke_passthrough(capability_id, arguments, server)
    }

    /// Handle a JSON-RPC ACP request through the direct passthrough path.
    ///
    /// This compatibility helper keeps the old config-preview and direct tool
    /// invocation behavior, but marks both as non-authoritative.
    pub fn handle_jsonrpc(&self, message: Value, server: &dyn ToolServerConnection) -> Value {
        self.edge.handle_jsonrpc_passthrough(message, server)
    }
}

/// Infer the ACP category for an Chio tool based on its name and properties.
fn infer_acp_category(tool: &ToolDefinition, default: AcpCategory) -> AcpCategory {
    let name_lower = tool.name.to_lowercase();
    if name_lower.contains("read_file")
        || name_lower.contains("write_file")
        || name_lower.contains("list_dir")
        || name_lower.starts_with("fs_")
    {
        AcpCategory::Filesystem
    } else if name_lower.contains("terminal")
        || name_lower.contains("exec")
        || name_lower.contains("shell")
        || name_lower.contains("command")
    {
        AcpCategory::Terminal
    } else if name_lower.contains("browser")
        || name_lower.contains("navigate")
        || name_lower.contains("screenshot")
    {
        AcpCategory::Browser
    } else {
        default
    }
}

/// Evaluate bridge fidelity for an Chio tool to ACP mapping.
fn evaluate_bridge_fidelity(
    tool: &ToolDefinition,
    category: AcpCategory,
    target_protocol: DiscoveryProtocol,
) -> BridgeFidelity {
    let registry = authoritative_target_registry();
    let hints = semantic_hints_for_tool(tool);
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::AcpAuthoritative);
    if !hints.publish {
        return BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string(),
        };
    }
    if !registry.supports_target_protocol(target_protocol) {
        return BridgeFidelity::Unsupported {
            reason: format!(
                "ACP authoritative execution does not yet have a registered `{target_protocol}` target executor"
            ),
        };
    }

    match category {
        AcpCategory::Browser => BridgeFidelity::Unsupported {
            reason:
                "browser/session automation semantics are not yet truthfully projected on the ACP edge"
                    .to_string(),
        },
        AcpCategory::Tool if tool.has_side_effects => BridgeFidelity::Unsupported {
            reason:
                "generic side-effectful tools do not map honestly to ACP capability classes on this edge"
                    .to_string(),
        },
        _ => {
            let mut caveats = Vec::new();
            if hints.approval_required {
                caveats.push(
                    "permission preview is advisory only; enforcement happens at invoke time with Chio capability checks"
                        .to_string(),
                );
            }
            if hints.streams_output {
                caveats.push(format!(
                    "stream-capable tools execute through deferred `{}` tasks and surface output when resumed via `{}` rather than as incremental push updates",
                    lifecycle.stream_entrypoint, lifecycle.follow_up_entrypoint
                ));
            }
            if hints.partial_output {
                caveats.push(
                    "partial output is preserved only inside the resumed terminal payload, not incremental ACP updates"
                        .to_string(),
                );
            }
            if hints.supports_cancellation {
                caveats.push(format!(
                    "cancellation is available on deferred `{}` tasks via `{}`; blocking `{}` remains terminal",
                    lifecycle.stream_entrypoint, lifecycle.cancel_entrypoint, lifecycle.blocking_entrypoint
                ));
            }
            if matches!(category, AcpCategory::Tool) {
                caveats.push(
                    "generic Chio tools are exposed through ACP's tool category rather than a native ACP primitive"
                        .to_string(),
                );
            }

            if caveats.is_empty() {
                BridgeFidelity::Lossless
            } else {
                BridgeFidelity::Adapted { caveats }
            }
        }
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn execute_orchestrated_acp_request(
    kernel: &ChioKernel,
    request: CrossProtocolExecutionRequest,
) -> Result<OrchestratedToolCall, AcpEdgeError> {
    let registry = authoritative_target_registry();
    if !registry.supports_target_protocol(request.target_protocol) {
        return Err(AcpEdgeError::InvalidRequest(format!(
            "ACP authoritative execution does not have a registered `{}` target executor",
            request.target_protocol
        )));
    }

    CrossProtocolOrchestrator::new(kernel)
        .with_registry(registry)
        .execute(&AcpCapabilityBridge, request)
        .map_err(Into::into)
}

fn authoritative_target_registry() -> TargetProtocolRegistry<'static> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native)
        .with_executor(&MCP_TARGET_EXECUTOR)
        .with_executor(&OPENAI_TARGET_EXECUTOR)
}

fn kernel_output_to_value(output: Option<&ToolCallOutput>) -> Value {
    match output {
        Some(ToolCallOutput::Value(value)) => value.clone(),
        Some(ToolCallOutput::Stream(stream)) => json!({
            "stream": stream
                .chunks
                .iter()
                .map(|chunk| chunk.data.clone())
                .collect::<Vec<_>>()
        }),
        None => Value::Null,
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
            "reason": reason,
        }
    })
}

fn capability_collision_reason(capability_id: &str, sources: &BTreeSet<String>) -> String {
    let source_list = sources.iter().cloned().collect::<Vec<_>>().join(", ");
    format!(
        "ACP capability `{capability_id}` is withheld from discovery because multiple manifests map it to different upstream bindings: {source_list}"
    )
}

fn authoritative_surface_metadata() -> Value {
    json!({
        "chio": {
            "authorityPath": "cross_protocol_orchestrator",
            "authoritative": true,
            "compatibilityOnly": false,
            "claimEligible": true,
            "receiptBearingInvoke": true,
            "permissionPreviewOnly": true,
            "invokeMode": "blocking_or_deferred_task",
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            },
            "streamDelivery": "resumed_terminal_payload",
        }
    })
}

#[cfg(any(test, feature = "compatibility-surface"))]
fn compatibility_surface_metadata() -> Value {
    json!({
        "chio": {
            "authorityPath": "passthrough_compatibility",
            "authoritative": false,
            "compatibilityOnly": true,
            "claimEligible": false,
            "receiptBearingInvoke": false,
            "permissionPreviewOnly": true,
            "invokeMode": "blocking_tool_invoke",
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpCompatibility),
            "unsupportedLifecycleMethods": ["tool/stream", "tool/cancel", "tool/resume"],
            "streamDelivery": "collected_final_payload_only",
        }
    })
}

fn pending_stream_task_metadata(authority_path: &str) -> Value {
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
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            }
        }
    })
}

fn cancelled_stream_task_metadata(authority_path: &str) -> Value {
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
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            }
        }
    })
}

fn acp_invocation_result_from_orchestrated(
    orchestrated: OrchestratedToolCall,
) -> AcpInvocationResult {
    let data = orchestrated
        .protocol_result
        .clone()
        .unwrap_or_else(|| kernel_output_to_value(orchestrated.response.output.as_ref()));
    let metadata = Some(orchestrated.metadata());
    let response = orchestrated.response;
    let success = matches!(response.verdict, KernelVerdict::Allow);

    AcpInvocationResult {
        success,
        data,
        error: if success { None } else { response.reason },
        metadata,
    }
}

fn build_acp_source_envelope(capability_id: &str, arguments: Value) -> Result<Value, BridgeError> {
    let mut envelope = json!({
        "capabilityId": capability_id,
        "arguments": arguments,
    });
    let _ = ensure_chio_metadata(&mut envelope)?;
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

fn permission_preview_metadata(path: &str, compatibility_only: bool) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "authorityPath": path,
            "authoritative": false,
            "previewOnly": true,
            "compatibilityOnly": compatibility_only,
            "claimEligible": false,
            "receiptBearing": false,
            "invokeAuthorityPath": if compatibility_only {
                "passthrough_compatibility"
            } else {
                "cross_protocol_orchestrator"
            },
            "reason": "permission preview only",
        }
    })
}

#[cfg(any(test, feature = "compatibility-surface"))]
fn lifecycle_not_supported_error(
    id: Value,
    method: &str,
    compatibility_only: bool,
    message: &str,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32601,
            "message": format!("{method} is not supported on this ACP edge"),
            "data": {
                "chio": {
                    "authorityPath": if compatibility_only {
                        "passthrough_compatibility"
                    } else {
                        "cross_protocol_orchestrator"
                    },
                    "authoritative": !compatibility_only,
                    "compatibilityOnly": compatibility_only,
                    "claimEligible": !compatibility_only,
                    "receiptBearing": false,
                    "invokeMode": "blocking_tool_invoke",
                    "reason": message,
                }
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
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

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test Server".to_string(),
            description: Some("Test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "exec_command".to_string(),
                    description: "Execute a shell command".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "search".to_string(),
                    description: "Search documents".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
            ],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn browser_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "browser-srv".to_string(),
            name: "Browser Server".to_string(),
            description: Some("Browser test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "browser_navigate".to_string(),
                description: "Navigate browser".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "browser".to_string(),
        }
    }

    fn generic_side_effect_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "tool-srv".to_string(),
            name: "Generic Tool Server".to_string(),
            description: Some("Generic side effect test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "mutate_records".to_string(),
                description: "Mutate records".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "mutate".to_string(),
        }
    }

    fn approval_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "approval-srv".to_string(),
            name: "Approval Server".to_string(),
            description: Some("Approval test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "read_secret".to_string(),
                description: "Read secret".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-approval-required": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "approval".to_string(),
        }
    }

    fn streaming_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "streaming-srv".to_string(),
            name: "Streaming Server".to_string(),
            description: Some("Streaming test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_stream".to_string(),
                description: "Stream search results".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-streaming": true,
                    "x-chio-partial-output": true,
                    "x-chio-cancellation": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "streaming".to_string(),
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
                name: "read_file".to_string(),
                description: "Read file via MCP target executor".to_string(),
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
                name: "read_file".to_string(),
                description: "Read file via OpenAI target executor".to_string(),
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
                name: "read_file".to_string(),
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
                name: "hidden_tool".to_string(),
                description: "Hidden tool".to_string(),
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

    fn colliding_search_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "other-srv".to_string(),
            name: "Other Search Server".to_string(),
            description: Some("Collision test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search".to_string(),
                description: "Search somewhere else".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "other-search".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "exec_command".to_string(),
                "search".to_string(),
            ],
            response: json!({"result": "ok"}),
        }
    }

    fn test_kernel_config() -> KernelConfig {
        let keypair = Keypair::generate();
        KernelConfig {
            ca_public_keys: vec![keypair.public_key()],
            keypair,
            max_delegation_depth: 8,
            policy_hash: "policy-acp-test".to_string(),
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
        let now = current_unix_timestamp();
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

    // ---- Capability generation tests ----

    #[test]
    fn edge_generates_capabilities_from_manifest() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn edge_capability_ids_match_tool_names() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let ids = edge.capability_ids();
        assert!(ids.contains(&"read_file".to_string()));
        assert!(ids.contains(&"write_file".to_string()));
        assert!(ids.contains(&"exec_command".to_string()));
        assert!(ids.contains(&"search".to_string()));
    }

    #[test]
    fn edge_capability_lookup() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.description, "Read a file");
    }

    #[test]
    fn edge_unknown_capability_returns_none() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert!(edge.capability("nonexistent").is_none());
    }

    // ---- Category inference tests ----

    #[test]
    fn read_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn write_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("write_file").unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn exec_command_gets_terminal_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("exec_command").unwrap();
        assert_eq!(cap.category, AcpCategory::Terminal);
    }

    #[test]
    fn search_gets_default_tool_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("search").unwrap();
        assert_eq!(cap.category, AcpCategory::Tool);
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn filesystem_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn terminal_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("exec_command").unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn generic_readonly_tool_is_adapted_with_category_caveat() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("search").unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("tool category") || c.contains("native ACP primitive")));
    }

    #[test]
    fn browser_tools_are_not_auto_published() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![browser_manifest()]).unwrap();
        assert!(edge.capability("browser_navigate").is_none());
        assert_eq!(
            edge.bridge_fidelity("browser_navigate"),
            Some(&BridgeFidelity::Unsupported {
                reason: "browser/session automation semantics are not yet truthfully projected on the ACP edge".to_string()
            })
        );
    }

    #[test]
    fn generic_side_effectful_tools_are_not_auto_published() {
        let edge = ChioAcpEdge::new(
            AcpEdgeConfig::default(),
            vec![generic_side_effect_manifest()],
        )
        .unwrap();
        assert!(edge.capability("mutate_records").is_none());
        assert_eq!(
            edge.bridge_fidelity("mutate_records"),
            Some(&BridgeFidelity::Unsupported {
                reason: "generic side-effectful tools do not map honestly to ACP capability classes on this edge".to_string()
            })
        );
    }

    #[test]
    fn approval_required_capability_is_adapted_with_permission_caveat() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![approval_manifest()]).unwrap();
        let cap = edge.capability("read_secret").unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("permission preview is advisory")));
    }

    #[test]
    fn streaming_capability_is_adapted_with_stream_and_cancellation_caveats() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).unwrap();
        let cap = edge.capability("search_stream").unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("deferred `tool/stream` tasks")));
        assert!(caveats
            .iter()
            .any(|c| c.contains("partial output is preserved")));
        assert!(caveats
            .iter()
            .any(|c| c.contains("cancellation is available")));
    }

    #[test]
    fn hidden_capability_is_not_auto_published() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![hidden_manifest()]).unwrap();
        assert!(edge.capability("hidden_tool").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden_tool"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    // ---- Permission tests ----

    #[test]
    fn side_effect_tools_require_permission() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("write_file").unwrap();
        assert!(cap.requires_permission);
    }

    #[test]
    fn permission_denied_by_default_for_required_caps() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_denied_for_unknown_capability() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let request = PermissionRequest {
            capability_id: "nonexistent".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_not_required_when_config_disabled() {
        let config = AcpEdgeConfig {
            require_permission: false,
            default_category: AcpCategory::Tool,
        };
        let edge = ChioAcpEdge::new(config, vec![test_manifest()]).unwrap();
        // read_file has no side effects and require_permission is false
        let cap = edge.capability("read_file").unwrap();
        assert!(!cap.requires_permission);
    }

    #[test]
    fn permission_with_capability_allows_matching_scope() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let request = PermissionRequest {
            capability_id: "read_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Allow
        );
    }

    #[test]
    fn permission_with_capability_denies_out_of_scope_request() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Deny
        );
    }

    // ---- Invocation tests ----

    #[test]
    fn invoke_succeeds() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let result = edge
            .compatibility()
            .invoke("read_file", json!({"path": "/tmp"}), &server)
            .unwrap();
        assert!(result.success);
        assert_eq!(result.data["result"], "ok");
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_unknown_tool_errors() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let err = edge
            .compatibility()
            .invoke("nonexistent", json!({}), &server)
            .unwrap_err();
        assert!(matches!(err, AcpEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn invoke_server_failure_returns_unsuccessful() {
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
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![manifest]).unwrap();
        let server = FailingToolServer;
        let result = edge
            .compatibility()
            .invoke("fail_tool", json!({}), &server)
            .unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_with_kernel_emits_signed_receipt_metadata() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap();
        assert!(result.success);
        let metadata = result.metadata.expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-read_file")
        );
    }

    #[test]
    fn invoke_with_kernel_denial_still_emits_receipt_metadata() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("write_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap();
        assert!(!result.success);
        let metadata = result.metadata.expect("deny path should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    }

    #[test]
    fn pending_approval_is_not_reported_as_success() {
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let mut orchestrated = execute_orchestrated_acp_request(
            &kernel,
            CrossProtocolExecutionRequest {
                origin_request_id: "acp-request-pending".to_string(),
                kernel_request_id: "acp-pending".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "read_file".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"path": "/tmp"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
                source_envelope: build_acp_source_envelope("read_file", json!({"path": "/tmp"}))
                    .unwrap(),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
            },
        )
        .unwrap();
        orchestrated.response.verdict = KernelVerdict::PendingApproval;
        orchestrated.response.reason = Some("approval required".to_string());

        let result = acp_invocation_result_from_orchestrated(orchestrated);
        let metadata = result
            .metadata
            .expect("pending approval should attach metadata");

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("approval required"));
        assert_eq!(
            metadata["chio"]["decision"].as_str(),
            Some("pending_approval")
        );
    }

    #[test]
    fn invoke_with_mcp_target_emits_receipt_metadata_and_mcp_projection() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke_with_mcp_target("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap();

        assert!(result.success);
        assert_eq!(result.data["isError"], Value::Bool(false));
        assert_eq!(
            result.data["structuredContent"]["result"].as_str(),
            Some("ok")
        );
        let metadata = result.metadata.expect("MCP target should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["acp", "mcp", "native"])
        );
    }

    #[test]
    fn default_invoke_honors_protocol_aware_target_binding() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![mcp_target_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap();

        let metadata = result
            .metadata
            .expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
    }

    #[test]
    fn default_invoke_supports_openai_target_binding() {
        let edge =
            ChioAcpEdge::new(AcpEdgeConfig::default(), vec![openai_target_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap();

        let metadata = result
            .metadata
            .expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(result.data["type"].as_str(), Some("function_call_output"));
    }

    #[test]
    fn invalid_target_protocol_metadata_is_rejected() {
        let error =
            match ChioAcpEdge::new(AcpEdgeConfig::default(), vec![invalid_target_manifest()]) {
                Ok(_) => panic!("expected invalid target protocol metadata to fail"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_list_capabilities() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
                "method": "session/list_capabilities",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        let caps = response["result"]["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeMode"].as_str(),
            Some("blocking_or_deferred_task")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["toolStream"].as_str(),
            Some("deferred_task_resume")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("acp_authoritative")
        );
    }

    #[test]
    fn jsonrpc_request_permission() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("capability_preview")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_tool_invoke() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response["result"]["success"].as_bool().unwrap_or(false));
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_unknown_method() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
    fn jsonrpc_passthrough_marks_non_authoritative_paths() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();

        let listed = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "session/list_capabilities",
                "params": {}
            }),
            &server,
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );

        let permission = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &server,
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("config_preview")
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["previewOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("passthrough_compatibility")
        );

        let invoke = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &server,
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_resume_resolves_result() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}, {"text": "chunk-2"}]}),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            response["result"]["task"]["status"].as_str(),
            Some("working")
        );
        let task_id = response["result"]["task"]["id"]
            .as_str()
            .expect("tool/stream should create task")
            .to_string();
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"]
                .as_str(),
            Some("tool/stream")
        );

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/resume",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert_eq!(
            resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        assert!(resumed["result"]["result"]["data"]["content"].is_array());
    }

    #[test]
    fn jsonrpc_cancel_marks_deferred_stream_task_cancelled() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tool/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled["result"]["task"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn compatibility_jsonrpc_explicitly_rejects_unimplemented_lifecycle_methods() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).unwrap();
        let server = test_server();

        let response = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/cancel",
                "params": {
                    "capabilityId": "search_stream"
                }
            }),
            &server,
        );
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(
            response["error"]["data"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["error"]["data"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![m1, m2]).unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn colliding_capability_ids_are_withheld_deterministically() {
        let edge = ChioAcpEdge::new(
            AcpEdgeConfig::default(),
            vec![test_manifest(), colliding_search_manifest()],
        )
        .unwrap();

        assert!(edge.capability("search").is_none());
        assert_eq!(edge.capabilities().len(), 3);

        let fidelity = edge
            .bridge_fidelity("search")
            .expect("collision should still have fidelity classification");
        let BridgeFidelity::Unsupported { reason } = fidelity else {
            panic!("colliding capability should be unsupported");
        };
        assert!(reason.contains("withheld from discovery"));
        assert!(reason.contains("other-srv/search"));
        assert!(reason.contains("test-srv/search"));
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = AcpEdgeError::ToolNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_access_denied() {
        let err = AcpEdgeError::AccessDenied("no cap".into());
        assert!(format!("{err}").contains("no cap"));
    }

    #[test]
    fn error_display_kernel() {
        let err = AcpEdgeError::Kernel("internal".into());
        assert!(format!("{err}").contains("internal"));
    }

    // ---- Serde tests ----

    #[test]
    fn bridge_fidelity_serializes() {
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Lossless).unwrap(),
            json!({"kind": "lossless"})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Adapted {
                caveats: vec!["preview only".to_string()]
            })
            .unwrap(),
            json!({"kind": "adapted", "caveats": ["preview only"]})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Unsupported {
                reason: "not publishable".to_string()
            })
            .unwrap(),
            json!({"kind": "unsupported", "reason": "not publishable"})
        );
    }

    #[test]
    fn acp_category_serializes() {
        assert_eq!(serde_json::to_value(AcpCategory::Tool).unwrap(), "tool");
        assert_eq!(
            serde_json::to_value(AcpCategory::Filesystem).unwrap(),
            "filesystem"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Terminal).unwrap(),
            "terminal"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Browser).unwrap(),
            "browser"
        );
    }

    #[test]
    fn permission_decision_serializes() {
        assert_eq!(
            serde_json::to_value(PermissionDecision::Allow).unwrap(),
            "allow"
        );
        assert_eq!(
            serde_json::to_value(PermissionDecision::Deny).unwrap(),
            "deny"
        );
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_requires_permission() {
        let config = AcpEdgeConfig::default();
        assert!(config.require_permission);
        assert_eq!(config.default_category, AcpCategory::Tool);
    }
}
