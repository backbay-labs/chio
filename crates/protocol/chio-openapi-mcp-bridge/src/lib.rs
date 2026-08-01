//! # chio-openapi-mcp-bridge
//!
//! Bridge that presents Chio-governed HTTP APIs as MCP tool surfaces.
//!
//! Given an OpenAPI 3.x specification, this crate:
//!
//! 1. Parses the spec with `chio-openapi` to produce `ToolDefinition` values.
//! 2. Wraps each route as an MCP-visible tool via `chio-mcp-edge`.
//! 3. Routes invocations through the Chio kernel for capability validation
//!    and receipt signing before dispatching to the upstream HTTP API.
//!
//! All invocations flow through the kernel guard pipeline, so every
//! HTTP call produces a signed Chio receipt.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

mod dispatch;

#[cfg(feature = "fuzz")]
pub mod fuzz;

use chio_egress_contract::HttpEgressContract;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_manifest::ToolManifest;
use chio_mcp_edge::McpToolInfo;
use chio_openapi::{GeneratorConfig, ManifestGenerator, OpenApiError, OpenApiSpec};
#[cfg(test)]
use dispatch::expand_route_path;
use dispatch::{
    bridged_tool_response, build_route_dispatches, dispatch_url, enforce_bridged_response_body,
    enforce_dispatch_contract, enforce_no_redirect_response, RouteDispatch,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Convert an `chio_core_types` ToolDefinition into the `chio_manifest` ToolDefinition
/// used by ToolManifest.
fn convert_tool_definition(tool: chio_core::ToolDefinition) -> chio_manifest::ToolDefinition {
    chio_manifest::ToolDefinition {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        pricing: None,
        has_side_effects: !tool.annotations.read_only,
        latency_hint: None,
    }
}

/// Report whether a generated tool is read-only.
///
/// `has_side_effects` is derived from the OpenAPI operation's read-only
/// annotation, so safe GET/HEAD routes stay exempt from durable side-effect
/// admission while mutating routes remain side-effecting. An unknown tool name
/// reports side-effecting, matching the fail-closed trait default.
fn manifest_tool_is_read_only(manifest: &ToolManifest, tool_name: &str) -> bool {
    manifest
        .tools
        .iter()
        .any(|tool| tool.name == tool_name && !tool.has_side_effects)
}

/// Errors produced by the OpenAPI-MCP bridge.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The OpenAPI spec could not be parsed.
    #[error("OpenAPI parse error: {0}")]
    OpenApi(#[from] OpenApiError),

    /// The manifest could not be validated.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),

    /// The tool was not found in the bridge.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The upstream HTTP call failed.
    #[error("upstream HTTP error: {0}")]
    UpstreamError(String),

    /// Kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),
}

/// Configuration for the OpenAPI-MCP bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Server ID for the generated manifest.
    pub server_id: String,
    /// Human-readable server name.
    pub server_name: String,
    /// Server version.
    pub server_version: String,
    /// Public key (hex-encoded) for the manifest.
    pub public_key: String,
    /// Base URL for the upstream HTTP API.
    pub base_url: String,
    /// Typed HTTP egress contract that gates every dispatcher invocation.
    /// Enforced at `invoke_tool` time before the dispatcher receives the URL.
    /// Production callers must populate this field; `None` falls back to
    /// substrate-default fail-closed behavior at dispatch time.
    pub egress_contract: Option<HttpEgressContract>,
}

/// An HTTP method and path pair identifying an API route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBinding {
    /// The HTTP method (GET, POST, etc.).
    pub method: String,
    /// The URL path template (e.g. /pets/{petId}).
    pub path: String,
}

/// Result of invoking a bridged tool (simulated HTTP response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgedResponse {
    /// HTTP status code from the upstream.
    pub status: u16,
    /// Response body.
    pub body: Value,
    /// Raw response body byte count observed by the dispatcher before JSON
    /// parsing or normalization. Live dispatchers must provide this so the
    /// egress contract is enforced against upstream bytes, not reserialized
    /// JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_body_bytes: Option<u64>,
    /// Whether the response indicates an error.
    pub is_error: bool,
}

/// HTTP dispatch function type.
///
/// Bridge users provide a function that performs the actual HTTP call.
/// This allows the bridge to remain transport-agnostic (no reqwest dependency).
/// Dispatchers must perform a single-hop request and return 3xx redirects
/// without following them internally. A dispatcher that follows redirects
/// violates the bridge egress contract. Live dispatchers must also populate
/// `BridgedResponse::observed_body_bytes` with the upstream body byte count.
pub type HttpDispatcher =
    dyn Fn(&str, &str, &Value) -> Result<BridgedResponse, BridgeError> + Send + Sync;

/// The OpenAPI-MCP bridge.
///
/// Parses an OpenAPI spec, generates MCP tool definitions, and dispatches
/// invocations through the kernel before calling the upstream HTTP API.
pub struct OpenApiMcpBridge {
    config: BridgeConfig,
    manifest: ToolManifest,
    route_dispatches: BTreeMap<String, RouteDispatch>,
    /// Optional HTTP dispatcher for live calls.
    dispatcher: Option<Box<HttpDispatcher>>,
}

impl OpenApiMcpBridge {
    /// Create a new bridge from an OpenAPI spec string.
    pub fn from_spec(spec_input: &str, config: BridgeConfig) -> Result<Self, BridgeError> {
        let spec = OpenApiSpec::parse(spec_input)?;
        Self::from_parsed_spec(&spec, config)
    }

    /// Create a new bridge from a pre-parsed OpenAPI spec.
    pub fn from_parsed_spec(spec: &OpenApiSpec, config: BridgeConfig) -> Result<Self, BridgeError> {
        let generator = ManifestGenerator::new(GeneratorConfig {
            server_id: config.server_id.clone(),
            include_output_schemas: true,
            respect_publish_flag: true,
        });
        let raw_tools = generator.generate_tools(spec);
        let tools: Vec<chio_manifest::ToolDefinition> =
            raw_tools.into_iter().map(convert_tool_definition).collect();

        if tools.is_empty() {
            return Err(BridgeError::Manifest(
                chio_manifest::ManifestError::EmptyManifest,
            ));
        }

        let route_dispatches = build_route_dispatches(spec)?;

        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: Some(format!(
                "OpenAPI-to-MCP bridge for {} ({})",
                spec.title, spec.api_version
            )),
            version: config.server_version.clone(),
            tools,
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: config.public_key.clone(),
        };

        chio_manifest::validate_manifest(&manifest)?;

        Ok(Self {
            config,
            manifest,
            route_dispatches,
            dispatcher: None,
        })
    }

    /// Set the HTTP dispatcher function.
    ///
    /// The dispatcher must not follow redirects internally. Return redirect
    /// responses to the bridge so they can be rejected instead of performing an
    /// ungated second network hop.
    pub fn set_dispatcher(&mut self, dispatcher: Box<HttpDispatcher>) {
        self.dispatcher = Some(dispatcher);
    }

    /// Get the generated manifest.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    /// Get a clone of the manifest.
    pub fn manifest_clone(&self) -> ToolManifest {
        self.manifest.clone()
    }

    /// Get the route binding for a tool.
    pub fn route_binding(&self, tool_name: &str) -> Option<&RouteBinding> {
        self.route_dispatches
            .get(tool_name)
            .map(RouteDispatch::binding)
    }

    /// List all tool names exposed by this bridge.
    pub fn tool_names(&self) -> Vec<String> {
        self.manifest.tools.iter().map(|t| t.name.clone()).collect()
    }

    /// Generate MCP tools/list entries from the manifest.
    pub fn mcp_tools_list(&self) -> Vec<McpToolInfo> {
        self.manifest
            .tools
            .iter()
            .map(|tool| McpToolInfo {
                name: tool.name.clone(),
                title: None,
                description: Some(tool.description.clone()),
                input_schema: tool.input_schema.clone(),
                output_schema: tool.output_schema.clone(),
                annotations: Some(json!({
                    "readOnlyHint": !tool.has_side_effects,
                })),
                execution: None,
            })
            .collect()
    }

    /// Invoke a bridged tool. A dispatcher is required so the kernel cannot
    /// sign successful receipts for simulated side effects.
    pub fn invoke_tool(&self, tool_name: &str, arguments: Value) -> Result<Value, BridgeError> {
        let dispatch = self
            .route_dispatches
            .get(tool_name)
            .ok_or_else(|| BridgeError::ToolNotFound(tool_name.to_string()))?;

        if let Some(dispatcher) = &self.dispatcher {
            let binding = dispatch.binding();
            let url = dispatch_url(&self.config.base_url, dispatch, &arguments)?;
            // HttpEgressContract: gate the dispatcher invocation on the typed
            // egress contract. The bridge stays transport-agnostic, so we
            // validate URL and DNS pre-flight, then enforce the response-byte
            // ceiling post-dispatch. Missing contract state fails closed.
            let contract = enforce_dispatch_contract(self.config.egress_contract.as_ref(), &url)?;
            let response = dispatcher(&binding.method, &url, &arguments)?;
            enforce_no_redirect_response(&response)?;
            enforce_bridged_response_body(contract, &response)?;
            Ok(bridged_tool_response(binding, response))
        } else {
            Err(BridgeError::Kernel(
                "OpenAPI bridge requires a dispatcher for live tool invocation".to_string(),
            ))
        }
    }

    /// Convert to a `ToolServerConnection` for kernel integration.
    pub fn as_tool_server(&self) -> BridgeToolServer<'_> {
        BridgeToolServer { bridge: self }
    }
}

/// Implements `ToolServerConnection` so the bridge can be registered
/// with a Chio kernel for capability validation and receipt signing.
pub struct BridgeToolServer<'a> {
    bridge: &'a OpenApiMcpBridge,
}

#[async_trait::async_trait]
impl ToolServerConnection for BridgeToolServer<'_> {
    fn server_id(&self) -> &str {
        &self.bridge.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.bridge.tool_names()
    }

    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        manifest_tool_is_read_only(&self.bridge.manifest, tool_name)
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.bridge
            .invoke_tool(tool_name, arguments)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}

/// Owned version of BridgeToolServer for kernel registration.
pub struct OwnedBridgeToolServer {
    config: BridgeConfig,
    manifest: ToolManifest,
    route_dispatches: BTreeMap<String, RouteDispatch>,
    dispatcher: Option<Box<HttpDispatcher>>,
}

impl OwnedBridgeToolServer {
    /// Create from a bridge, consuming it.
    pub fn from_bridge(bridge: OpenApiMcpBridge) -> Self {
        Self {
            config: bridge.config,
            manifest: bridge.manifest,
            route_dispatches: bridge.route_dispatches,
            dispatcher: bridge.dispatcher,
        }
    }

    fn invoke_tool(&self, tool_name: &str, arguments: Value) -> Result<Value, BridgeError> {
        let dispatch = self
            .route_dispatches
            .get(tool_name)
            .ok_or_else(|| BridgeError::ToolNotFound(tool_name.to_string()))?;

        if let Some(dispatcher) = &self.dispatcher {
            let binding = dispatch.binding();
            let url = dispatch_url(&self.config.base_url, dispatch, &arguments)?;
            // HttpEgressContract: validate URL pre-flight and enforce the
            // response-byte ceiling post-dispatch. Missing contract state
            // fails closed for live dispatchers.
            let contract = enforce_dispatch_contract(self.config.egress_contract.as_ref(), &url)?;
            let response = dispatcher(&binding.method, &url, &arguments)?;
            enforce_no_redirect_response(&response)?;
            enforce_bridged_response_body(contract, &response)?;
            Ok(bridged_tool_response(binding, response))
        } else {
            Err(BridgeError::Kernel(
                "OpenAPI bridge requires a dispatcher for live tool invocation".to_string(),
            ))
        }
    }

    /// Get the generated manifest.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for OwnedBridgeToolServer {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest.tools.iter().map(|t| t.name.clone()).collect()
    }

    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        manifest_tool_is_read_only(&self.manifest, tool_name)
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invoke_tool(tool_name, arguments)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
