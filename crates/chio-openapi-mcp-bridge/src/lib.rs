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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_test_public_key() -> String {
        chio_core::Keypair::from_seed(&[17u8; 32])
            .public_key()
            .to_hex()
    }

    const PETSTORE_SPEC: &str = r#"{
        "openapi": "3.0.3",
        "info": {
            "title": "Petstore",
            "description": "A sample pet store API",
            "version": "1.0.0"
        },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "listPets",
                    "summary": "List all pets",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": { "type": "integer" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "A list of pets"
                        }
                    }
                },
                "post": {
                    "operationId": "createPet",
                    "summary": "Create a pet",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created"
                        }
                    }
                }
            },
            "/pets/{petId}": {
                "get": {
                    "operationId": "getPet",
                    "summary": "Get a pet by ID",
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "A pet"
                        }
                    }
                },
                "delete": {
                    "operationId": "deletePet",
                    "summary": "Delete a pet",
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "204": {
                            "description": "Deleted"
                        }
                    }
                }
            }
        }
    }"#;

    fn petstore_config() -> BridgeConfig {
        BridgeConfig {
            server_id: "petstore-bridge".to_string(),
            server_name: "Petstore Bridge".to_string(),
            server_version: "1.0.0".to_string(),
            public_key: valid_test_public_key(),
            base_url: "https://api.example.com".to_string(),
            egress_contract: None,
        }
    }

    fn petstore_config_with_egress() -> BridgeConfig {
        let mut config = petstore_config();
        config.base_url = "https://93.184.216.34".to_string();
        config.egress_contract = Some(HttpEgressContract::permissive_for_tests("93.184.216.34"));
        config
    }

    fn required_query_spec() -> &'static str {
        r#"{
            "openapi": "3.0.3",
            "info": { "title": "Search API", "version": "1.0.0" },
            "paths": {
                "/search": {
                    "get": {
                        "operationId": "searchPets",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": true,
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "page",
                                "in": "query",
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#
    }

    fn optional_request_body_spec() -> &'static str {
        r#"{
            "openapi": "3.0.3",
            "info": { "title": "Optional Body API", "version": "1.0.0" },
            "paths": {
                "/optional-body": {
                    "post": {
                        "operationId": "optionalBody",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#
    }

    #[test]
    fn bridged_tool_response_preserves_metadata_and_body() {
        let binding = RouteBinding {
            method: "GET".to_string(),
            path: "/pets".to_string(),
        };
        let response = BridgedResponse {
            status: 202,
            body: json!({"ok": true}),
            observed_body_bytes: Some(64),
            is_error: false,
        };

        let result = bridged_tool_response(&binding, response);

        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], r#"{"ok":true}"#);
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["httpStatus"], 202);
        assert_eq!(result["structuredContent"]["method"], "GET");
        assert_eq!(result["structuredContent"]["path"], "/pets");
        assert_eq!(result["structuredContent"]["body"]["ok"], true);
    }

    #[test]
    fn bridge_parses_spec_and_generates_manifest() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        assert_eq!(bridge.manifest().schema, "chio.manifest.v1");
        assert_eq!(bridge.manifest().server_id, "petstore-bridge");
        assert_eq!(bridge.manifest().tools.len(), 4);
    }

    #[test]
    fn bridge_generates_correct_tool_names() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let names = bridge.tool_names();
        assert!(names.contains(&"listPets".to_string()));
        assert!(names.contains(&"createPet".to_string()));
        assert!(names.contains(&"getPet".to_string()));
        assert!(names.contains(&"deletePet".to_string()));
    }

    #[test]
    fn bridge_route_bindings_match_operations() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let binding = bridge.route_binding("listPets").expect("listPets binding");
        assert_eq!(binding.method, "GET");
        assert_eq!(binding.path, "/pets");

        let binding = bridge
            .route_binding("createPet")
            .expect("createPet binding");
        assert_eq!(binding.method, "POST");
        assert_eq!(binding.path, "/pets");

        let binding = bridge
            .route_binding("deletePet")
            .expect("deletePet binding");
        assert_eq!(binding.method, "DELETE");
        assert_eq!(binding.path, "/pets/{petId}");
    }

    #[test]
    fn bridge_mcp_tools_list_entries() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let mcp_tools = bridge.mcp_tools_list();
        assert_eq!(mcp_tools.len(), 4);
        for tool in &mcp_tools {
            assert!(tool.description.is_some());
        }
    }

    #[test]
    fn bridge_without_dispatcher_fails_closed() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let error = bridge
            .invoke_tool("listPets", json!({"limit": 10}))
            .unwrap_err();
        assert!(matches!(error, BridgeError::Kernel(_)));
    }

    #[test]
    fn bridge_invoke_with_dispatcher() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({
                    "method": method,
                    "url": url,
                    "pets": [{"name": "Fido"}]
                }),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));
        let result = bridge.invoke_tool("listPets", json!({"limit": 5})).unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["httpStatus"], 200);
        assert_eq!(result["structuredContent"]["method"], "GET");
    }

    #[test]
    fn bridge_invoke_dispatcher_error_response() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 404,
                body: json!({"error": "not found"}),
                observed_body_bytes: Some(64),
                is_error: true,
            })
        }));
        let result = bridge
            .invoke_tool("getPet", json!({"petId": "999"}))
            .unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["httpStatus"], 404);
    }

    #[test]
    fn bridge_dispatcher_without_egress_contract_fails_closed() {
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));
        let error = bridge.invoke_tool("listPets", json!({})).unwrap_err();
        assert!(format!("{error}").contains("requires an HttpEgressContract"));
    }

    #[test]
    fn bridge_dispatcher_response_body_cap_is_enforced() {
        let mut config = petstore_config_with_egress();
        config
            .egress_contract
            .as_mut()
            .expect("egress contract")
            .max_response_bytes = 8;
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, config).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"oversized": "response"}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));
        let error = bridge.invoke_tool("listPets", json!({})).unwrap_err();
        assert!(format!("{error}").contains("response size"));
    }

    #[test]
    fn bridge_dispatcher_response_body_cap_uses_observed_raw_bytes() {
        let mut config = petstore_config_with_egress();
        config
            .egress_contract
            .as_mut()
            .expect("egress contract")
            .max_response_bytes = 16;
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, config).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                observed_body_bytes: Some(128),
                is_error: false,
            })
        }));
        let error = bridge.invoke_tool("listPets", json!({})).unwrap_err();
        assert!(format!("{error}").contains("response size"));
    }

    #[test]
    fn bridge_dispatcher_requires_observed_response_body_bytes() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                observed_body_bytes: None,
                is_error: false,
            })
        }));

        let error = bridge.invoke_tool("listPets", json!({})).unwrap_err();

        assert!(format!("{error}").contains("observed_body_bytes"));
    }

    #[test]
    fn bridge_invoke_unknown_tool_returns_error() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let err = bridge.invoke_tool("nonexistent", json!({})).unwrap_err();
        assert!(matches!(err, BridgeError::ToolNotFound(_)));
    }

    #[test]
    fn bridge_manifest_description_includes_api_info() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let desc = bridge.manifest().description.as_deref().unwrap_or("");
        assert!(desc.contains("Petstore"));
    }

    #[test]
    fn bridge_manifest_clone() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let clone = bridge.manifest_clone();
        assert_eq!(clone.server_id, bridge.manifest().server_id);
        assert_eq!(clone.tools.len(), bridge.manifest().tools.len());
    }

    #[test]
    fn bridge_as_tool_server_implements_connection() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let server = bridge.as_tool_server();
        assert_eq!(server.server_id(), "petstore-bridge");
        assert_eq!(server.tool_names().len(), 4);
    }

    #[tokio::test]
    async fn bridge_tool_server_invoke_delegates() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let server = bridge.as_tool_server();
        let error = server
            .invoke("listPets", json!({}), None)
            .await
            .unwrap_err();
        assert!(matches!(error, KernelError::ToolServerError(_)));
    }

    #[tokio::test]
    async fn bridge_tool_server_invoke_unknown_tool_errors() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let server = bridge.as_tool_server();
        let err = server
            .invoke("nonexistent", json!({}), None)
            .await
            .unwrap_err();
        assert!(matches!(err, KernelError::ToolServerError(_)));
    }

    #[tokio::test]
    async fn owned_bridge_tool_server_implements_connection() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let owned = OwnedBridgeToolServer::from_bridge(bridge);
        assert_eq!(owned.server_id(), "petstore-bridge");
        assert_eq!(owned.tool_names().len(), 4);
        let error = owned.invoke("listPets", json!({}), None).await.unwrap_err();
        assert!(matches!(error, KernelError::ToolServerError(_)));
    }

    #[tokio::test]
    async fn owned_bridge_tool_server_with_dispatcher() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));
        let owned = OwnedBridgeToolServer::from_bridge(bridge);
        let result = owned
            .invoke("createPet", json!({"body": {"name": "Buddy"}}), None)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["httpStatus"], 200);
    }

    #[test]
    fn bridge_error_display_openapi() {
        let err = BridgeError::OpenApi(OpenApiError::MissingField("info".into()));
        assert!(format!("{err}").contains("info"));
    }

    #[test]
    fn bridge_error_display_tool_not_found() {
        let err = BridgeError::ToolNotFound("missing".into());
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn bridge_error_display_upstream() {
        let err = BridgeError::UpstreamError("timeout".into());
        assert!(format!("{err}").contains("timeout"));
    }

    #[test]
    fn bridge_error_display_kernel() {
        let err = BridgeError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    #[test]
    fn bridge_mcp_tools_list_has_annotations() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let tools = bridge.mcp_tools_list();
        for tool in &tools {
            let annotations = tool.annotations.as_ref().expect("annotations");
            assert!(annotations.get("readOnlyHint").is_some());
        }
    }

    #[test]
    fn bridge_dispatcher_receives_correct_url() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"receivedUrl": url}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));
        let result = bridge
            .invoke_tool("getPet", json!({"petId": "42"}))
            .unwrap();
        let url = result["structuredContent"]["body"]["receivedUrl"]
            .as_str()
            .unwrap_or("");
        assert!(url.starts_with("https://93.184.216.34"));
    }

    #[test]
    fn bridge_dispatcher_expands_path_parameters() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"receivedUrl": url}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));

        let result = bridge
            .invoke_tool("getPet", json!({"petId": "pet-42"}))
            .unwrap();

        assert_eq!(
            result["structuredContent"]["body"]["receivedUrl"],
            "https://93.184.216.34/pets/pet-42"
        );
    }

    #[test]
    fn bridge_dispatcher_rejects_dot_segment_path_parameters() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when path parameter is a dot segment")
        }));

        for pet_id in [".", ".."] {
            let error = bridge
                .invoke_tool("getPet", json!({"petId": pet_id}))
                .unwrap_err();
            assert!(format!("{error}").contains("must not be a dot segment"));
        }
    }

    #[test]
    fn bridge_rejects_declared_path_parameter_missing_from_template() {
        let spec = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Bad API", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "getPet",
                        "parameters": [
                            { "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;

        let error = match OpenApiMcpBridge::from_spec(spec, petstore_config()) {
            Ok(_) => panic!("bridge should reject unused declared path parameters"),
            Err(error) => error,
        };

        assert!(format!("{error}").contains("declares unused path parameter `petId`"));
    }

    #[test]
    fn bridge_dispatcher_rejects_redirect_responses() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 302,
                body: json!({"location": "https://169.254.169.254/latest/meta-data"}),
                observed_body_bytes: Some(64),
                is_error: true,
            })
        }));

        let error = bridge
            .invoke_tool("getPet", json!({"petId": "pet-42"}))
            .unwrap_err();

        assert!(format!("{error}").contains("must not follow redirects"));
    }

    #[test]
    fn bridge_dispatcher_normalizes_base_url_trailing_slash() {
        let mut config = petstore_config_with_egress();
        config.base_url = "https://93.184.216.34/".to_string();
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, config).unwrap();
        bridge.set_dispatcher(Box::new(|_method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"receivedUrl": url}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));

        let result = bridge
            .invoke_tool("getPet", json!({"petId": "pet-42"}))
            .unwrap();

        assert_eq!(
            result["structuredContent"]["body"]["receivedUrl"],
            "https://93.184.216.34/pets/pet-42"
        );
    }

    #[test]
    fn bridge_dispatcher_appends_declared_query_parameters() {
        let spec = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Search API", "version": "1.0.0" },
            "paths": {
                "/pets/{petId}/notes": {
                    "get": {
                        "operationId": "searchPetNotes",
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "q",
                                "in": "query",
                                "required": true,
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;
        let mut bridge = OpenApiMcpBridge::from_spec(spec, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"receivedUrl": url}),
                observed_body_bytes: Some(64),
                is_error: false,
            })
        }));

        let result = bridge
            .invoke_tool(
                "searchPetNotes",
                json!({
                    "petId": "pet 42",
                    "q": "needs follow up",
                    "limit": 10,
                    "ignored": "not declared in OpenAPI"
                }),
            )
            .unwrap();

        assert_eq!(
            result["structuredContent"]["body"]["receivedUrl"],
            "https://93.184.216.34/pets/pet%2042/notes?q=needs%20follow%20up&limit=10"
        );
    }

    #[test]
    fn bridge_dispatcher_rejects_missing_required_query_parameter() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(required_query_spec(), petstore_config_with_egress())
                .unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when required query parameter is missing")
        }));

        let error = bridge
            .invoke_tool("searchPets", json!({"page": 2}))
            .unwrap_err();

        assert!(format!("{error}").contains("missing required query parameter `q`"));
    }

    #[test]
    fn bridge_dispatcher_rejects_missing_request_body_before_dispatcher() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when required request body is missing")
        }));

        let error = bridge
            .invoke_tool("createPet", json!({"name": "no-body"}))
            .unwrap_err();

        assert!(format!("{error}").contains("missing required request body `body`"));
    }

    #[test]
    fn bridge_dispatcher_allows_missing_optional_request_body() {
        let mut bridge = OpenApiMcpBridge::from_spec(
            optional_request_body_spec(),
            petstore_config_with_egress(),
        )
        .unwrap();
        bridge.set_dispatcher(Box::new(|method, url, args| {
            assert_eq!(method, "POST");
            assert_eq!(url, "https://93.184.216.34/optional-body");
            assert!(args.get("body").is_none());
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                observed_body_bytes: Some(11),
                is_error: false,
            })
        }));

        let result = bridge.invoke_tool("optionalBody", json!({})).unwrap();

        assert_eq!(result["structuredContent"]["body"]["ok"], true);
    }

    #[test]
    fn bridge_dispatcher_rejects_null_or_empty_required_query_parameter() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(required_query_spec(), petstore_config_with_egress())
                .unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when required query parameter is empty")
        }));

        for arguments in [json!({"q": null}), json!({"q": []})] {
            let error = bridge.invoke_tool("searchPets", arguments).unwrap_err();
            assert!(format!("{error}").contains("missing required query parameter `q`"));
        }
    }

    #[tokio::test]
    async fn owned_bridge_tool_server_rejects_missing_required_query_parameter() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(required_query_spec(), petstore_config_with_egress())
                .unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when owned bridge is missing a required query")
        }));
        let owned = OwnedBridgeToolServer::from_bridge(bridge);

        let error = owned
            .invoke("searchPets", json!({"page": 2}), None)
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("missing required query parameter `q`"));
    }

    #[tokio::test]
    async fn owned_bridge_tool_server_rejects_missing_request_body_before_dispatcher() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when owned bridge is missing a required body")
        }));
        let owned = OwnedBridgeToolServer::from_bridge(bridge);

        let error = owned
            .invoke("createPet", json!({"name": "no-body"}), None)
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("missing required request body `body`"));
    }

    #[test]
    fn bridge_dispatcher_rejects_missing_path_parameter() {
        let mut bridge =
            OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config_with_egress()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            panic!("dispatcher must not run when path parameter is missing")
        }));

        let error = bridge.invoke_tool("getPet", json!({})).unwrap_err();

        assert!(format!("{error}").contains("missing path parameter `petId`"));
    }

    #[test]
    fn bridge_rejects_undeclared_path_template_parameter() {
        let spec = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Bad Paths", "version": "1.0.0" },
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPet",
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;

        let error = match OpenApiMcpBridge::from_spec(spec, petstore_config()) {
            Ok(_) => panic!("undeclared path template parameter must reject at ingest"),
            Err(error) => error,
        };

        assert!(format!("{error}").contains("undeclared path parameter `petId`"));
    }

    #[test]
    fn expand_route_path_rejects_unmatched_closing_brace() {
        let error = expand_route_path("/pets/{petId}}", &json!({"petId": "42"})).unwrap_err();

        assert!(format!("{error}").contains("unmatched"));
    }

    #[test]
    fn bridge_route_binding_unknown_returns_none() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        assert!(bridge.route_binding("nope").is_none());
    }

    #[test]
    fn unpublished_operations_are_not_routable() {
        let spec = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Hidden API", "version": "1.0.0" },
            "paths": {
                "/visible": {
                    "get": {
                        "operationId": "visibleOp",
                        "responses": { "200": { "description": "OK" } }
                    }
                },
                "/hidden": {
                    "post": {
                        "operationId": "hiddenOp",
                        "x-chio-publish": false,
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;
        let bridge = OpenApiMcpBridge::from_spec(spec, petstore_config()).unwrap();

        assert!(bridge.tool_names().contains(&"visibleOp".to_string()));
        assert!(!bridge.tool_names().contains(&"hiddenOp".to_string()));
        assert!(bridge.route_binding("hiddenOp").is_none());
        assert!(matches!(
            bridge.invoke_tool("hiddenOp", json!({})),
            Err(BridgeError::ToolNotFound(name)) if name == "hiddenOp"
        ));
    }

    #[test]
    fn bridge_manifest_has_correct_version() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        assert_eq!(bridge.manifest().version, "1.0.0");
    }

    #[test]
    fn bridge_get_side_effects_for_read_only_operations() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let list_pets = bridge
            .manifest()
            .tools
            .iter()
            .find(|t| t.name == "listPets")
            .expect("listPets tool");
        // GET operations should be marked as no side effects
        assert!(!list_pets.has_side_effects);

        let create_pet = bridge
            .manifest()
            .tools
            .iter()
            .find(|t| t.name == "createPet")
            .expect("createPet tool");
        // POST operations should have side effects
        assert!(create_pet.has_side_effects);
    }

    #[test]
    fn bridge_delete_operation_has_side_effects() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let delete_pet = bridge
            .manifest()
            .tools
            .iter()
            .find(|t| t.name == "deletePet")
            .expect("deletePet tool");
        assert!(delete_pet.has_side_effects);
    }
}
