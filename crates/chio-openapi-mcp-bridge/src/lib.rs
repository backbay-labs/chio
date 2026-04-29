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

use std::collections::BTreeMap;

#[cfg(feature = "fuzz")]
pub mod fuzz;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_manifest::ToolManifest;
use chio_mcp_edge::McpToolInfo;
use chio_openapi::{GeneratorConfig, ManifestGenerator, OpenApiError, OpenApiSpec};
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
    /// Whether the response indicates an error.
    pub is_error: bool,
}

/// HTTP dispatch function type.
///
/// Bridge users provide a function that performs the actual HTTP call.
/// This allows the bridge to remain transport-agnostic (no reqwest dependency).
pub type HttpDispatcher =
    dyn Fn(&str, &str, &Value) -> Result<BridgedResponse, BridgeError> + Send + Sync;

/// The OpenAPI-MCP bridge.
///
/// Parses an OpenAPI spec, generates MCP tool definitions, and dispatches
/// invocations through the kernel before calling the upstream HTTP API.
pub struct OpenApiMcpBridge {
    config: BridgeConfig,
    manifest: ToolManifest,
    /// Maps tool name to its route binding.
    route_bindings: BTreeMap<String, RouteBinding>,
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

        let mut route_bindings = BTreeMap::new();
        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let tool_name = operation
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("{} {}", method_str.to_uppercase(), path));
                route_bindings.insert(
                    tool_name,
                    RouteBinding {
                        method: method_str.to_uppercase(),
                        path: path.clone(),
                    },
                );
            }
        }

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
            route_bindings,
            dispatcher: None,
        })
    }

    /// Set the HTTP dispatcher function.
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
        self.route_bindings.get(tool_name)
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

    /// Invoke a bridged tool. If a dispatcher is set, the actual HTTP call
    /// is made. Otherwise, a simulated response is returned.
    pub fn invoke_tool(&self, tool_name: &str, arguments: Value) -> Result<Value, BridgeError> {
        let binding = self
            .route_bindings
            .get(tool_name)
            .ok_or_else(|| BridgeError::ToolNotFound(tool_name.to_string()))?;

        if let Some(dispatcher) = &self.dispatcher {
            let url = format!("{}{}", self.config.base_url, binding.path);
            let response = dispatcher(&binding.method, &url, &arguments)?;
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string(&response.body)
                        .unwrap_or_else(|_| "{}".to_string()),
                }],
                "isError": response.is_error,
                "structuredContent": {
                    "httpStatus": response.status,
                    "method": binding.method,
                    "path": binding.path,
                    "body": response.body,
                }
            }))
        } else {
            // Simulation mode: return the route binding info
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Bridged {} {} (no dispatcher configured)",
                        binding.method, binding.path
                    ),
                }],
                "isError": false,
                "structuredContent": {
                    "bridgeMode": "simulation",
                    "method": binding.method,
                    "path": binding.path,
                    "arguments": arguments,
                }
            }))
        }
    }

    /// Convert to a `ToolServerConnection` for kernel integration.
    pub fn as_tool_server(&self) -> BridgeToolServer<'_> {
        BridgeToolServer { bridge: self }
    }
}

/// Implements `ToolServerConnection` so the bridge can be registered
/// with an Chio kernel for capability validation and receipt signing.
pub struct BridgeToolServer<'a> {
    bridge: &'a OpenApiMcpBridge,
}

impl ToolServerConnection for BridgeToolServer<'_> {
    fn server_id(&self) -> &str {
        &self.bridge.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.bridge.tool_names()
    }

    fn invoke(
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
    route_bindings: BTreeMap<String, RouteBinding>,
    dispatcher: Option<Box<HttpDispatcher>>,
}

impl OwnedBridgeToolServer {
    /// Create from a bridge, consuming it.
    pub fn from_bridge(bridge: OpenApiMcpBridge) -> Self {
        Self {
            config: bridge.config,
            manifest: bridge.manifest,
            route_bindings: bridge.route_bindings,
            dispatcher: bridge.dispatcher,
        }
    }

    fn invoke_tool(&self, tool_name: &str, arguments: Value) -> Result<Value, BridgeError> {
        let binding = self
            .route_bindings
            .get(tool_name)
            .ok_or_else(|| BridgeError::ToolNotFound(tool_name.to_string()))?;

        if let Some(dispatcher) = &self.dispatcher {
            let url = format!("{}{}", self.config.base_url, binding.path);
            let response = dispatcher(&binding.method, &url, &arguments)?;
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string(&response.body)
                        .unwrap_or_else(|_| "{}".to_string()),
                }],
                "isError": response.is_error,
                "structuredContent": {
                    "httpStatus": response.status,
                    "method": binding.method,
                    "path": binding.path,
                    "body": response.body,
                }
            }))
        } else {
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Bridged {} {} (no dispatcher configured)",
                        binding.method, binding.path
                    ),
                }],
                "isError": false,
                "structuredContent": {
                    "bridgeMode": "simulation",
                    "method": binding.method,
                    "path": binding.path,
                    "arguments": arguments,
                }
            }))
        }
    }

    /// Get the generated manifest.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }
}

impl ToolServerConnection for OwnedBridgeToolServer {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest.tools.iter().map(|t| t.name.clone()).collect()
    }

    fn invoke(
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
            public_key: "aabbccdd".to_string(),
            base_url: "https://api.example.com".to_string(),
        }
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
    fn bridge_invoke_simulation_mode() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let result = bridge
            .invoke_tool("listPets", json!({"limit": 10}))
            .unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["bridgeMode"], "simulation");
        assert_eq!(result["structuredContent"]["method"], "GET");
        assert_eq!(result["structuredContent"]["path"], "/pets");
    }

    #[test]
    fn bridge_invoke_with_dispatcher() {
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        bridge.set_dispatcher(Box::new(|method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({
                    "method": method,
                    "url": url,
                    "pets": [{"name": "Fido"}]
                }),
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
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 404,
                body: json!({"error": "not found"}),
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

    #[test]
    fn bridge_tool_server_invoke_delegates() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let server = bridge.as_tool_server();
        let result = server.invoke("listPets", json!({}), None).unwrap();
        assert_eq!(result["structuredContent"]["bridgeMode"], "simulation");
    }

    #[test]
    fn bridge_tool_server_invoke_unknown_tool_errors() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let server = bridge.as_tool_server();
        let err = server.invoke("nonexistent", json!({}), None).unwrap_err();
        assert!(matches!(err, KernelError::ToolServerError(_)));
    }

    #[test]
    fn owned_bridge_tool_server_implements_connection() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        let owned = OwnedBridgeToolServer::from_bridge(bridge);
        assert_eq!(owned.server_id(), "petstore-bridge");
        assert_eq!(owned.tool_names().len(), 4);
        let result = owned.invoke("listPets", json!({}), None).unwrap();
        assert_eq!(result["structuredContent"]["bridgeMode"], "simulation");
    }

    #[test]
    fn owned_bridge_tool_server_with_dispatcher() {
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, _url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"ok": true}),
                is_error: false,
            })
        }));
        let owned = OwnedBridgeToolServer::from_bridge(bridge);
        let result = owned
            .invoke("createPet", json!({"name": "Buddy"}), None)
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
        let mut bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        bridge.set_dispatcher(Box::new(|_method, url, _args| {
            Ok(BridgedResponse {
                status: 200,
                body: json!({"receivedUrl": url}),
                is_error: false,
            })
        }));
        let result = bridge
            .invoke_tool("getPet", json!({"petId": "42"}))
            .unwrap();
        let url = result["structuredContent"]["body"]["receivedUrl"]
            .as_str()
            .unwrap_or("");
        assert!(url.starts_with("https://api.example.com"));
    }

    #[test]
    fn bridge_route_binding_unknown_returns_none() {
        let bridge = OpenApiMcpBridge::from_spec(PETSTORE_SPEC, petstore_config()).unwrap();
        assert!(bridge.route_binding("nope").is_none());
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
