//! # chio-mcp-adapter
//!
//! Compatibility adapter that wraps an existing MCP (Model Context Protocol)
//! server and exposes it as a Chio tool server. This allows incremental
//! migration: existing MCP tools continue to work, but gain the security
//! properties of Chio (capability tokens, guard evaluation, signed receipts).
//!
//! The adapter:
//!
//! 1. Reads the MCP server's tool list (via `tools/list`) and generates a
//!    Chio `ToolManifest`.
//! 2. Translates incoming Chio `ToolCallRequest` messages into MCP
//!    `tools/call` requests.
//! 3. Translates MCP responses back into Chio `ToolCallResponse` format.
//!
//! The MCP server itself runs in a sandboxed subprocess. The adapter sits
//! between the Chio kernel and the MCP server, providing the security
//! boundary that MCP lacks.

use std::sync::{Arc, Mutex};

use chio_core::session::CreateElicitationOperation;
use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, ServerId,
};
use chio_kernel::{
    KernelError, NestedFlowBridge, PromptProvider, ResourceProvider, ToolServerConnection,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use tracing::warn;

pub mod edge {
    pub use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig, McpExposedTool};
}
pub mod native;
pub mod transport;

/// libFuzzer entry-point module for `chio-mcp-adapter`.
///
/// Gated behind the `fuzz` Cargo feature so it only compiles into the
/// standalone `chio-fuzz` workspace at `../../fuzz`. Production builds never
/// pull in `arbitrary`, never expose these symbols, and never get recompiled
/// with libFuzzer instrumentation.
#[cfg(feature = "fuzz")]
pub mod fuzz;

pub use chio_mcp_edge::{
    AdapterError, ChioMcpEdge, McpEdgeConfig, McpExposedTool, McpServerCapabilities, McpToolInfo,
    McpToolResult, McpTransport,
};
pub use native::{
    NativeChioService, NativeChioServiceBuilder, NativePrompt, NativeResource, NativeTool,
};
pub use transport::StdioMcpTransport;

/// Configuration for the MCP adapter.
#[derive(Clone)]
pub struct McpAdapterConfig {
    /// Server ID to assign to the wrapped MCP server.
    pub server_id: ServerId,

    /// Human-readable name for the adapted server.
    pub server_name: String,

    /// Version string for the adapted server.
    pub server_version: String,

    /// Hex-encoded Ed25519 public key for the manifest.
    pub public_key: String,
}

/// Adapter that wraps an MCP server as a Chio tool server.
///
/// Usage:
///
/// ```ignore
/// let transport = StdioMcpTransport::spawn("npx", &["-y", "some-mcp-server"]);
/// let config = McpAdapterConfig { /* ... */ };
/// let adapter = McpAdapter::new(config, Box::new(transport));
/// let manifest = adapter.generate_manifest()?;
/// let result = adapter.invoke("read_file", json!({"path": "/tmp/test.txt"}))?;
/// ```
#[derive(Clone)]
pub struct McpAdapter {
    config: McpAdapterConfig,
    transport: Arc<dyn McpTransport>,
}

/// A Chio tool-server connection backed by a wrapped MCP server.
#[derive(Clone)]
pub struct AdaptedMcpServer {
    adapter: McpAdapter,
    manifest: ToolManifest,
}

pub struct AdaptedMcpResourceProvider {
    adapter: McpAdapter,
}

pub struct AdaptedMcpPromptProvider {
    adapter: McpAdapter,
}

/// Transport wrapper that serializes upstream MCP calls through one shared gate.
///
/// This is useful when multiple Chio sessions need to share a single wrapped
/// MCP transport without tripping the transport's single-active-request guard.
pub struct SerializedMcpTransport {
    inner: Arc<dyn McpTransport>,
    request_gate: Mutex<()>,
}

impl SerializedMcpTransport {
    pub fn from_arc(inner: Arc<dyn McpTransport>) -> Self {
        Self {
            inner,
            request_gate: Mutex::new(()),
        }
    }

    fn with_request_gate<T>(
        &self,
        action: impl FnOnce(&dyn McpTransport) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let _guard = self.request_gate.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!("shared MCP transport gate poisoned: {error}"))
        })?;
        action(self.inner.as_ref())
    }
}

impl McpTransport for SerializedMcpTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        self.inner.capabilities()
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        self.with_request_gate(|inner| inner.list_tools())
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.with_request_gate(|inner| inner.call_tool(tool_name, arguments))
    }

    fn call_tool_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<McpToolResult, AdapterError> {
        self.with_request_gate(|inner| {
            inner.call_tool_with_nested_flow(tool_name, arguments, nested_flow_bridge)
        })
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_resources())
    }

    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_resource_templates())
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        self.with_request_gate(|inner| inner.read_resource(uri))
    }

    fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_prompts())
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        self.with_request_gate(|inner| inner.get_prompt(name, arguments))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.with_request_gate(|inner| {
            inner.complete_prompt_argument(name, argument_name, value, context)
        })
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.with_request_gate(|inner| {
            inner.complete_resource_argument(uri, argument_name, value, context)
        })
    }

    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        self.inner.drain_notifications()
    }
}

impl McpAdapter {
    pub fn new(config: McpAdapterConfig, transport: Box<dyn McpTransport>) -> Self {
        Self {
            config,
            transport: Arc::from(transport),
        }
    }

    /// Create an adapter that spawns an MCP server as a subprocess.
    ///
    /// This is a convenience constructor that creates a [`StdioMcpTransport`]
    /// and wraps it in an `McpAdapter`. The MCP server is spawned immediately
    /// and the `initialize` handshake is performed before this returns.
    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
    ) -> Result<Self, AdapterError> {
        let transport = StdioMcpTransport::spawn(command, args)?;
        Ok(Self::new(config, Box::new(transport)))
    }

    /// Query the MCP server for its tool list and generate a Chio manifest.
    ///
    /// Each MCP tool becomes a `ToolDefinition` in the manifest. Since MCP
    /// tools provide no side-effect metadata, all adapted tools are marked
    /// `has_side_effects: true` (fail-closed).
    pub fn generate_manifest(&self) -> Result<ToolManifest, AdapterError> {
        let mcp_tools = self.transport.list_tools()?;

        let tools: Vec<ToolDefinition> = mcp_tools
            .into_iter()
            .map(|t| ToolDefinition {
                name: t.name,
                description: t.description.unwrap_or_default(),
                input_schema: t.input_schema,
                output_schema: t.output_schema,
                pricing: None,
                has_side_effects: infer_has_side_effects(t.annotations.as_ref()),
                latency_hint: None,
            })
            .collect();

        let manifest = ToolManifest {
            schema: "chio.manifest.v1".into(),
            server_id: self.config.server_id.clone(),
            name: self.config.server_name.clone(),
            description: Some("MCP server adapted to Chio protocol".into()),
            version: self.config.server_version.clone(),
            tools,
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: self.config.public_key.clone(),
        };

        chio_manifest::validate_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn capabilities(&self) -> McpServerCapabilities {
        self.transport.capabilities()
    }

    /// Invoke a tool on the wrapped MCP server.
    ///
    /// This translates the Chio-style call into an MCP `tools/call` request
    /// and converts the response back.
    pub fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.invoke_with_nested_flow(tool_name, arguments, None)
    }

    pub fn invoke_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, AdapterError> {
        let result =
            self.transport
                .call_tool_with_nested_flow(tool_name, arguments, nested_flow_bridge)?;

        let mut output = serde_json::Map::new();
        output.insert(
            "content".to_string(),
            serde_json::Value::Array(result.content),
        );
        if let Some(structured_content) = result.structured_content {
            output.insert("structuredContent".to_string(), structured_content);
        }
        if let Some(is_error) = result.is_error {
            output.insert("isError".to_string(), serde_json::Value::Bool(is_error));
        }

        Ok(serde_json::Value::Object(output))
    }

    pub fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        self.transport.list_resources()
    }

    pub fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        self.transport.list_resource_templates()
    }

    pub fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        self.transport.read_resource(uri)
    }

    pub fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        self.transport.list_prompts()
    }

    pub fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        self.transport.get_prompt(name, arguments)
    }

    pub fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.transport
            .complete_prompt_argument(name, argument_name, value, context)
    }

    pub fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.transport
            .complete_resource_argument(uri, argument_name, value, context)
    }
}

impl AdaptedMcpServer {
    pub fn new(adapter: McpAdapter) -> Result<Self, AdapterError> {
        let manifest = adapter.generate_manifest()?;
        Ok(Self { adapter, manifest })
    }

    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
    ) -> Result<Self, AdapterError> {
        Self::new(McpAdapter::from_command(command, args, config)?)
    }

    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    pub fn manifest_clone(&self) -> ToolManifest {
        self.manifest.clone()
    }

    pub fn upstream_capabilities(&self) -> McpServerCapabilities {
        self.adapter.capabilities()
    }

    pub fn notification_source(&self) -> Arc<dyn McpTransport> {
        self.adapter.transport.clone()
    }

    pub fn resource_provider(&self) -> Option<AdaptedMcpResourceProvider> {
        self.upstream_capabilities()
            .resources_supported
            .then(|| AdaptedMcpResourceProvider {
                adapter: self.adapter.clone(),
            })
    }

    pub fn prompt_provider(&self) -> Option<AdaptedMcpPromptProvider> {
        self.upstream_capabilities()
            .prompts_supported
            .then(|| AdaptedMcpPromptProvider {
                adapter: self.adapter.clone(),
            })
    }
}

impl ToolServerConnection for AdaptedMcpServer {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.adapter
            .invoke_with_nested_flow(tool_name, arguments, nested_flow_bridge)
            .map_err(map_tool_invocation_error)
    }
}

impl ResourceProvider for AdaptedMcpResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        self.adapter.list_resources().unwrap_or_else(|error| {
            warn!(error = %error, "wrapped MCP resources/list failed");
            vec![]
        })
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        self.adapter
            .list_resource_templates()
            .unwrap_or_else(|error| {
                warn!(error = %error, "wrapped MCP resources/templates/list failed");
                vec![]
            })
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        self.adapter
            .read_resource(uri)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        self.adapter
            .complete_resource_argument(uri, argument_name, value, context)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

impl PromptProvider for AdaptedMcpPromptProvider {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        self.adapter.list_prompts().unwrap_or_else(|error| {
            warn!(error = %error, "wrapped MCP prompts/list failed");
            vec![]
        })
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        self.adapter
            .get_prompt(name, arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        self.adapter
            .complete_prompt_argument(name, argument_name, value, context)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

fn map_tool_invocation_error(error: AdapterError) -> KernelError {
    match error {
        AdapterError::RequestCancelled { request_id, reason } => {
            KernelError::RequestCancelled { request_id, reason }
        }
        AdapterError::McpError {
            code: -32042,
            message,
            data,
        } => match parse_url_elicitation_required_error(message, data) {
            Ok(error) => error,
            Err(message) => KernelError::ToolServerError(message),
        },
        AdapterError::ConnectionFailed(message) | AdapterError::ParseError(message) => {
            KernelError::RequestIncomplete(message)
        }
        other => KernelError::ToolServerError(other.to_string()),
    }
}

fn parse_url_elicitation_required_error(
    message: String,
    data: Option<serde_json::Value>,
) -> Result<KernelError, String> {
    let data = data
        .ok_or_else(|| "upstream MCP URL-required error is missing structured data".to_string())?;
    let elicitations = data.get("elicitations").cloned().ok_or_else(|| {
        "upstream MCP URL-required error is missing data.elicitations".to_string()
    })?;
    let elicitations: Vec<CreateElicitationOperation> = serde_json::from_value(elicitations)
        .map_err(|error| format!("failed to parse upstream URL-required elicitations: {error}"))?;
    if elicitations.is_empty() {
        return Err(
            "upstream MCP URL-required error must include at least one elicitation".to_string(),
        );
    }
    if elicitations
        .iter()
        .any(|elicitation| !matches!(elicitation, CreateElicitationOperation::Url { .. }))
    {
        return Err(
            "upstream MCP URL-required error must include only URL-mode elicitations".to_string(),
        );
    }

    Ok(KernelError::UrlElicitationsRequired {
        message,
        elicitations,
    })
}

fn infer_has_side_effects(annotations: Option<&serde_json::Value>) -> bool {
    annotations
        .and_then(|value| value.get("readOnlyHint"))
        .and_then(serde_json::Value::as_bool)
        .map(|read_only| !read_only)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::session::CreateElicitationOperation;
    use chio_kernel::KernelError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    enum MockCallBehavior {
        Success(McpToolResult),
        UrlRequired {
            message: String,
            data: serde_json::Value,
        },
        McpError {
            code: i64,
            message: String,
        },
        ConnectionFailed(String),
    }

    struct MockTransport {
        tools: Vec<McpToolInfo>,
        call_behavior: MockCallBehavior,
        call_count: AtomicUsize,
        resources: Vec<ResourceDefinition>,
        resource_templates: Vec<ResourceTemplateDefinition>,
        prompts: Vec<chio_core::PromptDefinition>,
        capabilities: McpServerCapabilities,
    }

    impl MockTransport {
        fn simple(tools: Vec<McpToolInfo>, call_behavior: MockCallBehavior) -> Self {
            Self {
                tools,
                call_behavior,
                call_count: AtomicUsize::new(0),
                resources: vec![],
                resource_templates: vec![],
                prompts: vec![],
                capabilities: McpServerCapabilities::default(),
            }
        }

        fn with_capabilities(mut self, capabilities: McpServerCapabilities) -> Self {
            self.capabilities = capabilities;
            self
        }

        fn with_resources(mut self, resources: Vec<ResourceDefinition>) -> Self {
            self.resources = resources;
            self
        }

        fn with_resource_templates(mut self, templates: Vec<ResourceTemplateDefinition>) -> Self {
            self.resource_templates = templates;
            self
        }

        fn with_prompts(mut self, prompts: Vec<chio_core::PromptDefinition>) -> Self {
            self.prompts = prompts;
            self
        }
    }

    impl McpTransport for MockTransport {
        fn capabilities(&self) -> McpServerCapabilities {
            self.capabilities.clone()
        }

        fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
            Ok(self.tools.clone())
        }

        fn call_tool(
            &self,
            tool_name: &str,
            _arguments: serde_json::Value,
        ) -> Result<McpToolResult, AdapterError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let _ = tool_name;
            match &self.call_behavior {
                MockCallBehavior::Success(result) => Ok(result.clone()),
                MockCallBehavior::UrlRequired { message, data } => Err(AdapterError::McpError {
                    code: -32042,
                    message: message.clone(),
                    data: Some(data.clone()),
                }),
                MockCallBehavior::McpError { code, message } => Err(AdapterError::McpError {
                    code: *code,
                    message: message.clone(),
                    data: None,
                }),
                MockCallBehavior::ConnectionFailed(msg) => {
                    Err(AdapterError::ConnectionFailed(msg.clone()))
                }
            }
        }

        fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
            Ok(self.resources.clone())
        }

        fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
            Ok(self.resource_templates.clone())
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
            for resource in &self.resources {
                if resource.uri == uri {
                    return Ok(Some(vec![ResourceContent {
                        uri: uri.to_string(),
                        mime_type: resource.mime_type.clone(),
                        text: Some(format!("content of {uri}")),
                        blob: None,
                        annotations: None,
                    }]));
                }
            }
            Ok(None)
        }

        fn list_prompts(&self) -> Result<Vec<chio_core::PromptDefinition>, AdapterError> {
            Ok(self.prompts.clone())
        }

        fn get_prompt(
            &self,
            name: &str,
            _arguments: serde_json::Value,
        ) -> Result<Option<chio_core::PromptResult>, AdapterError> {
            if self.prompts.iter().any(|p| p.name == name) {
                Ok(Some(chio_core::PromptResult {
                    description: Some(format!("Prompt: {name}")),
                    messages: vec![chio_core::PromptMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({"type": "text", "text": format!("prompt {name}")}),
                    }],
                }))
            } else {
                Ok(None)
            }
        }

        fn complete_prompt_argument(
            &self,
            _name: &str,
            _argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, AdapterError> {
            Ok(Some(CompletionResult {
                total: Some(1),
                has_more: false,
                values: vec![format!("{value}-completed")],
            }))
        }

        fn complete_resource_argument(
            &self,
            _uri: &str,
            _argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, AdapterError> {
            Ok(Some(CompletionResult {
                total: Some(1),
                has_more: false,
                values: vec![format!("{value}-res-completed")],
            }))
        }
    }

    fn default_config() -> McpAdapterConfig {
        McpAdapterConfig {
            server_id: "mcp-test".into(),
            server_name: "Test".into(),
            server_version: "0.1.0".into(),
            public_key: "aabbccdd".into(),
        }
    }

    fn text_tool_info(name: &str) -> McpToolInfo {
        McpToolInfo {
            name: name.into(),
            title: None,
            description: Some(format!("Tool {name}")),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        }
    }

    fn success_result(text: &str) -> McpToolResult {
        McpToolResult {
            content: vec![serde_json::json!({"type": "text", "text": text})],
            structured_content: None,
            is_error: Some(false),
        }
    }

    // ---- Manifest generation tests ----

    #[test]
    fn generate_manifest_from_mcp() {
        let transport = MockTransport::simple(
            vec![McpToolInfo {
                name: "read_file".into(),
                title: Some("Read File".into()),
                description: Some("Read a file".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "string"})),
                annotations: Some(serde_json::json!({"readOnlyHint": true})),
                execution: None,
            }],
            MockCallBehavior::Success(success_result("called read_file")),
        );

        let config = McpAdapterConfig {
            server_id: "mcp-fs".into(),
            server_name: "Filesystem MCP".into(),
            server_version: "1.0.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapter = McpAdapter::new(config, Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("manifest: {e}"));

        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "read_file");
        assert_eq!(
            manifest.tools[0].output_schema,
            Some(serde_json::json!({"type": "string"}))
        );
        assert!(!manifest.tools[0].has_side_effects);
    }

    #[test]
    fn manifest_multiple_tools_preserves_order() {
        let tools = vec![
            text_tool_info("alpha"),
            text_tool_info("beta"),
            text_tool_info("gamma"),
        ];
        let transport =
            MockTransport::simple(tools, MockCallBehavior::Success(success_result("ok")));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("{e}"));
        let names: Vec<&str> = manifest.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn manifest_infers_side_effects_from_annotations() {
        let tool_readonly = McpToolInfo {
            name: "safe".into(),
            title: None,
            description: Some("Safe".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: Some(serde_json::json!({"readOnlyHint": true})),
            execution: None,
        };
        let tool_write = McpToolInfo {
            name: "danger".into(),
            title: None,
            description: Some("Danger".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: Some(serde_json::json!({"readOnlyHint": false})),
            execution: None,
        };
        let tool_none = McpToolInfo {
            name: "unknown".into(),
            title: None,
            description: Some("Unknown".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        };
        let transport = MockTransport::simple(
            vec![tool_readonly, tool_write, tool_none],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !manifest.tools[0].has_side_effects,
            "readOnly=true should be no side effects"
        );
        assert!(
            manifest.tools[1].has_side_effects,
            "readOnly=false should have side effects"
        );
        assert!(
            manifest.tools[2].has_side_effects,
            "missing annotations defaults to side effects (fail-closed)"
        );
    }

    #[test]
    fn manifest_empty_tools_list_rejected() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let err = adapter.generate_manifest().unwrap_err();
        assert!(matches!(err, AdapterError::ManifestError(_)));
    }

    #[test]
    fn manifest_schema_is_correct() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(manifest.schema, "chio.manifest.v1");
    }

    #[test]
    fn manifest_carries_server_metadata() {
        let config = McpAdapterConfig {
            server_id: "my-server".into(),
            server_name: "My Server".into(),
            server_version: "2.0.0".into(),
            public_key: "deadbeef".into(),
        };
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapter = McpAdapter::new(config, Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(manifest.server_id, "my-server");
        assert_eq!(manifest.name, "My Server");
        assert_eq!(manifest.version, "2.0.0");
        assert_eq!(manifest.public_key, "deadbeef");
    }

    // ---- Invocation tests ----

    #[test]
    fn invoke_tool_via_adapter() {
        let transport = MockTransport::simple(
            vec![],
            MockCallBehavior::Success(success_result("called some_tool")),
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let result = adapter
            .invoke("some_tool", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("invoke: {e}"));

        let content = result["content"]
            .as_array()
            .unwrap_or_else(|| panic!("expected content array"));
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["text"], "called some_tool");
    }

    #[test]
    fn invoke_returns_structured_content_when_present() {
        let result = McpToolResult {
            content: vec![serde_json::json!({"type": "text", "text": "hello"})],
            structured_content: Some(serde_json::json!({"weather": "sunny"})),
            is_error: None,
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("t", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(output["structuredContent"]["weather"], "sunny");
    }

    #[test]
    fn invoke_returns_is_error_flag() {
        let result = McpToolResult {
            content: vec![serde_json::json!({"type": "text", "text": "fail"})],
            structured_content: None,
            is_error: Some(true),
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("t", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(output["isError"], true);
    }

    #[test]
    fn invoke_omits_is_error_when_none() {
        let result = McpToolResult {
            content: vec![serde_json::json!({"type": "text", "text": "ok"})],
            structured_content: None,
            is_error: None,
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("t", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(output.get("isError").is_none());
    }

    #[test]
    fn invoke_multiple_content_chunks() {
        let result = McpToolResult {
            content: vec![
                serde_json::json!({"type": "text", "text": "chunk1"}),
                serde_json::json!({"type": "text", "text": "chunk2"}),
                serde_json::json!({"type": "text", "text": "chunk3"}),
            ],
            structured_content: None,
            is_error: Some(false),
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("t", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        let content = output["content"]
            .as_array()
            .unwrap_or_else(|| panic!("content"));
        assert_eq!(content.len(), 3);
        assert_eq!(content[2]["text"], "chunk3");
    }

    // ---- Error path tests ----

    #[test]
    fn invoke_connection_failed_produces_adapter_error() {
        let transport = MockTransport::simple(
            vec![],
            MockCallBehavior::ConnectionFailed("pipe broken".to_string()),
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let err = adapter.invoke("t", serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AdapterError::ConnectionFailed(_)));
    }

    #[test]
    fn invoke_mcp_error_non_url_code_surfaces_as_mcp_error() {
        let transport = MockTransport::simple(
            vec![],
            MockCallBehavior::McpError {
                code: -32601,
                message: "method not found".to_string(),
            },
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let err = adapter.invoke("t", serde_json::json!({})).unwrap_err();
        match err {
            AdapterError::McpError { code, message, .. } => {
                assert_eq!(code, -32601);
                assert_eq!(message, "method not found");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn map_tool_invocation_error_connection_failed_becomes_request_incomplete() {
        let err = map_tool_invocation_error(AdapterError::ConnectionFailed("oops".into()));
        assert!(matches!(err, KernelError::RequestIncomplete(_)));
    }

    #[test]
    fn map_tool_invocation_error_parse_error_becomes_request_incomplete() {
        let err = map_tool_invocation_error(AdapterError::ParseError("bad json".into()));
        assert!(matches!(err, KernelError::RequestIncomplete(_)));
    }

    #[test]
    fn map_tool_invocation_error_request_cancelled_preserved() {
        let request_id = chio_core::session::RequestId::from("req-123".to_string());
        let err = map_tool_invocation_error(AdapterError::RequestCancelled {
            request_id: request_id.clone(),
            reason: "user cancelled".into(),
        });
        match err {
            KernelError::RequestCancelled {
                request_id: id,
                reason,
            } => {
                assert_eq!(id, request_id);
                assert_eq!(reason, "user cancelled");
            }
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn map_tool_invocation_error_generic_mcp_error_becomes_tool_server_error() {
        let err = map_tool_invocation_error(AdapterError::McpError {
            code: -32000,
            message: "custom error".into(),
            data: None,
        });
        assert!(matches!(err, KernelError::ToolServerError(_)));
    }

    // ---- URL elicitation error mapping ----

    #[test]
    fn adapted_server_exposes_manifest_tool_names() {
        let transport = MockTransport::simple(
            vec![text_tool_info("read_file"), text_tool_info("write_file")],
            MockCallBehavior::Success(success_result("called read_file")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("adapted server: {e}"));
        assert_eq!(adapted.server_id(), "mcp-test");
        assert_eq!(
            adapted.tool_names(),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
    }

    #[test]
    fn adapted_server_maps_url_required_errors_into_kernel_errors() {
        let transport = MockTransport::simple(
            vec![McpToolInfo {
                name: "authorize".into(),
                title: None,
                description: Some("Requires URL elicitation".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                annotations: None,
                execution: None,
            }],
            MockCallBehavior::UrlRequired {
                message: "URL elicitation is required for this operation".to_string(),
                data: serde_json::json!({
                    "elicitations": [{
                        "mode": "url",
                        "message": "Complete authorization in your browser",
                        "url": "https://example.com/authorize",
                        "elicitationId": "elicit-auth"
                    }]
                }),
            },
        );

        let config = McpAdapterConfig {
            server_id: "mcp-auth".into(),
            server_name: "Auth".into(),
            server_version: "0.1.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapted = AdaptedMcpServer::new(McpAdapter::new(config, Box::new(transport)))
            .unwrap_or_else(|e| panic!("adapted server: {e}"));
        let error = adapted
            .invoke("authorize", serde_json::json!({}), None)
            .expect_err("invoke should surface URL-required error");

        match error {
            KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                assert_eq!(message, "URL elicitation is required for this operation");
                assert_eq!(elicitations.len(), 1);
                assert!(matches!(
                    &elicitations[0],
                    CreateElicitationOperation::Url { elicitation_id, .. }
                    if elicitation_id == "elicit-auth"
                ));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn url_elicitation_error_missing_data_falls_back_to_tool_server_error() {
        let err = parse_url_elicitation_required_error("missing data".into(), None);
        assert!(err.is_err());
    }

    #[test]
    fn url_elicitation_error_missing_elicitations_key_falls_back() {
        let err = parse_url_elicitation_required_error(
            "bad shape".into(),
            Some(serde_json::json!({"other": 1})),
        );
        assert!(err.is_err());
    }

    #[test]
    fn url_elicitation_error_empty_elicitations_falls_back() {
        let err = parse_url_elicitation_required_error(
            "empty".into(),
            Some(serde_json::json!({"elicitations": []})),
        );
        assert!(err.is_err());
    }

    // ---- AdaptedMcpServer ToolServerConnection ----

    #[test]
    fn adapted_server_invoke_delegates_to_adapter() {
        let transport = MockTransport::simple(
            vec![text_tool_info("echo")],
            MockCallBehavior::Success(success_result("echoed")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let result = adapted
            .invoke("echo", serde_json::json!({}), None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(result["content"][0]["text"], "echoed");
    }

    #[test]
    fn adapted_server_manifest_clone() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t1")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let clone = adapted.manifest_clone();
        assert_eq!(clone.server_id, adapted.manifest().server_id);
        assert_eq!(clone.tools.len(), adapted.manifest().tools.len());
    }

    // ---- Resource provider tests ----

    #[test]
    fn resource_provider_only_created_when_supported() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(adapted.resource_provider().is_none());
    }

    #[test]
    fn resource_provider_created_when_supported() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            resources_supported: true,
            ..Default::default()
        })
        .with_resources(vec![ResourceDefinition {
            uri: "test://doc".into(),
            name: "Doc".into(),
            title: None,
            description: None,
            mime_type: Some("text/plain".into()),
            size: None,
            annotations: None,
            icons: None,
        }]);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted.resource_provider();
        assert!(provider.is_some());
        let provider = provider.unwrap_or_else(|| panic!("expected provider"));
        let resources = provider.list_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "test://doc");
    }

    #[test]
    fn resource_provider_read_resource() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            resources_supported: true,
            ..Default::default()
        })
        .with_resources(vec![ResourceDefinition {
            uri: "test://readme".into(),
            name: "Readme".into(),
            title: None,
            description: None,
            mime_type: Some("text/markdown".into()),
            size: None,
            annotations: None,
            icons: None,
        }]);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .resource_provider()
            .unwrap_or_else(|| panic!("provider"));
        let content = provider
            .read_resource("test://readme")
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected content"));
        assert_eq!(content.len(), 1);
        assert!(content[0]
            .text
            .as_deref()
            .unwrap_or("")
            .contains("test://readme"));
    }

    #[test]
    fn resource_provider_templates_list() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            resources_supported: true,
            ..Default::default()
        })
        .with_resource_templates(vec![ResourceTemplateDefinition {
            uri_template: "test://docs/{slug}".into(),
            name: "Doc Template".into(),
            title: None,
            description: Some("Parameterized doc".into()),
            mime_type: Some("text/markdown".into()),
            annotations: None,
            icons: None,
        }]);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .resource_provider()
            .unwrap_or_else(|| panic!("provider"));
        let templates = provider.list_resource_templates();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].uri_template, "test://docs/{slug}");
    }

    #[test]
    fn resource_provider_complete_resource_argument() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            resources_supported: true,
            ..Default::default()
        });
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .resource_provider()
            .unwrap_or_else(|| panic!("provider"));
        let result = provider
            .complete_resource_argument(
                "test://docs/{slug}",
                "slug",
                "read",
                &serde_json::json!({}),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let result = result.unwrap_or_else(|| panic!("expected completion"));
        assert_eq!(result.values, vec!["read-res-completed".to_string()]);
    }

    // ---- Prompt provider tests ----

    #[test]
    fn prompt_provider_only_created_when_supported() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(adapted.prompt_provider().is_none());
    }

    #[test]
    fn prompt_provider_created_when_supported() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            prompts_supported: true,
            ..Default::default()
        })
        .with_prompts(vec![chio_core::PromptDefinition {
            name: "greet".into(),
            title: None,
            description: Some("Greeting".into()),
            arguments: vec![],
            icons: None,
        }]);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .prompt_provider()
            .unwrap_or_else(|| panic!("prompt provider"));
        let prompts = provider.list_prompts();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "greet");
    }

    #[test]
    fn prompt_provider_get_prompt() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            prompts_supported: true,
            ..Default::default()
        })
        .with_prompts(vec![chio_core::PromptDefinition {
            name: "greet".into(),
            title: None,
            description: Some("Greeting".into()),
            arguments: vec![],
            icons: None,
        }]);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .prompt_provider()
            .unwrap_or_else(|| panic!("prompt provider"));
        let result = provider
            .get_prompt("greet", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected prompt"));
        assert_eq!(result.messages.len(), 1);
    }

    #[test]
    fn prompt_provider_get_unknown_prompt_returns_none() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            prompts_supported: true,
            ..Default::default()
        });
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .prompt_provider()
            .unwrap_or_else(|| panic!("prompt provider"));
        let result = provider
            .get_prompt("nonexistent", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(result.is_none());
    }

    #[test]
    fn prompt_provider_complete_argument() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(McpServerCapabilities {
            prompts_supported: true,
            ..Default::default()
        });
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let provider = adapted
            .prompt_provider()
            .unwrap_or_else(|| panic!("prompt provider"));
        let result = provider
            .complete_prompt_argument("greet", "name", "Al", &serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        let result = result.unwrap_or_else(|| panic!("expected completion"));
        assert_eq!(result.values, vec!["Al-completed".to_string()]);
    }

    // ---- SerializedMcpTransport tests ----

    #[test]
    fn serialized_transport_delegates_list_tools() {
        let inner = MockTransport::simple(
            vec![text_tool_info("a"), text_tool_info("b")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let tools = serialized.list_tools().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn serialized_transport_delegates_call_tool() {
        let inner = MockTransport::simple(
            vec![],
            MockCallBehavior::Success(success_result("serialized call")),
        );
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let result = serialized
            .call_tool("t", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(result.content[0]["text"], "serialized call");
    }

    #[test]
    fn serialized_transport_delegates_capabilities() {
        let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
            .with_capabilities(McpServerCapabilities {
                prompts_supported: true,
                resources_supported: true,
                ..Default::default()
            });
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let caps = serialized.capabilities();
        assert!(caps.prompts_supported);
        assert!(caps.resources_supported);
    }

    #[test]
    fn serialized_transport_delegates_list_resources() {
        let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
            .with_resources(vec![ResourceDefinition {
                uri: "test://r".into(),
                name: "R".into(),
                title: None,
                description: None,
                mime_type: None,
                size: None,
                annotations: None,
                icons: None,
            }]);
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let resources = serialized
            .list_resources()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resources.len(), 1);
    }

    #[test]
    fn serialized_transport_delegates_list_prompts() {
        let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
            .with_prompts(vec![chio_core::PromptDefinition {
                name: "p".into(),
                title: None,
                description: None,
                arguments: vec![],
                icons: None,
            }]);
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let prompts = serialized.list_prompts().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prompts.len(), 1);
    }

    #[test]
    fn serialized_transport_drains_notifications() {
        let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
        let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
        let notifications = serialized.drain_notifications();
        assert!(notifications.is_empty());
    }

    // ---- Chunked output tests ----

    #[test]
    fn chunked_output_each_chunk_in_content_array() {
        let result = McpToolResult {
            content: vec![
                serde_json::json!({"type": "text", "text": "part-1"}),
                serde_json::json!({"type": "text", "text": "part-2"}),
                serde_json::json!({"type": "text", "text": "part-3"}),
                serde_json::json!({"type": "text", "text": "part-4"}),
                serde_json::json!({"type": "text", "text": "part-5"}),
            ],
            structured_content: None,
            is_error: Some(false),
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("chunked_tool", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        let content = output["content"]
            .as_array()
            .unwrap_or_else(|| panic!("expected content array"));
        assert_eq!(content.len(), 5);
        for (i, chunk) in content.iter().enumerate() {
            assert_eq!(chunk["text"], format!("part-{}", i + 1));
        }
    }

    #[test]
    fn chunked_output_mixed_types() {
        let result = McpToolResult {
            content: vec![
                serde_json::json!({"type": "text", "text": "hello"}),
                serde_json::json!({"type": "image", "data": "base64data", "mimeType": "image/png"}),
            ],
            structured_content: None,
            is_error: Some(false),
        };
        let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let output = adapter
            .invoke("mixed", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"));
        let content = output["content"]
            .as_array()
            .unwrap_or_else(|| panic!("expected content array"));
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image");
    }

    // ---- Denial receipt / structured error tests ----

    #[test]
    fn error_path_mcp_error_has_structured_code_and_message() {
        let transport = MockTransport::simple(
            vec![],
            MockCallBehavior::McpError {
                code: -32600,
                message: "invalid request shape".to_string(),
            },
        );
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let err = adapter.invoke("t", serde_json::json!({})).unwrap_err();
        let display = format!("{err}");
        assert!(
            display.contains("-32600"),
            "error display should contain code"
        );
        assert!(
            display.contains("invalid request shape"),
            "error display should contain message"
        );
    }

    #[test]
    fn adapted_server_mcp_error_maps_to_tool_server_error() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::McpError {
                code: -32001,
                message: "internal MCP error".to_string(),
            },
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let err = adapted
            .invoke("t", serde_json::json!({}), None)
            .unwrap_err();
        assert!(matches!(err, KernelError::ToolServerError(_)));
    }

    #[test]
    fn adapted_server_connection_error_maps_to_request_incomplete() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::ConnectionFailed("network down".to_string()),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let err = adapted
            .invoke("t", serde_json::json!({}), None)
            .unwrap_err();
        assert!(matches!(err, KernelError::RequestIncomplete(_)));
    }

    // ---- OAuth refresh placeholder tests ----

    #[test]
    fn adapter_error_display_includes_structured_details() {
        let err = AdapterError::McpError {
            code: -32042,
            message: "url elicitation required".into(),
            data: Some(serde_json::json!({"key": "value"})),
        };
        let display = format!("{err}");
        assert!(display.contains("-32042"));
        assert!(display.contains("url elicitation required"));
    }

    #[test]
    fn adapter_error_tool_not_found() {
        let err = AdapterError::ToolNotFound("missing_tool".into());
        let display = format!("{err}");
        assert!(display.contains("missing_tool"));
    }

    #[test]
    fn adapter_error_nested_flow_denied() {
        let err = AdapterError::NestedFlowDenied("no bridge".into());
        let display = format!("{err}");
        assert!(display.contains("no bridge"));
    }

    // ---- Capabilities tests ----

    #[test]
    fn adapter_capabilities_exposed() {
        let caps = McpServerCapabilities {
            tools_list_changed: true,
            resources_supported: true,
            prompts_supported: true,
            logging_supported: true,
            completions_supported: true,
            resources_subscribe: true,
            resources_list_changed: true,
            prompts_list_changed: true,
        };
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_capabilities(caps.clone());
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let result = adapter.capabilities();
        assert_eq!(result, caps);
    }

    #[test]
    fn upstream_capabilities_exposed_through_adapted_server() {
        let caps = McpServerCapabilities {
            resources_supported: true,
            prompts_supported: true,
            ..Default::default()
        };
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        )
        .with_capabilities(caps);
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let upstream = adapted.upstream_capabilities();
        assert!(upstream.resources_supported);
        assert!(upstream.prompts_supported);
    }

    // ---- Notification source tests ----

    #[test]
    fn notification_source_returns_chio_transport() {
        let transport = MockTransport::simple(
            vec![text_tool_info("t")],
            MockCallBehavior::Success(success_result("ok")),
        );
        let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
            .unwrap_or_else(|e| panic!("{e}"));
        let source = adapted.notification_source();
        let notifications = source.drain_notifications();
        assert!(notifications.is_empty());
    }

    // ---- infer_has_side_effects tests ----

    #[test]
    fn infer_side_effects_no_annotations_defaults_true() {
        assert!(infer_has_side_effects(None));
    }

    #[test]
    fn infer_side_effects_empty_object_defaults_true() {
        let ann = serde_json::json!({});
        assert!(infer_has_side_effects(Some(&ann)));
    }

    #[test]
    fn infer_side_effects_readonly_true_returns_false() {
        let ann = serde_json::json!({"readOnlyHint": true});
        assert!(!infer_has_side_effects(Some(&ann)));
    }

    #[test]
    fn infer_side_effects_readonly_false_returns_true() {
        let ann = serde_json::json!({"readOnlyHint": false});
        assert!(infer_has_side_effects(Some(&ann)));
    }

    #[test]
    fn infer_side_effects_readonly_non_bool_defaults_true() {
        let ann = serde_json::json!({"readOnlyHint": "yes"});
        assert!(infer_has_side_effects(Some(&ann)));
    }

    // ---- Direct adapter delegation tests ----

    #[test]
    fn adapter_list_resources_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_resources(vec![ResourceDefinition {
                    uri: "test://r1".into(),
                    name: "R1".into(),
                    title: None,
                    description: None,
                    mime_type: None,
                    size: None,
                    annotations: None,
                    icons: None,
                }]);
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let resources = adapter.list_resources().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resources.len(), 1);
    }

    #[test]
    fn adapter_list_resource_templates_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_resource_templates(vec![ResourceTemplateDefinition {
                    uri_template: "test://{id}".into(),
                    name: "T".into(),
                    title: None,
                    description: None,
                    mime_type: None,
                    annotations: None,
                    icons: None,
                }]);
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let templates = adapter
            .list_resource_templates()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(templates.len(), 1);
    }

    #[test]
    fn adapter_read_resource_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_resources(vec![ResourceDefinition {
                    uri: "test://doc".into(),
                    name: "Doc".into(),
                    title: None,
                    description: None,
                    mime_type: Some("text/plain".into()),
                    size: None,
                    annotations: None,
                    icons: None,
                }]);
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let content = adapter
            .read_resource("test://doc")
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected content"));
        assert_eq!(content.len(), 1);
    }

    #[test]
    fn adapter_list_prompts_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_prompts(vec![chio_core::PromptDefinition {
                    name: "p1".into(),
                    title: None,
                    description: None,
                    arguments: vec![],
                    icons: None,
                }]);
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let prompts = adapter.list_prompts().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prompts.len(), 1);
    }

    #[test]
    fn adapter_get_prompt_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
                .with_prompts(vec![chio_core::PromptDefinition {
                    name: "p1".into(),
                    title: None,
                    description: None,
                    arguments: vec![],
                    icons: None,
                }]);
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let result = adapter
            .get_prompt("p1", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected prompt"));
        assert_eq!(result.messages.len(), 1);
    }

    #[test]
    fn adapter_complete_prompt_argument_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let result = adapter
            .complete_prompt_argument("p", "arg", "val", &serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected completion"));
        assert_eq!(result.values, vec!["val-completed"]);
    }

    #[test]
    fn adapter_complete_resource_argument_delegates() {
        let transport =
            MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
        let adapter = McpAdapter::new(default_config(), Box::new(transport));
        let result = adapter
            .complete_resource_argument("u", "arg", "val", &serde_json::json!({}))
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("expected completion"));
        assert_eq!(result.values, vec!["val-res-completed"]);
    }

    // ---- McpServerCapabilities tests ----

    #[test]
    fn capabilities_from_initialize_result_parses_all_fields() {
        let result = serde_json::json!({
            "capabilities": {
                "tools": {"listChanged": true},
                "resources": {"subscribe": true, "listChanged": true},
                "prompts": {"listChanged": true},
                "completions": {},
                "logging": {}
            }
        });
        let caps = McpServerCapabilities::from_initialize_result(&result);
        assert!(caps.tools_list_changed);
        assert!(caps.resources_supported);
        assert!(caps.resources_subscribe);
        assert!(caps.resources_list_changed);
        assert!(caps.prompts_supported);
        assert!(caps.prompts_list_changed);
        assert!(caps.completions_supported);
        assert!(caps.logging_supported);
    }

    #[test]
    fn capabilities_from_empty_result_all_false() {
        let result = serde_json::json!({});
        let caps = McpServerCapabilities::from_initialize_result(&result);
        assert!(!caps.tools_list_changed);
        assert!(!caps.resources_supported);
        assert!(!caps.prompts_supported);
        assert!(!caps.completions_supported);
        assert!(!caps.logging_supported);
    }

    #[test]
    fn capabilities_partial_tools_only() {
        let result = serde_json::json!({
            "capabilities": {
                "tools": {}
            }
        });
        let caps = McpServerCapabilities::from_initialize_result(&result);
        assert!(!caps.tools_list_changed);
        assert!(!caps.resources_supported);
    }
}
