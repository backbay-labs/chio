use std::sync::{Arc, Mutex};

use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, ServerId,
};
use chio_kernel::NestedFlowBridge;
use chio_manifest::ToolManifest;
use tracing::warn;

use crate::edge::{AdapterError, McpServerCapabilities, McpToolInfo, McpToolResult, McpTransport};
use crate::manifest;
use crate::result_mapping::mcp_tool_result_to_chio_value;
use crate::transport::StdioMcpTransport;

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
    pub(crate) config: McpAdapterConfig,
    pub(crate) transport: Arc<dyn McpTransport>,
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
        self.with_request_gate(|inner| Ok(inner.drain_notifications()))
            .unwrap_or_else(|error| {
                warn!(error = %error, "wrapped MCP notification drain failed");
                vec![]
            })
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
    pub fn generate_manifest(&self) -> Result<ToolManifest, AdapterError> {
        let mcp_tools = self.transport.list_tools()?;
        manifest::generate_manifest(&self.config, mcp_tools)
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

        Ok(mcp_tool_result_to_chio_value(result))
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
