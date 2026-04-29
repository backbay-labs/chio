//! Shared MCP edge runtime and transport contracts for Chio.

use chio_core::session::RequestId;
use chio_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition,
};
use chio_kernel::NestedFlowBridge;
use serde::{Deserialize, Serialize};

mod runtime;

#[cfg(feature = "otel")]
pub mod otel;

pub use runtime::{
    execute_bridge_mcp_tool_call_async, BridgeMcpToolCall, BridgeMcpToolCallRequest, ChioMcpEdge,
    McpEdgeConfig, McpExposedTool, McpTargetExecutor,
};

/// libFuzzer entry-point module for `chio-mcp-edge`.
///
/// Gated behind the `fuzz` Cargo feature so it only compiles into the
/// standalone `chio-fuzz` workspace at `../../fuzz`. Production builds never
/// pull in `arbitrary`, never expose these symbols, and never get recompiled
/// with libFuzzer instrumentation.
#[cfg(feature = "fuzz")]
pub mod fuzz;

/// Minimal representation of an MCP tool listing response.
/// This captures just enough to translate into Chio tool definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolInfo {
    /// Tool name as advertised by the MCP server.
    pub name: String,

    /// Optional display title for the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Tool description.
    pub description: Option<String>,

    /// JSON Schema for the tool's input.
    pub input_schema: serde_json::Value,

    /// Optional JSON Schema for the tool's output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outputSchema"
    )]
    pub output_schema: Option<serde_json::Value>,

    /// Optional MCP tool annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,

    /// Optional MCP execution metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<serde_json::Value>,
}

/// An MCP tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolResult {
    /// The content blocks returned by the MCP tool.
    pub content: Vec<serde_json::Value>,

    /// Optional structured content returned by the MCP tool.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "structuredContent"
    )]
    pub structured_content: Option<serde_json::Value>,

    /// Whether the tool call resulted in an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// MCP feature flags captured from the upstream server's initialize response.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerCapabilities {
    #[serde(default)]
    pub tools_list_changed: bool,
    #[serde(default)]
    pub resources_supported: bool,
    #[serde(default)]
    pub resources_subscribe: bool,
    #[serde(default)]
    pub resources_list_changed: bool,
    #[serde(default)]
    pub prompts_supported: bool,
    #[serde(default)]
    pub prompts_list_changed: bool,
    #[serde(default)]
    pub completions_supported: bool,
    #[serde(default)]
    pub logging_supported: bool,
}

impl McpServerCapabilities {
    pub fn from_initialize_result(result: &serde_json::Value) -> Self {
        let capabilities = result
            .get("capabilities")
            .and_then(serde_json::Value::as_object);

        let tools = capabilities.and_then(|map| map.get("tools"));
        let resources = capabilities.and_then(|map| map.get("resources"));
        let prompts = capabilities.and_then(|map| map.get("prompts"));

        Self {
            tools_list_changed: tools
                .and_then(|value| value.get("listChanged"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            resources_supported: resources.is_some(),
            resources_subscribe: resources
                .and_then(|value| value.get("subscribe"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            resources_list_changed: resources
                .and_then(|value| value.get("listChanged"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            prompts_supported: prompts.is_some(),
            prompts_list_changed: prompts
                .and_then(|value| value.get("listChanged"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            completions_supported: capabilities
                .and_then(|map| map.get("completions"))
                .is_some(),
            logging_supported: capabilities.and_then(|map| map.get("logging")).is_some(),
        }
    }
}

/// Errors that can occur during MCP adaptation.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("MCP server connection failed: {0}")]
    ConnectionFailed(String),

    #[error("kernel runtime error: {0}")]
    KernelRuntime(String),

    #[error("MCP server returned an error ({code}): {message}")]
    McpError {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },

    #[error("nested flow denied: {0}")]
    NestedFlowDenied(String),

    #[error("request {request_id} was cancelled: {reason}")]
    RequestCancelled {
        request_id: RequestId,
        reason: String,
    },

    #[error("failed to parse MCP response: {0}")]
    ParseError(String),

    #[error("tool not found in MCP server: {0}")]
    ToolNotFound(String),

    #[error("manifest generation failed: {0}")]
    ManifestError(#[from] chio_manifest::ManifestError),
}

/// Trait for communicating with an MCP server.
///
/// The default MCP transport is stdio (the adapter spawns the MCP server as
/// a subprocess and communicates over stdin/stdout). Other transports
/// (streamable HTTP, SSE) can be implemented by providing this trait.
pub trait McpTransport: Send + Sync {
    /// Feature flags returned by the upstream MCP server.
    fn capabilities(&self) -> McpServerCapabilities {
        McpServerCapabilities::default()
    }

    /// List available tools on the MCP server.
    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError>;

    /// Call a tool on the MCP server.
    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError>;

    /// Call a tool on the MCP server while allowing the upstream server to
    /// issue negotiated server-to-client requests through the active parent
    /// request.
    fn call_tool_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<McpToolResult, AdapterError> {
        let _ = nested_flow_bridge;
        self.call_tool(tool_name, arguments)
    }

    /// List available resources on the MCP server.
    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        Ok(vec![])
    }

    /// List parameterized resource templates.
    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        Ok(vec![])
    }

    /// Read a resource from the MCP server.
    fn read_resource(&self, _uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        Ok(None)
    }

    /// List available prompts on the MCP server.
    fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        Ok(vec![])
    }

    /// Get a prompt from the MCP server.
    fn get_prompt(
        &self,
        _name: &str,
        _arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        Ok(None)
    }

    /// Complete a prompt argument.
    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        Ok(None)
    }

    /// Complete a resource template argument.
    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        Ok(None)
    }

    /// Drain unsolicited upstream notifications that arrived while no request
    /// was actively awaiting a response from the wrapped server.
    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        vec![]
    }
}
