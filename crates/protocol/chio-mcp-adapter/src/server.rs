use std::sync::Arc;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_manifest::ToolManifest;

use crate::adapter::{McpAdapter, McpAdapterConfig};
use crate::edge::{AdapterError, McpServerCapabilities, McpTransport};
use crate::errors::map_tool_invocation_error;
use crate::prompts::AdaptedMcpPromptProvider;
use crate::resources::AdaptedMcpResourceProvider;

/// A Chio tool-server connection backed by a wrapped MCP server.
#[derive(Clone)]
pub struct AdaptedMcpServer {
    pub(crate) adapter: McpAdapter,
    pub(crate) manifest: ToolManifest,
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
            .then(|| AdaptedMcpResourceProvider::new(self.adapter.clone()))
    }

    pub fn prompt_provider(&self) -> Option<AdaptedMcpPromptProvider> {
        self.upstream_capabilities()
            .prompts_supported
            .then(|| AdaptedMcpPromptProvider::new(self.adapter.clone()))
    }
}

#[async_trait::async_trait]
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

    /// The manifest derives `has_side_effects` from the upstream MCP
    /// `readOnlyHint` annotation, so a hinted read-only tool is exempt from
    /// side-effect handling (the dispatch-intent journal in particular)
    /// while unhinted tools stay side-effecting. This is the server's own
    /// self-reported claim, captured once at adapt time and never
    /// re-verified per call; the MCP spec treats tool annotations as
    /// untrusted hints, so a lying or compromised server can exempt its own
    /// side-effecting tools from the journal's crash-window audit net
    /// (policy, guards, and receipts are unaffected). See
    /// `crates/protocol/chio-mcp-adapter/ARCHITECTURE.md` for the full trust
    /// posture and the conservative parsing that bounds it.
    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        self.manifest.tool_is_read_only(tool_name)
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if !self
            .manifest
            .tools
            .iter()
            .any(|tool| tool.name == tool_name)
        {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        }

        self.adapter
            .invoke_with_nested_flow(tool_name, arguments, nested_flow_bridge)
            .map_err(map_tool_invocation_error)
    }
}
