use chio_core::{
    CompletionResult, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
};
use chio_kernel::{KernelError, ResourceProvider};
use tracing::warn;

use crate::adapter::McpAdapter;

pub struct AdaptedMcpResourceProvider {
    pub(crate) adapter: McpAdapter,
}

impl AdaptedMcpResourceProvider {
    pub(crate) fn new(adapter: McpAdapter) -> Self {
        Self { adapter }
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
