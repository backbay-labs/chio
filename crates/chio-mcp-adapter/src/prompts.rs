use chio_core::{CompletionResult, PromptDefinition, PromptResult};
use chio_kernel::{KernelError, PromptProvider};
use tracing::warn;

use crate::adapter::McpAdapter;

pub struct AdaptedMcpPromptProvider {
    pub(crate) adapter: McpAdapter,
}

impl AdaptedMcpPromptProvider {
    pub(crate) fn new(adapter: McpAdapter) -> Self {
        Self { adapter }
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
