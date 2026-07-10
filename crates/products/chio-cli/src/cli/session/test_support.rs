use super::*;

#[cfg(test)]
pub(crate) struct StubToolServer {
    pub(crate) id: String,
}

#[cfg(test)]
#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for StubToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(serde_json::json!({
            "stub": true,
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

#[cfg(test)]
pub(crate) struct StubSqlResultToolServer {
    pub(crate) id: String,
}

#[cfg(test)]
#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for StubSqlResultToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["sql".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(serde_json::json!({
            "rows": [
                {"email": "alice@example.com", "id": 1}
            ]
        }))
    }
}

#[cfg(test)]
pub(crate) struct StubStreamingToolServer {
    pub(super) id: String,
    pub(super) incomplete: bool,
}

#[cfg(test)]
#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for StubStreamingToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Option<chio_kernel::ToolServerStreamResult>, chio_kernel::KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                chio_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": "hello"}),
                },
                chio_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": arguments}),
                },
            ],
        };

        if self.incomplete {
            Ok(Some(chio_kernel::ToolServerStreamResult::Incomplete {
                stream,
                reason: "stream source ended before final frame".to_string(),
            }))
        } else {
            Ok(Some(chio_kernel::ToolServerStreamResult::Complete(stream)))
        }
    }
}
