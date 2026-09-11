use chio_kernel::{
    KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream, ToolServerConnection,
    ToolServerStreamResult,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

pub const SERVER: &str = "documents";
pub const TOOL: &str = "count_words";
pub const TEXT_LIMIT: usize = 65_536;

pub struct DocumentTools;

fn count(tool: &str, arguments: &Value) -> Result<Value, KernelError> {
    if tool != TOOL {
        return Err(KernelError::ToolNotRegistered(tool.to_owned()));
    }
    let text = arguments
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| KernelError::RequestIncomplete("text must be a string".into()))?;
    if text.len() > TEXT_LIMIT {
        return Err(KernelError::RequestIncomplete(
            "text exceeds 65536 UTF-8 bytes".into(),
        ));
    }
    Ok(json!({"words": text.split_whitespace().count(), "bytes": text.len()}))
}

#[async_trait::async_trait]
impl ToolServerConnection for DocumentTools {
    fn server_id(&self) -> &str {
        SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.into()]
    }

    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        count(tool, &arguments)
    }

    async fn invoke_stream(
        &self,
        tool: &str,
        arguments: Value,
        _nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let result = count(tool, &arguments)?;
        // These chunks are collated by the edge into one terminal response.
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk { data: result },
                ToolCallChunk {
                    data: json!({"content": [
                        {"type": "text", "text": "Document counted"}
                    ]}),
                },
            ],
        })))
    }
}

pub fn manifest(public_key: String) -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: SERVER.into(),
        name: "Document tools".into(),
        version: "1.0.0".into(),
        description: Some("Count words in caller-provided text".into()),
        tools: vec![ToolDefinition {
            name: TOOL.into(),
            description: "Count whitespace-separated words and UTF-8 bytes".into(),
            input_schema: json!({
                "type": "object", "properties": {"text": {"type": "string"}},
                "required": ["text"], "x-chio-streaming": true,
                "x-chio-partial-output": true, "x-chio-cancellation": true
            }),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key,
    }
}
