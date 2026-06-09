use crate::edge::McpToolResult;

pub(crate) fn mcp_tool_result_to_chio_value(result: McpToolResult) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    output.insert(
        "content".to_string(),
        serde_json::Value::Array(result.content),
    );
    if let Some(structured_content) = result.structured_content {
        output.insert("structuredContent".to_string(), structured_content);
    }
    output.insert(
        "isError".to_string(),
        serde_json::Value::Bool(result.is_error.unwrap_or(false)),
    );

    serde_json::Value::Object(output)
}
