use super::*;

pub(in crate::runtime) struct KernelResponseToToolResultArgs<'a> {
    pub pending_notifications: &'a mut Vec<Value>,
    pub request_id: &'a Value,
    pub output: Option<ToolCallOutput>,
    pub reason: Option<String>,
    pub verdict: Verdict,
    pub terminal_state: &'a OperationTerminalState,
    pub execution_nonce: Option<&'a SignedExecutionNonce>,
    pub peer_supports_chio_tool_streaming: bool,
    pub related_task_id: Option<&'a str>,
}
pub(in crate::runtime) fn kernel_response_to_tool_result(
    args: KernelResponseToToolResultArgs<'_>,
) -> Value {
    let KernelResponseToToolResultArgs {
        pending_notifications,
        request_id,
        output,
        reason,
        verdict,
        terminal_state,
        execution_nonce,
        peer_supports_chio_tool_streaming,
        related_task_id,
    } = args;
    let is_error = matches!(verdict, Verdict::Deny) || !terminal_state.is_completed();
    let terminal_reason = reason
        .as_deref()
        .or_else(|| terminal_state_reason(terminal_state));

    let result = match output {
        Some(ToolCallOutput::Value(value)) if !is_error => value_to_tool_result(value),
        Some(ToolCallOutput::Stream(stream)) => {
            if peer_supports_chio_tool_streaming {
                queue_tool_stream_chunk_notifications(
                    pending_notifications,
                    request_id,
                    &stream,
                    related_task_id,
                );
                streamed_notification_tool_result(
                    request_id,
                    stream.chunk_count(),
                    terminal_state,
                    terminal_reason,
                    is_error,
                )
            } else {
                collapsed_stream_tool_result(stream, terminal_state, terminal_reason, is_error)
            }
        }
        Some(ToolCallOutput::Value(_)) | None if is_error => tool_error_result(
            &reason.unwrap_or_else(|| default_tool_failure_reason(terminal_state)),
        ),
        Some(ToolCallOutput::Value(value)) => value_to_tool_result(value),
        None => value_to_tool_result(Value::Null),
    };
    attach_execution_nonce_meta_to_result(result, execution_nonce)
}

pub(in crate::runtime) fn queue_tool_stream_chunk_notifications(
    pending_notifications: &mut Vec<Value>,
    request_id: &Value,
    stream: &ToolCallStream,
    related_task_id: Option<&str>,
) {
    let total_chunks = stream.chunk_count();
    for (index, chunk) in stream.chunks.iter().enumerate() {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": CHIO_TOOL_STREAMING_NOTIFICATION_METHOD,
            "params": {
                "requestId": request_id,
                "chunkIndex": index as u64,
                "totalChunks": total_chunks,
                "chunk": chunk.data.clone(),
            }
        });
        pending_notifications.push(attach_related_task_meta_to_message(
            notification,
            related_task_id,
        ));
    }
}

pub(in crate::runtime) fn streamed_notification_tool_result(
    request_id: &Value,
    total_chunks: u64,
    terminal_state: &OperationTerminalState,
    reason: Option<&str>,
    is_error: bool,
) -> Value {
    let mut stream = serde_json::Map::new();
    stream.insert("mode".to_string(), json!("notification_stream"));
    stream.insert(
        "notificationMethod".to_string(),
        json!(CHIO_TOOL_STREAMING_NOTIFICATION_METHOD),
    );
    stream.insert("requestId".to_string(), request_id.clone());
    stream.insert("totalChunks".to_string(), json!(total_chunks));
    stream.insert(
        "terminalState".to_string(),
        json!(terminal_state_label(terminal_state)),
    );
    if let Some(reason) = reason {
        stream.insert("reason".to_string(), json!(reason));
    }

    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "Chio streamed tool output delivered via {}",
                CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
            ),
        }],
        "structuredContent": tool_stream_structured_content(stream),
        "isError": is_error,
    })
}

pub(in crate::runtime) fn collapsed_stream_tool_result(
    stream: ToolCallStream,
    terminal_state: &OperationTerminalState,
    reason: Option<&str>,
    is_error: bool,
) -> Value {
    let total_chunks = stream.chunk_count();
    let chunks = stream
        .chunks
        .into_iter()
        .map(|chunk| chunk.data)
        .collect::<Vec<_>>();

    let mut stream_summary = serde_json::Map::new();
    stream_summary.insert("mode".to_string(), json!("collapsed_result"));
    stream_summary.insert("totalChunks".to_string(), json!(total_chunks));
    stream_summary.insert(
        "terminalState".to_string(),
        json!(terminal_state_label(terminal_state)),
    );
    stream_summary.insert("chunks".to_string(), Value::Array(chunks));
    if let Some(reason) = reason {
        stream_summary.insert("reason".to_string(), json!(reason));
    }

    json!({
        "content": [{
            "type": "text",
            "text": format!("Chio streamed tool output collapsed into {} final chunk(s)", total_chunks),
        }],
        "structuredContent": tool_stream_structured_content(stream_summary),
        "isError": is_error,
    })
}

pub(in crate::runtime) fn tool_stream_structured_content(
    stream: serde_json::Map<String, Value>,
) -> Value {
    let stream_value = Value::Object(stream);
    let mut structured_content = serde_json::Map::new();
    structured_content.insert(CHIO_TOOL_STREAM_KEY.to_string(), stream_value);
    Value::Object(structured_content)
}

pub(in crate::runtime) fn terminal_state_label(
    terminal_state: &OperationTerminalState,
) -> &'static str {
    match terminal_state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

pub(in crate::runtime) fn terminal_state_reason(
    terminal_state: &OperationTerminalState,
) -> Option<&str> {
    match terminal_state {
        OperationTerminalState::Completed => None,
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => Some(reason),
    }
}

pub(in crate::runtime) fn default_tool_failure_reason(
    terminal_state: &OperationTerminalState,
) -> String {
    match terminal_state {
        OperationTerminalState::Completed => "tool call denied".to_string(),
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => reason.clone(),
    }
}
pub(in crate::runtime) fn value_to_tool_result(value: Value) -> Value {
    if let Some(object) = value.as_object() {
        let has_mcp_shape = object.contains_key("content")
            || object.contains_key("structuredContent")
            || object.contains_key("isError");
        if has_mcp_shape {
            let mut object = object.clone();
            object
                .entry("isError".to_string())
                .or_insert_with(|| Value::Bool(false));
            if !object.contains_key("content") {
                if let Some(structured) = object.get("structuredContent") {
                    object.insert(
                        "content".to_string(),
                        json!([{"type": "text", "text": serde_json::to_string(structured).unwrap_or_default()}]),
                    );
                }
            }
            return Value::Object(object);
        }

        return json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&value).unwrap_or_default(),
                }
            ],
            "structuredContent": value,
            "isError": false,
        });
    }

    match value {
        Value::String(text) => json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false,
        }),
        other => json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&other).unwrap_or_default(),
                }
            ],
            "isError": false,
        }),
    }
}

pub(in crate::runtime) fn tool_error_result(reason: &str) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": reason,
            }
        ],
        "isError": true,
    })
}
