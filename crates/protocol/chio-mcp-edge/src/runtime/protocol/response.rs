use super::*;

pub(in crate::runtime) fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

pub(in crate::runtime) fn queue_progress_notification(
    pending_notifications: &mut Vec<Value>,
    progress_token: Option<&ProgressToken>,
    progress_step: &mut u64,
    message: &str,
    related_task_id: Option<&str>,
) {
    let Some(progress_token) = progress_token else {
        return;
    };

    *progress_step += 1;
    pending_notifications.push(attach_related_task_meta_to_message(
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": progress_token_to_value(progress_token),
                "progress": *progress_step,
                "message": message,
            }
        }),
        related_task_id,
    ));
}

pub(in crate::runtime) fn progress_token_to_value(progress_token: &ProgressToken) -> Value {
    match progress_token {
        ProgressToken::String(value) => Value::String(value.clone()),
        ProgressToken::Integer(value) => json!(*value),
    }
}
pub(in crate::runtime) fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

pub(in crate::runtime) fn jsonrpc_error_with_data(
    id: Value,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> Value {
    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), json!(code));
    error.insert("message".to_string(), json!(message));
    if let Some(data) = data {
        error.insert("data".to_string(), data);
    }

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": Value::Object(error),
    })
}

pub(in crate::runtime) fn adapter_jsonrpc_error(error: &Value) -> AdapterError {
    AdapterError::McpError {
        code: error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or(JSONRPC_INTERNAL_ERROR),
        message: error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown JSON-RPC error")
            .to_string(),
        data: error.get("data").cloned(),
    }
}

pub(in crate::runtime) fn write_jsonrpc_line(
    writer: &mut impl Write,
    value: &Value,
) -> Result<(), AdapterError> {
    let line = serde_json::to_string(value).map_err(|error| {
        AdapterError::ParseError(format!("failed to serialize JSON-RPC response: {error}"))
    })?;
    writer.write_all(line.as_bytes()).map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to write MCP edge response: {error}"))
    })?;
    writer.write_all(b"\n").map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to terminate MCP edge response: {error}"))
    })?;
    writer.flush().map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to flush MCP edge response: {error}"))
    })?;
    Ok(())
}

pub(in crate::runtime) fn read_jsonrpc_line(
    reader: &mut impl BufRead,
) -> Result<Value, AdapterError> {
    read_jsonrpc_frame(reader)?.ok_or_else(|| {
        AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        )
    })
}
