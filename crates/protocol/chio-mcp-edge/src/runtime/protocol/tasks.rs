use super::*;

#[derive(Debug, Clone)]
pub(in crate::runtime) struct RequestedTask {
    pub(in crate::runtime) ttl: Option<u64>,
}
pub(in crate::runtime) fn iso8601_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(in crate::runtime) fn unix_now_millis() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

pub(in crate::runtime) fn parse_requested_task(
    id: &Value,
    params: &Value,
) -> Result<Option<RequestedTask>, Value> {
    let Some(task) = params.get("task") else {
        return Ok(None);
    };
    let Some(task) = task.as_object() else {
        return Err(jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "task must be an object with an optional numeric ttl",
        ));
    };

    let ttl = match task.get("ttl") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => {
            let Some(ttl) = number.as_u64() else {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "task ttl must be a non-negative integer",
                ));
            };
            if ttl > MAX_MCP_TASK_TTL_MILLIS {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "task ttl exceeds maximum",
                ));
            }
            Some(ttl)
        }
        Some(_) => {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "task ttl must be a non-negative integer",
            ))
        }
    };

    Ok(Some(RequestedTask { ttl }))
}
pub(in crate::runtime) fn edge_task_status_label(status: EdgeTaskStatus) -> &'static str {
    match status {
        EdgeTaskStatus::Working => "working",
        EdgeTaskStatus::Completed => "completed",
        EdgeTaskStatus::Failed => "failed",
        EdgeTaskStatus::Cancelled => "cancelled",
    }
}

pub(in crate::runtime) fn tool_result_is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(in crate::runtime) fn cancellation_reason_from_tool_result(result: &Value) -> Option<String> {
    if !tool_result_is_error(result) {
        return None;
    }

    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)?;

    if let Some((_, reason)) = text.split_once(" was cancelled: ") {
        return Some(reason.to_string());
    }

    if text.starts_with("cancelled by client") || text.starts_with("task cancelled by client") {
        return Some(text.to_string());
    }

    None
}

pub(in crate::runtime) fn task_status_message(
    status: &EdgeTaskStatus,
    result: &Value,
) -> Option<String> {
    match status {
        EdgeTaskStatus::Completed => Some("The operation completed successfully.".to_string()),
        EdgeTaskStatus::Failed => result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|content| content.first())
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| Some("The operation failed.".to_string())),
        EdgeTaskStatus::Working => Some("The operation is now in progress.".to_string()),
        EdgeTaskStatus::Cancelled => Some("The operation was cancelled.".to_string()),
    }
}
