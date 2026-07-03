use super::*;

pub(in crate::runtime) struct JsonRpcEnvelope {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

pub(in crate::runtime) fn parse_jsonrpc_envelope(
    message: &Value,
) -> Result<JsonRpcEnvelope, Value> {
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(jsonrpc_error(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "invalid jsonrpc envelope",
        ));
    }

    let id = message.get("id").cloned();
    if id
        .as_ref()
        .is_some_and(|id| !id.is_string() && !id.is_number() && !id.is_null())
    {
        return Err(jsonrpc_error(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "request id must be string, number, or null",
        ));
    }

    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            jsonrpc_error(
                id.clone().unwrap_or(Value::Null),
                JSONRPC_INVALID_REQUEST,
                "request missing method",
            )
        })?
        .to_string();
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    Ok(JsonRpcEnvelope { id, method, params })
}

pub(in crate::runtime) fn ensure_known_request_params_object(
    id: &Value,
    method: &str,
    params: &Value,
) -> Result<(), Value> {
    if !known_request_method(method) || params.is_object() {
        return Ok(());
    }

    Err(jsonrpc_error(
        id.clone(),
        JSONRPC_INVALID_PARAMS,
        &format!("{method} params must be an object"),
    ))
}

pub(in crate::runtime) fn known_notification_params_are_object(
    method: &str,
    params: &Value,
) -> bool {
    !known_notification_method(method) || params.is_object()
}

fn known_request_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "tools/call"
            | "tasks/list"
            | "tasks/get"
            | "tasks/result"
            | "tasks/cancel"
            | "resources/list"
            | "resources/read"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "resources/templates/list"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete"
            | "logging/setLevel"
    )
}

fn known_notification_method(method: &str) -> bool {
    matches!(
        method,
        "notifications/initialized"
            | "notifications/roots/list_changed"
            | "notifications/cancelled"
    )
}
