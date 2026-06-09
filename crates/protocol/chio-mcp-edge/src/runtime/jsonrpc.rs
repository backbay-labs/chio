use super::errors::JsonRpcProtocolErrorArgs;
use super::*;

fn chio_protocol_error_payload(
    code: i64,
    name: &str,
    transient: bool,
    retry_strategy: &str,
    guidance: &str,
) -> Value {
    json!({
        "code": code,
        "name": name,
        "category": "protocol",
        "transient": transient,
        "retry": {
            "strategy": retry_strategy,
            "guidance": guidance,
        }
    })
}

pub(super) fn jsonrpc_protocol_error(args: JsonRpcProtocolErrorArgs<'_>) -> Value {
    let JsonRpcProtocolErrorArgs {
        id,
        jsonrpc_code,
        message,
        chio_code,
        name,
        retry_strategy,
        guidance,
        context,
    } = args;
    let mut data = serde_json::Map::new();
    data.insert(
        "chioError".to_string(),
        chio_protocol_error_payload(chio_code, name, false, retry_strategy, guidance),
    );
    if let Some(context) = context.and_then(|value| value.as_object().cloned()) {
        for (key, value) in context {
            data.insert(key, value);
        }
    }
    jsonrpc_error_with_data(id, jsonrpc_code, message, Some(Value::Object(data)))
}

pub(super) fn negotiate_protocol_version(
    id: &Value,
    params: &Value,
) -> Result<&'static str, Value> {
    let Some(requested) = params.get("protocolVersion") else {
        return Ok(MCP_PROTOCOL_VERSION);
    };
    let Some(requested) = requested.as_str() else {
        return Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
            id: id.clone(),
            jsonrpc_code: JSONRPC_INVALID_REQUEST,
            message: "initialize.params.protocolVersion must be a string",
            chio_code: CHIO_ERROR_INVALID_REQUEST_SHAPE,
            name: "invalid_request_shape",
            retry_strategy: "do_not_retry",
            guidance: "correct the initialize request shape before retrying",
            context: Some(json!({
                "parameter": "protocolVersion"
            })),
        }));
    };
    if SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&requested) {
        Ok(MCP_PROTOCOL_VERSION)
    } else {
        Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
            id: id.clone(),
            jsonrpc_code: JSONRPC_INVALID_REQUEST,
            message: "unsupported protocolVersion",
            chio_code: CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED,
            name: "protocol_version_unsupported",
            retry_strategy: "do_not_retry_until_version_change",
            guidance: "retry only after selecting one of the server's supported protocol versions",
            context: Some(json!({
                "requestedProtocolVersion": requested,
                "supportedProtocolVersions": SUPPORTED_MCP_PROTOCOL_VERSIONS,
            })),
        }))
    }
}
