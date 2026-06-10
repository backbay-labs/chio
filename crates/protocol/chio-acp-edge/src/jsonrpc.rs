// JSON-RPC request-boundary parsing for the ACP edge.

#[derive(Debug)]
struct AcpJsonRpcEnvelope {
    id: Option<Value>,
    method: String,
    params: Value,
}

const ACP_JSONRPC_KNOWN_METHODS: &[&str] = &[
    "session/list_capabilities",
    "session/request_permission",
    "tool/invoke",
    "tool/stream",
    "tool/cancel",
    "tool/resume",
];

impl ChioAcpEdge {
    fn jsonrpc_protocol_error_response(id: Value, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        })
    }

    fn jsonrpc_error_response(id: Value, error: AcpEdgeError) -> Value {
        let (code, message) = match error {
            AcpEdgeError::InvalidRequest(message) => (-32602, message),
            other => (-32603, other.to_string()),
        };

        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    fn parse_jsonrpc_envelope(message: &Value) -> Result<AcpJsonRpcEnvelope, Option<Value>> {
        let id = message.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number() && !id.is_null())
        {
            return Err(Some(Self::jsonrpc_protocol_error_response(
                Value::Null,
                -32600,
                "request id must be string, number, or null",
            )));
        }

        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(id.clone().map(|id| {
                Self::jsonrpc_protocol_error_response(id, -32600, "invalid jsonrpc envelope")
            }));
        }

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Err(id.clone().map(|id| {
                Self::jsonrpc_protocol_error_response(id, -32600, "request missing method")
            }));
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        Ok(AcpJsonRpcEnvelope {
            id,
            method: method.to_string(),
            params,
        })
    }

    fn ensure_jsonrpc_params_object_for_known_method(
        id: &Value,
        method: &str,
        params: &Value,
        known_methods: &[&str],
    ) -> Result<(), Value> {
        if !known_methods.contains(&method) || params.is_object() {
            return Ok(());
        }

        Err(Self::jsonrpc_protocol_error_response(
            id.clone(),
            -32602,
            &format!("{method} params must be an object"),
        ))
    }

    fn jsonrpc_permission_request(params: &Value) -> Result<PermissionRequest, AcpEdgeError> {
        Ok(PermissionRequest {
            capability_id: Self::jsonrpc_capability_id(params, "session/request_permission")?,
            arguments: Self::jsonrpc_arguments(params),
        })
    }

    fn jsonrpc_invocation_params(
        params: &Value,
        operation: &str,
    ) -> Result<(String, Value), AcpEdgeError> {
        Ok((
            Self::jsonrpc_capability_id(params, operation)?,
            Self::jsonrpc_arguments(params),
        ))
    }

    fn jsonrpc_task_id_params(params: &Value, operation: &str) -> Result<String, AcpEdgeError> {
        let Some(task_id) = params.get("taskId") else {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} requires params.taskId"
            )));
        };
        let Some(task_id) = task_id.as_str() else {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must be a string"
            )));
        };
        if task_id.trim().is_empty() {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not be empty"
            )));
        }
        if task_id.trim() != task_id {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not include leading or trailing whitespace"
            )));
        }
        if task_id.chars().any(char::is_control) {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not include control characters"
            )));
        }
        Ok(task_id.to_string())
    }

    fn jsonrpc_capability_id(params: &Value, operation: &str) -> Result<String, AcpEdgeError> {
        let Some(capability_id) = params.get("capabilityId") else {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} requires params.capabilityId"
            )));
        };
        let Some(capability_id) = capability_id.as_str() else {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.capabilityId must be a string"
            )));
        };
        if capability_id.trim().is_empty() {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.capabilityId must not be empty"
            )));
        }
        if capability_id.trim() != capability_id {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.capabilityId must not include leading or trailing whitespace"
            )));
        }
        if capability_id.chars().any(char::is_control) {
            return Err(AcpEdgeError::InvalidRequest(format!(
                "{operation} params.capabilityId must not include control characters"
            )));
        }
        Ok(capability_id.to_string())
    }

    fn jsonrpc_arguments(params: &Value) -> Value {
        params.get("arguments").cloned().unwrap_or_else(|| json!({}))
    }
}
