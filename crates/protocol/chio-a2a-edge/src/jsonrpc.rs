// JSON-RPC request-boundary parsing for the A2A edge.

#[derive(Debug)]
struct A2aJsonRpcEnvelope {
    id: Option<Value>,
    method: String,
    params: Value,
}

impl ChioA2aEdge {
    fn parse_jsonrpc_envelope(message: &Value) -> Result<A2aJsonRpcEnvelope, Option<Value>> {
        let id = message.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number() && !id.is_null())
        {
            return Err(Some(Self::jsonrpc_error_payload(
                Value::Null,
                -32600,
                "request id must be string, number, or null",
            )));
        }

        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(id.clone().map(|id| {
                Self::jsonrpc_error_payload(id, -32600, "invalid jsonrpc envelope")
            }));
        }

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Err(id
                .clone()
                .map(|id| Self::jsonrpc_error_payload(id, -32600, "request missing method")));
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        Ok(A2aJsonRpcEnvelope {
            id,
            method: method.to_string(),
            params,
        })
    }

    fn ensure_jsonrpc_params_object_for_supported_method(
        id: &Value,
        method: &str,
        params: &Value,
        supported_methods: &[&str],
    ) -> Result<(), Value> {
        if !supported_methods.contains(&method) || params.is_object() {
            return Ok(());
        }

        Err(Self::jsonrpc_error_payload(
            id.clone(),
            -32602,
            &format!("{method} params must be an object"),
        ))
    }

    fn parse_jsonrpc_send_message_params(
        &self,
        params: Value,
        request_name: &str,
    ) -> Result<(String, SendMessageRequest), A2aEdgeError> {
        let skill_id = self.resolve_jsonrpc_target_skill_id(&params)?;
        let request = serde_json::from_value::<SendMessageRequest>(params).map_err(|error| {
            A2aEdgeError::InvalidRequest(format!("invalid {request_name} request: {error}"))
        })?;

        Ok((skill_id, request))
    }

    fn parse_jsonrpc_task_id_params(
        params: &Value,
        operation: &str,
    ) -> Result<String, A2aEdgeError> {
        let Some(task_id) = params.get("taskId") else {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "{operation} requires params.taskId"
            )));
        };
        let Some(task_id) = task_id.as_str() else {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must be a string"
            )));
        };
        if task_id.trim().is_empty() {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not be empty"
            )));
        }
        if task_id.trim() != task_id {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not include leading or trailing whitespace"
            )));
        }
        if task_id.chars().any(char::is_control) {
            return Err(A2aEdgeError::InvalidRequest(format!(
                "{operation} params.taskId must not include control characters"
            )));
        }
        Ok(task_id.to_string())
    }

    fn resolve_jsonrpc_target_skill_id(&self, params: &Value) -> Result<String, A2aEdgeError> {
        let skill_id_from_metadata = Self::target_skill_id_from_metadata(params)?;

        skill_id_from_metadata
            .or_else(|| {
                if self.skills.len() == 1 {
                    self.skills.first().map(|skill| skill.id.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                A2aEdgeError::InvalidRequest(
                    "metadata.chio.targetSkillId is required when multiple skills are exposed"
                        .to_string(),
                )
            })
    }

    fn target_skill_id_from_metadata(params: &Value) -> Result<Option<String>, A2aEdgeError> {
        let Some(metadata) = params.get("metadata") else {
            return Ok(None);
        };
        if metadata.is_null() {
            return Ok(None);
        }
        let Some(metadata) = metadata.as_object() else {
            return Err(A2aEdgeError::InvalidRequest(
                "metadata must be a JSON object".to_string(),
            ));
        };

        let Some(chio) = metadata.get("chio") else {
            return Ok(None);
        };
        if chio.is_null() {
            return Ok(None);
        }
        let Some(chio) = chio.as_object() else {
            return Err(A2aEdgeError::InvalidRequest(
                "metadata.chio must be a JSON object".to_string(),
            ));
        };

        let Some(target_skill_id) = chio.get("targetSkillId") else {
            return Ok(None);
        };
        if target_skill_id.is_null() {
            return Ok(None);
        }
        let Some(target_skill_id) = target_skill_id.as_str() else {
            return Err(A2aEdgeError::InvalidRequest(
                "metadata.chio.targetSkillId must be a string".to_string(),
            ));
        };
        if target_skill_id.trim().is_empty() {
            return Err(A2aEdgeError::InvalidRequest(
                "metadata.chio.targetSkillId must not be empty".to_string(),
            ));
        }
        if target_skill_id.trim() != target_skill_id {
            return Err(A2aEdgeError::InvalidRequest(
                "metadata.chio.targetSkillId must not include leading or trailing whitespace"
                    .to_string(),
            ));
        }
        Ok(Some(target_skill_id.to_string()))
    }
}
