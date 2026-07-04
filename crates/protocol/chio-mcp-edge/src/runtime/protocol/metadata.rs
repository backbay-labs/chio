use super::*;

pub(in crate::runtime) fn build_related_task_meta(
    task_id: &str,
    owner_session_id: Option<&str>,
    owner_request_id: Option<&str>,
    parent_request_id: Option<&str>,
) -> Value {
    json!({
        "taskId": task_id,
        "ownerSessionId": owner_session_id,
        "ownerRequestId": owner_request_id,
        "parentRequestId": parent_request_id,
    })
}

pub(in crate::runtime) fn attach_related_task_meta_to_result(
    mut result: Value,
    related_task_meta: Value,
) -> Value {
    if let Some(object) = result.as_object_mut() {
        let meta = object
            .entry("_meta".to_string())
            .or_insert_with(|| json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(RELATED_TASK_META_KEY.to_string(), related_task_meta);
        }
    }
    result
}

pub(in crate::runtime) fn attach_execution_nonce_meta_to_result(
    mut result: Value,
    execution_nonce: Option<&SignedExecutionNonce>,
) -> Value {
    let Some(execution_nonce) = execution_nonce else {
        return result;
    };
    let Ok(nonce_value) = serde_json::to_value(execution_nonce) else {
        return result;
    };

    if let Some(object) = result.as_object_mut() {
        let meta = object
            .entry("_meta".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert("chioExecutionNonce".to_string(), nonce_value);
        }
    }
    result
}

pub(in crate::runtime) fn attach_related_task_meta_to_message(
    message: Value,
    related_task_id: Option<&str>,
) -> Value {
    let Some(task_id) = related_task_id else {
        return message;
    };

    let mut message = message;
    if let Some(object) = message.as_object_mut() {
        let params = object
            .entry("params".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(params) = params.as_object_mut() {
            let meta = params
                .entry("_meta".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(
                    RELATED_TASK_META_KEY.to_string(),
                    json!({ "taskId": task_id }),
                );
            }
        }
    }
    message
}

pub(in crate::runtime) fn capture_accepted_url_elicitation(
    accepted_url_elicitations: &mut Vec<AcceptedUrlElicitation>,
    operation: &CreateElicitationOperation,
    result: &CreateElicitationResult,
    related_task_id: Option<&str>,
) {
    let CreateElicitationOperation::Url { elicitation_id, .. } = operation else {
        return;
    };
    if !matches!(result.action, ElicitationAction::Accept) {
        return;
    }

    accepted_url_elicitations.push(AcceptedUrlElicitation {
        elicitation_id: elicitation_id.clone(),
        related_task_id: related_task_id.map(ToString::to_string),
    });
}

pub(in crate::runtime) fn make_elicitation_completion_notification(
    elicitation_id: &str,
    related_task_id: Option<&str>,
) -> Value {
    attach_related_task_meta_to_message(
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/elicitation/complete",
            "params": {
                "elicitationId": elicitation_id,
            }
        }),
        related_task_id,
    )
}
impl From<Value> for ToolCallEdgeOutcome {
    fn from(result: Value) -> Self {
        Self::Result(result)
    }
}

pub(in crate::runtime) fn tool_call_outcome_to_jsonrpc(
    id: Value,
    outcome: ToolCallEdgeOutcome,
) -> Value {
    match outcome {
        ToolCallEdgeOutcome::Result(result) => jsonrpc_result(id, result),
        ToolCallEdgeOutcome::Cancelled { reason } => jsonrpc_result(id, tool_error_result(&reason)),
        ToolCallEdgeOutcome::JsonRpcError {
            code,
            message,
            data,
        } => jsonrpc_error_with_data(id, code, &message, data),
    }
}

pub(in crate::runtime) fn task_outcome_to_jsonrpc(
    task: Option<EdgeTask>,
    id: &Value,
    task_id: &str,
) -> Value {
    match task {
        Some(task) => {
            let related_task_meta = build_related_task_meta(
                &task.task_id,
                Some(&task.owner_session_id),
                Some(&task.owner_request_id),
                task.parent_request_id.as_deref(),
            );
            match task.final_outcome {
                Some(EdgeTaskFinalOutcome::Result(result)) => jsonrpc_result(
                    id.clone(),
                    attach_related_task_meta_to_result(result, related_task_meta),
                ),
                Some(EdgeTaskFinalOutcome::JsonRpcError {
                    code,
                    message,
                    data,
                }) => jsonrpc_error_with_data(id.clone(), code, &message, data),
                None => jsonrpc_result(
                    id.clone(),
                    attach_related_task_meta_to_result(
                        tool_error_result("task result unavailable"),
                        related_task_meta,
                    ),
                ),
            }
        }
        None => jsonrpc_result(
            id.clone(),
            attach_related_task_meta_to_result(
                tool_error_result("task result unavailable"),
                build_related_task_meta(task_id, None, None, None),
            ),
        ),
    }
}
