use super::*;

pub(super) struct KernelResponseToToolResultArgs<'a> {
    pub pending_notifications: &'a mut Vec<Value>,
    pub request_id: &'a Value,
    pub output: Option<ToolCallOutput>,
    pub reason: Option<String>,
    pub verdict: Verdict,
    pub terminal_state: &'a OperationTerminalState,
    pub peer_supports_chio_tool_streaming: bool,
    pub related_task_id: Option<&'a str>,
}

pub(super) fn manifest_tool_to_mcp_tool(tool: ToolDefinition) -> McpExposedTool {
    let annotations = Some(json!({
        "readOnlyHint": !tool.has_side_effects,
        "destructiveHint": tool.has_side_effects,
    }));

    let mut execution = serde_json::Map::new();
    execution.insert("taskSupport".to_string(), json!("optional"));
    if let Some(latency_hint) = tool.latency_hint {
        execution.insert(
            "suggestedLatency".to_string(),
            json!(latency_hint_to_label(latency_hint)),
        );
    }

    McpExposedTool {
        name: tool.name,
        title: None,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        annotations,
        execution: Some(Value::Object(execution)),
    }
}

pub(super) fn latency_hint_to_label(latency_hint: LatencyHint) -> &'static str {
    match latency_hint {
        LatencyHint::Instant => "instant",
        LatencyHint::Fast => "fast",
        LatencyHint::Moderate => "moderate",
        LatencyHint::Slow => "slow",
    }
}

pub(super) fn kernel_response_to_tool_result(args: KernelResponseToToolResultArgs<'_>) -> Value {
    let KernelResponseToToolResultArgs {
        pending_notifications,
        request_id,
        output,
        reason,
        verdict,
        terminal_state,
        peer_supports_chio_tool_streaming,
        related_task_id,
    } = args;
    let is_error = matches!(verdict, Verdict::Deny) || !terminal_state.is_completed();
    let terminal_reason = reason
        .as_deref()
        .or_else(|| terminal_state_reason(terminal_state));

    match output {
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
    }
}

pub(super) fn queue_tool_stream_chunk_notifications(
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

pub(super) fn streamed_notification_tool_result(
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

pub(super) fn collapsed_stream_tool_result(
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

pub(super) fn tool_stream_structured_content(stream: serde_json::Map<String, Value>) -> Value {
    let stream_value = Value::Object(stream);
    let mut structured_content = serde_json::Map::new();
    structured_content.insert(CHIO_TOOL_STREAM_KEY.to_string(), stream_value);
    Value::Object(structured_content)
}

pub(super) fn terminal_state_label(terminal_state: &OperationTerminalState) -> &'static str {
    match terminal_state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

pub(super) fn terminal_state_reason(terminal_state: &OperationTerminalState) -> Option<&str> {
    match terminal_state {
        OperationTerminalState::Completed => None,
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => Some(reason),
    }
}

pub(super) fn default_tool_failure_reason(terminal_state: &OperationTerminalState) -> String {
    match terminal_state {
        OperationTerminalState::Completed => "tool call denied".to_string(),
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => reason.clone(),
    }
}

pub(super) fn iso8601_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(super) fn unix_now_millis() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

pub(super) fn parse_requested_task(
    id: &Value,
    params: &Value,
) -> Result<Option<RequestedTask>, Value> {
    let Some(task) = params.get("task").cloned() else {
        return Ok(None);
    };
    serde_json::from_value(task).map(Some).map_err(|_| {
        jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "task must be an object with an optional numeric ttl",
        )
    })
}

pub(super) fn parse_task_id(id: &Value, params: &Value) -> Result<String, Value> {
    params
        .get("taskId")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "taskId must be a string",
            )
        })
}

pub(super) fn edge_task_status_label(status: EdgeTaskStatus) -> &'static str {
    match status {
        EdgeTaskStatus::Working => "working",
        EdgeTaskStatus::Completed => "completed",
        EdgeTaskStatus::Failed => "failed",
        EdgeTaskStatus::Cancelled => "cancelled",
    }
}

pub(super) fn tool_result_is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn cancellation_reason_from_tool_result(result: &Value) -> Option<String> {
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

pub(super) fn task_status_message(status: &EdgeTaskStatus, result: &Value) -> Option<String> {
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

pub(super) fn build_related_task_meta(
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

pub(super) fn attach_related_task_meta_to_result(
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

pub(super) fn attach_related_task_meta_to_message(
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

pub(super) fn capture_accepted_url_elicitation(
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

pub(super) fn make_elicitation_completion_notification(
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

pub(super) fn value_to_tool_result(value: Value) -> Value {
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

pub(super) fn tool_error_result(reason: &str) -> Value {
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

impl From<Value> for ToolCallEdgeOutcome {
    fn from(result: Value) -> Self {
        Self::Result(result)
    }
}

pub(super) fn tool_call_outcome_to_jsonrpc(id: Value, outcome: ToolCallEdgeOutcome) -> Value {
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

pub(super) fn task_outcome_to_jsonrpc(task: Option<EdgeTask>, id: &Value, task_id: &str) -> Value {
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

pub(super) fn serialize_resources(resources: Vec<ResourceDefinition>) -> Vec<Value> {
    resources
        .into_iter()
        .map(|resource| serde_json::to_value(resource).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(super) fn serialize_resource_templates(
    templates: Vec<ResourceTemplateDefinition>,
) -> Vec<Value> {
    templates
        .into_iter()
        .map(|template| serde_json::to_value(template).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(super) fn serialize_resource_contents(contents: Vec<ResourceContent>) -> Vec<Value> {
    contents
        .into_iter()
        .map(|content| serde_json::to_value(content).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(super) fn serialize_prompts(prompts: Vec<PromptDefinition>) -> Vec<Value> {
    prompts
        .into_iter()
        .map(|prompt| serde_json::to_value(prompt).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(super) fn parse_completion_reference(params: &Value) -> Result<CompletionReference, String> {
    let reference = params
        .get("ref")
        .and_then(Value::as_object)
        .ok_or_else(|| "completion/complete requires a ref".to_string())?;

    match reference.get("type").and_then(Value::as_str) {
        Some("ref/prompt") => {
            let name = reference
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "prompt ref requires a name".to_string())?;
            Ok(CompletionReference::Prompt {
                name: name.to_string(),
            })
        }
        Some("ref/resource") => {
            let uri = reference
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| "resource ref requires a uri".to_string())?;
            Ok(CompletionReference::Resource {
                uri: uri.to_string(),
            })
        }
        Some(_) => Err("unsupported completion ref type".to_string()),
        None => Err("completion ref requires a type".to_string()),
    }
}

pub(super) fn parse_completion_argument(params: &Value) -> Result<CompletionArgument, String> {
    let argument = params
        .get("argument")
        .and_then(Value::as_object)
        .ok_or_else(|| "completion/complete requires an argument".to_string())?;

    let name = argument
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a name".to_string())?;
    let value = argument
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a value".to_string())?;

    Ok(CompletionArgument {
        name: name.to_string(),
        value: value.to_string(),
    })
}

pub(super) fn paginate_response(
    id: Value,
    start: usize,
    page_size: usize,
    values: Vec<Value>,
) -> Value {
    paginate_named_response(id, start, page_size, "resources", values)
}

pub(super) fn paginate_named_response(
    id: Value,
    start: usize,
    page_size: usize,
    field_name: &str,
    values: Vec<Value>,
) -> Value {
    if start > values.len() {
        return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
    }

    let page_size = page_size.max(1);
    let end = (start + page_size).min(values.len());
    let next_cursor = (end < values.len()).then(|| end.to_string());

    let mut result = serde_json::Map::new();
    result.insert(
        field_name.to_string(),
        Value::Array(values[start..end].to_vec()),
    );
    result.insert(
        "nextCursor".to_string(),
        next_cursor.map(Value::String).unwrap_or(Value::Null),
    );

    jsonrpc_result(id, Value::Object(result))
}

pub(super) fn parse_cursor(id: &Value, params: &Value) -> Result<usize, Value> {
    let cursor = match params.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "cursor must be a string",
            ))
        }
    };

    match cursor.as_deref() {
        None => Ok(0),
        Some(cursor) => cursor.parse::<usize>().map_err(|_| {
            jsonrpc_error(id.clone(), JSONRPC_INVALID_PARAMS, "cursor must be numeric")
        }),
    }
}

pub(super) fn build_operation_context(
    id: &Value,
    session_id: SessionId,
    request_id: String,
    agent_id: &str,
    params: &Value,
) -> Result<OperationContext, Value> {
    let mut context =
        OperationContext::new(session_id, RequestId::new(request_id), agent_id.to_string());
    context.progress_token = parse_progress_token(id, params)?;
    Ok(context)
}

pub(super) fn parse_request_model_metadata(
    id: &Value,
    params: &Value,
) -> Result<Option<ModelMetadata>, Value> {
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let Some(meta) = meta.as_object() else {
        return Err(jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "_meta must be an object",
        ));
    };
    let Some(model_metadata) = meta
        .get("modelMetadata")
        .or_else(|| meta.get("chioModelMetadata"))
    else {
        return Ok(None);
    };

    let metadata: ModelMetadata = serde_json::from_value(model_metadata.clone()).map_err(|_| {
        jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "modelMetadata must be an object with model_id and optional safety_tier/provider",
        )
    })?;

    Ok(Some(metadata.with_provenance_class(
        chio_core::capability::ProvenanceEvidenceClass::Asserted,
    )))
}

pub(super) fn parse_progress_token(
    id: &Value,
    params: &Value,
) -> Result<Option<ProgressToken>, Value> {
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let Some(meta) = meta.as_object() else {
        return Err(jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "_meta must be an object",
        ));
    };
    let Some(progress_token) = meta.get("progressToken") else {
        return Ok(None);
    };

    serde_json::from_value(progress_token.clone())
        .map(Some)
        .map_err(|_| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "progressToken must be a string or integer",
            )
        })
}

pub(super) fn parse_peer_capabilities(params: &Value) -> PeerCapabilities {
    let experimental = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("experimental"));
    let resources = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("resources"));
    let roots = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("roots"));
    let sampling = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("sampling"));
    let elicitation = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("elicitation"));
    let elicitation_form = elicitation.is_some_and(|value| {
        value.as_object().is_some_and(|object| object.is_empty()) || value.get("form").is_some()
    });
    let elicitation_url = elicitation
        .is_some_and(|value| value.get("url").is_some() || value.get("openUrl").is_some());

    PeerCapabilities {
        supports_progress: true,
        supports_cancellation: true,
        supports_subscriptions: resources
            .and_then(|value| value.get("subscribe"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_chio_tool_streaming: experimental
            .and_then(|value| value.get(CHIO_TOOL_STREAMING_CAPABILITY_KEY))
            .and_then(|value| value.get("toolCallChunkNotifications"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_roots: roots.is_some(),
        roots_list_changed: roots
            .and_then(|value| value.get("listChanged"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_sampling: sampling.is_some(),
        sampling_context: sampling
            .and_then(|value| value.get("context"))
            .is_some_and(Value::is_object),
        sampling_tools: sampling
            .and_then(|value| value.get("tools"))
            .is_some_and(Value::is_object),
        supports_elicitation: elicitation.is_some(),
        elicitation_form,
        elicitation_url,
    }
}

pub(super) fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

pub(super) fn queue_progress_notification(
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

pub(super) fn progress_token_to_value(progress_token: &ProgressToken) -> Value {
    match progress_token {
        ProgressToken::String(value) => Value::String(value.clone()),
        ProgressToken::Integer(value) => json!(*value),
    }
}

pub(super) fn cancellation_matches_request(message: &Value, request_id: &str) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(&Value::String(request_id.to_string()))
}

pub(super) fn cancellation_matches_client_request(message: &Value, request_id: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(request_id)
}

pub(super) fn task_cancel_matches_related_task(
    message: &Value,
    related_task_id: Option<&str>,
) -> bool {
    let Some(related_task_id) = related_task_id else {
        return false;
    };

    message.get("method").and_then(Value::as_str) == Some("tasks/cancel")
        && message
            .get("params")
            .and_then(|params| params.get("taskId"))
            .and_then(Value::as_str)
            == Some(related_task_id)
}

pub(super) fn explicit_task_cancel_reason() -> &'static str {
    "task cancelled by client"
}

pub(super) fn cancellation_reason(message: &Value) -> String {
    let reason = message
        .get("params")
        .and_then(|params| params.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty());

    match reason {
        Some(reason) => format!("cancelled by client: {reason}"),
        None => "cancelled by client".to_string(),
    }
}

pub(super) fn next_client_message(
    client_rx: &mpsc::Receiver<ClientInbound>,
) -> Result<Value, AdapterError> {
    match client_rx.recv() {
        Ok(ClientInbound::Message(message)) => Ok(message),
        Ok(ClientInbound::ParseError(error)) => Err(AdapterError::ParseError(format!(
            "failed to parse MCP edge message: {error}"
        ))),
        Ok(ClientInbound::ReadError(error)) => Err(AdapterError::ConnectionFailed(format!(
            "failed to read MCP edge request: {error}"
        ))),
        Ok(ClientInbound::Closed) | Err(mpsc::RecvError) => Err(AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        )),
    }
}

pub(super) fn pump_client_messages<R: BufRead>(
    mut reader: R,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(ClientInbound::Closed);
                return;
            }
            Ok(_) => {}
            Err(error) => {
                let _ = sender.send(ClientInbound::ReadError(error.to_string()));
                return;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Value>(trimmed) {
            Ok(message) => {
                let is_cancel_signal = matches!(
                    message.get("method").and_then(Value::as_str),
                    Some("notifications/cancelled" | "tasks/cancel")
                );
                if sender
                    .send(ClientInbound::Message(message.clone()))
                    .is_err()
                {
                    return;
                }
                // Queue the JSON-RPC request before the side-channel signal so a
                // nested-flow cancellation can still defer and answer tasks/cancel.
                if is_cancel_signal {
                    let _ = cancel_sender.send(message);
                }
            }
            Err(error) => {
                if sender
                    .send(ClientInbound::ParseError(error.to_string()))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

pub(super) fn pump_channel_messages(
    receiver: mpsc::Receiver<Value>,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    while let Ok(message) = receiver.recv() {
        let is_cancel_signal = matches!(
            message.get("method").and_then(Value::as_str),
            Some("notifications/cancelled" | "tasks/cancel")
        );
        if sender
            .send(ClientInbound::Message(message.clone()))
            .is_err()
        {
            return;
        }
        if is_cancel_signal {
            let _ = cancel_sender.send(message);
        }
    }

    let _ = sender.send(ClientInbound::Closed);
}

pub(super) fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

pub(super) fn jsonrpc_error_with_data(
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

pub(super) fn adapter_jsonrpc_error(error: &Value) -> AdapterError {
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

pub(super) fn write_jsonrpc_line(
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

pub(super) fn read_jsonrpc_line(reader: &mut impl BufRead) -> Result<Value, AdapterError> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).map_err(|error| {
        AdapterError::ConnectionFailed(format!("failed to read MCP edge request: {error}"))
    })?;

    if bytes_read == 0 {
        return Err(AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        ));
    }

    serde_json::from_str(line.trim()).map_err(|error| {
        AdapterError::ParseError(format!("failed to parse MCP edge message: {error}"))
    })
}

pub(super) fn select_capability_for_request(
    capabilities: &[CapabilityToken],
    tool_name: &str,
    server_id: &str,
    arguments: &Value,
    model_metadata: Option<&ModelMetadata>,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_request_with_model_metadata(
                capability,
                tool_name,
                server_id,
                arguments,
                model_metadata,
            )
            .unwrap_or(false)
        })
        .cloned()
}

pub(super) fn select_capability_for_resource(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_request(capability, uri).unwrap_or(false)
        })
        .cloned()
}

pub(super) fn select_capability_for_resource_subscription(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_subscription(capability, uri).unwrap_or(false)
        })
        .cloned()
}

pub(super) fn select_capability_for_prompt(
    capabilities: &[CapabilityToken],
    prompt_name: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_prompt_request(capability, prompt_name).unwrap_or(false)
        })
        .cloned()
}

pub(super) fn select_capability_for_resource_pattern(
    capabilities: &[CapabilityToken],
    pattern: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_pattern(capability, pattern).unwrap_or(false)
        })
        .cloned()
}

pub(super) fn tool_is_authorized(
    capabilities: &[CapabilityToken],
    binding: &ExposedToolBinding,
) -> bool {
    capabilities.iter().any(|capability| {
        capability.scope.grants.iter().any(|grant| {
            matches_server(&grant.server_id, &binding.server_id)
                && matches_name(&grant.tool_name, &binding.tool_name)
                && grant.operations.contains(&Operation::Invoke)
        })
    })
}

pub(super) fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

pub(super) fn matches_name(pattern: &str, tool_name: &str) -> bool {
    pattern == "*" || pattern == tool_name
}
