use super::*;

pub(in crate::runtime) fn parse_task_id(id: &Value, params: &Value) -> Result<String, Value> {
    let task_id = params
        .get("taskId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "taskId must be a string",
            )
        })?;
    let task_id = parse_protocol_identifier(task_id, "taskId")
        .map_err(|message| jsonrpc_error(id.clone(), JSONRPC_INVALID_PARAMS, message.as_str()))?;
    Ok(task_id.to_string())
}
pub(in crate::runtime) fn parse_completion_reference(
    params: &Value,
) -> Result<CompletionReference, String> {
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
            let name = parse_protocol_identifier(name, "prompt ref name")?;
            Ok(CompletionReference::Prompt {
                name: name.to_string(),
            })
        }
        Some("ref/resource") => {
            let uri = reference
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| "resource ref requires a uri".to_string())?;
            let uri = parse_protocol_identifier(uri, "resource ref uri")?;
            Ok(CompletionReference::Resource {
                uri: uri.to_string(),
            })
        }
        Some(_) => Err("unsupported completion ref type".to_string()),
        None => Err("completion ref requires a type".to_string()),
    }
}

pub(in crate::runtime) fn parse_completion_argument(
    params: &Value,
) -> Result<CompletionArgument, String> {
    let argument = params
        .get("argument")
        .and_then(Value::as_object)
        .ok_or_else(|| "completion/complete requires an argument".to_string())?;

    let name = argument
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a name".to_string())?;
    let name = parse_protocol_identifier(name, "completion argument name")?;
    let value = argument
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| "completion argument requires a value".to_string())?;

    Ok(CompletionArgument {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn parse_protocol_identifier<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    if value.is_empty() || value.trim() != value || value.chars().any(|ch| ch.is_control()) {
        return Err(format!(
            "{label} must be a non-empty unpadded string without control characters"
        ));
    }

    Ok(value)
}
pub(in crate::runtime) fn parse_cursor(id: &Value, params: &Value) -> Result<usize, Value> {
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

pub(in crate::runtime) fn build_operation_context(
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

pub(in crate::runtime) fn parse_request_model_metadata(
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
        chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
    )))
}

pub(in crate::runtime) fn parse_request_execution_nonce(
    id: &Value,
    params: &Value,
) -> Result<Option<Value>, Value> {
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
    let Some(execution_nonce) = meta
        .get("executionNonce")
        .or_else(|| meta.get("chioExecutionNonce"))
    else {
        return Ok(None);
    };

    serde_json::from_value::<SignedExecutionNonce>(execution_nonce.clone()).map_err(|_| {
        jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "executionNonce must be a signed Chio execution nonce object",
        )
    })?;
    Ok(Some(execution_nonce.clone()))
}

pub(in crate::runtime) fn parse_request_governed_intent(
    id: &Value,
    params: &Value,
) -> Result<Option<GovernedTransactionIntent>, Value> {
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
    let Some(governed_intent) = meta
        .get("governedIntent")
        .or_else(|| meta.get("chioGovernedIntent"))
    else {
        return Ok(None);
    };

    serde_json::from_value(governed_intent.clone())
        .map(Some)
        .map_err(|_| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "governedIntent must be a Chio governed transaction intent object",
            )
        })
}

pub(in crate::runtime) fn parse_request_extra_metadata(
    id: &Value,
    params: &Value,
) -> Result<Option<Value>, Value> {
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
    let Some(route_selection) = meta
        .get("routeSelection")
        .or_else(|| meta.get("route_selection"))
        .or_else(|| meta.get("chioRouteSelection"))
    else {
        return Ok(None);
    };

    if !route_selection.is_object() {
        return Err(jsonrpc_error(
            id.clone(),
            JSONRPC_INVALID_PARAMS,
            "routeSelection must be an object",
        ));
    }
    Ok(Some(json!({ "route_selection": route_selection.clone() })))
}

pub(in crate::runtime) fn parse_progress_token(
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

pub(in crate::runtime) fn parse_peer_capabilities(params: &Value) -> PeerCapabilities {
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
