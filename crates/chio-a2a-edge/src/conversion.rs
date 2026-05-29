// Message/argument conversion helpers and Chio metadata envelope builders
// shared across the kernel and compatibility surfaces.

/// Extract arguments from A2A message parts.
fn extract_arguments_from_message(message: &A2aMessage) -> Value {
    let mut text_parts = Vec::new();
    let mut data_part = None;

    for part in &message.parts {
        match part {
            A2aPart::Text { text } => text_parts.push(text.clone()),
            A2aPart::Data { data } => data_part = Some(data.clone()),
        }
    }

    if let Some(data) = data_part {
        data
    } else {
        json!({
            "message": text_parts.join("\n"),
        })
    }
}

/// Convert a tool result to A2A message parts.
fn result_to_parts(result: &Value) -> Vec<A2aPart> {
    if let Some(text) = result.as_str() {
        vec![A2aPart::Text {
            text: text.to_string(),
        }]
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        content
            .iter()
            .filter_map(|c| {
                c.get("text")
                    .and_then(Value::as_str)
                    .map(|t| A2aPart::Text {
                        text: t.to_string(),
                    })
            })
            .collect()
    } else if result.is_object() || result.is_array() {
        vec![A2aPart::Data {
            data: result.clone(),
        }]
    } else {
        vec![A2aPart::Text {
            text: result.to_string(),
        }]
    }
}

fn task_response_from_orchestrated(
    task_id: String,
    orchestrated: OrchestratedToolCall,
) -> TaskResponse {
    let mut metadata = orchestrated.metadata();
    let response = orchestrated.response;
    annotate_authoritative_a2a_metadata(&mut metadata, response.output.as_ref());
    let receipt_metadata = Some(metadata);

    crate::metrics::record_receipt_write_verdict(response.verdict);

    match response.verdict {
        KernelVerdict::Allow => TaskResponse {
            id: task_id,
            status: TaskStatus::Completed,
            status_message: None,
            message: Some(A2aMessage {
                role: "agent".to_string(),
                parts: kernel_output_to_parts(response.output.as_ref()),
                metadata: None,
            }),
            metadata: receipt_metadata,
        },
        KernelVerdict::Deny | KernelVerdict::PendingApproval => TaskResponse {
            id: task_id,
            status: TaskStatus::Failed,
            status_message: response.reason,
            message: None,
            metadata: receipt_metadata,
        },
    }
}

fn pending_task_metadata(authority_path: &str, message_stream: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "pending",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "compatibilityOnly": false,
            "claimEligible": true,
            "receiptBearing": false,
            "receiptPending": true,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": message_stream,
                "taskGet": "supported",
                "taskCancel": "supported"
            }
        }
    })
}

fn cancelled_task_metadata(authority_path: &str, message_stream: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "cancelled",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "compatibilityOnly": false,
            "claimEligible": true,
            "receiptBearing": false,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": message_stream,
                "taskGet": "supported",
                "taskCancel": "supported"
            }
        }
    })
}

fn kernel_output_to_parts(output: Option<&ToolCallOutput>) -> Vec<A2aPart> {
    match output {
        Some(ToolCallOutput::Value(value)) => result_to_parts(value),
        Some(ToolCallOutput::Stream(stream)) => stream
            .chunks
            .iter()
            .flat_map(|chunk| result_to_parts(&chunk.data))
            .collect(),
        None => vec![],
    }
}

#[cfg(any(test, feature = "compatibility-surface"))]
fn passthrough_metadata(reason: Option<&str>) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "passthrough",
            "capabilityId": Value::Null,
            "authorityPath": "passthrough_compatibility",
            "authoritative": false,
            "compatibilityOnly": true,
            "claimEligible": false,
            "receiptBearing": false,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aCompatibility),
            "lifecycle": {
                "messageSend": "blocking_terminal_task",
                "messageStream": "unsupported"
            },
            "reason": reason,
        }
    })
}

fn annotate_authoritative_a2a_metadata(metadata: &mut Value, output: Option<&ToolCallOutput>) {
    let Some(chio_metadata) = metadata.get_mut("chio").and_then(Value::as_object_mut) else {
        return;
    };

    chio_metadata.insert(
        "lifecycle".to_string(),
        json!({
            "messageSend": "blocking_terminal_task",
            "messageStream": "deferred_task_poll",
            "taskGet": "supported",
            "taskCancel": "supported"
        }),
    );
    chio_metadata.insert(
        "a2aSurface".to_string(),
        Value::String("authoritative_blocking_send".to_string()),
    );
    chio_metadata.insert(
        "runtimeLifecycle".to_string(),
        runtime_lifecycle_metadata(RuntimeLifecycleSurface::A2aAuthoritative),
    );

    if matches!(output, Some(ToolCallOutput::Stream(_))) {
        chio_metadata.insert(
            "streamProjection".to_string(),
            Value::String("collated_final_message".to_string()),
        );
    }
}

fn build_a2a_source_envelope(
    skill_id: &str,
    request: &SendMessageRequest,
) -> Result<Value, A2aEdgeError> {
    let mut envelope = serde_json::to_value(request)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    let chio_metadata = ensure_chio_metadata(&mut envelope)
        .map_err(|error| A2aEdgeError::InvalidRequest(error.to_string()))?;
    chio_metadata.insert(
        "targetSkillId".to_string(),
        Value::String(skill_id.to_string()),
    );
    Ok(envelope)
}

fn ensure_chio_metadata(
    envelope: &mut Value,
) -> Result<&mut serde_json::Map<String, Value>, BridgeError> {
    let Some(object) = envelope.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "request envelope must be a JSON object".to_string(),
        ));
    };
    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| json!({}));
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "metadata must be a JSON object".to_string(),
        ));
    };
    let chio = metadata_obj
        .entry("chio".to_string())
        .or_insert_with(|| json!({}));
    chio.as_object_mut().ok_or_else(|| {
        BridgeError::InvalidRequest("metadata.chio must be a JSON object".to_string())
    })
}
