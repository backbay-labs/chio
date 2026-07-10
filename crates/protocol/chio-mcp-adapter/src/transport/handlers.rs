use std::io::Write;

use chio_core::session::{CreateElicitationResult, CreateMessageOperation, CreateMessageResult};
use chio_kernel::{KernelError, NestedFlowBridge};
use serde_json::json;
use tracing::debug;

use crate::edge::AdapterError;

use super::nested_flow::{parse_requested_task, NestedFlowTaskRuntime};
use super::utils::{
    json_rpc_error, json_rpc_result, jsonrpc_request_id_label, map_nested_flow_error_code,
    parse_create_elicitation_operation, send_line, send_upstream_cancellation,
};

pub(super) fn respond_to_upstream_roots_without_bridge(
    writer: &mut impl Write,
    message: &serde_json::Value,
) -> Result<bool, AdapterError> {
    if message.get("method").and_then(serde_json::Value::as_str) != Some("roots/list") {
        return Ok(false);
    }

    let id = message
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    send_line(writer, &json_rpc_result(id, json!({ "roots": [] })))?;
    Ok(true)
}

pub(super) fn respond_to_upstream_nested_flow(
    writer: &mut impl Write,
    message: &serde_json::Value,
    nested_flow_bridge: &mut dyn NestedFlowBridge,
    nested_task_runtime: &mut NestedFlowTaskRuntime,
) -> Result<(), AdapterError> {
    let id = message
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = message
        .get("method")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdapterError::ParseError("upstream request missing method".into()))?;
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    let response = match method {
        "roots/list" => match nested_flow_bridge.list_roots() {
            Ok(roots) => json_rpc_result(id, json!({ "roots": roots })),
            Err(error) => {
                json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
            }
        },
        "sampling/createMessage" => {
            let operation: CreateMessageOperation = serde_json::from_value(params.clone())
                .map_err(|error| {
                    AdapterError::ParseError(format!(
                        "failed to parse sampling/createMessage params: {error}"
                    ))
                })?;
            if let Some(task) = parse_requested_task(&params)? {
                let owner_request_id = jsonrpc_request_id_label(&id);
                let parent_request_id = nested_flow_bridge.parent_request_id().to_string();
                json_rpc_result(
                    id,
                    nested_task_runtime.create_message_task(
                        owner_request_id,
                        parent_request_id,
                        operation,
                        task,
                    ),
                )
            } else {
                match nested_flow_bridge.create_message(operation) {
                    Ok(result) => {
                        let result = serde_json::to_value::<CreateMessageResult>(result).map_err(
                            |error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize sampling/createMessage result: {error}"
                                ))
                            },
                        )?;
                        json_rpc_result(id, result)
                    }
                    Err(error) => {
                        json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
                    }
                }
            }
        }
        "elicitation/create" => {
            let operation = parse_create_elicitation_operation(&params)?;
            if let Some(task) = parse_requested_task(&params)? {
                let owner_request_id = jsonrpc_request_id_label(&id);
                let parent_request_id = nested_flow_bridge.parent_request_id().to_string();
                json_rpc_result(
                    id,
                    nested_task_runtime.create_elicitation_task(
                        owner_request_id,
                        parent_request_id,
                        operation,
                        task,
                    ),
                )
            } else {
                match nested_flow_bridge.create_elicitation(operation) {
                    Ok(result) => {
                        let result = serde_json::to_value::<CreateElicitationResult>(result)
                            .map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize elicitation/create result: {error}"
                                ))
                            })?;
                        json_rpc_result(id, result)
                    }
                    Err(error) => {
                        json_rpc_error(id, map_nested_flow_error_code(&error), &error.to_string())
                    }
                }
            }
        }
        "tasks/list" => nested_task_runtime.handle_tasks_list(id, &params),
        "tasks/get" => nested_task_runtime.handle_tasks_get(id, &params),
        "tasks/cancel" => nested_task_runtime.handle_tasks_cancel(id, &params),
        "tasks/result" => {
            nested_task_runtime.handle_tasks_result(id, &params, nested_flow_bridge, writer)?
        }
        _ => json_rpc_error(id, -32601, "method not found"),
    };

    send_line(writer, &response)
}

pub(super) fn forward_upstream_notification(
    message: &serde_json::Value,
    nested_flow_bridge: &mut dyn NestedFlowBridge,
) -> Result<(), AdapterError> {
    let Some(method) = message.get("method").and_then(serde_json::Value::as_str) else {
        debug!("MCP notification without method: {message}");
        return Ok(());
    };

    match method {
        "notifications/resources/updated" => {
            let uri = message
                .get("params")
                .and_then(|params| params.get("uri"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AdapterError::ParseError(
                        "notifications/resources/updated missing params.uri".into(),
                    )
                })?;
            nested_flow_bridge
                .notify_resource_updated(uri)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))
        }
        "notifications/elicitation/complete" => {
            let elicitation_id = message
                .get("params")
                .and_then(|params| params.get("elicitationId"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AdapterError::ParseError(
                        "notifications/elicitation/complete missing params.elicitationId".into(),
                    )
                })?;
            nested_flow_bridge
                .notify_elicitation_completed(elicitation_id)
                .map_err(|error| AdapterError::NestedFlowDenied(error.to_string()))
        }
        "notifications/resources/list_changed" => nested_flow_bridge
            .notify_resources_list_changed()
            .map_err(|error| AdapterError::NestedFlowDenied(error.to_string())),
        _ => {
            debug!("MCP notification ignored: {message}");
            Ok(())
        }
    }
}

pub(super) fn service_active_request_runtime(
    nested_flow_bridge: &mut Option<&mut dyn NestedFlowBridge>,
    nested_task_runtime: &mut NestedFlowTaskRuntime,
    writer: &mut impl Write,
    request_id: &serde_json::Value,
) -> Result<(), AdapterError> {
    let Some(bridge) = nested_flow_bridge.as_deref_mut() else {
        return Ok(());
    };

    nested_task_runtime.process_background_tasks(bridge, writer)?;
    match bridge.poll_parent_cancellation() {
        Ok(()) => Ok(()),
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) => {
            let _ = send_upstream_cancellation(writer, request_id, &reason);
            Err(AdapterError::RequestCancelled {
                request_id: cancelled_request_id,
                reason,
            })
        }
        Err(error) => Err(AdapterError::ConnectionFailed(error.to_string())),
    }
}
