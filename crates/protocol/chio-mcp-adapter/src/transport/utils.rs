use std::io::{BufRead, Write};
use std::process::Command;
use std::time::Duration;

use chio_core::session::CreateElicitationOperation;
use chio_kernel::KernelError;
use chrono::{SecondsFormat, Utc};
use serde_json::json;
use tracing::debug;

use crate::edge::AdapterError;
use crate::framing::read_jsonrpc_frame;

pub(super) const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub(super) const UPSTREAM_REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(20);
pub(super) const TASK_POLL_INTERVAL_MILLIS: u64 = 500;
pub(super) const MAX_BACKGROUND_TASKS_PER_TICK: usize = 8;
pub(super) const MAX_STDIO_MCP_BUFFERED_MESSAGES: usize = 128;
pub(super) const RELATED_TASK_META_KEY: &str = "io.modelcontextprotocol/related-task";
pub(super) const CHIO_AUTH_ENV_VARS: &[&str] = &[
    "CHIO_AUTH_TOKEN",
    "CHIO_ADMIN_TOKEN",
    "CHIO_MCP_AUTH_TOKEN",
    "CHIO_MCP_ADMIN_TOKEN",
    "CHIO_CONFORMANCE_AUTH_TOKEN",
    "CHIO_CONFORMANCE_ADMIN_TOKEN",
];

pub(super) fn remove_chio_auth_env(command: &mut Command) {
    for key in CHIO_AUTH_ENV_VARS {
        command.env_remove(key);
    }
}

pub(super) fn proxy_client_capabilities() -> serde_json::Value {
    json!({
        "roots": {
            "listChanged": true,
        },
        "sampling": {
            "context": {},
            "tools": {},
        },
        "elicitation": {
            "form": {},
            "url": {}
        },
        "tasks": {
            "list": {},
            "cancel": {},
            "requests": {
                "sampling": {
                    "createMessage": {}
                },
                "elicitation": {
                    "create": {}
                }
            }
        }
    })
}

pub(super) fn parse_create_elicitation_operation(
    params: &serde_json::Value,
) -> Result<CreateElicitationOperation, AdapterError> {
    let mut normalized = params.clone();
    if normalized.get("mode").is_none() {
        if let Some(object) = normalized.as_object_mut() {
            object.insert("mode".to_string(), json!("form"));
        }
    }

    serde_json::from_value(normalized).map_err(|error| {
        AdapterError::ParseError(format!(
            "failed to parse elicitation/create params: {error}"
        ))
    })
}

pub(super) fn iso8601_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(super) fn build_related_task_meta(
    task_id: &str,
    owner_request_id: Option<&str>,
    parent_request_id: Option<&str>,
) -> serde_json::Value {
    json!({
        "taskId": task_id,
        "ownerRequestId": owner_request_id,
        "parentRequestId": parent_request_id,
    })
}

pub(super) fn attach_related_task_meta_to_result(
    mut result: serde_json::Value,
    related_task_meta: serde_json::Value,
) -> serde_json::Value {
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

pub(super) fn is_nested_flow_notification(message: &serde_json::Value) -> bool {
    matches!(
        message.get("method").and_then(serde_json::Value::as_str),
        Some(
            "notifications/resources/updated"
                | "notifications/resources/list_changed"
                | "notifications/elicitation/complete"
        )
    )
}

pub(super) fn map_nested_flow_error_code(error: &KernelError) -> i64 {
    match error {
        KernelError::SamplingNotAllowedByPolicy
        | KernelError::SamplingNotNegotiated
        | KernelError::SamplingContextNotSupported
        | KernelError::SamplingToolUseNotAllowedByPolicy
        | KernelError::SamplingToolUseNotNegotiated
        | KernelError::ElicitationNotAllowedByPolicy
        | KernelError::ElicitationNotNegotiated
        | KernelError::ElicitationFormNotSupported
        | KernelError::ElicitationUrlNotSupported
        | KernelError::InvalidChildRequestParent
        | KernelError::RootsNotNegotiated => -32002,
        KernelError::UrlElicitationsRequired { .. } => -32042,
        KernelError::RequestCancelled { .. } => -32800,
        _ => -32603,
    }
}

pub(super) fn json_rpc_result(
    id: serde_json::Value,
    result: serde_json::Value,
) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

pub(super) fn json_rpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

pub(super) fn adapter_jsonrpc_error(error: &serde_json::Value) -> AdapterError {
    AdapterError::McpError {
        code: error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-32603),
        message: error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown JSON-RPC error")
            .to_string(),
        data: error.get("data").cloned(),
    }
}

/// Write a JSON value as a single newline-terminated line to the writer.
pub(super) fn send_line(
    writer: &mut impl Write,
    value: &serde_json::Value,
) -> Result<(), AdapterError> {
    let line = serde_json::to_string(value)
        .map_err(|e| AdapterError::ParseError(format!("failed to serialize JSON-RPC: {e}")))?;
    debug!("-> {line}");
    writer
        .write_all(line.as_bytes())
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to write to stdin: {e}")))?;
    writer
        .write_all(b"\n")
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to write newline: {e}")))?;
    writer
        .flush()
        .map_err(|e| AdapterError::ConnectionFailed(format!("failed to flush stdin: {e}")))?;
    Ok(())
}

pub(super) fn send_upstream_cancellation(
    writer: &mut impl Write,
    request_id: &serde_json::Value,
    reason: &str,
) -> Result<(), AdapterError> {
    send_line(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": request_id,
                "reason": reason,
            }
        }),
    )
}

pub(super) fn jsonrpc_request_id_label(request_id: &serde_json::Value) -> String {
    match request_id {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Read a single newline-terminated JSON line from the reader.
pub(super) fn read_line(reader: &mut impl BufRead) -> Result<serde_json::Value, AdapterError> {
    read_jsonrpc_frame(reader)?
        .ok_or_else(|| AdapterError::ConnectionFailed("MCP server closed stdout (EOF)".into()))
}
