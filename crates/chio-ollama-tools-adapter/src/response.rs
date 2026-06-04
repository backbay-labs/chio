//! Native Ollama response-envelope parsing for `/api/chat`.

use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::ToolCallPart;

pub(crate) fn tool_calls(raw: ProviderRequest) -> Result<Vec<ToolCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("Ollama /api/chat payload was not JSON: {error}"))
    })?;
    let body = response_body(value)?;
    classify_content_policy(&body)?;
    extract_tool_calls(&body)
}

fn response_body(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            return nested_response_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "Ollama /api/chat envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }
    Ok(value)
}

fn nested_response_body(value: &Value) -> Option<Value> {
    if let Some(obj) = value.as_object() {
        return Some(Value::Object(obj.clone()));
    }
    let text = value.as_str()?;
    let parsed: Value = serde_json::from_str(text).ok()?;
    parsed.as_object().map(|obj| Value::Object(obj.clone()))
}

pub(crate) fn classify_content_policy(body: &Value) -> Result<(), ProviderError> {
    if let Some(reason) = refusal_reason(body) {
        return Err(ProviderError::ContentPolicy(format!(
            "Ollama model refusal: {reason}"
        )));
    }
    Ok(())
}

fn refusal_reason(body: &Value) -> Option<String> {
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|policy| policy.eq_ignore_ascii_case("refusal"))?;
    let done_reason = body
        .get("done_reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    Some(match done_reason {
        Some(done_reason) => format!("policy={policy}, done_reason={done_reason}"),
        None => format!("policy={policy}"),
    })
}

fn extract_tool_calls(body: &Value) -> Result<Vec<ToolCallPart>, ProviderError> {
    let message = match body.get("message") {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    let array = match message.get("tool_calls").and_then(Value::as_array) {
        Some(array) => array,
        None => return Ok(Vec::new()),
    };
    let mut calls = Vec::with_capacity(array.len());
    for entry in array {
        calls.push(tool_call_part(entry)?);
    }
    Ok(calls)
}

pub(crate) fn tool_call_part(entry: &Value) -> Result<ToolCallPart, ProviderError> {
    serde_json::from_value(entry.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Ollama tool_call entry was malformed: {error}"))
    })
}
