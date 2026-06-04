//! Native Mistral response-envelope parsing for `chat/completions`.

use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::FunctionCallPart;

pub(crate) fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!(
            "Mistral chat/completions payload was not JSON: {error}"
        ))
    })?;
    let body = response_body(value)?;
    classify_content_policy(&body)?;
    extract_function_calls(&body)
}

fn response_body(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            return nested_response_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "Mistral chat/completions envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }
    Ok(value)
}

fn nested_response_body(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        Value::String(body) => serde_json::from_str(body).ok(),
        _ => None,
    }
}

fn classify_content_policy(body: &Value) -> Result<(), ProviderError> {
    if let Some(reason) = content_filter_reason(body) {
        return Err(ProviderError::ContentPolicy(format!(
            "Mistral safety block: {reason}"
        )));
    }
    Ok(())
}

fn content_filter_reason(body: &Value) -> Option<String> {
    body.get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| {
            choices.iter().enumerate().find_map(|(index, choice)| {
                choice
                    .get("finish_reason")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|reason| *reason == "content_filter")
                    .map(|reason| format!("choices[{index}].finish_reason={reason}"))
            })
        })
}

fn extract_function_calls(body: &Value) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let mut calls = Vec::new();
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let tool_calls = choice
                .get("message")
                .and_then(|message| message.get("tool_calls"))
                .and_then(Value::as_array);
            if let Some(tool_calls) = tool_calls {
                for entry in tool_calls {
                    if let Some(part) = openai_tool_call_to_function_call(entry, "Mistral")? {
                        calls.push(part);
                    }
                }
            }
        }
    }
    Ok(calls)
}

/// Decode an OpenAI-compatible `tool_calls[]` entry of shape
/// `{ id, type: "function", function: { name, arguments } }` into a
/// [`FunctionCallPart`].
pub(crate) fn openai_tool_call_to_function_call(
    entry: &Value,
    provider_label: &str,
) -> Result<Option<FunctionCallPart>, ProviderError> {
    let kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("function");
    if kind != "function" {
        return Ok(None);
    }
    let function = match entry.get("function") {
        Some(function) => function,
        None => {
            return Err(ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].function was missing"
            )))
        }
    };
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].function.name was missing or non-string"
            ))
        })?
        .to_string();
    let args_value = match function.get("arguments") {
        Some(Value::String(arguments)) => {
            serde_json::from_str::<Value>(arguments).map_err(|error| {
                ProviderError::Malformed(format!(
                    "{provider_label} tool_calls[].function.arguments was not valid JSON: {error}"
                ))
            })?
        }
        Some(other) => other.clone(),
        None => Value::Object(serde_json::Map::new()),
    };
    Ok(Some(FunctionCallPart {
        name,
        args: args_value,
    }))
}
