//! Native Mistral response-envelope parsing for `chat/completions`.

use chio_provider_adapter_core::{openai_tool_call_to_function_call, response_body};
use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::FunctionCallPart;

pub(crate) fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!(
            "Mistral chat/completions payload was not JSON: {error}"
        ))
    })?;
    let body = response_body(value, "Mistral chat/completions")?;
    classify_content_policy(&body)?;
    extract_function_calls(&body)
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
                    if let Some(part) =
                        openai_tool_call_to_function_call(entry, "Mistral", |id, name, args| {
                            FunctionCallPart { id, name, args }
                        })?
                    {
                        calls.push(part);
                    }
                }
            }
        }
    }
    Ok(calls)
}
