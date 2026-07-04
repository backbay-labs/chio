//! Gemini `generateContent` response-envelope parsing.

use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::FunctionCallPart;

pub(crate) fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!(
            "Gemini generateContent payload was not JSON: {error}"
        ))
    })?;
    let body = chio_provider_adapter_core::response_body(value, "Gemini generateContent")?;
    classify_content_policy(&body)?;
    extract_function_calls(&body)
}

fn classify_content_policy(body: &Value) -> Result<(), ProviderError> {
    let Some(block_reason) = gemini_safety_block_reason(body) else {
        return Ok(());
    };

    Err(ProviderError::ContentPolicy(format!(
        "Gemini safety block: {block_reason}"
    )))
}

fn gemini_safety_block_reason(body: &Value) -> Option<String> {
    if let Some(block_reason) = body
        .get("promptFeedback")
        .and_then(|feedback| feedback.get("blockReason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
    {
        return Some(format!("promptFeedback.blockReason={block_reason}"));
    };

    body.get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| {
            candidates
                .iter()
                .enumerate()
                .find_map(|(index, candidate)| {
                    candidate
                        .get("finishReason")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|reason| *reason == "SAFETY")
                        .map(|reason| format!("candidates[{index}].finishReason={reason}"))
                })
        })
}

fn extract_function_calls(body: &Value) -> Result<Vec<FunctionCallPart>, ProviderError> {
    if let Some(call) = body.get("functionCall") {
        let parsed: FunctionCallPart = serde_json::from_value(call.clone()).map_err(|error| {
            ProviderError::Malformed(format!("Gemini functionCall part was malformed: {error}"))
        })?;
        return Ok(vec![parsed]);
    }
    let candidates = body.get("candidates").and_then(Value::as_array);
    let mut calls = Vec::new();
    if let Some(candidates) = candidates {
        for candidate in candidates {
            let Some(parts) = candidate
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for part in parts {
                if let Some(call) = part.get("functionCall") {
                    let parsed: FunctionCallPart =
                        serde_json::from_value(call.clone()).map_err(|error| {
                            ProviderError::Malformed(format!(
                                "Gemini functionCall part was malformed: {error}"
                            ))
                        })?;
                    calls.push(parsed);
                }
            }
        }
    }
    Ok(calls)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_string_wrapped_body() {
        let payload = json!({
            "body": "{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Paris\"}}}"
        });
        let calls = function_calls(ProviderRequest(serde_json::to_vec(&payload).unwrap())).unwrap();

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
    }

    #[test]
    fn rejects_non_object_envelope_body() {
        let payload = json!({
            "body": 42,
            "functionCall": {"name": "get_weather", "args": {"city": "Paris"}}
        });
        let err = function_calls(ProviderRequest(serde_json::to_vec(&payload).unwrap()))
            .expect_err("invalid envelope body must fail closed");

        assert!(err.to_string().contains("envelope field `body`"));
    }

    #[test]
    fn maps_prompt_feedback_block_reason_to_content_policy() {
        let payload = json!({
            "promptFeedback": {
                "blockReason": "SAFETY"
            }
        });
        let err = function_calls(ProviderRequest(serde_json::to_vec(&payload).unwrap()))
            .expect_err("safety block must fail closed");

        assert!(matches!(err, ProviderError::ContentPolicy(_)));
        assert!(err.to_string().contains("SAFETY"));
    }
}
