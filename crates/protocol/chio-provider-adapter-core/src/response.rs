//! Shared response-envelope parsing primitives for provider adapters.
//!
//! Every native adapter accepts an outer transport envelope that may wrap the
//! provider payload under a `body`, `response`, or `payload` field (optionally
//! as a JSON-encoded string). [`response_body`] normalizes that envelope, and
//! [`openai_tool_call_to_function_call`] decodes a single OpenAI-compatible
//! `tool_calls[]` entry for the providers that speak the `chat/completions`
//! shape. The provider name only ever varies the error text, so it is carried
//! through a `provider_label` parameter.

use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

/// Normalize a transport envelope down to the provider response body.
///
/// If the value carries a `body`, `response`, or `payload` envelope field the
/// nested body is unwrapped (an object directly, or a JSON-encoded string that
/// parses into a value); otherwise the value is returned unchanged. A present
/// envelope field that is neither an object nor a decodable string fails closed
/// as [`ProviderError::Malformed`], labelled with `provider_label`.
pub fn response_body(value: Value, provider_label: &str) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            return nested_response_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "{provider_label} envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }
    Ok(value)
}

/// Unwrap a single envelope field value into a response body.
///
/// Objects are returned directly; JSON-encoded strings are parsed; any other
/// shape returns [`None`] so the caller can fail closed.
pub fn nested_response_body(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        Value::String(body) => serde_json::from_str(body).ok(),
        _ => None,
    }
}

/// Decode an OpenAI-compatible `tool_calls[]` entry of shape
/// `{ id, type: "function", function: { name, arguments } }` into a normalized
/// call built by `build`.
///
/// Non-function tool-call kinds are skipped (returning [`None`]). The
/// `build` constructor receives the decoded `(id, name, arguments)` so each
/// adapter can produce its own native call struct without duplicating the
/// decode logic. `provider_label` only varies the fail-closed error text.
pub fn openai_tool_call_to_function_call<T>(
    entry: &Value,
    provider_label: &str,
    build: impl FnOnce(String, String, Value) -> T,
) -> Result<Option<T>, ProviderError> {
    let kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("function");
    if kind != "function" {
        return Ok(None);
    }
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].id was missing or non-string"
            ))
        })?
        .to_string();
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
    Ok(Some(build(id, name, args_value)))
}
