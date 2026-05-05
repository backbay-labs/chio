//! Provider-native adapter that mediates Mistral `chat/completions`
//! tool-use traffic through the Chio kernel. Pinned upstream API version:
//! `2025-04` (see [`transport::MISTRAL_API_VERSION`]).
//!
//! Mistral surfaces tool calls as `tool_calls` parts inside the model's
//! `Content` payload. Tool results travel back as `functionResponse` parts
//! on the user turn. The adapter's [`lift_batch`](MistralAdapter::lift_batch)
//! lifts every `tool_calls` into a [`chio_tool_call_fabric::ToolInvocation`]
//! and [`lower_function_response`](MistralAdapter::lower_function_response)
//! lowers a kernel verdict back into a [`FunctionResponsePart`].

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

use std::sync::Arc;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ProviderRequest, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub use native::{FunctionCallPart, FunctionResponsePart};
pub use transport::{Transport, MISTRAL_API_VERSION, MISTRAL_CHAT_COMPLETIONS_HOST};

/// Configuration for the Mistral adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MistralAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`MISTRAL_API_VERSION`].
    pub api_version: String,
    /// Google Cloud project identifier (populates the AnthropicWorkspace
    /// principal slot via reuse; Mistral does not yet have its own variant
    /// in the fabric ProviderId enum's Principal taxonomy, so we reuse the
    /// generic OpenAi org slot here).
    pub project_id: String,
}

impl MistralAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`MISTRAL_API_VERSION`].
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: MISTRAL_API_VERSION.to_string(),
            project_id: project_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct MistralAdapter {
    config: MistralAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl MistralAdapter {
    /// Build a new adapter from a config and a transport handle.
    pub fn new(config: MistralAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Mistral
    }

    /// Pinned upstream API version (always [`MISTRAL_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &MistralAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Lift every Mistral `tool_calls` part in a non-streaming
    /// `chat/completions` response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let calls = function_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Mistral chat/completions payload did not contain tool_calls".to_string(),
            ));
        }
        calls
            .iter()
            .map(|call| self.invocation_from_function_call(call))
            .collect()
    }

    pub(crate) fn invocation_from_function_call(
        &self,
        call: &FunctionCallPart,
    ) -> Result<ToolInvocation, ProviderError> {
        validate_function_call(call)?;
        let arguments = canonical_json_bytes(&call.args).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Mistral functionCall args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Mistral,
            tool_name: call.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Mistral,
                request_id: format!("mistral_{}_call", call.name),
                api_version: self.config.api_version.clone(),
                principal: Principal::OpenAiOrg {
                    org_id: self.config.project_id.clone(),
                },
                received_at: SystemTime::now(),
            },
        })
    }

    /// Lower a kernel verdict and tool result into a
    /// [`FunctionResponsePart`].
    pub fn lower_function_response(
        &self,
        function_name: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<FunctionResponsePart, ProviderError> {
        let function_name = non_empty_str(function_name, "functionResponse.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let value = parse_value(&result.0)?;
                let value = apply_redactions(value, &redactions, "Mistral functionResponse")?;
                Ok(FunctionResponsePart::new(function_name, value))
            }
            VerdictResult::Deny { reason, .. } => Ok(FunctionResponsePart::new(
                function_name,
                deny_payload(&reason),
            )),
        }
    }
}

impl chio_provider_adapter_core::Provider for MistralAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum MistralAdapterError {
    /// Placeholder for call sites not yet implemented.
    #[error("mistral adapter call site is not implemented: {0}")]
    NotImplemented(&'static str),
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
}

fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!(
            "Mistral chat/completions payload was not JSON: {error}"
        ))
    })?;
    let body = response_body(value);
    extract_function_calls(&body)
}

fn response_body(value: Value) -> Value {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            if let Some(obj) = nested.as_object() {
                return Value::Object(obj.clone());
            }
        }
    }
    value
}

fn extract_function_calls(body: &Value) -> Result<Vec<FunctionCallPart>, ProviderError> {
    // Mistral is OpenAI-compatible: tool calls live at
    // `choices[].message.tool_calls[]` with shape
    // `{ id, type: "function", function: { name, arguments } }` where
    // `arguments` is a JSON-encoded string. Parse that primary shape first.
    let mut calls = Vec::new();
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let tool_calls = choice
                .get("message")
                .and_then(|m| m.get("tool_calls"))
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

    if !calls.is_empty() {
        return Ok(calls);
    }

    // Fall back to legacy Gemini-shaped fixtures for the cross-provider
    // advisory NDJSON path that pre-dates the OpenAI-compat scaffold.
    if let Some(call) = body.get("functionCall") {
        let parsed: FunctionCallPart = serde_json::from_value(call.clone()).map_err(|error| {
            ProviderError::Malformed(format!("Mistral functionCall part was malformed: {error}"))
        })?;
        return Ok(vec![parsed]);
    }
    if let Some(candidates) = body.get("candidates").and_then(Value::as_array) {
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
                                "Mistral functionCall part was malformed: {error}"
                            ))
                        })?;
                    calls.push(parsed);
                }
            }
        }
    }
    Ok(calls)
}

/// Decode an OpenAI-compatible `tool_calls[]` entry into a [`FunctionCallPart`].
/// See the Groq adapter's identical helper for the rationale; both crates
/// share this contract since Mistral and Groq use the same wire surface.
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
        Some(f) => f,
        None => return Ok(None),
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
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).map_err(|error| {
            ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].function.arguments was not valid JSON: {error}"
            ))
        })?,
        Some(other) => other.clone(),
        None => Value::Object(serde_json::Map::new()),
    };
    Ok(Some(FunctionCallPart {
        name,
        args: args_value,
    }))
}

fn validate_function_call(call: &FunctionCallPart) -> Result<(), ProviderError> {
    if call.name.trim().is_empty() {
        return Err(ProviderError::Malformed(
            "Mistral functionCall name was empty".to_string(),
        ));
    }
    if !call.args.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Mistral functionCall `{}` args were not a JSON object",
            call.name
        )));
    }
    Ok(())
}

fn parse_value(bytes: &[u8]) -> Result<Value, ProviderError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })
}

fn apply_redactions(
    mut value: Value,
    redactions: &[Redaction],
    context: &str,
) -> Result<Value, ProviderError> {
    for redaction in redactions {
        if redaction.path.is_empty() {
            value = Value::String(redaction.replacement.clone());
            continue;
        }
        if !redaction.path.starts_with('/') {
            return Err(ProviderError::Malformed(format!(
                "{context} redaction path `{}` is not a JSON Pointer",
                redaction.path
            )));
        }
        let target = value.pointer_mut(&redaction.path).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{context} redaction path `{}` did not resolve",
                redaction.path
            ))
        })?;
        *target = Value::String(redaction.replacement.clone());
    }
    Ok(value)
}

fn deny_payload(reason: &DenyReason) -> Value {
    let text = match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny: {rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny: {guard_id}: {detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    };
    json!({ "error": text })
}

fn non_empty_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ProviderError::Malformed(format!(
            "Mistral {field} must not be empty"
        )))
    } else {
        Ok(trimmed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> MistralAdapterConfig {
        MistralAdapterConfig::new(
            "mistral-1",
            "Mistral generateContent",
            "0.1.0",
            "deadbeef",
            "org_chio_demo",
        )
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, MISTRAL_API_VERSION);
        assert_eq!(cfg.api_version, "2025-04");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = MistralAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Mistral);
        assert_eq!(adapter.api_version(), "2025-04");
    }

    #[test]
    fn lift_batch_extracts_openai_tool_calls() {
        // Wire shape matches the captured Mistral fixture
        // crates/chio-provider-conformance/fixtures/mistral/mistral_basic_single_tool_call.ndjson:
        // choices[].message.tool_calls[] with `function.arguments` as a
        // JSON-encoded string.
        let cfg = config();
        let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_weather_1",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
    }

    #[test]
    fn lift_batch_legacy_gemini_shape_still_works() {
        let cfg = config();
        let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Let me check the forecast."},
                        {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                    ]
                }
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
    }

    #[test]
    fn lower_function_response_allow() {
        let cfg = config();
        let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());
        let part = adapter
            .lower_function_response("get_weather", verdict, result)
            .unwrap();
        assert_eq!(part.name, "get_weather");
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![MistralAdapterError::NotImplemented("chat/completions")];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'));
        }
    }
}
