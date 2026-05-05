//! Provider-native adapter that mediates Ollama `/api/chat` tool-use traffic
//! through the Chio kernel. Pinned upstream API version: `2025-04` (see
//! [`transport::OLLAMA_API_VERSION`]).
//!
//! Ollama surfaces tool calls as `tool_calls` entries on the assistant
//! `message` (mirroring the OpenAI `chat/completions` shape). Tool results
//! travel back as `tool` role messages on the next user turn. The adapter's
//! [`lift_batch`](OllamaAdapter::lift_batch) lifts every `tool_calls` entry
//! into a [`chio_tool_call_fabric::ToolInvocation`] and
//! [`lower_tool_message`](OllamaAdapter::lower_tool_message) lowers a kernel
//! verdict back into a [`ToolResultMessage`].

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

pub use native::{ToolCallFunction, ToolCallPart, ToolResultMessage};
pub use transport::{Transport, OLLAMA_API_VERSION, OLLAMA_CHAT_HOST};

/// Configuration for the Ollama adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OllamaAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`OLLAMA_API_VERSION`].
    pub api_version: String,
    /// Local-trust-edge org identifier. Ollama is a localhost daemon and has
    /// no upstream IAM principal; the adapter reuses the `OpenAiOrg` slot in
    /// the fabric `Principal` taxonomy with a `local_*` prefix so receipts
    /// remain provenance-stable.
    pub org_id: String,
}

impl OllamaAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`OLLAMA_API_VERSION`].
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        org_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: OLLAMA_API_VERSION.to_string(),
            org_id: org_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct OllamaAdapter {
    config: OllamaAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl OllamaAdapter {
    /// Build a new adapter from a config and a transport handle.
    pub fn new(config: OllamaAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Ollama
    }

    /// Pinned upstream API version (always [`OLLAMA_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &OllamaAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Lift every Ollama `tool_calls` entry in a non-streaming `/api/chat`
    /// response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let calls = tool_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Ollama /api/chat payload did not contain tool_calls entries".to_string(),
            ));
        }
        calls
            .iter()
            .enumerate()
            .map(|(index, call)| self.invocation_from_tool_call(index, call))
            .collect()
    }

    pub(crate) fn invocation_from_tool_call(
        &self,
        index: usize,
        call: &ToolCallPart,
    ) -> Result<ToolInvocation, ProviderError> {
        validate_tool_call(call)?;
        let arguments = canonical_json_bytes(&call.function.arguments).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Ollama tool_call args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Ollama,
            tool_name: call.function.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Ollama,
                request_id: synthesised_request_id(&call.function.name, index),
                api_version: self.config.api_version.clone(),
                principal: Principal::OpenAiOrg {
                    org_id: self.config.org_id.clone(),
                },
                received_at: SystemTime::now(),
            },
        })
    }

    /// Lower a kernel verdict and tool result into a [`ToolResultMessage`].
    pub fn lower_tool_message(
        &self,
        tool_name: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ToolResultMessage, ProviderError> {
        let tool_name = non_empty_str(tool_name, "tool_call.function.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let value = parse_value(&result.0)?;
                let value = apply_redactions(value, &redactions, "Ollama tool_result")?;
                let content = canonical_json_bytes(&value).map_err(|error| {
                    ProviderError::Malformed(format!(
                        "Ollama tool_result canonical encoding failed: {error}"
                    ))
                })?;
                let content = String::from_utf8(content).map_err(|error| {
                    ProviderError::Malformed(format!(
                        "Ollama tool_result canonical bytes were not UTF-8: {error}"
                    ))
                })?;
                Ok(ToolResultMessage::new(tool_name, content))
            }
            VerdictResult::Deny { reason, .. } => {
                let payload = deny_payload(&reason);
                let content = serde_json::to_string(&payload).map_err(|error| {
                    ProviderError::Malformed(format!(
                        "Ollama deny payload encoding failed: {error}"
                    ))
                })?;
                Ok(ToolResultMessage::new(tool_name, content))
            }
        }
    }
}

impl chio_provider_adapter_core::Provider for OllamaAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum OllamaAdapterError {
    /// Placeholder for call sites not yet implemented.
    #[error("ollama adapter call site is not implemented: {0}")]
    NotImplemented(&'static str),
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
}

fn tool_calls(raw: ProviderRequest) -> Result<Vec<ToolCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("Ollama /api/chat payload was not JSON: {error}"))
    })?;
    let body = response_body(value);
    extract_tool_calls(&body)
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
        let parsed: ToolCallPart = serde_json::from_value(entry.clone()).map_err(|error| {
            ProviderError::Malformed(format!("Ollama tool_call entry was malformed: {error}"))
        })?;
        calls.push(parsed);
    }
    Ok(calls)
}

fn validate_tool_call(call: &ToolCallPart) -> Result<(), ProviderError> {
    if call.function.name.trim().is_empty() {
        return Err(ProviderError::Malformed(
            "Ollama tool_call.function.name was empty".to_string(),
        ));
    }
    if !call.function.arguments.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Ollama tool_call `{}` arguments were not a JSON object",
            call.function.name
        )));
    }
    Ok(())
}

fn synthesised_request_id(name: &str, index: usize) -> String {
    format!("ollama_{name}_call_{index}")
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
            "Ollama {field} must not be empty"
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

    fn config() -> OllamaAdapterConfig {
        OllamaAdapterConfig::new(
            "ollama-1",
            "Ollama Chat",
            "0.1.0",
            "deadbeef",
            "local_chio_demo",
        )
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, OLLAMA_API_VERSION);
        assert_eq!(cfg.api_version, "2025-04");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = OllamaAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Ollama);
        assert_eq!(adapter.api_version(), "2025-04");
    }

    #[test]
    fn lift_batch_extracts_tool_calls() {
        let cfg = config();
        let adapter = OllamaAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}
                ]
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        assert_eq!(invocations[0].provider, ProviderId::Ollama);
    }

    #[test]
    fn lift_batch_rejects_payload_without_tool_calls() {
        let cfg = config();
        let adapter = OllamaAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({"message": {"role": "assistant", "content": "no tools"}});
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter.lift_batch(raw).unwrap_err();
        match err {
            ProviderError::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn lower_tool_message_allow() {
        let cfg = config();
        let adapter = OllamaAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());
        let msg = adapter
            .lower_tool_message("get_weather", verdict, result)
            .unwrap();
        assert_eq!(msg.role, "tool");
        assert_eq!(msg.name, "get_weather");
        assert!(msg.content.contains("\"temp\""));
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![OllamaAdapterError::NotImplemented("/api/chat")];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'));
        }
    }
}
