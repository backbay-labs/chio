//! Provider-native adapter that mediates Ollama `/api/chat` tool-use traffic
//! through the Chio kernel. Pinned upstream API version: `2025-04` (see
//! [`transport::OLLAMA_API_VERSION`]).
//!
//! Ollama runs as a local HTTP daemon (default `http://localhost:11434`) and
//! surfaces tool calls as `tool_calls` entries on the assistant `message`
//! (mirroring the OpenAI `chat/completions` shape). Tool results travel back as
//! `tool` role messages on the next user turn.
//!
//! The adapter forwards a native `/api/chat` request to the daemon through the
//! shared [`chio_provider_adapter_core::http`] transport, then:
//!
//! - [`chat`](OllamaAdapter::chat) posts a non-streaming request and lifts every
//!   `tool_calls` entry into a [`chio_tool_call_fabric::ToolInvocation`];
//! - [`chat_stream`](OllamaAdapter::chat_stream) posts a streaming request and
//!   gates the NDJSON tool-call frames behind a kernel verdict;
//! - [`lift_batch`](OllamaAdapter::lift_batch) lifts tool calls from bytes that
//!   were captured out of band;
//! - [`lower_tool_message`](OllamaAdapter::lower_tool_message) lowers a kernel
//!   verdict back into a [`ToolResultMessage`].

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

use std::sync::Arc;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_provider_adapter_core::http::{map_http_status, map_transport_error};
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ProviderRequest, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::streaming::GatedNdjsonStream;
use crate::transport::OLLAMA_CHAT_PATH;

pub use native::{ToolCallFunction, ToolCallPart, ToolResultMessage};
pub use transport::{Transport, OLLAMA_API_VERSION, OLLAMA_CHAT_HOST};

/// Provider label used when classifying upstream transport failures.
const PROVIDER_LABEL: &str = "Ollama";

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
    /// Ollama host or instance label. Ollama is a local daemon with no upstream
    /// identity provider, so the host is the stable provenance handle stamped
    /// into the [`Principal::OllamaHost`] slot.
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

    /// Post a non-streaming `/api/chat` request to the Ollama daemon and lift
    /// every `tool_calls` entry from the response.
    ///
    /// `request_body` is the raw native request JSON (model, messages, tools,
    /// and `stream: false`). The response body is buffered and run through
    /// [`lift_batch`](OllamaAdapter::lift_batch). Transport-layer failures are
    /// classified into the fabric [`ProviderError`] taxonomy and fail closed.
    pub async fn chat(&self, request_body: &[u8]) -> Result<Vec<ToolInvocation>, ProviderError> {
        let response = self
            .transport
            .post_json(OLLAMA_CHAT_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        if let Some(error) = map_http_status(PROVIDER_LABEL, response.status, &response.body) {
            return Err(error);
        }
        self.lift_batch(ProviderRequest(response.body))
    }

    /// Post a streaming `/api/chat` request and gate its NDJSON tool-call frames.
    ///
    /// Ollama streams `/api/chat` as newline-delimited JSON. The buffered body
    /// is run through [`gate_sse_stream`](OllamaAdapter::gate_sse_stream): each
    /// `tool_calls` entry is evaluated by `evaluate` before its enclosing line
    /// is admitted to the forwarded byte stream.
    pub async fn chat_stream<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<GatedNdjsonStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let body = self
            .transport
            .post_ndjson(OLLAMA_CHAT_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        self.gate_sse_stream(&body, evaluate)
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
                principal: Principal::OllamaHost {
                    host: self.config.org_id.clone(),
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
    /// A lift/lower or payload-shape failure surfaced by the fabric.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// An outbound `/api/chat` call failed at the transport layer.
    #[error(transparent)]
    Transport(#[from] chio_provider_adapter_core::http::HttpTransportError),
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

    fn mock() -> Arc<transport::MockTransport> {
        Arc::new(transport::MockTransport::new("mock://ollama"))
    }

    fn adapter() -> OllamaAdapter {
        OllamaAdapter::new(config(), mock())
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, OLLAMA_API_VERSION);
        assert_eq!(cfg.api_version, "2025-04");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let adapter = adapter();
        assert_eq!(adapter.provider(), ProviderId::Ollama);
        assert_eq!(adapter.api_version(), "2025-04");
    }

    #[tokio::test]
    async fn chat_posts_to_api_chat_and_lifts_tool_calls() {
        let response = json!({
            "model": "llama3.2:1b",
            "done": true,
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}
                ]
            }
        });
        let mock = mock();
        mock.push_json_response(serde_json::to_vec(&response).unwrap());
        let adapter = OllamaAdapter::new(config(), mock.clone());

        let request = serde_json::to_vec(&json!({
            "model": "llama3.2:1b",
            "stream": false,
            "messages": [{"role": "user", "content": "weather in Paris?"}]
        }))
        .unwrap();
        let invocations = adapter.chat(&request).await.unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        assert_eq!(invocations[0].provider, ProviderId::Ollama);

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, transport::OLLAMA_CHAT_PATH);
        assert_eq!(calls[0].body, request);
    }

    #[tokio::test]
    async fn chat_maps_upstream_5xx_to_provider_error() {
        let mock = mock();
        mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
            503,
            b"model not loaded".to_vec(),
            Some("application/json".to_string()),
        ));
        let adapter = OllamaAdapter::new(config(), mock);
        let error = adapter.chat(b"{}").await.unwrap_err();
        assert!(matches!(
            error,
            ProviderError::Upstream5xx { status: 503, .. }
        ));
    }

    #[tokio::test]
    async fn chat_stream_gates_ndjson_tool_calls() {
        let ndjson = concat!(
            "{\"model\":\"llama3.2:1b\",\"message\":{\"role\":\"assistant\",\"content\":\"\"}}\n",
            "{\"model\":\"llama3.2:1b\",\"done\":true,\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"get_weather\",\"arguments\":{\"city\":\"Paris\"}}}]}}\n"
        );
        let mock = mock();
        mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
            200,
            ndjson.as_bytes().to_vec(),
            Some("application/x-ndjson".to_string()),
        ));
        let adapter = OllamaAdapter::new(config(), mock.clone());

        let gated = adapter
            .chat_stream(b"{\"stream\":true}", |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
                })
            })
            .await
            .unwrap();
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.verdicts.len(), 1);
        assert_eq!(
            mock.calls()[0].kind,
            chio_provider_adapter_core::http::CallKind::Ndjson
        );
    }

    #[test]
    fn lift_batch_extracts_tool_calls() {
        let adapter = adapter();
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
        let adapter = adapter();
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
        let adapter = adapter();
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
        let cases = vec![
            OllamaAdapterError::Provider(ProviderError::Malformed(
                "Ollama /api/chat payload was not JSON".to_string(),
            )),
            OllamaAdapterError::Transport(
                chio_provider_adapter_core::http::HttpTransportError::MockExhausted {
                    path: OLLAMA_CHAT_PATH.to_string(),
                },
            ),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
