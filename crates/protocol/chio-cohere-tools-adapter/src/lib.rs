//! Provider-native adapter that mediates Cohere `/v2/chat` tool-use traffic
//! through the Chio kernel. Pinned upstream API version: `2025-04` (see
//! [`transport::COHERE_API_VERSION`]).
//!
//! Cohere v2 surfaces tool calls as a `tool_plan` string plus a `tool_calls`
//! array on the assistant `message`. Tool results travel back as `tool` role
//! messages carrying `tool_call_id` and a content block list. The adapter's
//! [`lift_batch`](CohereAdapter::lift_batch) lifts every `tool_calls` entry
//! into a [`chio_tool_call_fabric::ToolInvocation`] and
//! [`lower_tool_message`](CohereAdapter::lower_tool_message) lowers a kernel
//! verdict back into a [`ToolResultMessage`].
//!
//! [`chat`](CohereAdapter::chat) drives the outbound request end to end: a
//! [`CohereTransport`] POSTs the native `/v2/chat` body to
//! [`COHERE_CHAT_HOST`] with `Authorization: Bearer`, buffers the response, and
//! feeds it to `lift_batch`. [`chat_stream`](CohereAdapter::chat_stream) does
//! the same for the SSE surface and gates each `tool-call-end` frame. Tests use
//! the hermetic [`MockTransport`]; no live network is required.

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

pub use native::{ToolCallBlock, ToolCallFunction, ToolResultContent, ToolResultMessage};
pub use transport::{
    CohereTransport, MockTransport, Transport, TransportError, COHERE_API_KEY_ENV,
    COHERE_API_VERSION, COHERE_CHAT_HOST, COHERE_CHAT_PATH,
};

/// Configuration for the Cohere adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohereAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`COHERE_API_VERSION`].
    pub api_version: String,
    /// Cohere organization identifier that scopes tool calls. Stamped into the
    /// [`Principal::CohereOrg`] provenance slot.
    pub org_id: String,
}

impl CohereAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`COHERE_API_VERSION`].
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
            api_version: COHERE_API_VERSION.to_string(),
            org_id: org_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct CohereAdapter {
    config: CohereAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl CohereAdapter {
    /// Build a new adapter from a config and a transport handle.
    pub fn new(config: CohereAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Cohere
    }

    /// Pinned upstream API version (always [`COHERE_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &CohereAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    pub(crate) fn ensure_supported_api_version(&self) -> Result<(), ProviderError> {
        if self.config.api_version != COHERE_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Cohere adapter supports only API version {COHERE_API_VERSION}; configured {}",
                self.config.api_version
            )));
        }
        if self.transport.api_version() != COHERE_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Cohere adapter supports only API version {COHERE_API_VERSION}; transport advertised {}",
                self.transport.api_version()
            )));
        }
        Ok(())
    }

    /// Proxy a Cohere `/v2/chat` request to the upstream endpoint and lift the
    /// tool calls from the buffered response.
    ///
    /// `request_body` is the native Cohere `/v2/chat` JSON (model, messages,
    /// tools). The transport POSTs it with the configured bearer auth, and the
    /// buffered response is fed straight into [`lift_batch`](Self::lift_batch).
    /// Transport-layer failures are mapped into the [`ProviderError`] taxonomy
    /// so a failed request never reads as an empty success.
    pub async fn chat(&self, request_body: &[u8]) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let response = self.transport.send_chat(request_body).await?;
        self.lift_batch(response)
    }

    /// Proxy a streaming Cohere `/v2/chat` request and gate the SSE response.
    ///
    /// `request_body` is the native Cohere `/v2/chat` JSON with `stream: true`.
    /// The buffered SSE body is gated frame-by-frame through `evaluate` by
    /// [`gate_sse_stream`](Self::gate_sse_stream) before any bytes are forwarded.
    pub async fn chat_stream<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let body = self.transport.send_chat_stream(request_body).await?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Lift every Cohere `tool_calls` block in a non-streaming `/v2/chat`
    /// response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let calls = tool_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Cohere /v2/chat payload did not contain tool_calls blocks".to_string(),
            ));
        }
        calls
            .iter()
            .map(|call| self.invocation_from_tool_call(call))
            .collect()
    }

    pub(crate) fn invocation_from_tool_call(
        &self,
        call: &ToolCallBlock,
    ) -> Result<ToolInvocation, ProviderError> {
        self.ensure_supported_api_version()?;
        validate_tool_call(call)?;
        let parsed_args: Value =
            serde_json::from_str(&call.function.arguments).map_err(|error| {
                ProviderError::BadToolArgs(format!(
                    "Cohere tool_call `{}` arguments did not parse as JSON: {error}",
                    call.function.name
                ))
            })?;
        if !parsed_args.is_object() {
            return Err(ProviderError::BadToolArgs(format!(
                "Cohere tool_call `{}` arguments did not parse as a JSON object",
                call.function.name
            )));
        }
        let arguments = canonical_json_bytes(&parsed_args).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Cohere tool_call args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Cohere,
            tool_name: call.function.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Cohere,
                request_id: call.id.clone(),
                api_version: self.config.api_version.clone(),
                principal: Principal::CohereOrg {
                    org_id: self.config.org_id.clone(),
                },
                received_at: SystemTime::now(),
            },
        })
    }

    /// Lower a kernel verdict and tool result into a [`ToolResultMessage`].
    pub fn lower_tool_message(
        &self,
        tool_call_id: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ToolResultMessage, ProviderError> {
        self.ensure_supported_api_version()?;
        let tool_call_id = non_empty_str(tool_call_id, "tool_call_id")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                lower_allow_tool_message(tool_call_id, result, &redactions)
            }
            VerdictResult::Deny { reason, .. } => lower_deny_tool_message(tool_call_id, &reason),
        }
    }
}

impl chio_provider_adapter_core::Provider for CohereAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum CohereAdapterError {
    /// Raised while building or running the outbound HTTP transport.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// Raised while lifting or lowering a Cohere payload through the kernel.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

fn tool_calls(raw: ProviderRequest) -> Result<Vec<ToolCallBlock>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("Cohere /v2/chat payload was not JSON: {error}"))
    })?;
    let body = chio_provider_adapter_core::response_body(value, "Cohere /v2/chat")?;
    extract_tool_calls(&body)
}

fn extract_tool_calls(body: &Value) -> Result<Vec<ToolCallBlock>, ProviderError> {
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
        let parsed: ToolCallBlock = serde_json::from_value(entry.clone()).map_err(|error| {
            ProviderError::Malformed(format!("Cohere tool_call block was malformed: {error}"))
        })?;
        calls.push(parsed);
    }
    Ok(calls)
}

fn validate_tool_call(call: &ToolCallBlock) -> Result<(), ProviderError> {
    non_empty_str(&call.id, "tool_call id")?;
    if call.kind != "function" {
        return Err(ProviderError::Malformed(format!(
            "Cohere tool_call kind `{}` is not supported on the v2 surface",
            call.kind
        )));
    }
    non_empty_str(&call.function.name, "tool_call.function.name")?;
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

fn lower_allow_tool_message(
    tool_call_id: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<ToolResultMessage, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Cohere tool_result")?;
    let text = canonical_tool_result_text(&value)?;
    Ok(ToolResultMessage::new(tool_call_id, text))
}

fn lower_deny_tool_message(
    tool_call_id: &str,
    reason: &DenyReason,
) -> Result<ToolResultMessage, ProviderError> {
    let payload = deny_payload(reason);
    let text = serde_json::to_string(&payload).map_err(|error| {
        ProviderError::Malformed(format!("Cohere deny payload encoding failed: {error}"))
    })?;
    Ok(ToolResultMessage::new(tool_call_id, text))
}

fn canonical_tool_result_text(value: &Value) -> Result<String, ProviderError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        ProviderError::Malformed(format!(
            "Cohere tool_result canonical encoding failed: {error}"
        ))
    })?;
    String::from_utf8(canonical).map_err(|error| {
        ProviderError::Malformed(format!(
            "Cohere tool_result canonical bytes were not UTF-8: {error}"
        ))
    })
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
        return Err(ProviderError::Malformed(format!(
            "Cohere {field} must not be empty"
        )));
    }
    if trimmed != value {
        return Err(ProviderError::Malformed(format!(
            "Cohere {field} must not contain surrounding whitespace"
        )));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use serde_json::json;

    struct DriftedTransport {
        called: Arc<AtomicBool>,
    }

    impl DriftedTransport {
        fn new(called: Arc<AtomicBool>) -> Self {
            Self { called }
        }
    }

    #[async_trait::async_trait]
    impl transport::Transport for DriftedTransport {
        fn api_version(&self) -> &str {
            "2024-12"
        }

        async fn send_chat(&self, _body: &[u8]) -> Result<ProviderRequest, ProviderError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(raw_payload(tool_call_payload()))
        }

        async fn send_chat_stream(&self, _body: &[u8]) -> Result<Vec<u8>, ProviderError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(b"event: tool-call-end\ndata: {\"tool_call\":{\"id\":\"call_api_pin\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}}\n\n".to_vec())
        }
    }

    fn config() -> CohereAdapterConfig {
        CohereAdapterConfig::new(
            "cohere-1",
            "Cohere v2 chat",
            "0.1.0",
            "deadbeef",
            "org_chio_demo",
        )
    }

    fn config_with_api_version(api_version: &str) -> CohereAdapterConfig {
        let mut cfg = config();
        cfg.api_version = api_version.to_string();
        cfg
    }

    fn tool_call_payload() -> Value {
        json!({
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_api_pin",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }
                ]
            }
        })
    }

    fn raw_payload(value: Value) -> ProviderRequest {
        ProviderRequest(serde_json::to_vec(&value).unwrap())
    }

    fn assert_api_version_drift(error: ProviderError) {
        match error {
            ProviderError::Malformed(message) => {
                assert!(message.contains("Cohere adapter supports only API version 2025-04"));
                assert!(message.contains("2024-12"));
            }
            other => panic!("expected Malformed API version drift, got {other:?}"),
        }
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, COHERE_API_VERSION);
        assert_eq!(cfg.api_version, "2025-04");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = CohereAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Cohere);
        assert_eq!(adapter.api_version(), "2025-04");
    }

    #[tokio::test]
    async fn chat_rejects_api_version_drift_before_transport_call() {
        let cfg = config_with_api_version("2024-12");
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_chat_response(serde_json::to_vec(&tool_call_payload()).unwrap());
        let adapter = CohereAdapter::new(cfg, mock.clone());

        let err = adapter
            .chat(b"{\"model\":\"command-r\",\"messages\":[],\"tools\":[]}")
            .await
            .expect_err("drifted Cohere API version must fail before transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn chat_stream_rejects_api_version_drift_before_transport_call() {
        let cfg = config_with_api_version("2024-12");
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_response(chio_provider_adapter_core::http::HttpResponse::new(
            200,
            b"event: tool-call-end\ndata: {\"tool_call\":{\"id\":\"call_api_pin\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}}\n\n".to_vec(),
            Some("text/event-stream".to_string()),
        ));
        let adapter = CohereAdapter::new(cfg, mock.clone());

        let err = adapter
            .chat_stream(b"{\"stream\":true}", |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".to_string()),
                })
            })
            .await
            .expect_err("drifted Cohere API version must fail before stream transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn chat_rejects_transport_api_version_drift_before_send() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(DriftedTransport::new(called.clone()));
        let adapter = CohereAdapter::new(config(), transport);

        let err = adapter
            .chat(b"{\"model\":\"command-r\",\"messages\":[],\"tools\":[]}")
            .await
            .expect_err("drifted Cohere transport API version must fail before send");

        assert_api_version_drift(err);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn chat_stream_rejects_transport_api_version_drift_before_send() {
        let called = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(DriftedTransport::new(called.clone()));
        let adapter = CohereAdapter::new(config(), transport);

        let err = adapter
            .chat_stream(b"{\"stream\":true}", |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".to_string()),
                })
            })
            .await
            .expect_err("drifted Cohere transport API version must fail before stream send");

        assert_api_version_drift(err);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
        let cfg = config_with_api_version("2024-12");
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));

        let err = adapter
            .lift_batch(raw_payload(tool_call_payload()))
            .expect_err("drifted Cohere API version must fail before provenance stamping");

        assert_api_version_drift(err);
    }

    #[test]
    fn lower_tool_message_rejects_api_version_drift() {
        let cfg = config_with_api_version("2024-12");
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".to_string()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());

        let err = adapter
            .lower_tool_message("call_api_pin", verdict, result)
            .expect_err("drifted Cohere API version must fail before lowering");

        assert_api_version_drift(err);
    }

    #[test]
    fn lift_batch_extracts_tool_calls() {
        let cfg = config();
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "message": {
                "role": "assistant",
                "tool_plan": "I will look up the weather",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }
                ]
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        assert_eq!(invocations[0].provider, ProviderId::Cohere);
        assert_eq!(invocations[0].provenance.request_id, "call_1");
    }

    #[test]
    fn lift_batch_rejects_malformed_envelope_before_outer_tool_calls() {
        let cfg = config();
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "body": 42,
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_outer",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }
                ]
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter.lift_batch(raw).unwrap_err();

        assert!(err.to_string().contains("envelope field `body`"));
    }

    #[test]
    fn lift_batch_rejects_tool_call_name_with_surrounding_whitespace() {
        let cfg = config();
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_padded_name",
                        "type": "function",
                        "function": {
                            "name": " get_weather ",
                            "arguments": "{}"
                        }
                    }
                ]
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("whitespace-padded tool name must fail closed");

        assert!(err
            .to_string()
            .contains("tool_call.function.name must not contain surrounding whitespace"));
    }

    #[test]
    fn lift_batch_rejects_payload_without_tool_calls() {
        let cfg = config();
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
        let adapter = CohereAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());
        let msg = adapter
            .lower_tool_message("call_1", verdict, result)
            .unwrap();
        assert_eq!(msg.role, "tool");
        assert_eq!(msg.tool_call_id, "call_1");
        assert_eq!(msg.content.len(), 1);
        assert!(msg.content[0].text.contains("\"temp\""));
    }

    #[test]
    fn lower_allow_tool_message_helper_applies_redactions_and_canonicalizes() {
        let message = lower_allow_tool_message(
            "call_1",
            ToolResult(br#"{"z":1,"token":"secret"}"#.to_vec()),
            &[Redaction {
                path: "/token".to_string(),
                replacement: "[redacted]".to_string(),
            }],
        )
        .unwrap();

        assert_eq!(message.role, "tool");
        assert_eq!(message.tool_call_id, "call_1");
        assert_eq!(
            message.content[0].text,
            "{\"token\":\"[redacted]\",\"z\":1}"
        );
    }

    #[tokio::test]
    async fn chat_proxies_request_and_lifts_tool_calls() {
        let cfg = config();
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_chat_response(
            serde_json::to_vec(&json!({
                "message": {
                    "role": "assistant",
                    "tool_plan": "I will look up the weather",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"city\":\"Paris\"}"
                            }
                        }
                    ]
                }
            }))
            .unwrap(),
        );
        let adapter = CohereAdapter::new(cfg, mock.clone());
        let request = b"{\"model\":\"command-r\",\"messages\":[],\"tools\":[]}";
        let invocations = adapter.chat(request).await.unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, transport::COHERE_CHAT_PATH);
        assert_eq!(calls[0].1, request);
    }

    #[tokio::test]
    async fn chat_propagates_upstream_status_error() {
        let cfg = config();
        let mock = transport::MockTransport::new();
        mock.push_error(
            chio_provider_adapter_core::http::HttpTransportError::Status {
                code: 503,
                body: "service unavailable".to_string(),
            },
        );
        let adapter = CohereAdapter::new(cfg, Arc::new(mock));
        let err = adapter.chat(b"{}").await.unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Upstream5xx { status: 503, .. }
        ));
    }
}
