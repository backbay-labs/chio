//! Provider-native adapter that mediates Groq `chat/completions`
//! tool-use traffic through the Chio kernel. Pinned upstream API version:
//! `2025-04` (see [`transport::GROQ_API_VERSION`]).
//!
//! Groq exposes an OpenAI-compatible chat/completions API, so the model
//! surfaces tool calls as `choices[].message.tool_calls[]` entries
//! (`{ id, type: "function", function: { name, arguments } }`, where
//! `arguments` is a JSON-encoded string). Tool results travel back as a
//! `tool` role message carrying the matching `tool_call_id`.
//!
//! The adapter is a mediation gateway: [`send_chat_completion`] forwards a
//! native request body to the upstream endpoint over the shared HTTP
//! transport, then [`lift_batch`](GroqAdapter::lift_batch) lifts every
//! `tool_calls` entry into a [`chio_tool_call_fabric::ToolInvocation`].
//! [`lower_function_response`](GroqAdapter::lower_function_response) lowers a
//! kernel verdict back into the tool-result payload returned on the next turn.
//!
//! [`send_chat_completion`]: GroqAdapter::send_chat_completion

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

mod response;

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
pub use transport::{
    groq_transport, groq_transport_from_env, AuthScheme, HttpTransport, MockTransport, Transport,
    GROQ_API_VERSION, GROQ_CHAT_COMPLETIONS_HOST, GROQ_CHAT_COMPLETIONS_PATH,
};

use chio_provider_adapter_core::http::map_transport_error;

/// Provider label used in transport-failure messages.
const PROVIDER_LABEL: &str = "Groq";

/// Configuration for the Groq adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroqAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`GROQ_API_VERSION`].
    pub api_version: String,
    /// Groq project identifier that scopes tool calls on Groq's
    /// OpenAI-compatible API. Stamped into the [`Principal::GroqProject`]
    /// provenance slot.
    pub project_id: String,
}

impl GroqAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`GROQ_API_VERSION`].
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
            api_version: GROQ_API_VERSION.to_string(),
            project_id: project_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct GroqAdapter {
    config: GroqAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl GroqAdapter {
    /// Build a new adapter from a config and an outbound transport handle.
    ///
    /// In production pass an [`HttpTransport`] built via [`groq_transport`]; in
    /// tests pass a [`MockTransport`].
    pub fn new(config: GroqAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Groq
    }

    /// Pinned upstream API version (always [`GROQ_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &GroqAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    pub(crate) fn ensure_supported_api_version(&self) -> Result<(), ProviderError> {
        if self.config.api_version != GROQ_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Groq adapter supports only API version {GROQ_API_VERSION}; configured {}",
                self.config.api_version
            )));
        }
        Ok(())
    }

    /// Forward a native chat/completions request to the upstream Groq endpoint
    /// and lift the tool calls in the response.
    ///
    /// `request_body` is the OpenAI-compatible chat/completions JSON body
    /// (`{ model, messages, tools, .. }`). The body is POSTed to
    /// [`GROQ_CHAT_COMPLETIONS_PATH`] over the configured transport with Bearer
    /// auth; a non-2xx status, timeout, or transport failure is mapped into the
    /// fabric [`ProviderError`] taxonomy and fails closed. On success the
    /// response body is handed to [`lift_batch`](Self::lift_batch).
    pub async fn send_chat_completion(
        &self,
        request_body: &[u8],
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        validate_chat_request_body(request_body)?;
        let response = self.post_chat_completion(request_body).await?;
        self.lift_batch(ProviderRequest(response.body))
    }

    /// Forward a streaming chat/completions request and gate the SSE response.
    ///
    /// The request is POSTed to [`GROQ_CHAT_COMPLETIONS_PATH`]; the buffered
    /// `text/event-stream` body is then run through
    /// [`gate_sse_stream`](Self::gate_sse_stream) with the supplied evaluator so
    /// every buffered tool call is gated before any bytes are released.
    pub async fn send_chat_completion_stream<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        validate_chat_request_body(request_body)?;
        let body = self
            .transport
            .post_sse(GROQ_CHAT_COMPLETIONS_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Perform the raw upstream POST and return the buffered response, mapping
    /// any transport failure into the fabric error taxonomy.
    async fn post_chat_completion(
        &self,
        request_body: &[u8],
    ) -> Result<transport::HttpResponse, ProviderError> {
        self.ensure_supported_api_version()?;
        self.transport
            .post_json(GROQ_CHAT_COMPLETIONS_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))
    }

    /// Lift every Groq `tool_calls` part in a non-streaming
    /// `chat/completions` response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let calls = response::function_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Groq chat/completions payload did not contain tool_calls".to_string(),
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
        self.ensure_supported_api_version()?;
        validate_function_call(call)?;
        let arguments = canonical_json_bytes(&call.args).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Groq functionCall args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Groq,
            tool_name: call.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Groq,
                request_id: format!("groq_{}_call", call.name),
                api_version: self.config.api_version.clone(),
                principal: Principal::GroqProject {
                    project_id: self.config.project_id.clone(),
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
        self.ensure_supported_api_version()?;
        let function_name = non_empty_str(function_name, "functionResponse.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                lower_allow_function_response(function_name, result, &redactions)
            }
            VerdictResult::Deny { reason, .. } => {
                lower_deny_function_response(function_name, &reason)
            }
        }
    }
}

impl chio_provider_adapter_core::Provider for GroqAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum GroqAdapterError {
    /// Bubbled up from the shared HTTP transport layer.
    #[error(transparent)]
    Transport(#[from] transport::HttpTransportError),
    /// The upstream response could not be lifted into the canonical fabric
    /// types.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

fn validate_function_call(call: &FunctionCallPart) -> Result<(), ProviderError> {
    non_empty_str(&call.name, "functionCall name")?;
    if !call.args.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Groq functionCall `{}` args were not a JSON object",
            call.name
        )));
    }
    Ok(())
}

fn validate_chat_request_body(request_body: &[u8]) -> Result<(), ProviderError> {
    let value: Value = serde_json::from_slice(request_body).map_err(|error| {
        ProviderError::Malformed(format!(
            "Groq chat/completions request body was not JSON: {error}"
        ))
    })?;
    let request = value.as_object().ok_or_else(|| {
        ProviderError::BadToolArgs(
            "Groq chat/completions request body must be a JSON object".to_string(),
        )
    })?;
    let model = request
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::BadToolArgs(
                "Groq chat/completions request model must be a string".to_string(),
            )
        })?;
    non_empty_str(model, "chat/completions request model")?;
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::BadToolArgs(
                "Groq chat/completions request messages must be an array".to_string(),
            )
        })?;
    if messages.is_empty() {
        return Err(ProviderError::BadToolArgs(
            "Groq chat/completions request must include at least one message".to_string(),
        ));
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

fn lower_allow_function_response(
    function_name: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<FunctionResponsePart, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Groq functionResponse")?;
    Ok(FunctionResponsePart::new(function_name, value))
}

fn lower_deny_function_response(
    function_name: &str,
    reason: &DenyReason,
) -> Result<FunctionResponsePart, ProviderError> {
    Ok(FunctionResponsePart::new(
        function_name,
        deny_payload(reason),
    ))
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
            "Groq {field} must not be empty"
        )));
    }
    if trimmed != value {
        return Err(ProviderError::Malformed(format!(
            "Groq {field} must not contain surrounding whitespace"
        )));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> GroqAdapterConfig {
        GroqAdapterConfig::new(
            "groq-1",
            "Groq generateContent",
            "0.1.0",
            "deadbeef",
            "org_chio_demo",
        )
    }

    fn config_with_api_version(api_version: &str) -> GroqAdapterConfig {
        let mut cfg = config();
        cfg.api_version = api_version.to_string();
        cfg
    }

    fn tool_call_payload() -> Value {
        json!({
            "id": "chatcmpl_api_pin",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_api_pin",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        })
    }

    fn tool_call_stream() -> Vec<u8> {
        let chunk = json!({
            "id": "chatcmpl_api_pin_stream",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "id": "call_api_pin_stream",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }]
                }
            }]
        });
        let mut sse = Vec::new();
        sse.extend_from_slice(b"data: ");
        sse.extend_from_slice(&serde_json::to_vec(&chunk).unwrap());
        sse.extend_from_slice(b"\n\n");
        sse
    }

    fn raw_payload(value: Value) -> ProviderRequest {
        ProviderRequest(serde_json::to_vec(&value).unwrap())
    }

    fn assert_api_version_drift(error: ProviderError) {
        match error {
            ProviderError::Malformed(message) => {
                assert!(message.contains("Groq adapter supports only API version 2025-04"));
                assert!(message.contains("configured 2024-12"));
            }
            other => panic!("expected Malformed API version drift, got {other:?}"),
        }
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, GROQ_API_VERSION);
        assert_eq!(cfg.api_version, "2025-04");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Groq);
        assert_eq!(adapter.api_version(), "2025-04");
    }

    #[tokio::test]
    async fn send_chat_completion_rejects_api_version_drift_before_transport_call() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_json_response(serde_json::to_vec(&tool_call_payload()).unwrap());
        let adapter = GroqAdapter::new(config_with_api_version("2024-12"), mock.clone());

        let err = adapter
            .send_chat_completion(&chat_request_body())
            .await
            .expect_err("drifted Groq API version must fail before transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn send_chat_completion_rejects_invalid_request_body_before_transport_call() {
        let cases = [
            (
                "not-json",
                b"not-json".to_vec(),
                "Groq chat/completions request body was not JSON",
            ),
            (
                "not-object",
                b"[]".to_vec(),
                "Groq chat/completions request body must be a JSON object",
            ),
            (
                "padded-model",
                br#"{"model":" llama-3.3-70b-versatile ","messages":[{"role":"user","content":"hello"}]}"#
                    .to_vec(),
                "Groq chat/completions request model must not contain surrounding whitespace",
            ),
            (
                "empty-messages",
                br#"{"model":"llama-3.3-70b-versatile","messages":[]}"#.to_vec(),
                "Groq chat/completions request must include at least one message",
            ),
        ];

        for (name, request, expected) in cases {
            let mock = Arc::new(transport::MockTransport::new());
            mock.push_json_response(tool_call_response());
            let adapter = GroqAdapter::new(config(), mock.clone());

            let err = adapter
                .send_chat_completion(&request)
                .await
                .expect_err("invalid Groq request must fail before transport");

            assert!(
                err.to_string().contains(expected),
                "{name} error `{err}` did not contain `{expected}`"
            );
            assert!(mock.calls().is_empty(), "{name} reached transport");
        }
    }

    #[tokio::test]
    async fn send_chat_completion_stream_rejects_api_version_drift_before_transport_call() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_response(transport::HttpResponse::new(
            200,
            tool_call_stream(),
            Some("text/event-stream".to_string()),
        ));
        let adapter = GroqAdapter::new(config_with_api_version("2024-12"), mock.clone());

        let err = adapter
            .send_chat_completion_stream(&chat_request_body(), |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
                })
            })
            .await
            .expect_err("drifted Groq API version must fail before stream transport");

        assert_api_version_drift(err);
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn send_chat_completion_stream_rejects_invalid_request_body_before_transport_call() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_response(transport::HttpResponse::new(
            200,
            tool_call_stream(),
            Some("text/event-stream".to_string()),
        ));
        let adapter = GroqAdapter::new(config(), mock.clone());

        let err = adapter
            .send_chat_completion_stream(
                br#"{"model":"","messages":[{"role":"user","content":"hello"}]}"#,
                |_invocation| {
                    Ok(VerdictResult::Allow {
                        redactions: vec![],
                        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
                    })
                },
            )
            .await
            .expect_err("invalid Groq stream request must fail before transport");

        assert!(err
            .to_string()
            .contains("Groq chat/completions request model must not be empty"));
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
        let adapter = GroqAdapter::new(
            config_with_api_version("2024-12"),
            Arc::new(transport::MockTransport::new()),
        );

        let err = adapter
            .lift_batch(raw_payload(tool_call_payload()))
            .expect_err("drifted Groq API version must fail before provenance stamping");

        assert_api_version_drift(err);
    }

    #[test]
    fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
        let adapter = GroqAdapter::new(
            config_with_api_version("2024-12"),
            Arc::new(transport::MockTransport::new()),
        );
        let evaluated = std::cell::Cell::new(false);

        let err = adapter
            .gate_sse_stream(&tool_call_stream(), |_invocation| {
                evaluated.set(true);
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
                })
            })
            .expect_err("drifted Groq API version must fail before stream evaluation");

        assert_api_version_drift(err);
        assert!(!evaluated.get());
    }

    #[test]
    fn lower_function_response_rejects_api_version_drift() {
        let adapter = GroqAdapter::new(
            config_with_api_version("2024-12"),
            Arc::new(transport::MockTransport::new()),
        );
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
        };
        let result = ToolResult(b"{\"temp\":18}".to_vec());

        let err = adapter
            .lower_function_response("get_weather", verdict, result)
            .expect_err("drifted Groq API version must fail before lowering");

        assert_api_version_drift(err);
    }

    #[test]
    fn lift_batch_extracts_openai_tool_calls() {
        // Wire shape matches the captured Groq fixture
        // crates/chio-provider-conformance/fixtures/groq/groq_basic_single_tool_call.ndjson:
        // choices[].message.tool_calls[] with `function.arguments` as a
        // JSON-encoded string.
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
    fn lift_batch_extracts_parallel_tool_calls() {
        // Multiple OpenAI-compatible tool_calls[] entries lift in order.
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "id": "chatcmpl_parallel",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_weather_1",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"city\":\"Paris\"}"
                            }
                        },
                        {
                            "id": "call_time_1",
                            "type": "function",
                            "function": {
                                "name": "get_time",
                                "arguments": "{\"tz\":\"UTC\"}"
                            }
                        }
                    ]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let invocations = adapter.lift_batch(raw).unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].tool_name, "get_weather");
        assert_eq!(invocations[1].tool_name, "get_time");
        assert!(matches!(
            invocations[0].provenance.principal,
            Principal::GroqProject { .. }
        ));
    }

    #[test]
    fn lift_batch_rejects_function_tool_call_missing_function_object() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "id": "chatcmpl_malformed_tool",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_weather_1",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"city\":\"Paris\"}"
                            }
                        },
                        {
                            "id": "call_missing_function",
                            "type": "function"
                        }
                    ]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter.lift_batch(raw).unwrap_err();

        assert!(
            matches!(err, ProviderError::Malformed(message) if message.contains("tool_calls[].function was missing"))
        );
    }

    #[test]
    fn lift_batch_rejects_malformed_envelope_before_outer_tool_calls() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "body": 42,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_outer",
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
        let err = adapter.lift_batch(raw).unwrap_err();

        assert!(err.to_string().contains("envelope field `body`"));
    }

    #[test]
    fn lift_batch_maps_safety_block_to_content_policy() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "stop_reason": "refusal",
            "promptFeedback": {
                "blockReason": "SAFETY"
            }
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("Groq safety block must fail closed as content policy");

        assert!(matches!(err, ProviderError::ContentPolicy(_)));
        assert!(err.to_string().contains("SAFETY"));
    }

    #[test]
    fn lift_batch_maps_content_filter_finish_reason_to_content_policy() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "" },
                "finish_reason": "content_filter"
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("Groq content_filter finish reason must fail closed");

        assert!(matches!(err, ProviderError::ContentPolicy(_)));
        assert!(err.to_string().contains("content_filter"));
    }

    #[test]
    fn lift_batch_rejects_function_call_name_with_surrounding_whitespace() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
        let payload = json!({
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_padded_name",
                        "type": "function",
                        "function": {
                            "name": " get_weather ",
                            "arguments": "{}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
        let err = adapter
            .lift_batch(raw)
            .expect_err("whitespace-padded function name must fail closed");

        assert!(err
            .to_string()
            .contains("functionCall name must not contain surrounding whitespace"));
    }

    #[test]
    fn lower_function_response_allow() {
        let cfg = config();
        let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
    fn lower_allow_function_response_helper_applies_redactions() {
        let part = lower_allow_function_response(
            "get_weather",
            ToolResult(br#"{"token":"secret","ok":true}"#.to_vec()),
            &[Redaction {
                path: "/token".to_string(),
                replacement: "[redacted]".to_string(),
            }],
        )
        .unwrap();

        assert_eq!(part.name, "get_weather");
        assert_eq!(part.response, json!({"token": "[redacted]", "ok": true}));
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![
            GroqAdapterError::Transport(transport::HttpTransportError::Status {
                code: 500,
                body: "boom".to_string(),
            }),
            GroqAdapterError::Provider(ProviderError::Malformed("bad shape".to_string())),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }

    fn chat_request_body() -> Vec<u8> {
        let request = json!({
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": "What is the weather in Paris?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
                }
            }]
        });
        serde_json::to_vec(&request).unwrap()
    }

    fn tool_call_response() -> Vec<u8> {
        let response = json!({
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
        serde_json::to_vec(&response).unwrap()
    }

    #[tokio::test]
    async fn send_chat_completion_posts_and_lifts() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_json_response(tool_call_response());
        let adapter = GroqAdapter::new(config(), mock.clone());

        let request = chat_request_body();
        let invocations = adapter.send_chat_completion(&request).await.unwrap();

        // The lifted invocation came back from the real outbound parse path.
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");

        // The adapter posted the request body to the chat/completions path.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, GROQ_CHAT_COMPLETIONS_PATH);
        assert_eq!(calls[0].body, request);
    }

    #[tokio::test]
    async fn send_chat_completion_maps_upstream_status() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_error(transport::HttpTransportError::Status {
            code: 429,
            body: "rate limited".to_string(),
        });
        let adapter = GroqAdapter::new(config(), mock);

        let error = adapter
            .send_chat_completion(&chat_request_body())
            .await
            .expect_err("a 429 must fail closed");
        assert!(matches!(error, ProviderError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn send_chat_completion_timeout_fails_closed() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_error(transport::HttpTransportError::Timeout {
            url: "https://api.groq.com/openai/v1/chat/completions".to_string(),
            timeout_ms: 60_000,
        });
        let adapter = GroqAdapter::new(config(), mock);

        let error = adapter
            .send_chat_completion(&chat_request_body())
            .await
            .expect_err("a timeout must fail closed");
        assert!(matches!(
            error,
            ProviderError::TransportTimeout { ms: 60_000 }
        ));
    }

    #[tokio::test]
    async fn send_chat_completion_stream_gates_buffered_sse() {
        let chunk = json!({
            "id": "chatcmpl_stream",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "id": "call_weather_1",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }]
                }
            }]
        });
        let mut sse = Vec::new();
        sse.extend_from_slice(b"data: ");
        sse.extend_from_slice(&serde_json::to_vec(&chunk).unwrap());
        sse.extend_from_slice(b"\n\ndata: [DONE]\n\n");

        let mock = Arc::new(transport::MockTransport::new());
        mock.push_response(transport::HttpResponse::new(
            200,
            sse,
            Some("text/event-stream".to_string()),
        ));
        let adapter = GroqAdapter::new(config(), mock.clone());

        let gated = adapter
            .send_chat_completion_stream(&chat_request_body(), |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
                })
            })
            .await
            .unwrap();
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.invocations[0].tool_name, "get_weather");

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].kind,
            chio_provider_adapter_core::http::CallKind::Sse
        );
    }
}
