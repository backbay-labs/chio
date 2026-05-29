//! Provider-native adapter that mediates Google Gemini `generateContent`
//! tool-use traffic through the Chio kernel. Pinned upstream API version:
//! `v1beta` (see [`transport::GEMINI_API_VERSION`]).
//!
//! Gemini surfaces tool calls as `functionCall` parts inside the model's
//! `Content` payload. Tool results travel back as `functionResponse` parts
//! on the user turn. The adapter's [`lift_batch`](GeminiAdapter::lift_batch)
//! lifts every `functionCall` into a [`chio_tool_call_fabric::ToolInvocation`]
//! and [`lower_function_response`](GeminiAdapter::lower_function_response)
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
pub use transport::{
    GeminiTransport, Transport, GEMINI_API_KEY_ENV, GEMINI_API_VERSION,
    GEMINI_GENERATE_CONTENT_HOST,
};

/// Configuration for the Gemini adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeminiAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`GEMINI_API_VERSION`].
    pub api_version: String,
    /// Google Cloud project identifier that scopes Gemini tool calls. Stamped
    /// into the [`Principal::GeminiProject`] provenance slot.
    pub project_id: String,
}

impl GeminiAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`GEMINI_API_VERSION`].
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
            api_version: GEMINI_API_VERSION.to_string(),
            project_id: project_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct GeminiAdapter {
    config: GeminiAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl GeminiAdapter {
    /// Build a new adapter from a config and a transport handle.
    pub fn new(config: GeminiAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Gemini
    }

    /// Pinned upstream API version (always [`GEMINI_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &GeminiAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Proxy a non-streaming Gemini `generateContent` request and lift the
    /// response.
    ///
    /// `request_body` is the native Gemini `generateContent` JSON (`contents`,
    /// `tools.functionDeclarations`). The transport POSTs it to
    /// `/v1beta/models/<model>:generateContent` with the API key carried as the
    /// `?key=` query parameter, and the buffered response is fed straight into
    /// [`lift_batch`](Self::lift_batch). Transport-layer failures are mapped into
    /// the [`ProviderError`] taxonomy so a failed request never reads as an empty
    /// success.
    pub async fn generate_content(
        &self,
        model: &str,
        request_body: &[u8],
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        let response = self
            .transport
            .send_generate_content(model, request_body)
            .await?;
        self.lift_batch(response)
    }

    /// Proxy a streaming Gemini `streamGenerateContent` request and gate the SSE
    /// response.
    ///
    /// `request_body` is the native Gemini `generateContent` JSON. The buffered
    /// SSE body is gated frame-by-frame through `evaluate` by
    /// [`gate_sse_stream`](Self::gate_sse_stream) before any bytes are forwarded.
    pub async fn generate_content_stream<F>(
        &self,
        model: &str,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let body = self
            .transport
            .send_generate_content_stream(model, request_body)
            .await?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Lift every Gemini `functionCall` part in a non-streaming
    /// `generateContent` response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let calls = function_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Gemini generateContent payload did not contain functionCall parts".to_string(),
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
                "Gemini functionCall args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Gemini,
            tool_name: call.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Gemini,
                request_id: format!("gemini_{}_call", call.name),
                api_version: self.config.api_version.clone(),
                principal: Principal::GeminiProject {
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
        let function_name = non_empty_str(function_name, "functionResponse.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let value = parse_value(&result.0)?;
                let value = apply_redactions(value, &redactions, "Gemini functionResponse")?;
                Ok(FunctionResponsePart::new(function_name, value))
            }
            VerdictResult::Deny { reason, .. } => Ok(FunctionResponsePart::new(
                function_name,
                deny_payload(&reason),
            )),
        }
    }
}

impl chio_provider_adapter_core::Provider for GeminiAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum GeminiAdapterError {
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// A provider-layer failure surfaced while proxying a request.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!(
            "Gemini generateContent payload was not JSON: {error}"
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

fn validate_function_call(call: &FunctionCallPart) -> Result<(), ProviderError> {
    if call.name.trim().is_empty() {
        return Err(ProviderError::Malformed(
            "Gemini functionCall name was empty".to_string(),
        ));
    }
    if !call.args.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Gemini functionCall `{}` args were not a JSON object",
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
            "Gemini {field} must not be empty"
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

    fn config() -> GeminiAdapterConfig {
        GeminiAdapterConfig::new(
            "gemini-1",
            "Gemini generateContent",
            "0.1.0",
            "deadbeef",
            "proj_chio_demo",
        )
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, GEMINI_API_VERSION);
        assert_eq!(cfg.api_version, "v1beta");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Gemini);
        assert_eq!(adapter.api_version(), "v1beta");
    }

    #[test]
    fn lift_batch_extracts_function_call_parts() {
        let cfg = config();
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
        let adapter = GeminiAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
        let cases = vec![
            GeminiAdapterError::Transport(transport::TransportError::MissingApiKey),
            GeminiAdapterError::Provider(ProviderError::Malformed("bad".to_string())),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'));
        }
    }

    #[tokio::test]
    async fn generate_content_proxies_request_and_lifts_tool_calls() {
        let cfg = config();
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_generate_content_response(
            serde_json::to_vec(&json!({
                "candidates": [{
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
                        ]
                    }
                }]
            }))
            .unwrap(),
        );
        let adapter = GeminiAdapter::new(cfg, mock.clone());
        let request = b"{\"contents\":[],\"tools\":[]}";
        let invocations = adapter
            .generate_content("gemini-1.5-pro", request)
            .await
            .unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "/v1beta/models/gemini-1.5-pro:generateContent");
        assert_eq!(calls[0].1, request);
    }

    #[tokio::test]
    async fn generate_content_propagates_upstream_status_error() {
        let cfg = config();
        let mock = transport::MockTransport::new();
        mock.push_error(
            chio_provider_adapter_core::http::HttpTransportError::Status {
                code: 503,
                body: "service unavailable".to_string(),
            },
        );
        let adapter = GeminiAdapter::new(cfg, Arc::new(mock));
        let err = adapter
            .generate_content("gemini-1.5-pro", b"{}")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Upstream5xx { status: 503, .. }
        ));
    }

    #[tokio::test]
    async fn generate_content_stream_gates_function_call_frames() {
        let cfg = config();
        let mock = Arc::new(transport::MockTransport::new());
        let sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Paris\"}}}]}}]}\n\n";
        mock.push_generate_content_response(sse.as_bytes().to_vec());
        let adapter = GeminiAdapter::new(cfg, mock.clone());
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
        };
        let gated = adapter
            .generate_content_stream("gemini-1.5-pro", b"{\"contents\":[]}", |_invocation| {
                Ok(verdict.clone())
            })
            .await
            .unwrap();
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.invocations[0].tool_name, "get_weather");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            "/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse"
        );
    }
}
