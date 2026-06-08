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
                request_id: call.id.clone(),
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
        tool_call_id: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<FunctionResponsePart, ProviderError> {
        self.ensure_supported_api_version()?;
        let tool_call_id = non_empty_str(tool_call_id, "tool_call_id")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                lower_allow_function_response(tool_call_id, result, &redactions)
            }
            VerdictResult::Deny { reason, .. } => {
                lower_deny_function_response(tool_call_id, &reason)
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
    non_empty_str(&call.id, "tool_calls[].id")?;
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
    tool_call_id: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<FunctionResponsePart, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Groq functionResponse")?;
    Ok(FunctionResponsePart::new(tool_call_id, value))
}

fn lower_deny_function_response(
    tool_call_id: &str,
    reason: &DenyReason,
) -> Result<FunctionResponsePart, ProviderError> {
    Ok(FunctionResponsePart::new(
        tool_call_id,
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
mod tests;
