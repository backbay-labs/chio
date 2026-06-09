//! Provider-native adapter that mediates Mistral `chat/completions`
//! tool-use traffic through the Chio kernel. Pinned upstream API version:
//! `2025-04` (see [`transport::MISTRAL_API_VERSION`]).
//!
//! Mistral exposes an OpenAI-compatible chat/completions API, so the model
//! surfaces tool calls as `choices[].message.tool_calls[]` entries
//! (`{ id, type: "function", function: { name, arguments } }`, where
//! `arguments` is a JSON-encoded string). Tool results travel back as a
//! `tool` role message carrying the matching `tool_call_id`.
//!
//! The adapter's [`lift_batch`](MistralAdapter::lift_batch) lifts every
//! `tool_calls` entry into a [`chio_tool_call_fabric::ToolInvocation`] and
//! [`lower_function_response`](MistralAdapter::lower_function_response) lowers a
//! kernel verdict back into the tool-result payload returned on the next turn.

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

mod response;

use std::sync::Arc;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_provider_adapter_core::http::map_transport_error;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ProviderRequest, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub use native::{FunctionCallPart, FunctionResponsePart};
pub use transport::{
    Transport, MISTRAL_API_VERSION, MISTRAL_CHAT_COMPLETIONS_HOST, MISTRAL_CHAT_COMPLETIONS_PATH,
};

/// Provider label used when mapping transport failures into [`ProviderError`].
const PROVIDER_LABEL: &str = "Mistral";

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
    /// Mistral project identifier that scopes tool calls on La Plateforme.
    /// Stamped into the [`Principal::MistralProject`] provenance slot.
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

/// An outbound Mistral chat/completions request.
///
/// This is the OpenAI-compatible request shape Mistral expects: a model id, the
/// conversation `messages`, and the `tools` the model may call. Serialized to
/// JSON it becomes the POST body sent to `/v1/chat/completions`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MistralChatRequest {
    /// Model identifier, for example `mistral-large-latest`.
    pub model: String,
    /// Conversation turns in OpenAI `messages` shape.
    pub messages: Vec<Value>,
    /// Tool declarations the model may call (OpenAI `tools` shape).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    /// Whether to request a streamed (SSE) response.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stream: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl MistralChatRequest {
    /// Construct a non-streaming request for `model` with `messages` and `tools`.
    pub fn new(model: impl Into<String>, messages: Vec<Value>, tools: Vec<Value>) -> Self {
        Self {
            model: model.into(),
            messages,
            tools,
            stream: false,
        }
    }

    /// Encode the request as the JSON body bytes Mistral expects.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        if self.model.trim().is_empty() {
            return Err(ProviderError::BadToolArgs(
                "Mistral chat/completions request model must not be empty".to_string(),
            ));
        }
        if self.messages.is_empty() {
            return Err(ProviderError::BadToolArgs(
                "Mistral chat/completions request must include at least one message".to_string(),
            ));
        }
        serde_json::to_vec(self).map_err(|error| {
            ProviderError::Malformed(format!(
                "Mistral chat/completions request failed JSON encoding: {error}"
            ))
        })
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

    pub(crate) fn ensure_supported_api_version(&self) -> Result<(), ProviderError> {
        if self.config.api_version != MISTRAL_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Mistral adapter supports only API version {MISTRAL_API_VERSION}; configured {}",
                self.config.api_version
            )));
        }
        let transport_api_version = self.transport.api_version();
        if transport_api_version != MISTRAL_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Mistral adapter supports only API version {MISTRAL_API_VERSION}; transport advertised {transport_api_version}"
            )));
        }
        Ok(())
    }

    /// Forward a non-streaming chat/completions request to Mistral and lift the
    /// `tool_calls` in the response.
    ///
    /// The request body is the OpenAI-compatible chat/completions JSON Mistral
    /// expects (`{ model, messages, tools }`). It is POSTed through the transport
    /// to `/v1/chat/completions` with `Authorization: Bearer <key>`; the buffered
    /// response is then handed to [`lift_batch`](Self::lift_batch). Transport
    /// failures fail closed: a timeout, non-2xx status, or decode error becomes a
    /// [`ProviderError`] and is never reported as an empty success.
    pub async fn send_chat_completion(
        &self,
        request: &MistralChatRequest,
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let body = request.to_json_bytes()?;
        let response = self
            .transport
            .chat_completion(&body)
            .await
            .map_err(map_mistral_transport_error)?;
        self.lift_batch(ProviderRequest(response))
    }

    /// Forward a streaming chat/completions request to Mistral and gate the SSE
    /// response through `evaluate` before any tool-call frame is forwarded.
    ///
    /// The buffered SSE body is run through
    /// [`gate_sse_stream`](Self::gate_sse_stream) so each `tool_calls` frame is
    /// held behind the kernel verdict. Transport failures fail closed.
    pub async fn send_chat_completion_stream<F>(
        &self,
        request: &MistralChatRequest,
        evaluate: F,
    ) -> Result<streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let mut request = request.clone();
        request.stream = true;
        let body = request.to_json_bytes()?;
        let raw = self
            .transport
            .chat_completion_stream(&body)
            .await
            .map_err(map_mistral_transport_error)?;
        self.gate_sse_stream(&raw, evaluate)
    }

    /// Lift every Mistral `tool_calls` part in a non-streaming
    /// `chat/completions` response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let calls = response::function_calls(raw)?;
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
        self.ensure_supported_api_version()?;
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
                request_id: call.id.clone(),
                api_version: self.config.api_version.clone(),
                principal: Principal::MistralProject {
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
                Ok(lower_deny_function_response(tool_call_id, &reason))
            }
        }
    }
}

fn lower_allow_function_response(
    tool_call_id: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<FunctionResponsePart, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Mistral functionResponse")?;
    Ok(FunctionResponsePart::new(tool_call_id, value))
}

fn lower_deny_function_response(tool_call_id: &str, reason: &DenyReason) -> FunctionResponsePart {
    FunctionResponsePart::new(tool_call_id, deny_payload(reason))
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
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
}

/// Map a transport failure into the fabric [`ProviderError`] taxonomy.
///
/// A non-2xx status or timeout from the shared HTTP transport is classified by
/// [`map_transport_error`]; an exhausted mock surfaces as
/// [`ProviderError::Malformed`]. Every arm is fail-closed.
fn map_mistral_transport_error(error: transport::TransportError) -> ProviderError {
    match error {
        transport::TransportError::Http(http) => map_transport_error(PROVIDER_LABEL, http),
        transport::TransportError::MockExhausted { endpoint } => ProviderError::Malformed(format!(
            "Mistral mock transport had no scripted response for `{endpoint}`"
        )),
    }
}

fn validate_function_call(call: &FunctionCallPart) -> Result<(), ProviderError> {
    non_empty_str(&call.id, "tool_calls[].id")?;
    non_empty_str(&call.name, "functionCall name")?;
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
    } else if trimmed != value {
        Err(ProviderError::Malformed(format!(
            "Mistral {field} must not contain surrounding whitespace"
        )))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
