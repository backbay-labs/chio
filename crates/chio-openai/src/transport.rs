//! Outbound HTTP transport for the OpenAI provider adapter.
//!
//! [`OpenAiAdapter`] (in [`crate::adapter`]) owns the byte-level lift/lower
//! transforms. This module adds the missing half: a real outbound call that
//! forwards a native OpenAI request to the upstream API, reads the response,
//! and hands the bytes to the adapter's existing lift path so the caller gets
//! back canonical [`ToolInvocation`]s (and the adapter's own
//! [`OpenAiToolCall`] shape for Chat Completions).
//!
//! The plumbing (reqwest client, `Authorization: Bearer` header, timeout, and
//! failure classification) is provided by
//! [`chio_provider_adapter_core::http`], so this module only encodes the two
//! OpenAI endpoints and their response shapes:
//!
//! - `/v1/responses` (the Responses API the adapter already models): the
//!   response `output[]` is lifted by [`OpenAiAdapter::lift_batch`].
//! - `/v1/chat/completions`: `choices[].message.tool_calls[]` are parsed into
//!   [`OpenAiToolCall`] via the existing
//!   [`ChioOpenAiAdapter::extract_tool_calls`] helper and then lifted into the
//!   fabric invocation shape.
//!
//! Streaming uses [`ProviderHttpTransport::post_sse`] to buffer the SSE body
//! and runs it through the adapter's [`OpenAiAdapter::gate_sse_stream`] gate.
//!
//! Every failure path is fail-closed: a transport error, a non-2xx status, or
//! a malformed body becomes a [`ProviderError`] and is never reported as a
//! silent success. For hermetic tests, construct an
//! [`OpenAiTransport`] over a
//! [`chio_provider_adapter_core::http::MockHttpTransport`].

use std::sync::Arc;
use std::time::Duration;

use chio_provider_adapter_core::http::{
    map_transport_error, AuthScheme, HttpTransport, HttpTransportConfig, HttpTransportError,
    ProviderHttpTransport, DEFAULT_TIMEOUT,
};
use chio_tool_call_fabric::{ProviderError, ProviderRequest, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::adapter::{OpenAiAdapter, OpenAiAdapterConfig};
use crate::{ChioOpenAiAdapter, OpenAiToolCall};

/// Default OpenAI API host. Request paths (`/v1/responses`,
/// `/v1/chat/completions`) are joined onto it.
pub const OPENAI_API_BASE_URL: &str = "https://api.openai.com";

/// Responses API request path.
pub const OPENAI_RESPONSES_PATH: &str = "/v1/responses";

/// Chat Completions API request path.
pub const OPENAI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";

/// Environment variable read by [`OpenAiTransport::from_env`] for the bearer
/// token.
pub const OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";

/// Header carrying the optional OpenAI organization id on outbound requests.
const OPENAI_ORGANIZATION_HEADER: &str = "OpenAI-Organization";

/// Forwards native OpenAI requests over the shared HTTP transport and lifts the
/// responses through an [`OpenAiAdapter`].
///
/// The transport is held as an `Arc<dyn ProviderHttpTransport>` so production
/// code uses a [`HttpTransport`] while tests inject a
/// [`chio_provider_adapter_core::http::MockHttpTransport`] without changing the
/// call sites.
pub struct OpenAiTransport {
    transport: Arc<dyn ProviderHttpTransport>,
    adapter: OpenAiAdapter,
}

impl std::fmt::Debug for OpenAiTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiTransport")
            .field("base_url", &self.transport.base_url())
            .field("adapter", &self.adapter)
            .finish()
    }
}

impl OpenAiTransport {
    /// Build a transport that posts to the OpenAI API at
    /// [`OPENAI_API_BASE_URL`] using `Authorization: Bearer <api_key>`.
    ///
    /// The `config` supplies the organization id stamped into provenance and
    /// the pinned API version; the organization id is also sent as the
    /// `OpenAI-Organization` header when it is non-empty.
    pub fn new(
        api_key: impl Into<String>,
        config: impl Into<OpenAiAdapterConfig>,
    ) -> Result<Self, ProviderError> {
        Self::with_base_url(OPENAI_API_BASE_URL, api_key, config, DEFAULT_TIMEOUT)
    }

    /// Build a transport reading the bearer token from the [`OPENAI_API_KEY_ENV`]
    /// environment variable.
    ///
    /// Fails closed with [`ProviderError::Malformed`] when the variable is unset
    /// or empty, so a missing key never authenticates with an empty token.
    pub fn from_env(config: impl Into<OpenAiAdapterConfig>) -> Result<Self, ProviderError> {
        let auth =
            AuthScheme::bearer_from_env(OPENAI_API_KEY_ENV).map_err(transport_build_error)?;
        let AuthScheme::Bearer(api_key) = auth else {
            return Err(ProviderError::Malformed(
                "OpenAI bearer auth scheme did not yield a token".to_string(),
            ));
        };
        Self::new(api_key, config)
    }

    /// Build a transport against an explicit `base_url` (for example a proxy or
    /// an Azure OpenAI gateway) with a caller-chosen request timeout.
    pub fn with_base_url(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        config: impl Into<OpenAiAdapterConfig>,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        let config = config.into();
        let mut transport_config = HttpTransportConfig::new(base_url)
            .with_auth(AuthScheme::Bearer(api_key.into()))
            .with_timeout(timeout);
        let org_id = config.org_id.trim();
        if !org_id.is_empty() {
            transport_config = transport_config.with_header(OPENAI_ORGANIZATION_HEADER, org_id);
        }
        let transport = HttpTransport::new(transport_config).map_err(transport_build_error)?;
        Ok(Self::with_transport(Arc::new(transport), config))
    }

    /// Wrap an already-constructed transport (for example a
    /// [`chio_provider_adapter_core::http::MockHttpTransport`]) and adapter
    /// config. This is the seam hermetic tests use to drive the real request and
    /// response handling without a network.
    pub fn with_transport(
        transport: Arc<dyn ProviderHttpTransport>,
        config: impl Into<OpenAiAdapterConfig>,
    ) -> Self {
        Self {
            transport,
            adapter: OpenAiAdapter::new(config),
        }
    }

    /// Borrow the adapter used for lift/lower so callers can reuse the existing
    /// `lower`/streaming surface alongside the outbound send.
    pub fn adapter(&self) -> &OpenAiAdapter {
        &self.adapter
    }

    /// POST a Responses API `responses.create` body to `/v1/responses` and lift
    /// every `function_call` output item into a [`ToolInvocation`].
    ///
    /// `request_body` is the caller's native request JSON bytes; they are sent
    /// verbatim. The buffered response body is fed to
    /// [`OpenAiAdapter::lift_batch`], preserving the adapter's existing
    /// extraction and provenance stamping.
    pub async fn send_responses(
        &self,
        request_body: &[u8],
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        let response = self
            .transport
            .post_json(OPENAI_RESPONSES_PATH, request_body)
            .await
            .map_err(map_openai_transport_error)?;
        self.adapter.lift_batch(ProviderRequest(response.body))
    }

    /// POST a Chat Completions request body to `/v1/chat/completions` and return
    /// both the adapter-native [`OpenAiToolCall`]s parsed from the first choice
    /// and the lifted [`ToolInvocation`]s.
    ///
    /// `choices[].message.tool_calls[]` are parsed by the existing
    /// [`ChioOpenAiAdapter::extract_tool_calls`] helper, then each call is
    /// rewritten into a Responses API `function_call` item so the canonical
    /// [`OpenAiAdapter::lift_batch`] path stamps provenance identically to the
    /// Responses API flow.
    pub async fn send_chat_completions(
        &self,
        request_body: &[u8],
    ) -> Result<ChatCompletionsOutcome, ProviderError> {
        let response = self
            .transport
            .post_json(OPENAI_CHAT_COMPLETIONS_PATH, request_body)
            .await
            .map_err(map_openai_transport_error)?;
        let value: Value = serde_json::from_slice(&response.body).map_err(|error| {
            ProviderError::Malformed(format!(
                "OpenAI chat.completions response was not JSON: {error}"
            ))
        })?;

        let tool_calls = extract_chat_completion_tool_calls(&value)?;
        let invocations = if tool_calls.is_empty() {
            Vec::new()
        } else {
            let output = chat_tool_calls_as_responses_output(&tool_calls)?;
            self.adapter.lift_batch(ProviderRequest(output))?
        };

        Ok(ChatCompletionsOutcome {
            tool_calls,
            invocations,
        })
    }

    /// POST a streaming Responses API request to `/v1/responses` and gate the
    /// buffered SSE body through [`OpenAiAdapter::gate_sse_stream`].
    ///
    /// `evaluate` is invoked exactly when a completed tool-call output item is
    /// observed; tool-call frames stay buffered until the verdict allows them.
    pub async fn stream_responses<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<crate::streaming::GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let body = self
            .transport
            .post_sse(OPENAI_RESPONSES_PATH, request_body)
            .await
            .map_err(map_openai_transport_error)?;
        self.adapter.gate_sse_stream(&body, evaluate)
    }
}

/// Result of a `/v1/chat/completions` call: the adapter-native tool calls and
/// the lifted canonical invocations.
#[derive(Debug, Clone)]
pub struct ChatCompletionsOutcome {
    /// Tool calls parsed from `choices[0].message.tool_calls[]`.
    pub tool_calls: Vec<OpenAiToolCall>,
    /// The same calls lifted into the canonical fabric shape.
    pub invocations: Vec<ToolInvocation>,
}

/// Parse `choices[].message.tool_calls[]` from a Chat Completions response.
///
/// Only the first choice is inspected (OpenAI returns the assistant turn in
/// `choices[0]`); a response with no choices or no tool calls yields an empty
/// vector rather than an error so a plain text answer is not treated as a
/// failure.
fn extract_chat_completion_tool_calls(value: &Value) -> Result<Vec<OpenAiToolCall>, ProviderError> {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let Some(first) = choices.first() else {
        return Ok(Vec::new());
    };
    let message = first.get("message").ok_or_else(|| {
        ProviderError::Malformed("OpenAI chat.completions choice was missing message".to_string())
    })?;
    ChioOpenAiAdapter::extract_tool_calls(message)
        .map_err(|error| ProviderError::Malformed(error.to_string()))
}

/// Rewrite Chat Completions tool calls into a Responses API `output[]` envelope
/// so the canonical [`OpenAiAdapter::lift_batch`] path can lift them.
fn chat_tool_calls_as_responses_output(
    tool_calls: &[OpenAiToolCall],
) -> Result<Vec<u8>, ProviderError> {
    let output: Vec<Value> = tool_calls
        .iter()
        .map(|call| {
            serde_json::json!({
                "type": "function_call",
                "call_id": call.id,
                "name": call.function.name,
                "arguments": call.function.arguments,
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({ "output": output })).map_err(|error| {
        ProviderError::Malformed(format!(
            "OpenAI chat.completions tool calls failed JSON encoding: {error}"
        ))
    })
}

/// Map a transport-build failure into the fabric error taxonomy.
fn transport_build_error(error: HttpTransportError) -> ProviderError {
    ProviderError::Malformed(format!(
        "OpenAI transport could not be constructed: {error}"
    ))
}

/// Map an outbound transport failure into the fabric error taxonomy, using the
/// shared classifier so non-2xx statuses land on the same variants the README
/// error table pins.
fn map_openai_transport_error(error: HttpTransportError) -> ProviderError {
    map_transport_error("OpenAI", error)
}
