//! Cohere `/v2/chat` transport.
//!
//! The adapter forwards a native Cohere `/v2/chat` request to the upstream
//! endpoint, reads the response body, and hands the bytes to
//! [`crate::CohereAdapter::lift_batch`] (batch) or
//! [`crate::CohereAdapter::gate_sse_stream`] (streaming). The outbound plumbing
//! (a [`reqwest`](https://docs.rs/reqwest)-backed client, the
//! `Authorization: Bearer` header, timeouts, and failure classification) is
//! provided by the shared [`chio_provider_adapter_core::http`] module; this
//! file wires it to Cohere's host, path, and auth scheme.

use std::sync::{Arc, Mutex};

use chio_provider_adapter_core::http::{
    map_transport_error, AuthScheme, HttpResponse, HttpTransport, HttpTransportConfig,
    HttpTransportError, MockHttpTransport, ProviderHttpTransport,
};
use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use thiserror::Error;

/// Pinned Cohere API version. Bumping requires re-recording conformance fixtures.
pub const COHERE_API_VERSION: &str = "2025-04";

/// Default Cohere `/v2/chat` host.
pub const COHERE_CHAT_HOST: &str = "https://api.cohere.com";

/// Request path for the Cohere v2 chat endpoint, joined onto the host.
pub const COHERE_CHAT_PATH: &str = "/v2/chat";

/// Environment variable a [`CohereTransport::from_env`] caller reads the API key from.
pub const COHERE_API_KEY_ENV: &str = "COHERE_API_KEY";

/// Adapter-local transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The reqwest client could not be constructed (invalid header, timeout, or
    /// TLS backend failure).
    #[error("failed to build Cohere transport: {0}")]
    Build(String),
    /// The configured API key was unset or empty, so the request fails closed
    /// rather than authenticating with an empty bearer token.
    #[error("Cohere API key is unset or empty")]
    MissingApiKey,
}

/// Outbound contract for the Cohere `/v2/chat` surface.
///
/// An adapter holds an `Arc<dyn Transport>` and calls [`send_chat`] for a
/// non-streaming response or [`send_chat_stream`] for an SSE stream, then feeds
/// the returned bytes to its lift/gate code. In production this is a
/// [`CohereTransport`]; in tests it is a [`MockTransport`].
///
/// [`send_chat`]: Transport::send_chat
/// [`send_chat_stream`]: Transport::send_chat_stream
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Pinned upstream API version advertised by this transport.
    fn api_version(&self) -> &str {
        COHERE_API_VERSION
    }

    /// Endpoint host this transport posts against.
    fn endpoint(&self) -> &str {
        COHERE_CHAT_HOST
    }

    /// POST a Cohere `/v2/chat` request body and return the buffered batch
    /// response wrapped as a [`ProviderRequest`] ready for `lift_batch`.
    async fn send_chat(&self, body: &[u8]) -> Result<ProviderRequest, ProviderError>;

    /// POST a Cohere `/v2/chat` request body with `stream: true` and return the
    /// buffered SSE response bytes ready for `gate_sse_stream`.
    async fn send_chat_stream(&self, body: &[u8]) -> Result<Vec<u8>, ProviderError>;
}

/// Provider label used when mapping transport failures into the fabric taxonomy.
const PROVIDER_LABEL: &str = "Cohere";

/// A real [`HttpTransport`]-backed Cohere `/v2/chat` transport.
pub struct CohereTransport {
    inner: HttpTransport,
}

impl CohereTransport {
    /// Build a transport that posts to [`COHERE_CHAT_HOST`] with a bearer API key.
    ///
    /// Fails closed via [`TransportError::MissingApiKey`] when `api_key` is empty
    /// so an empty token never reaches the wire.
    pub fn new(api_key: impl Into<String>) -> Result<Self, TransportError> {
        Self::with_base_url(COHERE_CHAT_HOST, api_key)
    }

    /// Build a transport against an explicit `base_url` (used by hermetic tests
    /// that point the adapter at a local mock server).
    pub fn with_base_url(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(TransportError::MissingApiKey);
        }
        let config = HttpTransportConfig::new(base_url).with_auth(AuthScheme::Bearer(api_key));
        let inner = HttpTransport::new(config).map_err(|error| match error {
            HttpTransportError::MissingEnvVar { .. } => TransportError::MissingApiKey,
            other => TransportError::Build(other.to_string()),
        })?;
        Ok(Self { inner })
    }

    /// Build a transport reading the API key from [`COHERE_API_KEY_ENV`].
    ///
    /// Fails closed when the variable is unset or empty.
    pub fn from_env() -> Result<Self, TransportError> {
        let auth =
            AuthScheme::bearer_from_env(COHERE_API_KEY_ENV).map_err(|error| match error {
                HttpTransportError::MissingEnvVar { .. } => TransportError::MissingApiKey,
                other => TransportError::Build(other.to_string()),
            })?;
        let config = HttpTransportConfig::new(COHERE_CHAT_HOST).with_auth(auth);
        let inner =
            HttpTransport::new(config).map_err(|error| TransportError::Build(error.to_string()))?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl Transport for CohereTransport {
    fn endpoint(&self) -> &str {
        self.inner.base_url()
    }

    async fn send_chat(&self, body: &[u8]) -> Result<ProviderRequest, ProviderError> {
        let response = self
            .inner
            .post_json(COHERE_CHAT_PATH, body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        Ok(ProviderRequest(response.body))
    }

    async fn send_chat_stream(&self, body: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.inner
            .post_sse(COHERE_CHAT_PATH, body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))
    }
}

/// In-memory transport for hermetic adapter tests.
///
/// Backed by the shared [`MockHttpTransport`]: scripted responses are dequeued
/// in FIFO order and every call is recorded. When the script is exhausted the
/// mock fails closed rather than returning an empty success. The manual
/// `record`/`calls` helpers are retained so existing tests that only use the
/// mock as an inert handle keep compiling.
pub struct MockTransport {
    inner: Arc<MockHttpTransport>,
    /// Endpoint advertised by [`Transport::endpoint`]; defaults to `mock://cohere`.
    endpoint: String,
    /// Calls recorded through the manual [`MockTransport::record`] helper.
    manual_calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MockHttpTransport::new("mock://cohere")),
            endpoint: "mock://cohere".to_string(),
            manual_calls: Mutex::new(Vec::new()),
        }
    }

    /// Queue a successful JSON `/v2/chat` body the next [`Transport::send_chat`]
    /// call will return.
    pub fn push_chat_response(&self, body: impl Into<Vec<u8>>) {
        self.inner.push_json_response(body);
    }

    /// Queue an arbitrary scripted response (for non-2xx classification tests).
    pub fn push_response(&self, response: HttpResponse) {
        self.inner.push_response(response);
    }

    /// Queue a scripted transport error the next send will surface.
    pub fn push_error(&self, error: HttpTransportError) {
        self.inner.push_error(error);
    }

    /// Record a placed call (manual helper for tests that drive the mock by hand).
    pub fn record(&self, endpoint: &str, body: &[u8]) {
        if let Ok(mut guard) = self.manual_calls.lock() {
            guard.push((endpoint.to_string(), body.to_vec()));
        }
    }

    /// Snapshot every recorded call: those captured by the backing
    /// [`MockHttpTransport`] during real `send_*` calls followed by any added
    /// through the manual [`MockTransport::record`] helper.
    pub fn calls(&self) -> Vec<(String, Vec<u8>)> {
        let mut calls: Vec<(String, Vec<u8>)> = self
            .inner
            .calls()
            .into_iter()
            .map(|call| (call.path, call.body))
            .collect();
        if let Ok(guard) = self.manual_calls.lock() {
            calls.extend(guard.iter().cloned());
        }
        calls
    }
}

#[async_trait::async_trait]
impl Transport for MockTransport {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn send_chat(&self, body: &[u8]) -> Result<ProviderRequest, ProviderError> {
        let response = self
            .inner
            .post_json(COHERE_CHAT_PATH, body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        Ok(ProviderRequest(response.body))
    }

    async fn send_chat_stream(&self, body: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.inner
            .post_sse(COHERE_CHAT_PATH, body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(COHERE_API_VERSION, "2025-04");
        assert_eq!(COHERE_CHAT_HOST, "https://api.cohere.com");
        assert_eq!(COHERE_CHAT_PATH, "/v2/chat");
    }

    #[test]
    fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.record("/v2/chat", b"{\"foo\":1}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.api_version(), COHERE_API_VERSION);
        assert_eq!(mock.endpoint(), "mock://cohere");
    }

    #[tokio::test]
    async fn mock_transport_send_chat_returns_scripted_body() {
        let mock = MockTransport::new();
        mock.push_chat_response(b"{\"message\":{}}".to_vec());
        let response = mock.send_chat(b"{\"model\":\"command\"}").await.unwrap();
        assert_eq!(response.0, b"{\"message\":{}}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, COHERE_CHAT_PATH);
    }

    #[tokio::test]
    async fn mock_transport_exhaustion_fails_closed() {
        let mock = MockTransport::new();
        match mock.send_chat(b"{}").await {
            Err(ProviderError::Malformed(_)) => {}
            Err(other) => panic!("an empty script must fail closed, got {other:?}"),
            Ok(_) => panic!("an empty script must fail closed, got success"),
        }
    }

    #[tokio::test]
    async fn mock_transport_maps_status_error() {
        let mock = MockTransport::new();
        mock.push_error(HttpTransportError::Status {
            code: 429,
            body: "rate limited".to_string(),
        });
        match mock.send_chat(b"{}").await {
            Err(ProviderError::RateLimited { .. }) => {}
            Err(other) => panic!("a 429 must fail closed, got {other:?}"),
            Ok(_) => panic!("a 429 must fail closed, got success"),
        }
    }

    #[test]
    fn cohere_transport_rejects_empty_key() {
        match CohereTransport::new("") {
            Err(TransportError::MissingApiKey) => {}
            _ => panic!("empty key must fail closed"),
        }
    }

    #[test]
    fn cohere_transport_builds_with_key() {
        let transport = CohereTransport::new("test-key").unwrap();
        assert_eq!(transport.endpoint(), COHERE_CHAT_HOST);
        assert_eq!(transport.api_version(), COHERE_API_VERSION);
    }
}
