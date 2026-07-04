//! Gemini `generateContent` transport.
//!
//! The adapter forwards a native Gemini `generateContent` request to the
//! upstream Generative Language API, reads the response body, and hands the
//! bytes to [`crate::GeminiAdapter::lift_batch`] (batch) or
//! [`crate::GeminiAdapter::gate_sse_stream`] (`streamGenerateContent`). The
//! outbound plumbing (a [`reqwest`](https://docs.rs/reqwest)-backed client,
//! timeouts, and failure classification) is provided by the shared
//! [`chio_provider_adapter_core::http`] module; this file wires it to Gemini's
//! host, model-scoped path, and query-parameter API-key auth.
//!
//! The Generative Language API (Google AI Studio) authenticates with the API
//! key as a query parameter (`?key=<API_KEY>`), which maps onto
//! [`AuthScheme::QueryParam`]. No key is embedded in library code; it is
//! injected at construction or read from an environment variable a caller opts
//! into.

use std::sync::{Arc, Mutex};

use chio_provider_adapter_core::http::{
    map_transport_error, AuthScheme, HttpResponse, HttpTransport, HttpTransportConfig,
    HttpTransportError, MockHttpTransport, ProviderHttpTransport,
};
use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use thiserror::Error;

/// Pinned Gemini API version. Bumping requires re-recording conformance fixtures.
pub const GEMINI_API_VERSION: &str = "v1beta";

/// Default Gemini generateContent endpoint host.
pub const GEMINI_GENERATE_CONTENT_HOST: &str = "https://generativelanguage.googleapis.com";

/// Query-parameter name carrying the Generative Language API key (`?key=...`).
pub const GEMINI_API_KEY_PARAM: &str = "key";

/// Environment variable a [`GeminiTransport::from_env`] caller reads the API key from.
pub const GEMINI_API_KEY_ENV: &str = "GEMINI_API_KEY";

/// Provider label used when mapping transport failures into the fabric taxonomy.
const PROVIDER_LABEL: &str = "Gemini";

/// Build the model-scoped `generateContent` request path joined onto the host.
///
/// For example, model `gemini-1.5-pro` yields
/// `/v1beta/models/gemini-1.5-pro:generateContent`.
pub fn generate_content_path(model: &str) -> String {
    format!("/{GEMINI_API_VERSION}/models/{model}:generateContent")
}

/// Build the model-scoped `streamGenerateContent` request path joined onto the
/// host.
///
/// The `alt=sse` query parameter selects the server-sent-events framing the
/// adapter's [`crate::GeminiAdapter::gate_sse_stream`] expects.
pub fn stream_generate_content_path(model: &str) -> String {
    format!("/{GEMINI_API_VERSION}/models/{model}:streamGenerateContent?alt=sse")
}

/// Adapter-local transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The reqwest client could not be constructed (invalid header, timeout, or
    /// TLS backend failure).
    #[error("failed to build Gemini transport: {0}")]
    Build(String),
    /// The configured API key was unset or empty, so the request fails closed
    /// rather than authenticating with an empty key.
    #[error("Gemini API key is unset or empty")]
    MissingApiKey,
}

/// Outbound contract for the Gemini `generateContent` surface.
///
/// An adapter holds an `Arc<dyn Transport>` and calls [`send_generate_content`]
/// for a non-streaming response or [`send_generate_content_stream`] for an SSE
/// stream, then feeds the returned bytes to its lift/gate code. In production
/// this is a [`GeminiTransport`]; in tests it is a [`MockTransport`].
///
/// [`send_generate_content`]: Transport::send_generate_content
/// [`send_generate_content_stream`]: Transport::send_generate_content_stream
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Pinned upstream API version advertised by this transport.
    fn api_version(&self) -> &str {
        GEMINI_API_VERSION
    }

    /// Endpoint host this transport posts against.
    fn endpoint(&self) -> &str {
        GEMINI_GENERATE_CONTENT_HOST
    }

    /// POST a `generateContent` request body for `model` and return the buffered
    /// batch response wrapped as a [`ProviderRequest`] ready for `lift_batch`.
    async fn send_generate_content(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<ProviderRequest, ProviderError>;

    /// POST a `streamGenerateContent` request body for `model` and return the
    /// buffered SSE response bytes ready for `gate_sse_stream`.
    async fn send_generate_content_stream(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;
}

/// A real [`HttpTransport`]-backed Gemini `generateContent` transport.
pub struct GeminiTransport {
    inner: HttpTransport,
}

impl GeminiTransport {
    /// Build a transport that posts to [`GEMINI_GENERATE_CONTENT_HOST`] with the
    /// API key carried as the `?key=` query parameter.
    ///
    /// Fails closed via [`TransportError::MissingApiKey`] when `api_key` is empty
    /// so an empty key never reaches the wire.
    pub fn new(api_key: impl Into<String>) -> Result<Self, TransportError> {
        Self::with_base_url(GEMINI_GENERATE_CONTENT_HOST, api_key)
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
        let config = HttpTransportConfig::new(base_url).with_auth(AuthScheme::QueryParam {
            name: GEMINI_API_KEY_PARAM.to_string(),
            value: api_key,
        });
        let inner = HttpTransport::new(config).map_err(|error| match error {
            HttpTransportError::MissingEnvVar { .. } => TransportError::MissingApiKey,
            other => TransportError::Build(other.to_string()),
        })?;
        Ok(Self { inner })
    }

    /// Build a transport reading the API key from [`GEMINI_API_KEY_ENV`].
    ///
    /// Fails closed when the variable is unset or empty.
    pub fn from_env() -> Result<Self, TransportError> {
        let auth = AuthScheme::query_param_from_env(GEMINI_API_KEY_PARAM, GEMINI_API_KEY_ENV)
            .map_err(|error| match error {
                HttpTransportError::MissingEnvVar { .. } => TransportError::MissingApiKey,
                other => TransportError::Build(other.to_string()),
            })?;
        let config = HttpTransportConfig::new(GEMINI_GENERATE_CONTENT_HOST).with_auth(auth);
        let inner =
            HttpTransport::new(config).map_err(|error| TransportError::Build(error.to_string()))?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl Transport for GeminiTransport {
    fn endpoint(&self) -> &str {
        self.inner.base_url()
    }

    async fn send_generate_content(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<ProviderRequest, ProviderError> {
        let response = self
            .inner
            .post_json(&generate_content_path(model), body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        Ok(ProviderRequest(response.body))
    }

    async fn send_generate_content_stream(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.inner
            .post_sse(&stream_generate_content_path(model), body)
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
    /// Endpoint advertised by [`Transport::endpoint`]; defaults to `mock://gemini`.
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
            inner: Arc::new(MockHttpTransport::new("mock://gemini")),
            endpoint: "mock://gemini".to_string(),
            manual_calls: Mutex::new(Vec::new()),
        }
    }

    /// Queue a successful JSON `generateContent` body the next
    /// [`Transport::send_generate_content`] call will return.
    pub fn push_generate_content_response(&self, body: impl Into<Vec<u8>>) {
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

    async fn send_generate_content(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<ProviderRequest, ProviderError> {
        let response = self
            .inner
            .post_json(&generate_content_path(model), body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        Ok(ProviderRequest(response.body))
    }

    async fn send_generate_content_stream(
        &self,
        model: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.inner
            .post_sse(&stream_generate_content_path(model), body)
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
        assert_eq!(GEMINI_API_VERSION, "v1beta");
        assert_eq!(
            GEMINI_GENERATE_CONTENT_HOST,
            "https://generativelanguage.googleapis.com"
        );
        assert_eq!(GEMINI_API_KEY_PARAM, "key");
    }

    #[test]
    fn model_scoped_paths_are_built() {
        assert_eq!(
            generate_content_path("gemini-1.5-pro"),
            "/v1beta/models/gemini-1.5-pro:generateContent"
        );
        assert_eq!(
            stream_generate_content_path("gemini-1.5-pro"),
            "/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.record(
            "/v1beta/models/gemini-1.5-pro:generateContent",
            b"{\"foo\":1}",
        );
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.api_version(), GEMINI_API_VERSION);
        assert_eq!(mock.endpoint(), "mock://gemini");
    }

    #[tokio::test]
    async fn mock_transport_send_returns_scripted_body() {
        let mock = MockTransport::new();
        mock.push_generate_content_response(b"{\"candidates\":[]}".to_vec());
        let response = mock
            .send_generate_content("gemini-1.5-pro", b"{\"contents\":[]}")
            .await
            .unwrap();
        assert_eq!(response.0, b"{\"candidates\":[]}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "/v1beta/models/gemini-1.5-pro:generateContent");
    }

    #[tokio::test]
    async fn mock_transport_exhaustion_fails_closed() {
        let mock = MockTransport::new();
        match mock.send_generate_content("gemini-1.5-pro", b"{}").await {
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
            body: "resource exhausted".to_string(),
        });
        match mock.send_generate_content("gemini-1.5-pro", b"{}").await {
            Err(ProviderError::RateLimited { .. }) => {}
            Err(other) => panic!("a 429 must fail closed, got {other:?}"),
            Ok(_) => panic!("a 429 must fail closed, got success"),
        }
    }

    #[test]
    fn gemini_transport_rejects_empty_key() {
        match GeminiTransport::new("") {
            Err(TransportError::MissingApiKey) => {}
            _ => panic!("empty key must fail closed"),
        }
    }

    #[test]
    fn gemini_transport_builds_with_key() {
        let transport = GeminiTransport::new("test-key").unwrap();
        assert_eq!(transport.endpoint(), GEMINI_GENERATE_CONTENT_HOST);
        assert_eq!(transport.api_version(), GEMINI_API_VERSION);
    }
}
