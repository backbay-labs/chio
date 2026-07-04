//! Mistral `chat/completions` transport.
//!
//! Mistral exposes an OpenAI-compatible chat/completions API. The real
//! [`MistralHttpTransport`] forwards a native request body to
//! `https://api.mistral.ai/v1/chat/completions` over HTTPS with a
//! `Authorization: Bearer <key>` header, buffers the response, and hands the
//! bytes back to the adapter's lift/gate code. [`MockTransport`] keeps the same
//! contract for hermetic unit tests without touching the network.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chio_provider_adapter_core::http::{
    AuthScheme, HttpTransport, HttpTransportConfig, HttpTransportError, ProviderHttpTransport,
};
use thiserror::Error;

/// Pinned Mistral API version. Bumping requires re-recording conformance fixtures.
pub const MISTRAL_API_VERSION: &str = "2025-04";

/// Default Mistral chat/completions endpoint host.
pub const MISTRAL_CHAT_COMPLETIONS_HOST: &str = "https://api.mistral.ai";

/// Request path for the Mistral chat/completions endpoint.
pub const MISTRAL_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";

/// Environment variable a caller may read the bearer key from.
pub const MISTRAL_API_KEY_ENV: &str = "MISTRAL_API_KEY";

/// Wire-level transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The mock transport has no scripted response for this endpoint.
    #[error("mock transport has no scripted response for `{endpoint}`")]
    MockExhausted { endpoint: String },
    /// An outbound HTTP failure raised by the shared transport.
    #[error(transparent)]
    Http(#[from] HttpTransportError),
}

/// Wire-level transport contract.
///
/// Implementors forward a buffered chat/completions request body to the upstream
/// Mistral endpoint and return the buffered response bytes. The non-streaming
/// surface returns a JSON body; the streaming surface returns the buffered SSE
/// body so the adapter's existing `gate_sse_stream` can run over it.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Pinned upstream API version.
    fn api_version(&self) -> &str {
        MISTRAL_API_VERSION
    }

    /// Endpoint host this transport posts against.
    fn endpoint(&self) -> &str {
        MISTRAL_CHAT_COMPLETIONS_HOST
    }

    /// POST a non-streaming chat/completions request and buffer the JSON body.
    async fn chat_completion(&self, body: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// POST a streaming chat/completions request and buffer the SSE body.
    async fn chat_completion_stream(&self, body: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Real Mistral transport backed by the shared [`HttpTransport`].
pub struct MistralHttpTransport {
    inner: HttpTransport,
}

impl MistralHttpTransport {
    /// Build a transport that authenticates with `Authorization: Bearer <api_key>`.
    pub fn new(api_key: impl Into<String>) -> Result<Self, TransportError> {
        Self::with_auth(AuthScheme::Bearer(api_key.into()))
    }

    /// Build a transport reading the bearer key from [`MISTRAL_API_KEY_ENV`].
    ///
    /// Fails closed with [`HttpTransportError::MissingEnvVar`] when the variable
    /// is unset or empty so a missing secret never authenticates with an empty
    /// token.
    pub fn from_env() -> Result<Self, TransportError> {
        Self::with_auth(AuthScheme::bearer_from_env(MISTRAL_API_KEY_ENV)?)
    }

    /// Build a transport with an explicit [`AuthScheme`].
    pub fn with_auth(auth: AuthScheme) -> Result<Self, TransportError> {
        let config = HttpTransportConfig::new(MISTRAL_CHAT_COMPLETIONS_HOST)
            .with_auth(auth)
            .with_header("x-mistral-api-version", MISTRAL_API_VERSION)
            .with_timeout(Duration::from_secs(60));
        Ok(Self {
            inner: HttpTransport::new(config)?,
        })
    }

    /// Build a transport from a fully-formed [`HttpTransportConfig`].
    pub fn from_config(config: HttpTransportConfig) -> Result<Self, TransportError> {
        Ok(Self {
            inner: HttpTransport::new(config)?,
        })
    }
}

#[async_trait]
impl Transport for MistralHttpTransport {
    fn api_version(&self) -> &str {
        MISTRAL_API_VERSION
    }

    fn endpoint(&self) -> &str {
        self.inner.base_url()
    }

    async fn chat_completion(&self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(self
            .inner
            .post_json(MISTRAL_CHAT_COMPLETIONS_PATH, body)
            .await?
            .body)
    }

    async fn chat_completion_stream(&self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(self
            .inner
            .post_sse(MISTRAL_CHAT_COMPLETIONS_PATH, body)
            .await?)
    }
}

/// In-memory transport that records every call placed against it and returns
/// scripted responses. Used for hermetic adapter unit tests.
#[derive(Default)]
pub struct MockTransport {
    /// Captured `(endpoint, raw-body-bytes)` tuples in order of issue.
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    /// FIFO queue of scripted response bodies.
    responses: Mutex<std::collections::VecDeque<Vec<u8>>>,
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a scripted response body returned by the next chat/completions call.
    pub fn push_response(&self, body: impl Into<Vec<u8>>) {
        if let Ok(mut guard) = self.responses.lock() {
            guard.push_back(body.into());
        }
    }

    /// Record a placed call.
    pub fn record(&self, endpoint: &str, body: &[u8]) {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push((endpoint.to_string(), body.to_vec()));
        }
    }

    /// Snapshot the recorded calls for assertions.
    pub fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn next_response(&self, endpoint: &str) -> Result<Vec<u8>, TransportError> {
        let scripted = self
            .responses
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front());
        scripted.ok_or_else(|| TransportError::MockExhausted {
            endpoint: endpoint.to_string(),
        })
    }
}

#[async_trait]
impl Transport for MockTransport {
    fn endpoint(&self) -> &str {
        "mock://mistral"
    }

    async fn chat_completion(&self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.record(MISTRAL_CHAT_COMPLETIONS_PATH, body);
        self.next_response(MISTRAL_CHAT_COMPLETIONS_PATH)
    }

    async fn chat_completion_stream(&self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.record(MISTRAL_CHAT_COMPLETIONS_PATH, body);
        self.next_response(MISTRAL_CHAT_COMPLETIONS_PATH)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(MISTRAL_API_VERSION, "2025-04");
        assert_eq!(MISTRAL_CHAT_COMPLETIONS_HOST, "https://api.mistral.ai");
        assert_eq!(MISTRAL_CHAT_COMPLETIONS_PATH, "/v1/chat/completions");
    }

    #[tokio::test]
    async fn mock_transport_records_and_scripts_calls() {
        let mock = MockTransport::new();
        mock.push_response(b"{\"choices\":[]}".to_vec());
        let body = mock.chat_completion(b"{\"foo\":1}").await.unwrap();
        assert_eq!(body, b"{\"choices\":[]}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, MISTRAL_CHAT_COMPLETIONS_PATH);
    }

    #[tokio::test]
    async fn mock_transport_exhaustion_fails_closed() {
        let mock = MockTransport::new();
        let error = mock
            .chat_completion(b"{}")
            .await
            .expect_err("an empty script must fail closed");
        assert!(matches!(error, TransportError::MockExhausted { .. }));
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.api_version(), MISTRAL_API_VERSION);
        assert_eq!(mock.endpoint(), "mock://mistral");
    }

    #[test]
    fn http_transport_advertises_real_endpoint() {
        let transport =
            MistralHttpTransport::new("sk-test").expect("bearer transport builds with a token");
        assert_eq!(transport.endpoint(), MISTRAL_CHAT_COMPLETIONS_HOST);
        assert_eq!(transport.api_version(), MISTRAL_API_VERSION);
    }

    #[test]
    fn http_transport_from_env_is_fail_closed_when_unset() {
        // SAFETY: single-threaded test mutation of a unique variable name.
        std::env::remove_var(MISTRAL_API_KEY_ENV);
        // `MistralHttpTransport` holds a reqwest client and is not `Debug`, so
        // match on the result rather than using `expect_err`.
        match MistralHttpTransport::from_env() {
            Ok(_) => panic!("an unset key must not build a transport"),
            Err(error) => assert!(matches!(
                error,
                TransportError::Http(HttpTransportError::MissingEnvVar { .. })
            )),
        }
    }
}
