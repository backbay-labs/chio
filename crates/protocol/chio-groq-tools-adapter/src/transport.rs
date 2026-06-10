//! Groq `chat/completions` transport wiring.
//!
//! Groq exposes an OpenAI-compatible chat/completions API, so the real
//! outbound call is a Bearer-authenticated JSON POST to
//! `https://api.groq.com/openai/v1/chat/completions`. The reqwest client,
//! header injection, timeout handling, and failure classification are owned by
//! the shared [`chio_provider_adapter_core::http`] module; this module only
//! pins the Groq endpoint constants and provides a convenience constructor for
//! a Groq-configured [`HttpTransport`].
//!
//! The adapter holds an [`Arc<dyn ProviderHttpTransport>`](ProviderHttpTransport).
//! In production that is an [`HttpTransport`] built by [`groq_transport`]; in
//! unit tests it is a [`MockTransport`] that records calls and returns scripted
//! responses without touching the network.
//!
//! [`Arc<dyn ProviderHttpTransport>`]: std::sync::Arc

use std::time::Duration;

pub use chio_provider_adapter_core::http::{
    AuthScheme, HttpResponse, HttpTransport, HttpTransportConfig, HttpTransportError,
    ProviderHttpTransport, ProviderHttpTransport as Transport, RecordedCall,
};

/// Pinned Groq API version. Bumping requires re-recording conformance fixtures.
pub const GROQ_API_VERSION: &str = "2025-04";

/// Default Groq API host (OpenAI-compatible surface).
pub const GROQ_CHAT_COMPLETIONS_HOST: &str = "https://api.groq.com";

/// Request path for the OpenAI-compatible chat/completions endpoint.
pub const GROQ_CHAT_COMPLETIONS_PATH: &str = "/openai/v1/chat/completions";

/// Environment variable a CLI may set to supply the Groq API key.
pub const GROQ_API_KEY_ENV: &str = "GROQ_API_KEY";

/// Build a real Groq [`HttpTransport`] from an explicit Bearer API key.
///
/// The key is injected by the caller; nothing reads it from the process
/// environment unless the caller opts in via [`groq_transport_from_env`].
pub fn groq_transport(api_key: impl Into<String>) -> Result<HttpTransport, HttpTransportError> {
    HttpTransport::new(groq_transport_config(AuthScheme::Bearer(api_key.into())))
}

/// Build a real Groq [`HttpTransport`], reading the Bearer key from the
/// [`GROQ_API_KEY_ENV`] environment variable.
///
/// Fails closed with [`HttpTransportError::MissingEnvVar`] when the variable is
/// unset or empty rather than authenticating with an empty token.
pub fn groq_transport_from_env() -> Result<HttpTransport, HttpTransportError> {
    let auth = AuthScheme::bearer_from_env(GROQ_API_KEY_ENV)?;
    HttpTransport::new(groq_transport_config(auth))
}

/// Assemble the [`HttpTransportConfig`] for the Groq endpoint with the pinned
/// host and the supplied authentication scheme.
pub fn groq_transport_config(auth: AuthScheme) -> HttpTransportConfig {
    HttpTransportConfig {
        base_url: GROQ_CHAT_COMPLETIONS_HOST.to_string(),
        auth,
        extra_headers: vec![(
            "x-groq-api-version".to_string(),
            GROQ_API_VERSION.to_string(),
        )],
        timeout: Duration::from_secs(60),
    }
}

/// Hermetic transport double for the adapter's unit tests.
///
/// This is the shared [`chio_provider_adapter_core::http::MockHttpTransport`]
/// pre-pointed at a `mock://groq` base URL so existing call sites can construct
/// it without arguments. Scripted responses are dequeued in FIFO order and
/// every call is recorded; an exhausted script fails closed.
pub struct MockTransport {
    inner: chio_provider_adapter_core::http::MockHttpTransport,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Construct an empty mock advertising the `mock://groq` base URL.
    pub fn new() -> Self {
        Self {
            inner: chio_provider_adapter_core::http::MockHttpTransport::new("mock://groq"),
        }
    }

    /// Queue a successful JSON response (status 200, `application/json`).
    pub fn push_json_response(&self, body: impl Into<Vec<u8>>) {
        self.inner.push_json_response(body);
    }

    /// Queue an arbitrary scripted response.
    pub fn push_response(&self, response: HttpResponse) {
        self.inner.push_response(response);
    }

    /// Queue a scripted transport error.
    pub fn push_error(&self, error: HttpTransportError) {
        self.inner.push_error(error);
    }

    /// Snapshot the recorded calls in order of issue.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.inner.calls()
    }

    /// Pinned upstream API version this mock advertises.
    pub fn api_version(&self) -> &str {
        GROQ_API_VERSION
    }

    /// Base URL the mock reports through [`ProviderHttpTransport::base_url`].
    pub fn endpoint(&self) -> &str {
        self.inner.base_url()
    }
}

#[async_trait::async_trait]
impl ProviderHttpTransport for MockTransport {
    fn base_url(&self) -> &str {
        self.inner.base_url()
    }

    async fn post_json(&self, path: &str, body: &[u8]) -> Result<HttpResponse, HttpTransportError> {
        self.inner.post_json(path, body).await
    }

    async fn post_sse(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        self.inner.post_sse(path, body).await
    }

    async fn post_ndjson(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        self.inner.post_ndjson(path, body).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_provider_adapter_core::http::CallKind;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(GROQ_API_VERSION, "2025-04");
        assert_eq!(GROQ_CHAT_COMPLETIONS_HOST, "https://api.groq.com");
        assert_eq!(GROQ_CHAT_COMPLETIONS_PATH, "/openai/v1/chat/completions");
    }

    #[test]
    fn groq_transport_config_uses_bearer_and_host() {
        let config = groq_transport_config(AuthScheme::Bearer("sk-test".to_string()));
        assert_eq!(config.base_url, GROQ_CHAT_COMPLETIONS_HOST);
        assert_eq!(config.auth, AuthScheme::Bearer("sk-test".to_string()));
        assert!(config
            .extra_headers
            .iter()
            .any(|(name, value)| name == "x-groq-api-version" && value == GROQ_API_VERSION));
    }

    #[test]
    fn groq_transport_builds_client() {
        let transport = groq_transport("sk-test").unwrap();
        assert_eq!(transport.base_url(), GROQ_CHAT_COMPLETIONS_HOST);
    }

    #[test]
    fn groq_transport_from_env_fails_closed_when_unset() {
        // SAFETY: single-threaded test reading a uniquely named variable.
        std::env::remove_var(GROQ_API_KEY_ENV);
        match groq_transport_from_env() {
            Ok(_) => panic!("missing key must fail closed"),
            Err(error) => assert!(matches!(error, HttpTransportError::MissingEnvVar { .. })),
        }
    }

    #[tokio::test]
    async fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.push_json_response(b"{\"choices\":[]}".to_vec());
        let response = mock
            .post_json(GROQ_CHAT_COMPLETIONS_PATH, b"{\"foo\":1}")
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, CallKind::Json);
        assert_eq!(calls[0].path, GROQ_CHAT_COMPLETIONS_PATH);
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.api_version(), GROQ_API_VERSION);
        assert_eq!(mock.endpoint(), "mock://groq");
    }
}
