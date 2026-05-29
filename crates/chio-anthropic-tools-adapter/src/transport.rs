//! Anthropic Messages transport wiring.
//!
//! Anthropic exposes the Messages API, so the real outbound call is an
//! `x-api-key`-authenticated JSON POST to
//! `https://api.anthropic.com/v1/messages` carrying the pinned
//! `anthropic-version` header (and the `anthropic-beta` header when the
//! `computer-use` feature is on). The reqwest client, header injection, timeout
//! handling, and failure classification are owned by the shared
//! [`chio_provider_adapter_core::http`] module; this module only pins the
//! Anthropic endpoint constants and provides a convenience constructor for an
//! Anthropic-configured [`HttpTransport`].
//!
//! The adapter holds an [`Arc<dyn ProviderHttpTransport>`](ProviderHttpTransport).
//! In production that is an [`HttpTransport`] built by [`anthropic_transport`];
//! in unit tests it is a [`MockTransport`] that records calls and returns
//! scripted responses without touching the network.
//!
//! [`Arc<dyn ProviderHttpTransport>`]: std::sync::Arc

use std::time::Duration;

pub use chio_provider_adapter_core::http::{
    AuthScheme, HttpResponse, HttpTransport, HttpTransportConfig, HttpTransportError,
    ProviderHttpTransport, ProviderHttpTransport as Transport, RecordedCall,
};

/// Pinned Anthropic Messages API version. Bumping requires re-recording
/// conformance fixtures.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Beta header value sent when the `computer-use` cargo feature is on.
pub const COMPUTER_USE_BETA: &str = "computer-use-2025-01-24";

/// Default Anthropic API host.
pub const ANTHROPIC_MESSAGES_HOST: &str = "https://api.anthropic.com";

/// Request path for the Messages endpoint.
pub const ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";

/// Full default Anthropic Messages endpoint (host plus path).
pub const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";

/// Header carrying the pinned Messages API version.
pub const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";

/// Header carrying the beta opt-in flags.
pub const ANTHROPIC_BETA_HEADER: &str = "anthropic-beta";

/// Header carrying the API key (Anthropic uses `x-api-key`, not Bearer auth).
pub const ANTHROPIC_API_KEY_HEADER: &str = "x-api-key";

/// Environment variable a CLI may set to supply the Anthropic API key.
pub const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// Beta header value applied to outgoing requests in this build, or [`None`]
/// when the `computer-use` cargo feature is off.
pub fn computer_use_beta_header() -> Option<&'static str> {
    if cfg!(feature = "computer-use") {
        Some(COMPUTER_USE_BETA)
    } else {
        None
    }
}

/// Build a real Anthropic [`HttpTransport`] from an explicit API key.
///
/// The key is injected by the caller and sent as the `x-api-key` header;
/// nothing reads it from the process environment unless the caller opts in via
/// [`anthropic_transport_from_env`].
pub fn anthropic_transport(
    api_key: impl Into<String>,
) -> Result<HttpTransport, HttpTransportError> {
    HttpTransport::new(anthropic_transport_config(AuthScheme::Header {
        name: ANTHROPIC_API_KEY_HEADER.to_string(),
        value: api_key.into(),
    }))
}

/// Build a real Anthropic [`HttpTransport`], reading the `x-api-key` value from
/// the [`ANTHROPIC_API_KEY_ENV`] environment variable.
///
/// Fails closed with [`HttpTransportError::MissingEnvVar`] when the variable is
/// unset or empty rather than authenticating with an empty key.
pub fn anthropic_transport_from_env() -> Result<HttpTransport, HttpTransportError> {
    let auth = AuthScheme::header_from_env(ANTHROPIC_API_KEY_HEADER, ANTHROPIC_API_KEY_ENV)?;
    HttpTransport::new(anthropic_transport_config(auth))
}

/// Assemble the [`HttpTransportConfig`] for the Anthropic Messages endpoint with
/// the pinned host, the mandatory `anthropic-version` header, the conditional
/// `anthropic-beta` header, and the supplied authentication scheme.
pub fn anthropic_transport_config(auth: AuthScheme) -> HttpTransportConfig {
    let mut extra_headers = vec![(
        ANTHROPIC_VERSION_HEADER.to_string(),
        ANTHROPIC_VERSION.to_string(),
    )];
    if let Some(beta) = computer_use_beta_header() {
        extra_headers.push((ANTHROPIC_BETA_HEADER.to_string(), beta.to_string()));
    }
    HttpTransportConfig {
        base_url: ANTHROPIC_MESSAGES_HOST.to_string(),
        auth,
        extra_headers,
        timeout: Duration::from_secs(60),
    }
}

/// Hermetic transport double for the adapter's unit tests.
///
/// This is the shared [`chio_provider_adapter_core::http::MockHttpTransport`]
/// pre-pointed at a `mock://anthropic` base URL so existing call sites can
/// construct it without arguments. Scripted responses are dequeued in FIFO
/// order and every call is recorded; an exhausted script fails closed.
pub struct MockTransport {
    inner: chio_provider_adapter_core::http::MockHttpTransport,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Construct an empty mock advertising the `mock://anthropic` base URL.
    pub fn new() -> Self {
        Self {
            inner: chio_provider_adapter_core::http::MockHttpTransport::new("mock://anthropic"),
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
    pub fn anthropic_version(&self) -> &str {
        ANTHROPIC_VERSION
    }

    /// Beta header value this build sends, or [`None`] when `computer-use` is
    /// off.
    pub fn computer_use_beta(&self) -> Option<&'static str> {
        computer_use_beta_header()
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
        assert_eq!(ANTHROPIC_VERSION, "2023-06-01");
        assert_eq!(COMPUTER_USE_BETA, "computer-use-2025-01-24");
        assert_eq!(ANTHROPIC_MESSAGES_HOST, "https://api.anthropic.com");
        assert_eq!(ANTHROPIC_MESSAGES_PATH, "/v1/messages");
        assert_eq!(
            ANTHROPIC_MESSAGES_URL,
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn transport_config_uses_api_key_header_and_version() {
        let config = anthropic_transport_config(AuthScheme::Header {
            name: ANTHROPIC_API_KEY_HEADER.to_string(),
            value: "sk-ant-test".to_string(),
        });
        assert_eq!(config.base_url, ANTHROPIC_MESSAGES_HOST);
        assert_eq!(
            config.auth,
            AuthScheme::Header {
                name: "x-api-key".to_string(),
                value: "sk-ant-test".to_string(),
            }
        );
        assert!(config.extra_headers.iter().any(|(name, value)| {
            name == ANTHROPIC_VERSION_HEADER && value == ANTHROPIC_VERSION
        }));
        assert_eq!(
            config
                .extra_headers
                .iter()
                .any(|(name, _)| name == ANTHROPIC_BETA_HEADER),
            cfg!(feature = "computer-use")
        );
    }

    #[test]
    fn transport_builds_client() {
        let transport = anthropic_transport("sk-ant-test").unwrap();
        assert_eq!(transport.base_url(), ANTHROPIC_MESSAGES_HOST);
    }

    #[test]
    fn transport_from_env_fails_closed_when_unset() {
        // SAFETY: single-threaded test reading a uniquely named variable.
        std::env::remove_var(ANTHROPIC_API_KEY_ENV);
        match anthropic_transport_from_env() {
            Ok(_) => panic!("missing key must fail closed"),
            Err(error) => assert!(matches!(error, HttpTransportError::MissingEnvVar { .. })),
        }
    }

    #[tokio::test]
    async fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.push_json_response(b"{\"content\":[]}".to_vec());
        let response = mock
            .post_json(ANTHROPIC_MESSAGES_PATH, b"{\"model\":\"claude\"}")
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, CallKind::Json);
        assert_eq!(calls[0].path, ANTHROPIC_MESSAGES_PATH);
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.anthropic_version(), ANTHROPIC_VERSION);
        assert_eq!(mock.endpoint(), "mock://anthropic");
    }

    #[test]
    fn computer_use_header_tracks_feature() {
        let mock = MockTransport::new();
        assert_eq!(
            mock.computer_use_beta().is_some(),
            cfg!(feature = "computer-use")
        );
    }
}
