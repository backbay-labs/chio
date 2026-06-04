//! Ollama `/api/chat` transport.
//!
//! Ollama runs as a local HTTP daemon (default `http://localhost:11434`) and
//! exposes `/api/chat`. A non-streaming call returns a single JSON object; a
//! streaming call returns NDJSON (one JSON object per line) terminated by an
//! object carrying `done: true`. The real outbound plumbing (the reqwest
//! client, headers, timeouts, and failure classification) lives in
//! [`chio_provider_adapter_core::http`]; this module wires Ollama's defaults
//! onto it and re-exports the shared transport contract.

use std::sync::Arc;
use std::time::Duration;

use chio_provider_adapter_core::http::{
    AuthScheme, HttpTransport, HttpTransportConfig, HttpTransportError,
};

/// Pinned Ollama API version. Bumping requires re-recording conformance fixtures.
pub const OLLAMA_API_VERSION: &str = "2025-04";

/// Header stamped on every outbound Ollama request to bind captures to the API
/// snapshot asserted by replay fixtures.
pub const OLLAMA_API_VERSION_HEADER: &str = "x-ollama-api-version";

/// Default Ollama daemon host (localhost only by default).
pub const OLLAMA_CHAT_HOST: &str = "http://localhost:11434";

/// Request path for the Ollama chat endpoint.
pub const OLLAMA_CHAT_PATH: &str = "/api/chat";

/// Environment variable that overrides the default Ollama host.
pub const OLLAMA_HOST_ENV: &str = "OLLAMA_HOST";

/// Environment variable that, when set, supplies a bearer token for a remote
/// Ollama gateway sitting in front of the daemon.
pub const OLLAMA_API_KEY_ENV: &str = "OLLAMA_API_KEY";

/// The transport contract every Ollama transport implements.
///
/// It is the shared
/// [`ProviderHttpTransport`](chio_provider_adapter_core::http::ProviderHttpTransport)
/// from the adapter core: an adapter holds `Arc<dyn Transport>` and posts native
/// `/api/chat` bytes through it, then feeds the response to its lift/gate code.
/// In production this is an [`HttpTransport`]; in tests it is a [`MockTransport`].
pub use chio_provider_adapter_core::http::ProviderHttpTransport as Transport;

/// In-memory transport used by hermetic adapter tests.
///
/// This re-exports the shared
/// [`MockHttpTransport`](chio_provider_adapter_core::http::MockHttpTransport),
/// which records every outbound call and returns scripted responses, failing
/// closed when the script is exhausted.
pub use chio_provider_adapter_core::http::MockHttpTransport as MockTransport;

/// Build the [`HttpTransportConfig`] for a localhost (or `OLLAMA_HOST`) daemon.
///
/// The base URL defaults to [`OLLAMA_CHAT_HOST`] and is overridden by the
/// `OLLAMA_HOST` environment variable when it is set and non-empty. Ollama needs
/// no authentication on localhost, so [`AuthScheme::None`] is used unless
/// `OLLAMA_API_KEY` is set, in which case a bearer token is attached for a
/// remote gateway.
pub fn host_config() -> Result<HttpTransportConfig, HttpTransportError> {
    let host = std::env::var(OLLAMA_HOST_ENV).ok();
    let api_key = std::env::var(OLLAMA_API_KEY_ENV).ok();
    Ok(resolve_config(host.as_deref(), api_key.as_deref()))
}

/// Resolve a [`HttpTransportConfig`] from explicit host and API-key values.
///
/// `host` falls back to [`OLLAMA_CHAT_HOST`] when [`None`] or blank; `api_key`
/// attaches a bearer token when present and non-blank, otherwise the transport
/// uses [`AuthScheme::None`]. Kept free of process-environment access so the
/// resolution is deterministic and testable.
fn resolve_config(host: Option<&str>, api_key: Option<&str>) -> HttpTransportConfig {
    let base_url = match host {
        Some(value) if !value.trim().is_empty() => value.to_string(),
        _ => OLLAMA_CHAT_HOST.to_string(),
    };
    let auth = match api_key {
        Some(value) if !value.trim().is_empty() => AuthScheme::Bearer(value.to_string()),
        _ => AuthScheme::None,
    };
    pinned_config(base_url, auth)
}

fn pinned_config(base_url: impl Into<String>, auth: AuthScheme) -> HttpTransportConfig {
    HttpTransportConfig::new(base_url)
        .with_auth(auth)
        .with_header(OLLAMA_API_VERSION_HEADER, OLLAMA_API_VERSION)
}

/// Construct a live [`HttpTransport`] against the configured Ollama daemon.
///
/// Reads `OLLAMA_HOST` (falling back to [`OLLAMA_CHAT_HOST`]) and an optional
/// `OLLAMA_API_KEY` bearer token, then builds a reqwest-backed transport. Use
/// [`live_transport_with_timeout`] to override the default request timeout.
pub fn live_transport() -> Result<Arc<dyn Transport>, HttpTransportError> {
    let transport = HttpTransport::new(host_config()?)?;
    Ok(Arc::new(transport))
}

/// Construct a live [`HttpTransport`] with an explicit request timeout.
pub fn live_transport_with_timeout(
    timeout: Duration,
) -> Result<Arc<dyn Transport>, HttpTransportError> {
    let config = host_config()?.with_timeout(timeout);
    let transport = HttpTransport::new(config)?;
    Ok(Arc::new(transport))
}

/// Construct a live transport bound to an explicit base URL (no env lookup).
///
/// Useful when a caller already resolved the daemon address out of band, or for
/// driving the adapter against a fixed test server.
pub fn live_transport_for(
    base_url: impl Into<String>,
) -> Result<Arc<dyn Transport>, HttpTransportError> {
    let config = pinned_config(base_url, AuthScheme::None);
    let transport = HttpTransport::new(config)?;
    Ok(Arc::new(transport))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn api_version_header(config: &HttpTransportConfig) -> Option<&str> {
        config
            .extra_headers
            .iter()
            .find(|(name, _)| name == OLLAMA_API_VERSION_HEADER)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(OLLAMA_API_VERSION, "2025-04");
        assert_eq!(OLLAMA_CHAT_HOST, "http://localhost:11434");
        assert_eq!(OLLAMA_CHAT_PATH, "/api/chat");
    }

    #[test]
    fn resolve_config_defaults_to_localhost_without_auth() {
        let config = resolve_config(None, None);
        assert_eq!(config.base_url, OLLAMA_CHAT_HOST);
        assert_eq!(config.auth, AuthScheme::None);
        assert_eq!(api_version_header(&config), Some(OLLAMA_API_VERSION));
    }

    #[test]
    fn resolve_config_treats_blank_values_as_unset() {
        let config = resolve_config(Some("   "), Some(""));
        assert_eq!(config.base_url, OLLAMA_CHAT_HOST);
        assert_eq!(config.auth, AuthScheme::None);
        assert_eq!(api_version_header(&config), Some(OLLAMA_API_VERSION));
    }

    #[test]
    fn resolve_config_honors_host_override_and_bearer() {
        let config = resolve_config(Some("http://remote-ollama:11434"), Some("gateway-token"));
        assert_eq!(config.base_url, "http://remote-ollama:11434");
        assert_eq!(config.auth, AuthScheme::Bearer("gateway-token".to_string()));
        assert_eq!(api_version_header(&config), Some(OLLAMA_API_VERSION));
    }

    #[tokio::test]
    async fn mock_transport_records_calls() {
        let mock = MockTransport::new("mock://ollama");
        mock.push_json_response(b"{\"done\":true}".to_vec());
        let response = mock
            .post_json(OLLAMA_CHAT_PATH, b"{\"model\":\"x\"}")
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, OLLAMA_CHAT_PATH);
    }

    #[test]
    fn mock_transport_advertises_base_url() {
        let mock = MockTransport::new("mock://ollama");
        assert_eq!(mock.base_url(), "mock://ollama");
    }
}
