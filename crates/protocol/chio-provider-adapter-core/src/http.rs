//! Reusable async HTTP transport shared by the Chio provider adapters.
//!
//! Each provider adapter (OpenAI, Anthropic, Gemini, Groq, Mistral, Cohere,
//! Ollama) forwards a native request to an upstream chat/tool endpoint, reads
//! the response, and hands the bytes to its `lift`/gate code. The plumbing for
//! that outbound call - a [`reqwest`] client, provider auth headers, default
//! headers, timeouts, and failure classification - is identical across adapters,
//! so it lives here once.
//!
//! The module provides:
//!
//! - [`AuthScheme`]: caller-injected authentication (bearer token, custom
//!   header such as `x-api-key`, query parameter such as Gemini's `?key=`, or
//!   none for localhost). No provider key is hardcoded; an env-var convenience
//!   constructor reads a named variable when a caller opts in.
//! - [`HttpTransportConfig`]: base URL, auth, default headers, and timeout.
//! - [`HttpTransport`]: a [`reqwest::Client`]-backed transport that performs
//!   batch JSON posts and buffered streaming (SSE / NDJSON) posts.
//! - [`ProviderHttpTransport`]: the async trait both [`HttpTransport`] and
//!   [`MockHttpTransport`] implement so an adapter can hold
//!   `Arc<dyn ProviderHttpTransport>` and swap the mock for the real client.
//! - [`MockHttpTransport`]: a hermetic test double that records outbound calls
//!   and returns scripted responses.
//! - [`map_http_status`]: maps an upstream HTTP status + body into the fabric
//!   [`ProviderError`] taxonomy.
//! - [`parse_ndjson_lines`]: a buffered NDJSON line reader for providers such as
//!   Ollama that stream one JSON object per line rather than SSE.
//!
//! All failure paths are fail-closed: a network error, a non-2xx status, or a
//! decode failure becomes an error and is never reported as a silent success.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chio_tool_call_fabric::ProviderError;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use thiserror::Error;

/// Default request timeout applied when a caller does not set one explicitly.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// How an outbound request authenticates to the upstream provider.
///
/// The scheme is injected by the caller so no provider key is ever embedded in
/// library code. Use [`AuthScheme::bearer_from_env`],
/// [`AuthScheme::header_from_env`], or [`AuthScheme::query_param_from_env`] to
/// read a secret from a named environment variable at construction time when a
/// caller (such as a CLI) opts in to that convenience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <token>` (OpenAI, Groq, Mistral, Cohere).
    Bearer(String),
    /// An arbitrary request header, for example Anthropic's `x-api-key`.
    Header { name: String, value: String },
    /// A query-string parameter, for example Gemini's `?key=<api-key>`.
    QueryParam { name: String, value: String },
    /// No authentication (default for a localhost Ollama gateway).
    None,
}

impl AuthScheme {
    /// Build a [`AuthScheme::Bearer`] from the value of an environment variable.
    ///
    /// Returns [`HttpTransportError::MissingEnvVar`] when the variable is unset
    /// or empty so a missing secret fails closed rather than authenticating with
    /// an empty token.
    pub fn bearer_from_env(var: &str) -> Result<Self, HttpTransportError> {
        Ok(Self::Bearer(read_required_env(var)?))
    }

    /// Build an [`AuthScheme::Header`] reading the secret from `var`.
    pub fn header_from_env(header_name: &str, var: &str) -> Result<Self, HttpTransportError> {
        Ok(Self::Header {
            name: header_name.to_string(),
            value: read_required_env(var)?,
        })
    }

    /// Build an [`AuthScheme::QueryParam`] reading the secret from `var`.
    pub fn query_param_from_env(param_name: &str, var: &str) -> Result<Self, HttpTransportError> {
        validate_auth_query_param_name(param_name)?;
        Ok(Self::QueryParam {
            name: param_name.to_string(),
            value: read_required_env(var)?,
        })
    }
}

fn read_required_env(var: &str) -> Result<String, HttpTransportError> {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(HttpTransportError::MissingEnvVar {
            var: var.to_string(),
        }),
    }
}

/// Configuration for a [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Endpoint host, for example `https://api.openai.com` (no trailing slash
    /// required; request paths are joined onto it).
    pub base_url: String,
    /// How requests authenticate.
    pub auth: AuthScheme,
    /// Headers applied to every request (for example `anthropic-version`).
    pub extra_headers: Vec<(String, String)>,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl HttpTransportConfig {
    /// Construct a configuration with [`AuthScheme::None`], no extra headers, and
    /// the [`DEFAULT_TIMEOUT`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth: AuthScheme::None,
            extra_headers: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the authentication scheme.
    pub fn with_auth(mut self, auth: AuthScheme) -> Self {
        self.auth = auth;
        self
    }

    /// Append a default header applied to every request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A buffered upstream HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Full response body bytes.
    pub body: Vec<u8>,
    /// `Content-Type` header value when present.
    pub content_type: Option<String>,
}

impl HttpResponse {
    /// Construct a response (primarily for scripting [`MockHttpTransport`]).
    pub fn new(status: u16, body: impl Into<Vec<u8>>, content_type: Option<String>) -> Self {
        Self {
            status,
            body: body.into(),
            content_type,
        }
    }
}

/// Transport-layer failures.
///
/// Every variant denotes a denied request: there is no success path that hides
/// a network or decode failure.
#[derive(Debug, Error)]
pub enum HttpTransportError {
    /// The reqwest client could not be constructed (for example an invalid
    /// timeout or TLS backend failure).
    #[error("failed to build HTTP client: {0}")]
    Build(String),
    /// A header name or value could not be encoded.
    #[error("invalid header `{name}`: {detail}")]
    InvalidHeader { name: String, detail: String },
    /// The request URL could not be parsed.
    #[error("invalid request URL `{url}`: {detail}")]
    InvalidUrl { url: String, detail: String },
    /// The connection could not be established.
    #[error("connect error to `{url}`: {detail}")]
    Connect { url: String, detail: String },
    /// The request exceeded the configured timeout.
    #[error("request to `{url}` timed out after {timeout_ms}ms")]
    Timeout { url: String, timeout_ms: u64 },
    /// A generic request/transport failure that is neither connect nor timeout.
    #[error("request to `{url}` failed: {detail}")]
    Request { url: String, detail: String },
    /// The upstream returned a non-2xx status.
    #[error("upstream returned status {code}: {body}")]
    Status { code: u16, body: String },
    /// The response body could not be read or decoded.
    #[error("failed to decode response from `{url}`: {detail}")]
    Decode { url: String, detail: String },
    /// A requested environment variable holding a secret was unset or empty.
    #[error("required environment variable `{var}` is unset or empty")]
    MissingEnvVar { var: String },
    /// A [`MockHttpTransport`] had no scripted response for the call.
    #[error("mock transport has no scripted response for `{path}`")]
    MockExhausted { path: String },
}

/// Outbound transport contract shared by every HTTP-backed provider adapter.
///
/// An adapter holds an `Arc<dyn ProviderHttpTransport>` and calls [`post_json`]
/// for non-streaming requests or [`post_sse`] / [`post_ndjson`] for streaming
/// requests, then feeds the returned bytes to its existing lift/gate code. In
/// production this is a [`HttpTransport`]; in tests it is a
/// [`MockHttpTransport`].
///
/// [`post_json`]: ProviderHttpTransport::post_json
/// [`post_sse`]: ProviderHttpTransport::post_sse
/// [`post_ndjson`]: ProviderHttpTransport::post_ndjson
#[async_trait]
pub trait ProviderHttpTransport: Send + Sync {
    /// Configured base URL (host) the transport posts against.
    fn base_url(&self) -> &str;

    /// POST `body` as `application/json` to `path` and buffer the JSON response.
    async fn post_json(&self, path: &str, body: &[u8]) -> Result<HttpResponse, HttpTransportError>;

    /// POST `body` and buffer a streaming `text/event-stream` (SSE) response.
    ///
    /// The full SSE body is returned so the adapter's existing
    /// `parse_sse_frames`-driven gate can run over it.
    async fn post_sse(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError>;

    /// POST `body` and buffer a streaming NDJSON response (one JSON object per
    /// line, used by Ollama). The full body is returned for line parsing.
    async fn post_ndjson(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError>;
}

/// A [`reqwest`]-backed implementation of [`ProviderHttpTransport`].
pub struct HttpTransport {
    client: reqwest::Client,
    config: HttpTransportConfig,
    default_headers: HeaderMap,
}

impl HttpTransport {
    /// Build a transport from `config`.
    ///
    /// The reqwest client is created once and reused across requests, following
    /// the workspace convention. Default headers (including any header-style
    /// auth) are resolved up front so per-request work is minimal.
    pub fn new(config: HttpTransportConfig) -> Result<Self, HttpTransportError> {
        validate_base_url(&config.base_url)?;
        let default_headers = default_headers_for_config(&config)?;

        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: shared provider-adapter
        // transport client; egress is bounded by the validated base URL.
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| HttpTransportError::Build(error.to_string()))?;

        Ok(Self {
            client,
            config,
            default_headers,
        })
    }

    /// Borrow the configuration this transport was built with.
    pub fn config(&self) -> &HttpTransportConfig {
        &self.config
    }

    fn request_url(&self, path: &str) -> String {
        if path.is_empty() {
            return self.config.base_url.clone();
        }
        let base = self.config.base_url.trim_end_matches('/');
        if path.starts_with('/') {
            format!("{base}{path}")
        } else {
            format!("{base}/{path}")
        }
    }

    async fn send(
        &self,
        path: &str,
        body: &[u8],
        accept: &'static str,
    ) -> Result<HttpResponse, HttpTransportError> {
        let url = self.request_url(path);
        let mut request = self
            .client
            .post(&url)
            .headers(self.default_headers.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, accept)
            .body(body.to_vec());
        if let AuthScheme::QueryParam { name, value } = &self.config.auth {
            request = request.query(&[(name.as_str(), value.as_str())]);
        }

        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: request issued by the shared
        // transport client built above against the validated base URL.
        let response = request
            .send()
            .await
            .map_err(|error| map_send_error(&url, &error, self.config.timeout))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes = response
            .bytes()
            .await
            .map_err(|error| HttpTransportError::Decode {
                url: url.clone(),
                detail: error.to_string(),
            })?;

        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            return Err(HttpTransportError::Status {
                code: status.as_u16(),
                body,
            });
        }

        Ok(HttpResponse {
            status: status.as_u16(),
            body: bytes.to_vec(),
            content_type,
        })
    }
}

fn validate_base_url(base_url: &str) -> Result<(), HttpTransportError> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(invalid_base_url(
            base_url,
            "base URL must not be empty".to_string(),
        ));
    }
    if trimmed != base_url {
        return Err(invalid_base_url(
            base_url,
            "base URL must not contain surrounding whitespace".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|error| invalid_base_url(base_url, error.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(invalid_base_url(
                base_url,
                format!("base URL scheme `{scheme}` must be http or https"),
            ));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_base_url(
            base_url,
            "base URL must not contain username or password material".to_string(),
        ));
    }
    if parsed.query().is_some() {
        return Err(invalid_base_url(
            base_url,
            "base URL must not contain a query string".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(invalid_base_url(
            base_url,
            "base URL must not contain a fragment".to_string(),
        ));
    }
    Ok(())
}

fn invalid_base_url(base_url: &str, detail: String) -> HttpTransportError {
    HttpTransportError::InvalidUrl {
        url: base_url.to_string(),
        detail,
    }
}

fn default_headers_for_config(
    config: &HttpTransportConfig,
) -> Result<HeaderMap, HttpTransportError> {
    validate_auth_scheme(&config.auth)?;
    let mut headers = HeaderMap::new();
    for (name, value) in &config.extra_headers {
        insert_header(&mut headers, name, value)?;
    }
    match &config.auth {
        AuthScheme::Bearer(token) => insert_bearer_header(&mut headers, token)?,
        AuthScheme::Header { name, value } => insert_header(&mut headers, name, value)?,
        AuthScheme::QueryParam { .. } | AuthScheme::None => {}
    }
    Ok(headers)
}

fn validate_auth_scheme(auth: &AuthScheme) -> Result<(), HttpTransportError> {
    match auth {
        AuthScheme::Bearer(token) => validate_bearer_auth_secret(token),
        AuthScheme::Header { name, value } => {
            validate_auth_secret(name, value, "auth header value")
        }
        AuthScheme::QueryParam { name, value } => {
            validate_auth_query_param_name(name)?;
            validate_auth_secret(name, value, "auth query value")
        }
        AuthScheme::None => Ok(()),
    }
}

fn validate_auth_query_param_name(name: &str) -> Result<(), HttpTransportError> {
    if name.is_empty() {
        return Err(invalid_auth_query_param_name(
            name,
            "auth query parameter name must not be empty",
        ));
    }
    if name.trim() != name {
        return Err(invalid_auth_query_param_name(
            name,
            "auth query parameter name must not contain surrounding whitespace",
        ));
    }
    if name
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid_auth_query_param_name(
            name,
            "auth query parameter name must not contain whitespace or control bytes",
        ));
    }
    if name
        .bytes()
        .any(|byte| matches!(byte, b'&' | b'=' | b'?' | b'#'))
    {
        return Err(invalid_auth_query_param_name(
            name,
            "auth query parameter name must not contain query delimiters",
        ));
    }
    Ok(())
}

fn invalid_auth_query_param_name(name: &str, detail: &str) -> HttpTransportError {
    HttpTransportError::InvalidHeader {
        name: name.to_string(),
        detail: detail.to_string(),
    }
}

fn validate_auth_secret(name: &str, value: &str, label: &str) -> Result<(), HttpTransportError> {
    if value.trim().is_empty() {
        return Err(HttpTransportError::InvalidHeader {
            name: name.to_string(),
            detail: format!("{label} must not be empty"),
        });
    }
    if value.trim() != value {
        return Err(HttpTransportError::InvalidHeader {
            name: name.to_string(),
            detail: format!("{label} must not contain surrounding whitespace"),
        });
    }
    Ok(())
}

fn validate_bearer_auth_secret(value: &str) -> Result<(), HttpTransportError> {
    validate_auth_secret(AUTHORIZATION.as_str(), value, "bearer token")?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(HttpTransportError::InvalidHeader {
            name: AUTHORIZATION.to_string(),
            detail: "bearer token must not contain whitespace or control bytes".to_string(),
        });
    }
    Ok(())
}

fn insert_bearer_header(headers: &mut HeaderMap, token: &str) -> Result<(), HttpTransportError> {
    validate_bearer_auth_secret(token)?;
    let value = format!("Bearer {token}");
    let header_value =
        HeaderValue::from_str(&value).map_err(|error| HttpTransportError::InvalidHeader {
            name: AUTHORIZATION.to_string(),
            detail: error.to_string(),
        })?;
    headers.insert(AUTHORIZATION, header_value);
    Ok(())
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), HttpTransportError> {
    let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
        HttpTransportError::InvalidHeader {
            name: name.to_string(),
            detail: error.to_string(),
        }
    })?;
    let header_value =
        HeaderValue::from_str(value).map_err(|error| HttpTransportError::InvalidHeader {
            name: name.to_string(),
            detail: error.to_string(),
        })?;
    headers.insert(header_name, header_value);
    Ok(())
}

fn map_send_error(url: &str, error: &reqwest::Error, timeout: Duration) -> HttpTransportError {
    if error.is_timeout() {
        HttpTransportError::Timeout {
            url: url.to_string(),
            timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
        }
    } else if error.is_connect() {
        HttpTransportError::Connect {
            url: url.to_string(),
            detail: error.to_string(),
        }
    } else if error.is_builder() {
        HttpTransportError::InvalidUrl {
            url: url.to_string(),
            detail: error.to_string(),
        }
    } else {
        HttpTransportError::Request {
            url: url.to_string(),
            detail: error.to_string(),
        }
    }
}

#[async_trait]
impl ProviderHttpTransport for HttpTransport {
    fn base_url(&self) -> &str {
        &self.config.base_url
    }

    async fn post_json(&self, path: &str, body: &[u8]) -> Result<HttpResponse, HttpTransportError> {
        self.send(path, body, "application/json").await
    }

    async fn post_sse(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        Ok(self.send(path, body, "text/event-stream").await?.body)
    }

    async fn post_ndjson(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        Ok(self.send(path, body, "application/x-ndjson").await?.body)
    }
}

/// Map an upstream HTTP status (and body) into the fabric [`ProviderError`].
///
/// Adapters call this so they do not each re-derive the classification:
///
/// - `429` -> [`ProviderError::RateLimited`] (honoring `Retry-After` when the
///   adapter supplies it through `retry_after_ms`).
/// - `403` -> [`ProviderError::ContentPolicy`] (upstream refused the request).
/// - other `4xx` -> [`ProviderError::BadToolArgs`] (the request was rejected as
///   malformed by the upstream).
/// - `5xx` -> [`ProviderError::Upstream5xx`].
/// - anything else non-2xx -> [`ProviderError::Malformed`].
///
/// A 2xx status is not an error and is reported as [`None`].
pub fn map_http_status(provider_label: &str, status: u16, body: &[u8]) -> Option<ProviderError> {
    if (200..300).contains(&status) {
        return None;
    }
    let body_text = String::from_utf8_lossy(body).into_owned();
    let error = match status {
        429 => ProviderError::RateLimited { retry_after_ms: 0 },
        403 => ProviderError::ContentPolicy(format!("{provider_label}: {body_text}")),
        400..=499 => ProviderError::BadToolArgs(format!(
            "{provider_label} rejected request ({status}): {body_text}"
        )),
        500..=599 => ProviderError::Upstream5xx {
            status,
            body: format!("{provider_label}: {body_text}"),
        },
        _ => ProviderError::Malformed(format!(
            "{provider_label} returned unexpected status {status}: {body_text}"
        )),
    };
    Some(error)
}

/// Map a [`HttpTransportError`] into the fabric [`ProviderError`] taxonomy.
///
/// Transport-layer failures fail closed: a timeout becomes
/// [`ProviderError::TransportTimeout`], a non-2xx status is routed through
/// [`map_http_status`], and connect/decode failures surface as
/// [`ProviderError::Malformed`] so no failed request is mistaken for success.
pub fn map_transport_error(provider_label: &str, error: HttpTransportError) -> ProviderError {
    match error {
        HttpTransportError::Timeout { timeout_ms, .. } => {
            ProviderError::TransportTimeout { ms: timeout_ms }
        }
        HttpTransportError::Status { code, body } => {
            map_http_status(provider_label, code, body.as_bytes()).unwrap_or_else(|| {
                ProviderError::Malformed(format!("{provider_label} returned status {code}: {body}"))
            })
        }
        other => ProviderError::Malformed(format!("{provider_label} transport error: {other}")),
    }
}

/// Parse a buffered NDJSON body into one [`Value`] per non-empty line.
///
/// Ollama streams its `/api/chat` response as newline-delimited JSON objects,
/// terminated by an object carrying `done: true`. Blank lines (including a
/// trailing newline) are skipped; any non-empty line that is not valid JSON
/// fails closed with [`ProviderError::Malformed`].
pub fn parse_ndjson_lines(raw: &[u8], provider_label: &str) -> Result<Vec<Value>, ProviderError> {
    let text = std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!(
            "{provider_label} NDJSON bytes were not UTF-8: {error}"
        ))
    })?;
    let mut values = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(trimmed).map_err(|error| {
            ProviderError::Malformed(format!(
                "{provider_label} NDJSON line was not JSON: {error}"
            ))
        })?;
        values.push(value);
    }
    Ok(values)
}

/// A single recorded outbound call against a [`MockHttpTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    /// Which surface was exercised.
    pub kind: CallKind,
    /// The request path the adapter posted to.
    pub path: String,
    /// The raw request body bytes.
    pub body: Vec<u8>,
}

/// Which transport surface a [`RecordedCall`] exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Json,
    Sse,
    Ndjson,
}

/// A scripted response for [`MockHttpTransport`].
enum ScriptedResponse {
    Ok(HttpResponse),
    Err(HttpTransportError),
}

/// In-memory [`ProviderHttpTransport`] for hermetic adapter tests.
///
/// Scripted responses are dequeued in FIFO order as the adapter places calls;
/// every call is recorded for assertions. When the script is exhausted the mock
/// fails closed with [`HttpTransportError::MockExhausted`] rather than returning
/// an empty success, so a missing expectation surfaces as a test failure instead
/// of silently passing.
pub struct MockHttpTransport {
    base_url: String,
    calls: Mutex<Vec<RecordedCall>>,
    responses: Mutex<VecDeque<ScriptedResponse>>,
}

impl MockHttpTransport {
    /// Construct an empty mock advertising `base_url`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue a successful JSON response (status 200, `application/json`).
    pub fn push_json_response(&self, body: impl Into<Vec<u8>>) {
        self.push_response(HttpResponse::new(
            200,
            body,
            Some("application/json".to_string()),
        ));
    }

    /// Queue an arbitrary scripted response.
    pub fn push_response(&self, response: HttpResponse) {
        if let Ok(mut guard) = self.responses.lock() {
            guard.push_back(ScriptedResponse::Ok(response));
        }
    }

    /// Queue a scripted transport error.
    pub fn push_error(&self, error: HttpTransportError) {
        if let Ok(mut guard) = self.responses.lock() {
            guard.push_back(ScriptedResponse::Err(error));
        }
    }

    /// Snapshot the recorded calls in order of issue.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn record(&self, kind: CallKind, path: &str, body: &[u8]) {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push(RecordedCall {
                kind,
                path: path.to_string(),
                body: body.to_vec(),
            });
        }
    }

    fn next_response(&self, path: &str) -> Result<HttpResponse, HttpTransportError> {
        let scripted = self
            .responses
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front());
        match scripted {
            Some(ScriptedResponse::Ok(response)) => Ok(response),
            Some(ScriptedResponse::Err(error)) => Err(error),
            None => Err(HttpTransportError::MockExhausted {
                path: path.to_string(),
            }),
        }
    }
}

#[async_trait]
impl ProviderHttpTransport for MockHttpTransport {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn post_json(&self, path: &str, body: &[u8]) -> Result<HttpResponse, HttpTransportError> {
        self.record(CallKind::Json, path, body);
        self.next_response(path)
    }

    async fn post_sse(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        self.record(CallKind::Sse, path, body);
        self.next_response(path).map(|response| response.body)
    }

    async fn post_ndjson(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, HttpTransportError> {
        self.record(CallKind::Ndjson, path, body);
        self.next_response(path).map(|response| response.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;
    use wiremock::matchers::{body_string, header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn assert_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn auth_scheme_from_env_is_fail_closed_when_unset() {
        // SAFETY: single-threaded test mutation of a unique variable name.
        std::env::remove_var("CHIO_TEST_NONEXISTENT_KEY");
        let error = assert_error(
            AuthScheme::bearer_from_env("CHIO_TEST_NONEXISTENT_KEY"),
            "an unset variable must not yield a token",
        );
        assert!(matches!(error, HttpTransportError::MissingEnvVar { .. }));
    }

    #[test]
    fn auth_scheme_from_env_reads_value() {
        std::env::set_var("CHIO_TEST_PRESENT_KEY", "secret-token");
        let scheme = AuthScheme::bearer_from_env("CHIO_TEST_PRESENT_KEY").test_unwrap();
        assert_eq!(scheme, AuthScheme::Bearer("secret-token".to_string()));
        std::env::remove_var("CHIO_TEST_PRESENT_KEY");
    }

    #[test]
    fn auth_scheme_from_env_rejects_whitespace_only_value() {
        std::env::set_var("CHIO_TEST_BLANK_KEY", "   ");
        let error = assert_error(
            AuthScheme::bearer_from_env("CHIO_TEST_BLANK_KEY"),
            "a whitespace-only variable must not yield a token",
        );
        std::env::remove_var("CHIO_TEST_BLANK_KEY");

        assert!(matches!(error, HttpTransportError::MissingEnvVar { .. }));
    }

    #[test]
    fn default_headers_for_config_includes_extra_and_bearer_auth() {
        let config = HttpTransportConfig::new("https://api.example.test")
            .with_auth(AuthScheme::Bearer("sk-test".to_string()))
            .with_header("x-provider-version", "2026-05-31");

        let headers = default_headers_for_config(&config).test_unwrap();

        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .test_unwrap()
                .to_str()
                .test_unwrap(),
            "Bearer sk-test"
        );
        assert_eq!(
            headers
                .get("x-provider-version")
                .test_unwrap()
                .to_str()
                .test_unwrap(),
            "2026-05-31"
        );
    }

    #[test]
    fn default_headers_for_config_rejects_blank_bearer_auth() {
        let config = HttpTransportConfig::new("https://api.example.test")
            .with_auth(AuthScheme::Bearer("   ".to_string()));

        let error = assert_error(
            default_headers_for_config(&config),
            "blank direct bearer auth must fail closed",
        );

        assert!(matches!(
            error,
            HttpTransportError::InvalidHeader { ref name, .. } if name == AUTHORIZATION.as_str()
        ));
        assert!(error.to_string().contains("bearer token"));
    }

    #[test]
    fn default_headers_for_config_rejects_whitespace_in_bearer_auth() {
        for token in ["abc def", "abc\tdef"] {
            let config = HttpTransportConfig::new("https://api.example.test")
                .with_auth(AuthScheme::Bearer(token.to_string()));

            let error = assert_error(
                default_headers_for_config(&config),
                "whitespace-bearing bearer auth must fail closed",
            );

            assert!(matches!(
                error,
                HttpTransportError::InvalidHeader { ref name, .. } if name == AUTHORIZATION.as_str()
            ));
            assert!(error.to_string().contains("bearer token"));
        }
    }

    #[test]
    fn http_transport_rejects_blank_or_padded_direct_header_auth() {
        for value in ["", "   ", " secret", "secret "] {
            let config = HttpTransportConfig::new("https://api.example.test").with_auth(
                AuthScheme::Header {
                    name: "x-api-key".to_string(),
                    value: value.to_string(),
                },
            );

            let error = match HttpTransport::new(config) {
                Ok(_) => panic!("blank or padded direct header auth must fail closed"),
                Err(error) => error,
            };

            assert!(matches!(
                error,
                HttpTransportError::InvalidHeader { ref name, .. } if name == "x-api-key"
            ));
            assert!(error.to_string().contains("auth header value"));
        }
    }

    #[test]
    fn http_transport_rejects_blank_or_padded_direct_query_auth() {
        for value in ["", "   ", " secret", "secret "] {
            let config = HttpTransportConfig::new("https://api.example.test").with_auth(
                AuthScheme::QueryParam {
                    name: "key".to_string(),
                    value: value.to_string(),
                },
            );

            let error = match HttpTransport::new(config) {
                Ok(_) => panic!("blank or padded direct query auth must fail closed"),
                Err(error) => error,
            };

            assert!(matches!(
                error,
                HttpTransportError::InvalidHeader { ref name, .. } if name == "key"
            ));
            assert!(error.to_string().contains("auth query value"));
        }
    }

    #[test]
    fn http_transport_rejects_invalid_direct_query_auth_name() {
        for name in [
            "",
            " key",
            "key ",
            "api key",
            "key=value",
            "key&other",
            "key?debug",
            "key#fragment",
            "key\n",
        ] {
            let config = HttpTransportConfig::new("https://api.example.test").with_auth(
                AuthScheme::QueryParam {
                    name: name.to_string(),
                    value: "secret-value".to_string(),
                },
            );

            let error = match HttpTransport::new(config) {
                Ok(_) => panic!("invalid direct query auth name must fail closed"),
                Err(error) => error,
            };
            let message = error.to_string();

            assert!(matches!(error, HttpTransportError::InvalidHeader { .. }));
            assert!(message.contains("auth query parameter name"));
            assert!(
                !message.contains("secret-value"),
                "query auth secret leaked in `{message}`"
            );
        }
    }

    #[test]
    fn query_param_from_env_rejects_invalid_name_before_returning_secret() {
        std::env::set_var("CHIO_TEST_QUERY_KEY", "secret-value");
        let error = assert_error(
            AuthScheme::query_param_from_env(" key", "CHIO_TEST_QUERY_KEY"),
            "invalid query auth name must fail closed",
        );
        std::env::remove_var("CHIO_TEST_QUERY_KEY");
        let message = error.to_string();

        assert!(matches!(error, HttpTransportError::InvalidHeader { .. }));
        assert!(message.contains("auth query parameter name"));
        assert!(
            !message.contains("secret-value"),
            "query auth secret leaked in `{message}`"
        );
    }

    #[test]
    fn http_transport_rejects_blank_base_url_at_construction() {
        let error = match HttpTransport::new(HttpTransportConfig::new("   ")) {
            Ok(_) => panic!("blank base URL must fail closed before any request is sent"),
            Err(error) => error,
        };

        assert!(matches!(error, HttpTransportError::InvalidUrl { .. }));
        assert!(error.to_string().contains("base URL"));
    }

    #[test]
    fn http_transport_rejects_padded_base_url_at_construction() {
        let error = match HttpTransport::new(HttpTransportConfig::new(" https://api.example.test "))
        {
            Ok(_) => panic!("padded base URL must fail closed before any request is sent"),
            Err(error) => error,
        };

        assert!(matches!(error, HttpTransportError::InvalidUrl { .. }));
        assert!(error.to_string().contains("surrounding whitespace"));
    }

    #[test]
    fn http_transport_rejects_non_http_base_url_at_construction() {
        let error = match HttpTransport::new(HttpTransportConfig::new("file:///tmp/provider.sock"))
        {
            Ok(_) => panic!("non-HTTP base URL must fail closed before any request is sent"),
            Err(error) => error,
        };

        assert!(matches!(error, HttpTransportError::InvalidUrl { .. }));
        assert!(error.to_string().contains("http or https"));
    }

    #[test]
    fn http_transport_rejects_authority_material_in_base_url() {
        for base_url in [
            "https://user:pass@api.example.test",
            "https://api.example.test?key=secret",
            "https://api.example.test#fragment",
        ] {
            let error = match HttpTransport::new(HttpTransportConfig::new(base_url)) {
                Ok(_) => panic!("authority material in base URL must fail closed"),
                Err(error) => error,
            };

            assert!(matches!(error, HttpTransportError::InvalidUrl { .. }));
            assert!(error.to_string().contains("base URL"));
        }
    }

    #[test]
    fn map_http_status_classifies_codes() {
        assert!(map_http_status("OpenAI", 200, b"{}").is_none());
        assert!(matches!(
            map_http_status("OpenAI", 429, b"slow down"),
            Some(ProviderError::RateLimited { .. })
        ));
        assert!(matches!(
            map_http_status("OpenAI", 403, b"blocked"),
            Some(ProviderError::ContentPolicy(_))
        ));
        assert!(matches!(
            map_http_status("OpenAI", 400, b"bad"),
            Some(ProviderError::BadToolArgs(_))
        ));
        assert!(matches!(
            map_http_status("OpenAI", 503, b"down"),
            Some(ProviderError::Upstream5xx { status: 503, .. })
        ));
    }

    #[test]
    fn ndjson_parser_reads_lines_and_skips_blanks() {
        let raw = b"{\"a\":1}\n\n{\"done\":true}\n";
        let values = parse_ndjson_lines(raw, "Ollama").test_unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1].get("done"), Some(&Value::Bool(true)));
    }

    #[test]
    fn ndjson_parser_fails_closed_on_garbage() {
        let raw = b"{\"a\":1}\nnot json\n";
        let error = assert_error(
            parse_ndjson_lines(raw, "Ollama"),
            "a non-JSON line must fail closed",
        );
        assert!(matches!(error, ProviderError::Malformed(_)));
    }

    #[tokio::test]
    async fn mock_transport_records_and_scripts() {
        let mock = MockHttpTransport::new("mock://provider");
        mock.push_json_response(b"{\"ok\":true}".to_vec());
        let response = mock
            .post_json("/v1/chat", b"{\"model\":\"x\"}")
            .await
            .test_unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"ok\":true}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, CallKind::Json);
        assert_eq!(calls[0].path, "/v1/chat");
    }

    #[tokio::test]
    async fn mock_transport_exhaustion_fails_closed() {
        let mock = MockHttpTransport::new("mock://provider");
        let error = assert_error(
            mock.post_json("/v1/chat", b"{}").await,
            "an empty script must fail closed",
        );
        assert!(matches!(error, HttpTransportError::MockExhausted { .. }));
    }

    #[tokio::test]
    async fn http_transport_posts_json_with_bearer_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .and(header("authorization", "Bearer sk-test"))
            .and(header("x-extra", "yes"))
            .and(body_string("{\"model\":\"gpt\"}"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("{\"output\":[]}".as_bytes(), "application/json"),
            )
            .mount(&server)
            .await;

        let config = HttpTransportConfig::new(server.uri())
            .with_auth(AuthScheme::Bearer("sk-test".to_string()))
            .with_header("x-extra", "yes");
        let transport = HttpTransport::new(config).test_unwrap();
        let response = transport
            .post_json("/v1/responses", b"{\"model\":\"gpt\"}")
            .await
            .test_unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"output\":[]}");
        assert_eq!(response.content_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn http_transport_sends_custom_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "anthropic-secret"))
            .and(header("anthropic-version", "2023-06-01"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        let config = HttpTransportConfig::new(server.uri())
            .with_auth(AuthScheme::Header {
                name: "x-api-key".to_string(),
                value: "anthropic-secret".to_string(),
            })
            .with_header("anthropic-version", "2023-06-01");
        let transport = HttpTransport::new(config).test_unwrap();
        let response = transport
            .post_json("/v1/messages", b"{}")
            .await
            .test_unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn http_transport_sends_query_param_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini:generateContent"))
            .and(query_param("key", "gemini-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"candidates\":[]}"))
            .mount(&server)
            .await;

        let config = HttpTransportConfig::new(server.uri()).with_auth(AuthScheme::QueryParam {
            name: "key".to_string(),
            value: "gemini-secret".to_string(),
        });
        let transport = HttpTransport::new(config).test_unwrap();
        let response = transport
            .post_json("/v1beta/models/gemini:generateContent", b"{}")
            .await
            .test_unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn http_transport_buffers_sse_body() {
        let server = MockServer::start().await;
        let sse = "event: ping\ndata: {\"type\":\"ping\"}\n\ndata: [DONE]\n\n";
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .and(header_exists("accept"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&server)
            .await;

        let transport = HttpTransport::new(HttpTransportConfig::new(server.uri())).test_unwrap();
        let body = transport
            .post_sse("/v1/responses", b"{}")
            .await
            .test_unwrap();
        assert_eq!(String::from_utf8_lossy(&body), sse);
    }

    #[tokio::test]
    async fn http_transport_buffers_ndjson_body() {
        let server = MockServer::start().await;
        let ndjson = "{\"message\":{}}\n{\"done\":true}\n";
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-ndjson")
                    .set_body_string(ndjson),
            )
            .mount(&server)
            .await;

        let transport = HttpTransport::new(HttpTransportConfig::new(server.uri())).test_unwrap();
        let body = transport
            .post_ndjson("/api/chat", b"{}")
            .await
            .test_unwrap();
        let values = parse_ndjson_lines(&body, "Ollama").test_unwrap();
        assert_eq!(values.len(), 2);
    }

    #[tokio::test]
    async fn http_transport_maps_non_2xx_to_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&server)
            .await;

        let transport = HttpTransport::new(HttpTransportConfig::new(server.uri())).test_unwrap();
        let error = assert_error(
            transport.post_json("/v1/responses", b"{}").await,
            "a 429 must fail closed",
        );
        match error {
            HttpTransportError::Status { code, .. } => assert_eq!(code, 429),
            other => panic!("expected Status error, got {other}"),
        }
        // The status maps into the fabric rate-limit variant.
        let mapped = map_transport_error(
            "OpenAI",
            HttpTransportError::Status {
                code: 429,
                body: "rate limited".to_string(),
            },
        );
        assert!(matches!(mapped, ProviderError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn http_transport_connect_error_fails_closed() {
        // Port 0 with an unroutable host: the connect attempt fails fast.
        let config =
            HttpTransportConfig::new("http://127.0.0.1:1").with_timeout(Duration::from_millis(250));
        let transport = HttpTransport::new(config).test_unwrap();
        let error = assert_error(
            transport.post_json("/v1/chat", b"{}").await,
            "an unreachable endpoint must fail closed",
        );
        assert!(matches!(
            error,
            HttpTransportError::Connect { .. } | HttpTransportError::Request { .. }
        ));
    }
}
