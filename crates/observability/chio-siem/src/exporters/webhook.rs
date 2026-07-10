//! Generic webhook exporter for Chio receipts.
//!
//! Delivers each receipt in a batch as a JSON POST to a user-configured URL.
//! Features:
//!
//! - Configurable HTTP method (POST or PUT).
//! - Optional authentication (Bearer, Basic, custom header).
//! - Custom extra headers merged into every request.
//! - Per-request retry with exponential backoff for transient (5xx/429)
//!   errors.
//! - Optional severity / guard allow-lists so noisy or low-signal events can
//!   be dropped before hitting the wire.
//!
//! This is the generic webhook path: backend-specific payload variants (Slack,
//! Teams block-kit) layer on top as thin adapters.

use std::collections::HashMap;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::alerting::{derive_event_severity, AlertSeverity};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::exporters::require_https_endpoint;
use crate::redaction::redact_for_operator_log;
use chio_core::receipt::decision::Decision;
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

/// Authentication mode for the webhook exporter.
///
/// SECURITY: secret material (bearer tokens, basic passwords, custom header
/// values) is wrapped in [`Zeroizing<String>`] so the backing bytes are
/// overwritten when the value is dropped.
#[derive(Debug, Clone, Default)]
pub enum WebhookAuth {
    /// No authentication applied.
    #[default]
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(Zeroizing<String>),
    /// HTTP Basic authentication via reqwest's `basic_auth` helper.
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
    /// Custom header `name: value`.
    Header {
        name: String,
        value: Zeroizing<String>,
    },
}

/// HTTP method supported by the webhook exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebhookMethod {
    /// `POST` (default).
    #[default]
    Post,
    /// `PUT`.
    Put,
}

/// Retry policy for transient (5xx, 429) webhook failures.
#[derive(Debug, Clone)]
pub struct WebhookRetry {
    /// Maximum number of retry attempts after the initial request.
    ///
    /// `0` means no retries (single attempt). Default: `2`.
    pub max_retries: u32,
    /// Base backoff in milliseconds for exponential retry
    /// (actual delay: `base * 2^(attempt-1)`). Default: `250`.
    pub base_backoff_ms: u64,
}

impl Default for WebhookRetry {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_backoff_ms: 250,
        }
    }
}

/// Configuration for the webhook exporter.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Target HTTPS URL. Must be non-empty.
    pub url: String,
    /// HTTP method. Default: [`WebhookMethod::Post`].
    pub method: WebhookMethod,
    /// Authentication mode. Default: [`WebhookAuth::None`].
    pub auth: WebhookAuth,
    /// Extra headers added to every request.
    pub headers: HashMap<String, String>,
    /// Retry policy. Default: 2 retries, 250 ms base backoff.
    pub retry: WebhookRetry,
    /// Minimum severity required to forward an event. Events below this
    /// threshold are dropped silently (counted as successful).
    pub min_severity: Option<AlertSeverity>,
    /// When non-empty, only events whose `decision.guard` (for Deny) or
    /// whose `evidence[].guard_name` matches are forwarded.
    pub include_guards: Vec<String>,
    /// Events matching any of these guard names are dropped.
    pub exclude_guards: Vec<String>,
    /// HTTP request timeout. Default: 30 seconds.
    pub timeout: Duration,
    /// Typed HTTP egress contract enforced before every request and on
    /// every redirect hop. When `None`, the substrate fails closed at
    /// dispatch time instead of leaking a request. Required in production.
    pub egress_contract: Option<HttpEgressContract>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: WebhookMethod::Post,
            auth: WebhookAuth::None,
            headers: HashMap::new(),
            retry: WebhookRetry::default(),
            min_severity: None,
            include_guards: Vec::new(),
            exclude_guards: Vec::new(),
            timeout: Duration::from_secs(30),
            egress_contract: None,
        }
    }
}

/// Notification-oriented exporter that POSTs one receipt per HTTP request.
pub struct WebhookExporter {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookExporter {
    /// Create a new `WebhookExporter`.
    ///
    /// Returns an error if `url` is empty, not HTTPS, the
    /// [`HttpEgressContract`] is missing or rejects the configured URL, or
    /// if the HTTP client cannot be built.
    pub fn new(config: WebhookConfig) -> Result<Self, ExportError> {
        if config.url.trim().is_empty() {
            return Err(ExportError::HttpError(
                "Webhook url must not be empty".to_string(),
            ));
        }
        require_https_endpoint(
            &config.url,
            "Webhook receipt export requires an https endpoint",
        )?;
        // HttpEgressContract: production webhook callers must declare a
        // typed egress contract that admits the configured URL. The contract
        // is re-checked on every dispatch via send_with_contract; this early
        // check is purely a config-time guard so misconfiguration fails at
        // construction rather than at first delivery.
        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError(
                "Webhook receipt export requires an HttpEgressContract".to_string(),
            )
        })?;
        contract.enforce_url(&config.url, 0).map_err(|err| {
            ExportError::HttpError(format!("HttpEgressContract rejects webhook URL: {err}"))
        })?;

        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Construct a webhook SOC export sink from an operator-configured endpoint
    /// URL, deriving the required [`HttpEgressContract`] from the URL authority
    /// the same way the alert backends do. This is the
    /// env-driven production constructor the `chio-wall siem-export` serve path
    /// uses to register a real durable audit-export consumer.
    ///
    /// The generic webhook is the most general SOC receiver: with the default
    /// `WebhookConfig` (no `min_severity`, no guard filters) it forwards EVERY
    /// audit row, not just high-severity denials, so it is a complete SOC export
    /// sink rather than a notification overlay.
    ///
    /// `url` must be `https://`. `bearer_token`, when present, is sent as
    /// `Authorization: Bearer` and wrapped in [`Zeroizing`] so its bytes are
    /// cleared on drop. Returns an error (fail-closed) when the URL is not HTTPS,
    /// the derived contract rejects the URL, or the HTTP client cannot be built.
    pub fn from_endpoint(url: String, bearer_token: Option<String>) -> Result<Self, ExportError> {
        let egress_contract = crate::alerting::siem_endpoint_egress_contract("webhook", &url)?;
        let auth = match bearer_token {
            Some(token) => WebhookAuth::Bearer(Zeroizing::new(token)),
            None => WebhookAuth::None,
        };
        let config = WebhookConfig {
            url,
            auth,
            egress_contract: Some(egress_contract),
            ..WebhookConfig::default()
        };
        Self::new(config)
    }

    /// Create a `WebhookExporter` without TLS scheme validation.
    ///
    /// This constructor is intended for integration tests that run against a
    /// local mock server over plain HTTP. Do NOT use this in production code:
    /// it bypasses the HTTPS enforcement that protects receipt export.
    ///
    /// If the supplied [`WebhookConfig`] does not declare an
    /// [`HttpEgressContract`], a permissive test-only contract is derived from
    /// the configured URL so the egress substrate still runs.
    pub fn new_plaintext_for_tests(mut config: WebhookConfig) -> Result<Self, ExportError> {
        if config.url.trim().is_empty() {
            return Err(ExportError::HttpError(
                "Webhook url must not be empty".to_string(),
            ));
        }

        if config.egress_contract.is_none() {
            let url = url::Url::parse(&config.url).map_err(|e| {
                ExportError::HttpError(format!("invalid webhook URL for test contract: {e}"))
            })?;
            let host = url.host_str().unwrap_or("localhost");
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            config.egress_contract = Some(HttpEgressContract::permissive_for_tests(&authority));
        }

        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError(
                "Webhook test exporter requires an HttpEgressContract".to_string(),
            )
        })?;
        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { config, client })
    }

    fn should_forward(&self, event: &SiemEvent) -> bool {
        if let Some(min) = self.config.min_severity {
            if derive_event_severity(event) < min {
                return false;
            }
        }

        let guards: Vec<&str> = match &event.receipt.decision {
            Some(Decision::Deny { guard, .. }) => {
                let mut gs: Vec<&str> = vec![guard.as_str()];
                gs.extend(event.receipt.evidence.iter().map(|g| g.guard_name.as_str()));
                gs
            }
            _ => event
                .receipt
                .evidence
                .iter()
                .map(|g| g.guard_name.as_str())
                .collect(),
        };

        if !self.config.include_guards.is_empty()
            && !guards
                .iter()
                .any(|g| self.config.include_guards.iter().any(|inc| inc == g))
        {
            return false;
        }

        if guards
            .iter()
            .any(|g| self.config.exclude_guards.iter().any(|exc| exc == g))
        {
            return false;
        }

        true
    }

    fn build_request(&self, event: &SiemEvent) -> Result<reqwest::RequestBuilder, ExportError> {
        let mut req = match self.config.method {
            WebhookMethod::Post => self.client.post(&self.config.url),
            WebhookMethod::Put => self.client.put(&self.config.url),
        };

        for (k, v) in &self.config.headers {
            req = req.header(k, v);
        }

        req = match &self.config.auth {
            WebhookAuth::None => req,
            WebhookAuth::Bearer(token) => req.bearer_auth(token.as_str()),
            WebhookAuth::Basic { username, password } => {
                req.basic_auth(username, Some(password.as_str()))
            }
            WebhookAuth::Header { name, value } => req.header(name.as_str(), value.as_str()),
        };

        let body = serde_json::to_string(event).map_err(|e| {
            ExportError::SerializationError(format!(
                "failed to serialize event for receipt {}: {e}",
                event.receipt.id
            ))
        })?;

        Ok(req.header("Content-Type", "application/json").body(body))
    }

    fn safe_endpoint_label(&self) -> String {
        sanitize_url_for_error(&self.config.url)
    }

    async fn deliver_one(&self, event: &SiemEvent) -> Result<(), ExportError> {
        let mut last_err: Option<ExportError> = None;

        for attempt in 0..=self.config.retry.max_retries {
            if attempt > 0 {
                let backoff_ms = self.config.retry.base_backoff_ms
                    * (1u64 << (attempt.saturating_sub(1).min(16)));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            // HttpEgressContract: every webhook dispatch must run through the
            // typed egress contract. Build the reqwest::Request, validate it
            // against the contract via send_with_contract, and only then
            // hand the response back to the retry loop.
            let request_builder = self.build_request(event)?;
            let raw_request = request_builder.build().map_err(|e| {
                ExportError::HttpError(format!("failed to build webhook request: {e}"))
            })?;
            let result = match &self.config.egress_contract {
                Some(contract) => send_with_contract(contract, &self.client, raw_request)
                    .await
                    .map_err(|err| ExportError::HttpError(err.to_string())),
                None => Err(ExportError::HttpError(
                    "webhook exporter is missing HttpEgressContract; substrate fails closed"
                        .to_string(),
                )),
            };

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() || status.as_u16() == 202 {
                        return Ok(());
                    }

                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unreadable body>".to_string());
                    let body = redact_for_operator_log(body);
                    let err = ExportError::HttpError(format!(
                        "webhook endpoint returned {status}: {body} ({})",
                        self.safe_endpoint_label()
                    ));

                    // Retry on 429 and 5xx; give up on other 4xx.
                    let code = status.as_u16();
                    if code == 429 || (500..=599).contains(&code) {
                        last_err = Some(err);
                        continue;
                    }
                    return Err(err);
                }
                Err(e) => {
                    last_err = Some(ExportError::HttpError(format!(
                        "webhook endpoint request failed: {e} ({})",
                        self.safe_endpoint_label()
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ExportError::HttpError("webhook delivery failed with no error".to_string())
        }))
    }
}

fn sanitize_url_for_error(raw_url: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw_url) else {
        return "<invalid webhook endpoint>".to_string();
    };

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

impl Exporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhook"
    }

    /// Stable, endpoint-derived durable cursor identity. Every `WebhookExporter`
    /// reports the name "webhook", so keying the durable cursor by registration
    /// index would let a config reorder or an inserted same-named sink inherit
    /// another instance's `acked_seq` and skip receipts. Folding the configured
    /// endpoint into the identity keeps two
    /// webhook sinks to different destinations on distinct cursors and makes the
    /// key depend only on configuration, not registration order. Userinfo and
    /// query are stripped (via `sanitize_url_for_error`) so no secret material
    /// lands in the cursor DB; the metric label stays the bare "webhook".
    fn cursor_identity(&self) -> String {
        format!(
            "{}@{}",
            self.name(),
            sanitize_url_for_error(&self.config.url)
        )
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut first_err: Option<String> = None;

            for event in events {
                if !self.should_forward(event) {
                    // Filtered events are counted as successful so the
                    // manager's cursor can advance; they do not hit the DLQ.
                    succeeded += 1;
                    continue;
                }

                match self.deliver_one(event).await {
                    Ok(()) => succeeded += 1,
                    Err(err) => {
                        failed += 1;
                        if first_err.is_none() {
                            first_err = Some(err.to_string());
                        }
                    }
                }
            }

            if failed == 0 {
                return Ok(succeeded);
            }

            if succeeded == 0 {
                return Err(ExportError::HttpError(first_err.unwrap_or_else(|| {
                    "webhook exporter: all events failed".to_string()
                })));
            }

            Err(ExportError::PartialFailure {
                succeeded,
                failed,
                details: first_err.unwrap_or_else(|| "webhook delivery failure".to_string()),
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_url() {
        let cfg = WebhookConfig {
            url: "  ".to_string(),
            ..WebhookConfig::default()
        };
        assert!(WebhookExporter::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_plain_http_url() {
        let cfg = WebhookConfig {
            url: "http://example.test/receipts".to_string(),
            ..WebhookConfig::default()
        };
        let Err(error) = WebhookExporter::new(cfg) else {
            panic!("plain HTTP webhook endpoint should be rejected");
        };

        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn default_auth_is_none() {
        assert!(matches!(WebhookAuth::default(), WebhookAuth::None));
    }

    #[test]
    fn from_endpoint_builds_a_real_https_soc_consumer() {
        // The env-driven serve constructor derives the egress contract from the
        // URL and yields a real, named "webhook" SOC export consumer offline (no
        // DNS resolution at construction).
        let exporter =
            WebhookExporter::from_endpoint("https://soc.example.test/ingest".to_string(), None)
                .expect("https endpoint builds a webhook SOC sink");
        assert_eq!(exporter.name(), "webhook");
        // The default config forwards EVERY audit row (no severity/guard filter),
        // so it is a complete SOC export sink, not a notification overlay.
        assert!(exporter.config.min_severity.is_none());
        assert!(exporter.config.include_guards.is_empty());
        assert!(matches!(exporter.config.auth, WebhookAuth::None));
    }

    #[test]
    fn from_endpoint_carries_bearer_token_and_rejects_plaintext() {
        let with_token = WebhookExporter::from_endpoint(
            "https://soc.example.test/ingest".to_string(),
            Some("soc-secret".to_string()),
        )
        .expect("bearer-authenticated https endpoint builds");
        assert!(matches!(with_token.config.auth, WebhookAuth::Bearer(_)));

        let plaintext =
            WebhookExporter::from_endpoint("http://soc.example.test/ingest".to_string(), None);
        assert!(
            plaintext.is_err(),
            "a plaintext http SOC endpoint must be rejected"
        );
    }

    #[test]
    fn cursor_identity_is_endpoint_derived_and_stable() {
        // The durable cursor identity is derived from the configured endpoint,
        // not the bare name, so two webhook sinks to different destinations keep
        // distinct cursors and a config reorder cannot remap one onto the other.
        let a = WebhookExporter::from_endpoint("https://soc.example.test/a".to_string(), None)
            .expect("build a");
        let b = WebhookExporter::from_endpoint("https://soc.example.test/b".to_string(), None)
            .expect("build b");
        assert_ne!(
            a.cursor_identity(),
            b.cursor_identity(),
            "different endpoints must get distinct cursor identities"
        );
        // Stable and endpoint-bearing (not the bare metric name).
        assert_eq!(a.cursor_identity(), a.cursor_identity());
        assert_ne!(a.cursor_identity(), a.name());
        assert!(a.cursor_identity().starts_with("webhook@"));
        // sanitize_url_for_error strips query/fragment, so no query-string secret
        // material lands in the durable cursor key. (userinfo is already rejected
        // at construction by the egress contract.)
        let with_query = WebhookExporter::from_endpoint(
            "https://soc.example.test/a?token=abc".to_string(),
            None,
        )
        .expect("build with query string");
        assert!(
            !with_query.cursor_identity().contains("token=abc"),
            "query-string material must not leak into the cursor identity: {}",
            with_query.cursor_identity()
        );
    }
}
