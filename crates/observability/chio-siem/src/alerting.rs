//! Alerting surface for Chio SIEM events.
//!
//! This module provides:
//!
//! 1. [`AlertSeverity`], a shared severity enum used by Datadog, webhook, and
//!    alerting exporters.
//! 2. [`derive_severity`], a deterministic mapping from [`ChioReceipt`] to
//!    [`AlertSeverity`] based on `decision` and guard evidence.
//! 3. [`AlertBackend`], a small trait representing a side-channel alerting
//!    backend (PagerDuty, OpsGenie) that fires on high-severity guard
//!    denials.
//! 4. [`AlertingExporter`], an [`Exporter`] implementation that filters a
//!    batch of events down to those that should trigger alerts and dispatches
//!    each one to every configured [`AlertBackend`].
//!
//! Unlike Splunk HEC or Datadog Logs, alerting is a *trigger*, not a
//! transport: it only fires on high-severity denials and carries a minimal
//! payload optimized for on-call ergonomics (short summary, dedup key,
//! severity).
//!
//! # Integration
//!
//! Register the exporter through the existing
//! [`crate::manager::ExporterManager::add_exporter`] surface:
//!
//! ```no_run
//! use chio_siem::alerting::{AlertingConfig, AlertingExporter, PagerDutyBackend};
//! use chio_siem::manager::{ExporterManager, SiemConfig};
//!
//! # fn build() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manager = ExporterManager::new(SiemConfig::default())?;
//! let pagerduty = PagerDutyBackend::new("rk_live_xxx".into())?;
//! let alerting = AlertingExporter::builder(AlertingConfig::default())
//!     .with_backend(Box::new(pagerduty))
//!     .build();
//! manager.add_exporter(Box::new(alerting));
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::redaction::redact_for_operator_log;
use chio_core::receipt::body::chio_receipt_id;
use chio_core::receipt::{body::ChioReceipt, decision::Decision, metadata::GuardEvidence};
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

// -- Severity -----------------------------------------------------------------

/// Ordered severity levels used by alerting-aware exporters.
///
/// The ordering is deliberate: `Info < Low < Medium < High < Critical`. Use
/// the `PartialOrd`/`Ord` impls to test thresholds like
/// `severity >= AlertSeverity::High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Informational (allow, no warnings).
    Info,
    /// Low (allow with soft warnings).
    Low,
    /// Medium (generic deny).
    Medium,
    /// High (deny on security-sensitive guard).
    High,
    /// Critical (deny on secret leak, policy breach, egress to known-bad).
    Critical,
}

impl AlertSeverity {
    /// Lowercase tag label for dashboards and log status fields.
    pub fn as_tag(self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }

    /// PagerDuty Events API v2 severity string.
    pub fn as_pagerduty(self) -> &'static str {
        match self {
            AlertSeverity::Critical => "critical",
            AlertSeverity::High => "error",
            AlertSeverity::Medium => "warning",
            AlertSeverity::Low | AlertSeverity::Info => "info",
        }
    }

    /// OpsGenie Alerts API priority (P1-P5).
    pub fn as_opsgenie_priority(self) -> &'static str {
        match self {
            AlertSeverity::Critical => "P1",
            AlertSeverity::High => "P2",
            AlertSeverity::Medium => "P3",
            AlertSeverity::Low => "P4",
            AlertSeverity::Info => "P5",
        }
    }
}

/// Derive an [`AlertSeverity`] from a receipt's decision and guard evidence.
///
/// The mapping table is:
///
/// | Decision | Guard / evidence               | Severity |
/// |----------|--------------------------------|----------|
/// | Deny     | `secret` in guard name         | Critical |
/// | Deny     | `egress`, `firewall`, `exfil`  | Critical |
/// | Deny     | `path`, `filesystem`, `fs`     | High     |
/// | Deny     | `financial`, `budget`, `limit` | High     |
/// | Deny     | (any other)                    | Medium   |
/// | Cancelled / Incomplete | any             | Low      |
/// | Allow    | non-authorizing semantics      | Low      |
/// | Allow    | authorized, failed evidence    | Low      |
/// | Allow    | authorized, clean              | Info     |
pub fn derive_severity(receipt: &ChioReceipt) -> AlertSeverity {
    let receipt_id_valid = chio_receipt_id(&receipt.body())
        .map(|id| id == receipt.id)
        .unwrap_or(false);
    let authoritative = receipt_id_valid
        && receipt.verify_signature().unwrap_or(false)
        && receipt.action.verify_hash().unwrap_or(false);
    let authorized = authoritative
        && receipt
            .semantic_fields()
            .is_authorized(receipt.decision.as_ref());
    match &receipt.decision {
        Some(Decision::Allow) => {
            if !authorized || receipt.evidence.iter().any(|g| !g.verdict) {
                AlertSeverity::Low
            } else {
                AlertSeverity::Info
            }
        }
        Some(Decision::Cancelled { .. }) | Some(Decision::Incomplete { .. }) | None => {
            AlertSeverity::Low
        }
        Some(Decision::Deny { guard, .. }) => severity_for_guard(guard, &receipt.evidence),
    }
}

/// Derive severity from an already-verified SIEM event. This path preserves
/// signer trust and semantic authorization computed at ingestion time.
pub fn derive_event_severity(event: &SiemEvent) -> AlertSeverity {
    match &event.receipt.decision {
        Some(Decision::Allow) => {
            if !event.authorized || event.receipt.evidence.iter().any(|g| !g.verdict) {
                AlertSeverity::Low
            } else {
                AlertSeverity::Info
            }
        }
        _ => derive_severity(&event.receipt),
    }
}

fn severity_for_guard(guard: &str, evidence: &[GuardEvidence]) -> AlertSeverity {
    let guard_lower = guard.to_ascii_lowercase();
    let mut tokens: Vec<String> = vec![guard_lower.clone()];
    tokens.extend(evidence.iter().map(|g| g.guard_name.to_ascii_lowercase()));

    let matches = |needles: &[&str]| tokens.iter().any(|t| needles.iter().any(|n| t.contains(n)));

    if matches(&["secret", "credential", "token_leak"]) {
        return AlertSeverity::Critical;
    }
    if matches(&["egress", "firewall", "exfil", "known_bad"]) {
        return AlertSeverity::Critical;
    }
    if matches(&["path", "filesystem", "fs_", "forbidden_path"]) {
        return AlertSeverity::High;
    }
    if matches(&["financial", "budget", "limit", "payment"]) {
        return AlertSeverity::High;
    }

    AlertSeverity::Medium
}

// -- Backend trait ------------------------------------------------------------

/// A side-channel alerting backend (PagerDuty, OpsGenie, etc.).
///
/// Implementers do the actual I/O to their respective APIs. The
/// [`AlertingExporter`] fans each high-severity event out to every
/// registered backend.
pub trait AlertBackend: Send + Sync {
    /// Human-readable backend name for logging and DLQ attribution.
    fn name(&self) -> &str;

    /// Dispatch a single alert. The implementation owns the HTTP transport.
    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>;
}

/// A structured alert payload passed to every [`AlertBackend`].
#[derive(Debug, Clone)]
pub struct Alert {
    /// Short, human-readable summary (one line).
    pub summary: String,
    /// Severity derived by [`derive_severity`].
    pub severity: AlertSeverity,
    /// Stable dedup key for alert grouping (guard + tool + receipt id).
    pub dedup_key: String,
    /// Guard name that produced the deny decision (or `"chio.kernel"`).
    pub guard: String,
    /// Tool name that was being invoked.
    pub tool_name: String,
    /// Tool server that was hosting the tool.
    pub tool_server: String,
    /// Receipt identifier for cross-referencing with the receipt log.
    pub receipt_id: String,
    /// Full serialized [`ChioReceipt`] for custom details / drill-down.
    pub receipt_json: serde_json::Value,
}

// -- PagerDuty backend --------------------------------------------------------

/// PagerDuty Events API v2 backend.
///
/// SECURITY: the routing key is wrapped in [`Zeroizing<String>`] so its
/// bytes are overwritten on drop.
pub struct PagerDutyBackend {
    routing_key: Zeroizing<String>,
    endpoint: String,
    client: reqwest::Client,
    egress_contract: HttpEgressContract,
}

impl PagerDutyBackend {
    /// Create a new PagerDuty backend with the default endpoint
    /// (`https://events.pagerduty.com`).
    ///
    /// Returns an error if the underlying HTTP client cannot be built (e.g.
    /// missing TLS backend). Fail-closed: callers must surface the error
    /// rather than silently constructing a backend without the configured
    /// 30s timeout.
    pub fn new(routing_key: String) -> Result<Self, ExportError> {
        Self::with_endpoint(routing_key, "https://events.pagerduty.com".to_string())
    }

    /// Create a new PagerDuty backend with a custom endpoint. Intended for
    /// integration tests against `wiremock`.
    ///
    /// Returns an error if the underlying HTTP client cannot be built. The
    /// 30s timeout is intentional and must not be silently dropped on
    /// builder failure.
    pub fn with_endpoint(routing_key: String, endpoint: String) -> Result<Self, ExportError> {
        // Fail closed on a plaintext endpoint, exactly like the webhook SOC sink:
        // the production serve wiring passes CHIO_SIEM_ALERT_PAGERDUTY_ENDPOINT
        // straight here, and an http:// value would send the PagerDuty routing
        // key over the wire in the clear. The
        // egress contract otherwise derives its allowed scheme FROM the endpoint,
        // so http:// would be accepted. Tests that need a plaintext loopback
        // wiremock target construct via with_endpoint_and_contract instead.
        crate::exporters::require_https_endpoint(
            &endpoint,
            "PagerDuty alert endpoint requires https: a plaintext http endpoint \
             would transmit the routing key without TLS",
        )?;
        let egress_contract = siem_endpoint_egress_contract("pagerduty", &endpoint)?;
        Self::with_endpoint_and_contract(routing_key, endpoint, egress_contract)
    }

    /// Construct a PagerDuty backend with a required [`HttpEgressContract`].
    pub fn with_endpoint_and_contract(
        routing_key: String,
        endpoint: String,
        egress_contract: HttpEgressContract,
    ) -> Result<Self, ExportError> {
        let client = client_builder_with_contract(&egress_contract)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                ExportError::HttpError(format!(
                    "failed to build PagerDuty HTTP client (timeout=30s): {e}"
                ))
            })?;
        let probe_url = format!("{}/v2/enqueue", endpoint.trim_end_matches('/'));
        egress_contract.enforce_url(&probe_url, 0).map_err(|err| {
            ExportError::HttpError(format!(
                "HttpEgressContract rejects PagerDuty endpoint: {err}"
            ))
        })?;
        Ok(Self {
            routing_key: Zeroizing::new(routing_key),
            endpoint,
            client,
            egress_contract,
        })
    }
}

impl AlertBackend for PagerDutyBackend {
    fn name(&self) -> &str {
        "pagerduty"
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async move {
            let url = format!("{}/v2/enqueue", self.endpoint.trim_end_matches('/'));
            let payload = serde_json::json!({
                "routing_key": self.routing_key.as_str(),
                "event_action": "trigger",
                "dedup_key": alert.dedup_key,
                "payload": {
                    "summary": alert.summary,
                    "source": "chio.kernel",
                    "severity": alert.severity.as_pagerduty(),
                    "component": alert.tool_name,
                    "group": alert.tool_server,
                    "class": alert.guard,
                    "custom_details": alert.receipt_json,
                }
            });

            // HttpEgressContract: every dispatch routes through send_with_contract.
            let contract = &self.egress_contract;
            let raw_request = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .build()
                .map_err(|e| {
                    ExportError::HttpError(format!("failed to build PagerDuty request: {e}"))
                })?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| {
                    ExportError::HttpError(format!("PagerDuty request failed: {err}"))
                })?;

            let status = response.status();
            if status.is_success() || status.as_u16() == 202 {
                return Ok(());
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            Err(ExportError::HttpError(format!(
                "PagerDuty returned {status}: {body}"
            )))
        })
    }
}

// -- OpsGenie backend ---------------------------------------------------------

/// OpsGenie Alerts API v2 backend.
///
/// SECURITY: the API key is wrapped in [`Zeroizing<String>`] so its bytes
/// are overwritten on drop.
pub struct OpsGenieBackend {
    api_key: Zeroizing<String>,
    endpoint: String,
    client: reqwest::Client,
    tags: Vec<String>,
    egress_contract: HttpEgressContract,
}

impl OpsGenieBackend {
    /// Create a new OpsGenie backend with the default endpoint
    /// (`https://api.opsgenie.com`).
    ///
    /// Returns an error if the underlying HTTP client cannot be built (e.g.
    /// missing TLS backend). Fail-closed: callers must surface the error
    /// rather than silently constructing a backend without the configured
    /// 30s timeout.
    pub fn new(api_key: String) -> Result<Self, ExportError> {
        Self::with_endpoint(api_key, "https://api.opsgenie.com".to_string())
    }

    /// Create a new OpsGenie backend with a custom endpoint. Intended for
    /// integration tests against `wiremock`.
    ///
    /// Returns an error if the underlying HTTP client cannot be built. The
    /// 30s timeout is intentional and must not be silently dropped on
    /// builder failure.
    pub fn with_endpoint(api_key: String, endpoint: String) -> Result<Self, ExportError> {
        // Fail closed on a plaintext endpoint, exactly like the webhook SOC sink:
        // the production serve wiring passes CHIO_SIEM_ALERT_OPSGENIE_ENDPOINT
        // straight here, and an http:// value would send the OpsGenie API key in
        // the clear. The egress contract
        // otherwise derives its allowed scheme FROM the endpoint. Tests needing a
        // plaintext loopback wiremock target use with_endpoint_and_contract.
        crate::exporters::require_https_endpoint(
            &endpoint,
            "OpsGenie alert endpoint requires https: a plaintext http endpoint \
             would transmit the API key without TLS",
        )?;
        let egress_contract = siem_endpoint_egress_contract("opsgenie", &endpoint)?;
        Self::with_endpoint_and_contract(api_key, endpoint, egress_contract)
    }

    /// Construct an OpsGenie backend with a required [`HttpEgressContract`].
    pub fn with_endpoint_and_contract(
        api_key: String,
        endpoint: String,
        egress_contract: HttpEgressContract,
    ) -> Result<Self, ExportError> {
        let client = client_builder_with_contract(&egress_contract)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                ExportError::HttpError(format!(
                    "failed to build OpsGenie HTTP client (timeout=30s): {e}"
                ))
            })?;
        let probe_url = format!("{}/v2/alerts", endpoint.trim_end_matches('/'));
        egress_contract.enforce_url(&probe_url, 0).map_err(|err| {
            ExportError::HttpError(format!(
                "HttpEgressContract rejects OpsGenie endpoint: {err}"
            ))
        })?;
        Ok(Self {
            api_key: Zeroizing::new(api_key),
            endpoint,
            client,
            tags: Vec::new(),
            egress_contract,
        })
    }

    /// Attach static tags to every alert dispatched by this backend.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Build the required [`HttpEgressContract`] for a SIEM egress endpoint by
/// deriving the allowed scheme/authority from the endpoint URL. Used
/// by both the alert-backend endpoints (PagerDuty/OpsGenie) and the SOC export
/// sinks (e.g. the generic webhook) so every SIEM egress path derives its
/// contract the same way. `namespace_prefix` scopes the tenant egress namespace
/// (`siem:{prefix}:{authority}`); loopback/link-local/ULA denials are relaxed
/// only when the endpoint explicitly targets such an address.
pub(crate) fn siem_endpoint_egress_contract(
    namespace_prefix: &str,
    endpoint: &str,
) -> Result<HttpEgressContract, ExportError> {
    let parsed = url::Url::parse(endpoint).map_err(|error| {
        ExportError::HttpError(format!(
            "invalid {namespace_prefix} endpoint URL `{endpoint}`: {error}"
        ))
    })?;
    let authority = normalized_alert_authority(&parsed)?;
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(authority.clone());
    let mut deny_loopback = true;
    let mut deny_link_local = true;
    let mut deny_ipv6_ula = true;

    if let Some(host) = parsed.host() {
        match host {
            url::Host::Domain(domain) => {
                let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                if matches!(normalized.as_str(), "localhost" | "localhost.localdomain") {
                    deny_loopback = false;
                }
            }
            url::Host::Ipv4(address) => {
                if address.is_loopback() {
                    deny_loopback = false;
                }
                if address.is_link_local() {
                    deny_link_local = false;
                }
            }
            url::Host::Ipv6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    if mapped.is_loopback() {
                        deny_loopback = false;
                    }
                    if mapped.is_link_local() {
                        deny_link_local = false;
                    }
                }
                if address.is_loopback() {
                    deny_loopback = false;
                }
                if is_alert_ipv6_unicast_link_local(&address) {
                    deny_link_local = false;
                }
                if is_alert_ipv6_unique_local(&address) {
                    deny_ipv6_ula = false;
                }
            }
        }
    }

    let contract = HttpEgressContract {
        tenant_egress_namespace: format!("siem:{namespace_prefix}:{authority}"),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback,
        deny_link_local,
        deny_ipv6_ula,
        max_redirect_chain: 3,
        max_response_bytes: 1024 * 1024,
    };
    contract.validate().map_err(|error| {
        ExportError::HttpError(format!(
            "{namespace_prefix} egress contract is invalid: {error}"
        ))
    })?;
    Ok(contract)
}

fn normalized_alert_authority(url: &url::Url) -> Result<String, ExportError> {
    let host = url.host_str().ok_or_else(|| {
        ExportError::HttpError(format!("endpoint URL `{url}` is missing an authority"))
    })?;
    let host = match url.host() {
        Some(url::Host::Ipv6(_)) => format!("[{}]", host.to_ascii_lowercase()),
        Some(url::Host::Domain(_)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn is_alert_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

fn is_alert_ipv6_unique_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

impl AlertBackend for OpsGenieBackend {
    fn name(&self) -> &str {
        "opsgenie"
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async move {
            let url = format!("{}/v2/alerts", self.endpoint.trim_end_matches('/'));

            let mut tags = self.tags.clone();
            tags.push(format!("guard:{}", alert.guard));
            tags.push(format!("severity:{}", alert.severity.as_tag()));
            tags.push(format!("tool:{}", alert.tool_name));

            let body = serde_json::json!({
                "message": alert.summary,
                "alias": alert.dedup_key,
                "description": alert.summary,
                "priority": alert.severity.as_opsgenie_priority(),
                "tags": tags,
                "details": alert.receipt_json,
            });

            // HttpEgressContract: every dispatch routes through send_with_contract.
            let contract = &self.egress_contract;
            let raw_request = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header(
                    "Authorization",
                    format!("GenieKey {}", self.api_key.as_str()),
                )
                .json(&body)
                .build()
                .map_err(|e| {
                    ExportError::HttpError(format!("failed to build OpsGenie request: {e}"))
                })?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| ExportError::HttpError(format!("OpsGenie request failed: {err}")))?;

            let status = response.status();
            if status.is_success() || status.as_u16() == 202 {
                return Ok(());
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            Err(ExportError::HttpError(format!(
                "OpsGenie returned {status}: {body}"
            )))
        })
    }
}

// -- AlertingExporter ---------------------------------------------------------

/// Configuration for the [`AlertingExporter`].
#[derive(Debug, Clone)]
pub struct AlertingConfig {
    /// Minimum severity required to dispatch an alert. Default:
    /// [`AlertSeverity::High`] (so Medium denies do NOT page on-call).
    pub min_severity: AlertSeverity,
    /// Guards whose name appears here are never alerted on.
    pub exclude_guards: Vec<String>,
    /// When non-empty, only events whose guard matches one of these entries
    /// are alerted on.
    pub include_guards: Vec<String>,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            min_severity: AlertSeverity::High,
            exclude_guards: Vec::new(),
            include_guards: Vec::new(),
        }
    }
}

/// Builder for [`AlertingExporter`].
pub struct AlertingExporterBuilder {
    config: AlertingConfig,
    backends: Vec<Arc<dyn AlertBackend>>,
    metrics: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
}

impl AlertingExporterBuilder {
    /// Attach a backend to the builder. Accepts owned `Box<dyn AlertBackend>`
    /// so the caller keeps full control over the concrete type.
    #[must_use]
    pub fn with_backend(mut self, backend: Box<dyn AlertBackend>) -> Self {
        self.backends.push(Arc::from(backend));
        self
    }

    /// Attach an `Arc`-wrapped backend (useful when the backend is shared
    /// with other callers, e.g. a background heartbeat loop).
    #[must_use]
    pub fn with_backend_arc(mut self, backend: Arc<dyn AlertBackend>) -> Self {
        self.backends.push(backend);
        self
    }

    /// Attach a metrics sink. Defaults to no-op.
    #[must_use]
    pub fn with_metrics_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
    ) -> Self {
        self.metrics = sink;
        self
    }

    /// Finalize the builder into a usable [`AlertingExporter`].
    #[must_use]
    pub fn build(self) -> AlertingExporter {
        AlertingExporter {
            config: self.config,
            backends: self.backends,
            metrics: self.metrics,
        }
    }
}

/// Alerting exporter: filters a batch of SIEM events to those that should
/// trigger an alert, then fans each one out to every configured
/// [`AlertBackend`].
pub struct AlertingExporter {
    config: AlertingConfig,
    backends: Vec<Arc<dyn AlertBackend>>,
    // Consumed by `export_batch` to emit alert-dispatch outcome/latency metrics
    // on every real dispatch. The SIEM serve-mode host installs a registry-backed
    // sink via `with_metrics_sink`; headless callers keep the no-op default.
    metrics: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
}

impl AlertingExporter {
    /// Start a new builder with the given configuration.
    #[must_use]
    pub fn builder(config: AlertingConfig) -> AlertingExporterBuilder {
        AlertingExporterBuilder {
            config,
            backends: Vec::new(),
            metrics: crate::metrics_sink::noop_metrics_sink(),
        }
    }

    /// Return the number of configured alert backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    fn should_alert(&self, event: &SiemEvent) -> bool {
        // Only fire on explicit Deny; Allow/Cancelled/Incomplete never page.
        let (guard, _reason) = match &event.receipt.decision {
            Some(Decision::Deny { guard, reason }) => (guard.clone(), reason.clone()),
            _ => return false,
        };

        if derive_event_severity(event) < self.config.min_severity {
            return false;
        }
        if self.config.exclude_guards.iter().any(|g| g == &guard) {
            return false;
        }
        if !self.config.include_guards.is_empty()
            && !self.config.include_guards.iter().any(|g| g == &guard)
        {
            return false;
        }
        true
    }

    fn build_alert(event: &SiemEvent) -> Result<Alert, ExportError> {
        let (guard, reason) = match &event.receipt.decision {
            Some(Decision::Deny { guard, reason }) => (guard.clone(), reason.clone()),
            _ => ("chio.kernel".to_string(), "non-deny event".to_string()),
        };

        let severity = derive_event_severity(event);
        let summary = format!(
            "Chio guard deny: {} ({}) on {}/{}",
            guard, reason, event.receipt.tool_server, event.receipt.tool_name
        );

        let dedup_key = format!(
            "{}::{}::{}",
            guard, event.receipt.tool_name, event.receipt.id
        );

        let receipt_json = serde_json::to_value(&event.receipt).map_err(|e| {
            ExportError::SerializationError(format!(
                "failed to serialize receipt {}: {e}",
                event.receipt.id
            ))
        })?;

        Ok(Alert {
            summary,
            severity,
            dedup_key,
            guard,
            tool_name: event.receipt.tool_name.clone(),
            tool_server: event.receipt.tool_server.clone(),
            receipt_id: event.receipt.id.clone(),
            receipt_json,
        })
    }
}

impl Exporter for AlertingExporter {
    fn name(&self) -> &str {
        "alerting"
    }

    /// Alerting is a NOTIFICATION overlay, not a durable SOC audit-export sink.
    /// Its outcomes are recorded on the `chio_alert_dispatch_total` family by
    /// this exporter itself, so the manager must not also count it on
    /// `chio_soc_export_total` / `_lag` / SOC DLQ depth; otherwise a failed
    /// PagerDuty/OpsGenie dispatch would burn the SOC export SLO while audit
    /// export is healthy.
    fn is_soc_export_sink(&self) -> bool {
        false
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() || self.backends.is_empty() {
                return Ok(events.len());
            }

            let mut dispatched = 0usize;
            let mut failed = 0usize;
            let mut first_err: Option<String> = None;

            for event in events {
                if !self.should_alert(event) {
                    // Counts toward the processed total returned on success
                    // (consistent with the alerting-disabled path returning
                    // events.len()); only threshold-meeting events are alerted.
                    dispatched += 1;
                    continue;
                }

                let alert = Self::build_alert(event)?;
                let mut any_failure = false;

                for backend in &self.backends {
                    let route = backend.name().to_string();
                    let started = std::time::Instant::now();
                    let dispatch_result = backend.dispatch(&alert).await;
                    let outcome = if dispatch_result.is_ok() {
                        "success"
                    } else {
                        "error"
                    };
                    // Record every dispatch outcome and latency so the p1
                    // ChioAlertDispatchMetricsMissing backstop and the PagerDuty
                    // dispatch SLO have a real producer.
                    self.metrics.record_alert_dispatch(&route, outcome);
                    self.metrics.observe_alert_dispatch_latency(
                        &route,
                        outcome,
                        started.elapsed().as_secs_f64(),
                    );
                    if let Err(err) = dispatch_result {
                        any_failure = true;
                        if first_err.is_none() {
                            first_err = Some(format!("{route}: {err}"));
                        }
                        tracing::warn!(
                            backend = %route,
                            receipt_id = %event.receipt.id,
                            error = %redact_for_operator_log(&err),
                            "alert backend dispatch failed"
                        );
                    }
                }

                if any_failure {
                    failed += 1;
                } else {
                    dispatched += 1;
                }
            }

            if failed == 0 {
                return Ok(dispatched);
            }

            if dispatched == 0 {
                return Err(ExportError::HttpError(first_err.unwrap_or_else(|| {
                    "alerting exporter: all dispatches failed".to_string()
                })));
            }

            Err(ExportError::PartialFailure {
                succeeded: dispatched,
                failed,
                details: first_err
                    .unwrap_or_else(|| "alerting exporter: partial failure".to_string()),
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceiptBody, decision::ToolCallAction, metadata::GuardEvidence,
        metadata::ReceiptSemanticFields,
    };

    /// The production serve wiring passes the operator
    /// `CHIO_SIEM_ALERT_*_ENDPOINT` value straight to `with_endpoint`, so a
    /// plaintext http:// endpoint must fail closed the same way the webhook SOC
    /// sink does, or the routing key / API key would be sent without TLS.
    #[test]
    fn pagerduty_with_endpoint_rejects_plaintext_accepts_https() {
        let err = match PagerDutyBackend::with_endpoint(
            "rk".to_string(),
            "http://events.pagerduty.com".to_string(),
        ) {
            Ok(_) => panic!("a plaintext http PagerDuty endpoint must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("https"),
            "the rejection must name the https requirement: {err}"
        );
        assert!(
            PagerDutyBackend::with_endpoint(
                "rk".to_string(),
                "https://events.pagerduty.com".to_string()
            )
            .is_ok(),
            "an https PagerDuty endpoint must build"
        );
    }

    #[test]
    fn opsgenie_with_endpoint_rejects_plaintext_accepts_https() {
        let err = match OpsGenieBackend::with_endpoint(
            "api-key".to_string(),
            "http://api.opsgenie.com".to_string(),
        ) {
            Ok(_) => panic!("a plaintext http OpsGenie endpoint must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("https"),
            "the rejection must name the https requirement: {err}"
        );
        assert!(
            OpsGenieBackend::with_endpoint(
                "api-key".to_string(),
                "https://api.opsgenie.com".to_string()
            )
            .is_ok(),
            "an https OpsGenie endpoint must build"
        );
    }

    fn deny_receipt(guard: &str) -> ChioReceipt {
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("hash receipt parameters");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "alert-rcpt-1".to_string(),
                timestamp: 1_700_000_000,
                capability_id: "cap".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action,
                decision: Some(Decision::Deny {
                    reason: "denied".to_string(),
                    guard: guard.to_string(),
                }),
                receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
                boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
                redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "c".to_string(),
                policy_hash: "p".to_string(),
                evidence: vec![GuardEvidence {
                    guard_name: guard.to_string(),
                    verdict: false,
                    details: None,
                }],
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign")
    }

    fn allow_receipt() -> ChioReceipt {
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("hash receipt parameters");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "alert-rcpt-2".to_string(),
                timestamp: 1_700_000_000,
                capability_id: "cap".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action,
                decision: Some(Decision::Allow),
                receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
                boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
                redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "c".to_string(),
                policy_hash: "p".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign")
    }

    fn trace_allow_receipt() -> ChioReceipt {
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("hash receipt parameters");
        let semantics = ReceiptSemanticFields::trace_detect_only();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "alert-rcpt-trace".to_string(),
                timestamp: 1_700_000_000,
                capability_id: "cap".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action,
                decision: None,
                receipt_kind: semantics.receipt_kind,
                boundary_class: semantics.boundary_class,
                observation_outcome: semantics.observation_outcome,
                tool_origin: semantics.tool_origin,
                redaction_mode: semantics.redaction_mode,
                actor_chain: semantics.actor_chain,
                content_hash: "c".to_string(),
                policy_hash: "p".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::Verified,
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign")
    }

    #[test]
    fn severity_allow_clean_is_info() {
        assert_eq!(derive_severity(&allow_receipt()), AlertSeverity::Info);
    }

    #[test]
    fn severity_trace_allow_is_not_authorization_info() {
        let receipt = trace_allow_receipt();
        assert!(!receipt.is_allowed());
        assert_eq!(derive_severity(&receipt), AlertSeverity::Low);
    }

    #[test]
    fn severity_deny_secret_is_critical() {
        assert_eq!(
            derive_severity(&deny_receipt("SecretLeakGuard")),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn severity_deny_egress_is_critical() {
        assert_eq!(
            derive_severity(&deny_receipt("EgressGuard")),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn severity_deny_path_is_high() {
        assert_eq!(
            derive_severity(&deny_receipt("ForbiddenPathGuard")),
            AlertSeverity::High
        );
    }

    #[test]
    fn severity_deny_generic_is_medium() {
        assert_eq!(
            derive_severity(&deny_receipt("CustomGuard")),
            AlertSeverity::Medium
        );
    }

    #[test]
    fn allow_never_alerts() {
        let exporter = AlertingExporter::builder(AlertingConfig::default()).build();
        let event = SiemEvent::from_receipt(allow_receipt());
        assert!(!exporter.should_alert(&event));
    }

    #[test]
    fn medium_deny_does_not_alert_by_default() {
        let exporter = AlertingExporter::builder(AlertingConfig::default()).build();
        let event = SiemEvent::from_receipt(deny_receipt("CustomGuard"));
        assert!(!exporter.should_alert(&event));
    }

    #[test]
    fn high_deny_alerts_by_default() {
        let exporter = AlertingExporter::builder(AlertingConfig::default()).build();
        let event = SiemEvent::from_receipt(deny_receipt("ForbiddenPathGuard"));
        assert!(exporter.should_alert(&event));
    }

    #[test]
    fn exclude_guards_suppresses_alerts() {
        let cfg = AlertingConfig {
            min_severity: AlertSeverity::Medium,
            exclude_guards: vec!["NoisyGuard".to_string()],
            include_guards: Vec::new(),
        };
        let exporter = AlertingExporter::builder(cfg).build();
        let event = SiemEvent::from_receipt(deny_receipt("NoisyGuard"));
        assert!(!exporter.should_alert(&event));
    }

    #[test]
    fn include_guards_restricts_alerts() {
        let cfg = AlertingConfig {
            min_severity: AlertSeverity::Medium,
            exclude_guards: Vec::new(),
            include_guards: vec!["ForbiddenPathGuard".to_string()],
        };
        let exporter = AlertingExporter::builder(cfg).build();
        let match_event = SiemEvent::from_receipt(deny_receipt("ForbiddenPathGuard"));
        let miss_event = SiemEvent::from_receipt(deny_receipt("OtherGuard"));
        assert!(exporter.should_alert(&match_event));
        assert!(!exporter.should_alert(&miss_event));
    }

    #[test]
    fn severity_ordering_is_total() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }
}
