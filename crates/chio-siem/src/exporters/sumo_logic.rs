//! Sumo Logic HTTP Source exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to a Sumo Logic collector's HTTP Source URL.
//! Authentication is embedded in the URL token itself (no separate auth
//! header). The exporter supports three on-the-wire formats:
//!
//! - [`SumoLogicFormat::Json`]: newline-delimited JSON, one receipt per line.
//! - [`SumoLogicFormat::Text`]: compact one-line text string per event.
//! - [`SumoLogicFormat::KeyValue`]: Splunk-style `k=v` pairs per event.
//!
//! Metadata headers (`X-Sumo-Category`, `X-Sumo-Name`, `X-Sumo-Host`) attach
//! Sumo Logic metadata for routing and parser selection.
//!
//! Port of ClawdStrike's `hushd/src/siem/exporters/sumo_logic.rs`. The
//! optional gzip compression from the ClawdStrike exporter is intentionally
//! omitted here: gzip is not part of the 12.1 acceptance criteria and would
//! add a `flate2` dependency to `chio-siem`. Compression can be added later
//! without breaking the exporter's public surface.

use std::time::Duration;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::exporters::require_https_endpoint;
use crate::redaction::redact_for_operator_log;
use chio_core::receipt::Decision;
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

/// On-the-wire format for the Sumo Logic batch body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SumoLogicFormat {
    /// Newline-delimited JSON, one full [`crate::event::SiemEvent`] per line.
    #[default]
    Json,
    /// Compact single-line text per event.
    Text,
    /// Splunk-style `key=value` pairs per event.
    KeyValue,
}

/// Configuration for the Sumo Logic exporter.
#[derive(Debug, Clone)]
pub struct SumoLogicConfig {
    /// Sumo Logic HTTP Source collector URL (includes the auth token).
    ///
    /// Must start with `https://`. HTTP is rejected because the URL carries
    /// the collector's secret token.
    pub http_source_url: String,
    /// `X-Sumo-Category` header. Default: `"security/chio"`.
    pub source_category: String,
    /// `X-Sumo-Name` header. Default: `"chio"`.
    pub source_name: String,
    /// Optional `X-Sumo-Host` header. When `None`, falls back to the
    /// `HOSTNAME` environment variable, then to `"unknown"`.
    pub source_host: Option<String>,
    /// On-the-wire format. Default: [`SumoLogicFormat::Json`].
    pub format: SumoLogicFormat,
    /// HTTP request timeout. Default: 30 seconds.
    pub timeout: Duration,
    /// Typed HTTP egress contract enforced before every dispatch and on
    /// every redirect hop. Required in production.
    pub egress_contract: Option<HttpEgressContract>,
}

impl Default for SumoLogicConfig {
    fn default() -> Self {
        Self {
            http_source_url: String::new(),
            source_category: "security/chio".to_string(),
            source_name: "chio".to_string(),
            source_host: None,
            format: SumoLogicFormat::Json,
            timeout: Duration::from_secs(30),
            egress_contract: None,
        }
    }
}

/// SIEM exporter that POSTs Chio receipt batches to a Sumo Logic HTTP Source.
pub struct SumoLogicExporter {
    config: SumoLogicConfig,
    client: reqwest::Client,
    allow_plaintext: bool,
}

impl SumoLogicExporter {
    /// Create a new `SumoLogicExporter`.
    ///
    /// Returns an error if the HTTP source URL is empty, uses a scheme other
    /// than `https://`, or if the HTTP client cannot be built.
    pub fn new(mut config: SumoLogicConfig) -> Result<Self, ExportError> {
        config.http_source_url = config.http_source_url.trim().to_string();

        if config.http_source_url.is_empty() {
            return Err(ExportError::HttpError(
                "Sumo Logic http_source_url must not be empty".to_string(),
            ));
        }
        // RFC 3986 schemes are case-insensitive; parse the URL and require an
        // exact `https` scheme to prevent `HTTP://` (uppercase) endpoints
        // from bypassing the cleartext check.
        require_https_endpoint(
            &config.http_source_url,
            "Sumo Logic http_source_url must use https:// -- the collector \
             token is embedded in the URL and must not travel over cleartext",
        )?;
        // HttpEgressContract: every Sumo Logic dispatch must run through
        // the typed egress contract.
        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError("Sumo Logic exporter requires an HttpEgressContract".to_string())
        })?;
        contract
            .enforce_url(&config.http_source_url, 0)
            .map_err(|err| {
                ExportError::HttpError(format!("HttpEgressContract rejects Sumo URL: {err}"))
            })?;

        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            client,
            allow_plaintext: false,
        })
    }

    /// Construct a `SumoLogicExporter` that accepts `http://` URLs. Intended
    /// for integration tests against `wiremock`; do not use in production
    /// because the Sumo Logic collector token is embedded in the URL.
    pub fn new_plaintext_for_tests(mut config: SumoLogicConfig) -> Result<Self, ExportError> {
        config.http_source_url = config.http_source_url.trim().to_string();
        if config.http_source_url.is_empty() {
            return Err(ExportError::HttpError(
                "Sumo Logic http_source_url must not be empty".to_string(),
            ));
        }
        if config.egress_contract.is_none() {
            let url = url::Url::parse(&config.http_source_url).map_err(|e| {
                ExportError::HttpError(format!("invalid Sumo URL for test contract: {e}"))
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
                "Sumo Logic test exporter requires an HttpEgressContract".to_string(),
            )
        })?;
        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            client,
            allow_plaintext: true,
        })
    }

    fn hostname(&self) -> String {
        if let Some(h) = &self.config.source_host {
            return h.clone();
        }
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }

    fn format_event(&self, event: &SiemEvent) -> Result<String, ExportError> {
        let reason = redact_for_operator_log(decision_reason(&event.receipt.decision));
        match self.config.format {
            SumoLogicFormat::Json => serde_json::to_string(event).map_err(|e| {
                ExportError::SerializationError(format!(
                    "failed to serialize receipt {}: {e}",
                    event.receipt.id
                ))
            }),
            SumoLogicFormat::Text => Ok(format!(
                "ts={} id={} tool={} tool_server={} decision={} reason={}",
                event.receipt.timestamp,
                event.receipt.id,
                event.receipt.tool_name,
                event.receipt.tool_server,
                decision_label(&event.receipt.decision),
                reason.replace('\n', " "),
            )),
            SumoLogicFormat::KeyValue => Ok(format!(
                "receipt_id={} timestamp={} tool={} tool_server={} capability={} decision={} reason=\"{}\"",
                event.receipt.id,
                event.receipt.timestamp,
                event.receipt.tool_name,
                event.receipt.tool_server,
                event.receipt.capability_id,
                decision_label(&event.receipt.decision),
                reason.replace('"', "'"),
            )),
        }
    }

    fn build_body(&self, events: &[SiemEvent]) -> Result<String, ExportError> {
        let mut out = String::new();
        for event in events {
            out.push_str(&self.format_event(event)?);
            out.push('\n');
        }
        Ok(out)
    }

    fn content_type(&self) -> &'static str {
        match self.config.format {
            SumoLogicFormat::Json => "application/json",
            SumoLogicFormat::Text | SumoLogicFormat::KeyValue => "text/plain",
        }
    }
}

impl Exporter for SumoLogicExporter {
    fn name(&self) -> &str {
        "sumo-logic"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            let body = self.build_body(events)?;
            let hostname = self.hostname();

            // allow_plaintext is only set via new_plaintext_for_tests; production
            // paths enforce the https:// constraint at construction time.
            let _ = self.allow_plaintext;

            // HttpEgressContract: every dispatch routes through send_with_contract.
            let contract = self.config.egress_contract.as_ref().ok_or_else(|| {
                ExportError::HttpError(
                    "Sumo Logic exporter is missing HttpEgressContract; substrate fails closed"
                        .to_string(),
                )
            })?;
            let raw_request = self
                .client
                .post(&self.config.http_source_url)
                .header("Content-Type", self.content_type())
                .header("X-Sumo-Category", &self.config.source_category)
                .header("X-Sumo-Name", &self.config.source_name)
                .header("X-Sumo-Host", &hostname)
                .body(body)
                .build()
                .map_err(|e| {
                    ExportError::HttpError(format!("failed to build Sumo request: {e}"))
                })?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| {
                    ExportError::HttpError(format!("Sumo HTTP source request failed: {err}"))
                })?;

            let status = response.status();
            if status.is_success() || status.as_u16() == 202 {
                return Ok(events.len());
            }

            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            let body_text = redact_for_operator_log(body_text);
            Err(ExportError::HttpError(format!(
                "Sumo Logic returned {status}: {body_text}"
            )))
        })
    }
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn decision_reason(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allowed".to_string(),
        Decision::Deny { reason, guard } => format!("{guard}: {reason}"),
        Decision::Cancelled { reason } => reason.clone(),
        Decision::Incomplete { reason } => reason.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_url() {
        let cfg = SumoLogicConfig {
            http_source_url: "   ".to_string(),
            ..SumoLogicConfig::default()
        };
        assert!(SumoLogicExporter::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_plaintext_http() {
        let cfg = SumoLogicConfig {
            http_source_url: "http://collectors.sumologic.com/foo".to_string(),
            ..SumoLogicConfig::default()
        };
        assert!(SumoLogicExporter::new(cfg).is_err());
    }

    #[test]
    fn new_accepts_https() {
        let cfg = SumoLogicConfig {
            http_source_url: "https://collectors.sumologic.com/foo".to_string(),
            egress_contract: Some(HttpEgressContract::permissive_for_tests(
                "collectors.sumologic.com",
            )),
            ..SumoLogicConfig::default()
        };
        assert!(SumoLogicExporter::new(cfg).is_ok());
    }
}
