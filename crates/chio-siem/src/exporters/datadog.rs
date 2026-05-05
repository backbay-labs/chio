//! Datadog Logs API exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to Datadog's Log Intake endpoint
//! (`https://http-intake.logs.<site>/api/v2/logs`) as a JSON array of log
//! entries. Each log entry carries:
//!
//! - `message`: the first deny reason, or `"chio.receipt"` on Allow.
//! - `ddsource`/`service`: configurable source + service fields.
//! - `status`: Datadog status derived from [`AlertSeverity`] + decision.
//! - `ddtags`: comma-separated tags including `tool`, `server`, `outcome`,
//!   and every guard name from `receipt.evidence`.
//! - `event`: the full [`ChioReceipt`] payload for analyst drill-down.
//!
//! Port of ClawdStrike's `hushd/src/siem/exporters/datadog.rs` adapted to the
//! Chio `Exporter` trait (dyn-compatible `Pin<Box<dyn Future>>`) and
//! Chio receipt shape (`Decision::{Allow, Deny, ...}`).

use std::time::Duration;

use crate::alerting::{derive_severity, AlertSeverity};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::redaction::redact_for_operator_log;
use chio_core::receipt::Decision;

/// Configuration for the Datadog Logs exporter.
#[derive(Debug, Clone)]
pub struct DatadogConfig {
    /// Datadog API key sent as the `DD-API-KEY` header.
    pub api_key: String,
    /// Datadog site (e.g. `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`).
    /// The base URL for log intake is built as
    /// `https://http-intake.logs.<site>/api/v2/logs`.
    pub site: String,
    /// Logical service name sent with every log entry. Default: `"chio"`.
    pub service: String,
    /// `ddsource` field sent with every log entry. Default: `"chio"`.
    pub source: String,
    /// Static tags merged into every log entry's `ddtags` field.
    pub tags: Vec<String>,
    /// Optional `hostname` field. When `None`, falls back to the `HOSTNAME`
    /// environment variable, then to `"unknown"`.
    pub hostname: Option<String>,
    /// HTTP request timeout. Default: 30 seconds.
    pub timeout: Duration,
}

impl Default for DatadogConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            site: "datadoghq.com".to_string(),
            service: "chio".to_string(),
            source: "chio".to_string(),
            tags: Vec::new(),
            hostname: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// SIEM exporter that POSTs Chio receipt batches to Datadog's Log Intake API.
pub struct DatadogExporter {
    config: DatadogConfig,
    client: reqwest::Client,
    logs_url: String,
}

impl DatadogExporter {
    /// Create a new `DatadogExporter`.
    ///
    /// Returns an error if the API key is empty, if the configured site is
    /// blank, or if the HTTP client cannot be constructed. Fail-closed at
    /// construction keeps runtime delivery hot-path free of config errors.
    pub fn new(mut config: DatadogConfig) -> Result<Self, ExportError> {
        config.site = config
            .site
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('/')
            .to_string();

        if config.api_key.trim().is_empty() {
            return Err(ExportError::HttpError(
                "Datadog api_key must not be empty".to_string(),
            ));
        }
        if config.site.is_empty() {
            return Err(ExportError::HttpError(
                "Datadog site must not be empty (e.g. datadoghq.com)".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        let logs_url = format!("https://http-intake.logs.{}/api/v2/logs", config.site);
        Ok(Self {
            config,
            client,
            logs_url,
        })
    }

    /// Create a `DatadogExporter` whose log intake URL points at an arbitrary
    /// `base_url`. Intended for integration tests against `wiremock`; the
    /// normal [`DatadogExporter::new`] constructor always targets the real
    /// `https://http-intake.logs.<site>` intake.
    pub fn new_with_base_url_for_tests(
        mut config: DatadogConfig,
        base_url: &str,
    ) -> Result<Self, ExportError> {
        if config.api_key.trim().is_empty() {
            config.api_key = "test-api-key".to_string();
        }
        if config.site.trim().is_empty() {
            config.site = "datadoghq.com".to_string();
        }

        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

        let logs_url = format!("{}/api/v2/logs", base_url.trim_end_matches('/'));
        Ok(Self {
            config,
            client,
            logs_url,
        })
    }

    fn hostname(&self) -> String {
        if let Some(h) = &self.config.hostname {
            return h.clone();
        }
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }

    /// Map Chio severity + decision to a Datadog status string
    /// (<https://docs.datadoghq.com/logs/log_configuration/attributes_naming_convention/#reserved-attributes>).
    fn datadog_status(severity: AlertSeverity, allow: bool) -> &'static str {
        if !allow {
            return match severity {
                AlertSeverity::Critical => "critical",
                AlertSeverity::High => "error",
                AlertSeverity::Medium | AlertSeverity::Low => "warn",
                AlertSeverity::Info => "info",
            };
        }
        match severity {
            AlertSeverity::Critical => "critical",
            AlertSeverity::High => "error",
            AlertSeverity::Medium | AlertSeverity::Low => "warn",
            AlertSeverity::Info => "info",
        }
    }

    fn build_payload(&self, events: &[SiemEvent]) -> Result<Vec<serde_json::Value>, ExportError> {
        let hostname = self.hostname();
        let mut logs = Vec::with_capacity(events.len());

        for ev in events {
            let receipt = &ev.receipt;
            let (allow, guard_label, reason) = match &receipt.decision {
                Decision::Allow => (true, "allow", "chio.receipt".to_string()),
                Decision::Deny { reason, guard } => (false, guard.as_str(), reason.clone()),
                Decision::Cancelled { reason } => (false, "cancelled", reason.clone()),
                Decision::Incomplete { reason } => (false, "incomplete", reason.clone()),
            };
            let reason = redact_for_operator_log(reason);

            let severity = derive_severity(receipt);

            let mut tags = self.config.tags.clone();
            tags.push(format!("tool:{}", sanitize_tag_value(&receipt.tool_name)));
            tags.push(format!(
                "tool_server:{}",
                sanitize_tag_value(&receipt.tool_server)
            ));
            tags.push(format!("guard:{}", sanitize_tag_value(guard_label)));
            tags.push(format!(
                "severity:{}",
                sanitize_tag_value(severity.as_tag())
            ));
            tags.push(format!("outcome:{}", if allow { "allow" } else { "deny" }));

            for guard in &receipt.evidence {
                tags.push(format!(
                    "evidence_guard:{}",
                    sanitize_tag_value(&guard.guard_name)
                ));
            }

            let event_json = serde_json::to_value(receipt).map_err(|e| {
                ExportError::SerializationError(format!(
                    "failed to serialize receipt {}: {e}",
                    receipt.id
                ))
            })?;

            logs.push(serde_json::json!({
                "message": reason,
                "ddsource": self.config.source,
                "service": self.config.service,
                "hostname": hostname,
                "status": Self::datadog_status(severity, allow),
                "ddtags": tags.join(","),
                "event": event_json,
            }));
        }

        Ok(logs)
    }
}

impl Exporter for DatadogExporter {
    fn name(&self) -> &str {
        "datadog"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            let logs = self.build_payload(events)?;

            let response = self
                .client
                .post(&self.logs_url)
                .header("DD-API-KEY", &self.config.api_key)
                .header("Content-Type", "application/json")
                .json(&logs)
                .send()
                .await
                .map_err(|e| ExportError::HttpError(format!("Datadog logs request failed: {e}")))?;

            let status = response.status();
            // Datadog returns 202 Accepted on success.
            if status.is_success() || status.as_u16() == 202 {
                return Ok(events.len());
            }

            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            let body = redact_for_operator_log(body);
            Err(ExportError::HttpError(format!(
                "Datadog returned {status}: {body}"
            )))
        })
    }
}

fn sanitize_tag_value(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            ' ' | ',' | '\n' | '\r' | '\t' => '_',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_api_key() {
        let cfg = DatadogConfig {
            api_key: "   ".to_string(),
            ..DatadogConfig::default()
        };
        assert!(DatadogExporter::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_empty_site() {
        let cfg = DatadogConfig {
            api_key: "key".to_string(),
            site: "".to_string(),
            ..DatadogConfig::default()
        };
        assert!(DatadogExporter::new(cfg).is_err());
    }

    #[test]
    fn datadog_status_maps_deny_to_error_or_critical() {
        assert_eq!(
            DatadogExporter::datadog_status(AlertSeverity::Critical, false),
            "critical"
        );
        assert_eq!(
            DatadogExporter::datadog_status(AlertSeverity::High, false),
            "error"
        );
        assert_eq!(
            DatadogExporter::datadog_status(AlertSeverity::Medium, true),
            "warn"
        );
    }
}
