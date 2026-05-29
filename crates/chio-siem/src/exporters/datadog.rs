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
//! Implemented against the Chio `Exporter` trait (dyn-compatible
//! `Pin<Box<dyn Future>>`) and Chio receipt shape
//! (`Decision::{Allow, Deny, ...}`).

use std::time::Duration;

use crate::alerting::{derive_event_severity, AlertSeverity};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::redaction::redact_for_operator_log;
use chio_core::receipt::Decision;
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

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
    /// Typed HTTP egress contract enforced before every dispatch and on
    /// every redirect hop. Required in production.
    pub egress_contract: Option<HttpEgressContract>,
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
            egress_contract: None,
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

        let logs_url = format!("https://http-intake.logs.{}/api/v2/logs", config.site);

        // HttpEgressContract: every Datadog Logs dispatch must run through
        // the typed egress contract. Re-checked per-request via send_with_contract.
        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError("Datadog exporter requires an HttpEgressContract".to_string())
        })?;
        contract.enforce_url(&logs_url, 0).map_err(|err| {
            ExportError::HttpError(format!("HttpEgressContract rejects Datadog URL: {err}"))
        })?;

        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

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

        let logs_url = format!("{}/api/v2/logs", base_url.trim_end_matches('/'));

        if config.egress_contract.is_none() {
            let url = url::Url::parse(&logs_url)
                .map_err(|e| ExportError::HttpError(format!("invalid Datadog test URL: {e}")))?;
            let host = url.host_str().unwrap_or("localhost");
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            config.egress_contract = Some(HttpEgressContract::permissive_for_tests(&authority));
        }

        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError(
                "Datadog test exporter requires an HttpEgressContract".to_string(),
            )
        })?;
        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;

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
            let authorized = ev.is_authorized();
            let (allow, guard_label, reason) = match &receipt.decision {
                Some(Decision::Allow) if authorized => (true, "allow", "chio.receipt".to_string()),
                Some(Decision::Allow) => (
                    false,
                    ev.receipt_kind.as_str(),
                    format!("{} receipt", ev.receipt_kind),
                ),
                Some(Decision::Deny { reason, guard }) => (false, guard.as_str(), reason.clone()),
                Some(Decision::Cancelled { reason }) => (false, "cancelled", reason.clone()),
                Some(Decision::Incomplete { reason }) => (false, "incomplete", reason.clone()),
                None => (
                    false,
                    ev.receipt_kind.as_str(),
                    format!("{} receipt", ev.receipt_kind),
                ),
            };
            let reason = redact_for_operator_log(reason);

            let severity = derive_event_severity(ev);

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
            tags.push(format!(
                "receipt_kind:{}",
                sanitize_tag_value(&ev.receipt_kind)
            ));
            tags.push(format!(
                "boundary_class:{}",
                sanitize_tag_value(&ev.boundary_class)
            ));
            tags.push(format!(
                "outcome:{}",
                if allow {
                    "allow"
                } else {
                    ev.receipt_kind.as_str()
                }
            ));

            for guard in &receipt.evidence {
                tags.push(format!(
                    "evidence_guard:{}",
                    sanitize_tag_value(&guard.guard_name)
                ));
            }

            let mut event_json = serde_json::to_value(receipt).map_err(|e| {
                ExportError::SerializationError(format!(
                    "failed to serialize receipt {}: {e}",
                    receipt.id
                ))
            })?;
            if let Some(obj) = event_json.as_object_mut() {
                obj.insert(
                    "receipt_kind".to_string(),
                    serde_json::Value::String(ev.receipt_kind.clone()),
                );
                obj.insert(
                    "boundary_class".to_string(),
                    serde_json::Value::String(ev.boundary_class.clone()),
                );
                obj.insert(
                    "result".to_string(),
                    serde_json::Value::String(ev.result.clone()),
                );
                obj.insert(
                    "authorized".to_string(),
                    serde_json::Value::Bool(ev.authorized),
                );
            }

            logs.push(serde_json::json!({
                "message": reason,
                "ddsource": self.config.source,
                "service": self.config.service,
                "hostname": hostname,
                "status": Self::datadog_status(severity, allow),
                "ddtags": tags.join(","),
                "receipt_kind": ev.receipt_kind.clone(),
                "boundary_class": ev.boundary_class.clone(),
                "result": ev.result.clone(),
                "authorized": ev.authorized,
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

            // HttpEgressContract: every dispatch routes through send_with_contract.
            let contract = self.config.egress_contract.as_ref().ok_or_else(|| {
                ExportError::HttpError(
                    "Datadog exporter is missing HttpEgressContract; substrate fails closed"
                        .to_string(),
                )
            })?;
            let raw_request = self
                .client
                .post(&self.logs_url)
                .header("DD-API-KEY", &self.config.api_key)
                .header("Content-Type", "application/json")
                .json(&logs)
                .build()
                .map_err(|e| {
                    ExportError::HttpError(format!("failed to build Datadog request: {e}"))
                })?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| {
                    ExportError::HttpError(format!("Datadog logs request failed: {err}"))
                })?;

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
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ReceiptSemanticFields, ToolCallAction, TrustLevel,
    };
    use chio_test_support::prelude::*;

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

    #[test]
    fn trace_observation_allow_is_tagged_as_trace_not_allow() {
        let exporter =
            DatadogExporter::new_with_base_url_for_tests(DatadogConfig::default(), "http://local")
                .test_expect("construct test exporter");
        let event = SiemEvent::from_receipt(test_receipt_with_semantics(
            Decision::Allow,
            ReceiptSemanticFields::trace_detect_only(),
            TrustLevel::Verified,
        ));
        let payload = exporter
            .build_payload(&[event])
            .test_expect("build datadog payload");
        let tags = payload[0]["ddtags"].as_str().test_expect("ddtags string");

        assert!(tags.contains("receipt_kind:trace_observation"));
        assert!(tags.contains("boundary_class:detect_only"));
        assert!(tags.contains("outcome:trace_observation"));
        assert!(!tags.contains("outcome:allow"));
        assert_eq!(payload[0]["receipt_kind"], "trace_observation");
        assert_eq!(payload[0]["boundary_class"], "detect_only");
        assert_eq!(payload[0]["authorized"], false);
        assert_eq!(payload[0]["event"]["authorized"], false);
    }

    fn test_receipt_with_semantics(
        decision: Decision,
        semantics: ReceiptSemanticFields,
        trust_level: TrustLevel,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        }))
        .test_expect("hash test receipt parameters");
        let decision = if semantics.receipt_kind == chio_core::ReceiptKind::MediatedDecision {
            Some(decision)
        } else {
            None
        };
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "trace-datadog-1".to_string(),
                timestamp: 1_712_345_678,
                capability_id: "cap-abc".to_string(),
                tool_server: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                action,
                decision,
                receipt_kind: semantics.receipt_kind,
                boundary_class: semantics.boundary_class,
                observation_outcome: semantics.observation_outcome,
                tool_origin: semantics.tool_origin,
                redaction_mode: semantics.redaction_mode,
                actor_chain: semantics.actor_chain,
                content_hash: "content-xyz".to_string(),
                policy_hash: "policy-xyz".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level,
                tenant_id: None,
                kernel_key: kp.public_key(),
            },
            &kp,
        )
        .test_expect("sign test receipt")
    }
}
