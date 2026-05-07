//! OCSF exporter for Chio receipts.
//!
//! This exporter transforms each [`SiemEvent`] into an OCSF 1.3.0
//! Authorization event (class_uid 3002) using [`receipt_to_ocsf`] and forwards
//! the resulting JSON to a configurable HTTPS sink (for example, AWS Security
//! Lake's custom source ingestion endpoint or a Splunk OCSF add-on receiver).
//!
//! The exporter emits one JSON object per receipt. Two on-the-wire payload
//! modes are supported:
//!
//! - [`OcsfPayloadFormat::JsonArray`]: the batch is sent as a single JSON
//!   array.
//! - [`OcsfPayloadFormat::Ndjson`]: the batch is sent as newline-delimited
//!   JSON (one object per line) -- the format expected by the Splunk HEC
//!   `/services/collector/raw` endpoint and by Fluent Bit's `http` output.
//!
//! The exporter can also be used purely as a formatter: call
//! [`OcsfExporter::format_events`] to get the per-event JSON objects without
//! making any network calls.

use std::time::Duration;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::exporters::require_https_endpoint;
use crate::ocsf::receipt_to_ocsf;
use crate::redaction::redact_for_operator_log;
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

const DEFAULT_OCSF_TIMEOUT: Duration = Duration::from_secs(30);

/// Payload serialization format for the OCSF exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcsfPayloadFormat {
    /// Send the batch as a single JSON array: `[{...}, {...}]`.
    JsonArray,
    /// Send the batch as newline-delimited JSON objects.
    #[default]
    Ndjson,
}

/// Configuration for the OCSF exporter.
#[derive(Debug, Clone)]
pub struct OcsfExporterConfig {
    /// HTTPS endpoint that accepts OCSF events.
    ///
    /// Leave empty when the exporter is used purely as a formatter (tests
    /// or in-process consumers); in that case [`Exporter::export_batch`]
    /// will not attempt a network call.
    pub endpoint: String,
    /// Optional bearer token sent as `Authorization: Bearer <token>`.
    pub bearer_token: Option<String>,
    /// On-the-wire format for the batch payload.
    pub payload_format: OcsfPayloadFormat,
    /// Content type sent with the request. When omitted, a sensible default
    /// is chosen based on [`OcsfPayloadFormat`]:
    /// `application/json` for [`OcsfPayloadFormat::JsonArray`] and
    /// `application/x-ndjson` for [`OcsfPayloadFormat::Ndjson`].
    pub content_type: Option<String>,
    /// HTTP request timeout.
    pub timeout: Duration,
    /// Typed HTTP egress contract enforced before every dispatch and on
    /// every redirect hop. Required when `endpoint` is non-empty.
    pub egress_contract: Option<HttpEgressContract>,
}

impl Default for OcsfExporterConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            bearer_token: None,
            payload_format: OcsfPayloadFormat::default(),
            content_type: None,
            timeout: DEFAULT_OCSF_TIMEOUT,
            egress_contract: None,
        }
    }
}

/// Exporter that transforms Chio receipts into OCSF 1.3.0 Authorization events
/// before forwarding them to an HTTPS sink.
pub struct OcsfExporter {
    config: OcsfExporterConfig,
    client: reqwest::Client,
}

impl OcsfExporter {
    /// Construct a new [`OcsfExporter`].
    ///
    /// Returns an error when the HTTP client cannot be built. If `endpoint`
    /// is empty the exporter operates as an in-process formatter and will
    /// short-circuit network delivery in [`Exporter::export_batch`].
    pub fn new(config: OcsfExporterConfig) -> Result<Self, ExportError> {
        Self::validate_endpoint_security(&config)?;

        // HttpEgressContract: when endpoint is configured, OCSF dispatch
        // must run through the typed egress contract.
        let contract = if !config.endpoint.trim().is_empty() {
            Some(config.egress_contract.as_ref().ok_or_else(|| {
                ExportError::HttpError(
                    "OCSF exporter with endpoint requires an HttpEgressContract".to_string(),
                )
            })?)
        } else {
            None
        };
        if let Some(contract) = contract {
            contract.enforce_url(&config.endpoint, 0).map_err(|err| {
                ExportError::HttpError(format!("HttpEgressContract rejects OCSF URL: {err}"))
            })?;
        }

        let client = match contract {
            Some(contract) => client_builder_with_contract(contract)
                .timeout(config.timeout)
                .build(),
            None => reqwest::Client::builder().timeout(config.timeout).build(),
        }
        .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    /// Construct an [`OcsfExporter`] without TLS scheme validation.
    ///
    /// This constructor is intended for integration tests that run against a
    /// local mock server over plain HTTP. Do NOT use this in production code:
    /// it bypasses the HTTPS enforcement that protects receipt export.
    pub fn new_plaintext_for_tests(mut config: OcsfExporterConfig) -> Result<Self, ExportError> {
        if !config.endpoint.trim().is_empty() && config.egress_contract.is_none() {
            let url = url::Url::parse(&config.endpoint).map_err(|e| {
                ExportError::HttpError(format!("invalid OCSF endpoint for test contract: {e}"))
            })?;
            let host = url.host_str().unwrap_or("localhost");
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            config.egress_contract = Some(HttpEgressContract::permissive_for_tests(&authority));
        }
        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError("OCSF test exporter requires an HttpEgressContract".to_string())
        })?;
        let client = client_builder_with_contract(contract)
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    fn validate_endpoint_security(config: &OcsfExporterConfig) -> Result<(), ExportError> {
        if config.endpoint.trim().is_empty() {
            return Ok(());
        }

        require_https_endpoint(
            &config.endpoint,
            "OCSF receipt export requires an https endpoint",
        )
    }

    /// Produce one OCSF JSON object per receipt without performing I/O.
    ///
    /// Useful for embedding the OCSF transform into other exporters or for
    /// tests that want to assert on the mapped shape directly.
    #[must_use]
    pub fn format_events(events: &[SiemEvent]) -> Vec<serde_json::Value> {
        events
            .iter()
            .map(|ev| receipt_to_ocsf(&ev.receipt))
            .collect()
    }

    /// Serialize a batch of OCSF events into the on-the-wire body for the
    /// configured [`OcsfPayloadFormat`].
    fn serialize_body(&self, events: &[SiemEvent]) -> Result<String, ExportError> {
        let mapped = Self::format_events(events);
        match self.config.payload_format {
            OcsfPayloadFormat::JsonArray => serde_json::to_string(&mapped).map_err(|e| {
                ExportError::SerializationError(format!(
                    "failed to serialize OCSF JSON array batch: {e}"
                ))
            }),
            OcsfPayloadFormat::Ndjson => {
                let mut body = String::new();
                for value in mapped {
                    let line = serde_json::to_string(&value).map_err(|e| {
                        ExportError::SerializationError(format!(
                            "failed to serialize OCSF event: {e}"
                        ))
                    })?;
                    body.push_str(&line);
                    body.push('\n');
                }
                Ok(body)
            }
        }
    }

    fn default_content_type(&self) -> &'static str {
        match self.config.payload_format {
            OcsfPayloadFormat::JsonArray => "application/json",
            OcsfPayloadFormat::Ndjson => "application/x-ndjson",
        }
    }
}

impl Exporter for OcsfExporter {
    fn name(&self) -> &str {
        "ocsf"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            let body = self.serialize_body(events)?;

            // Formatter-only mode: endpoint is empty, so skip the network
            // call. The serialize step above still validates that every
            // event maps cleanly.
            if self.config.endpoint.is_empty() {
                return Ok(events.len());
            }

            let content_type = self
                .config
                .content_type
                .as_deref()
                .unwrap_or_else(|| self.default_content_type())
                .to_string();

            let mut request = self
                .client
                .post(&self.config.endpoint)
                .header("Content-Type", content_type)
                .body(body);

            if let Some(token) = &self.config.bearer_token {
                request = request.header("Authorization", format!("Bearer {token}"));
            }

            // HttpEgressContract: every dispatch routes through send_with_contract.
            let contract = self.config.egress_contract.as_ref().ok_or_else(|| {
                ExportError::HttpError(
                    "OCSF exporter is missing HttpEgressContract; substrate fails closed"
                        .to_string(),
                )
            })?;
            let raw_request = request.build().map_err(|e| {
                ExportError::HttpError(format!("failed to build OCSF request: {e}"))
            })?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| {
                    ExportError::HttpError(format!("OCSF sink request failed: {err}"))
                })?;

            let status = response.status();
            if !status.is_success() {
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".to_string());
                let body_text = redact_for_operator_log(body_text);
                return Err(ExportError::HttpError(format!(
                    "OCSF sink returned {status}: {body_text}"
                )));
            }

            Ok(events.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_payload_format_is_ndjson() {
        assert_eq!(OcsfPayloadFormat::default(), OcsfPayloadFormat::Ndjson);
    }

    #[test]
    fn default_config_has_empty_endpoint() {
        let cfg = OcsfExporterConfig::default();
        assert!(cfg.endpoint.is_empty());
        assert!(cfg.bearer_token.is_none());
    }

    #[test]
    fn new_rejects_plain_http_endpoint_without_bearer_token() {
        let cfg = OcsfExporterConfig {
            endpoint: "http://example.test/ocsf".to_string(),
            ..OcsfExporterConfig::default()
        };
        let Err(error) = OcsfExporter::new(cfg) else {
            panic!("plain HTTP OCSF endpoint should be rejected");
        };

        assert!(error.to_string().contains("https"));
    }
}
