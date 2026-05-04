//! Splunk HEC (HTTP Event Collector) exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to a Splunk HEC endpoint using newline-separated
//! JSON event envelopes. Each envelope wraps the full ChioReceipt JSON under the
//! "event" key with Splunk-native time/sourcetype fields.

use std::time::Duration;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};

/// Configuration for the Splunk HEC exporter.
#[derive(Debug, Clone)]
pub struct SplunkConfig {
    /// Splunk HEC endpoint URL (e.g. "https://splunk.example.com:8088").
    pub endpoint: String,
    /// HEC authentication token.
    pub hec_token: String,
    /// Splunk sourcetype for all exported events. Default: "chio:receipt".
    pub sourcetype: String,
    /// Optional Splunk index name. Omit to use the default index configured for the HEC token.
    pub index: Option<String>,
    /// Optional host field sent with each event envelope.
    pub host: Option<String>,
    /// HTTP request timeout. Default: 30 seconds.
    ///
    /// A slow or stalled HEC endpoint must not block the SIEM manager poll
    /// loop. `reqwest` does not apply any timeout by default, so we install
    /// one here and treat a stuck collector as a transient error.
    pub timeout: Duration,
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            hec_token: String::new(),
            sourcetype: "chio:receipt".to_string(),
            index: None,
            host: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// SIEM exporter that POSTs Chio receipt batches to a Splunk HEC endpoint.
///
/// Uses newline-separated JSON event envelopes (not a JSON array) as required
/// by the Splunk HEC event endpoint (`/services/collector/event`).
///
/// SECURITY: HEC tokens must only be transmitted over TLS. Construction will
/// return an error if the endpoint URL uses a plain `http://` scheme.
pub struct SplunkHecExporter {
    config: SplunkConfig,
    client: reqwest::Client,
}

impl SplunkHecExporter {
    /// Create a new SplunkHecExporter with the given configuration.
    ///
    /// Builds a `reqwest::Client` with rustls TLS and returns an error if the
    /// client cannot be constructed.
    ///
    /// Returns an error if `config.endpoint` uses `http://` (plaintext). HEC
    /// tokens must only be sent over a TLS-protected connection (`https://`).
    pub fn new(config: SplunkConfig) -> Result<Self, ExportError> {
        if config.endpoint.starts_with("http://") {
            return Err(ExportError::HttpError(
                "Splunk HEC endpoint must use https:// -- sending HEC tokens over \
                 plaintext http:// is not permitted"
                    .to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    /// Create a SplunkHecExporter without TLS scheme validation.
    ///
    /// This constructor is intended for use in integration tests that run
    /// against a local mock server over plain HTTP. Do NOT use this in
    /// production code -- it bypasses the https:// enforcement that protects
    /// HEC tokens from being sent in cleartext.
    pub fn new_plaintext_for_tests(config: SplunkConfig) -> Result<Self, ExportError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }
}

impl Exporter for SplunkHecExporter {
    fn name(&self) -> &str {
        "splunk-hec"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            // Build newline-separated JSON event envelopes.
            // CRITICAL: HEC expects newline-separated objects, NOT a JSON array.
            let mut parts: Vec<String> = Vec::with_capacity(events.len());
            for ev in events {
                let mut envelope = serde_json::json!({
                    "time": ev.receipt.timestamp as f64,
                    "sourcetype": &self.config.sourcetype,
                    "event": &ev.receipt,
                });

                if let Some(index) = &self.config.index {
                    envelope["index"] = serde_json::Value::String(index.clone());
                }
                if let Some(host) = &self.config.host {
                    envelope["host"] = serde_json::Value::String(host.clone());
                }

                let line = serde_json::to_string(&envelope).map_err(|e| {
                    ExportError::SerializationError(format!(
                        "failed to serialize HEC envelope: {e}"
                    ))
                })?;
                parts.push(line);
            }

            let payload = parts.join("\n");
            let url = format!("{}/services/collector/event", self.config.endpoint);

            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Splunk {}", self.config.hec_token))
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
                .map_err(|e| ExportError::HttpError(format!("HEC request failed: {e}")))?;

            let status = response.status();
            if !status.is_success() {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".to_string());
                return Err(ExportError::HttpError(format!(
                    "HEC returned {status}: {body}"
                )));
            }

            Ok(events.len())
        })
    }
}
