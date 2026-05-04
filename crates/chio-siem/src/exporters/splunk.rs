//! Splunk HEC (HTTP Event Collector) exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to a Splunk HEC endpoint using newline-separated
//! JSON event envelopes. Each envelope wraps the full ChioReceipt JSON under the
//! "event" key with Splunk-native time/sourcetype fields.

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
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            hec_token: String::new(),
            sourcetype: "chio:receipt".to_string(),
            index: None,
            host: None,
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
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string());

            if !status.is_success() {
                return Err(ExportError::HttpError(format!(
                    "HEC returned {status}: {body}"
                )));
            }

            // 2xx does not always mean every event was indexed. Splunk HEC
            // can return 200 with `code != 0` or with embedded
            // `invalid-event-number` markers when individual events in the
            // batch were rejected. Parse the body to detect partial failure
            // rather than silently treating it as full success.
            classify_hec_response(&body, events.len())
        })
    }
}

/// Classify a Splunk HEC 2xx response body.
///
/// Splunk HEC returns 200 OK even when one or more events were rejected.
/// The response is JSON with at least a top-level `code` field; success is
/// `code == 0`. Per-event failures additionally surface as
/// `invalid-event-number` markers in the response.
///
/// Returns:
/// - `Ok(batch_size)` when `code == 0` and no per-event errors are present.
/// - `Err(PartialFailure)` when `code != 0` or per-event errors are
///   detected. The error carries enough detail to drive metrics and a DLQ
///   entry without re-parsing the body.
fn classify_hec_response(body: &str, batch_size: usize) -> Result<usize, ExportError> {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            // HEC normally returns a JSON object on success. A non-JSON 2xx
            // body is unexpected; treat it as a partial failure rather than
            // silently dropping events.
            return Err(ExportError::PartialFailure {
                succeeded: 0,
                failed: batch_size,
                details: format!("HEC 2xx with non-JSON body: {body}"),
            });
        }
    };

    let code = parsed.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    let text = parsed
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("<no text>");

    // `invalid-event-number` is HEC's marker for per-event rejections.
    let invalid_events: Vec<i64> = parsed
        .get("invalid-event-number")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();

    if code == 0 && invalid_events.is_empty() {
        return Ok(batch_size);
    }

    let failed = invalid_events
        .len()
        .max(if code == 0 { 0 } else { batch_size });
    let succeeded = batch_size.saturating_sub(failed);
    let invalid_summary = if invalid_events.is_empty() {
        String::new()
    } else {
        format!(" invalid-event-number={invalid_events:?}")
    };
    Err(ExportError::PartialFailure {
        succeeded,
        failed,
        details: format!("HEC 2xx with code={code} text={text:?}{invalid_summary}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_full_success() {
        let body = r#"{"text":"Success","code":0}"#;
        assert_eq!(classify_hec_response(body, 5).unwrap(), 5);
    }

    #[test]
    fn classify_global_failure_with_nonzero_code() {
        let body = r#"{"text":"Server error","code":8}"#;
        match classify_hec_response(body, 3).unwrap_err() {
            ExportError::PartialFailure {
                succeeded,
                failed,
                details,
            } => {
                assert_eq!(succeeded, 0);
                assert_eq!(failed, 3);
                assert!(details.contains("code=8"), "details: {details}");
                assert!(details.contains("Server error"), "details: {details}");
            }
            other => panic!("expected PartialFailure, got: {other:?}"),
        }
    }

    #[test]
    fn classify_per_event_invalid_event_number() {
        // Splunk HEC sometimes returns 200 with an array of rejected event
        // indices when the batch was partially accepted.
        let body = r#"{"text":"partial","code":0,"invalid-event-number":[1,3]}"#;
        match classify_hec_response(body, 5).unwrap_err() {
            ExportError::PartialFailure {
                succeeded,
                failed,
                details,
            } => {
                assert_eq!(failed, 2);
                assert_eq!(succeeded, 3);
                assert!(
                    details.contains("invalid-event-number"),
                    "details: {details}"
                );
            }
            other => panic!("expected PartialFailure, got: {other:?}"),
        }
    }

    #[test]
    fn classify_non_json_body_treated_as_partial_failure() {
        let body = "not json at all";
        match classify_hec_response(body, 4).unwrap_err() {
            ExportError::PartialFailure {
                succeeded,
                failed,
                details,
            } => {
                assert_eq!(succeeded, 0);
                assert_eq!(failed, 4);
                assert!(details.contains("non-JSON"), "details: {details}");
            }
            other => panic!("expected PartialFailure, got: {other:?}"),
        }
    }

    #[test]
    fn classify_missing_code_treated_as_success() {
        // Defensive: if HEC returns 200 with a body that omits `code`, default
        // to success. This matches how older HEC versions sometimes reply.
        let body = r#"{"text":"OK"}"#;
        assert_eq!(classify_hec_response(body, 2).unwrap(), 2);
    }
}
