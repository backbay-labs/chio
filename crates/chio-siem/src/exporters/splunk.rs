//! Splunk HEC (HTTP Event Collector) exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to a Splunk HEC endpoint using newline-separated
//! JSON event envelopes. Each envelope wraps the full ChioReceipt JSON under the
//! "event" key with Splunk-native time/sourcetype fields.

use std::time::Duration;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::exporters::require_https_endpoint;
use crate::redaction::redact_for_operator_log;
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractResponse, HttpEgressContract,
};

const DEFAULT_HEC_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEC_RESPONSE_BODY_BYTES: usize = 64 * 1024;

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
    /// Typed HTTP egress contract enforced before every HEC dispatch and on
    /// every redirect hop. Required in production; tests may use
    /// `HttpEgressContract::permissive_for_tests`.
    pub egress_contract: Option<HttpEgressContract>,
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            hec_token: String::new(),
            sourcetype: "chio:receipt".to_string(),
            index: None,
            host: None,
            timeout: DEFAULT_HEC_TIMEOUT,
            egress_contract: None,
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
    /// Returns an error if `config.endpoint` is not an `https://` URL
    /// (plaintext or unparsable). HEC tokens must only be sent over a
    /// TLS-protected connection (`https://`). The scheme comparison is
    /// case-insensitive per RFC 3986, so `HTTP://`, `Http://`, and
    /// similar variants are all rejected.
    pub fn new(config: SplunkConfig) -> Result<Self, ExportError> {
        require_https_endpoint(
            &config.endpoint,
            "Splunk HEC endpoint must use https:// -- sending HEC tokens over \
             plaintext http:// is not permitted",
        )?;
        // HttpEgressContract: Splunk HEC dispatch must run through the
        // typed egress contract. The contract is re-checked on every
        // dispatch via send_with_contract.
        let contract = config.egress_contract.as_ref().ok_or_else(|| {
            ExportError::HttpError("Splunk HEC exporter requires an HttpEgressContract".to_string())
        })?;
        let dispatch_url = format!("{}/services/collector/event", config.endpoint);
        contract.enforce_url(&dispatch_url, 0).map_err(|err| {
            ExportError::HttpError(format!("HttpEgressContract rejects HEC URL: {err}"))
        })?;

        let client = client_builder_with_contract(contract)
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
    pub fn new_plaintext_for_tests(mut config: SplunkConfig) -> Result<Self, ExportError> {
        if config.egress_contract.is_none() {
            let url = url::Url::parse(&config.endpoint).map_err(|e| {
                ExportError::HttpError(format!("invalid HEC endpoint for test contract: {e}"))
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
                "Splunk HEC test exporter requires an HttpEgressContract".to_string(),
            )
        })?;
        let client = client_builder_with_contract(contract)
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

            // HttpEgressContract: every HEC dispatch routes through
            // send_with_contract so the URL, every redirect hop, and the
            // response size are validated by the typed contract before bytes
            // leave the substrate.
            let contract = self.config.egress_contract.as_ref().ok_or_else(|| {
                ExportError::HttpError(
                    "Splunk HEC exporter is missing HttpEgressContract; substrate fails closed"
                        .to_string(),
                )
            })?;
            let raw_request = self
                .client
                .post(&url)
                .header("Authorization", format!("Splunk {}", self.config.hec_token))
                .header("Content-Type", "application/json")
                .body(payload)
                .build()
                .map_err(|e| ExportError::HttpError(format!("failed to build HEC request: {e}")))?;
            let response = send_with_contract(contract, &self.client, raw_request)
                .await
                .map_err(|err| ExportError::HttpError(format!("HEC request failed: {err}")))?;

            let status = response.status();
            let body = read_hec_response_body(&response)?;

            if !status.is_success() {
                let body = redact_for_operator_log(body);
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

fn read_hec_response_body(response: &ContractResponse) -> Result<String, ExportError> {
    let body = response.body();
    if body.len() > MAX_HEC_RESPONSE_BODY_BYTES {
        return Err(hec_response_body_too_large(body.len() as u64));
    }

    Ok(String::from_utf8_lossy(body).into_owned())
}

fn hec_response_body_too_large(size: u64) -> ExportError {
    ExportError::HttpError(format!(
        "HEC response body exceeded {MAX_HEC_RESPONSE_BODY_BYTES} byte limit (received at least {size} bytes)"
    ))
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
                details: format!(
                    "HEC 2xx with non-JSON body: {}",
                    redact_for_operator_log(body)
                ),
            });
        }
    };

    let code = parsed.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    let text = parsed
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("<no text>");

    // `invalid-event-number` is HEC's marker for per-event rejections.
    let invalid_events = parsed
        .get("invalid-event-number")
        .and_then(parse_invalid_event_numbers);

    if code == 0 && invalid_events.is_none() {
        return Ok(batch_size);
    }

    let (succeeded, failed) = match invalid_events.as_ref() {
        Some(InvalidEventNumbers::FirstRejected(index)) => {
            let succeeded = (*index as usize).min(batch_size);
            (succeeded, batch_size.saturating_sub(succeeded))
        }
        Some(InvalidEventNumbers::RejectedIndices(indices)) => {
            let failed = indices.len().min(batch_size);
            (batch_size.saturating_sub(failed), failed)
        }
        None => (0, batch_size),
    };
    let invalid_summary = invalid_events
        .as_ref()
        .map(|invalid_events| format!(" invalid-event-number={invalid_events}"))
        .unwrap_or_default();
    let text = redact_for_operator_log(text);
    Err(ExportError::PartialFailure {
        succeeded,
        failed,
        details: format!("HEC 2xx with code={code} text={text:?}{invalid_summary}"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InvalidEventNumbers {
    FirstRejected(i64),
    RejectedIndices(Vec<i64>),
}

impl std::fmt::Display for InvalidEventNumbers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstRejected(index) => write!(f, "{index}"),
            Self::RejectedIndices(indices) => write!(f, "{indices:?}"),
        }
    }
}

fn parse_invalid_event_numbers(value: &serde_json::Value) -> Option<InvalidEventNumbers> {
    if let Some(index) = value.as_i64() {
        return Some(InvalidEventNumbers::FirstRejected(index.max(0)));
    }
    let indices = value
        .as_array()?
        .iter()
        .filter_map(|value| value.as_i64())
        .filter(|index| *index >= 0)
        .collect::<Vec<_>>();
    if indices.is_empty() {
        None
    } else {
        Some(InvalidEventNumbers::RejectedIndices(indices))
    }
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
    fn classify_scalar_invalid_event_number_as_first_rejected_event() {
        let body = r#"{"text":"Invalid data format","code":6,"invalid-event-number":3}"#;
        match classify_hec_response(body, 5).unwrap_err() {
            ExportError::PartialFailure {
                succeeded,
                failed,
                details,
            } => {
                assert_eq!(succeeded, 3);
                assert_eq!(failed, 2);
                assert!(
                    details.contains("invalid-event-number=3"),
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
