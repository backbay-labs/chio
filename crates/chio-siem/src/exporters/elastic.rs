//! Elasticsearch bulk API exporter for Chio receipts.
//!
//! Sends batches of Chio receipts to an Elasticsearch cluster using the
//! `/_bulk` API with NDJSON action+document pairs. Uses `receipt.id` as the
//! document `_id` to make index operations idempotent (safe to retry).
//!
//! Partial failures (HTTP 200 with `errors: true`) are detected by parsing
//! the bulk response body and counting per-item status codes.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::exporters::require_https_endpoint;
use crate::redaction::redact_for_operator_log;

/// Authentication configuration for the Elasticsearch exporter.
///
/// SECURITY: The `Basic` variant wraps the password in `Zeroizing<String>` so
/// that the credential bytes are overwritten when the value is dropped.
#[derive(Debug, Clone)]
pub enum ElasticAuthConfig {
    /// API key authentication: sends `Authorization: ApiKey <key>` header.
    ApiKey(String),
    /// HTTP Basic authentication: encodes credentials via reqwest's built-in
    /// `basic_auth` helper (no manual base64 encoding needed).
    ///
    /// The password is stored in a `Zeroizing<String>` wrapper to ensure the
    /// memory is zeroed on drop.
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
}

/// Configuration for the Elasticsearch bulk exporter.
#[derive(Debug, Clone)]
pub struct ElasticConfig {
    /// Elasticsearch endpoint URL (e.g. "https://es.example.com:9200").
    pub endpoint: String,
    /// Target index name for all exported receipts. Default: "chio-receipts".
    pub index_name: String,
    /// Authentication method and credentials.
    pub auth: ElasticAuthConfig,
    /// HTTP request timeout. Default: 30 seconds.
    ///
    /// A stalled cluster must not block the SIEM manager poll loop;
    /// `reqwest` does not apply a default timeout, so we install one here.
    pub timeout: Duration,
}

impl Default for ElasticConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            index_name: "chio-receipts".to_string(),
            auth: ElasticAuthConfig::ApiKey(String::new()),
            timeout: Duration::from_secs(30),
        }
    }
}

/// SIEM exporter that POSTs Chio receipt batches to an Elasticsearch cluster
/// using the `/_bulk` API with NDJSON index action + document pairs.
pub struct ElasticsearchExporter {
    config: ElasticConfig,
    client: reqwest::Client,
}

impl ElasticsearchExporter {
    /// Create a new ElasticsearchExporter with the given configuration.
    ///
    /// Builds a `reqwest::Client` with rustls TLS and returns an error if the
    /// client cannot be constructed.
    ///
    /// Returns an error if `config.endpoint` is not an `https://` URL
    /// (plaintext or unparsable). The auth credentials (API keys, Basic
    /// passwords) MUST NOT be transmitted over an unencrypted connection.
    /// The scheme comparison is case-insensitive per RFC 3986, so
    /// `HTTP://`, `Http://`, and similar variants are all rejected. Use
    /// [`Self::new_plaintext_for_tests`] for integration tests against a
    /// local mock server.
    pub fn new(config: ElasticConfig) -> Result<Self, ExportError> {
        require_https_endpoint(
            &config.endpoint,
            "Elasticsearch endpoint must use https:// -- sending API keys \
             or Basic credentials over plaintext http:// is not permitted",
        )?;

        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    /// Create an `ElasticsearchExporter` without TLS scheme validation.
    ///
    /// This constructor is intended for integration tests that run against a
    /// local mock server over plain HTTP. Do NOT use this in production code:
    /// it bypasses the `https://` enforcement that protects auth credentials
    /// from being sent in cleartext.
    pub fn new_plaintext_for_tests(config: ElasticConfig) -> Result<Self, ExportError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ExportError::HttpError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }
}

impl Exporter for ElasticsearchExporter {
    fn name(&self) -> &str {
        "elasticsearch-bulk"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            // Build NDJSON body: for each event, two lines:
            //   Line 1: action -- {"index": {"_index": "<index>", "_id": "<receipt.id>"}}
            //   Line 2: document -- full receipt JSON
            // Every line (including the last) must end with '\n'.
            let mut body = String::new();
            for ev in events {
                let action = serde_json::json!({
                    "index": {
                        "_index": &self.config.index_name,
                        "_id": &ev.receipt.id,
                    }
                });
                body.push_str(&action.to_string());
                body.push('\n');

                let doc = serde_json::to_string(&ev.receipt).map_err(|e| {
                    ExportError::SerializationError(format!(
                        "failed to serialize receipt {}: {e}",
                        ev.receipt.id
                    ))
                })?;
                body.push_str(&doc);
                body.push('\n');
            }

            let url = format!("{}/_bulk", self.config.endpoint);

            // Build the request and apply authentication.
            let builder = self
                .client
                .post(&url)
                .header("Content-Type", "application/x-ndjson")
                .body(body);

            let builder = match &self.config.auth {
                ElasticAuthConfig::ApiKey(key) => {
                    builder.header("Authorization", format!("ApiKey {key}"))
                }
                ElasticAuthConfig::Basic { username, password } => {
                    builder.basic_auth(username, Some(password.as_str()))
                }
            };

            let response = builder
                .send()
                .await
                .map_err(|e| ExportError::HttpError(format!("bulk request failed: {e}")))?;

            let status = response.status();
            if !status.is_success() {
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".to_string());
                let body_text = redact_for_operator_log(body_text);
                return Err(ExportError::HttpError(format!(
                    "Elasticsearch returned {status}: {body_text}"
                )));
            }

            // Parse response body to detect partial failures.
            // ES bulk API returns HTTP 200 even when individual documents fail.
            // We must check `response["errors"]` and iterate per-item statuses.
            let resp_json: serde_json::Value = response.json().await.map_err(|e| {
                ExportError::HttpError(format!("failed to parse bulk response: {e}"))
            })?;

            let has_errors = resp_json
                .get("errors")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if has_errors {
                let items = resp_json
                    .get("items")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.as_slice())
                    .unwrap_or(&[]);

                let mut failed_count = 0usize;
                let mut first_error = String::new();

                for item in items {
                    let item_status = item
                        .get("index")
                        .and_then(|idx| idx.get("status"))
                        .and_then(|s| s.as_u64())
                        .unwrap_or(0);

                    if item_status >= 400 {
                        failed_count += 1;
                        if first_error.is_empty() {
                            // Extract the error reason for diagnostics.
                            let reason = item
                                .get("index")
                                .and_then(|idx| idx.get("error"))
                                .and_then(|err| err.get("reason"))
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown error");
                            first_error = redact_for_operator_log(reason);
                        }
                    }
                }

                if failed_count > 0 {
                    let succeeded = events.len().saturating_sub(failed_count);
                    return Err(ExportError::PartialFailure {
                        succeeded,
                        failed: failed_count,
                        details: first_error,
                    });
                }
            }

            Ok(events.len())
        })
    }
}
