// OpenTelemetry-compatible telemetry export for ACP receipts.
//
// This module provides a thin abstraction layer for exporting Chio
// receipts as OpenTelemetry-compatible spans. It defines the span
// structure and a trait for the actual export backend, so that
// consumers can plug in any OTel SDK version without coupling the
// core ACP proxy to a specific OTel release.

// ChioReceipt is already imported via attestation.rs in the include! pattern.

/// An OTel-compatible span representation for a receipt.
///
/// This mirrors the key fields of an OpenTelemetry span without
/// depending on the OTel SDK directly. Export backends convert
/// these into their SDK's native span type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptSpan {
    /// W3C trace ID (32 hex chars). Derived from the session ID.
    pub trace_id: String,
    /// W3C span ID (16 hex chars). Derived from the receipt ID.
    pub span_id: String,
    /// Parent span ID (16 hex chars). For session root spans, this is empty.
    pub parent_span_id: String,
    /// The tool name that was invoked.
    pub tool_name: String,
    /// The semantic verdict, such as "allow", "deny", "trace_observation",
    /// or "advisory_evaluation".
    pub verdict: String,
    /// The capability ID that authorized the invocation.
    pub capability_id: String,
    /// Start time in nanoseconds since Unix epoch.
    pub start_time_nanos: u64,
    /// End time in nanoseconds since Unix epoch (same as start for point-in-time events).
    pub end_time_nanos: u64,
    /// Span attributes as key-value pairs.
    pub attributes: Vec<SpanAttribute>,
    /// Span events (e.g., compliance certificate events).
    pub events: Vec<SpanEvent>,
}

/// A key-value attribute on a span.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanAttribute {
    /// Attribute key.
    pub key: String,
    /// Attribute value (always serialized as a string).
    pub value: String,
}

/// A span event (a point-in-time occurrence within a span).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanEvent {
    /// Event name.
    pub name: String,
    /// Timestamp in nanoseconds since Unix epoch.
    pub timestamp_nanos: u64,
    /// Event attributes.
    pub attributes: Vec<SpanAttribute>,
}

/// Trait for backends that export receipt spans.
///
/// Implementations convert `ReceiptSpan` values into whatever
/// format their OTel SDK requires and forward them to a collector.
pub trait ReceiptSpanExporter: Send + Sync {
    /// Export a batch of receipt spans.
    ///
    /// Returns the number of spans successfully exported.
    fn export(&self, spans: &[ReceiptSpan]) -> Result<usize, TelemetryExportError>;

    /// Flush any buffered spans.
    fn flush(&self) -> Result<(), TelemetryExportError>;

    /// Shut down the exporter.
    fn shutdown(&self) -> Result<(), TelemetryExportError>;
}

/// Error type for telemetry export failures.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryExportError {
    /// The export endpoint was unreachable or returned an error.
    #[error("export failed: {0}")]
    ExportFailed(String),

    /// Serialization of span data failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// The exporter has been shut down.
    #[error("exporter shut down")]
    Shutdown,
}

/// Telemetry configuration parsed from `chio.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TelemetryConfig {
    /// Whether telemetry export is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// OTel collector endpoint (e.g., "http://localhost:4317").
    #[serde(default)]
    pub endpoint: String,

    /// Service name reported to the collector.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Whether to include receipt parameters in span attributes.
    /// Disabled by default to avoid leaking sensitive data.
    #[serde(default)]
    pub include_parameters: bool,

    /// Batch size for span export. 0 = export immediately.
    #[serde(default)]
    pub batch_size: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            service_name: default_service_name(),
            include_parameters: false,
            batch_size: 0,
        }
    }
}

fn default_service_name() -> String {
    "chio-acp-proxy".to_string()
}

/// Convert an Chio receipt into an OTel-compatible span.
pub fn receipt_to_span(receipt: &ChioReceipt, session_trace_id: &str) -> ReceiptSpan {
    let semantics = receipt.semantic_fields();
    let verdict = match &receipt.decision {
        chio_core::receipt::Decision::Allow if semantics.is_authorized(&receipt.decision) => {
            "allow"
        }
        chio_core::receipt::Decision::Allow => semantics.receipt_kind.as_str(),
        chio_core::receipt::Decision::Deny { .. } => "deny",
        chio_core::receipt::Decision::Cancelled { .. } => "cancelled",
        chio_core::receipt::Decision::Incomplete { .. } => "incomplete",
    };

    // Derive span_id from receipt ID (take first 16 hex chars or pad).
    let span_id = derive_span_id(&receipt.id);

    // Convert timestamp from seconds to nanoseconds.
    let timestamp_nanos = receipt.timestamp.saturating_mul(1_000_000_000);

    let mut attributes = vec![
        SpanAttribute {
            key: "chio.tool_server".to_string(),
            value: receipt.tool_server.clone(),
        },
        SpanAttribute {
            key: "chio.tool_name".to_string(),
            value: receipt.tool_name.clone(),
        },
        SpanAttribute {
            key: "chio.verdict".to_string(),
            value: verdict.to_string(),
        },
        SpanAttribute {
            key: "chio.receipt_kind".to_string(),
            value: semantics.receipt_kind.as_str().to_string(),
        },
        SpanAttribute {
            key: "chio.boundary_class".to_string(),
            value: semantics.boundary_class.as_str().to_string(),
        },
        SpanAttribute {
            key: "chio.capability_id".to_string(),
            value: receipt.capability_id.clone(),
        },
        SpanAttribute {
            key: "chio.receipt_id".to_string(),
            value: receipt.id.clone(),
        },
        SpanAttribute {
            key: "chio.content_hash".to_string(),
            value: receipt.content_hash.clone(),
        },
    ];

    // Add deny reason if applicable.
    if let chio_core::receipt::Decision::Deny { reason, guard } = &receipt.decision {
        attributes.push(SpanAttribute {
            key: "chio.deny_reason".to_string(),
            value: reason.clone(),
        });
        attributes.push(SpanAttribute {
            key: "chio.deny_guard".to_string(),
            value: guard.clone(),
        });
    }

    // Add guard evidence as span events.
    let events: Vec<SpanEvent> = receipt
        .evidence
        .iter()
        .map(|ev| SpanEvent {
            name: format!("guard.{}", ev.guard_name),
            timestamp_nanos,
            attributes: vec![
                SpanAttribute {
                    key: "guard.name".to_string(),
                    value: ev.guard_name.clone(),
                },
                SpanAttribute {
                    key: "guard.verdict".to_string(),
                    value: ev.verdict.to_string(),
                },
                SpanAttribute {
                    key: "guard.details".to_string(),
                    value: ev
                        .details
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                },
            ],
        })
        .collect();

    ReceiptSpan {
        trace_id: session_trace_id.to_string(),
        span_id,
        parent_span_id: String::new(),
        tool_name: receipt.tool_name.clone(),
        verdict: verdict.to_string(),
        capability_id: receipt.capability_id.clone(),
        start_time_nanos: timestamp_nanos,
        end_time_nanos: timestamp_nanos,
        attributes,
        events,
    }
}

/// Convert a compliance certificate event into a span event on the session root span.
pub fn compliance_certificate_event(
    cert: &ComplianceCertificateBody,
) -> SpanEvent {
    let timestamp_nanos = cert.issued_at.saturating_mul(1_000_000_000);

    SpanEvent {
        name: "chio.compliance.certificate".to_string(),
        timestamp_nanos,
        attributes: vec![
            SpanAttribute {
                key: "cert.session_id".to_string(),
                value: cert.session_id.clone(),
            },
            SpanAttribute {
                key: "cert.receipt_count".to_string(),
                value: cert.receipt_count.to_string(),
            },
            SpanAttribute {
                key: "cert.all_signatures_valid".to_string(),
                value: cert.all_signatures_valid.to_string(),
            },
            SpanAttribute {
                key: "cert.chain_continuous".to_string(),
                value: cert.chain_continuous.to_string(),
            },
            SpanAttribute {
                key: "cert.scope_compliant".to_string(),
                value: cert.scope_compliant.to_string(),
            },
            SpanAttribute {
                key: "cert.budget_compliant".to_string(),
                value: cert.budget_compliant.to_string(),
            },
            SpanAttribute {
                key: "cert.guards_compliant".to_string(),
                value: cert.guards_compliant.to_string(),
            },
        ],
    }
}

/// Create a session root span for OTel tracing.
///
/// This span serves as the parent for all receipt spans within a session.
pub fn session_root_span(
    session_id: &str,
    trace_id: &str,
    start_time_secs: u64,
    end_time_secs: u64,
) -> ReceiptSpan {
    let span_id = derive_span_id(session_id);

    ReceiptSpan {
        trace_id: trace_id.to_string(),
        span_id,
        parent_span_id: String::new(),
        tool_name: "chio.session".to_string(),
        verdict: "session".to_string(),
        capability_id: String::new(),
        start_time_nanos: start_time_secs.saturating_mul(1_000_000_000),
        end_time_nanos: end_time_secs.saturating_mul(1_000_000_000),
        attributes: vec![SpanAttribute {
            key: "chio.session_id".to_string(),
            value: session_id.to_string(),
        }],
        events: Vec::new(),
    }
}

/// Derive a W3C trace ID (32 hex chars) from a session ID.
///
/// Uses SHA-256 and takes the first 16 bytes (32 hex chars).
pub fn derive_trace_id(session_id: &str) -> String {
    let hash = sha2_digest(session_id.as_bytes());
    // First 16 bytes = 32 hex chars for trace ID.
    hash[..32].to_string()
}

/// Derive a W3C span ID (16 hex chars) from an identifier.
///
/// Uses SHA-256 and takes bytes 16-24 (16 hex chars).
fn derive_span_id(id: &str) -> String {
    let hash = sha2_digest(id.as_bytes());
    // Bytes 16-24 = 16 hex chars for span ID.
    hash[32..48].to_string()
}

/// Compute SHA-256 hex digest.
fn sha2_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut s = String::with_capacity(result.len() * 2);
    for &b in result.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A no-op exporter that logs spans to tracing but does not send them anywhere.
///
/// Useful for development and testing when no OTel collector is available.
pub struct LoggingSpanExporter;

impl ReceiptSpanExporter for LoggingSpanExporter {
    fn export(&self, spans: &[ReceiptSpan]) -> Result<usize, TelemetryExportError> {
        for span in spans {
            tracing::info!(
                trace_id = %span.trace_id,
                span_id = %span.span_id,
                tool_name = %span.tool_name,
                verdict = %span.verdict,
                "receipt span exported"
            );
        }
        Ok(spans.len())
    }

    fn flush(&self) -> Result<(), TelemetryExportError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), TelemetryExportError> {
        Ok(())
    }
}

/// A JSON file exporter that writes spans to a JSONL file.
///
/// Each line is a JSON object representing one span. Useful for
/// offline analysis or piping into other tools.
pub struct JsonFileExporter {
    path: std::sync::Mutex<String>,
}

impl JsonFileExporter {
    /// Create a new JSON file exporter.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: std::sync::Mutex::new(path.into()),
        }
    }
}

impl ReceiptSpanExporter for JsonFileExporter {
    fn export(&self, spans: &[ReceiptSpan]) -> Result<usize, TelemetryExportError> {
        let path = self.path.lock().map_err(|e| {
            TelemetryExportError::ExportFailed(format!("lock poisoned: {e}"))
        })?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_str())
            .map_err(|e| {
                TelemetryExportError::ExportFailed(format!("failed to open file: {e}"))
            })?;

        let mut count = 0;
        for span in spans {
            let json = serde_json::to_string(span).map_err(|e| {
                TelemetryExportError::SerializationFailed(format!("{e}"))
            })?;
            use std::io::Write;
            writeln!(file, "{json}").map_err(|e| {
                TelemetryExportError::ExportFailed(format!("write failed: {e}"))
            })?;
            count += 1;
        }

        Ok(count)
    }

    fn flush(&self) -> Result<(), TelemetryExportError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), TelemetryExportError> {
        Ok(())
    }
}
