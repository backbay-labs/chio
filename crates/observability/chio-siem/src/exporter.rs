//! Exporter trait and export error types for SIEM backends.

use std::future::Future;
use std::pin::Pin;

use crate::event::SiemEvent;

/// Error variants for SIEM export operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The HTTP request to the SIEM backend failed.
    #[error("http error: {0}")]
    HttpError(String),

    /// Event serialization failed before sending.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Some events in the batch were exported successfully, others failed.
    #[error("partial failure: {succeeded} succeeded, {failed} failed -- {details}")]
    PartialFailure {
        succeeded: usize,
        failed: usize,
        details: String,
    },
}

/// Boxed future returned by dyn-compatible async trait methods.
pub type ExportFuture<'a> = Pin<Box<dyn Future<Output = Result<usize, ExportError>> + Send + 'a>>;

/// Trait implemented by SIEM backend exporters (Splunk HEC, Elasticsearch, etc.).
///
/// Uses `Pin<Box<dyn Future>>` to remain dyn-compatible so ExporterManager can
/// hold exporters as `Box<dyn Exporter>` and fan out to multiple backends.
pub trait Exporter: Send + Sync {
    /// Export a batch of SIEM events to the backend.
    ///
    /// Returns the number of events successfully exported on success.
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a>;

    /// Return the human-readable name of this exporter (for logging and DLQ attribution).
    fn name(&self) -> &str;

    /// Stable, configuration-derived identity used as the durable cursor key so
    /// a persisted high-water mark follows this exporter across config reorders
    /// and insertions rather than its registration index. Built-in exporters
    /// return a static name (every `WebhookExporter` is "webhook"), so keying the
    /// durable cursor by index would let inserting or reordering a same-named
    /// exporter inherit a previous instance's `acked_seq` and skip receipts. An
    /// endpoint-bearing exporter overrides this to fold in its destination; the
    /// default is the bare name for exporters whose name already uniquely
    /// identifies the sink. Distinct from the metric label, which stays the bare
    /// name to keep label cardinality bounded.
    fn cursor_identity(&self) -> String {
        self.name().to_string()
    }

    /// Whether this exporter is a durable SOC audit-export sink whose per-row
    /// outcomes belong on the `chio_soc_export_total` / `_lag` / DLQ-depth
    /// families. A notification overlay (alerting) returns `false`: it records
    /// its own `chio_alert_dispatch_total` family, so counting it as a SOC export
    /// would let a PagerDuty/OpsGenie dispatch failure burn the SOC export SLO
    /// while audit export is healthy. Defaults `true`.
    fn is_soc_export_sink(&self) -> bool {
        true
    }
}
