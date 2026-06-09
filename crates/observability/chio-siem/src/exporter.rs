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
}
