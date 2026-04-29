//! OpenTelemetry trace ingress for Chio receipt stores.
//!
//! The crate accepts OTLP trace batches in a narrow Rust representation, signs
//! span-derived Chio receipts, appends them to a configured receipt store, and
//! exposes the high-cardinality attribute deny-list used before forwarding
//! span attributes to Prometheus-shaped sinks.

pub mod denylist;
pub mod ingress;
pub mod sink;

pub use denylist::{
    denied_attribute_keys, is_denied_attribute, strip_denied_attributes,
    strip_denied_batch_attributes, strip_denied_span_attributes, PROMETHEUS_DENIED_ATTRIBUTES,
};
pub use ingress::{
    BoundedOtlpExportSummary, BoundedOtlpGrpcIngress, OtlpAttribute, OtlpExporterEnqueueSummary,
    OtlpExporterQueueConfig, OtlpExporterQueueSnapshot, OtlpGrpcIngress, OtlpGrpcTraceExport,
    OtlpResourceSpans, OtlpSpan,
};
pub use sink::{
    CanonicalChioReceipt, CanonicalReceiptSink, OTelReceiptExportError, ReceiptStoreSink,
    ReceiptStoreSinkConfig, ReceiptStoreSinkSummary,
};
