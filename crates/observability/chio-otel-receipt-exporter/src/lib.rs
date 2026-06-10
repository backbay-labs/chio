//! OpenTelemetry trace ingress for Chio receipt stores.
//!
//! The crate accepts OTLP trace batches in a narrow Rust representation, signs
//! span-derived Chio receipts, appends them to a configured receipt store, and
//! exposes the high-cardinality attribute deny-list used before forwarding
//! span attributes to Prometheus-shaped sinks.

#![forbid(unsafe_code)]

#[cfg(not(loom))]
pub mod denylist;
#[cfg(not(loom))]
pub mod ingress;
#[cfg(loom)]
pub mod queue_core;
#[cfg(not(loom))]
mod queue_core;
#[cfg(not(loom))]
pub mod sink;

#[cfg(not(loom))]
pub use chio_kernel::{METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL, METRIC_CHIO_OTEL_SINK_DROP_TOTAL};

#[cfg(not(loom))]
pub use denylist::{
    denied_attribute_keys, is_denied_attribute, strip_denied_attributes,
    strip_denied_batch_attributes, strip_denied_span_attributes, PROMETHEUS_DENIED_ATTRIBUTES,
};
#[cfg(not(loom))]
pub use ingress::{
    BoundedOtlpExportSummary, BoundedOtlpGrpcIngress, OtlpAttribute, OtlpExporterEnqueueSummary,
    OtlpExporterQueueConfig, OtlpExporterQueueSnapshot, OtlpGrpcIngress, OtlpGrpcTraceExport,
    OtlpResourceSpans, OtlpSpan,
};
#[cfg(not(loom))]
pub use sink::{
    CanonicalChioReceipt, CanonicalReceiptSink, OTelReceiptExportError, ReceiptStoreSink,
    ReceiptStoreSinkConfig, ReceiptStoreSinkSummary, RECEIPT_EXPORT_MAX_ESTIMATED_BYTES,
    RECEIPT_EXPORT_MAX_RESOURCE_SPANS, RECEIPT_EXPORT_MAX_SPANS,
};
