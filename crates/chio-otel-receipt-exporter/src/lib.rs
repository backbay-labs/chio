//! OpenTelemetry trace ingress for Chio receipt stores.
//!
//! The crate accepts OTLP trace batches in a narrow Rust representation, signs
//! span-derived Chio receipts, appends them to a configured receipt store, and
//! exposes the high-cardinality attribute deny-list used before forwarding
//! span attributes to Prometheus-shaped sinks.

#[cfg(not(loom))]
pub mod denylist;
#[cfg(not(loom))]
pub mod ingress;
#[cfg(not(loom))]
pub mod sink;

pub const METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL: &str = "chio_otel_ingress_drop_total";
pub const METRIC_CHIO_OTEL_SINK_DROP_TOTAL: &str = "chio_otel_sink_drop_total";

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
    ReceiptStoreSinkConfig, ReceiptStoreSinkSummary,
};
