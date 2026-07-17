//! chio-siem: SIEM integration for the Chio receipt audit pipeline.
//!
//! This crate provides the foundational abstractions for forwarding Chio receipt
//! events to external SIEM systems (Splunk, Elasticsearch, etc.).
//!
//! # Architecture
//!
//! chio-siem depends on chio-core (for ChioReceipt and FinancialReceiptMetadata),
//! rusqlite (for direct read access to the kernel receipt database), and
//! chio-kernel for its read-only receipt boundary (ReceiptReadBoundary /
//! ReceiptReadContext). The dependency is one-directional (chio-siem ->
//! chio-kernel): the kernel does not depend on chio-siem, so SIEM HTTP-client
//! surface stays out of the kernel TCB.
//!
//! The ExporterManager opens its own read-only rusqlite connection and pulls
//! receipts using a seq-based cursor. It fans out to registered Exporter
//! implementations with exponential backoff retry and a bounded DeadLetterQueue.

#![forbid(unsafe_code)]

pub mod alerting;
pub mod cursor_store;
pub mod dlq;
pub mod event;
pub mod exporter;
pub mod exporters;
pub mod manager;
pub mod metrics_sink;
pub mod ocsf;
pub mod ratelimit;
mod redaction;

pub use alerting::{
    derive_event_severity, derive_severity, Alert, AlertBackend, AlertSeverity, AlertingConfig,
    AlertingExporter, AlertingExporterBuilder, OpsGenieBackend, PagerDutyBackend,
};
pub use cursor_store::SiemCursorStore;
pub use dlq::{DeadLetterQueue, FailedEvent};
pub use event::SiemEvent;
pub use exporter::{ExportError, ExportFuture, Exporter};
pub use exporters::cef::{CefExporter, CefExporterConfig};
pub use exporters::datadog::{DatadogConfig, DatadogExporter};
pub use exporters::elastic::{ElasticAuthConfig, ElasticConfig, ElasticsearchExporter};
pub use exporters::ocsf_exporter::{OcsfExporter, OcsfExporterConfig, OcsfPayloadFormat};
pub use exporters::splunk::{SplunkConfig, SplunkHecExporter};
pub use exporters::sumo_logic::{SumoLogicConfig, SumoLogicExporter, SumoLogicFormat};
pub use exporters::webhook::{
    WebhookAuth, WebhookConfig, WebhookExporter, WebhookMethod, WebhookRetry,
};
pub use manager::{ExporterManager, SiemConfig, SiemError};
pub use metrics_sink::{noop_metrics_sink, ExportOutcome, NoopMetricsSink, SiemMetricsSink};
pub use ocsf::{
    receipt_to_ocsf, OCSF_CATEGORY_NAME, OCSF_CATEGORY_UID, OCSF_CLASS_NAME, OCSF_CLASS_UID,
    OCSF_PRODUCT_NAME, OCSF_PRODUCT_VENDOR, OCSF_SCHEMA_VERSION,
};
pub use ratelimit::{ExportRateLimiter, RateLimitConfig, RateLimitConfigError};
