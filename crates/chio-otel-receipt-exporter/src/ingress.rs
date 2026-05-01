use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::queue_core::{
    BoundedDropOldestQueue, BoundedQueueItem, BoundedQueueLimits, BoundedQueuePushSummary,
    BoundedQueueSnapshot,
};
use crate::sink::{OTelReceiptExportError, ReceiptStoreSink, ReceiptStoreSinkSummary};

/// Synchronous OTLP gRPC trace ingress facade.
///
/// The network listener owns protobuf decoding. This facade receives the decoded
/// export request and commits it through the receipt-store sink.
pub struct OtlpGrpcIngress {
    bounded: BoundedOtlpGrpcIngress,
}

impl OtlpGrpcIngress {
    pub fn new(sink: ReceiptStoreSink) -> Self {
        Self::with_queue_config(sink, OtlpExporterQueueConfig::default())
    }

    pub fn with_queue_config(sink: ReceiptStoreSink, config: OtlpExporterQueueConfig) -> Self {
        Self {
            bounded: BoundedOtlpGrpcIngress::new(sink, config),
        }
    }

    pub fn export(
        &self,
        request: &OtlpGrpcTraceExport,
    ) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let summary = self.bounded.export(request.clone())?;
        if summary.queue.dropped_batches() > 0 {
            return Err(OTelReceiptExportError::Queue(format!(
                "OTEL queue dropped {} batch(es) during export",
                summary.queue.dropped_batches()
            )));
        }
        Ok(summary.sink)
    }

    pub fn enqueue(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<OtlpExporterEnqueueSummary, OTelReceiptExportError> {
        self.bounded.enqueue(request)
    }

    pub fn drain(&self) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        self.bounded.drain()
    }

    pub fn snapshot(&self) -> Result<OtlpExporterQueueSnapshot, OTelReceiptExportError> {
        self.bounded.snapshot()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtlpExporterQueueConfig {
    pub max_queued_batches: usize,
    pub max_queued_spans: usize,
    pub max_queued_bytes: usize,
    pub drain_limit: usize,
}

impl Default for OtlpExporterQueueConfig {
    fn default() -> Self {
        Self {
            max_queued_batches: 1024,
            max_queued_spans: 65_536,
            max_queued_bytes: 64 * 1024 * 1024,
            drain_limit: 128,
        }
    }
}

impl OtlpExporterQueueConfig {
    fn normalized(self) -> Self {
        Self {
            max_queued_batches: self.max_queued_batches,
            max_queued_spans: self.max_queued_spans,
            max_queued_bytes: self.max_queued_bytes,
            drain_limit: self.drain_limit.max(1),
        }
    }

    fn queue_limits(self) -> BoundedQueueLimits {
        BoundedQueueLimits {
            max_queued_batches: self.max_queued_batches,
            max_queued_spans: self.max_queued_spans,
            max_queued_bytes: self.max_queued_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtlpExporterQueueSnapshot {
    pub queued_batches: usize,
    pub queued_spans: usize,
    pub queued_bytes: usize,
    pub accepted_batches: u64,
    pub accepted_spans: u64,
    pub dropped_oldest_batches: u64,
    pub dropped_oldest_spans: u64,
    pub dropped_incoming_batches: u64,
    pub dropped_incoming_spans: u64,
    pub appended_batches: u64,
    pub appended_spans: u64,
    pub append_error_batches: u64,
    pub append_error_spans: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtlpExporterEnqueueSummary {
    pub enqueued_batches: usize,
    pub enqueued_spans: usize,
    pub dropped_oldest_batches: usize,
    pub dropped_oldest_spans: usize,
    pub dropped_incoming_batches: usize,
    pub dropped_incoming_spans: usize,
    pub queued_batches: usize,
    pub queued_spans: usize,
    pub queued_bytes: usize,
}

impl From<BoundedQueuePushSummary> for OtlpExporterEnqueueSummary {
    fn from(summary: BoundedQueuePushSummary) -> Self {
        Self {
            enqueued_batches: summary.enqueued_batches,
            enqueued_spans: summary.enqueued_spans,
            dropped_oldest_batches: summary.dropped_oldest_batches,
            dropped_oldest_spans: summary.dropped_oldest_spans,
            dropped_incoming_batches: summary.dropped_incoming_batches,
            dropped_incoming_spans: summary.dropped_incoming_spans,
            queued_batches: summary.queued_batches,
            queued_spans: summary.queued_spans,
            queued_bytes: summary.queued_bytes,
        }
    }
}

impl OtlpExporterEnqueueSummary {
    fn dropped_batches(self) -> usize {
        self.dropped_oldest_batches
            .saturating_add(self.dropped_incoming_batches)
    }
}

impl From<BoundedQueueSnapshot> for OtlpExporterQueueSnapshot {
    fn from(snapshot: BoundedQueueSnapshot) -> Self {
        Self {
            queued_batches: snapshot.queued_batches,
            queued_spans: snapshot.queued_spans,
            queued_bytes: snapshot.queued_bytes,
            accepted_batches: snapshot.accepted_batches,
            accepted_spans: snapshot.accepted_spans,
            dropped_oldest_batches: snapshot.dropped_oldest_batches,
            dropped_oldest_spans: snapshot.dropped_oldest_spans,
            dropped_incoming_batches: snapshot.dropped_incoming_batches,
            dropped_incoming_spans: snapshot.dropped_incoming_spans,
            appended_batches: snapshot.appended_batches,
            appended_spans: snapshot.appended_spans,
            append_error_batches: snapshot.append_error_batches,
            append_error_spans: snapshot.append_error_spans,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundedOtlpExportSummary {
    pub queue: OtlpExporterEnqueueSummary,
    pub sink: ReceiptStoreSinkSummary,
}

pub struct BoundedOtlpGrpcIngress {
    sink: ReceiptStoreSink,
    config: OtlpExporterQueueConfig,
    queue: Mutex<BoundedOtlpQueue>,
    flow_lock: Mutex<()>,
}

impl BoundedOtlpGrpcIngress {
    pub fn new(sink: ReceiptStoreSink, config: OtlpExporterQueueConfig) -> Self {
        Self {
            sink,
            config: config.normalized(),
            queue: Mutex::new(BoundedOtlpQueue::default()),
            flow_lock: Mutex::new(()),
        }
    }

    pub fn enqueue(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<OtlpExporterEnqueueSummary, OTelReceiptExportError> {
        let _flow = self.lock_flow()?;
        self.enqueue_locked(request)
    }

    pub fn drain(&self) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let _flow = self.lock_flow()?;
        self.drain_locked()
    }

    pub fn export(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<BoundedOtlpExportSummary, OTelReceiptExportError> {
        let _flow = self.lock_flow()?;
        let queue = self.enqueue_locked(request)?;
        let sink = self.drain_locked()?;
        Ok(BoundedOtlpExportSummary { queue, sink })
    }

    pub fn snapshot(&self) -> Result<OtlpExporterQueueSnapshot, OTelReceiptExportError> {
        let queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.snapshot().into())
    }

    fn lock_flow(&self) -> Result<MutexGuard<'_, ()>, OTelReceiptExportError> {
        self.flow_lock.lock().map_err(|_| {
            OTelReceiptExportError::Queue("OTEL queue flow mutex poisoned".to_string())
        })
    }

    fn enqueue_locked(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<OtlpExporterEnqueueSummary, OTelReceiptExportError> {
        let item = QueuedOtlpExport::new(request);
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue
            .push_drop_oldest(item, self.config.queue_limits())
            .into())
    }

    fn drain_locked(&self) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let mut summary = ReceiptStoreSinkSummary::default();
        for _ in 0..self.config.drain_limit {
            let Some((export, spans)) = self.front_export()? else {
                break;
            };
            let item_summary = match self.sink.export_traces(&export) {
                Ok(item_summary) => item_summary,
                Err(error) => {
                    let retain_batch = error.is_retryable_batch_error();
                    self.record_append_error(spans)?;
                    if !retain_batch {
                        let _ = self.pop_front()?;
                    }
                    return Err(error);
                }
            };
            let _ = self.pop_front()?;
            summary.accepted_spans += item_summary.accepted_spans;
            summary.appended_receipts += item_summary.appended_receipts;
            self.record_appended(spans)?;
        }
        Ok(summary)
    }

    fn pop_front(&self) -> Result<Option<QueuedOtlpExport>, OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.pop_front())
    }

    fn front_export(&self) -> Result<Option<(OtlpGrpcTraceExport, usize)>, OTelReceiptExportError> {
        let queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.front().map(|item| (item.export.clone(), item.spans)))
    }

    fn record_appended(&self, spans: usize) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        queue.record_appended(spans);
        Ok(())
    }

    fn record_append_error(&self, spans: usize) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        queue.record_append_error(spans);
        Ok(())
    }
}

type BoundedOtlpQueue = BoundedDropOldestQueue<QueuedOtlpExport>;

struct QueuedOtlpExport {
    export: OtlpGrpcTraceExport,
    spans: usize,
    bytes: usize,
}

impl QueuedOtlpExport {
    fn new(export: OtlpGrpcTraceExport) -> Self {
        let spans = export.span_count();
        let bytes = export.estimated_bytes();
        Self {
            export,
            spans,
            bytes,
        }
    }
}

impl BoundedQueueItem for QueuedOtlpExport {
    fn spans(&self) -> usize {
        self.spans
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

/// OTLP gRPC trace export payload after protobuf decoding.
///
/// Production ingress can decode `ExportTraceServiceRequest` into this stable
/// crate-local shape before sending spans to the receipt sink. Tests and offline
/// collectors can construct it directly.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpGrpcTraceExport {
    #[serde(default)]
    pub resource_spans: Vec<OtlpResourceSpans>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpResourceSpans {
    #[serde(default)]
    pub resource_attributes: Vec<OtlpAttribute>,
    #[serde(default)]
    pub spans: Vec<OtlpSpan>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtlpSpan {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    #[serde(default)]
    pub attributes: Vec<OtlpAttribute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_unix_nano: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at_unix_nano: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtlpAttribute {
    pub key: String,
    pub value: serde_json::Value,
}

impl OtlpGrpcTraceExport {
    pub fn from_spans(spans: Vec<OtlpSpan>) -> Self {
        Self {
            resource_spans: vec![OtlpResourceSpans {
                resource_attributes: Vec::new(),
                spans,
            }],
        }
    }

    pub fn span_count(&self) -> usize {
        self.resource_spans
            .iter()
            .map(|resource| resource.spans.len())
            .sum()
    }

    pub fn spans(&self) -> impl Iterator<Item = &OtlpSpan> {
        self.resource_spans
            .iter()
            .flat_map(|resource| resource.spans.iter())
    }

    pub fn estimated_bytes(&self) -> usize {
        self.resource_spans
            .iter()
            .map(OtlpResourceSpans::estimated_bytes)
            .sum()
    }
}

impl OtlpResourceSpans {
    pub fn resource_attribute_map(&self) -> BTreeMap<String, serde_json::Value> {
        attributes_to_map(&self.resource_attributes)
    }

    fn estimated_bytes(&self) -> usize {
        self.resource_attributes
            .iter()
            .map(OtlpAttribute::estimated_bytes)
            .sum::<usize>()
            + self
                .spans
                .iter()
                .map(OtlpSpan::estimated_bytes)
                .sum::<usize>()
    }
}

impl OtlpSpan {
    pub fn new(
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            name: name.into(),
            attributes: Vec::new(),
            started_at_unix_nano: None,
            ended_at_unix_nano: None,
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.push(OtlpAttribute {
            key: key.into(),
            value,
        });
        self
    }

    pub fn attribute_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes
            .iter()
            .find(|attribute| attribute.key == key)
            .map(|attribute| &attribute.value)
    }

    pub fn attribute_string(&self, key: &str) -> Option<&str> {
        self.attribute_value(key)
            .and_then(serde_json::Value::as_str)
    }

    pub fn attribute_map(&self) -> BTreeMap<String, serde_json::Value> {
        attributes_to_map(&self.attributes)
    }

    fn estimated_bytes(&self) -> usize {
        self.trace_id.len()
            + self.span_id.len()
            + self.name.len()
            + self
                .attributes
                .iter()
                .map(OtlpAttribute::estimated_bytes)
                .sum::<usize>()
            + usize::from(self.started_at_unix_nano.is_some()) * std::mem::size_of::<u64>()
            + usize::from(self.ended_at_unix_nano.is_some()) * std::mem::size_of::<u64>()
    }
}

impl OtlpAttribute {
    fn estimated_bytes(&self) -> usize {
        self.key.len() + json_estimated_bytes(&self.value)
    }
}

pub(crate) fn attributes_to_map(
    attributes: &[OtlpAttribute],
) -> BTreeMap<String, serde_json::Value> {
    attributes
        .iter()
        .map(|attribute| (attribute.key.clone(), attribute.value.clone()))
        .collect()
}

fn json_estimated_bytes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 0,
        serde_json::Value::Bool(_) => 1,
        serde_json::Value::Number(number) => number.to_string().len(),
        serde_json::Value::String(string) => string.len(),
        serde_json::Value::Array(values) => values.iter().map(json_estimated_bytes).sum(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| key.len() + json_estimated_bytes(value))
            .sum(),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::{Arc, Mutex};

    use chio_core::crypto::Keypair;
    use chio_kernel::receipt_store::ReceiptStoreError;

    use crate::sink::{CanonicalChioReceipt, CanonicalReceiptSink, ReceiptStoreSinkConfig};

    use super::*;

    #[derive(Default)]
    struct RecordingCanonicalSink {
        receipts: Mutex<Vec<CanonicalChioReceipt>>,
    }

    struct FailingCanonicalSink;

    impl RecordingCanonicalSink {
        fn receipt_names(&self) -> Result<Vec<String>, ReceiptStoreError> {
            let guard = self
                .receipts
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("receipt mutex poisoned".to_string()))?;
            Ok(guard
                .iter()
                .filter_map(|receipt| {
                    receipt
                        .receipt()
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata["otel"]["span_name"].as_str())
                        .map(str::to_string)
                })
                .collect())
        }
    }

    impl CanonicalReceiptSink for RecordingCanonicalSink {
        fn append_chio_receipt_canonical(
            &self,
            receipt: CanonicalChioReceipt,
        ) -> Result<(), ReceiptStoreError> {
            let mut guard = self
                .receipts
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("receipt mutex poisoned".to_string()))?;
            guard.push(receipt);
            Ok(())
        }
    }

    impl CanonicalReceiptSink for FailingCanonicalSink {
        fn append_chio_receipt_canonical(
            &self,
            _receipt: CanonicalChioReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Err(ReceiptStoreError::Pool("forced append failure".to_string()))
        }
    }

    #[test]
    fn ingress_facade_crosses_bounded_queue() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let sink = ReceiptStoreSink::new_canonical(
            recorder.clone(),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = OtlpGrpcIngress::new(sink);

        let delivered = ingress.export(&export_with_span("span-1"))?;
        let snapshot = ingress.snapshot()?;

        assert_eq!(delivered.appended_receipts, 1);
        assert_eq!(snapshot.accepted_batches, 1);
        assert_eq!(snapshot.appended_batches, 1);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(recorder.receipt_names()?, vec!["span-1".to_string()]);

        Ok(())
    }

    #[test]
    fn bounded_ingress_delivers_queued_batch() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let ingress = bounded_ingress(recorder.clone(), OtlpExporterQueueConfig::default());

        let enqueue = ingress.enqueue(export_with_span("span-1"))?;
        let delivered = ingress.drain()?;
        let snapshot = ingress.snapshot()?;

        assert_eq!(enqueue.enqueued_batches, 1);
        assert_eq!(enqueue.enqueued_spans, 1);
        assert_eq!(delivered.appended_receipts, 1);
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.appended_batches, 1);
        assert_eq!(snapshot.appended_spans, 1);
        assert_eq!(recorder.receipt_names()?, vec!["span-1".to_string()]);

        Ok(())
    }

    #[test]
    fn bounded_ingress_drops_oldest_batch_on_overload() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let config = OtlpExporterQueueConfig {
            max_queued_batches: 2,
            max_queued_spans: 8,
            max_queued_bytes: 8192,
            drain_limit: 8,
        };
        let ingress = bounded_ingress(recorder.clone(), config);

        assert_eq!(
            ingress
                .enqueue(export_with_span("span-1"))?
                .enqueued_batches,
            1
        );
        assert_eq!(
            ingress
                .enqueue(export_with_span("span-2"))?
                .enqueued_batches,
            1
        );
        let third = ingress.enqueue(export_with_span("span-3"))?;
        let delivered = ingress.drain()?;
        let snapshot = ingress.snapshot()?;

        assert_eq!(third.dropped_oldest_batches, 1);
        assert_eq!(third.dropped_oldest_spans, 1);
        assert_eq!(delivered.appended_receipts, 2);
        assert_eq!(snapshot.dropped_oldest_batches, 1);
        assert_eq!(snapshot.dropped_oldest_spans, 1);
        assert_eq!(
            recorder.receipt_names()?,
            vec!["span-2".to_string(), "span-3".to_string()]
        );

        Ok(())
    }

    #[test]
    fn ingress_facade_reports_queue_admission_drops() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let sink = ReceiptStoreSink::new_canonical(
            recorder,
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = OtlpGrpcIngress::with_queue_config(
            sink,
            OtlpExporterQueueConfig {
                max_queued_batches: 0,
                max_queued_spans: 8,
                max_queued_bytes: 8192,
                drain_limit: 8,
            },
        );

        let error = match ingress.export(&export_with_span("span-dropped")) {
            Ok(_) => {
                return Err(std::io::Error::other("dropped export was reported as accepted").into())
            }
            Err(error) => error,
        };
        let snapshot = ingress.snapshot()?;

        assert!(matches!(error, OTelReceiptExportError::Queue(_)));
        assert_eq!(snapshot.dropped_incoming_batches, 1);
        assert_eq!(snapshot.dropped_incoming_spans, 1);
        assert_eq!(snapshot.appended_batches, 0);

        Ok(())
    }

    #[test]
    fn bounded_ingress_keeps_failed_append_queued() -> Result<(), Box<dyn Error>> {
        let sink = ReceiptStoreSink::new_canonical(
            Arc::new(FailingCanonicalSink),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = BoundedOtlpGrpcIngress::new(sink, OtlpExporterQueueConfig::default());

        let enqueue = ingress.enqueue(export_with_span("span-1"))?;
        let error = match ingress.drain() {
            Ok(_) => return Err(std::io::Error::other("failing sink accepted append").into()),
            Err(error) => error,
        };
        let snapshot = ingress.snapshot()?;

        assert_eq!(enqueue.enqueued_batches, 1);
        assert!(matches!(error, OTelReceiptExportError::ReceiptStore(_)));
        assert_eq!(snapshot.queued_batches, 1);
        assert_eq!(snapshot.append_error_batches, 1);
        assert_eq!(snapshot.append_error_spans, 1);
        assert_eq!(snapshot.appended_batches, 0);

        Ok(())
    }

    #[test]
    fn bounded_ingress_drops_non_retryable_failed_batch() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let ingress = bounded_ingress(recorder, OtlpExporterQueueConfig::default());
        let invalid = OtlpGrpcTraceExport::from_spans(vec![OtlpSpan::new(
            "not-a-trace-id",
            "0123456789abcdef",
            "span-invalid",
        )
        .with_attribute("chio.verdict", serde_json::json!("allow"))]);

        let enqueue = ingress.enqueue(invalid)?;
        let error = match ingress.drain() {
            Ok(_) => return Err(std::io::Error::other("invalid batch was accepted").into()),
            Err(error) => error,
        };
        let snapshot = ingress.snapshot()?;

        assert_eq!(enqueue.enqueued_batches, 1);
        assert!(matches!(error, OTelReceiptExportError::InvalidSpan(_)));
        assert_eq!(snapshot.queued_batches, 0);
        assert_eq!(snapshot.append_error_batches, 1);
        assert_eq!(snapshot.append_error_spans, 1);
        assert_eq!(snapshot.appended_batches, 0);

        Ok(())
    }

    fn bounded_ingress(
        recorder: Arc<RecordingCanonicalSink>,
        config: OtlpExporterQueueConfig,
    ) -> BoundedOtlpGrpcIngress {
        let sink = ReceiptStoreSink::new_canonical(
            recorder,
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        BoundedOtlpGrpcIngress::new(sink, config)
    }

    fn export_with_span(name: &str) -> OtlpGrpcTraceExport {
        OtlpGrpcTraceExport::from_spans(vec![OtlpSpan::new(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef",
            name,
        )
        .with_attribute("chio.verdict", serde_json::json!("allow"))])
    }
}
