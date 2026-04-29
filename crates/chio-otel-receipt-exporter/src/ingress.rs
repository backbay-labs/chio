use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::sink::{OTelReceiptExportError, ReceiptStoreSink, ReceiptStoreSinkSummary};

/// Synchronous OTLP gRPC trace ingress facade.
///
/// The network listener owns protobuf decoding. This facade receives the decoded
/// export request and commits it through the receipt-store sink.
pub struct OtlpGrpcIngress {
    sink: ReceiptStoreSink,
}

impl OtlpGrpcIngress {
    pub fn new(sink: ReceiptStoreSink) -> Self {
        Self { sink }
    }

    pub fn export(
        &self,
        request: &OtlpGrpcTraceExport,
    ) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        self.sink.export_traces(request)
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundedOtlpExportSummary {
    pub queue: OtlpExporterEnqueueSummary,
    pub sink: ReceiptStoreSinkSummary,
}

pub struct BoundedOtlpGrpcIngress {
    sink: ReceiptStoreSink,
    config: OtlpExporterQueueConfig,
    queue: Mutex<BoundedOtlpQueue>,
}

impl BoundedOtlpGrpcIngress {
    pub fn new(sink: ReceiptStoreSink, config: OtlpExporterQueueConfig) -> Self {
        Self {
            sink,
            config: config.normalized(),
            queue: Mutex::new(BoundedOtlpQueue::default()),
        }
    }

    pub fn enqueue(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<OtlpExporterEnqueueSummary, OTelReceiptExportError> {
        let item = QueuedOtlpExport::new(request);
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.push_drop_oldest(item, self.config))
    }

    pub fn drain(&self) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let mut summary = ReceiptStoreSinkSummary::default();
        for _ in 0..self.config.drain_limit {
            let Some(item) = self.pop_front()? else {
                break;
            };
            let item_spans = item.spans;
            let item_summary = self.sink.export_traces(&item.export)?;
            summary.accepted_spans += item_summary.accepted_spans;
            summary.appended_receipts += item_summary.appended_receipts;
            self.record_appended(item_spans)?;
        }
        Ok(summary)
    }

    pub fn export(
        &self,
        request: OtlpGrpcTraceExport,
    ) -> Result<BoundedOtlpExportSummary, OTelReceiptExportError> {
        let queue = self.enqueue(request)?;
        let sink = self.drain()?;
        Ok(BoundedOtlpExportSummary { queue, sink })
    }

    pub fn snapshot(&self) -> Result<OtlpExporterQueueSnapshot, OTelReceiptExportError> {
        let queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.snapshot())
    }

    fn pop_front(&self) -> Result<Option<QueuedOtlpExport>, OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        Ok(queue.pop_front())
    }

    fn record_appended(&self, spans: usize) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        queue.appended_batches += 1;
        queue.appended_spans += spans as u64;
        Ok(())
    }
}

#[derive(Default)]
struct BoundedOtlpQueue {
    queue: VecDeque<QueuedOtlpExport>,
    queued_spans: usize,
    queued_bytes: usize,
    accepted_batches: u64,
    accepted_spans: u64,
    dropped_oldest_batches: u64,
    dropped_oldest_spans: u64,
    dropped_incoming_batches: u64,
    dropped_incoming_spans: u64,
    appended_batches: u64,
    appended_spans: u64,
}

impl BoundedOtlpQueue {
    fn push_drop_oldest(
        &mut self,
        item: QueuedOtlpExport,
        config: OtlpExporterQueueConfig,
    ) -> OtlpExporterEnqueueSummary {
        let mut summary = OtlpExporterEnqueueSummary::default();
        if item.spans > config.max_queued_spans
            || item.bytes > config.max_queued_bytes
            || config.max_queued_batches == 0
        {
            self.dropped_incoming_batches += 1;
            self.dropped_incoming_spans += item.spans as u64;
            summary.dropped_incoming_batches = 1;
            summary.dropped_incoming_spans = item.spans;
            summary.queued_batches = self.queue.len();
            summary.queued_spans = self.queued_spans;
            summary.queued_bytes = self.queued_bytes;
            return summary;
        }

        while self.queue.len() + 1 > config.max_queued_batches
            || self.queued_spans + item.spans > config.max_queued_spans
            || self.queued_bytes + item.bytes > config.max_queued_bytes
        {
            let Some(dropped) = self.pop_front() else {
                break;
            };
            self.dropped_oldest_batches += 1;
            self.dropped_oldest_spans += dropped.spans as u64;
            summary.dropped_oldest_batches += 1;
            summary.dropped_oldest_spans += dropped.spans;
        }

        summary.enqueued_batches = 1;
        summary.enqueued_spans = item.spans;
        self.accepted_batches += 1;
        self.accepted_spans += item.spans as u64;
        self.queued_spans += item.spans;
        self.queued_bytes += item.bytes;
        self.queue.push_back(item);
        summary.queued_batches = self.queue.len();
        summary.queued_spans = self.queued_spans;
        summary.queued_bytes = self.queued_bytes;
        summary
    }

    fn pop_front(&mut self) -> Option<QueuedOtlpExport> {
        let item = self.queue.pop_front()?;
        self.queued_spans = self.queued_spans.saturating_sub(item.spans);
        self.queued_bytes = self.queued_bytes.saturating_sub(item.bytes);
        Some(item)
    }

    fn snapshot(&self) -> OtlpExporterQueueSnapshot {
        OtlpExporterQueueSnapshot {
            queued_batches: self.queue.len(),
            queued_spans: self.queued_spans,
            queued_bytes: self.queued_bytes,
            accepted_batches: self.accepted_batches,
            accepted_spans: self.accepted_spans,
            dropped_oldest_batches: self.dropped_oldest_batches,
            dropped_oldest_spans: self.dropped_oldest_spans,
            dropped_incoming_batches: self.dropped_incoming_batches,
            dropped_incoming_spans: self.dropped_incoming_spans,
            appended_batches: self.appended_batches,
            appended_spans: self.appended_spans,
        }
    }
}

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
