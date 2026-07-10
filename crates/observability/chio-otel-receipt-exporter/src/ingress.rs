use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::queue_core::{
    BoundedDropOldestQueue, BoundedQueueItem, BoundedQueueLimits, BoundedQueuePushSummary,
    BoundedQueueSnapshot,
};
use crate::sink::{
    CanonicalChioReceipt, OTelReceiptExportError, ReceiptStoreSink, ReceiptStoreSinkSummary,
};

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
        let summary = queue.push_drop_oldest(item, self.config.queue_limits());
        // Count every batch dropped by bounded-queue admission (drop-oldest to
        // make room, or drop-incoming when full), reconciling with the
        // snapshot's dropped_*_batches fields.
        let dropped_batches = summary.dropped_oldest_batches + summary.dropped_incoming_batches;
        if dropped_batches > 0 {
            chio_metrics_spec::runtime::families::OTEL_INGRESS_DROP
                .incr_by(&[], dropped_batches as u64);
        }
        Ok(summary.into())
    }

    /// Ensure the front item's receipts are generated once (cached on the item)
    /// and return a clone of (prepared receipts, resume cursor, span count).
    /// Generation is pure (no store append), so doing it under the queue lock is
    /// safe.
    #[allow(clippy::type_complexity)]
    fn prepare_front(
        &self,
    ) -> Result<
        Option<(
            Result<Vec<CanonicalChioReceipt>, OTelReceiptExportError>,
            usize,
            usize,
        )>,
        OTelReceiptExportError,
    > {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        let Some(item) = queue.front_mut() else {
            return Ok(None);
        };
        let appended = item.appended;
        let spans = item.spans;
        // Generate the receipts once and cache them on the item. On failure the
        // caller records the error and drops/retains the batch (like an append
        // failure), so a poison-pill batch never wedges the queue.
        let mut newly_cached_bytes = 0usize;
        if item.prepared.is_none() {
            match self.sink.prepare_receipts(&item.export) {
                Ok(receipts) => {
                    // Charge the cached signed receipts against the queue byte
                    // budget so a batch held open during a store outage cannot
                    // exceed the 64 MiB limit while snapshots report it in
                    // budget.
                    newly_cached_bytes = estimate_prepared_bytes(&receipts);
                    item.prepared_bytes = newly_cached_bytes;
                    item.prepared = Some(receipts);
                }
                Err(error) => return Ok(Some((Err(error), appended, spans))),
            }
        }
        let prepared = item.prepared.clone().unwrap_or_default();
        // `item` (a &mut borrow of `queue`) is no longer used past this point, so
        // the queue can be reborrowed to fold the cached receipt bytes into
        // `queued_bytes`. pop_front subtracts them again via item.bytes().
        if newly_cached_bytes > 0 {
            queue.record_prepared_bytes(newly_cached_bytes);
        }
        Ok(Some((Ok(prepared), appended, spans)))
    }

    fn set_front_appended(&self, appended: usize) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        if let Some(item) = queue.front_mut() {
            item.appended = appended;
        }
        Ok(())
    }

    fn drain_locked(&self) -> Result<ReceiptStoreSinkSummary, OTelReceiptExportError> {
        let mut summary = ReceiptStoreSinkSummary::default();
        for _ in 0..self.config.drain_limit {
            let Some((prepare_result, already, spans)) = self.prepare_front()? else {
                break;
            };
            let prepared = match prepare_result {
                Ok(prepared) => prepared,
                Err(error) => {
                    // Receipt generation failed (validation/signing). Treat like
                    // an append failure: record the unappended spans and drop the
                    // batch unless the failure is retryable.
                    let remaining = spans.saturating_sub(already);
                    if remaining > 0 {
                        self.record_append_error(remaining)?;
                    }
                    if !error.is_retryable_batch_error() {
                        let _ = self.pop_front()?;
                        // Terminal, non-retryable: the unappended spans are lost.
                        if remaining > 0 {
                            self.record_sink_drop();
                        }
                    }
                    return Err(error);
                }
            };
            let mut appended = already;
            let append_result = self.sink.append_from(&prepared, &mut appended);
            let newly = appended.saturating_sub(already);
            if newly > 0 {
                // Span accounting only: a partial append records the spans it
                // managed to write, but the BATCH is not counted as completed
                // until the whole batch drains on the Ok path below. This keeps
                // one batch resumed across retries from being counted as several
                // completed batches, or as completed while it is still queued.
                self.record_appended_spans(newly)?;
            }
            match append_result {
                Ok(()) => {
                    // The whole batch drained: count exactly one completed batch
                    // here, never per partial append.
                    self.record_appended_batch()?;
                    let _ = self.pop_front()?;
                    // Count only receipts appended DURING THIS drain. After a
                    // retryable partial append, `already` receipts were appended
                    // (and summarized) in a prior drain, so adding the whole
                    // batch size here would double-count them.
                    summary.accepted_spans += newly;
                    summary.appended_receipts += newly;
                }
                Err(error) => {
                    let remaining = spans.saturating_sub(appended);
                    if remaining > 0 {
                        self.record_append_error(remaining)?;
                    }
                    if error.is_retryable_batch_error() {
                        // Keep the batch AND its prepared receipts AND its resume
                        // cursor, so the next drain re-appends only appended..n
                        // with the SAME ids. This is NOT a drop: no drop counter.
                        self.set_front_appended(appended)?;
                    } else {
                        let _ = self.pop_front()?;
                        // Terminal, non-retryable: the unappended spans are lost.
                        if remaining > 0 {
                            self.record_sink_drop();
                        }
                    }
                    return Err(error);
                }
            }
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

    fn record_appended_spans(&self, spans: usize) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        queue.record_appended_spans(spans);
        Ok(())
    }

    fn record_appended_batch(&self) -> Result<(), OTelReceiptExportError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| OTelReceiptExportError::Queue("OTEL queue mutex poisoned".to_string()))?;
        queue.record_appended_batch();
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

    /// Count a terminal, non-retryable batch drop. Distinct from
    /// `record_append_error`: a retryable append error retains the batch with
    /// its resume cursor and re-appends it on the next
    /// drain, so it is NOT a drop and must not increment this counter, otherwise
    /// transient store saturation reads as real data loss.
    fn record_sink_drop(&self) {
        chio_metrics_spec::runtime::families::OTEL_SINK_DROP.incr(&[]);
    }
}

type BoundedOtlpQueue = BoundedDropOldestQueue<QueuedOtlpExport>;

struct QueuedOtlpExport {
    export: OtlpGrpcTraceExport,
    spans: usize,
    bytes: usize,
    /// Signed receipts generated once for this batch. Kept so a retryable append
    /// failure resumes with the SAME ids rather than re-signing.
    prepared: Option<Vec<CanonicalChioReceipt>>,
    /// Resident bytes of the cached `prepared` receipts, counted toward the
    /// queue byte budget. Zero until the receipts are prepared; mirrored into
    /// the queue's `queued_bytes` when they are cached so the bounded queue
    /// accounts a batch retained during a store outage at its real memory
    /// footprint, not just its original OTLP estimate.
    prepared_bytes: usize,
    /// Resume cursor: how many of `prepared` have been appended so far.
    appended: usize,
}

impl QueuedOtlpExport {
    fn new(export: OtlpGrpcTraceExport) -> Self {
        let spans = export.span_count();
        let bytes = export.estimated_bytes();
        Self {
            export,
            spans,
            bytes,
            prepared: None,
            prepared_bytes: 0,
            appended: 0,
        }
    }
}

/// Estimate the resident bytes of a prepared receipt batch from the length of
/// each receipt's canonical serialization. Used to charge the cached signed
/// receipts against the bounded queue's byte budget.
fn estimate_prepared_bytes(receipts: &[CanonicalChioReceipt]) -> usize {
    receipts
        .iter()
        .map(|receipt| receipt.canonical_bytes().len())
        .fold(0usize, usize::saturating_add)
}

impl BoundedQueueItem for QueuedOtlpExport {
    fn spans(&self) -> usize {
        self.spans
    }

    fn bytes(&self) -> usize {
        // Include the cached signed receipts so a batch retained after a
        // retryable append error is accounted at its true resident size; the
        // queue adds these bytes when they are cached (`record_prepared_bytes`)
        // and subtracts them here on pop, keeping `queued_bytes` consistent.
        self.bytes.saturating_add(self.prepared_bytes)
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
        self.resource_spans.iter().fold(0usize, |total, resource| {
            total.saturating_add(resource.estimated_bytes())
        })
    }
}

impl OtlpResourceSpans {
    pub fn resource_attribute_map(&self) -> BTreeMap<String, serde_json::Value> {
        attributes_to_map(&self.resource_attributes)
    }

    fn estimated_bytes(&self) -> usize {
        let resource_bytes = self
            .resource_attributes
            .iter()
            .map(OtlpAttribute::estimated_bytes)
            .fold(0usize, usize::saturating_add);
        let span_bytes = self
            .spans
            .iter()
            .map(OtlpSpan::estimated_bytes)
            .fold(0usize, usize::saturating_add);
        resource_bytes.saturating_add(span_bytes)
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
        let attribute_bytes = self
            .attributes
            .iter()
            .map(OtlpAttribute::estimated_bytes)
            .fold(0usize, usize::saturating_add);
        self.trace_id
            .len()
            .saturating_add(self.span_id.len())
            .saturating_add(self.name.len())
            .saturating_add(attribute_bytes)
            .saturating_add(
                usize::from(self.started_at_unix_nano.is_some()) * std::mem::size_of::<u64>(),
            )
            .saturating_add(
                usize::from(self.ended_at_unix_nano.is_some()) * std::mem::size_of::<u64>(),
            )
    }
}

impl OtlpAttribute {
    fn estimated_bytes(&self) -> usize {
        self.key
            .len()
            .saturating_add(json_estimated_bytes(&self.value))
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
        serde_json::Value::Array(values) => values
            .iter()
            .map(json_estimated_bytes)
            .fold(0usize, usize::saturating_add),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| key.len().saturating_add(json_estimated_bytes(value)))
            .fold(0usize, usize::saturating_add),
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

    /// Serializes the tests that read/advance the process-global
    /// `chio_otel_sink_drop_total` counter, so before/after deltas are
    /// deterministic under the parallel test harness.
    static SINK_DROP_COUNTER_LOCK: Mutex<()> = Mutex::new(());

    /// Read the current process-global sink-drop counter value.
    fn sink_drop_count() -> u64 {
        let mut rendered = String::new();
        chio_metrics_spec::runtime::families::OTEL_SINK_DROP.render(&mut rendered);
        rendered
            .lines()
            .find(|line| line.starts_with("chio_otel_sink_drop_total "))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

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
    fn ingress_admission_drop_increments_counter() -> Result<(), Box<dyn Error>> {
        use chio_metrics_spec::runtime::families;
        let mut before = String::new();
        families::OTEL_INGRESS_DROP.render(&mut before);

        // Bounded queue of 2 batches; the third enqueue drops the oldest.
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let config = OtlpExporterQueueConfig {
            max_queued_batches: 2,
            max_queued_spans: 8,
            max_queued_bytes: 8192,
            drain_limit: 8,
        };
        let ingress = bounded_ingress(recorder, config);
        let _ = ingress.enqueue(export_with_span("drop-span-1"))?;
        let _ = ingress.enqueue(export_with_span("drop-span-2"))?;
        let third = ingress.enqueue(export_with_span("drop-span-3"))?;
        assert_eq!(third.dropped_oldest_batches, 1);

        let mut after = String::new();
        families::OTEL_INGRESS_DROP.render(&mut after);
        assert!(
            after.contains("chio_otel_ingress_drop_total "),
            "ingress drop series must exist: {after}"
        );
        assert_ne!(before, after, "an admission drop must advance the counter");
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
        let _guard = SINK_DROP_COUNTER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// A RETRYABLE append error retains the batch for redelivery, so it must NOT
    /// increment the sink-drop counter. A `Pool` error is retryable.
    #[test]
    fn retryable_append_error_does_not_count_a_sink_drop() -> Result<(), Box<dyn Error>> {
        let _guard = SINK_DROP_COUNTER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sink = ReceiptStoreSink::new_canonical(
            Arc::new(FailingCanonicalSink),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = BoundedOtlpGrpcIngress::new(sink, OtlpExporterQueueConfig::default());
        ingress.enqueue(export_with_span("span-retry"))?;

        let before = sink_drop_count();
        // A retryable append failure keeps the batch queued; nothing is dropped.
        let _ = ingress.drain();

        assert_eq!(
            sink_drop_count(),
            before,
            "a retryable append error must not advance chio_otel_sink_drop_total"
        );
        assert_eq!(
            ingress.snapshot()?.queued_batches,
            1,
            "the retryable batch is retained for redelivery, not dropped"
        );
        Ok(())
    }

    /// A TERMINAL, non-retryable append error drops the batch (data lost), so it
    /// must increment the sink-drop counter exactly once. An `InvalidSpan` error
    /// is non-retryable.
    #[test]
    fn terminal_append_error_counts_exactly_one_sink_drop() -> Result<(), Box<dyn Error>> {
        let _guard = SINK_DROP_COUNTER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recorder = Arc::new(RecordingCanonicalSink::default());
        let ingress = bounded_ingress(recorder, OtlpExporterQueueConfig::default());
        let invalid = OtlpGrpcTraceExport::from_spans(vec![OtlpSpan::new(
            "not-a-trace-id",
            "0123456789abcdef",
            "span-invalid-drop",
        )
        .with_attribute("chio.verdict", serde_json::json!("allow"))]);
        ingress.enqueue(invalid)?;

        let before = sink_drop_count();
        let _ = ingress.drain();

        assert_eq!(
            sink_drop_count(),
            before + 1,
            "a terminal, non-retryable drop must advance chio_otel_sink_drop_total once"
        );
        assert_eq!(
            ingress.snapshot()?.queued_batches,
            0,
            "the terminally-failed batch is removed from the queue"
        );
        Ok(())
    }

    /// A sink that appends the first `fail_after` receipts, then fails ONCE with
    /// a retryable `Pool` error, then appends everything on the retry. Used to
    /// exercise the partial-append resume path.
    struct PartialThenRetrySink {
        appended: Mutex<usize>,
        fail_after: usize,
        failed_once: Mutex<bool>,
    }

    impl CanonicalReceiptSink for PartialThenRetrySink {
        fn append_chio_receipt_canonical(
            &self,
            _receipt: CanonicalChioReceipt,
        ) -> Result<(), ReceiptStoreError> {
            let mut appended = self
                .appended
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("appended mutex poisoned".to_string()))?;
            let mut failed_once = self
                .failed_once
                .lock()
                .map_err(|_| ReceiptStoreError::Pool("failed_once mutex poisoned".to_string()))?;
            if !*failed_once && *appended >= self.fail_after {
                *failed_once = true;
                return Err(ReceiptStoreError::Pool(
                    "forced retryable partial append failure".to_string(),
                ));
            }
            *appended += 1;
            Ok(())
        }
    }

    /// After a retryable partial append, the retry must count only the NEWLY
    /// appended receipts in its success summary, not the whole batch (which
    /// would double-count the receipts appended on the first attempt).
    #[test]
    fn retry_after_partial_append_counts_only_newly_appended() -> Result<(), Box<dyn Error>> {
        let sink = ReceiptStoreSink::new_canonical(
            Arc::new(PartialThenRetrySink {
                appended: Mutex::new(0),
                fail_after: 1,
                failed_once: Mutex::new(false),
            }),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = BoundedOtlpGrpcIngress::new(sink, OtlpExporterQueueConfig::default());
        ingress.enqueue(export_with_two_spans("span-a", "span-b"))?;

        // First drain: appends 1 of 2 receipts, then fails retryably, so the
        // batch is retained with its resume cursor at 1.
        let first = ingress.drain();
        assert!(
            first.is_err(),
            "the partial append must surface the retryable error"
        );
        assert_eq!(
            ingress.snapshot()?.queued_batches,
            1,
            "the retryable batch is retained for redelivery"
        );

        // Second drain: appends only the remaining receipt. The summary must
        // report the 1 newly appended receipt, not the full 2-span batch.
        let summary = ingress.drain()?;
        assert_eq!(
            summary.appended_receipts, 1,
            "the retry counts only the newly appended receipt: {summary:?}"
        );
        assert_eq!(
            summary.accepted_spans, 1,
            "the retry counts only the newly accepted span: {summary:?}"
        );
        assert_eq!(ingress.snapshot()?.queued_batches, 0);
        Ok(())
    }

    /// A partial append that fails retryably must NOT count the batch as
    /// completed (it is still queued for retry), and the batch must be counted
    /// exactly once when it finally drains, never once per partial append.
    #[test]
    fn partial_append_counts_the_batch_once_on_completion() -> Result<(), Box<dyn Error>> {
        let sink = ReceiptStoreSink::new_canonical(
            Arc::new(PartialThenRetrySink {
                appended: Mutex::new(0),
                fail_after: 1,
                failed_once: Mutex::new(false),
            }),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = BoundedOtlpGrpcIngress::new(sink, OtlpExporterQueueConfig::default());
        ingress.enqueue(export_with_two_spans("span-a", "span-b"))?;

        // First drain appends 1 of 2 receipts, then fails retryably and retains
        // the batch. The batch is still queued, so it must NOT be counted as an
        // appended (completed) batch; only its 1 appended span is accounted.
        let first = ingress.drain();
        assert!(first.is_err(), "the partial append must surface the error");
        let after_partial = ingress.snapshot()?;
        assert_eq!(
            after_partial.appended_batches, 0,
            "a batch retained for retry must not count as a completed batch: {after_partial:?}"
        );
        assert_eq!(
            after_partial.appended_spans, 1,
            "the 1 span appended before the failure is accounted: {after_partial:?}"
        );
        assert_eq!(after_partial.queued_batches, 1);

        // Second drain appends the remaining receipt and completes the batch,
        // which is counted exactly once (not twice).
        ingress.drain()?;
        let after_complete = ingress.snapshot()?;
        assert_eq!(
            after_complete.appended_batches, 1,
            "the resumed batch is counted exactly once on completion: {after_complete:?}"
        );
        assert_eq!(
            after_complete.appended_spans, 2,
            "both spans are accounted across the two drains: {after_complete:?}"
        );
        assert_eq!(after_complete.queued_batches, 0);
        Ok(())
    }

    /// A batch retained after a retryable append error keeps its signed receipts
    /// cached in the queue, so those bytes must count toward the bounded queue's
    /// byte budget rather than being invisible to `queued_bytes`.
    #[test]
    fn retained_batch_accounts_cached_receipt_bytes_in_queue_budget() -> Result<(), Box<dyn Error>>
    {
        let sink = ReceiptStoreSink::new_canonical(
            Arc::new(FailingCanonicalSink),
            ReceiptStoreSinkConfig::new(Keypair::generate()),
        );
        let ingress = BoundedOtlpGrpcIngress::new(sink, OtlpExporterQueueConfig::default());

        ingress.enqueue(export_with_span("span-1"))?;
        let base_bytes = ingress.snapshot()?.queued_bytes;

        // A retryable append error retains the batch WITH its cached signed
        // receipts, so the accounted bytes must grow beyond the raw OTLP estimate.
        let _ = ingress.drain();
        let after = ingress.snapshot()?;

        assert_eq!(
            after.queued_batches, 1,
            "the retryable batch is retained for redelivery"
        );
        assert!(
            after.queued_bytes > base_bytes,
            "cached signed receipts must count toward the queue byte budget: \
             base={base_bytes} after={}",
            after.queued_bytes
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

    fn export_with_two_spans(first: &str, second: &str) -> OtlpGrpcTraceExport {
        OtlpGrpcTraceExport::from_spans(vec![
            OtlpSpan::new(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef",
                first,
            )
            .with_attribute("chio.verdict", serde_json::json!("allow")),
            OtlpSpan::new(
                "0123456789abcdef0123456789abcdef",
                "fedcba9876543210",
                second,
            )
            .with_attribute("chio.verdict", serde_json::json!("allow")),
        ])
    }
}
