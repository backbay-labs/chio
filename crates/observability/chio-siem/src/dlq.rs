//! Dead-letter queue for SIEM export failures.
//!
//! When all retry attempts for an exporter are exhausted, the failed events
//! are pushed to the DLQ. The DLQ is bounded by `max_capacity`; when the
//! capacity is reached, the oldest entry is dropped to make room for the new one.

use std::collections::VecDeque;

/// A failed event entry stored in the dead-letter queue.
#[derive(Debug, Clone)]
pub struct FailedEvent {
    /// JSON-serialized SiemEvent that could not be exported.
    pub event_json: String,
    /// Human-readable description of the export error.
    pub error: String,
    /// Unix timestamp (seconds) when the failure occurred.
    pub failed_at: u64,
    /// Name of the exporter that produced this failure.
    pub exporter_name: String,
}

/// Bounded dead-letter queue for failed SIEM export events.
///
/// When the queue reaches `max_capacity`, the oldest entry is silently dropped
/// and a tracing error is emitted. This prevents unbounded memory growth during
/// sustained exporter outages.
pub struct DeadLetterQueue {
    inner: VecDeque<FailedEvent>,
    max_capacity: usize,
}

impl DeadLetterQueue {
    /// Default maximum capacity if not specified in SiemConfig.
    pub const DEFAULT_CAPACITY: usize = 1000;

    /// Create a new DeadLetterQueue with the given maximum capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            max_capacity,
        }
    }

    /// Push a FailedEvent onto the queue.
    ///
    /// If the queue is already at capacity, the oldest entry is dropped and
    /// a tracing::error is emitted before the new entry is inserted.
    pub fn push(&mut self, event: FailedEvent) {
        if self.max_capacity == 0 {
            tracing::error!(
                exporter = %event.exporter_name,
                failed_at = event.failed_at,
                "DLQ at zero capacity -- dropped failed event"
            );
            return;
        }
        if self.inner.len() >= self.max_capacity {
            let dropped = self.inner.pop_front();
            if let Some(dropped_event) = dropped {
                tracing::error!(
                    exporter = %dropped_event.exporter_name,
                    failed_at = dropped_event.failed_at,
                    "DLQ at capacity -- dropped oldest failed event to make room"
                );
            }
        }
        self.inner.push_back(event);
    }

    /// Return the current number of entries in the queue.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return the number of entries attributed to a single exporter.
    ///
    /// The DLQ is shared across all exporters, so the per-exporter DLQ-depth
    /// gauge must count only the entries produced by that exporter rather than
    /// the global length.
    pub fn depth_for_exporter(&self, exporter: &str) -> usize {
        self.inner
            .iter()
            .filter(|event| event.exporter_name == exporter)
            .count()
    }

    /// Return true if the queue contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drain all entries from the queue and return them as a Vec.
    pub fn drain(&mut self) -> Vec<FailedEvent> {
        self.inner.drain(..).collect()
    }
}
