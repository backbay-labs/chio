use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedQueueLimits {
    pub max_queued_batches: usize,
    pub max_queued_spans: usize,
    pub max_queued_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundedQueuePushSummary {
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
pub struct BoundedQueueSnapshot {
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

pub trait BoundedQueueItem {
    fn spans(&self) -> usize;
    fn bytes(&self) -> usize;
}

#[derive(Debug)]
pub struct BoundedDropOldestQueue<T> {
    queue: VecDeque<T>,
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
    append_error_batches: u64,
    append_error_spans: u64,
}

impl<T> Default for BoundedDropOldestQueue<T> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            queued_spans: 0,
            queued_bytes: 0,
            accepted_batches: 0,
            accepted_spans: 0,
            dropped_oldest_batches: 0,
            dropped_oldest_spans: 0,
            dropped_incoming_batches: 0,
            dropped_incoming_spans: 0,
            appended_batches: 0,
            appended_spans: 0,
            append_error_batches: 0,
            append_error_spans: 0,
        }
    }
}

impl<T: BoundedQueueItem> BoundedDropOldestQueue<T> {
    pub fn push_drop_oldest(
        &mut self,
        item: T,
        limits: BoundedQueueLimits,
    ) -> BoundedQueuePushSummary {
        let mut summary = BoundedQueuePushSummary::default();
        let item_spans = item.spans();
        let item_bytes = item.bytes();
        if item_spans > limits.max_queued_spans
            || item_bytes > limits.max_queued_bytes
            || limits.max_queued_batches == 0
        {
            self.dropped_incoming_batches += 1;
            self.dropped_incoming_spans += item_spans as u64;
            summary.dropped_incoming_batches = 1;
            summary.dropped_incoming_spans = item_spans;
            summary.queued_batches = self.queue.len();
            summary.queued_spans = self.queued_spans;
            summary.queued_bytes = self.queued_bytes;
            return summary;
        }

        while self.queue.len() + 1 > limits.max_queued_batches
            || self.queued_spans.saturating_add(item_spans) > limits.max_queued_spans
            || self.queued_bytes.saturating_add(item_bytes) > limits.max_queued_bytes
        {
            let Some(dropped) = self.pop_front() else {
                break;
            };
            self.dropped_oldest_batches += 1;
            self.dropped_oldest_spans += dropped.spans() as u64;
            summary.dropped_oldest_batches += 1;
            summary.dropped_oldest_spans += dropped.spans();
        }

        summary.enqueued_batches = 1;
        summary.enqueued_spans = item_spans;
        self.accepted_batches += 1;
        self.accepted_spans += item_spans as u64;
        self.queued_spans += item_spans;
        self.queued_bytes += item_bytes;
        self.queue.push_back(item);
        summary.queued_batches = self.queue.len();
        summary.queued_spans = self.queued_spans;
        summary.queued_bytes = self.queued_bytes;
        summary
    }

    pub fn pop_front(&mut self) -> Option<T> {
        let item = self.queue.pop_front()?;
        self.queued_spans = self.queued_spans.saturating_sub(item.spans());
        self.queued_bytes = self.queued_bytes.saturating_sub(item.bytes());
        Some(item)
    }
}

impl<T> BoundedDropOldestQueue<T> {
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.queue.front_mut()
    }

    pub fn snapshot(&self) -> BoundedQueueSnapshot {
        BoundedQueueSnapshot {
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
            append_error_batches: self.append_error_batches,
            append_error_spans: self.append_error_spans,
        }
    }

    /// Account receipts that crossed the store-append boundary during a drain.
    /// Split from batch-completion accounting: a retryable partial append
    /// records the spans it managed to append here, but the batch is NOT yet
    /// counted as completed, so one OTLP batch resumed across several retries
    /// has its spans summed exactly once and is never reported as a completed
    /// batch while it is still queued.
    pub fn record_appended_spans(&mut self, spans: usize) {
        self.appended_spans += spans as u64;
    }

    /// Count one fully-appended batch. Called only after the whole batch is
    /// confirmed appended (the `Ok` path in the drain loop), so a batch retained
    /// for retry after a partial append is not counted as completed while it is
    /// still queued, and a batch that finishes across multiple drains is counted
    /// exactly once.
    pub fn record_appended_batch(&mut self) {
        self.appended_batches += 1;
    }

    /// Add the bytes of receipts cached on the front item (the signed/canonical
    /// receipts retained for retry after a retryable append error) to the queue
    /// byte budget, so a batch held during a store outage is accounted at its
    /// true resident memory rather than only its original OTLP estimate.
    /// `pop_front` subtracts the same bytes via the item's `bytes()`.
    pub fn record_prepared_bytes(&mut self, bytes: usize) {
        self.queued_bytes = self.queued_bytes.saturating_add(bytes);
    }

    pub fn record_append_error(&mut self, spans: usize) {
        self.append_error_batches += 1;
        self.append_error_spans += spans as u64;
    }
}
