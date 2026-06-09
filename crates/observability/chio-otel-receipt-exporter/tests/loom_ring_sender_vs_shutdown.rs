#![cfg_attr(not(loom), allow(dead_code))]

#[cfg(loom)]
use chio_otel_receipt_exporter::queue_core::{
    BoundedDropOldestQueue, BoundedQueueItem, BoundedQueueLimits,
};

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, Ordering};
#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(loom)]
use loom::thread;

#[cfg(loom)]
const CAPACITY: usize = 1;

#[cfg(loom)]
fn lock_mutex<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(loom)]
fn join_ok(handle: thread::JoinHandle<()>) {
    assert!(handle.join().is_ok(), "loom thread should complete");
}

#[cfg(loom)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    Accepted,
    Closed,
}

#[cfg(loom)]
#[derive(Debug, Clone, Copy)]
struct TestExport {
    spans: usize,
    bytes: usize,
}

#[cfg(loom)]
impl BoundedQueueItem for TestExport {
    fn spans(&self) -> usize {
        self.spans
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(loom)]
#[derive(Debug, Default)]
struct ShutdownQueueState {
    queue: BoundedDropOldestQueue<TestExport>,
    drained: usize,
    closed_sends: usize,
}

#[cfg(loom)]
#[derive(Debug)]
struct ShutdownQueue {
    shutdown: AtomicBool,
    state: Mutex<ShutdownQueueState>,
}

#[cfg(loom)]
impl ShutdownQueue {
    fn new_prefilled() -> Self {
        let mut state = ShutdownQueueState::default();
        let summary = state
            .queue
            .push_drop_oldest(Self::test_export(), Self::limits());
        assert_eq!(summary.enqueued_batches, 1);
        Self {
            shutdown: AtomicBool::new(false),
            state: Mutex::new(state),
        }
    }

    fn send_drop_oldest(&self) -> SendOutcome {
        if self.shutdown.load(Ordering::Acquire) {
            lock_mutex(&self.state).closed_sends += 1;
            return SendOutcome::Closed;
        }

        let mut state = lock_mutex(&self.state);
        if self.shutdown.load(Ordering::Acquire) {
            state.closed_sends += 1;
            return SendOutcome::Closed;
        }

        let summary = state
            .queue
            .push_drop_oldest(Self::test_export(), Self::limits());
        assert_eq!(summary.enqueued_batches, 1);
        SendOutcome::Accepted
    }

    fn shutdown_and_drain(&self) {
        self.shutdown.store(true, Ordering::Release);
        thread::yield_now();
        self.drain_all();
    }

    fn drain_all(&self) {
        let mut state = lock_mutex(&self.state);
        while state.queue.pop_front().is_some() {
            state.drained += 1;
        }
    }

    fn test_export() -> TestExport {
        TestExport { spans: 1, bytes: 1 }
    }

    fn limits() -> BoundedQueueLimits {
        BoundedQueueLimits {
            max_queued_batches: CAPACITY,
            max_queued_spans: CAPACITY,
            max_queued_bytes: CAPACITY,
        }
    }
}

#[cfg(loom)]
#[test]
fn loom_ring_sender_vs_shutdown() {
    loom::model(|| {
        let queue = Arc::new(ShutdownQueue::new_prefilled());

        let sender_a_queue = Arc::clone(&queue);
        let sender_a = thread::spawn(move || {
            thread::yield_now();
            let _ = sender_a_queue.send_drop_oldest();
        });

        let sender_b_queue = Arc::clone(&queue);
        let sender_b = thread::spawn(move || {
            let _ = sender_b_queue.send_drop_oldest();
        });

        let shutdown_queue = Arc::clone(&queue);
        let shutdown = thread::spawn(move || {
            thread::yield_now();
            shutdown_queue.shutdown_and_drain();
        });

        join_ok(sender_a);
        join_ok(sender_b);
        join_ok(shutdown);
        queue.drain_all();

        let state = lock_mutex(&queue.state);
        let snapshot = state.queue.snapshot();
        assert_eq!(
            snapshot.queued_batches, 0,
            "shutdown completion must not leave queued exports"
        );
        assert!(
            state.closed_sends <= 2,
            "only racing senders can observe shutdown closure"
        );
        assert_eq!(
            snapshot.accepted_batches,
            snapshot.dropped_oldest_batches + state.drained as u64,
            "accepted exports must be either drained or counted as drop-oldest"
        );
        assert!(
            snapshot.dropped_oldest_batches <= snapshot.accepted_batches.saturating_sub(1),
            "drop-oldest cannot exceed accepted exports displaced by later sends"
        );
    });
}
