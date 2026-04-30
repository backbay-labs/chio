#![cfg_attr(not(loom), allow(dead_code))]

#[cfg(loom)]
use std::collections::{BTreeSet, VecDeque};

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
#[derive(Debug, Default)]
struct RingState {
    queue: VecDeque<u8>,
    accepted: Vec<u8>,
    dropped_oldest: Vec<u8>,
    drained: Vec<u8>,
    closed_sends: usize,
}

#[cfg(loom)]
#[derive(Debug)]
struct ShutdownRing {
    shutdown: AtomicBool,
    state: Mutex<RingState>,
}

#[cfg(loom)]
impl ShutdownRing {
    fn new_prefilled() -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            state: Mutex::new(RingState {
                queue: VecDeque::from([0]),
                accepted: vec![0],
                dropped_oldest: Vec::new(),
                drained: Vec::new(),
                closed_sends: 0,
            }),
        }
    }

    fn send_drop_oldest(&self, item: u8) -> SendOutcome {
        if self.shutdown.load(Ordering::Acquire) {
            lock_mutex(&self.state).closed_sends += 1;
            return SendOutcome::Closed;
        }

        let mut state = lock_mutex(&self.state);
        if self.shutdown.load(Ordering::Acquire) {
            state.closed_sends += 1;
            return SendOutcome::Closed;
        }

        while state.queue.len() >= CAPACITY {
            if let Some(dropped) = state.queue.pop_front() {
                state.dropped_oldest.push(dropped);
            }
        }
        state.queue.push_back(item);
        state.accepted.push(item);
        SendOutcome::Accepted
    }

    fn shutdown_and_drain(&self) {
        self.shutdown.store(true, Ordering::Release);
        thread::yield_now();
        self.drain_all();
    }

    fn drain_all(&self) {
        let mut state = lock_mutex(&self.state);
        while let Some(item) = state.queue.pop_front() {
            state.drained.push(item);
        }
    }
}

#[cfg(loom)]
#[test]
fn loom_ring_sender_vs_shutdown() {
    loom::model(|| {
        let ring = Arc::new(ShutdownRing::new_prefilled());

        let sender_a_ring = Arc::clone(&ring);
        let sender_a = thread::spawn(move || {
            thread::yield_now();
            let _ = sender_a_ring.send_drop_oldest(1);
        });

        let sender_b_ring = Arc::clone(&ring);
        let sender_b = thread::spawn(move || {
            let _ = sender_b_ring.send_drop_oldest(2);
        });

        let shutdown_ring = Arc::clone(&ring);
        let shutdown = thread::spawn(move || {
            thread::yield_now();
            shutdown_ring.shutdown_and_drain();
        });

        join_ok(sender_a);
        join_ok(sender_b);
        join_ok(shutdown);
        ring.drain_all();

        let state = lock_mutex(&ring.state);
        assert!(
            state.queue.is_empty(),
            "shutdown completion must not leave queued exports"
        );
        assert!(
            state.closed_sends <= 2,
            "only racing senders can observe shutdown closure"
        );

        let accepted: BTreeSet<u8> = state.accepted.iter().copied().collect();
        let completed: BTreeSet<u8> = state
            .dropped_oldest
            .iter()
            .chain(state.drained.iter())
            .copied()
            .collect();

        assert_eq!(
            accepted, completed,
            "accepted exports must be either drained or counted as drop-oldest"
        );
        assert_eq!(
            completed.len(),
            state.dropped_oldest.len() + state.drained.len(),
            "an export must not be both drained and dropped"
        );
        assert!(
            state.dropped_oldest.len() <= state.accepted.len().saturating_sub(1),
            "drop-oldest cannot exceed accepted exports displaced by later sends"
        );
    });
}
