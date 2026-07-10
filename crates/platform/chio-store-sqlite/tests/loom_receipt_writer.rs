//! loom model of the receipt commit actor's command-channel accounting.
//!
//! loom cannot execute SQLite, so this models the protocol invariant the
//! real actor relies on (receipt_store.rs: pre-send inflight increment,
//! unconditional dequeue decrement, bounded queue with fail-closed
//! rejection) across concurrent Append- and Write-shaped producers.
//! Run: RUSTFLAGS="--cfg chio_store_sqlite_loom" cargo test -p chio-store-sqlite --test loom_receipt_writer --release
#![cfg_attr(not(any(loom, chio_store_sqlite_loom)), allow(dead_code))]

#[cfg(any(loom, chio_store_sqlite_loom))]
mod model {
    use loom::sync::atomic::{AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;
    use std::collections::VecDeque;

    const QUEUE_CAPACITY: usize = 2;

    struct Channel {
        queue: Mutex<VecDeque<u64>>,
        inflight: AtomicU64,
    }

    impl Channel {
        fn try_send(&self, job: u64) -> bool {
            // Pre-send increment (receipt_store.rs append/run_write invariant).
            self.inflight.fetch_add(1, Ordering::SeqCst);
            let pushed = match self.queue.lock() {
                Ok(mut queue) if queue.len() < QUEUE_CAPACITY => {
                    queue.push_back(job);
                    true
                }
                Ok(_) => false,
                Err(_) => false,
            };
            if !pushed {
                // Undo the speculative increment, exactly like try_send
                // Full/Disconnected handling.
                let mut current = self.inflight.load(Ordering::SeqCst);
                loop {
                    let next = current.saturating_sub(1);
                    match self.inflight.compare_exchange(
                        current,
                        next,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(observed) => current = observed,
                    }
                }
            }
            pushed
        }

        fn drain(&self) -> u64 {
            let mut drained = 0;
            loop {
                let job = match self.queue.lock() {
                    Ok(mut queue) => queue.pop_front(),
                    Err(_) => None,
                };
                let Some(_job) = job else { break };
                // Unconditional decrement on dequeue.
                let mut current = self.inflight.load(Ordering::SeqCst);
                loop {
                    let next = current.saturating_sub(1);
                    match self.inflight.compare_exchange(
                        current,
                        next,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(observed) => current = observed,
                    }
                }
                drained += 1;
            }
            drained
        }
    }

    #[test]
    fn inflight_accounting_never_leaks_across_append_write_flush() {
        loom::model(|| {
            let channel = Arc::new(Channel {
                queue: Mutex::new(VecDeque::new()),
                inflight: AtomicU64::new(0),
            });

            let producer_a = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(1)) // Append-shaped
            };
            let producer_b = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(2)) // Write-shaped
            };
            let consumer = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.drain()) // actor loop
            };

            let sent_a = producer_a.join().unwrap_or(false);
            let sent_b = producer_b.join().unwrap_or(false);
            let _ = consumer.join();
            // Final drain (actor keeps running until channel close).
            channel.drain();

            let accepted = u64::from(sent_a) + u64::from(sent_b);
            let _ = accepted;
            assert_eq!(
                channel.inflight.load(Ordering::SeqCst),
                0,
                "inflight must be zero after every accepted job is drained"
            );
        });
    }
}
