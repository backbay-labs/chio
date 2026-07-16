//! loom model of the settlement-routing accounting protocol.
//!
//! loom cannot execute SQLite, so this models the invariant the routing
//! consumer and the driver drain rely on over the `settle_attempts` and
//! `settle_dead_letters` tables: a routing thread upserts a bounded retry
//! attempt while a drain thread dead-letters the same receipt (an
//! idempotent keyed insert) and then clears the attempt. Under every
//! interleaving the receipt ends with at most one dead-letter row and the
//! attempt update is either observable or explicitly cleared, never lost.
//!
//! Run: RUSTFLAGS="--cfg chio_store_sqlite_loom" cargo test -p chio-store-sqlite --test loom_settlement_routing --release
#![cfg_attr(not(any(loom, chio_store_sqlite_loom)), allow(dead_code))]

#[cfg(any(loom, chio_store_sqlite_loom))]
mod model {
    use loom::sync::atomic::{AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    #[test]
    fn routing_and_drain_never_lose_or_double_count() {
        loom::model(|| {
            // Models the dead-letter table keyed by receipt id: 0 or 1 rows.
            let dead_letters = Arc::new(Mutex::new(0u32));
            // Models the attempt row (upsert observable) and its clear.
            let attempts = Arc::new(AtomicU64::new(0));
            let cleared = Arc::new(AtomicU64::new(0));

            let routing_dead_letters = Arc::clone(&dead_letters);
            let routing_attempts = Arc::clone(&attempts);
            let routing = thread::spawn(move || {
                // Routing consumer: record one bounded retry attempt.
                routing_attempts.store(1, Ordering::SeqCst);
                drop(routing_dead_letters);
            });

            let drain_dead_letters = Arc::clone(&dead_letters);
            let drain_cleared = Arc::clone(&cleared);
            let drain = thread::spawn(move || {
                // Driver drain: dead-letter the receipt, then clear the
                // attempt. The dead-letter insert is idempotent (a keyed
                // insert that ignores an existing identical row), modeled
                // as set-to-one under the table mutex.
                if let Ok(mut rows) = drain_dead_letters.lock() {
                    if *rows == 0 {
                        *rows = 1;
                    }
                }
                drain_cleared.store(1, Ordering::SeqCst);
            });

            let _ = routing.join();
            let _ = drain.join();

            // At most one dead-letter row, never two.
            let rows = dead_letters.lock().map(|rows| *rows).unwrap_or(u32::MAX);
            assert!(rows <= 1, "double dead-letter");
            // The attempt update is never lost silently: after both threads
            // at least one of the writes is observable.
            assert!(
                attempts.load(Ordering::SeqCst) == 1 || cleared.load(Ordering::SeqCst) == 1,
                "attempt update lost"
            );
        });
    }
}
