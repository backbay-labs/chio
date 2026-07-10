//! Nightly loom concurrency models. Run with:
//!   RUSTFLAGS="--cfg chio_iroh_transport_loom" cargo test -p \
//!     chio-federation-transport-iroh --lib loom_ -- --nocapture
//! Off by default.
//!
//! loom models require the code under test to use loom's `Arc`/`Mutex`/atomics
//! under the cfg. The production `AcceptLimiter`/`DirectoryGate` use `std::sync`
//! and `arc_swap`, which loom cannot instrument, so these models mirror the
//! per-peer reserve/release invariant and the publish/read invariant with loom's
//! own primitives (the standard loom approach when the production type is not
//! loom-parameterized).
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// The per-peer reserve/release logic never loses a decrement or leaks a slot:
/// two threads each reserve then release one slot for the same peer, and the
/// final count must be 0 (mirrors `AcceptLimiter::admit_peer` / `release_peer_slot`).
#[test]
fn loom_per_peer_counter_no_lost_decrement() {
    loom::model(|| {
        use loom::sync::{Arc, Mutex};
        use std::collections::HashMap;

        let counts: Arc<Mutex<HashMap<u8, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let cap = 2usize;
        let mut handles = Vec::new();
        for _ in 0..2 {
            let counts = Arc::clone(&counts);
            handles.push(loom::thread::spawn(move || {
                // reserve (bounded, under the lock)
                {
                    let mut c = counts.lock().unwrap();
                    let entry = c.entry(1u8).or_insert(0);
                    if *entry < cap {
                        *entry += 1;
                    }
                }
                // release (prune at zero)
                {
                    let mut c = counts.lock().unwrap();
                    if let Some(entry) = c.get_mut(&1u8) {
                        *entry = entry.saturating_sub(1);
                        if *entry == 0 {
                            c.remove(&1u8);
                        }
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(
            counts.lock().unwrap().get(&1u8).is_none(),
            "no leaked per-peer slot after balanced reserve/release"
        );
    });
}

/// The gate's publish/read never yields a torn read: a writer swaps the current
/// directory Arc while a reader loads it; the reader always observes a
/// fully-formed value (old or new), and the swapped-to value is eventually
/// observed (mirrors `DirectoryGate::swap` / the `ArcSwap` load path).
#[test]
fn loom_directory_arcswap_no_torn_read() {
    loom::model(|| {
        use loom::sync::{Arc, Mutex};

        let current: Arc<Mutex<Arc<u64>>> = Arc::new(Mutex::new(Arc::new(1u64)));

        let writer_current = Arc::clone(&current);
        let writer = loom::thread::spawn(move || {
            let next = Arc::new(2u64);
            *writer_current.lock().unwrap() = next;
        });

        // A concurrent load must see either the old or the new fully-formed value.
        let observed: u64 = **current.lock().unwrap();
        assert!(
            observed == 1 || observed == 2,
            "reader observed a torn value: {observed}"
        );

        writer.join().unwrap();
        // After the writer completes, the swapped-to value stands.
        assert_eq!(
            **current.lock().unwrap(),
            2,
            "the swapped-to value is eventually observed"
        );
    });
}
