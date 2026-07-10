//! Deterministic std-thread stress test for the bounded-map concurrency
//! invariant. The exhaustive interleaving proof lives in loom_bounded_map.rs
//! (nightly, `--cfg loom`); this carries the PR gate with no special infra.

use std::sync::{Arc, Mutex};
use std::thread;

use chio_bounded::{BoundedMap, SizeGauge};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[test]
fn racing_insert_and_get_never_breaches_capacity_or_desyncs_gauge() {
    let gauge = SizeGauge::new();
    let map: Arc<Mutex<BoundedMap<u32, u32>>> =
        Arc::new(Mutex::new(BoundedMap::new(16, 0, gauge.clone())));
    let mut handles = Vec::new();
    for t in 0..8u32 {
        let map = Arc::clone(&map);
        handles.push(thread::spawn(move || {
            for i in 0..2000u32 {
                let key = (t * 2000 + i) % 64;
                let mut guard = lock(&map);
                let _ = guard.insert(key, i, 0);
                let _ = guard.get(&key, 0);
                assert!(guard.len() <= 16, "capacity breach: {}", guard.len());
            }
        }));
    }
    for h in handles {
        assert!(h.join().is_ok(), "worker thread panicked");
    }
    let guard = lock(&map);
    assert_eq!(
        guard.len(),
        gauge.get(),
        "gauge desynced from len after race"
    );
    assert!(guard.len() <= 16);
}
