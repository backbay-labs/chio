//! Exhaustive loom model of two threads racing insert and get on a
//! Mutex<BoundedMap>. Nightly only:
//!   RUSTFLAGS="--cfg loom" cargo test -p chio-bounded --test loom_bounded_map
#![cfg_attr(not(loom), allow(dead_code))]

#[cfg(loom)]
use chio_bounded::{BoundedMap, SizeGauge};
#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(loom)]
use loom::thread;

#[cfg(loom)]
fn lock_map(m: &Mutex<BoundedMap<u8, u8>>) -> MutexGuard<'_, BoundedMap<u8, u8>> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(loom)]
#[test]
fn insert_get_race_preserves_gauge_and_capacity() {
    loom::model(|| {
        let gauge = SizeGauge::new();
        let map: Arc<Mutex<BoundedMap<u8, u8>>> =
            Arc::new(Mutex::new(BoundedMap::new(2, 0, gauge.clone())));

        let writer = {
            let map = Arc::clone(&map);
            thread::spawn(move || {
                let mut g = lock_map(&map);
                let _ = g.insert(1, 10, 0);
                let _ = g.insert(2, 20, 0);
                let _ = g.insert(3, 30, 0);
            })
        };
        let reader = {
            let map = Arc::clone(&map);
            thread::spawn(move || {
                let mut g = lock_map(&map);
                let _ = g.get(&1, 0);
            })
        };
        assert!(writer.join().is_ok());
        assert!(reader.join().is_ok());

        let g = lock_map(&map);
        assert!(g.len() <= 2, "capacity breached under race");
        assert_eq!(g.len(), gauge.get(), "gauge desynced under race");
    });
}

#[cfg(not(loom))]
#[test]
fn loom_disabled_placeholder() {
    // Compiled without --cfg loom: nothing to model here.
}
