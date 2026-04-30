//! Concurrency soak for the arc-swap-backed revocation view.
//!
//! Lives as an integration test (not a `#[cfg(test)] mod tests` inside
//! `chio-kernel-core/src/revocation_view.rs`) because the crate itself is
//! `#![no_std]` at the source level. Standard threading primitives are
//! the most ergonomic way to demonstrate the no-blocking-readers
//! invariant; integration tests run as a normal hosted binary so
//! `std::thread` is fine here.

#![cfg(feature = "revocation-view")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread;

use chio_kernel_core::{RevocationSnapshot, RevocationView, RevocationViewSubject};

fn snapshot(epoch: u64, revoked: &[&str]) -> RevocationSnapshot {
    let revoked_set = revoked
        .iter()
        .copied()
        .map(RevocationViewSubject::from)
        .collect();
    RevocationSnapshot {
        epoch,
        root_hash: [(epoch as u8); 32],
        issued_at_unix_ms: 1_700_000_000_000 + epoch,
        revoked: revoked_set,
    }
}

/// One writer monotonically advances the snapshot's epoch while four
/// readers continuously load it. Every observed snapshot is internally
/// self-consistent: the revoked-subject label encodes its own epoch, so
/// any tearing between epoch and the revoked set would fail the assertion
/// below. `arc_swap::ArcSwap::store` is atomic on the `Arc`, so this
/// invariant must hold even at high contention.
#[test]
fn concurrent_readers_observe_consistent_snapshot() {
    let view = Arc::new(RevocationView::new());
    view.install_if_newer(snapshot(1, &["s-1"])).unwrap();

    let writer_view = Arc::clone(&view);
    let writer = thread::spawn(move || {
        for epoch in 2..=200 {
            let label = format!("s-{}", epoch);
            // Leak intentional: keeps the &'static str alive for the
            // duration of the test so we can stamp it into the snapshot
            // through the same code path the production gossip task uses.
            let leaked: &'static str = Box::leak(label.into_boxed_str());
            writer_view
                .install_if_newer(snapshot(epoch, &[leaked]))
                .unwrap();
        }
    });

    let mut reader_handles = Vec::new();
    for _ in 0..4 {
        let reader_view = Arc::clone(&view);
        reader_handles.push(thread::spawn(move || {
            for _ in 0..1_000 {
                let snap = reader_view.load();
                if snap.epoch == 0 {
                    continue;
                }
                let expected = format!("s-{}", snap.epoch);
                let subject = RevocationViewSubject::from(expected.as_str());
                assert!(
                    snap.is_revoked(&subject),
                    "snapshot at epoch {} missing self-consistent label",
                    snap.epoch
                );
            }
        }));
    }

    writer.join().unwrap();
    for handle in reader_handles {
        handle.join().unwrap();
    }
    assert_eq!(view.current_epoch(), 200);
}
