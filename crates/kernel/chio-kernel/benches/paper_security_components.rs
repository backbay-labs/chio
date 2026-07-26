//! Security components used by the bilateral-admission paper evaluation.

use std::cell::Cell;

use chio_store_sqlite::SqliteReceiptStore;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use tempfile::tempdir;

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("receipt_sign", |b| {
        b.iter(|| black_box(fixture.receipt_sign_once()));
    });

    c.bench_function("receipt_verify", |b| {
        b.iter(|| {
            assert!(
                black_box(fixture.receipt_verify_once()),
                "receipt verification benchmark rejected its signed fixture"
            );
        });
    });

    let directory = match tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("failed to create receipt append benchmark directory: {error}"),
    };
    let store = match SqliteReceiptStore::open(directory.path().join("receipts.sqlite3")) {
        Ok(store) => store,
        Err(error) => panic!("failed to open receipt append benchmark store: {error}"),
    };
    let sequence = Cell::new(0_u64);
    c.bench_function("receipt_append_sqlite", |b| {
        b.iter_batched(
            || {
                let next = sequence.get().saturating_add(1);
                sequence.set(next);
                fixture.signed_receipt_with_id(format!("bench-receipt-{next}"))
            },
            |receipt| match store.append_chio_receipt_returning_seq(&receipt) {
                Ok(appended_sequence) => black_box(appended_sequence),
                Err(error) => panic!("receipt append benchmark failed: {error}"),
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
