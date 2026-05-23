//! Baseline bench: append signed receipts to the in-memory receipt log.

use chio_kernel::ReceiptLog;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("receipt_append", |b| {
        b.iter_batched(
            ReceiptLog::new,
            |mut log| black_box(fixture.receipt_append_once(&mut log)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
