//! Signature verification of the receipt shape emitted by the buyer closure.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("receipt_verify", |b| {
        b.iter(|| {
            assert!(
                black_box(fixture.receipt_verify_once()),
                "receipt verification benchmark rejected its signed fixture"
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
