//! Canonical signing of the receipt shape emitted by the buyer closure.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("receipt_sign", |b| {
        b.iter(|| black_box(fixture.receipt_sign_once()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
