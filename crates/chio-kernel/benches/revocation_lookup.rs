//! Baseline bench: in-memory revocation lookup.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("revocation_lookup", |b| {
        b.iter(|| black_box(fixture.revocation_lookup_once()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
