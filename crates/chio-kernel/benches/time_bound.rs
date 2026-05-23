//! Baseline bench: capability time-bound validation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("time_bound", |b| {
        b.iter(|| black_box(fixture.capability_time_valid()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
