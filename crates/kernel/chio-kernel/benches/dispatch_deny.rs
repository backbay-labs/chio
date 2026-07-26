//! Treaty denial through the runtime admission hook before tool dispatch.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("treaty_predispatch_deny", |b| {
        b.iter(|| {
            assert!(
                black_box(fixture.dispatch_deny_once()),
                "treaty denial reached the tool or returned the wrong failure"
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
