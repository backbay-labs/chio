//! Baseline bench: Ed25519 capability verification.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

pub fn bench(c: &mut Criterion) {
    let fixture = DispatchAllowFixture::new();

    c.bench_function("cap_verify_ed25519", |b| {
        b.iter(|| black_box(fixture.capability_signature_valid()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
