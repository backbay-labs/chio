//! M05 baseline bench: cap_verify_ed25519.
//! Body fills in M05 P1 / P2 once the async-kernel pivot lands.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn bench(c: &mut Criterion) {
    c.bench_function("cap_verify_ed25519", |b| {
        b.iter(|| black_box(0_u64));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
