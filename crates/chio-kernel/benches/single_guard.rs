//! M05 baseline bench: single_guard.
//! Body fills in M05 P1 / P2 once the async-kernel pivot lands.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn bench(c: &mut Criterion) {
    c.bench_function("single_guard", |b| {
        b.iter(|| black_box(0_u64));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
