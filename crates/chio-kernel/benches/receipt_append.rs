//! Baseline bench: receipt_append.
//! Body fills in once the async-kernel pivot lands.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn bench(c: &mut Criterion) {
    c.bench_function("receipt_append", |b| {
        b.iter(|| black_box(0_u64));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
