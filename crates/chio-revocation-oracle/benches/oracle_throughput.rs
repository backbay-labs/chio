use std::time::{Duration, Instant};

use chio_revocation_oracle::{
    EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle, SubjectId,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const SUBJECTS: usize = 10_000;
const P99_SAMPLE_COUNT: usize = 64;
const INSERT_AND_PROOF_P99_BUDGET: Duration = Duration::from_micros(200);

fn seed_oracle() -> chio_revocation_oracle::Result<InMemoryRevocationOracle> {
    let mut oracle = InMemoryRevocationOracle::with_capacity(SUBJECTS + P99_SAMPLE_COUNT);
    for idx in 0..SUBJECTS {
        let key = RevocationKey::new(
            SubjectId::new(format!("subject-{idx}")),
            EpochNonce::new(idx as u64),
        );
        oracle.insert(key, idx as u64)?;
    }
    Ok(oracle)
}

fn measure_insert_and_proof_p99() -> chio_revocation_oracle::Result<Duration> {
    let mut oracle = seed_oracle()?;
    let mut samples = Vec::with_capacity(P99_SAMPLE_COUNT);
    for idx in 0..P99_SAMPLE_COUNT {
        let key = RevocationKey::new(
            SubjectId::new(format!("new-subject-{idx}")),
            EpochNonce::new((SUBJECTS + idx) as u64),
        );
        let start = Instant::now();
        oracle.insert(key.clone(), (SUBJECTS + idx) as u64)?;
        let proof = oracle.inclusion_proof(&key)?;
        samples.push(start.elapsed());
        InMemoryRevocationOracle::verify_inclusion(&proof)?;
    }
    samples.sort_unstable();
    let index = ((samples.len() * 99).div_ceil(100)).saturating_sub(1);
    samples
        .get(index)
        .copied()
        .ok_or(chio_revocation_oracle::RevocationOracleError::InvalidProof)
}

fn assert_insert_and_proof_budget() {
    let p99 = match measure_insert_and_proof_p99() {
        Ok(value) => value,
        Err(err) => panic!("oracle throughput measurement failed: {err}"),
    };
    assert!(
        p99 <= INSERT_AND_PROOF_P99_BUDGET,
        "oracle insert + proof p99 {:?} exceeded {:?}",
        p99,
        INSERT_AND_PROOF_P99_BUDGET
    );
}

pub fn bench_oracle_throughput(c: &mut Criterion) {
    assert_insert_and_proof_budget();
    let baseline = match seed_oracle() {
        Ok(value) => value,
        Err(err) => panic!("oracle seed failed: {err}"),
    };
    c.bench_function("oracle_insert_and_proof_10k_subjects", |b| {
        let mut idx = 0_u64;
        b.iter(|| {
            let mut oracle = baseline.clone();
            let key = RevocationKey::new(
                SubjectId::new(format!("bench-subject-{idx}")),
                EpochNonce::new(SUBJECTS as u64 + idx),
            );
            idx = idx.saturating_add(1);
            let root = match oracle.insert(key.clone(), idx) {
                Ok(value) => value,
                Err(err) => panic!("bench insert failed: {err}"),
            };
            let proof = match oracle.inclusion_proof(&key) {
                Ok(value) => value,
                Err(err) => panic!("bench proof failed: {err}"),
            };
            black_box((root, proof));
        });
    });
}

criterion_group!(benches, bench_oracle_throughput);
criterion_main!(benches);
