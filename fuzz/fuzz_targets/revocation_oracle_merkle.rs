#![no_main]

use arbitrary::Arbitrary;
use chio_revocation_oracle::{
    EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle, SubjectId,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Insert {
        subject: Vec<u8>,
        nonce: u64,
        now_unix_ms: u64,
    },
    InclusionProof {
        index: u8,
    },
    NonInclusionProof {
        subject: Vec<u8>,
        nonce: u64,
        now_unix_ms: u64,
    },
}

fn key_from_parts(subject: &[u8], nonce: u64) -> RevocationKey {
    let clipped = &subject[..subject.len().min(64)];
    let subject_id = String::from_utf8_lossy(clipped).into_owned();
    RevocationKey::new(SubjectId::new(subject_id), EpochNonce::new(nonce))
}

fuzz_target!(|input: Input| {
    let mut oracle = InMemoryRevocationOracle::with_capacity(input.ops.len().min(256));
    let mut inserted = Vec::new();

    for op in input.ops.into_iter().take(256) {
        match op {
            Op::Insert {
                subject,
                nonce,
                now_unix_ms,
            } => {
                let key = key_from_parts(&subject, nonce);
                if oracle.insert(key.clone(), now_unix_ms).is_ok() {
                    inserted.push(key);
                }
            }
            Op::InclusionProof { index } => {
                if inserted.is_empty() {
                    continue;
                }
                let key = &inserted[usize::from(index) % inserted.len()];
                if let Ok(proof) = oracle.inclusion_proof(key) {
                    let _ = InMemoryRevocationOracle::verify_inclusion(&proof);
                }
            }
            Op::NonInclusionProof {
                subject,
                nonce,
                now_unix_ms,
            } => {
                let key = key_from_parts(&subject, nonce);
                if let Ok(proof) = oracle.non_inclusion_proof(key, now_unix_ms) {
                    let _ = oracle.verify_non_inclusion(&proof);
                }
            }
        }
    }
});
