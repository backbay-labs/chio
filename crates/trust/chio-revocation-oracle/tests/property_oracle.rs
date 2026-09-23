use std::collections::BTreeSet;

use chio_revocation_oracle::{
    Ed25519RootSigner, EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle,
    SubjectId,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn key(subject: String, nonce: u64) -> RevocationKey {
    RevocationKey::new(SubjectId::new(subject), EpochNonce::new(nonce))
}

/// Generate between 2 and 16 distinct (subject, nonce) pairs, ensuring multi-leaf
/// trees so the sibling collection logic in `proof_bytes_for_index` is exercised.
fn distinct_keys_strategy() -> impl Strategy<Value = Vec<RevocationKey>> {
    vec(("[a-z0-9]{1,24}", 0_u64..10_000_u64), 2..16).prop_map(|raw| {
        let mut seen: BTreeSet<(String, u64)> = BTreeSet::new();
        let mut out: Vec<RevocationKey> = Vec::new();
        for (subject, nonce) in raw {
            if seen.insert((subject.clone(), nonce)) {
                out.push(key(subject, nonce));
            }
        }
        // Guarantee at least two distinct leaves even after dedup.
        let mut filler_nonce: u64 = 1_000_000;
        while out.len() < 2 {
            let candidate = (format!("filler-{filler_nonce}"), filler_nonce);
            if seen.insert(candidate.clone()) {
                out.push(key(candidate.0, candidate.1));
            }
            filler_nonce += 1;
        }
        out
    })
}

proptest! {
    #[test]
    fn inclusion_proof_soundness(keys in distinct_keys_strategy()) {
        let mut oracle = InMemoryRevocationOracle::new();
        let mut now: u64 = 10;
        for k in &keys {
            oracle
                .insert(k.clone(), now)
                .map_err(|err| TestCaseError::fail(format!("insert failed: {err}")))?;
            now += 1;
        }

        // Verify inclusion proofs for every leaf so that multi-leaf sibling paths
        // (proof_bytes_for_index with len > 1) are exercised, not just trivial roots.
        for k in &keys {
            let proof = oracle
                .inclusion_proof(k)
                .map_err(|err| TestCaseError::fail(format!("proof failed: {err}")))?;
            prop_assert!(InMemoryRevocationOracle::verify_inclusion(&proof).is_ok());
            prop_assert!(!proof.proof_bytes.is_empty() || keys.len() == 1);
        }
    }

    #[test]
    fn non_inclusion_proof_soundness(subject in "[a-z0-9]{1,24}", nonce in 0_u64..10_000) {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = key(subject, nonce);
        let proof = oracle
            .non_inclusion_proof(key.clone(), 10)
            .map_err(|err| TestCaseError::fail(format!("non-inclusion proof failed: {err}")))?;

        prop_assert!(oracle.verify_non_inclusion(&proof));
        oracle
            .insert(key, 11)
            .map_err(|err| TestCaseError::fail(format!("insert failed: {err}")))?;
        prop_assert!(!oracle.verify_non_inclusion(&proof));
    }

    #[test]
    fn root_signature_verification(subject in "[a-z0-9]{1,24}", nonce in 0_u64..10_000) {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = key(subject, nonce);
        let signer = Ed25519RootSigner::from_signing_key(
            "property-oracle-root",
            "0404040404040404040404040404040404040404040404040404040404040404",
        )
        .map_err(|err| TestCaseError::fail(format!("signer init failed: {err}")))?;
        let verifier = signer.verifier();
        oracle
            .insert(key, 10)
            .map_err(|err| TestCaseError::fail(format!("insert failed: {err}")))?;

        let mut signed = oracle
            .signed_epoch_root(&signer)
            .map_err(|err| TestCaseError::fail(format!("sign failed: {err}")))?;

        prop_assert!(signed.verify(&verifier).is_ok());
        signed.signature.signature_bytes.push(0);
        prop_assert!(signed.verify(&verifier).is_err());
    }

    #[test]
    fn epoch_monotone(subject_a in "[a-z0-9]{1,24}", subject_b in "[a-z0-9]{1,24}") {
        let mut oracle = InMemoryRevocationOracle::new();
        // RevocationKey equality covers (subject_id, epoch_nonce); using distinct
        // nonces (1 vs 2) guarantees the two keys are distinct regardless of the
        // generated subject strings, so no collision guard is required.
        let first = key(subject_a, 1);
        let second = key(subject_b, 2);

        let root_one = oracle
            .insert(first, 10)
            .map_err(|err| TestCaseError::fail(format!("first insert failed: {err}")))?;
        let root_two = oracle
            .insert(second, 11)
            .map_err(|err| TestCaseError::fail(format!("second insert failed: {err}")))?;

        prop_assert!(root_two.epoch > root_one.epoch);
        prop_assert!(root_two.issued_at_unix_ms >= root_one.issued_at_unix_ms);
    }
}
