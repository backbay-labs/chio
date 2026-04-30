use chio_revocation_oracle::{
    DigestRootSigner, EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle,
    SubjectId,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn key(subject: String, nonce: u64) -> RevocationKey {
    RevocationKey::new(SubjectId::new(subject), EpochNonce::new(nonce))
}

proptest! {
    #[test]
    fn inclusion_proof_soundness(subject in "[a-z0-9]{1,24}", nonce in 0_u64..10_000) {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = key(subject, nonce);
        oracle
            .insert(key.clone(), 10)
            .map_err(|err| TestCaseError::fail(format!("insert failed: {err}")))?;

        let proof = oracle
            .inclusion_proof(&key)
            .map_err(|err| TestCaseError::fail(format!("proof failed: {err}")))?;

        prop_assert!(InMemoryRevocationOracle::verify_inclusion(&proof).is_ok());
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
        let signer = DigestRootSigner::new("m04-property", b"secret".to_vec());
        oracle
            .insert(key, 10)
            .map_err(|err| TestCaseError::fail(format!("insert failed: {err}")))?;

        let mut signed = oracle
            .signed_epoch_root(&signer)
            .map_err(|err| TestCaseError::fail(format!("sign failed: {err}")))?;

        prop_assert!(signed.verify(&signer).is_ok());
        signed.signature.signature_bytes.push(0);
        prop_assert!(signed.verify(&signer).is_err());
    }

    #[test]
    fn epoch_monotone(subject_a in "[a-z0-9]{1,24}", subject_b in "[a-z0-9]{1,24}") {
        let mut oracle = InMemoryRevocationOracle::new();
        let first = key(subject_a, 1);
        let mut second = key(subject_b, 2);
        if second == first {
            second = key("fallback-subject".to_string(), 3);
        }

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
