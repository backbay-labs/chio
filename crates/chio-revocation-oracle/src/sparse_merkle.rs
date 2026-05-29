use std::collections::HashMap;

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};

use crate::api::{
    EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey, RevocationOracle,
    RevocationOracleError,
};
use crate::{EpochRootSigner, SignedEpochRoot};

#[derive(Debug, Clone)]
struct LeafRecord {
    index: usize,
    hash: [u8; 32],
}

#[derive(Clone)]
pub struct InMemoryRevocationOracle {
    layers: Vec<Vec<[u8; 32]>>,
    records: HashMap<RevocationKey, LeafRecord>,
    epoch: u64,
    issued_at_unix_ms: u64,
}

impl Default for InMemoryRevocationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRevocationOracle {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let mut layers = Vec::new();
        if capacity > 0 {
            layers.push(Vec::with_capacity(capacity));
        }
        Self {
            layers,
            records: HashMap::with_capacity(capacity),
            epoch: 0,
            issued_at_unix_ms: 0,
        }
    }

    fn leaf_count(&self) -> usize {
        self.layers.first().map_or(0, Vec::len)
    }

    pub fn verify_inclusion(proof: &InclusionProof) -> Result<()> {
        let leaf_hash = Self::leaf_hash(&proof.key)?;
        if leaf_hash != proof.leaf_hash {
            return Err(RevocationOracleError::InvalidProof);
        }

        let parsed = MerkleProof::<Sha256>::from_bytes(&proof.proof_bytes)
            .map_err(|_| RevocationOracleError::InvalidProof)?;
        let ok = parsed.verify(
            proof.epoch_root.root_hash,
            &[proof.leaf_index],
            &[leaf_hash],
            proof.epoch_root.leaf_count,
        );
        if ok {
            Ok(())
        } else {
            Err(RevocationOracleError::InvalidProof)
        }
    }

    #[must_use]
    pub fn verify_non_inclusion(&self, proof: &NonInclusionProof) -> bool {
        proof.epoch_root == self.epoch_root() && !self.contains(&proof.key)
    }

    fn current_root_hash(&self) -> [u8; 32] {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or([0_u8; 32])
    }

    fn leaf_hash(key: &RevocationKey) -> Result<[u8; 32]> {
        let subject = key.subject_id.as_str().as_bytes();
        let mut bytes = Vec::with_capacity(subject.len() + 16);
        bytes.extend_from_slice(&(subject.len() as u64).to_be_bytes());
        bytes.extend_from_slice(subject);
        bytes.extend_from_slice(&key.epoch_nonce.get().to_be_bytes());
        Ok(Sha256::hash(&bytes))
    }

    pub fn signed_epoch_root(&self, signer: &impl EpochRootSigner) -> Result<SignedEpochRoot> {
        SignedEpochRoot::sign(self.epoch_root(), signer)
    }

    fn append_leaf(&mut self, hash: [u8; 32]) {
        if self.layers.is_empty() {
            self.layers.push(Vec::new());
        }
        self.layers[0].push(hash);

        let mut level = 0;
        let mut index = self.layers[0].len() - 1;
        loop {
            let parent_index = index / 2;
            let left_index = parent_index * 2;
            let right_index = left_index + 1;
            let Some(left) = self.layers[level].get(left_index).copied() else {
                break;
            };
            let parent = Sha256::concat_and_hash(&left, self.layers[level].get(right_index));
            if self.layers.len() == level + 1 {
                self.layers.push(Vec::new());
            }
            if parent_index < self.layers[level + 1].len() {
                self.layers[level + 1][parent_index] = parent;
            } else {
                self.layers[level + 1].push(parent);
            }

            level += 1;
            index = parent_index;
            if self.layers[level].len() == 1 {
                break;
            }
        }
    }

    fn proof_bytes_for_index(&self, mut index: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for layer in &self.layers {
            if layer.len() <= 1 {
                break;
            }
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index.saturating_sub(1)
            };
            if let Some(sibling) = layer.get(sibling_index) {
                bytes.extend_from_slice(sibling);
            }
            index /= 2;
        }
        bytes
    }
}

impl RevocationOracle for InMemoryRevocationOracle {
    fn insert(&mut self, key: RevocationKey, now_unix_ms: u64) -> Result<EpochRoot> {
        if self.records.contains_key(&key) {
            return Err(RevocationOracleError::AlreadyRevoked);
        }

        let hash = Self::leaf_hash(&key)?;
        let index = self.leaf_count();
        self.append_leaf(hash);
        self.records.insert(key, LeafRecord { index, hash });
        self.epoch = self.epoch.saturating_add(1);
        // Clamp issued_at to a monotone non-decreasing floor. Wall-clock
        // skew (NTP correction, leap-second roll-back) MUST NOT make a
        // newer epoch carry an earlier `issued_at_unix_ms` than a prior
        // one: downstream freshness caches that track "latest seen
        // issued_at" as a replay-protection floor would otherwise accept
        // a root issued strictly before the previous epoch as still
        // fresh. Fail-closed on the time field by taking the max.
        self.issued_at_unix_ms = self.issued_at_unix_ms.max(now_unix_ms);
        Ok(self.epoch_root())
    }

    fn contains(&self, key: &RevocationKey) -> bool {
        self.records.contains_key(key)
    }

    fn epoch_root(&self) -> EpochRoot {
        EpochRoot {
            epoch: self.epoch,
            root_hash: self.current_root_hash(),
            leaf_count: self.leaf_count(),
            issued_at_unix_ms: self.issued_at_unix_ms,
        }
    }

    fn inclusion_proof(&self, key: &RevocationKey) -> Result<InclusionProof> {
        let record = self
            .records
            .get(key)
            .ok_or(RevocationOracleError::NotRevoked)?;
        Ok(InclusionProof {
            key: key.clone(),
            epoch_root: self.epoch_root(),
            leaf_index: record.index,
            leaf_hash: record.hash,
            proof_bytes: self.proof_bytes_for_index(record.index),
        })
    }

    fn non_inclusion_proof(
        &self,
        key: RevocationKey,
        now_unix_ms: u64,
    ) -> Result<NonInclusionProof> {
        if self.contains(&key) {
            return Err(RevocationOracleError::AlreadyRevoked);
        }
        Ok(NonInclusionProof {
            key,
            epoch_root: self.epoch_root(),
            checked_at_unix_ms: now_unix_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochNonce, SubjectId};

    #[test]
    fn inclusion_proof_verifies_for_revoked_subject() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(7));

        oracle.insert(key.clone(), 10)?;
        let proof = oracle.inclusion_proof(&key)?;

        InMemoryRevocationOracle::verify_inclusion(&proof)
    }

    #[test]
    fn inclusion_proof_rejects_tampered_key() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(7));

        oracle.insert(key.clone(), 10)?;
        let mut proof = oracle.inclusion_proof(&key)?;
        proof.key = RevocationKey::new(SubjectId::from("subject-b"), EpochNonce::new(7));

        assert_eq!(
            InMemoryRevocationOracle::verify_inclusion(&proof),
            Err(RevocationOracleError::InvalidProof)
        );
        Ok(())
    }

    #[test]
    fn non_inclusion_proof_fails_closed_after_insert() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(7));
        let proof = oracle.non_inclusion_proof(key.clone(), 10)?;

        oracle.insert(key, 11)?;

        assert!(!oracle.verify_non_inclusion(&proof));
        Ok(())
    }

    #[test]
    fn signed_epoch_root_verifies() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(7));
        oracle.insert(key, 10)?;
        let signer = crate::Ed25519RootSigner::from_signing_key(
            "m04-test",
            "0303030303030303030303030303030303030303030303030303030303030303",
        )?;

        let signed = oracle.signed_epoch_root(&signer)?;

        signed.verify(&signer.verifier())
    }

    /// Regression: clock skew backward across `insert` calls must not
    /// decrease `issued_at_unix_ms`. A downstream cache that uses the
    /// latest-seen `issued_at` as a freshness floor would otherwise
    /// accept the new root (with an earlier timestamp) as still in-grace
    /// and silently observe a torn ordering between the two epochs.
    #[test]
    fn issued_at_is_monotone_under_clock_skew() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key_a = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(1));
        let key_b = RevocationKey::new(SubjectId::from("subject-b"), EpochNonce::new(2));

        let root_one = oracle.insert(key_a, 1_000)?;
        // Wall-clock has skewed backwards (NTP correction or leap-second
        // roll-back). The new epoch MUST still carry a non-decreasing
        // `issued_at_unix_ms`.
        let root_two = oracle.insert(key_b, 500)?;

        assert!(root_two.epoch > root_one.epoch);
        assert!(
            root_two.issued_at_unix_ms >= root_one.issued_at_unix_ms,
            "issued_at must be monotone non-decreasing across inserts: \
             root_one={} root_two={}",
            root_one.issued_at_unix_ms,
            root_two.issued_at_unix_ms,
        );
        Ok(())
    }
}
