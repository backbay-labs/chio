use std::collections::BTreeMap;

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

use crate::api::{
    EpochRoot, InclusionProof, NonInclusionProof, Result, RevocationKey, RevocationOracle,
    RevocationOracleError,
};

#[derive(Debug, Clone)]
struct LeafRecord {
    index: usize,
    hash: [u8; 32],
}

#[derive(Clone)]
pub struct InMemoryRevocationOracle {
    tree: MerkleTree<Sha256>,
    leaves: Vec<[u8; 32]>,
    records: BTreeMap<RevocationKey, LeafRecord>,
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
        Self {
            tree: MerkleTree::new(),
            leaves: Vec::new(),
            records: BTreeMap::new(),
            epoch: 0,
            issued_at_unix_ms: 0,
        }
    }

    pub fn verify_inclusion(proof: &InclusionProof) -> Result<()> {
        let parsed = MerkleProof::<Sha256>::from_bytes(&proof.proof_bytes)
            .map_err(|_| RevocationOracleError::InvalidProof)?;
        let ok = parsed.verify(
            proof.epoch_root.root_hash,
            &[proof.leaf_index],
            &[proof.leaf_hash],
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
        self.tree.root().unwrap_or([0_u8; 32])
    }

    fn leaf_hash(key: &RevocationKey) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(key)
            .map_err(|err| RevocationOracleError::Serialization(err.to_string()))?;
        Ok(Sha256::hash(&bytes))
    }
}

impl RevocationOracle for InMemoryRevocationOracle {
    fn insert(&mut self, key: RevocationKey, now_unix_ms: u64) -> Result<EpochRoot> {
        if self.records.contains_key(&key) {
            return Err(RevocationOracleError::AlreadyRevoked);
        }

        let hash = Self::leaf_hash(&key)?;
        let index = self.leaves.len();
        self.tree.insert(hash).commit();
        self.leaves.push(hash);
        self.records.insert(key, LeafRecord { index, hash });
        self.epoch = self.epoch.saturating_add(1);
        self.issued_at_unix_ms = now_unix_ms;
        Ok(self.epoch_root())
    }

    fn contains(&self, key: &RevocationKey) -> bool {
        self.records.contains_key(key)
    }

    fn epoch_root(&self) -> EpochRoot {
        EpochRoot {
            epoch: self.epoch,
            root_hash: self.current_root_hash(),
            leaf_count: self.leaves.len(),
            issued_at_unix_ms: self.issued_at_unix_ms,
        }
    }

    fn inclusion_proof(&self, key: &RevocationKey) -> Result<InclusionProof> {
        let record = self
            .records
            .get(key)
            .ok_or(RevocationOracleError::NotRevoked)?;
        let proof = self.tree.proof(&[record.index]);
        Ok(InclusionProof {
            key: key.clone(),
            epoch_root: self.epoch_root(),
            leaf_index: record.index,
            leaf_hash: record.hash,
            proof_bytes: proof.to_bytes(),
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
    fn non_inclusion_proof_fails_closed_after_insert() -> Result<()> {
        let mut oracle = InMemoryRevocationOracle::new();
        let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(7));
        let proof = oracle.non_inclusion_proof(key.clone(), 10)?;

        oracle.insert(key, 11)?;

        assert!(!oracle.verify_non_inclusion(&proof));
        Ok(())
    }
}
