//! Portable sparse authenticated-map proofs for the finding-status feed.
//!
//! This backend is deliberately separate from [`crate::InMemoryRevocationOracle`].
//! The existing oracle is an append-only ordinary Merkle tree whose absence
//! checks consult local state. Finding status needs portable absence, so this
//! module defines a full-depth sparse map with fixed hashing semantics.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::{Result, RevocationOracleError};

/// Fixed numeric key domain for `chio.finding.status.v1`.
///
/// This is the first 53 bits of SHA-256(`chio.finding.status.v1`) selected by
/// ADR-B. It is a wire constant and is never derived at runtime.
pub const FINDING_STATUS_KEY_DOMAIN_NONCE: u64 = 0x0b_c9f6_f005_59b6;

/// The sparse map consumes every bit of the SHA-256 key digest.
pub const FINDING_STATUS_SPARSE_DEPTH: usize = 256;

/// Signed status-map version.
pub const FINDING_STATUS_MAP_VERSION: &str = "sparse_map_v1";

/// Portable proof semantics. Siblings are ordered from leaf to root.
pub const FINDING_STATUS_PROOF_SEMANTICS: &str = "siblings_leaf_to_root_v1";

/// Hash algorithm used by every sparse-map operation.
pub const FINDING_STATUS_HASH_ALGORITHM: &str = "sha256";

/// Public labels bound into the signed epoch body.
pub const FINDING_STATUS_KEY_HASH_DOMAIN: &str = "chio.finding.status.v1:key";
pub const FINDING_STATUS_EMPTY_LEAF_DOMAIN: &str = "chio.finding.status.v1:empty-leaf";
pub const FINDING_STATUS_OCCUPIED_LEAF_DOMAIN: &str = "chio.finding.status.v1:occupied-leaf";
pub const FINDING_STATUS_BRANCH_DOMAIN: &str = "chio.finding.status.v1:branch";

const KEY_HASH_PREFIX: &[u8] = b"chio.finding.status.v1:key\0";
const EMPTY_LEAF_PREFIX: &[u8] = b"chio.finding.status.v1:empty-leaf\0";
const OCCUPIED_LEAF_PREFIX: &[u8] = b"chio.finding.status.v1:occupied-leaf\0";
const BRANCH_PREFIX: &[u8] = b"chio.finding.status.v1:branch\0";
const RETRACTED_VALUE: &[u8] = b"retracted";

type Hash = [u8; 32];

/// One immutable occupied leaf in the finding-status map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusSparseLeaf {
    pub finding_id: String,
    pub retraction_intent_sha256: String,
}

/// Portable fixed-depth path. The first sibling is adjacent to the leaf and
/// the last sibling is adjacent to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusSparseProof {
    pub key_hash: Hash,
    pub siblings: Vec<Hash>,
    pub leaf: Option<FindingStatusSparseLeaf>,
}

/// Root generation returned by the sparse backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingStatusSparseRoot {
    pub map_epoch: u64,
    pub root_hash: Hash,
}

/// Persistence-neutral sparse status map.
///
/// A durable store can persist `leaves`, `nodes`, and `map_epoch` in one
/// transaction. This in-memory form defines the portable hashing and proof
/// semantics without pretending to provide restart durability itself.
#[derive(Debug, Clone)]
pub struct FindingStatusSparseMap {
    leaves: HashMap<Hash, FindingStatusSparseLeaf>,
    nodes: HashMap<(u16, Hash), Hash>,
    map_epoch: u64,
    empty_hashes: Vec<Hash>,
}

impl Default for FindingStatusSparseMap {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingStatusSparseMap {
    /// Construct the canonical empty status map at epoch zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            map_epoch: 0,
            empty_hashes: compute_empty_hashes(),
        }
    }

    /// Insert one immutable retraction and advance the root generation.
    pub fn insert(
        &mut self,
        finding_id: &str,
        retraction_intent_sha256: &str,
    ) -> Result<FindingStatusSparseRoot> {
        let key_hash = finding_status_key_hash(finding_id)?;
        let intent = decode_hex_32(retraction_intent_sha256)?;
        if self.leaves.contains_key(&key_hash) {
            return Err(RevocationOracleError::AlreadyRevoked);
        }

        let leaf = FindingStatusSparseLeaf {
            finding_id: finding_id.to_string(),
            retraction_intent_sha256: retraction_intent_sha256.to_string(),
        };
        let mut position = key_hash;
        let mut current = occupied_leaf_hash(&key_hash, &intent);
        self.nodes.insert((0, position), current);

        for height in 0..FINDING_STATUS_SPARSE_DEPTH {
            let branch_depth = FINDING_STATUS_SPARSE_DEPTH - 1 - height;
            let current_is_right = bit_at(&key_hash, branch_depth);
            let mut sibling_position = position;
            toggle_bit(&mut sibling_position, branch_depth);
            let sibling = self
                .nodes
                .get(&(height as u16, sibling_position))
                .copied()
                .unwrap_or(self.empty_hashes[height]);
            let (left, right) = if current_is_right {
                (sibling, current)
            } else {
                (current, sibling)
            };
            current = branch_hash(&left, &right);
            clear_bit(&mut position, branch_depth);
            self.nodes.insert(((height + 1) as u16, position), current);
        }

        self.leaves.insert(key_hash, leaf);
        self.map_epoch = self
            .map_epoch
            .checked_add(1)
            .ok_or(RevocationOracleError::InvalidEpochTransition)?;
        Ok(self.root())
    }

    /// Return the current monotonic root generation.
    #[must_use]
    pub fn root(&self) -> FindingStatusSparseRoot {
        let zero = [0_u8; 32];
        FindingStatusSparseRoot {
            map_epoch: self.map_epoch,
            root_hash: self
                .nodes
                .get(&(FINDING_STATUS_SPARSE_DEPTH as u16, zero))
                .copied()
                .unwrap_or(self.empty_hashes[FINDING_STATUS_SPARSE_DEPTH]),
        }
    }

    /// Build an inclusion or non-inclusion path for one finding id.
    pub fn proof(&self, finding_id: &str) -> Result<FindingStatusSparseProof> {
        let key_hash = finding_status_key_hash(finding_id)?;
        let mut position = key_hash;
        let mut siblings = Vec::with_capacity(FINDING_STATUS_SPARSE_DEPTH);
        for height in 0..FINDING_STATUS_SPARSE_DEPTH {
            let branch_depth = FINDING_STATUS_SPARSE_DEPTH - 1 - height;
            let mut sibling_position = position;
            toggle_bit(&mut sibling_position, branch_depth);
            siblings.push(
                self.nodes
                    .get(&(height as u16, sibling_position))
                    .copied()
                    .unwrap_or(self.empty_hashes[height]),
            );
            clear_bit(&mut position, branch_depth);
        }
        Ok(FindingStatusSparseProof {
            key_hash,
            siblings,
            leaf: self.leaves.get(&key_hash).cloned(),
        })
    }
}

/// Hash the fixed numeric key domain and finding id into one sparse-map path.
pub fn finding_status_key_hash(finding_id: &str) -> Result<Hash> {
    validate_hex64(finding_id)?;
    let length = u64::try_from(finding_id.len())
        .map_err(|error| RevocationOracleError::Serialization(error.to_string()))?;
    Ok(hash_parts(&[
        KEY_HASH_PREFIX,
        &FINDING_STATUS_KEY_DOMAIN_NONCE.to_be_bytes(),
        &length.to_be_bytes(),
        finding_id.as_bytes(),
    ]))
}

/// Hash of the canonical empty leaf, bound into every signed status epoch.
#[must_use]
pub fn finding_status_empty_leaf_hash() -> Hash {
    hash_parts(&[EMPTY_LEAF_PREFIX])
}

/// Verify a portable sparse inclusion proof without consulting local state.
pub fn verify_finding_status_inclusion(
    root_hash: &Hash,
    finding_id: &str,
    retraction_intent_sha256: &str,
    proof: &FindingStatusSparseProof,
) -> Result<()> {
    let key_hash = finding_status_key_hash(finding_id)?;
    if proof.key_hash != key_hash || proof.siblings.len() != FINDING_STATUS_SPARSE_DEPTH {
        return Err(RevocationOracleError::InvalidProof);
    }
    let leaf = proof
        .leaf
        .as_ref()
        .ok_or(RevocationOracleError::InvalidProof)?;
    if leaf.finding_id != finding_id || leaf.retraction_intent_sha256 != retraction_intent_sha256 {
        return Err(RevocationOracleError::InvalidProof);
    }
    let intent = decode_hex_32(retraction_intent_sha256)?;
    verify_path(
        root_hash,
        &key_hash,
        occupied_leaf_hash(&key_hash, &intent),
        &proof.siblings,
    )
}

/// Verify a portable sparse non-inclusion proof without consulting local
/// state. The exact empty-leaf hash starts the path computation.
pub fn verify_finding_status_non_inclusion(
    root_hash: &Hash,
    finding_id: &str,
    proof: &FindingStatusSparseProof,
) -> Result<()> {
    let key_hash = finding_status_key_hash(finding_id)?;
    if proof.key_hash != key_hash
        || proof.leaf.is_some()
        || proof.siblings.len() != FINDING_STATUS_SPARSE_DEPTH
    {
        return Err(RevocationOracleError::InvalidProof);
    }
    verify_path(
        root_hash,
        &key_hash,
        finding_status_empty_leaf_hash(),
        &proof.siblings,
    )
}

fn verify_path(
    root_hash: &Hash,
    key_hash: &Hash,
    mut current: Hash,
    siblings: &[Hash],
) -> Result<()> {
    if siblings.len() != FINDING_STATUS_SPARSE_DEPTH {
        return Err(RevocationOracleError::InvalidProof);
    }
    for (height, sibling) in siblings.iter().enumerate() {
        let branch_depth = FINDING_STATUS_SPARSE_DEPTH - 1 - height;
        current = if bit_at(key_hash, branch_depth) {
            branch_hash(sibling, &current)
        } else {
            branch_hash(&current, sibling)
        };
    }
    if &current == root_hash {
        Ok(())
    } else {
        Err(RevocationOracleError::InvalidProof)
    }
}

fn compute_empty_hashes() -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(FINDING_STATUS_SPARSE_DEPTH + 1);
    hashes.push(finding_status_empty_leaf_hash());
    for height in 0..FINDING_STATUS_SPARSE_DEPTH {
        hashes.push(branch_hash(&hashes[height], &hashes[height]));
    }
    hashes
}

fn occupied_leaf_hash(key_hash: &Hash, intent_hash: &Hash) -> Hash {
    hash_parts(&[OCCUPIED_LEAF_PREFIX, key_hash, RETRACTED_VALUE, intent_hash])
}

fn branch_hash(left: &Hash, right: &Hash) -> Hash {
    hash_parts(&[BRANCH_PREFIX, left, right])
}

fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn validate_hex64(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RevocationOracleError::InvalidRevocationKey(
            "finding status identifiers must be lowercase sha256 hex".to_string(),
        ))
    }
}

fn decode_hex_32(value: &str) -> Result<Hash> {
    validate_hex64(value)?;
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(RevocationOracleError::InvalidRevocationKey(
            "finding status digest contains non-hex bytes".to_string(),
        )),
    }
}

fn bit_at(key: &Hash, depth_from_root: usize) -> bool {
    let byte_index = depth_from_root / 8;
    let bit_index = 7 - (depth_from_root % 8);
    key[byte_index] & (1 << bit_index) != 0
}

fn toggle_bit(key: &mut Hash, depth_from_root: usize) {
    let byte_index = depth_from_root / 8;
    let bit_index = 7 - (depth_from_root % 8);
    key[byte_index] ^= 1 << bit_index;
}

fn clear_bit(key: &mut Hash, depth_from_root: usize) {
    let byte_index = depth_from_root / 8;
    let bit_index = 7 - (depth_from_root % 8);
    key[byte_index] &= !(1 << bit_index);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINDING_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FINDING_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FINDING_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const INTENT_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const INTENT_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn empty_and_non_empty_roots_have_portable_non_inclusion() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        let empty = map.root();
        let empty_proof = map.proof(FINDING_A)?;
        verify_finding_status_non_inclusion(&empty.root_hash, FINDING_A, &empty_proof)?;

        let root = map.insert(FINDING_B, INTENT_B)?;
        let proof = map.proof(FINDING_A)?;
        verify_finding_status_non_inclusion(&root.root_hash, FINDING_A, &proof)
    }

    #[test]
    fn inclusion_survives_other_inserts() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        map.insert(FINDING_A, INTENT_A)?;
        let root = map.insert(FINDING_B, INTENT_B)?;
        let proof = map.proof(FINDING_A)?;
        assert_eq!(proof.siblings.len(), FINDING_STATUS_SPARSE_DEPTH);
        verify_finding_status_inclusion(&root.root_hash, FINDING_A, INTENT_A, &proof)
    }

    #[test]
    fn mutation_and_branch_substitution_reject() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        let root = map.insert(FINDING_A, INTENT_A)?;
        let mut proof = map.proof(FINDING_A)?;
        proof.siblings[127][3] ^= 1;
        assert_eq!(
            verify_finding_status_inclusion(&root.root_hash, FINDING_A, INTENT_A, &proof),
            Err(RevocationOracleError::InvalidProof)
        );

        let ordinary_root = [7_u8; 32];
        let clean = map.proof(FINDING_A)?;
        assert_eq!(
            verify_finding_status_inclusion(&ordinary_root, FINDING_A, INTENT_A, &clean),
            Err(RevocationOracleError::InvalidProof)
        );
        Ok(())
    }

    #[test]
    fn inclusion_cannot_be_relabelled_non_inclusion() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        let root = map.insert(FINDING_A, INTENT_A)?;
        let proof = map.proof(FINDING_A)?;
        assert_eq!(
            verify_finding_status_non_inclusion(&root.root_hash, FINDING_A, &proof),
            Err(RevocationOracleError::InvalidProof)
        );
        Ok(())
    }

    #[test]
    fn key_value_and_intent_cross_bindings_reject() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        let root = map.insert(FINDING_A, INTENT_A)?;
        let proof = map.proof(FINDING_A)?;
        assert!(
            verify_finding_status_inclusion(&root.root_hash, FINDING_B, INTENT_A, &proof).is_err()
        );
        assert!(
            verify_finding_status_inclusion(&root.root_hash, FINDING_A, INTENT_B, &proof).is_err()
        );
        assert!(verify_finding_status_non_inclusion(&root.root_hash, FINDING_C, &proof).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_insert_does_not_advance_epoch() -> Result<()> {
        let mut map = FindingStatusSparseMap::new();
        let first = map.insert(FINDING_A, INTENT_A)?;
        assert_eq!(
            map.insert(FINDING_A, INTENT_A),
            Err(RevocationOracleError::AlreadyRevoked)
        );
        assert_eq!(map.root(), first);
        Ok(())
    }

    #[test]
    fn root_is_independent_of_insertion_order() -> Result<()> {
        let mut forward = FindingStatusSparseMap::new();
        forward.insert(FINDING_A, INTENT_A)?;
        let forward_root = forward.insert(FINDING_B, INTENT_B)?;

        let mut reverse = FindingStatusSparseMap::new();
        reverse.insert(FINDING_B, INTENT_B)?;
        let reverse_root = reverse.insert(FINDING_A, INTENT_A)?;

        assert_eq!(forward_root, reverse_root);
        for (finding_id, intent) in [(FINDING_A, INTENT_A), (FINDING_B, INTENT_B)] {
            let proof = reverse.proof(finding_id)?;
            verify_finding_status_inclusion(&reverse_root.root_hash, finding_id, intent, &proof)?;
        }
        Ok(())
    }

    #[test]
    fn fixed_nonce_is_the_locked_numeric_value() {
        assert_eq!(FINDING_STATUS_KEY_DOMAIN_NONCE, 3_318_287_169_837_494);
    }
}
