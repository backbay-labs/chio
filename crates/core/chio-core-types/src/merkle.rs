//! RFC 6962-compatible Merkle tree (Certificate Transparency style).
//!
//! This tree is required for receipt log integrity proofs:
//! - `LeafHash(leaf_bytes) = SHA256(0x00 || leaf_bytes)`
//! - `NodeHash(left, right) = SHA256(0x01 || left || right)`
//!
//! This implementation does **not** "duplicate last" when a level has an odd
//! number of nodes; it carries the last node upward unchanged (left-balanced /
//! append-only semantics).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};
use crate::hashing::Hash;
use crate::merkle_steps::inclusion_step;

/// Compute leaf hash per RFC 6962: `SHA256(0x00 || leaf_bytes)`.
#[must_use]
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute node hash per RFC 6962: `SHA256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    #[cfg(kani)]
    {
        // The traversal proof treats hashing as an order-sensitive algebra
        // under ASSUME-SHA256.
        let mut output = [0u8; 32];
        output[0] = left.as_bytes()[0]
            .wrapping_mul(3)
            .wrapping_add(right.as_bytes()[0].wrapping_mul(5))
            .wrapping_add(1);
        output[1] = left.as_bytes()[1]
            .wrapping_mul(7)
            .wrapping_add(right.as_bytes()[1].wrapping_mul(11))
            .wrapping_add(1);
        Hash::from_bytes(output)
    }

    #[cfg(not(kani))]
    {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash::from_bytes(bytes)
    }
}

/// RFC 6962-compatible Merkle tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// Returns `Err(Error::EmptyTree)` if the slice is empty.
    pub fn from_leaves<T: AsRef<[u8]>>(leaves: &[T]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current: Vec<Hash> = Vec::with_capacity(leaves.len());
        let mut li = 0;
        while li < leaves.len() {
            current.push(leaf_hash(leaves[li].as_ref()));
            li += 1;
        }
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    // Carry last node upward unchanged.
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn from_hashes(leaf_hashes: Vec<Hash>) -> Result<Self> {
        if leaf_hashes.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current = leaf_hashes;
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Get the number of leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        if self.levels.is_empty() {
            0
        } else {
            self.levels[0].len()
        }
    }

    /// Get the root hash.
    #[must_use]
    pub fn root(&self) -> Hash {
        if self.levels.is_empty() {
            Hash::zero()
        } else {
            let last = &self.levels[self.levels.len() - 1];
            if last.is_empty() {
                Hash::zero()
            } else {
                last[0]
            }
        }
    }

    /// Generate an inclusion proof for a leaf at the given index.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        let tree_size = self.leaf_count();
        if leaf_index >= tree_size {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves: tree_size,
            });
        }

        let mut audit_path: Vec<Hash> = Vec::new();
        let mut idx = leaf_index;

        let mut level_idx = 0;
        while level_idx < self.levels.len() {
            let level_len = self.levels[level_idx].len();
            if level_len <= 1 {
                break;
            }

            if idx.is_multiple_of(2) {
                let sib = idx + 1;
                if sib < level_len {
                    audit_path.push(self.levels[level_idx][sib]);
                }
            } else {
                audit_path.push(self.levels[level_idx][idx - 1]);
            }

            idx /= 2;
            level_idx += 1;
        }

        Ok(MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        })
    }
}

/// Merkle inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Total number of leaves in the tree.
    pub tree_size: usize,
    /// Index of the leaf being proved.
    pub leaf_index: usize,
    /// Audit path (sibling hashes from leaf to root).
    pub audit_path: Vec<Hash>,
}

impl MerkleProof {
    /// Compute the root from leaf bytes and the proof.
    pub fn compute_root(&self, leaf_bytes: &[u8]) -> Result<Hash> {
        self.compute_root_from_hash(leaf_hash(leaf_bytes))
    }

    /// Compute the root from a pre-hashed leaf and the proof.
    pub fn compute_root_from_hash(&self, lh: Hash) -> Result<Hash> {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return Err(Error::MerkleProofFailed);
        }

        let mut h = lh;
        let mut idx = u64::try_from(self.leaf_index).map_err(|_| Error::MerkleProofFailed)?;
        let mut size = u64::try_from(self.tree_size).map_err(|_| Error::MerkleProofFailed)?;
        let mut path_idx: usize = 0;

        while size > 1 {
            let step = inclusion_step(idx, size);
            if step.consume_sibling {
                let sibling = self
                    .audit_path
                    .get(path_idx)
                    .ok_or(Error::MerkleProofFailed)?;
                path_idx = path_idx.checked_add(1).ok_or(Error::MerkleProofFailed)?;
                h = if step.sibling_on_left {
                    node_hash(sibling, &h)
                } else {
                    node_hash(&h, sibling)
                };
            }

            idx = step.next_index;
            size = step.next_size;
        }

        if path_idx != self.audit_path.len() {
            return Err(Error::MerkleProofFailed);
        }

        Ok(h)
    }

    /// Verify the proof against an expected root.
    #[must_use]
    pub fn verify(&self, leaf_bytes: &[u8], expected_root: &Hash) -> bool {
        match self.compute_root(leaf_bytes) {
            Ok(root) => &root == expected_root,
            Err(_) => false,
        }
    }

    /// Verify the proof from a pre-hashed leaf.
    #[must_use]
    pub fn verify_hash(&self, lh: Hash, expected_root: &Hash) -> bool {
        match self.compute_root_from_hash(lh) {
            Ok(root) => &root == expected_root,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tree_hash_recursive(level0: &[Hash]) -> Hash {
        match level0.len() {
            0 => Hash::zero(),
            1 => level0[0],
            n => {
                let k = largest_power_of_two_less_than(n);
                let left = tree_hash_recursive(&level0[..k]);
                let right = tree_hash_recursive(&level0[k..]);
                node_hash(&left, &right)
            }
        }
    }

    fn largest_power_of_two_less_than(n: usize) -> usize {
        let mut p = 1usize;
        while (p << 1) < n {
            p <<= 1;
        }
        p
    }

    #[test]
    fn root_matches_recursive_reference() {
        for n in 1..32usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
            let tree = MerkleTree::from_leaves(&leaves).unwrap();

            let leaf_hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
            let expected = tree_hash_recursive(&leaf_hashes);
            assert_eq!(tree.root(), expected, "n={n}");
        }
    }

    #[test]
    fn inclusion_proofs_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..25usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(idx).unwrap();
            assert!(proof.verify(leaf, &root), "idx={idx}");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..10usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(3).unwrap();
        assert!(!proof.verify(b"wrong", &root));
    }

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf_hash(b"single"));

        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"single", &tree.root()));
        assert!(proof.audit_path.is_empty());
    }

    #[test]
    fn two_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(tree.leaf_count(), 2);

        let expected_root = node_hash(&leaf_hash(b"left"), &leaf_hash(b"right"));
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    #[cfg(not(kani))]
    fn standard_build_node_hash_uses_rfc6962_sha256() {
        let left = Hash::from_bytes([0; 32]);
        let right = Hash::from_bytes([1; 32]);
        let expected = Hash::from_bytes([
            0x2a, 0xd8, 0x2c, 0x3a, 0x51, 0xe8, 0xed, 0x64, 0x18, 0xcb, 0x5b, 0xf2, 0x67, 0xc5,
            0xf9, 0xe5, 0x21, 0xb9, 0x9f, 0x7a, 0xb4, 0xfc, 0xe6, 0x57, 0xf4, 0x60, 0xa8, 0xf1,
            0xa3, 0xe8, 0x7b, 0x2e,
        ]);

        assert_eq!(node_hash(&left, &right), expected);
    }

    #[test]
    fn empty_tree_fails() {
        let empty: Vec<&[u8]> = vec![];
        let result = MerkleTree::from_leaves(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..5usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = tree.inclusion_proof(2).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let restored: MerkleProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.tree_size, restored.tree_size);
        assert_eq!(proof.leaf_index, restored.leaf_index);
        assert_eq!(proof.audit_path.len(), restored.audit_path.len());
        assert!(restored.verify(&leaves[2], &tree.root()));
    }

    #[test]
    fn from_hashes_matches_from_leaves() {
        let leaves: Vec<Vec<u8>> = (0..7usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree_from_leaves = MerkleTree::from_leaves(&leaves).unwrap();

        let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let tree_from_hashes = MerkleTree::from_hashes(hashes).unwrap();

        assert_eq!(tree_from_leaves.root(), tree_from_hashes.root());
        assert_eq!(tree_from_leaves.leaf_count(), tree_from_hashes.leaf_count());
    }

    #[test]
    fn proof_out_of_bounds() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        let result = tree.inclusion_proof(1);
        assert!(result.is_err());
    }

    #[test]
    fn verify_hash_works() {
        let leaves: Vec<Vec<u8>> = (0..4usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(2).unwrap();
        let lh = leaf_hash(&leaves[2]);
        assert!(proof.verify_hash(lh, &root));
        assert!(!proof.verify_hash(Hash::zero(), &root));
    }
}
