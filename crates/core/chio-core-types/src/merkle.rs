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

    /// Generate an RFC 6962 consistency proof (RFC 9162 section 2.1.4.1)
    /// showing that the tree over the first `old_size` leaves is a prefix of
    /// this tree.
    ///
    /// The proof for `old_size == leaf_count()` is empty. Returns
    /// `Err(Error::InvalidProofIndex)` when `old_size` is zero or exceeds the
    /// current leaf count.
    pub fn consistency_proof(&self, old_size: usize) -> Result<Vec<Hash>> {
        self.consistency_proof_between(old_size, self.leaf_count())
    }

    /// Generate an RFC 6962 consistency proof between two prefixes of this
    /// tree without rebuilding the shorter tree.
    pub fn consistency_proof_between(&self, old_size: usize, new_size: usize) -> Result<Vec<Hash>> {
        let leaves = self.leaf_count();
        if old_size == 0 || old_size > new_size || new_size > leaves {
            return Err(Error::InvalidProofIndex {
                index: old_size,
                leaves,
            });
        }
        let mut proof = Vec::new();
        self.consistency_subproof(old_size, 0, new_size, true, &mut proof)?;
        Ok(proof)
    }

    fn consistency_subproof(
        &self,
        m: usize,
        lo: usize,
        hi: usize,
        complete: bool,
        out: &mut Vec<Hash>,
    ) -> Result<()> {
        let n = hi - lo;
        if m == n {
            if !complete {
                out.push(self.range_hash(lo, hi)?);
            }
            return Ok(());
        }
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            self.consistency_subproof(m, lo, lo + k, complete, out)?;
            out.push(self.range_hash(lo + k, hi)?);
        } else {
            self.consistency_subproof(m - k, lo + k, hi, false, out)?;
            out.push(self.range_hash(lo, lo + k)?);
        }
        Ok(())
    }

    /// Return the root of the first `tree_size` leaves without rebuilding that
    /// prefix.
    pub fn prefix_root(&self, tree_size: usize) -> Result<Hash> {
        let leaves = self.leaf_count();
        if tree_size == 0 || tree_size > leaves {
            return Err(Error::InvalidProofIndex {
                index: tree_size,
                leaves,
            });
        }
        self.range_hash(0, tree_size)
    }

    /// Hash the RFC 6962 subtree covering leaves `[lo, hi)`.
    ///
    /// Perfect aligned subtrees come directly from the cached levels.
    /// Irregular ranges decompose into logarithmically many perfect subtrees.
    fn range_hash(&self, lo: usize, hi: usize) -> Result<Hash> {
        let leaves = self.leaf_count();
        if lo >= hi || hi > leaves {
            return Err(Error::MerkleProofFailed);
        }
        let size = hi - lo;
        if size.is_power_of_two() && lo.is_multiple_of(size) {
            let level = size.trailing_zeros() as usize;
            return self
                .levels
                .get(level)
                .and_then(|nodes| nodes.get(lo / size))
                .copied()
                .ok_or(Error::MerkleProofFailed);
        }

        let split = largest_power_of_two_less_than(size);
        let left = self.range_hash(lo, lo + split)?;
        let right = self.range_hash(lo + split, hi)?;
        Ok(node_hash(&left, &right))
    }

    /// Generate an inclusion proof for a leaf at the given index.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        self.inclusion_proof_at_size(leaf_index, self.leaf_count())
    }

    /// Generate an inclusion proof within a prefix of this tree without
    /// rebuilding that prefix.
    pub fn inclusion_proof_at_size(
        &self,
        leaf_index: usize,
        tree_size: usize,
    ) -> Result<MerkleProof> {
        let leaves = self.leaf_count();
        if tree_size == 0 || tree_size > leaves || leaf_index >= tree_size {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves,
            });
        }

        let mut audit_path: Vec<Hash> = Vec::new();
        self.inclusion_subproof(leaf_index, 0, tree_size, &mut audit_path)?;

        Ok(MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        })
    }

    fn inclusion_subproof(
        &self,
        leaf_index: usize,
        lo: usize,
        hi: usize,
        out: &mut Vec<Hash>,
    ) -> Result<()> {
        let size = hi - lo;
        if size == 1 {
            return Ok(());
        }
        let split = largest_power_of_two_less_than(size);
        let mid = lo + split;
        if leaf_index < mid {
            self.inclusion_subproof(leaf_index, lo, mid, out)?;
            out.push(self.range_hash(mid, hi)?);
        } else {
            self.inclusion_subproof(leaf_index, mid, hi, out)?;
            out.push(self.range_hash(lo, mid)?);
        }
        Ok(())
    }
}

/// Largest power of two strictly less than `n`, per the RFC 6962 split rule.
fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut p = 1usize;
    while (p << 1) < n {
        p <<= 1;
    }
    p
}

/// Verify an RFC 6962 consistency proof (RFC 9162 section 2.1.4.2) between an
/// old tree of `old_size` leaves with root `old_root` and a new tree of
/// `new_size` leaves with root `new_root`.
///
/// Returns `false` on any mismatch, malformed proof, or invalid size pair.
#[must_use]
pub fn verify_consistency_proof(
    old_size: usize,
    new_size: usize,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    // When old_size is an exact power of two, the old root itself is the
    // first node on the path and is not repeated inside the proof.
    let mut path: Vec<&Hash> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(old_root);
    }
    path.extend(proof.iter());
    let mut nodes = path.into_iter();
    let Some(first) = nodes.next() else {
        return false;
    };

    let mut fnode = old_size - 1;
    let mut snode = new_size - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    let mut old_reconstructed = *first;
    let mut new_reconstructed = *first;
    for node in nodes {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            old_reconstructed = node_hash(node, &old_reconstructed);
            new_reconstructed = node_hash(node, &new_reconstructed);
            while fnode != 0 && fnode & 1 == 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            new_reconstructed = node_hash(&new_reconstructed, node);
        }
        fnode >>= 1;
        snode >>= 1;
    }

    old_reconstructed == *old_root && new_reconstructed == *new_root && snode == 0
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

    /// Reference consistency-proof generator implementing the RFC 9162
    /// SUBPROOF recursion directly over leaf-hash slices, independent of the
    /// level-based tree structure.
    fn reference_subproof(leaf_hashes: &[Hash], m: usize, complete: bool, out: &mut Vec<Hash>) {
        let n = leaf_hashes.len();
        if m == n {
            if !complete {
                out.push(tree_hash_recursive(leaf_hashes));
            }
            return;
        }
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            reference_subproof(&leaf_hashes[..k], m, complete, out);
            out.push(tree_hash_recursive(&leaf_hashes[k..]));
        } else {
            reference_subproof(&leaf_hashes[k..], m - k, false, out);
            out.push(tree_hash_recursive(&leaf_hashes[..k]));
        }
    }

    fn test_leaf_hashes(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn consistency_proofs_match_reference_and_verify_for_all_size_pairs() {
        for n in 1..=48usize {
            let leaf_hashes = test_leaf_hashes(n);
            let tree = MerkleTree::from_hashes(leaf_hashes.clone()).unwrap();
            let new_root = tree.root();
            for m in 1..=n {
                let proof = tree.consistency_proof(m).unwrap();

                let mut expected = Vec::new();
                reference_subproof(&leaf_hashes, m, true, &mut expected);
                assert_eq!(proof, expected, "generator mismatch at m={m} n={n}");

                let old_root = tree_hash_recursive(&leaf_hashes[..m]);
                assert!(
                    verify_consistency_proof(m, n, &old_root, &new_root, &proof),
                    "valid proof rejected at m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn one_tree_derives_every_prefix_root_and_proof() {
        let leaf_hashes = test_leaf_hashes(64);
        let tree = MerkleTree::from_hashes(leaf_hashes.clone()).unwrap();

        for new_size in 1..=leaf_hashes.len() {
            let new_root = tree_hash_recursive(&leaf_hashes[..new_size]);
            assert_eq!(tree.prefix_root(new_size).unwrap(), new_root);

            let last_leaf = new_size - 1;
            let inclusion = tree.inclusion_proof_at_size(last_leaf, new_size).unwrap();
            assert!(inclusion.verify_hash(leaf_hashes[last_leaf], &new_root));

            for old_size in 1..=new_size {
                let old_root = tree_hash_recursive(&leaf_hashes[..old_size]);
                let proof = tree.consistency_proof_between(old_size, new_size).unwrap();
                assert!(
                    verify_consistency_proof(old_size, new_size, &old_root, &new_root, &proof),
                    "valid prefix proof rejected at old={old_size} new={new_size}"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_tampered_roots_and_proofs() {
        for (m, n) in [(1usize, 2usize), (3, 7), (4, 12), (6, 13), (7, 8), (16, 33)] {
            let leaf_hashes = test_leaf_hashes(n);
            let tree = MerkleTree::from_hashes(leaf_hashes.clone()).unwrap();
            let new_root = tree.root();
            let old_root = tree_hash_recursive(&leaf_hashes[..m]);
            let proof = tree.consistency_proof(m).unwrap();

            assert!(
                !verify_consistency_proof(m, n, &Hash::zero(), &new_root, &proof),
                "tampered old root accepted at m={m} n={n}"
            );
            assert!(
                !verify_consistency_proof(m, n, &old_root, &Hash::zero(), &proof),
                "tampered new root accepted at m={m} n={n}"
            );
            for index in 0..proof.len() {
                let mut mutated = proof.clone();
                mutated[index] = node_hash(&mutated[index], &mutated[index]);
                assert!(
                    !verify_consistency_proof(m, n, &old_root, &new_root, &mutated),
                    "mutated proof node {index} accepted at m={m} n={n}"
                );
            }
            if !proof.is_empty() {
                assert!(
                    !verify_consistency_proof(
                        m,
                        n,
                        &old_root,
                        &new_root,
                        &proof[..proof.len() - 1]
                    ),
                    "truncated proof accepted at m={m} n={n}"
                );
            }
            let mut extended = proof.clone();
            extended.push(Hash::zero());
            assert!(
                !verify_consistency_proof(m, n, &old_root, &new_root, &extended),
                "extended proof accepted at m={m} n={n}"
            );
        }
    }

    #[test]
    fn consistency_proof_size_edge_cases() {
        let leaf_hashes = test_leaf_hashes(9);
        let tree = MerkleTree::from_hashes(leaf_hashes.clone()).unwrap();
        let root = tree.root();

        assert!(tree.consistency_proof(0).is_err());
        assert!(tree.consistency_proof(10).is_err());

        let equal = tree.consistency_proof(9).unwrap();
        assert!(equal.is_empty());
        assert!(verify_consistency_proof(9, 9, &root, &root, &equal));
        assert!(!verify_consistency_proof(
            9,
            9,
            &root,
            &Hash::zero(),
            &equal
        ));
        assert!(!verify_consistency_proof(0, 9, &root, &root, &[]));
        assert!(!verify_consistency_proof(10, 9, &root, &root, &[]));

        let old_root = tree_hash_recursive(&leaf_hashes[..4]);
        assert!(!verify_consistency_proof(4, 9, &old_root, &root, &[]));
    }
}
