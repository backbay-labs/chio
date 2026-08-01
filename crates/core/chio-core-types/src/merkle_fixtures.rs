use alloc::vec;

use crate::hashing::Hash;
use crate::merkle::{node_hash, MerkleProof};

#[must_use]
pub fn bounded_merkle_case(
    tree_size: usize,
    leaf_index: usize,
) -> Option<(Hash, Hash, MerkleProof)> {
    let leaf_0 = Hash::from_bytes([1; 32]);
    let leaf_1 = Hash::from_bytes([2; 32]);
    let leaf_2 = Hash::from_bytes([3; 32]);
    let leaf_3 = Hash::from_bytes([4; 32]);
    let leaf_4 = Hash::from_bytes([5; 32]);
    let leaf_5 = Hash::from_bytes([6; 32]);
    let leaf_6 = Hash::from_bytes([7; 32]);
    let leaf_7 = Hash::from_bytes([8; 32]);

    let node_01 = node_hash(&leaf_0, &leaf_1);
    let node_23 = node_hash(&leaf_2, &leaf_3);
    let node_45 = node_hash(&leaf_4, &leaf_5);
    let node_67 = node_hash(&leaf_6, &leaf_7);
    let node_03 = node_hash(&node_01, &node_23);
    let node_47 = node_hash(&node_45, &node_67);
    let node_46 = node_hash(&node_45, &leaf_6);

    let leaf = match leaf_index {
        0 => leaf_0,
        1 => leaf_1,
        2 => leaf_2,
        3 => leaf_3,
        4 => leaf_4,
        5 => leaf_5,
        6 => leaf_6,
        7 => leaf_7,
        _ => return None,
    };
    let expected_root = match tree_size {
        1 => leaf_0,
        2 => node_01,
        3 => node_hash(&node_01, &leaf_2),
        4 => node_03,
        5 => node_hash(&node_03, &leaf_4),
        6 => node_hash(&node_03, &node_45),
        7 => node_hash(&node_03, &node_46),
        8 => node_hash(&node_03, &node_47),
        _ => return None,
    };
    let audit_path = match (tree_size, leaf_index) {
        (1, 0) => vec![],
        (2, 0) => vec![leaf_1],
        (2, 1) => vec![leaf_0],
        (3, 0) => vec![leaf_1, leaf_2],
        (3, 1) => vec![leaf_0, leaf_2],
        (3, 2) => vec![node_01],
        (4, 0) => vec![leaf_1, node_23],
        (4, 1) => vec![leaf_0, node_23],
        (4, 2) => vec![leaf_3, node_01],
        (4, 3) => vec![leaf_2, node_01],
        (5, 0) => vec![leaf_1, node_23, leaf_4],
        (5, 1) => vec![leaf_0, node_23, leaf_4],
        (5, 2) => vec![leaf_3, node_01, leaf_4],
        (5, 3) => vec![leaf_2, node_01, leaf_4],
        (5, 4) => vec![node_03],
        (6, 0) => vec![leaf_1, node_23, node_45],
        (6, 1) => vec![leaf_0, node_23, node_45],
        (6, 2) => vec![leaf_3, node_01, node_45],
        (6, 3) => vec![leaf_2, node_01, node_45],
        (6, 4) => vec![leaf_5, node_03],
        (6, 5) => vec![leaf_4, node_03],
        (7, 0) => vec![leaf_1, node_23, node_46],
        (7, 1) => vec![leaf_0, node_23, node_46],
        (7, 2) => vec![leaf_3, node_01, node_46],
        (7, 3) => vec![leaf_2, node_01, node_46],
        (7, 4) => vec![leaf_5, leaf_6, node_03],
        (7, 5) => vec![leaf_4, leaf_6, node_03],
        (7, 6) => vec![node_45, node_03],
        (8, 0) => vec![leaf_1, node_23, node_47],
        (8, 1) => vec![leaf_0, node_23, node_47],
        (8, 2) => vec![leaf_3, node_01, node_47],
        (8, 3) => vec![leaf_2, node_01, node_47],
        (8, 4) => vec![leaf_5, node_67, node_03],
        (8, 5) => vec![leaf_4, node_67, node_03],
        (8, 6) => vec![leaf_7, node_45, node_03],
        (8, 7) => vec![leaf_6, node_45, node_03],
        _ => return None,
    };

    Some((
        leaf,
        expected_root,
        MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        },
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::error::{Error, Result};
    use crate::merkle::MerkleTree;

    #[test]
    fn bounded_fixtures_match_real_tree_builder() -> Result<()> {
        let leaves: Vec<Hash> = (1u8..=8).map(|byte| Hash::from_bytes([byte; 32])).collect();

        for tree_size in 1usize..=8 {
            let tree = MerkleTree::from_hashes(leaves[..tree_size].to_vec())?;
            for (leaf_index, expected_leaf) in leaves.iter().take(tree_size).enumerate() {
                let (leaf, expected_root, proof) =
                    bounded_merkle_case(tree_size, leaf_index).ok_or(Error::MerkleProofFailed)?;
                let built_proof = tree.inclusion_proof(leaf_index)?;

                assert_eq!(&leaf, expected_leaf);
                assert_eq!(expected_root, tree.root());
                assert_eq!(proof, built_proof);
            }
        }

        Ok(())
    }
}
