use chio_core_types::hashing::Hash;
use chio_core_types::merkle::{leaf_hash, MerkleTree};
use chio_core_types::merkle_steps::{inclusion_step, InclusionStep};

fn leaves(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| format!("leaf-{index}").into_bytes())
        .collect()
}

#[test]
fn inclusion_steps_cover_left_right_and_carry() {
    assert_eq!(
        inclusion_step(0, 2),
        InclusionStep {
            consume_sibling: true,
            sibling_on_left: false,
            next_index: 0,
            next_size: 1,
        }
    );
    assert_eq!(
        inclusion_step(1, 2),
        InclusionStep {
            consume_sibling: true,
            sibling_on_left: true,
            next_index: 0,
            next_size: 1,
        }
    );
    assert_eq!(
        inclusion_step(2, 3),
        InclusionStep {
            consume_sibling: false,
            sibling_on_left: false,
            next_index: 1,
            next_size: 2,
        }
    );
    assert_eq!(
        inclusion_step(u64::MAX, u64::MAX),
        InclusionStep {
            consume_sibling: true,
            sibling_on_left: true,
            next_index: u64::MAX / 2,
            next_size: u64::MAX / 2 + 1,
        }
    );
}

#[test]
fn production_walk_roundtrips_required_tree_geometries() -> Result<(), chio_core_types::Error> {
    for tree_size in 1..=8 {
        let leaves = leaves(tree_size);
        let tree = MerkleTree::from_leaves(&leaves)?;
        for (leaf_index, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(leaf_index)?;
            assert!(
                proof.verify(leaf, &tree.root()),
                "tree_size={tree_size} leaf_index={leaf_index}"
            );
        }
    }
    Ok(())
}

#[test]
fn production_walk_rejects_misordered_odd_index_path() -> Result<(), chio_core_types::Error> {
    let leaves = leaves(8);
    let tree = MerkleTree::from_leaves(&leaves)?;
    let mut proof = tree.inclusion_proof(3)?;
    proof.audit_path.swap(0, 1);

    assert!(!proof.verify(&leaves[3], &tree.root()));
    Ok(())
}

#[test]
fn production_walk_rejects_truncated_and_padded_paths() -> Result<(), chio_core_types::Error> {
    let leaves = leaves(5);
    let tree = MerkleTree::from_leaves(&leaves)?;
    let proof = tree.inclusion_proof(3)?;

    let mut truncated = proof.clone();
    truncated.audit_path.pop();
    assert!(!truncated.verify(&leaves[3], &tree.root()));

    let mut padded = proof;
    padded.audit_path.push(Hash::zero());
    assert!(!padded.verify(&leaves[3], &tree.root()));
    Ok(())
}

#[test]
fn production_walk_rejects_invalid_geometry_before_hashing() {
    let leaf = leaf_hash(b"leaf");
    let proof = chio_core_types::merkle::MerkleProof {
        tree_size: 0,
        leaf_index: 0,
        audit_path: Vec::new(),
    };
    assert!(proof.compute_root_from_hash(leaf).is_err());

    let proof = chio_core_types::merkle::MerkleProof {
        tree_size: 2,
        leaf_index: 2,
        audit_path: Vec::new(),
    };
    assert!(proof.compute_root_from_hash(leaf).is_err());
}
