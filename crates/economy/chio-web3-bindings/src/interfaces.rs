//! Artifact-derived Alloy bindings for the official Chio web3 contract family.

use alloy::primitives::{B256, U256};

pub(crate) mod root_registry_bindings {
    use alloy::sol;

    sol!(
        IChioRootRegistry,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/artifacts/interfaces/IChioRootRegistry.json"
        )
    );
}

pub(crate) mod identity_registry_bindings {
    use alloy::sol;

    sol!(
        IChioIdentityRegistry,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/artifacts/interfaces/IChioIdentityRegistry.json"
        )
    );
}

pub(crate) mod escrow_bindings {
    use alloy::sol;

    sol!(
        IChioEscrow,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/artifacts/interfaces/IChioEscrow.json"
        )
    );
}

pub(crate) mod bond_vault_bindings {
    use alloy::sol;

    sol!(
        IChioBondVault,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/artifacts/interfaces/IChioBondVault.json"
        )
    );
}

pub(crate) mod price_resolver_bindings {
    use alloy::sol;

    sol!(
        IChioPriceResolver,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/artifacts/interfaces/IChioPriceResolver.json"
        )
    );
}

pub use bond_vault_bindings::IChioBondVault;
pub use escrow_bindings::IChioEscrow;
pub use identity_registry_bindings::IChioIdentityRegistry;
pub use price_resolver_bindings::IChioPriceResolver;
pub use root_registry_bindings::IChioRootRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChioMerkleProof {
    pub audit_path: Vec<B256>,
    pub leaf_index: U256,
    pub tree_size: U256,
}

impl From<&ChioMerkleProof> for root_registry_bindings::ChioMerkle::Proof {
    fn from(proof: &ChioMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ChioMerkleProof> for root_registry_bindings::ChioMerkle::Proof {
    fn from(proof: ChioMerkleProof) -> Self {
        Self::from(&proof)
    }
}

impl From<&ChioMerkleProof> for escrow_bindings::ChioMerkle::Proof {
    fn from(proof: &ChioMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ChioMerkleProof> for escrow_bindings::ChioMerkle::Proof {
    fn from(proof: ChioMerkleProof) -> Self {
        Self::from(&proof)
    }
}

impl From<&ChioMerkleProof> for bond_vault_bindings::ChioMerkle::Proof {
    fn from(proof: &ChioMerkleProof) -> Self {
        Self {
            auditPath: proof.audit_path.clone(),
            leafIndex: proof.leaf_index,
            treeSize: proof.tree_size,
        }
    }
}

impl From<ChioMerkleProof> for bond_vault_bindings::ChioMerkle::Proof {
    fn from(proof: ChioMerkleProof) -> Self {
        Self::from(&proof)
    }
}
