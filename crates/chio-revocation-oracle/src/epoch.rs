use serde::{Deserialize, Serialize};

use crate::{signer::EpochRootSigner, EpochRoot, Result, RootSignature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEpochRoot {
    pub root: EpochRoot,
    pub signature: RootSignature,
}

impl SignedEpochRoot {
    pub fn sign(root: EpochRoot, signer: &impl EpochRootSigner) -> Result<Self> {
        let signature = signer.sign_epoch_root(&root)?;
        Ok(Self { root, signature })
    }

    pub fn verify(&self, signer: &impl EpochRootSigner) -> Result<()> {
        signer.verify_epoch_root(&self.root, &self.signature)
    }
}
