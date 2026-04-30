use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{EpochRoot, Result, RevocationOracleError, RootSignature};

pub trait EpochRootSigner {
    fn signer_id(&self) -> &str;
    fn sign_epoch_root(&self, root: &EpochRoot) -> Result<RootSignature>;
    fn verify_epoch_root(&self, root: &EpochRoot, signature: &RootSignature) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct DigestRootSigner {
    signer_id: String,
    secret: Vec<u8>,
}

impl DigestRootSigner {
    #[must_use]
    pub fn new(signer_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            signer_id: signer_id.into(),
            secret: secret.into(),
        }
    }

    fn digest(&self, root: &EpochRoot) -> Result<Vec<u8>> {
        let payload = canonicalish_bytes(root)?;
        let mut hasher = Sha256::new();
        hasher.update(b"chio-revocation-oracle:v1:epoch-root");
        hasher.update(&self.secret);
        hasher.update(payload);
        Ok(hasher.finalize().to_vec())
    }
}

impl EpochRootSigner for DigestRootSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn sign_epoch_root(&self, root: &EpochRoot) -> Result<RootSignature> {
        Ok(RootSignature {
            signer_id: self.signer_id.clone(),
            algorithm: "digest-stub-sha256".to_string(),
            signature_bytes: self.digest(root)?,
        })
    }

    fn verify_epoch_root(&self, root: &EpochRoot, signature: &RootSignature) -> Result<()> {
        if signature.signer_id != self.signer_id || signature.algorithm != "digest-stub-sha256" {
            return Err(RevocationOracleError::SignatureVerificationFailed);
        }
        let expected = self.digest(root)?;
        if expected == signature.signature_bytes {
            Ok(())
        } else {
            Err(RevocationOracleError::SignatureVerificationFailed)
        }
    }
}

fn canonicalish_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| RevocationOracleError::Serialization(err.to_string()))
}
