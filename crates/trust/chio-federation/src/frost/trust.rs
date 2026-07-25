use std::collections::BTreeMap;

use chio_core_types::{PublicKey, Signature, SigningAlgorithm};

use super::roster::{FrostEpochCheckpointV1, FrostRosterError, FrostRosterV1};
use super::types::validate_identifier;
use super::verify::{FrostAuthorizationSlotCheckpointV1, FrostVerificationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FrostArtifactAuthorityRole {
    Roster,
    EpochAnchor,
    AuthorizationSlotAnchor,
}

#[derive(Debug, Clone)]
pub struct FrostArtifactTrustRoot {
    pub role: FrostArtifactAuthorityRole,
    pub key_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, thiserror::Error)]
pub enum FrostArtifactTrustError {
    #[error("invalid FROST artifact trust root: {0}")]
    InvalidRoot(&'static str),
    #[error("duplicate FROST artifact trust root for {role:?} key {key_id:?}")]
    DuplicateRoot {
        role: FrostArtifactAuthorityRole,
        key_id: String,
    },
    #[error("untrusted FROST {role:?} key {key_id:?}")]
    UntrustedKey {
        role: FrostArtifactAuthorityRole,
        key_id: String,
    },
    #[error("invalid FROST {0:?} artifact signature")]
    InvalidSignature(FrostArtifactAuthorityRole),
    #[error(transparent)]
    Roster(#[from] FrostRosterError),
    #[error(transparent)]
    AuthorizationSlot(#[from] FrostVerificationError),
}

#[derive(Debug, Clone)]
pub struct FrostArtifactTrustStore {
    roots: BTreeMap<(FrostArtifactAuthorityRole, String), PublicKey>,
}

impl FrostArtifactTrustStore {
    pub fn new(
        roots: impl IntoIterator<Item = FrostArtifactTrustRoot>,
    ) -> Result<Self, FrostArtifactTrustError> {
        let mut trusted = BTreeMap::new();
        let mut trusted_material = BTreeMap::new();
        for root in roots {
            validate_identifier(&root.key_id, "key_id")
                .map_err(|_| FrostArtifactTrustError::InvalidRoot("invalid key id"))?;
            if root.public_key.algorithm() != SigningAlgorithm::Ed25519 {
                return Err(FrostArtifactTrustError::InvalidRoot(
                    "artifact authority keys must use Ed25519",
                ));
            }
            let lookup = (root.role, root.key_id.clone());
            let material = root.public_key.to_hex();
            if trusted_material
                .insert(material, (root.role, root.key_id.clone()))
                .is_some()
            {
                return Err(FrostArtifactTrustError::InvalidRoot(
                    "authority public keys must not be reused",
                ));
            }
            if trusted.insert(lookup, root.public_key).is_some() {
                return Err(FrostArtifactTrustError::DuplicateRoot {
                    role: root.role,
                    key_id: root.key_id,
                });
            }
        }
        if trusted.is_empty() {
            return Err(FrostArtifactTrustError::InvalidRoot(
                "at least one trust root is required",
            ));
        }
        Ok(Self { roots: trusted })
    }

    pub fn verify_roster(&self, roster: &FrostRosterV1) -> Result<(), FrostArtifactTrustError> {
        roster.validate()?;
        self.verify(
            FrostArtifactAuthorityRole::Roster,
            &roster.roster_authority_key_id,
            &roster.signing_bytes()?,
            &roster.roster_authority_signature,
        )
    }

    pub fn verify_epoch_checkpoint(
        &self,
        checkpoint: &FrostEpochCheckpointV1,
    ) -> Result<(), FrostArtifactTrustError> {
        checkpoint.validate()?;
        self.verify(
            FrostArtifactAuthorityRole::EpochAnchor,
            &checkpoint.anchor_key_id,
            &checkpoint.signing_bytes()?,
            &checkpoint.anchor_signature,
        )
    }

    pub fn verify_authorization_slot_checkpoint(
        &self,
        checkpoint: &FrostAuthorizationSlotCheckpointV1,
    ) -> Result<(), FrostArtifactTrustError> {
        checkpoint.validate()?;
        self.verify(
            FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
            &checkpoint.anchor_key_id,
            &checkpoint.signing_bytes()?,
            &checkpoint.anchor_signature,
        )
    }

    fn verify(
        &self,
        role: FrostArtifactAuthorityRole,
        key_id: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<(), FrostArtifactTrustError> {
        let key = self.roots.get(&(role, key_id.to_string())).ok_or_else(|| {
            FrostArtifactTrustError::UntrustedKey {
                role,
                key_id: key_id.to_string(),
            }
        })?;
        let signature = Signature::from_hex(signature)
            .map_err(|_| FrostArtifactTrustError::InvalidSignature(role))?;
        if !key.verify(message, &signature) {
            return Err(FrostArtifactTrustError::InvalidSignature(role));
        }
        Ok(())
    }
}
