use std::collections::BTreeSet;

use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::error::ChioPackageError;
use crate::validation::{validate_sha256_hex, validate_trust_field};

pub const REVOCATION_CHECKPOINT_SCHEMA: &str = "chio.federation.revocation-checkpoint.v1";
pub const CHIO_FEDERATION_REVOCATION_CHECKPOINT_SCHEMA_V1: &str = REVOCATION_CHECKPOINT_SCHEMA;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPinnedRevocationEpoch {
    pub now_unix_ms: u64,
    pub epoch_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioRevocationCheckpoint {
    pub schema: String,
    pub checkpoint_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub epoch_height: u64,
    pub revoked_key_fingerprints: Vec<String>,
}

pub type SignedChioRevocationCheckpoint = SignedExportEnvelope<ChioRevocationCheckpoint>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChioRevocationMaterial {
    Historical(ChioPinnedRevocationEpoch),
    Checkpoint(Box<SignedChioRevocationCheckpoint>),
}

pub(crate) fn validate_revocation_checkpoint(
    checkpoint: &SignedChioRevocationCheckpoint,
) -> Result<(), ChioPackageError> {
    if checkpoint.body.schema != REVOCATION_CHECKPOINT_SCHEMA {
        return Err(ChioPackageError::TrustBundle(format!(
            "revocation checkpoint schema {} is unsupported",
            checkpoint.body.schema
        )));
    }
    validate_trust_field(
        &checkpoint.body.checkpoint_id,
        "revocationCheckpoint.checkpointId",
    )?;
    if checkpoint.body.expires_at_unix_ms <= checkpoint.body.issued_at_unix_ms {
        return Err(ChioPackageError::TrustBundle(
            "revocation checkpoint expiry must be greater than issue time".to_string(),
        ));
    }
    revoked_key_fingerprints(&checkpoint.body.revoked_key_fingerprints)?;
    if !checkpoint
        .verify_signature()
        .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?
    {
        return Err(ChioPackageError::TrustBundle(
            "revocation checkpoint signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn revoked_key_fingerprints(
    values: &[String],
) -> Result<BTreeSet<String>, ChioPackageError> {
    let mut fingerprints = BTreeSet::new();
    for fingerprint in values {
        validate_sha256_hex(fingerprint, "revocationCheckpoint.revokedKeyFingerprints")?;
        if !fingerprints.insert(fingerprint.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "duplicate revoked key fingerprint {fingerprint}"
            )));
        }
    }
    Ok(fingerprints)
}
