use chio_core::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::receipt_metadata::{MercuryContractError, MercuryWorkflowIdentifiers};
use crate::validation::ensure_non_empty;

pub const MERCURY_BUNDLE_MANIFEST_SCHEMA: &str = "chio.mercury.bundle_manifest.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryArtifactReference {
    pub artifact_id: String,
    pub artifact_type: String,
    pub sha256: String,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_class: Option<String>,
    #[serde(default)]
    pub legal_hold: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_policy: Option<String>,
}

impl MercuryArtifactReference {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("artifacts[].artifact_id", &self.artifact_id)?;
        ensure_non_empty("artifacts[].artifact_type", &self.artifact_type)?;
        ensure_non_empty("artifacts[].sha256", &self.sha256)?;
        ensure_non_empty("artifacts[].media_type", &self.media_type)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryBundleManifest {
    pub schema: String,
    pub bundle_id: String,
    pub created_at: u64,
    pub business_ids: MercuryWorkflowIdentifiers,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<MercuryArtifactReference>,
}

impl MercuryBundleManifest {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_BUNDLE_MANIFEST_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_BUNDLE_MANIFEST_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("bundle_id", &self.bundle_id)?;
        self.business_ids.validate()?;
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField("artifacts"));
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MercuryContractError> {
        self.validate()?;
        canonical_json_bytes(self).map_err(|error| MercuryContractError::Json(error.to_string()))
    }

    pub fn manifest_sha256(&self) -> Result<String, MercuryContractError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryBundleReference {
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub artifact_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_class: Option<String>,
}

impl MercuryBundleReference {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("bundle_refs[].bundle_id", &self.bundle_id)?;
        ensure_non_empty("bundle_refs[].manifest_sha256", &self.manifest_sha256)
    }

    pub fn from_manifest(manifest: &MercuryBundleManifest) -> Result<Self, MercuryContractError> {
        Ok(Self {
            bundle_id: manifest.bundle_id.clone(),
            manifest_sha256: manifest.manifest_sha256()?,
            artifact_count: manifest.artifacts.len() as u64,
            retention_class: manifest
                .artifacts
                .first()
                .and_then(|artifact| artifact.retention_class.clone()),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixtures::sample_mercury_bundle_manifest;

    #[test]
    fn bundle_manifest_hash_is_stable() {
        let manifest = sample_mercury_bundle_manifest();
        let first = manifest.manifest_sha256().expect("first hash");
        let second = manifest.manifest_sha256().expect("second hash");
        assert_eq!(first, second);
    }

    #[test]
    fn bundle_reference_uses_manifest_hash() {
        let manifest = sample_mercury_bundle_manifest();
        let reference = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        assert_eq!(reference.bundle_id, manifest.bundle_id);
        assert_eq!(reference.artifact_count, manifest.artifacts.len() as u64);
    }

    #[test]
    fn bundle_manifest_rejects_padded_bundle_id() {
        let mut manifest = sample_mercury_bundle_manifest();
        manifest.bundle_id = " bundle-release-2026-04-02 ".to_string();

        let error = manifest.validate().expect_err("padded bundle id");

        assert!(matches!(
            error,
            MercuryContractError::PaddedField("bundle_id")
        ));
    }
}
