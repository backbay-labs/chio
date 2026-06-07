//! Pull support for caching Chio guard OCI artifacts by digest.

use crate::cache::{CachedGuardArtifact, GuardCache, GuardCacheArtifact};
use crate::oci::{
    GuardArtifactLayer, GuardOciRef, GuardRegistryClient, GuardRegistryError, PulledGuardArtifact,
    RegistryCredentials, Result, GUARD_CONFIG_MEDIA_TYPE, GUARD_MANIFEST_LAYER_MEDIA_TYPE,
    GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_MEDIA_TYPE,
};
use crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use sha2::{Digest, Sha256};

/// Inputs for pulling a digest-pinned guard artifact into the local cache.
#[derive(Debug, Clone, Copy)]
pub struct GuardPullRequest<'a> {
    /// Digest-pinned OCI source reference.
    pub reference: &'a GuardOciRef,
    /// Registry credentials.
    pub credentials: &'a RegistryCredentials,
    /// Target content-addressed cache.
    pub cache: &'a GuardCache,
    /// Optional caller-supplied Sigstore bundle bytes to cache alongside the
    /// pulled artifact. The pull path does not discover OCI referrers.
    pub sigstore_bundle_json: Option<&'a [u8]>,
}

/// Result of pulling a guard artifact into the local cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardPullResponse {
    /// Cache entry written to disk.
    pub cached: CachedGuardArtifact,
    /// Registry-reported manifest digest.
    pub registry_manifest_digest: String,
}

impl GuardRegistryClient {
    /// Pull a digest-pinned guard artifact, validate its shape, and write it to cache.
    pub async fn pull_guard_to_cache(
        &self,
        request: GuardPullRequest<'_>,
    ) -> Result<GuardPullResponse> {
        let (manifest_json, manifest_digest) = self
            .client
            .pull_manifest_raw(
                request.reference.as_oci_reference(),
                &request.credentials.to_registry_auth(),
                &[GUARD_OCI_MANIFEST_MEDIA_TYPE],
            )
            .await?;
        ensure_manifest_digest_matches(request.reference, &manifest_digest)?;

        let artifact = self
            .pull_guard_artifact(request.reference, request.credentials)
            .await?;
        if let Some(registry_manifest_digest) = artifact.registry_manifest_digest.as_deref() {
            ensure_manifest_digest_matches(request.reference, registry_manifest_digest)?;
        }
        ensure_artifact_matches_manifest_descriptors(&manifest_json, &artifact)?;

        let cached = request.cache.write_artifact(
            request.reference.digest(),
            GuardCacheArtifact {
                manifest_json: &manifest_json,
                config_json: &artifact.config,
                wit: &artifact.wit.data,
                module: &artifact.module.data,
                sigstore_bundle_json: request.sigstore_bundle_json,
            },
        )?;

        Ok(GuardPullResponse {
            cached,
            registry_manifest_digest: manifest_digest,
        })
    }
}

fn ensure_manifest_digest_matches(reference: &GuardOciRef, actual: &str) -> Result<()> {
    let expected = reference.digest().as_str();
    if actual != expected {
        return Err(GuardRegistryError::ManifestDigestMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }

    Ok(())
}

fn ensure_artifact_matches_manifest_descriptors(
    manifest_json: &[u8],
    artifact: &PulledGuardArtifact,
) -> Result<()> {
    let manifest = serde_json::from_slice::<OciImageManifest>(manifest_json).map_err(|err| {
        GuardRegistryError::VerifyFailedClosed {
            message: format!("failed to parse pulled OCI manifest JSON: {err}"),
        }
    })?;
    validate_descriptor(
        "config.json",
        &manifest.config,
        GUARD_CONFIG_MEDIA_TYPE,
        &artifact.config,
    )?;
    if manifest.layers.len() != 3 {
        return Err(GuardRegistryError::LayerCount {
            actual: manifest.layers.len(),
        });
    }
    validate_layer_descriptor(
        "wit.bin",
        &manifest.layers[0],
        GUARD_WIT_LAYER_MEDIA_TYPE,
        &artifact.wit,
    )?;
    validate_layer_descriptor(
        "module.wasm",
        &manifest.layers[1],
        GUARD_MODULE_LAYER_MEDIA_TYPE,
        &artifact.module,
    )?;
    validate_layer_descriptor(
        "guard manifest",
        &manifest.layers[2],
        GUARD_MANIFEST_LAYER_MEDIA_TYPE,
        &artifact.manifest,
    )?;
    Ok(())
}

fn validate_layer_descriptor(
    artifact_name: &'static str,
    descriptor: &OciDescriptor,
    expected_media_type: &'static str,
    layer: &GuardArtifactLayer,
) -> Result<()> {
    if layer.media_type != expected_media_type {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: artifact_name,
            expected: expected_media_type,
            actual: layer.media_type.clone(),
        });
    }
    validate_descriptor(artifact_name, descriptor, expected_media_type, &layer.data)
}

fn validate_descriptor(
    artifact_name: &'static str,
    descriptor: &OciDescriptor,
    expected_media_type: &'static str,
    bytes: &[u8],
) -> Result<()> {
    if descriptor.media_type != expected_media_type {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: artifact_name,
            expected: expected_media_type,
            actual: descriptor.media_type.clone(),
        });
    }
    let actual_digest = format!("sha256:{:x}", Sha256::digest(bytes));
    if descriptor.digest != actual_digest {
        return Err(GuardRegistryError::DescriptorDigestMismatch {
            artifact: artifact_name,
            expected: descriptor.digest.clone(),
            actual: actual_digest,
        });
    }
    let actual_size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    if descriptor.size != actual_size {
        return Err(GuardRegistryError::DescriptorSizeMismatch {
            artifact: artifact_name,
            expected: descriptor.size,
            actual: actual_size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{GUARD_MANIFEST_LAYER_ROLE, GUARD_MODULE_LAYER_ROLE, GUARD_WIT_LAYER_ROLE};
    use oci_distribution::client::{Config, ImageLayer};

    #[test]
    fn descriptor_binding_accepts_matching_pulled_blobs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (manifest_json, artifact) = descriptor_fixture(false)?;

        ensure_artifact_matches_manifest_descriptors(&manifest_json, &artifact)?;
        Ok(())
    }

    #[test]
    fn descriptor_binding_rejects_tampered_pulled_layer_bytes(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (manifest_json, artifact) = descriptor_fixture(true)?;

        match ensure_artifact_matches_manifest_descriptors(&manifest_json, &artifact) {
            Err(GuardRegistryError::DescriptorDigestMismatch {
                artifact: "wit.bin",
                ..
            }) => Ok(()),
            Ok(()) => panic!("tampered WIT bytes must not enter cache"),
            Err(err) => panic!("expected WIT descriptor digest mismatch, got {err}"),
        }
    }

    fn descriptor_fixture(
        tamper_wit: bool,
    ) -> std::result::Result<(Vec<u8>, PulledGuardArtifact), Box<dyn std::error::Error>> {
        let config_bytes = br#"{"wit_world":"chio:guard/guard@0.2.0"}"#.to_vec();
        let wit_bytes = b"package chio:guard@0.2.0;".to_vec();
        let module_bytes = b"\0asm\x01\0\0\0".to_vec();
        let guard_manifest_bytes = br#"{"name":"fixture"}"#.to_vec();
        let config = Config::new(
            config_bytes.clone(),
            GUARD_CONFIG_MEDIA_TYPE.to_owned(),
            None,
        );
        let layers = vec![
            ImageLayer::new(
                wit_bytes.clone(),
                GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(),
                None,
            ),
            ImageLayer::new(
                module_bytes.clone(),
                GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(),
                None,
            ),
            ImageLayer::new(
                guard_manifest_bytes.clone(),
                GUARD_MANIFEST_LAYER_MEDIA_TYPE.to_owned(),
                None,
            ),
        ];
        let manifest = OciImageManifest::build(&layers, &config, None);
        let manifest_json = serde_json::to_vec(&manifest)?;
        let reference = "oci://ghcr.io/chio/tool-gate@sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .parse::<GuardOciRef>()?;
        let pulled_wit = if tamper_wit {
            b"tampered wit".to_vec()
        } else {
            wit_bytes
        };
        let artifact = PulledGuardArtifact {
            reference,
            config: config_bytes,
            wit: GuardArtifactLayer {
                data: pulled_wit,
                media_type: GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(),
                role: GUARD_WIT_LAYER_ROLE,
            },
            module: GuardArtifactLayer {
                data: module_bytes,
                media_type: GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(),
                role: GUARD_MODULE_LAYER_ROLE,
            },
            manifest: GuardArtifactLayer {
                data: guard_manifest_bytes,
                media_type: GUARD_MANIFEST_LAYER_MEDIA_TYPE.to_owned(),
                role: GUARD_MANIFEST_LAYER_ROLE,
            },
            registry_manifest_digest: None,
        };
        Ok((manifest_json, artifact))
    }
}
