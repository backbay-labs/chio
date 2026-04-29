//! Pull support for caching Chio guard OCI artifacts by digest.

use crate::cache::{CachedGuardArtifact, GuardCache, GuardCacheArtifact};
use crate::oci::{
    GuardOciRef, GuardRegistryClient, GuardRegistryError, RegistryCredentials, Result,
};
use crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE;

/// Reserved cache slot for Sigstore bundle verification. Empty until the
/// verification path is wired; bundle verification fails closed rather than
/// passing with placeholder JSON.
pub const RESERVED_SIGSTORE_BUNDLE_JSON: &[u8] = b"";

/// Inputs for pulling a digest-pinned guard artifact into the local cache.
#[derive(Debug, Clone, Copy)]
pub struct GuardPullRequest<'a> {
    /// Digest-pinned OCI source reference.
    pub reference: &'a GuardOciRef,
    /// Registry credentials.
    pub credentials: &'a RegistryCredentials,
    /// Target content-addressed cache.
    pub cache: &'a GuardCache,
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

        let cached = request.cache.write_artifact(
            request.reference.digest(),
            GuardCacheArtifact {
                manifest_json: &manifest_json,
                config_json: &artifact.config,
                wit: &artifact.wit.data,
                module: &artifact.module.data,
                sigstore_bundle_json: RESERVED_SIGSTORE_BUNDLE_JSON,
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
