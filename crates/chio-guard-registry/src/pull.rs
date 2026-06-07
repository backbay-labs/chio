//! Pull support for caching Chio guard OCI artifacts by digest.

use crate::cache::{CachedGuardArtifact, GuardCache, GuardCacheArtifact};
use crate::oci::{
    GuardOciRef, GuardRegistryClient, GuardRegistryError, RegistryCredentials, Result,
};
use crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE;
use crate::{AttestVerifier, ExpectedIdentity, GuardSigstoreVerifier};

/// Source of Sigstore bundle bytes cached during guard pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardPullSigstoreBundleSource {
    /// Bundle was supplied directly by the caller.
    CallerProvided,
    /// Bundle was discovered and pulled from OCI referrers.
    OciReferrer,
}

/// Inputs for pulling a digest-pinned guard artifact into the local cache.
pub struct GuardPullRequest<'a> {
    /// Digest-pinned OCI source reference.
    pub reference: &'a GuardOciRef,
    /// Registry credentials.
    pub credentials: &'a RegistryCredentials,
    /// Target content-addressed cache.
    pub cache: &'a GuardCache,
    /// Optional caller-supplied Sigstore bundle bytes. When absent, pull
    /// attempts OCI referrer discovery for a Sigstore bundle attachment.
    pub sigstore_bundle_json: Option<&'a [u8]>,
    /// Optional Sigstore verifier used to verify bundle/artifact binding
    /// before cache admission.
    pub sigstore_verifier: Option<&'a dyn AttestVerifier>,
    /// Expected identity policy paired with `sigstore_verifier`.
    pub sigstore_expected_identity: Option<&'a ExpectedIdentity>,
}

/// Result of pulling a guard artifact into the local cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardPullResponse {
    /// Cache entry written to disk.
    pub cached: CachedGuardArtifact,
    /// Registry-reported manifest digest.
    pub registry_manifest_digest: String,
    /// Source of cached Sigstore bundle bytes, if present.
    pub sigstore_bundle_source: Option<GuardPullSigstoreBundleSource>,
    /// Whether Sigstore bundle bytes were verified before cache admission.
    pub sigstore_verified: bool,
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
        let (sigstore_bundle_owned, sigstore_bundle_source) =
            self.sigstore_bundle_for_pull(&request).await?;
        let sigstore_bundle_json = request
            .sigstore_bundle_json
            .or(sigstore_bundle_owned.as_deref());
        let sigstore_verified = verify_sigstore_bundle_before_cache(
            &request,
            &artifact.module.data,
            sigstore_bundle_json,
        )?;

        let cached = request.cache.write_artifact(
            request.reference.digest(),
            GuardCacheArtifact {
                manifest_json: &manifest_json,
                config_json: &artifact.config,
                wit: &artifact.wit.data,
                module: &artifact.module.data,
                guard_manifest_json: &artifact.manifest.data,
                sigstore_bundle_json,
            },
        )?;

        Ok(GuardPullResponse {
            cached,
            registry_manifest_digest: manifest_digest,
            sigstore_bundle_source,
            sigstore_verified,
        })
    }

    async fn sigstore_bundle_for_pull<'a>(
        &self,
        request: &GuardPullRequest<'a>,
    ) -> Result<(Option<Vec<u8>>, Option<GuardPullSigstoreBundleSource>)> {
        if request.sigstore_bundle_json.is_some() {
            return Ok((None, Some(GuardPullSigstoreBundleSource::CallerProvided)));
        }
        let Some(bundle) = self
            .pull_sigstore_bundle_referrer(request.reference, request.credentials)
            .await?
        else {
            return Ok((None, None));
        };
        Ok((
            Some(bundle),
            Some(GuardPullSigstoreBundleSource::OciReferrer),
        ))
    }
}

fn verify_sigstore_bundle_before_cache(
    request: &GuardPullRequest<'_>,
    module: &[u8],
    sigstore_bundle_json: Option<&[u8]>,
) -> Result<bool> {
    match (
        request.sigstore_verifier,
        request.sigstore_expected_identity,
    ) {
        (None, None) => Ok(false),
        (Some(_), None) | (None, Some(_)) => Err(GuardRegistryError::InvalidClientConfig(
            "Sigstore cache-admission verification requires both verifier and expected identity",
        )),
        (Some(verifier), Some(expected)) => {
            let Some(bundle) = sigstore_bundle_json else {
                return Err(GuardRegistryError::SigstoreBundleNotFound);
            };
            GuardSigstoreVerifier::new(verifier, expected).verify_bundle(module, bundle)?;
            Ok(true)
        }
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{AttestError, GuardCache, VerifiedAttestation};

    #[test]
    fn sigstore_policy_denies_when_no_bundle_was_found() {
        let reference = reference();
        let cache = GuardCache::new("unused-cache-root");
        let credentials = RegistryCredentials::Anonymous;
        let verifier = CountingVerifier {
            bundle_calls: AtomicUsize::new(0),
        };
        let expected = ExpectedIdentity::doc_hidden_inline(
            "https://github\\.com/backbay-labs/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v.*",
            "https://token.actions.githubusercontent.com",
        );
        let request = GuardPullRequest {
            reference: &reference,
            credentials: &credentials,
            cache: &cache,
            sigstore_bundle_json: None,
            sigstore_verifier: Some(&verifier),
            sigstore_expected_identity: Some(&expected),
        };

        let err = match verify_sigstore_bundle_before_cache(&request, b"module", None) {
            Ok(_) => panic!("Sigstore policy without any bundle source must deny"),
            Err(error) => error,
        };

        assert!(matches!(err, GuardRegistryError::SigstoreBundleNotFound));
        assert_eq!(verifier.bundle_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pull_without_sigstore_policy_does_not_claim_verification() {
        let reference = reference();
        let cache = GuardCache::new("unused-cache-root");
        let credentials = RegistryCredentials::Anonymous;
        let request = GuardPullRequest {
            reference: &reference,
            credentials: &credentials,
            cache: &cache,
            sigstore_bundle_json: None,
            sigstore_verifier: None,
            sigstore_expected_identity: None,
        };

        let verified = match verify_sigstore_bundle_before_cache(&request, b"module", None) {
            Ok(verified) => verified,
            Err(error) => panic!("policy-free pull should not require Sigstore bundle: {error}"),
        };

        assert!(!verified);
    }

    struct CountingVerifier {
        bundle_calls: AtomicUsize,
    }

    impl AttestVerifier for CountingVerifier {
        fn verify_blob(
            &self,
            _artifact: &Path,
            _signature: &Path,
            _certificate: &Path,
            _expected: &ExpectedIdentity,
        ) -> std::result::Result<VerifiedAttestation, AttestError> {
            Err(AttestError::Malformed("verify_blob unused".to_owned()))
        }

        fn verify_bytes(
            &self,
            _artifact: &[u8],
            _signature: &[u8],
            _certificate_pem: &[u8],
            _expected: &ExpectedIdentity,
        ) -> std::result::Result<VerifiedAttestation, AttestError> {
            Err(AttestError::Malformed("verify_bytes unused".to_owned()))
        }

        fn verify_bundle(
            &self,
            _artifact: &[u8],
            _bundle_json: &[u8],
            _expected: &ExpectedIdentity,
        ) -> std::result::Result<VerifiedAttestation, AttestError> {
            self.bundle_calls.fetch_add(1, Ordering::SeqCst);
            Err(AttestError::Malformed(
                "verify_bundle should not run".to_owned(),
            ))
        }
    }

    fn reference() -> GuardOciRef {
        match "oci://ghcr.io/chio/guard@sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
        {
            Ok(reference) => reference,
            Err(error) => panic!("fixture reference should parse: {error}"),
        }
    }
}
