use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use sigstore::bundle::verify::Verifier as AsyncBundleVerifier;
use sigstore::bundle::Bundle;
use sigstore::crypto::CosignVerificationKey;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::{AttestError, AttestVerifier, ExpectedIdentity, VerifiedAttestation};

use super::bundle_verify::{
    bundle_leaf_certificate_der, bundle_rekor_inclusion_verified, bundle_rekor_metadata,
    map_bundle_verification_error, run_async_bundle_verify,
};
use super::identity::match_identity;
use super::parse::parse_certificate_to_der;
use super::policy::IssuerOnlyPolicy;
use super::validators::{
    certificate_validity, is_within_validity_window, validate_against_fulcio,
    verify_signature_bytes,
};
use super::EMBEDDED_TRUSTED_ROOT_JSON;

/// Production [`AttestVerifier`] implementation. Built once via
/// [`SigstoreVerifier::with_embedded_root`] and shared (e.g. in an `Arc`)
/// across the kernel's tokio runtime; the type is [`Send`] + [`Sync`].
pub struct SigstoreVerifier {
    /// Pre-built collection of trusted Fulcio root certificates, used by
    /// the raw `verify_blob` / `verify_bytes` paths to chain-validate the
    /// supplied leaf certificate via [`webpki`]. Held as owned bytes so
    /// `TrustAnchor` borrows can be reconstructed per call.
    fulcio_root_ders: Arc<Vec<Vec<u8>>>,
    /// Dedicated single-thread tokio runtime for driving the async
    /// `sigstore-rs` bundle verifier from a synchronous trait method.
    runtime: tokio::runtime::Runtime,
}

impl SigstoreVerifier {
    /// Construct a verifier backed by the embedded Sigstore Public Good
    /// Instance trust root. The TUF root is shipped in-tree under
    /// `sigstore-root/trusted_root.json` and validated at build time by
    /// `build.rs`. This constructor never panics on a well-formed
    /// embedded root; a corrupted root surfaces as
    /// [`AttestError::TrustRoot`].
    pub fn with_embedded_root() -> Result<Self, AttestError> {
        let trust_root = build_trust_root()?;

        let fulcio_root_ders: Vec<Vec<u8>> = trust_root
            .fulcio_certs()
            .map_err(|_| AttestError::TrustRoot)?
            .into_iter()
            .map(|der| der.as_ref().to_vec())
            .collect();

        if fulcio_root_ders.is_empty() {
            return Err(AttestError::TrustRoot);
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(AttestError::Io)?;

        Ok(Self {
            fulcio_root_ders: Arc::new(fulcio_root_ders),
            runtime,
        })
    }

    /// Internal helper that builds an [`AsyncBundleVerifier`] from a
    /// freshly-parsed copy of the embedded trust root. A new verifier is
    /// constructed per call so that the bundle verifier's internal state
    /// never leaks between concurrent `verify_*` invocations. The
    /// per-call parse cost is negligible compared with the network and
    /// crypto work that follows in the typical `verify_bundle` flow.
    fn build_bundle_verifier(&self) -> Result<AsyncBundleVerifier, AttestError> {
        let trust_root = build_trust_root()?;
        AsyncBundleVerifier::new(Default::default(), trust_root).map_err(|_| AttestError::TrustRoot)
    }
}

fn build_trust_root() -> Result<SigstoreTrustRoot, AttestError> {
    SigstoreTrustRoot::from_trusted_root_json_unchecked(EMBEDDED_TRUSTED_ROOT_JSON)
        .map_err(|_| AttestError::TrustRoot)
}

impl AttestVerifier for SigstoreVerifier {
    fn verify_blob(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        let artifact_bytes = fs::read(artifact)?;
        let signature_bytes = fs::read(signature)?;
        let certificate_bytes = fs::read(certificate)?;
        self.verify_bytes(
            &artifact_bytes,
            &signature_bytes,
            &certificate_bytes,
            expected,
        )
    }

    fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        let leaf_der = parse_certificate_to_der(certificate_pem)?;
        let leaf_cert = Certificate::from_der(&leaf_der)
            .map_err(|e| AttestError::Malformed(format!("leaf cert DER parse: {e}")))?;

        validate_against_fulcio(&leaf_der, self.fulcio_root_ders.as_ref())?;

        let identity = match_identity(&leaf_cert, expected)?;

        let (not_before, not_after) = certificate_validity(&leaf_cert)?;
        let now = SystemTime::now();
        if !is_within_validity_window(now, not_before, not_after) {
            return Err(AttestError::CertificateExpired);
        }

        let key =
            CosignVerificationKey::try_from(&leaf_cert.tbs_certificate.subject_public_key_info)
                .map_err(|_| AttestError::Malformed("unsupported leaf public key".into()))?;

        verify_signature_bytes(&key, signature, artifact)?;

        Ok(VerifiedAttestation {
            subject_digest_sha256: Sha256::digest(artifact).into(),
            certificate_identity: identity,
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index: 0,
            rekor_inclusion_verified: false,
            signed_at: not_before,
        })
    }

    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        let bundle: Bundle = serde_json::from_slice(bundle_json)
            .map_err(|e| AttestError::Malformed(format!("bundle JSON parse: {e}")))?;

        let issuer_policy = IssuerOnlyPolicy {
            expected_issuer: expected.certificate_oidc_issuer.clone(),
        };

        let mut hasher = Sha256::new();
        hasher.update(artifact);
        let bundle_clone = bundle.clone();
        let verifier = self.build_bundle_verifier()?;
        run_async_bundle_verify(&self.runtime, verifier, hasher, bundle_clone, issuer_policy)
            .map_err(map_bundle_verification_error)?;

        let leaf_der = bundle_leaf_certificate_der(&bundle)?;
        let leaf_cert = Certificate::from_der(&leaf_der)
            .map_err(|e| AttestError::Malformed(format!("leaf cert DER parse: {e}")))?;

        let identity = match_identity(&leaf_cert, expected)?;

        let (rekor_log_index, signed_at) = bundle_rekor_metadata(&bundle);

        Ok(VerifiedAttestation {
            subject_digest_sha256: Sha256::digest(artifact).into(),
            certificate_identity: identity,
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index,
            rekor_inclusion_verified: bundle_rekor_inclusion_verified(&bundle),
            signed_at,
        })
    }
}
