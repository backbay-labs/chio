//! Sigstore verification wiring for cached and streamed guard artifacts.
//!
//! This module is intentionally thin. It receives the shared
//! `chio_attest_verify::AttestVerifier` trait object, forwards bytes to that
//! trait, and maps every verifier failure into a fail-closed registry error.

use std::fs;

use chio_attest_verify::AttestError;
use serde::Serialize;

use crate::cache::GuardCacheLayout;
use crate::oci::{GuardRegistryError, Result};
use crate::{AttestVerifier, ExpectedIdentity, VerifiedAttestation};

/// Structured event name emitted for every guard load verification path.
pub const CHIO_GUARD_VERIFY_EVENT: &str = "chio.guard.verify";

/// Verification path selected for a guard load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardVerificationKind {
    /// Ed25519 manifest signature verification only.
    Ed25519Only,
    /// Sigstore bundle verification only.
    SigstoreOnly,
    /// Ed25519 and Sigstore both verified and reconciled.
    DualVerified,
}

impl GuardVerificationKind {
    /// Stable wire label for structured load events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519Only => "ed25519-only",
            Self::SigstoreOnly => "sigstore-only",
            Self::DualVerified => "dual-verified",
        }
    }
}

/// Result carried by a structured guard load event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardLoadEventResult {
    /// The guard load may continue.
    Allow,
    /// The guard load is denied fail-closed.
    Deny,
}

impl GuardLoadEventResult {
    /// Stable wire label for structured load events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Source path used by the guard load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardLoadSource {
    /// The load path depended on the network path.
    Network,
    /// The load path depended on the local offline cache.
    OfflineCache,
}

impl GuardLoadSource {
    /// Stable wire label for structured load events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::OfflineCache => "offline-cache",
        }
    }
}

/// Structured event emitted for a guard load verification decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardLoadEvent {
    /// Event name. Always [`CHIO_GUARD_VERIFY_EVENT`].
    pub event: &'static str,
    /// Allow or deny result.
    pub result: GuardLoadEventResult,
    /// Verification path selected for the load.
    pub verification: GuardVerificationKind,
    /// Network or offline cache source.
    pub source: GuardLoadSource,
    /// Pinned cache or OCI digest associated with the load.
    pub digest: String,
    /// Verified artifact digest, when verification reached a signed artifact.
    pub subject_digest_sha256: Option<String>,
    /// Verified signer identity, when verification reached a signer identity.
    pub identity: Option<String>,
    /// Stable denial reason for fail-closed events.
    pub reason: Option<String>,
}

impl GuardLoadEvent {
    /// Build an allow event from a verified signature assertion.
    pub fn allow(
        verification: GuardVerificationKind,
        source: GuardLoadSource,
        digest: impl Into<String>,
        assertion: &GuardVerifiedSignature,
    ) -> Self {
        Self {
            event: CHIO_GUARD_VERIFY_EVENT,
            result: GuardLoadEventResult::Allow,
            verification,
            source,
            digest: digest.into(),
            subject_digest_sha256: Some(sha256_hex(&assertion.digest_sha256)),
            identity: Some(assertion.identity.clone()),
            reason: None,
        }
    }

    /// Build a deny event for a fail-closed load path.
    pub fn deny(
        verification: GuardVerificationKind,
        source: GuardLoadSource,
        digest: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            event: CHIO_GUARD_VERIFY_EVENT,
            result: GuardLoadEventResult::Deny,
            verification,
            source,
            digest: digest.into(),
            subject_digest_sha256: None,
            identity: None,
            reason: Some(reason.into()),
        }
    }
}

/// Normalized assertion produced by one verified signing mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardVerifiedSignature {
    /// SHA-256 digest of the verified artifact bytes.
    pub digest_sha256: [u8; 32],
    /// Normalized signer identity for reconciliation and audit.
    pub identity: String,
}

impl GuardVerifiedSignature {
    /// Build a normalized assertion from a Sigstore attestation.
    pub fn from_sigstore(attestation: &VerifiedAttestation) -> Self {
        Self {
            digest_sha256: attestation.subject_digest_sha256,
            identity: attestation.certificate_identity.clone(),
        }
    }
}

/// Successful verification report for one load path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardVerificationReport {
    /// Verification path that produced this report.
    pub kind: GuardVerificationKind,
    /// Normalized verified signature assertion.
    pub assertion: GuardVerifiedSignature,
}

impl GuardVerificationReport {
    /// Report a successful Ed25519-only verification.
    pub fn ed25519_only(assertion: GuardVerifiedSignature) -> Self {
        Self {
            kind: GuardVerificationKind::Ed25519Only,
            assertion,
        }
    }

    /// Report a successful Sigstore-only verification.
    pub fn sigstore_only(attestation: &VerifiedAttestation) -> Self {
        Self {
            kind: GuardVerificationKind::SigstoreOnly,
            assertion: GuardVerifiedSignature::from_sigstore(attestation),
        }
    }
}

/// Build the shared expected identity from operator configuration.
///
/// Callers should construct this once when loading registry configuration and
/// then reuse it for every verification call. The returned type is the
/// `chio-attest-verify` source-of-truth type, not a guard-registry shadow.
pub fn expected_identity_from_config(
    fulcio_subject_regex: impl Into<String>,
    fulcio_oidc_issuer: impl Into<String>,
) -> ExpectedIdentity
where
    ExpectedIdentity: Sized,
{
    chio_attest_verify::ExpectedIdentity {
        certificate_identity_regexp: fulcio_subject_regex.into(),
        certificate_oidc_issuer: fulcio_oidc_issuer.into(),
    }
}

/// Guard-registry wrapper around the shared attestation verifier.
pub struct GuardSigstoreVerifier<'a> {
    verifier: &'a dyn AttestVerifier,
    expected: &'a ExpectedIdentity,
}

impl<'a> GuardSigstoreVerifier<'a> {
    /// Create a verifier wrapper from injected trust-boundary dependencies.
    pub fn new(verifier: &'a dyn AttestVerifier, expected: &'a ExpectedIdentity) -> Self {
        Self { verifier, expected }
    }

    /// Verify cached `module.wasm` and `sigstore-bundle.json` bytes.
    ///
    /// This is the normal on-disk cache path and requires a verified Rekor
    /// inclusion proof. A verifier that returns success without Rekor inclusion
    /// is treated as fail-closed.
    pub fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
    ) -> Result<VerifiedAttestation> {
        let attestation = self
            .verifier
            .verify_bundle(artifact, bundle_json, self.expected)
            .map_err(map_attest_error)?;

        if !attestation.rekor_inclusion_verified {
            return Err(GuardRegistryError::VerifyMissingRekorProof);
        }

        Ok(attestation)
    }

    /// Read `module.wasm` and `sigstore-bundle.json` from a cache layout and
    /// verify them through [`Self::verify_bundle`].
    pub fn verify_cached_layout(&self, layout: &GuardCacheLayout) -> Result<VerifiedAttestation> {
        let artifact = read_cache_file(&layout.module_wasm_path())?;
        let bundle_json = read_cache_file(&layout.sigstore_bundle_json_path())?;
        self.verify_bundle(&artifact, &bundle_json)
    }

    /// Verify a cached layout and return a Sigstore-only structured report.
    pub fn verify_cached_layout_report(
        &self,
        layout: &GuardCacheLayout,
    ) -> Result<GuardVerificationReport> {
        let attestation = self.verify_cached_layout(layout)?;
        Ok(GuardVerificationReport::sigstore_only(&attestation))
    }

    /// Verify streamed artifact bytes with detached signature and PEM cert.
    ///
    /// Streamed verification does not have a bundle yet, so the returned
    /// attestation can legitimately carry `rekor_inclusion_verified = false`.
    /// Callers that require the stronger Rekor gate should use
    /// [`Self::verify_bundle`].
    pub fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
    ) -> Result<VerifiedAttestation> {
        self.verifier
            .verify_bytes(artifact, signature, certificate_pem, self.expected)
            .map_err(map_attest_error)
    }
}

/// Reconcile Ed25519 manifest verification with Sigstore bundle verification.
///
/// Both closures are invoked. The load is allowed only when both verifiers
/// succeed and their normalized identities and artifact digests agree.
pub fn verify_dual_mode<Ed25519Verify, SigstoreVerify>(
    verify_ed25519: Ed25519Verify,
    verify_sigstore: SigstoreVerify,
) -> Result<GuardVerificationReport>
where
    Ed25519Verify: FnOnce() -> Result<GuardVerifiedSignature>,
    SigstoreVerify: FnOnce() -> Result<VerifiedAttestation>,
{
    let ed25519 = verify_ed25519();
    let sigstore = verify_sigstore();

    let ed25519 = ed25519?;
    let sigstore = sigstore?;
    let sigstore_assertion = GuardVerifiedSignature::from_sigstore(&sigstore);

    if ed25519.digest_sha256 != sigstore_assertion.digest_sha256 {
        return Err(GuardRegistryError::VerifyFailedClosed {
            message: "dual-mode verification digest mismatch".to_owned(),
        });
    }

    if ed25519.identity != sigstore_assertion.identity {
        return Err(GuardRegistryError::VerifyFailedClosed {
            message: "dual-mode verification identity mismatch".to_owned(),
        });
    }

    Ok(GuardVerificationReport {
        kind: GuardVerificationKind::DualVerified,
        assertion: ed25519,
    })
}

fn read_cache_file(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| GuardRegistryError::CacheIo {
        operation: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn map_attest_error(error: AttestError) -> GuardRegistryError {
    match error {
        AttestError::Io(source) => GuardRegistryError::VerifyIo { source },
        AttestError::SignatureMismatch => GuardRegistryError::VerifySignatureMismatch,
        AttestError::IdentityMismatch => GuardRegistryError::VerifyWrongSubject,
        AttestError::IssuerMismatch => GuardRegistryError::VerifyWrongOidcIssuer,
        AttestError::RekorInclusion => GuardRegistryError::VerifyMissingRekorProof,
        AttestError::CertificateExpired => GuardRegistryError::VerifyCertificateExpired,
        AttestError::TrustRoot => GuardRegistryError::VerifyTrustRoot,
        AttestError::Malformed(message) => GuardRegistryError::VerifyMalformedBundle { message },
        _ => GuardRegistryError::VerifyFailedClosed {
            message: error.to_string(),
        },
    }
}

fn sha256_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
