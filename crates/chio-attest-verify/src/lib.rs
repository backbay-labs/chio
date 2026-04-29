//! Single source of truth for Sigstore verification across the chio workspace.
//! No other crate is permitted to call `sigstore-rs` directly.
//!
//! # Trust boundary
//!
//! Every public method on [`AttestVerifier`] is fail-closed. A method that
//! returns `Ok(VerifiedAttestation)` MUST mean that:
//!
//! - the artifact bytes were hashed and matched the signed digest,
//! - the signing certificate chains to the embedded Fulcio trust root,
//! - the certificate's OIDC issuer matches the expected issuer exactly,
//! - the certificate identity SAN matches the caller-supplied regexp,
//! - and (where applicable) the Rekor inclusion was reconciled against the
//!   bundle's transparency log entry.
//!
//! Any input that does not satisfy all of those properties yields one of
//! the [`AttestError`] variants. There is no path through this crate that
//! returns `Ok(_)` on a partial verification.
//!
//! # Forbidden constructs
//!
//! Per the workspace EXECUTION-BOARD policy "No verifier or trust-boundary
//! stubs", this crate forbids `unwrap`, `expect`, and unsafe blocks at the
//! lint level. The reviewer checklist for any PR touching this crate also
//! requires a `rg -n 'todo!\(|unimplemented!\(|panic!\('` sweep across
//! `src/` and `tests/`.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::path::Path;
use std::time::SystemTime;

mod sigstore;

pub use crate::sigstore::SigstoreVerifier;

/// Identity expectation pinned by every verification call. Both fields are
/// required; verification fails-closed if either is unset.
///
/// `certificate_identity_regexp` is matched against every Subject
/// Alternative Name on the leaf certificate (URI, RFC 822, and Sigstore
/// "OtherName" entries). The regex is anchored at both ends by the verifier;
/// callers should not include their own `^` / `$` anchors but doing so is
/// harmless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    /// Regex matched against the Fulcio cert SAN. Example:
    /// `https://github\.com/owner/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*`
    pub certificate_identity_regexp: String,
    /// Fulcio cert OIDC issuer. For GitHub-hosted runners this is exactly
    /// `https://token.actions.githubusercontent.com`.
    pub certificate_oidc_issuer: String,
}

/// Result of a successful verification. Carries enough metadata for
/// receipts and audit logs without re-parsing the cert chain.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// SHA-256 of the artifact bytes that the signature was computed over.
    pub subject_digest_sha256: [u8; 32],
    /// The first SAN entry that satisfied the expected-identity regexp.
    pub certificate_identity: String,
    /// The OIDC issuer extracted from the Fulcio cert extension.
    pub certificate_oidc_issuer: String,
    /// Rekor log index, where available. `0` if the underlying bundle did
    /// not carry a transparency log entry index.
    pub rekor_log_index: u64,
    /// `true` when this verification path consumed and reconciled a Rekor
    /// transparency log entry; `false` for raw blob/bytes paths that lack
    /// a bundle. Audit consumers MUST treat `false` as a weaker assertion
    /// even though the cert chain and signature were still validated.
    pub rekor_inclusion_verified: bool,
    /// Best-effort signing time, derived from the Rekor integrated time
    /// when present and otherwise from the certificate `notBefore`.
    pub signed_at: SystemTime,
}

/// Errors are deliberately non-exhaustive so callers cannot pattern-match
/// past a future variant and silently accept. Every variant denies access.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature does not verify")]
    SignatureMismatch,
    #[error("certificate identity does not match expected regexp")]
    IdentityMismatch,
    #[error("oidc issuer does not match expected issuer")]
    IssuerMismatch,
    #[error("rekor inclusion proof failed")]
    RekorInclusion,
    #[error("certificate is outside its validity window")]
    CertificateExpired,
    #[error("trust root is missing or stale")]
    TrustRoot,
    #[error("malformed bundle: {0}")]
    Malformed(String),
}

/// The single trait every chio component implements against.
pub trait AttestVerifier: Send + Sync {
    /// Verify a detached blob signature.
    fn verify_blob(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;

    /// Verify an in-memory blob.
    fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;

    /// Verify a Sigstore bundle (a single self-describing JSON blob that
    /// inlines the cert, signature, and Rekor entry).
    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;
}
