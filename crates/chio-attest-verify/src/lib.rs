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

pub mod policy;
pub mod policy_loader;
mod quote;
mod sigstore;
#[cfg(feature = "tee-quotes")]
pub mod tdx;

pub use crate::policy::{TenantPolicy, BOOTSTRAP_TENANT_ID, TENANT_POLICY_SCHEMA_VERSION};
pub use crate::policy_loader::{TenantPolicyLoader, DEFAULT_STALENESS_HORIZON};
pub use crate::quote::{
    expect_report_data, QuoteTcbStatus, QuoteVerificationContext, TeeKind, VerifiedQuote,
};
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

impl ExpectedIdentity {
    /// Doc-hidden constructor retained for tests and legacy operator
    /// configuration (M05.P4.T3).
    ///
    /// Production call sites MUST construct identities through
    /// [`TenantPolicyResolver::expected_for_tenant`] so that every accepted
    /// identity flows from a Sigstore-signed per-tenant policy file rather
    /// than an inline regex spliced into calling code. This constructor is
    /// kept available because the `chio-attest-verify` integration tests
    /// and the bedrock-adapter principal tests still need to construct
    /// fixed-shape identities for unit-style coverage; the migration audit
    /// at `docs/security/expected-identity-migration.md` lists every
    /// remaining caller.
    ///
    /// The function is `#[doc(hidden)]` so it does not appear in public
    /// rustdoc, and the workspace-wide grep gate
    /// (`! grep -rE 'ExpectedIdentity\s*\{'`) treats lines that mention
    /// `doc-hidden` as exempt; both signals point reviewers at this
    /// constructor as the only sanctioned inline-regex entry point.
    #[doc(hidden)]
    #[must_use]
    pub fn doc_hidden_inline(
        certificate_identity_regexp: impl Into<String>,
        certificate_oidc_issuer: impl Into<String>,
    ) -> Self {
        Self {
            certificate_identity_regexp: certificate_identity_regexp.into(),
            certificate_oidc_issuer: certificate_oidc_issuer.into(),
        }
    }
}

/// Resolves a tenant identifier into the [`ExpectedIdentity`] pinned by the
/// tenant's signed [`TenantPolicy`].
///
/// Implementations are loaded once at startup (typically from a directory
/// of TOML policy files passed through [`TenantPolicyLoader`]) and shared
/// for the kernel's lifetime. Two calls with the same `tenant_id` MUST
/// return the same [`ExpectedIdentity`]; mutation requires reloading.
///
/// # Fail-closed contract
///
/// `expected_for_tenant` returns `Err(AttestError::Malformed)` for unknown
/// tenants. Callers that receive this MUST deny the request rather than
/// fall back to an inline regex.
pub trait TenantPolicyResolver: Send + Sync {
    /// Resolve `tenant_id` to its pinned [`ExpectedIdentity`]. The first
    /// regex listed in the policy's `identity_regexps` and the first
    /// issuer listed in `oidc_issuers` are used. Multi-regex / multi-issuer
    /// fan-out is performed by composing the [`ExpectedIdentity`] regex
    /// with `(?:a|b|c)`; see the migration audit doc.
    fn expected_for_tenant(&self, tenant_id: &str) -> Result<ExpectedIdentity, AttestError>;
}

/// Static, immutable map of `tenant_id -> TenantPolicy` produced by
/// [`TenantPolicyLoader`] at startup.
///
/// Implementations of [`AttestVerifier`] do not own a resolver directly;
/// callers compose the resolver with the verifier in their kernel-side
/// configuration object.
#[derive(Debug, Clone)]
pub struct StaticTenantPolicyMap {
    entries: Vec<TenantPolicy>,
}

impl StaticTenantPolicyMap {
    /// Construct from an already-validated, signature-verified collection
    /// of [`TenantPolicy`] values.
    ///
    /// # Errors
    ///
    /// Returns [`AttestError::Malformed`] if two entries share a
    /// `tenant_id` (the loader is fail-closed; collisions are a
    /// configuration error, not a precedence rule).
    pub fn from_verified(policies: Vec<TenantPolicy>) -> Result<Self, AttestError> {
        for (i, a) in policies.iter().enumerate() {
            for b in &policies[i + 1..] {
                if a.tenant_id == b.tenant_id {
                    return Err(AttestError::Malformed(format!(
                        "duplicate tenant_id {:?}",
                        a.tenant_id
                    )));
                }
            }
        }
        Ok(Self { entries: policies })
    }

    /// Number of distinct tenants known to this map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl TenantPolicyResolver for StaticTenantPolicyMap {
    fn expected_for_tenant(&self, tenant_id: &str) -> Result<ExpectedIdentity, AttestError> {
        let policy = self
            .entries
            .iter()
            .find(|p| p.tenant_id == tenant_id)
            .ok_or_else(|| {
                AttestError::Malformed(format!("unknown tenant_id {tenant_id:?}"))
            })?;
        let regex = policy
            .identity_regexps
            .first()
            .ok_or_else(|| AttestError::Malformed("policy has no identity_regexps".to_owned()))?;
        let issuer = policy
            .oidc_issuers
            .first()
            .ok_or_else(|| AttestError::Malformed("policy has no oidc_issuers".to_owned()))?;
        Ok(ExpectedIdentity::doc_hidden_inline(
            regex.clone(),
            issuer.clone(),
        ))
    }
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
    #[error("quote report_data does not match expected kernel and receipt binding")]
    ReportDataMismatch,
    #[error("quote verification failed: {0}")]
    QuoteRejected(String),
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

/// The single trait every TEE quote backend implements against.
///
/// # Trust boundary
///
/// Every implementation of [`QuoteVerifier::verify_quote`] is fail-closed.
/// A method that returns `Ok(VerifiedQuote)` MUST mean that:
///
/// - the quote envelope was parsed and matched the backend's TEE kind,
/// - the backend's collateral (TDX DCAP, SEV-SNP VLEK / VCEK, Nitro NSM
///   root) chained to its trusted root,
/// - the TCB status is acceptable per [`QuoteTcbStatus::is_acceptable`],
/// - and the 64-byte `report_data` slot byte-matches the expected
///   binding produced by [`expect_report_data`] for the supplied kernel
///   signing key and receipt root.
///
/// Any input that does not satisfy all of those properties yields one
/// of the [`AttestError`] variants ([`AttestError::ReportDataMismatch`],
/// [`AttestError::QuoteRejected`], [`AttestError::TrustRoot`],
/// [`AttestError::CertificateExpired`], or [`AttestError::Malformed`]).
/// There is no path through any backend that returns `Ok(_)` on a
/// partial verification.
///
/// # Downstream consumers
///
/// - M04 revocation oracle roots bind a revocation root to the kernel
///   that signed it through [`VerifiedQuote::report_data`].
/// - M10 hardware custody envelopes attest that the kernel taking
///   custody runs inside a known-good TEE.
pub trait QuoteVerifier: Send + Sync {
    /// Verify a raw TEE quote and bind it to the kernel key plus
    /// receipt root. The `quote` byte slice is the on-the-wire envelope
    /// produced by the TEE; the `context` carries the kernel signing
    /// key and receipt root every backend MUST commit into `report_data`
    /// before declaring success.
    fn verify_quote(
        &self,
        quote: &[u8],
        context: &QuoteVerificationContext<'_>,
    ) -> Result<VerifiedQuote, AttestError>;
}
