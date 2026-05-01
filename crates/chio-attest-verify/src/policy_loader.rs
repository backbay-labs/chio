//! Tenant policy loader (M05.P4.T2).
//!
//! Source-of-truth design: `.planning/trajectory-2/05-adversarial-escape-threat-model.md`
//! (Phase 4, mitigation row "Per-tenant policy file drift"). The loader
//! consumes a [`TenantPolicy`] together with the certificate that signed it
//! and verifies the policy through the same [`crate::AttestVerifier`]
//! surface every other attestation flows through. No new sigstore-rs
//! imports are introduced; the loader is a pure consumer of
//! [`crate::SigstoreVerifier`].
//!
//! # Fail-closed contract
//!
//! [`TenantPolicyLoader::load_signed`] returns `Ok(TenantPolicy)` only when:
//!
//! - the structural validation in [`TenantPolicy::validate_structural`]
//!   passes,
//! - the canonical signing bytes (which exclude the `signature` field) are
//!   accepted by the supplied [`AttestVerifier::verify_bytes`] with the
//!   caller-supplied policy-signer [`ExpectedIdentity`],
//! - and `signed_at` is no older than the configured staleness horizon
//!   (default 90 days) and is not in the future.
//!
//! Any other input returns one of the [`AttestError`] variants; there is no
//! path through this module that yields a policy on a partial check.
//!
//! # Bootstrap chicken-and-egg
//!
//! The first per-tenant policy is itself a chicken-and-egg problem: the
//! signing identity expected by [`TenantPolicyLoader::load_signed`] for the
//! first ever load is the workspace release identity (the same identity
//! M06 uses for binary releases). Operators inherit the
//! [`crate::BOOTSTRAP_TENANT_ID`] policy and override per tenant from
//! there. The bootstrap policy file ships at
//! `crates/chio-attest-verify/tests/fixtures/policies/bootstrap.toml`; its
//! signing identity is documented in the M05 audit doc at
//! `docs/security/expected-identity-migration.md` (M05.P4.T4).

use std::time::{Duration, SystemTime};

use crate::policy::TenantPolicy;
use crate::{AttestError, AttestVerifier, ExpectedIdentity};

/// Default staleness horizon. Operators rotate signed policies on a 90-day
/// cadence; loader rejects policies older than this fail-closed.
pub const DEFAULT_STALENESS_HORIZON: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Fail-closed loader for [`TenantPolicy`] files.
///
/// Construct once at startup with the desired staleness horizon (default
/// 90 days) and reuse for every tenant on the boot path. The loader holds
/// no state besides the horizon; it is `Send + Sync` so it can be embedded
/// in the kernel-side configuration object.
#[derive(Debug, Clone, Copy)]
pub struct TenantPolicyLoader {
    horizon: Duration,
}

impl TenantPolicyLoader {
    /// Construct a loader with the documented 90-day staleness horizon.
    #[must_use]
    pub const fn with_default_horizon() -> Self {
        Self {
            horizon: DEFAULT_STALENESS_HORIZON,
        }
    }

    /// Construct a loader with a non-default horizon. Operators that rotate
    /// more aggressively can shorten this; lengthening it past 90 days
    /// requires an explicit operator decision recorded in the M05 audit
    /// doc.
    #[must_use]
    pub const fn with_horizon(horizon: Duration) -> Self {
        Self { horizon }
    }

    /// Configured staleness horizon.
    #[must_use]
    pub const fn horizon(self) -> Duration {
        self.horizon
    }

    /// Load a policy from raw TOML bytes plus a signing certificate (PEM)
    /// and verify it against the supplied [`AttestVerifier`].
    ///
    /// The `policy_signer_expected` argument names the signing identity
    /// the operator trusts to issue per-tenant policies (typically the
    /// workspace release identity for the bootstrap policy and a
    /// tenant-scoped Fulcio identity for per-tenant overrides).
    ///
    /// # Errors
    ///
    /// - [`AttestError::Malformed`] for TOML decode failures, structural
    ///   validation failures, malformed timestamps, or canonical-encode
    ///   failures.
    /// - [`AttestError::SignatureMismatch`] if the underlying verifier
    ///   rejects the signature.
    /// - Any [`AttestError`] returned by the underlying
    ///   [`AttestVerifier::verify_bytes`] (cert-chain, OIDC issuer,
    ///   identity-regex, validity-window, etc.).
    /// - [`AttestError::Malformed`] with `"signed_at"` in the message if
    ///   the policy's `signed_at` is older than the loader's staleness
    ///   horizon. Staleness is reported as `Malformed` (not as a
    ///   structurally distinct variant) because the [`AttestError`] enum
    ///   is `#[non_exhaustive]` and downstream policy gates already
    ///   pattern-match `Malformed` as fail-closed; see the audit doc at
    ///   `docs/security/expected-identity-migration.md`.
    pub fn load_signed<V>(
        &self,
        verifier: &V,
        policy_signer_expected: &ExpectedIdentity,
        policy_toml: &[u8],
        certificate_pem: &[u8],
        now: SystemTime,
    ) -> Result<TenantPolicy, AttestError>
    where
        V: AttestVerifier + ?Sized,
    {
        // 1) Parse and structurally validate.
        let policy = TenantPolicy::from_toml_slice(policy_toml)?;

        // 2) Verify the signature over the canonical bytes.
        let canonical = policy.canonical_signing_bytes()?;
        let signature_bytes = policy.signature.as_bytes();
        verifier.verify_bytes(
            &canonical,
            signature_bytes,
            certificate_pem,
            policy_signer_expected,
        )?;

        // 3) Staleness check: signed_at must be no older than the horizon
        //    and not in the future. Both directions fail closed.
        let signed_at = policy.signed_at_system_time(now)?;
        let age = now
            .duration_since(signed_at)
            .map_err(|err| AttestError::Malformed(format!("signed_at clock skew: {err}")))?;
        if age > self.horizon {
            return Err(AttestError::Malformed(format!(
                "signed_at {} is {} seconds old (horizon {} seconds)",
                policy.signed_at,
                age.as_secs(),
                self.horizon.as_secs()
            )));
        }

        Ok(policy)
    }
}

impl Default for TenantPolicyLoader {
    fn default() -> Self {
        Self::with_default_horizon()
    }
}
