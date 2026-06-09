//! Kernel-side passkey-capability verification.
//!
//! The kernel sits behind the issuer surface ([`chio_custody_hw::IssuerService`]).
//! When a caller presents a [`PasskeyCapability`] to the kernel, the kernel
//! delegates to [`PasskeyCapabilityVerifier`] which:
//!
//! 1. Refuses any capability with an empty signature (custody contract:
//!    empty signatures NEVER verify).
//! 2. Checks the audience pin matches the kernel's configured identity.
//! 3. Checks the capability is live (`now < exp`).
//! 4. Reconstructs the signing message via
//!    [`chio_custody_hw::mint::signing_message`] and verifies the
//!    detached signature against the configured issuer
//!    [`chio_core_types::crypto::PublicKey`].
//!
//! All four gates are fail-closed: any path that does not strictly
//! satisfy its precondition returns a typed [`CustodyError`] with a
//! stable `urn:chio:error:custody:*` code.
//!
//! # Async discipline
//!
//! This module introduces NO `&mut self` on the verifier surface.
//! `PasskeyCapabilityVerifier::verify` takes `&self` so it can be shared
//! behind an `Arc<>` and consumed concurrently from the async kernel.

use chio_core_types::crypto::{PublicKey, Signature};
use chio_custody_hw::capability::PasskeyCapability;
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::mint::signing_message;
use chrono::{DateTime, Utc};

/// Kernel-side verifier for [`PasskeyCapability`] envelopes.
///
/// The verifier is configured with the audience the kernel pins itself
/// to, and the issuer's public key (the public half of the
/// [`chio_core_types::crypto::SigningBackend`] the issuer used to sign
/// the capability). The verifier is `Send + Sync` and stateless;
/// production deployments hold one in an `Arc<>` and re-use it across
/// every kernel call.
pub struct PasskeyCapabilityVerifier {
    audience: String,
    issuer_public_key: PublicKey,
}

impl PasskeyCapabilityVerifier {
    /// Build a verifier pinned to a kernel audience and the issuer
    /// public key.
    #[must_use]
    pub fn new(audience: impl Into<String>, issuer_public_key: PublicKey) -> Self {
        Self {
            audience: audience.into(),
            issuer_public_key,
        }
    }

    /// Configured kernel audience pin.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Configured issuer public key.
    #[must_use]
    pub fn issuer_public_key(&self) -> &PublicKey {
        &self.issuer_public_key
    }

    /// Verify a [`PasskeyCapability`] presented to this kernel.
    ///
    /// Returns `Ok(())` only when ALL four gates pass:
    ///
    /// 1. `capability.signature` is non-empty.
    /// 2. `capability.audience == self.audience`.
    /// 3. `now < capability.exp`.
    /// 4. The detached hex-encoded `capability.signature` verifies
    ///    under [`Self::issuer_public_key`] over the canonical-JSON
    ///    bytes of the envelope WITH `signature = ""` (the same
    ///    message the issuer signed).
    ///
    /// Fail-closed: any failing gate returns a typed [`CustodyError`].
    /// The first failing gate short-circuits; deployments that need
    /// distinct telemetry per gate read the [`CustodyError::urn`].
    pub fn verify(
        &self,
        capability: &PasskeyCapability,
        now: DateTime<Utc>,
    ) -> Result<(), CustodyError> {
        // Gate 1: empty signatures NEVER verify. The kernel
        // refuses to admit an unsigned envelope even if the audience and clock
        // would otherwise let it through.
        if capability.signature.is_empty() {
            return Err(CustodyError::AssertionRejected(
                "PasskeyCapability presented with empty signature".into(),
            ));
        }

        // Gate 2: audience pin.
        capability.require_audience(&self.audience)?;

        // Gate 3: liveness.
        capability.require_live(now)?;

        // Gate 4: cryptographic verification.
        let message = signing_message(capability)?;
        let signature = Signature::from_hex(&capability.signature).map_err(|err| {
            CustodyError::AssertionRejected(format!("signature hex decode failed: {err}"))
        })?;
        if !self.issuer_public_key.verify(&message, &signature) {
            return Err(CustodyError::AssertionRejected(
                "PasskeyCapability signature did not verify against issuer public key".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
    use chio_custody_hw::capability::ScopeSet;
    use chio_custody_hw::issuer::{IssuerService, MintRequest};
    use chio_custody_hw::verifier::VerifiedAssertion;
    use chrono::TimeZone;

    const AUDIENCE: &str = "urn:chio:audience:kernel";

    fn fixed_now() -> chrono::DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_now fixture must construct"),
        }
    }

    fn signed_cap_for_audience(audience: &str) -> (PasskeyCapability, PublicKey) {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[41u8; 32]));
        let public = backend.public_key();
        let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
        let svc = IssuerService::with_signer(audience, backend_arc);
        let req = MintRequest {
            audience: audience.into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let assertion = VerifiedAssertion {
            credential_id_b64: "AAAA".into(),
            user_verified: true,
        };
        let resp = match svc.mint_capability(&assertion, &req, fixed_now()) {
            Ok(r) => r,
            Err(e) => panic!("mint must succeed: {e}"),
        };
        (resp.capability, public)
    }

    #[test]
    fn verifies_signed_capability_for_pinned_audience() {
        let (cap, public) = signed_cap_for_audience(AUDIENCE);
        let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
        if let Err(e) = verifier.verify(&cap, fixed_now()) {
            panic!("matching capability must verify: {e}");
        }
    }

    #[test]
    fn rejects_audience_mismatch() {
        let (cap, public) = signed_cap_for_audience("urn:chio:audience:other");
        let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
        let res = verifier.verify(&cap, fixed_now());
        assert!(matches!(res, Err(CustodyError::AudienceMismatch { .. })));
    }

    #[test]
    fn rejects_empty_signature() {
        let (mut cap, public) = signed_cap_for_audience(AUDIENCE);
        cap.signature.clear();
        let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
        let res = verifier.verify(&cap, fixed_now());
        assert!(matches!(res, Err(CustodyError::AssertionRejected(_))));
    }

    #[test]
    fn rejects_expired_capability() {
        let (cap, public) = signed_cap_for_audience(AUDIENCE);
        let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
        let later = cap.exp + chrono::Duration::seconds(1);
        let res = verifier.verify(&cap, later);
        assert!(matches!(res, Err(CustodyError::CapabilityExpired)));
    }

    #[test]
    fn rejects_signature_from_wrong_issuer_key() {
        let (cap, _real_public) = signed_cap_for_audience(AUDIENCE);
        // Same audience, different issuer key. The kernel pins the
        // public key, so a foreign issuer never produces a verifying
        // capability.
        let other_backend = Ed25519Backend::new(Keypair::from_seed(&[99u8; 32]));
        let other_public = other_backend.public_key();
        let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, other_public);
        let res = verifier.verify(&cap, fixed_now());
        assert!(matches!(res, Err(CustodyError::AssertionRejected(_))));
    }
}
