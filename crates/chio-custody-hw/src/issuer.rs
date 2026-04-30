//! Issuer service skeleton.
//!
//! P1 ships an in-process [`IssuerService`] that turns a verified WebAuthn
//! assertion into an unsigned [`PasskeyCapability`]. There is intentionally
//! no Axum binary in this milestone: the service is a library surface that
//! `chio-control-plane` operators mount. The shape is HTTP-shaped
//! ([`MintRequest`] / [`MintResponse`]) so a P2 follower can wire an Axum
//! `Router` without changing the call site.
//!
//! # Trust contract
//!
//! - The issuer accepts a `MintRequest` containing the audience pin, the
//!   verified credential id, the requested scope set, and the WebAuthn
//!   challenge nonce.
//! - The issuer never derives the audience from caller input outside of
//!   the signed request body; deployments pin the audience via constructor
//!   configuration that the caller cannot rewrite.
//! - The issuer requires user verification on the underlying assertion.
//!   A verified assertion that reports `user_verified = false` is rejected
//!   fail-closed with [`CustodyError::UserVerificationRequired`]; custody
//!   issuance is never downgraded to possession-only authentication, even
//!   in deployments where the relying party has not pinned UV at the
//!   WebAuthn layer.
//! - P1 returns an unsigned capability; P2 wires `HybridBackend::sign` and
//!   the durable `PasskeyNonceStore`.
//!
//! TODO(security): P2 wires:
//!   - Per-credential nonce store keyed by `(credential_id,
//!     challenge_nonce)`. Replayed assertions reject with
//!     `urn:chio:error:custody:replay-detected`.
//!   - `HybridBackend` signing through the M03 surface.
//!   - Revocation cascade through the M04 oracle.
//!   - Rate limiting and bot-defence at the HTTP edge.

use std::sync::Arc;

use chio_core_types::crypto::SigningBackend;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::capability::{PasskeyCapability, ScopeSet};
use crate::error::CustodyError;
use crate::mint::sign_capability;
use crate::nonce_store::{PasskeyNonceStore, RecordOutcome};
use crate::revocation::CredentialRevocationOracle;
use crate::verifier::VerifiedAssertion;

/// HTTP-shaped mint request. Canonical-JSON encodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    /// Audience the caller wants the capability bound to. The issuer
    /// rejects the request fail-closed if this does not match its
    /// configured audience pin.
    pub audience: String,
    /// Requested scope set.
    pub scope_set: ScopeSet,
    /// Base64url-no-pad WebAuthn challenge nonce.
    pub challenge_nonce: String,
}

/// HTTP-shaped mint response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintResponse {
    /// The minted (P1: unsigned) capability.
    pub capability: PasskeyCapability,
}

/// In-process issuer service.
///
/// Configured with a fixed audience pin that requests must match. The
/// audience pin is the kernel identity URI; it is not caller-rewritable.
///
/// An optional signing backend turns the unsigned P1 stub envelope into a
/// signed P2 capability. The same constructor accepts any
/// [`chio_core_types::crypto::SigningBackend`] (Ed25519, P-256/P-384 via
/// the `fips` feature, or `HybridBackend` via the `pq` feature) so a
/// deployment running with `crypto_floor=allow_classical` and one running
/// hybrid produce byte-identical envelopes apart from the `signature`
/// slot itself.
pub struct IssuerService {
    audience: String,
    signer: Option<Arc<dyn SigningBackend>>,
    nonce_store: Option<Arc<dyn PasskeyNonceStore>>,
    revocation: Option<Arc<dyn CredentialRevocationOracle>>,
}

impl IssuerService {
    /// Build an issuer pinned to a specific audience URI. The returned
    /// service has no signer wired (legacy P1 path: produces unsigned
    /// stubs).
    ///
    /// New code SHOULD prefer [`Self::with_signer`]; this constructor
    /// remains for backwards compatibility with the P1 unsigned-stub test
    /// surface and for deployments that synthesise capabilities for
    /// canonical-JSON regression suites.
    #[must_use]
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            signer: None,
            nonce_store: None,
            revocation: None,
        }
    }

    /// Build an issuer pinned to an audience URI and a signing backend.
    /// The signing backend is the M03 `HybridBackend` (or any
    /// [`SigningBackend`] when `crypto_floor=allow_classical`).
    #[must_use]
    pub fn with_signer(audience: impl Into<String>, signer: Arc<dyn SigningBackend>) -> Self {
        Self {
            audience: audience.into(),
            signer: Some(signer),
            nonce_store: None,
            revocation: None,
        }
    }

    /// Attach a [`PasskeyNonceStore`] for replay-attack resistance.
    ///
    /// Builder-style: returns the issuer with the nonce store wired.
    /// When set, every successful mint records
    /// `(credential_id, challenge_nonce)` keyed for replay detection;
    /// a duplicate fails the mint with [`CustodyError::ReplayDetected`].
    #[must_use]
    pub fn with_nonce_store(mut self, store: Arc<dyn PasskeyNonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// Attach a [`CredentialRevocationOracle`] (M10.P2.T3 cascade).
    ///
    /// Builder-style: returns the issuer with the revocation cascade
    /// wired through the M04 sparse-Merkle oracle. When set, every mint
    /// consults the oracle BEFORE recording the nonce or signing; a
    /// revoked credential fails-closed with
    /// [`CustodyError::CredentialRevoked`].
    #[must_use]
    pub fn with_revocation_oracle(mut self, oracle: Arc<dyn CredentialRevocationOracle>) -> Self {
        self.revocation = Some(oracle);
        self
    }

    /// Configured audience pin for inspection.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Mint a stub capability from a verified assertion plus a request.
    ///
    /// `now` is the verifier clock; the capability's `iat` and `exp` are
    /// computed off this value (not the system clock) so tests can pin
    /// the timeline deterministically.
    ///
    /// Fail-closed paths:
    /// - audience mismatch -> [`CustodyError::AudienceMismatch`]
    /// - assertion did not report user verification ->
    ///   [`CustodyError::UserVerificationRequired`]. Custody issuance
    ///   requires UV; an authenticator that verified cryptographically but
    ///   did not perform a user-verifying gesture (PIN, biometric) is
    ///   possession-only authentication, which the M10 trust contract
    ///   forbids.
    pub fn mint_capability(
        &self,
        verified: &VerifiedAssertion,
        request: &MintRequest,
        now: DateTime<Utc>,
    ) -> Result<MintResponse, CustodyError> {
        if request.audience != self.audience {
            return Err(CustodyError::AudienceMismatch {
                expected: self.audience.clone(),
                found: request.audience.clone(),
            });
        }

        if !verified.user_verified {
            return Err(CustodyError::UserVerificationRequired);
        }

        // Revocation cascade (M10.P2.T3). The check happens AFTER
        // audience and UV gates but BEFORE recording the nonce or
        // signing so a revoked credential never advances the nonce
        // store nor consumes a signing budget. The cascade is
        // synchronous from the issuer's point of view: revoking the
        // credential at the M04 oracle denies the next mint within
        // the current epoch.
        if let Some(oracle) = &self.revocation {
            if oracle.is_revoked(&verified.credential_id_b64)? {
                return Err(CustodyError::CredentialRevoked);
            }
        }

        let mut cap = PasskeyCapability::new_stub_unsigned(
            self.audience.clone(),
            verified.credential_id_b64.clone(),
            request.scope_set.clone(),
            request.challenge_nonce.clone(),
            now,
        );

        // Replay-attack resistance (M10.P2.T2). The nonce store is keyed
        // on (credential_id, challenge_nonce). The check happens BEFORE
        // signing so a replayed assertion never produces a signed
        // capability, even if the signer is fast enough to keep up.
        // Retention is `cap.exp + clock_skew` (clock_skew = 30s default
        // per `DEFAULT_CLOCK_SKEW_SECONDS`).
        if let Some(store) = &self.nonce_store {
            match store.record_if_fresh(
                &verified.credential_id_b64,
                &request.challenge_nonce,
                cap.exp.timestamp(),
            )? {
                RecordOutcome::Fresh => {}
                RecordOutcome::Replayed => {
                    return Err(CustodyError::ReplayDetected {
                        credential_id: verified.credential_id_b64.clone(),
                    });
                }
            }
        }

        if let Some(signer) = &self.signer {
            sign_capability(&mut cap, signer.as_ref())?;
        }

        Ok(MintResponse { capability: cap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_now fixture must construct"),
        }
    }

    fn verified() -> VerifiedAssertion {
        VerifiedAssertion {
            credential_id_b64: "AAAA".into(),
            user_verified: true,
        }
    }

    #[test]
    fn mints_unsigned_capability_with_correct_audience() {
        let svc = IssuerService::new("urn:chio:audience:kernel");
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let res = svc.mint_capability(&verified(), &req, fixed_now());
        let resp = match res {
            Ok(r) => r,
            Err(e) => panic!("mint must succeed for matching audience: {e}"),
        };
        assert_eq!(resp.capability.audience, "urn:chio:audience:kernel");
        assert_eq!(resp.capability.signature, "", "P1 stub MUST be unsigned");
        assert_eq!(resp.capability.credential_id, "AAAA");
    }

    #[test]
    fn rejects_audience_mismatch_fail_closed() {
        let svc = IssuerService::new("urn:chio:audience:kernel");
        let req = MintRequest {
            audience: "urn:chio:audience:other".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let res = svc.mint_capability(&verified(), &req, fixed_now());
        assert!(matches!(res, Err(CustodyError::AudienceMismatch { .. })));
    }

    #[test]
    fn rejects_assertion_without_user_verification_fail_closed() {
        // An authenticator that verified cryptographically but did not
        // report a user-verifying gesture must NOT receive a capability:
        // custody issuance requires UV to avoid silent downgrade to
        // possession-only authentication.
        let svc = IssuerService::new("urn:chio:audience:kernel");
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let assertion = VerifiedAssertion {
            credential_id_b64: "AAAA".into(),
            user_verified: false,
        };
        let res = svc.mint_capability(&assertion, &req, fixed_now());
        let err = match res {
            Ok(_) => panic!("missing UV must fail-closed"),
            Err(e) => e,
        };
        assert!(matches!(err, CustodyError::UserVerificationRequired));
        assert_eq!(
            err.urn(),
            "urn:chio:error:custody:user-verification-required"
        );
    }
}
