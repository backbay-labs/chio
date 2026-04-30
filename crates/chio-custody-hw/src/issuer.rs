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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::capability::{PasskeyCapability, ScopeSet};
use crate::error::CustodyError;
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
pub struct IssuerService {
    audience: String,
}

impl IssuerService {
    /// Build an issuer pinned to a specific audience URI.
    #[must_use]
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
        }
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

        let cap = PasskeyCapability::new_stub_unsigned(
            self.audience.clone(),
            verified.credential_id_b64.clone(),
            request.scope_set.clone(),
            request.challenge_nonce.clone(),
            now,
        );
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
