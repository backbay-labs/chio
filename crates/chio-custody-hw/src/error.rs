//! Custody error taxonomy.
//!
//! Every `Err(_)` path through this crate carries a stable
//! `urn:chio:error:custody:*` code matching a row in
//! `spec/errors/registry.yaml`. The codes are surface-stable; renaming a
//! variant requires registry rotation.

use thiserror::Error;

/// Stable URN for "WebAuthn assertion failed structural or signature check".
pub const URN_ASSERTION_REJECTED: &str = "urn:chio:error:custody:assertion-rejected";

/// Stable URN for "capability presented for a different audience than minted".
pub const URN_AUDIENCE_MISMATCH: &str = "urn:chio:error:custody:audience-mismatch";

/// Stable URN for "challenge nonce was previously redeemed against this credential".
pub const URN_REPLAY_DETECTED: &str = "urn:chio:error:custody:replay-detected";

/// Stable URN for "capability `exp` is in the past relative to the verifier clock".
pub const URN_CAPABILITY_EXPIRED: &str = "urn:chio:error:custody:capability-expired";

/// Stable URN for "WebAuthn credential bound to this capability has been revoked".
pub const URN_CREDENTIAL_REVOKED: &str = "urn:chio:error:custody:credential-revoked";

/// Stable URN for "assertion verified but did not report user verification".
pub const URN_USER_VERIFICATION_REQUIRED: &str =
    "urn:chio:error:custody:user-verification-required";

/// Stable URN for "issuance denied because the subject exceeded its rate budget".
pub const URN_RATE_LIMITED: &str = "urn:chio:error:custody:rate-limited";

/// Stable URN for "custody surface failed to canonicalize, encode, or decode".
///
/// Distinct from [`URN_ASSERTION_REJECTED`] so HTTP / JSON-RPC translation
/// layers do not advise callers to retry with a fresh challenge for what is
/// in fact an internal serialization bug.
pub const URN_INTERNAL_ENCODING: &str = "urn:chio:error:custody:internal-encoding";

/// All custody-side failure modes. Fail-closed: every variant denies access.
#[derive(Debug, Error)]
pub enum CustodyError {
    /// The WebAuthn assertion did not verify against the registered
    /// credential. Includes structural failures (malformed CBOR, missing
    /// fields) and signature failures.
    #[error("custody: WebAuthn assertion rejected: {0}")]
    AssertionRejected(String),

    /// The capability was minted for one audience but presented to another.
    #[error("custody: audience mismatch (expected {expected}, found {found})")]
    AudienceMismatch {
        /// Audience the verifier expected (its own identity).
        expected: String,
        /// Audience encoded in the capability.
        found: String,
    },

    /// The challenge nonce was redeemed before for this credential.
    #[error("custody: replay detected for credential {credential_id}")]
    ReplayDetected {
        /// Base64url-encoded WebAuthn credential id whose nonce store was hit.
        credential_id: String,
    },

    /// The capability `exp` is in the past relative to the verifier clock.
    #[error("custody: capability expired")]
    CapabilityExpired,

    /// The WebAuthn credential bound to this capability has been revoked.
    #[error("custody: credential revoked")]
    CredentialRevoked,

    /// The WebAuthn assertion verified cryptographically but the
    /// authenticator did not report a user-verification gesture (PIN,
    /// biometric). Custody issuance requires UV; this is fail-closed
    /// distinct from a generic assertion rejection so deployments can
    /// surface a precise re-prompt without leaking whether the credential
    /// itself was valid.
    #[error("custody: user verification required (UV bit not set on assertion)")]
    UserVerificationRequired,

    /// The subject exceeded its issuance rate budget. Fail-closed: the
    /// mint is denied before the revocation oracle, nonce store, or
    /// signing backend are consulted. Distinct from a credential being
    /// invalid; the caller may retry after the rate window elapses.
    #[error("custody: issuance rate limit exceeded for subject {subject}")]
    RateLimited {
        /// Base64url-encoded WebAuthn credential id that exceeded its budget.
        subject: String,
    },

    /// Internal serialization or canonical-JSON encoding failure. Fail-closed.
    ///
    /// Maps to [`URN_INTERNAL_ENCODING`], not [`URN_ASSERTION_REJECTED`]:
    /// a fresh challenge will not resolve a server-side encoding bug, so
    /// translation layers must not advise the caller to retry the
    /// ceremony.
    #[error("custody: encoding failure: {0}")]
    Encoding(String),
}

impl CustodyError {
    /// Stable `urn:chio:error:custody:*` code for this error variant.
    ///
    /// Consumed by HTTP / JSON-RPC translation layers; the string codes are
    /// defined in `spec/errors/registry.yaml`.
    #[must_use]
    pub fn urn(&self) -> &'static str {
        match self {
            Self::AssertionRejected(_) => URN_ASSERTION_REJECTED,
            Self::AudienceMismatch { .. } => URN_AUDIENCE_MISMATCH,
            Self::ReplayDetected { .. } => URN_REPLAY_DETECTED,
            Self::CapabilityExpired => URN_CAPABILITY_EXPIRED,
            Self::CredentialRevoked => URN_CREDENTIAL_REVOKED,
            Self::UserVerificationRequired => URN_USER_VERIFICATION_REQUIRED,
            Self::RateLimited { .. } => URN_RATE_LIMITED,
            Self::Encoding(_) => URN_INTERNAL_ENCODING,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urns_match_registry() {
        // These string constants are mirrored verbatim in
        // `spec/errors/registry.yaml`. If the registry rows are renamed,
        // this test stays green only because the constants moved with them.
        assert_eq!(
            URN_ASSERTION_REJECTED,
            "urn:chio:error:custody:assertion-rejected"
        );
        assert_eq!(
            URN_AUDIENCE_MISMATCH,
            "urn:chio:error:custody:audience-mismatch"
        );
        assert_eq!(
            URN_REPLAY_DETECTED,
            "urn:chio:error:custody:replay-detected"
        );
        assert_eq!(
            URN_CAPABILITY_EXPIRED,
            "urn:chio:error:custody:capability-expired"
        );
        assert_eq!(
            URN_CREDENTIAL_REVOKED,
            "urn:chio:error:custody:credential-revoked"
        );
        assert_eq!(
            URN_USER_VERIFICATION_REQUIRED,
            "urn:chio:error:custody:user-verification-required"
        );
        assert_eq!(URN_RATE_LIMITED, "urn:chio:error:custody:rate-limited");
        assert_eq!(
            URN_INTERNAL_ENCODING,
            "urn:chio:error:custody:internal-encoding"
        );
    }

    #[test]
    fn variant_to_urn_mapping() {
        let e = CustodyError::AudienceMismatch {
            expected: "a".into(),
            found: "b".into(),
        };
        assert_eq!(e.urn(), URN_AUDIENCE_MISMATCH);

        let e = CustodyError::ReplayDetected {
            credential_id: "cid".into(),
        };
        assert_eq!(e.urn(), URN_REPLAY_DETECTED);

        assert_eq!(
            CustodyError::CapabilityExpired.urn(),
            URN_CAPABILITY_EXPIRED
        );
        assert_eq!(
            CustodyError::CredentialRevoked.urn(),
            URN_CREDENTIAL_REVOKED
        );
        assert_eq!(
            CustodyError::AssertionRejected("x".into()).urn(),
            URN_ASSERTION_REJECTED
        );
        assert_eq!(
            CustodyError::UserVerificationRequired.urn(),
            URN_USER_VERIFICATION_REQUIRED
        );
        assert_eq!(
            CustodyError::RateLimited {
                subject: "cid".into()
            }
            .urn(),
            URN_RATE_LIMITED
        );
        assert_eq!(
            CustodyError::Encoding("boom".into()).urn(),
            URN_INTERNAL_ENCODING,
            "internal encoding errors must NOT alias to assertion-rejected"
        );
    }
}
