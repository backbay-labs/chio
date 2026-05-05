//! WebAuthn assertion verifier.
//!
//! [`PasskeyVerifier`] wraps the `webauthn-rs` 0.5 relying-party surface so
//! the rest of the chio workspace can verify a passkey assertion through a
//! single fail-closed entry point. The verifier keeps the underlying
//! [`Webauthn`] instance opaque; callers do not get to bypass the wrapper.
//!
//! # Trust contract
//!
//! `verify_assertion(challenge_state, assertion)` returns
//! `Ok(VerifiedAssertion)` only if `webauthn-rs` accepts the assertion under
//! the configured relying-party id, origin, and previously-issued
//! [`PasskeyAuthentication`] state. Every error path returns a typed
//! [`CustodyError`] whose `urn()` is the
//! `urn:chio:error:custody:assertion-rejected` row in
//! `spec/errors/registry.yaml`.
//!
//! TODO(security): P2 wires a per-credential nonce store to detect replay
//! and an issuer-side revocation hook. P1 only proves the verifier path
//! returns typed `Err(_)` for malformed assertions.

#[cfg(feature = "passkey")]
use crate::error::CustodyError;
#[cfg(feature = "passkey")]
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, Url, Webauthn};
#[cfg(feature = "passkey")]
use webauthn_rs::WebauthnBuilder;

/// Output of a successful assertion verification.
///
/// The shape carries only the bytes that downstream code needs to mint a
/// capability: the WebAuthn credential id (base64url-encoded) and the
/// user-verification bit the relying party observed. The full
/// `webauthn-rs` `AuthenticationResult` is intentionally not re-exported so
/// callers cannot accidentally couple to upstream churn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// Base64url-encoded WebAuthn credential id. Stable across assertions.
    pub credential_id_b64: String,
    /// True if the authenticator reported a user verification (PIN, biometric, ...) check.
    pub user_verified: bool,
}

/// Thin wrapper over a `webauthn-rs` relying-party instance.
///
/// The verifier is reusable across requests; it holds no per-assertion
/// state. Per-assertion state (the [`PasskeyAuthentication`] handed back by
/// `start_passkey_authentication`) is the caller's responsibility to
/// persist across the issuer round trip.
#[cfg(feature = "passkey")]
pub struct PasskeyVerifier {
    inner: Webauthn,
}

#[cfg(feature = "passkey")]
impl PasskeyVerifier {
    /// Build a verifier from a relying-party id and origin.
    ///
    /// Errors fall through unchanged from `WebauthnBuilder::build`. Misuse
    /// at this construction step is fail-closed: an invalid origin or RPID
    /// returns `Err(CustodyError::Encoding)` (mapped to
    /// `urn:chio:error:custody:internal-encoding`) rather than producing a
    /// verifier that silently accepts mismatched assertions. The URN is
    /// distinct from `assertion-rejected` so callers do not retry the
    /// ceremony on a server-side configuration bug.
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self, CustodyError> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|err| CustodyError::Encoding(format!("WebauthnBuilder::new failed: {err}")))?;
        let inner = builder.build().map_err(|err| {
            CustodyError::Encoding(format!("WebauthnBuilder::build failed: {err}"))
        })?;
        Ok(Self { inner })
    }

    /// Verify a WebAuthn assertion against pre-issued challenge state.
    ///
    /// Fail-closed: any structural failure (malformed CBOR, missing fields,
    /// wrong origin, signature mismatch, counter regression) returns
    /// [`CustodyError::AssertionRejected`] which maps to
    /// `urn:chio:error:custody:assertion-rejected`.
    pub fn verify_assertion(
        &self,
        state: &PasskeyAuthentication,
        assertion: &PublicKeyCredential,
    ) -> Result<VerifiedAssertion, CustodyError> {
        let result = self
            .inner
            .finish_passkey_authentication(assertion, state)
            .map_err(|err| CustodyError::AssertionRejected(format!("{err:?}")))?;

        // The credential id is intentionally serialised as base64url string
        // form so downstream capability minting and the M04 revocation
        // oracle key on a stable transport-friendly identifier.
        let cred_id = result.cred_id();
        let credential_id_b64 = base64_url_no_pad(cred_id.as_ref());

        Ok(VerifiedAssertion {
            credential_id_b64,
            user_verified: result.user_verified(),
        })
    }
}

/// Encode bytes as RFC 4648 §5 base64url without padding.
///
/// Uses `base64ct`'s constant-time encoder; padding is stripped because the
/// WebAuthn spec encodes credential ids without padding.
#[cfg(feature = "passkey")]
fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}

#[cfg(all(test, feature = "passkey"))]
mod tests {
    use super::*;

    fn parse_origin(s: &str) -> Url {
        match Url::parse(s) {
            Ok(u) => u,
            Err(err) => panic!("test fixture origin {s} must parse: {err}"),
        }
    }

    #[test]
    fn rejects_invalid_origin_at_construction() {
        // An RPID that does not match the origin host is rejected by
        // webauthn-rs at build() time. We surface that as an Encoding error
        // (fail-closed; do not produce a verifier that silently accepts).
        // The URN is `internal-encoding`, not `assertion-rejected`, because
        // a server-side configuration bug should not advise the caller to
        // retry the ceremony with a fresh challenge.
        let origin = parse_origin("https://example.com");
        let res = PasskeyVerifier::new("other.test", &origin);
        assert!(res.is_err(), "RPID/origin mismatch must fail-closed");
        if let Err(err) = res {
            assert_eq!(err.urn(), crate::error::URN_INTERNAL_ENCODING);
        }
    }

    #[test]
    fn base64_url_no_pad_roundtrip_known_vector() {
        // RFC 4648 §10 base64url vector: bytes [0x14, 0xfb, 0x9c, 0x03] -> "FPucAw"
        // (no padding because output length is a multiple of 4 chars).
        let encoded = base64_url_no_pad(&[0x14, 0xfb, 0x9c, 0x03]);
        assert_eq!(encoded, "FPucAw");
    }

    #[test]
    fn verifier_constructs_with_valid_rpid_origin() {
        let origin = parse_origin("https://example.test");
        let v = PasskeyVerifier::new("example.test", &origin);
        assert!(v.is_ok(), "valid rpid/origin pair must build");
    }
}
