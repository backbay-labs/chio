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
//! # Replay resistance
//!
//! The verifier owns a per-credential nonce store keyed on
//! `(credential_id, challenge)`, where the challenge is the WebAuthn
//! challenge bound into the assertion's `clientDataJSON`. After
//! `webauthn-rs` accepts the assertion, the verifier records the
//! `(credential_id, challenge)` pair; presenting the SAME assertion a
//! second time fails closed with [`CustodyError::ReplayDetected`]. This
//! defends against assertion replay even when an attacker captures a
//! valid assertion in flight, complementing the issuer-side nonce store
//! (the two stores guard different boundaries: the verifier guards the
//! WebAuthn ceremony, the issuer guards capability minting).
//!
//! The store is injectable so a clustered deployment can replace the
//! default in-memory store with a durable / shared one; a fresh verifier
//! ships with an [`InMemoryPasskeyNonceStore`] so replay resistance is on
//! by default. The recorded retention bound is the verifier clock plus a
//! conservative window (see [`PasskeyVerifier::verify_assertion`]).

#[cfg(feature = "passkey")]
use std::sync::Arc;

#[cfg(feature = "passkey")]
use crate::error::CustodyError;
#[cfg(feature = "passkey")]
use crate::nonce_store::{
    InMemoryPasskeyNonceStore, PasskeyNonceStore, RecordOutcome, DEFAULT_CLOCK_SKEW_SECONDS,
};
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

/// Verifier-side replay retention window, in seconds.
///
/// A WebAuthn challenge is single-use within one authentication ceremony.
/// `webauthn-rs` pins a five-minute authenticator timeout
/// (`DEFAULT_AUTHENTICATOR_TIMEOUT`), so a recorded `(credential_id,
/// challenge)` pair only needs to be retained long enough to cover a late
/// replay of a ceremony that could still have been accepted. We retain
/// for the five-minute ceremony window plus the standard clock-skew
/// tolerance, which is bounded and matches the capability lifetime the
/// issuer side already uses. Beyond this window the underlying challenge
/// is dead at the WebAuthn layer, so a stale record can be GC'd.
#[cfg(feature = "passkey")]
pub const VERIFIER_REPLAY_RETENTION_SECONDS: i64 = 300;

/// Thin wrapper over a `webauthn-rs` relying-party instance plus a
/// per-credential replay nonce store.
///
/// The verifier is reusable across requests. Per-assertion challenge state
/// (the [`PasskeyAuthentication`] handed back by
/// `start_passkey_authentication`) is the caller's responsibility to
/// persist across the issuer round trip; the verifier additionally keeps a
/// nonce store so a replayed assertion is rejected even if the caller's
/// challenge state was reused.
#[cfg(feature = "passkey")]
pub struct PasskeyVerifier {
    inner: Webauthn,
    nonce_store: Arc<dyn PasskeyNonceStore>,
    replay_retention_seconds: i64,
}

#[cfg(feature = "passkey")]
impl PasskeyVerifier {
    /// Build a verifier from a relying-party id and origin, wiring the
    /// default in-memory replay nonce store.
    ///
    /// Errors fall through unchanged from `WebauthnBuilder::build`. Misuse
    /// at this construction step is fail-closed: an invalid origin or RPID
    /// returns `Err(CustodyError::Encoding)` (mapped to
    /// `urn:chio:error:custody:internal-encoding`) rather than producing a
    /// verifier that silently accepts mismatched assertions. The URN is
    /// distinct from `assertion-rejected` so callers do not retry the
    /// ceremony on a server-side configuration bug.
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self, CustodyError> {
        Self::with_nonce_store(rp_id, rp_origin, Arc::new(InMemoryPasskeyNonceStore::new()))
    }

    /// Build a verifier with an injected [`PasskeyNonceStore`].
    ///
    /// Use this to share a durable / distributed replay store across a
    /// cluster of verifier instances so a replay is detected regardless of
    /// which node observed the original assertion.
    pub fn with_nonce_store(
        rp_id: &str,
        rp_origin: &Url,
        nonce_store: Arc<dyn PasskeyNonceStore>,
    ) -> Result<Self, CustodyError> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|err| CustodyError::Encoding(format!("WebauthnBuilder::new failed: {err}")))?;
        let inner = builder.build().map_err(|err| {
            CustodyError::Encoding(format!("WebauthnBuilder::build failed: {err}"))
        })?;
        Ok(Self {
            inner,
            nonce_store,
            replay_retention_seconds: VERIFIER_REPLAY_RETENTION_SECONDS,
        })
    }

    /// Verify a WebAuthn assertion against pre-issued challenge state and
    /// reject replays.
    ///
    /// `now_unix_seconds` is the verifier clock; it sets the retention
    /// bound for the recorded `(credential_id, challenge)` pair
    /// (`now + VERIFIER_REPLAY_RETENTION_SECONDS + clock_skew`). Passing
    /// the verifier clock (rather than reading the system clock inside the
    /// verifier) keeps the replay window deterministic under test and lets
    /// a deployment pin a single authoritative clock source.
    ///
    /// Fail-closed paths:
    /// - any structural failure (malformed CBOR, missing fields, wrong
    ///   origin, signature mismatch, counter regression) returns
    ///   [`CustodyError::AssertionRejected`]
    ///   (`urn:chio:error:custody:assertion-rejected`);
    /// - a `(credential_id, challenge)` pair already recorded returns
    ///   [`CustodyError::ReplayDetected`]
    ///   (`urn:chio:error:custody:replay-detected`). The replay check runs
    ///   AFTER `webauthn-rs` accepts the assertion so only genuine,
    ///   cryptographically-valid assertions ever advance the nonce store.
    pub fn verify_assertion(
        &self,
        state: &PasskeyAuthentication,
        assertion: &PublicKeyCredential,
        now_unix_seconds: i64,
    ) -> Result<VerifiedAssertion, CustodyError> {
        // Recover the challenge bound into the assertion BEFORE handing it
        // to webauthn-rs so the replay key is derived from the same bytes
        // the authenticator signed over. webauthn-rs independently checks
        // the challenge against `state`; this extraction is only for the
        // replay key, not a substitute for that check.
        let challenge_b64url = challenge_from_assertion(assertion)?;

        let result = self
            .inner
            .finish_passkey_authentication(assertion, state)
            .map_err(|err| CustodyError::AssertionRejected(format!("{err:?}")))?;

        // The credential id is intentionally serialised as base64url string
        // form so downstream capability minting and the revocation
        // oracle key on a stable transport-friendly identifier.
        let cred_id = result.cred_id();
        let credential_id_b64 = base64_url_no_pad(cred_id.as_ref());

        // Replay resistance. Record the (credential_id, challenge) pair;
        // a duplicate is a replayed assertion and is denied fail-closed.
        // The retention bound covers the WebAuthn ceremony window.
        let retain_until = now_unix_seconds
            .saturating_add(self.replay_retention_seconds)
            .saturating_add(DEFAULT_CLOCK_SKEW_SECONDS);
        match self.nonce_store.record_if_fresh(
            &credential_id_b64,
            &challenge_b64url,
            retain_until,
        )? {
            RecordOutcome::Fresh => {}
            RecordOutcome::Replayed => {
                return Err(CustodyError::ReplayDetected {
                    credential_id: credential_id_b64,
                });
            }
        }

        Ok(VerifiedAssertion {
            credential_id_b64,
            user_verified: result.user_verified(),
        })
    }
}

/// Extract the base64url-no-pad WebAuthn challenge from an assertion's
/// `clientDataJSON`.
///
/// The challenge is the replay key. Failure to recover it is treated as
/// an assertion rejection (fail-closed): an assertion whose client data is
/// not parseable JSON, or is missing the `challenge` member, is not a
/// well-formed WebAuthn assertion and must not advance the replay store
/// nor be accepted.
#[cfg(feature = "passkey")]
fn challenge_from_assertion(assertion: &PublicKeyCredential) -> Result<String, CustodyError> {
    use serde::Deserialize;

    /// Minimal projection of `CollectedClientData`: we only need the
    /// challenge. Deserialising a narrow struct keeps the replay key
    /// independent of upstream `clientDataJSON` extensions.
    #[derive(Deserialize)]
    struct ClientDataChallenge {
        challenge: String,
    }

    let raw = assertion.response.client_data_json.as_ref();
    if raw.is_empty() {
        return Err(CustodyError::AssertionRejected(
            "assertion clientDataJSON is empty".into(),
        ));
    }
    let parsed: ClientDataChallenge = serde_json::from_slice(raw).map_err(|err| {
        CustodyError::AssertionRejected(format!("assertion clientDataJSON parse failed: {err}"))
    })?;
    if parsed.challenge.is_empty() {
        return Err(CustodyError::AssertionRejected(
            "assertion clientDataJSON challenge is empty".into(),
        ));
    }
    Ok(parsed.challenge)
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

    /// Build a `PublicKeyCredential` from a clientDataJSON document by
    /// deserialising the assertion wire shape. The authenticator data and
    /// signature are placeholders: these tests exercise only the
    /// challenge-extraction and replay-keying logic, which runs off the
    /// clientDataJSON, not the signature.
    fn assertion_with_client_data(client_data_json: &str) -> PublicKeyCredential {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let cdj_b64 = Base64UrlUnpadded::encode_string(client_data_json.as_bytes());
        let json = format!(
            r#"{{
                "id": "Y3JlZA",
                "rawId": "Y3JlZA",
                "type": "public-key",
                "response": {{
                    "authenticatorData": "AA",
                    "clientDataJSON": "{cdj_b64}",
                    "signature": "AA"
                }}
            }}"#
        );
        match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(e) => panic!("assertion fixture must deserialise: {e}"),
        }
    }

    #[test]
    fn challenge_extraction_recovers_webauthn_challenge() {
        let cred = assertion_with_client_data(
            r#"{"type":"webauthn.get","challenge":"Q0hBTExFTkdF","origin":"https://example.test"}"#,
        );
        let challenge = match challenge_from_assertion(&cred) {
            Ok(c) => c,
            Err(e) => panic!("challenge extraction must succeed: {e}"),
        };
        assert_eq!(challenge, "Q0hBTExFTkdF");
    }

    #[test]
    fn challenge_extraction_fails_closed_on_malformed_client_data() {
        let cred = assertion_with_client_data("not json at all");
        let res = challenge_from_assertion(&cred);
        let err = match res {
            Ok(_) => panic!("malformed clientDataJSON must fail closed"),
            Err(e) => e,
        };
        assert!(matches!(err, CustodyError::AssertionRejected(_)));
        assert_eq!(err.urn(), crate::error::URN_ASSERTION_REJECTED);
    }

    #[test]
    fn challenge_extraction_fails_closed_when_challenge_missing() {
        let cred = assertion_with_client_data(
            r#"{"type":"webauthn.get","origin":"https://example.test"}"#,
        );
        let res = challenge_from_assertion(&cred);
        assert!(
            matches!(res, Err(CustodyError::AssertionRejected(_))),
            "a clientDataJSON without a challenge must be rejected"
        );
    }

    #[test]
    fn challenge_extraction_fails_closed_on_empty_challenge() {
        let cred = assertion_with_client_data(
            r#"{"type":"webauthn.get","challenge":"","origin":"https://example.test"}"#,
        );
        assert!(matches!(
            challenge_from_assertion(&cred),
            Err(CustodyError::AssertionRejected(_))
        ));
    }

    #[test]
    fn verifier_replay_key_rejects_duplicate_credential_challenge_pair() {
        // The verifier records (credential_id, challenge) after a
        // successful assertion. This test pins the exact keying the
        // verifier uses against the nonce store: the SAME pair recorded
        // twice is a replay. (The full verify_assertion path additionally
        // requires a cryptographically-valid assertion, exercised by the
        // integration suite; here we isolate the replay-keying contract.)
        let store = InMemoryPasskeyNonceStore::new();
        let cred = "Y3JlZA";
        let challenge = "Q0hBTExFTkdF";
        let retain_until = 1_000 + VERIFIER_REPLAY_RETENTION_SECONDS + DEFAULT_CLOCK_SKEW_SECONDS;
        match store.record_if_fresh(cred, challenge, retain_until) {
            Ok(RecordOutcome::Fresh) => {}
            other => panic!("first observation must be fresh: {other:?}"),
        }
        match store.record_if_fresh(cred, challenge, retain_until) {
            Ok(RecordOutcome::Replayed) => {}
            other => panic!("second observation of the same pair must be a replay: {other:?}"),
        }
    }
}
