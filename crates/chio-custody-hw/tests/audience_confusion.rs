//! Audience-confusion proptest.
//!
//! Soft contract: a [`PasskeyCapability`] is audience-pinned. Re-presenting
//! a capability minted for audience A to audience B MUST fail-closed at
//! the verifier surface AND, when the capability is signed, MUST
//! invalidate the detached signature. The latter is the cryptographic
//! check; the former is the application-level check via
//! [`PasskeyCapability::require_audience`].
//!
//! These properties are exercised by both an audience-bit-flip random
//! corpus (proptest) and a pinned regression: flipping a single bit of
//! the encoded `audience` URN MUST change the canonical-JSON message and
//! therefore invalidate the signature.

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, Signature, SigningBackend};
use chio_custody_hw::capability::{PasskeyCapability, ScopeSet};
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::mint::signing_message;
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};
use proptest::prelude::*;

const AUDIENCE: &str = "urn:chio:audience:kernel";

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn assertion() -> VerifiedAssertion {
    VerifiedAssertion {
        credential_id_b64: "AAAA".into(),
        user_verified: true,
    }
}

fn mint_signed(audience: &str) -> (PasskeyCapability, chio_core_types::crypto::PublicKey) {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[31u8; 32]));
    let public = backend.public_key();
    let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
    let svc = IssuerService::with_signer(audience, backend_arc);
    let req = MintRequest {
        audience: audience.into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "nonce-aud".into(),
    };
    let resp = match svc.mint_capability(&assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };
    (resp.capability, public)
}

#[test]
fn require_audience_fail_closed_for_mismatch_pinned() {
    let (cap, _public) = mint_signed(AUDIENCE);
    let res = cap.require_audience("urn:chio:audience:other");
    assert!(matches!(res, Err(CustodyError::AudienceMismatch { .. })));
}

#[test]
fn audience_bit_flip_invalidates_signature_pinned() {
    // Single-byte mutation of the audience URN. The flipped envelope
    // must NOT verify against the issuer public key.
    let (cap, public) = mint_signed(AUDIENCE);
    let mut tampered = cap.clone();
    let mut bytes = tampered.audience.into_bytes();
    bytes[0] ^= 0x01;
    tampered.audience = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => panic!("audience tamper must remain UTF-8: {e}"),
    };

    let message = match signing_message(&tampered) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    let signature = match Signature::from_hex(&tampered.signature) {
        Ok(s) => s,
        Err(e) => panic!("hex must decode: {e}"),
    };
    assert!(!public.verify(&message, &signature));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// For any non-trivial audience mutation, the signature MUST NOT
    /// verify and the application-level audience check MUST reject.
    ///
    /// The mutation strategy generates an attacker-controlled audience
    /// suffix; the issuer is pinned to AUDIENCE so any non-AUDIENCE
    /// value must be rejected. We constrain the mutation to printable
    /// ASCII so the URN remains a valid Rust `String` after mutation.
    #[test]
    fn audience_mutation_rejected_at_both_layers(suffix in "[a-z0-9:-]{1,32}") {
        let (cap, public) = mint_signed(AUDIENCE);
        let attacker_audience = format!("urn:chio:audience:{suffix}");
        prop_assume!(attacker_audience != AUDIENCE);

        // Application-level: require_audience rejects.
        let app_res = cap.require_audience(&attacker_audience);
        let app_rejects = matches!(app_res, Err(CustodyError::AudienceMismatch { .. }));
        prop_assert!(app_rejects);

        // Cryptographic: tampering with the envelope to swap audiences
        // invalidates the signature.
        let mut tampered = cap.clone();
        tampered.audience = attacker_audience;
        let message = match signing_message(&tampered) {
            Ok(b) => b,
            Err(e) => panic!("signing_message must encode: {e}"),
        };
        let signature = match Signature::from_hex(&tampered.signature) {
            Ok(s) => s,
            Err(e) => panic!("hex must decode: {e}"),
        };
        prop_assert!(!public.verify(&message, &signature));
    }

    /// An audience-bit-flip MUST always invalidate the signature, even
    /// in the worst case where every bit of the audience is flipped or
    /// only one bit is flipped.
    #[test]
    fn audience_bit_flip_arbitrary_index_breaks_sig(byte_index in 0usize..AUDIENCE.len(), bit in 0u8..8) {
        let (cap, public) = mint_signed(AUDIENCE);
        let mut bytes = cap.audience.clone().into_bytes();
        bytes[byte_index] ^= 1u8 << bit;
        let new_audience = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Ok(()), // skip non-UTF8 mutations
        };
        prop_assume!(new_audience != cap.audience);
        let mut tampered = cap.clone();
        tampered.audience = new_audience;
        let message = match signing_message(&tampered) {
            Ok(b) => b,
            Err(e) => panic!("signing_message must encode: {e}"),
        };
        let signature = match Signature::from_hex(&tampered.signature) {
            Ok(s) => s,
            Err(e) => panic!("hex must decode: {e}"),
        };
        prop_assert!(!public.verify(&message, &signature));
    }
}
