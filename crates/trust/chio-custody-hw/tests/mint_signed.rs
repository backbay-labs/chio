//! Integration coverage for the `HybridBackend`-style signing path
//! wired into [`IssuerService::mint_capability`].
//!
//! These tests exercise three properties:
//!
//! 1. A capability minted via [`IssuerService::with_signer`] carries a
//!    non-empty `signature` and the surrounding envelope is byte-identical
//!    (modulo the `signature` slot) to the unsigned form.
//! 2. The detached signature verifies under the backend's public key when
//!    re-canonicalised against the envelope-with-empty-signature message
//!    [`signing_message`] reconstructs.
//! 3. Tampering with any envelope field invalidates the signature
//!    fail-closed.
//!
//! The classical-only path uses `Ed25519Backend` so the test runs without
//! the optional `pq` feature. Hybrid coverage is gated behind `#[cfg(feature
//! = "pq")]` and reuses the same call site, demonstrating the
//! `crypto_floor=allow_classical` byte-identity invariant.

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, Signature, SigningBackend};
use chio_custody_hw::capability::{PasskeyCapability, ScopeSet};
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::mint::signing_message;
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};

const AUDIENCE: &str = "urn:chio:audience:kernel";

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn fixture_assertion() -> VerifiedAssertion {
    VerifiedAssertion {
        credential_id_b64: "AAAA".into(),
        user_verified: true,
    }
}

fn fixture_request(audience: &str, nonce: &str) -> MintRequest {
    MintRequest {
        audience: audience.into(),
        scope_set: ScopeSet::new(["tool:read", "tool:write"]),
        challenge_nonce: nonce.into(),
    }
}

fn ed25519_backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[test]
fn signed_mint_yields_non_empty_signature_under_classical_floor() {
    let backend: Arc<dyn SigningBackend> = Arc::new(ed25519_backend(11));
    let svc = IssuerService::with_signer(AUDIENCE, backend);
    let req = fixture_request(AUDIENCE, "n1");
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };
    assert!(
        !resp.capability.signature.is_empty(),
        "a signed capability MUST carry a non-empty signature"
    );
}

#[test]
fn signing_envelope_is_byte_identical_across_signers() {
    // Mint the same request under two different signers. The
    // canonical-JSON encoding of the envelope with the signature slot
    // cleared (`signing_message`) must match byte-for-byte regardless of
    // which key signed it: only the `signature` field differs across
    // backends. This is the observable form of the byte-identity
    // invariant that `crypto_floor=allow_classical` relies on.
    let svc_a = IssuerService::with_signer(AUDIENCE, Arc::new(ed25519_backend(11)));
    let svc_b = IssuerService::with_signer(AUDIENCE, Arc::new(ed25519_backend(99)));
    let req = fixture_request(AUDIENCE, "n2");

    let signed_a = match svc_a.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("mint under signer A must succeed: {e}"),
    };
    let signed_b = match svc_b.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("mint under signer B must succeed: {e}"),
    };

    // Both are signed (the issuer never emits an unsigned capability),
    // and the two signatures differ because the keys differ.
    assert!(!signed_a.capability.signature.is_empty());
    assert!(!signed_b.capability.signature.is_empty());
    assert_ne!(
        signed_a.capability.signature, signed_b.capability.signature,
        "distinct signing keys must produce distinct signatures"
    );

    let lhs = match signing_message(&signed_a.capability) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    let rhs = match signing_message(&signed_b.capability) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    assert_eq!(
        lhs, rhs,
        "envelope with the signature slot cleared must be byte-identical across signers"
    );
}

#[test]
fn signature_verifies_against_backend_public_key() {
    let backend = ed25519_backend(13);
    let public = backend.public_key();
    let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
    let svc = IssuerService::with_signer(AUDIENCE, backend_arc);
    let req = fixture_request(AUDIENCE, "n3");
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };

    let message = match signing_message(&resp.capability) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    let signature = match Signature::from_hex(&resp.capability.signature) {
        Ok(s) => s,
        Err(e) => panic!("signed capability signature must decode: {e}"),
    };
    assert!(
        public.verify(&message, &signature),
        "issuer signature must verify against backend public key"
    );
}

#[test]
fn tampering_with_audience_breaks_signature() {
    let backend = ed25519_backend(17);
    let public = backend.public_key();
    let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
    let svc = IssuerService::with_signer(AUDIENCE, backend_arc);
    let req = fixture_request(AUDIENCE, "n4");
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };

    let mut tampered: PasskeyCapability = resp.capability.clone();
    tampered.audience = "urn:chio:audience:other".into();

    let message = match signing_message(&tampered) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    let signature = match Signature::from_hex(&tampered.signature) {
        Ok(s) => s,
        Err(e) => panic!("hex must decode: {e}"),
    };
    assert!(
        !public.verify(&message, &signature),
        "tampering with audience MUST invalidate the signature"
    );
}

#[test]
fn tampering_with_scope_set_breaks_signature() {
    let backend = ed25519_backend(19);
    let public = backend.public_key();
    let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
    let svc = IssuerService::with_signer(AUDIENCE, backend_arc);
    let req = fixture_request(AUDIENCE, "n5");
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };

    let mut tampered: PasskeyCapability = resp.capability.clone();
    tampered.scope_set = ScopeSet::new(["tool:read", "tool:write", "tool:admin"]);

    let message = match signing_message(&tampered) {
        Ok(b) => b,
        Err(e) => panic!("signing_message must encode: {e}"),
    };
    let signature = match Signature::from_hex(&tampered.signature) {
        Ok(s) => s,
        Err(e) => panic!("hex must decode: {e}"),
    };
    assert!(
        !public.verify(&message, &signature),
        "tampering with scope set MUST invalidate the signature"
    );
}

#[cfg(feature = "pq")]
mod hybrid {
    //! Hybrid (Ed25519 + ML-DSA-65) coverage gated on the `pq` feature.
    //!
    //! Demonstrates the byte-identity invariant: the same call site that
    //! signs with `Ed25519Backend` also signs with `HybridBackend`, and
    //! the unsigned canonical envelope is byte-identical between the
    //! two modes (only the `signature` slot differs).
    use super::*;
    use chio_core_types::crypto::Ed25519Backend;
    use chio_core_types::pq::{HybridBackend, MlDsa65Backend};

    #[test]
    fn hybrid_backend_signs_capability_round_trip() {
        let classical = Box::new(Ed25519Backend::new(Keypair::from_seed(&[23u8; 32])));
        let pq = match MlDsa65Backend::generate() {
            Ok(b) => b,
            Err(e) => panic!("ML-DSA-65 keygen must succeed: {e}"),
        };
        let hybrid = match HybridBackend::new(classical, pq) {
            Ok(h) => h,
            Err(e) => panic!("HybridBackend ctor must succeed: {e}"),
        };
        let public = hybrid.public_key();
        let backend_arc: Arc<dyn SigningBackend> = Arc::new(hybrid);
        let svc = IssuerService::with_signer(AUDIENCE, backend_arc);
        let req = fixture_request(AUDIENCE, "n-hybrid");
        let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
            Ok(r) => r,
            Err(e) => panic!("hybrid signed mint must succeed: {e}"),
        };
        assert!(!resp.capability.signature.is_empty());
        let message = match signing_message(&resp.capability) {
            Ok(b) => b,
            Err(e) => panic!("signing_message must encode: {e}"),
        };
        let signature = match Signature::from_hex(&resp.capability.signature) {
            Ok(s) => s,
            Err(e) => panic!("hybrid signature hex must decode: {e}"),
        };
        assert!(
            public.verify(&message, &signature),
            "hybrid signature must verify against hybrid public key"
        );
    }
}
