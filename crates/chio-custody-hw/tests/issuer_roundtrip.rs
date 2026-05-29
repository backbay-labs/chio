//! Issuer round-trip integration test.
//!
//! Drives the [`IssuerService::mint_capability`] entry point with a
//! verified-assertion fixture and asserts that the resulting capability is
//! audience-pinned, scope-pinned, lifetime-pinned, and signed (the issuer
//! never emits an unsigned capability).

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_custody_hw::capability::{PasskeyCapability, ScopeSet, CAPABILITY_LIFETIME_SECONDS};
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn signer() -> Arc<dyn SigningBackend> {
    Arc::new(Ed25519Backend::new(Keypair::from_seed(&[29u8; 32])))
}

fn issuer(audience: &str) -> IssuerService {
    IssuerService::with_signer(audience, signer())
}

fn fixture_assertion() -> VerifiedAssertion {
    VerifiedAssertion {
        credential_id_b64: "AAAA-credential-id".into(),
        user_verified: true,
    }
}

#[test]
fn round_trip_mint_then_verify_audience_and_lifetime() {
    let svc = issuer("urn:chio:audience:kernel");
    let req = MintRequest {
        audience: "urn:chio:audience:kernel".into(),
        scope_set: ScopeSet::new(["tool:read", "tool:write"]),
        challenge_nonce: "nonce-roundtrip".into(),
    };

    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("mint must succeed: {e}"),
    };

    // Audience must round-trip from issuer config (NOT from caller input
    // beyond the equality check).
    assert_eq!(resp.capability.audience, "urn:chio:audience:kernel");

    // Capability must accept the audience it was minted for.
    if let Err(e) = resp.capability.require_audience("urn:chio:audience:kernel") {
        panic!("capability must accept its own audience: {e}");
    }

    // Capability must reject any other audience fail-closed.
    let mismatch = resp.capability.require_audience("urn:chio:audience:other");
    assert!(matches!(
        mismatch,
        Err(CustodyError::AudienceMismatch { .. })
    ));

    // Lifetime is exactly 5 minutes.
    assert_eq!(
        (resp.capability.exp - resp.capability.iat).num_seconds(),
        CAPABILITY_LIFETIME_SECONDS
    );

    // Capability is live at iat and not live past exp.
    assert!(resp.capability.is_live(resp.capability.iat));
    assert!(!resp.capability.is_live(resp.capability.exp));
}

#[test]
fn round_trip_canonical_json_survives_mint() {
    let svc = issuer("urn:chio:audience:kernel");
    let req = MintRequest {
        audience: "urn:chio:audience:kernel".into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "n2".into(),
    };
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("mint must succeed: {e}"),
    };
    let bytes = match resp.capability.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("canonical-json encode must succeed: {e}"),
    };
    let decoded = match PasskeyCapability::from_canonical_json(&bytes) {
        Ok(c) => c,
        Err(e) => panic!("canonical-json decode must succeed: {e}"),
    };
    assert_eq!(decoded, resp.capability);
}

#[test]
fn issuer_rejects_audience_mismatch_in_request() {
    let svc = issuer("urn:chio:audience:kernel");
    let req = MintRequest {
        audience: "urn:chio:audience:other".into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "n3".into(),
    };
    let res = svc.mint_capability(&fixture_assertion(), &req, fixed_now());
    let err = match res {
        Ok(_) => panic!("audience mismatch must fail-closed"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::AudienceMismatch { .. }));
    assert_eq!(err.urn(), "urn:chio:error:custody:audience-mismatch");
}

#[test]
fn minted_capability_is_always_signed() {
    let svc = issuer("urn:chio:audience:kernel");
    let req = MintRequest {
        audience: "urn:chio:audience:kernel".into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "n4".into(),
    };
    let resp = match svc.mint_capability(&fixture_assertion(), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("mint must succeed: {e}"),
    };
    assert!(
        !resp.capability.signature.is_empty(),
        "the issuer signs every capability; an unsigned capability is impossible"
    );
}
