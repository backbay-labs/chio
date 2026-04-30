//! Kernel-side passkey-capability dispatch coverage (M10.P2.T5).
//!
//! Asserts that [`chio_kernel::custody::PasskeyCapabilityVerifier`]:
//!
//! - accepts a freshly-minted, audience-matching, in-lifetime,
//!   correctly-signed [`chio_custody_hw::PasskeyCapability`],
//! - rejects empty signatures,
//! - rejects audience mismatches,
//! - rejects expired capabilities,
//! - rejects signatures from a foreign issuer key.
//!
//! Per the M10.P2.T5 soft-dep, the verifier surface is `&self`-only;
//! these tests therefore consume the verifier behind an `Arc<>` to make
//! the discipline observable from the test harness.

use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_custody_hw::capability::{PasskeyCapability, ScopeSet};
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::verifier::VerifiedAssertion;
use chio_kernel::custody::PasskeyCapabilityVerifier;
use chrono::{TimeZone, Utc};

const AUDIENCE: &str = "urn:chio:audience:kernel";

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn signed_capability(
    audience: &str,
    seed: u8,
) -> (PasskeyCapability, chio_core_types::crypto::PublicKey) {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[seed; 32]));
    let public = backend.public_key();
    let backend_arc: Arc<dyn SigningBackend> = Arc::new(backend);
    let svc = IssuerService::with_signer(audience, backend_arc);
    let req = MintRequest {
        audience: audience.into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "n-dispatch".into(),
    };
    let assertion = VerifiedAssertion {
        credential_id_b64: "AAAA".into(),
        user_verified: true,
    };
    let resp = match svc.mint_capability(&assertion, &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("signed mint must succeed: {e}"),
    };
    (resp.capability, public)
}

#[test]
fn dispatch_accepts_valid_capability() {
    let (cap, public) = signed_capability(AUDIENCE, 53);
    let verifier = Arc::new(PasskeyCapabilityVerifier::new(AUDIENCE, public));
    if let Err(e) = verifier.verify(&cap, fixed_now()) {
        panic!("matching capability must verify: {e}");
    }
}

#[test]
fn dispatch_rejects_empty_signature_fail_closed() {
    let (mut cap, public) = signed_capability(AUDIENCE, 53);
    cap.signature.clear();
    let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
    let res = verifier.verify(&cap, fixed_now());
    assert!(matches!(res, Err(CustodyError::AssertionRejected(_))));
}

#[test]
fn dispatch_rejects_audience_mismatch_fail_closed() {
    let (cap, public) = signed_capability("urn:chio:audience:other", 53);
    let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
    let res = verifier.verify(&cap, fixed_now());
    let err = match res {
        Ok(()) => panic!("audience mismatch MUST fail-closed"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::AudienceMismatch { .. }));
    assert_eq!(err.urn(), "urn:chio:error:custody:audience-mismatch");
}

#[test]
fn dispatch_rejects_expired_capability_fail_closed() {
    let (cap, public) = signed_capability(AUDIENCE, 53);
    let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, public);
    let later = cap.exp + chrono::Duration::seconds(1);
    let res = verifier.verify(&cap, later);
    let err = match res {
        Ok(()) => panic!("expired capability MUST fail-closed"),
        Err(e) => e,
    };
    assert!(matches!(err, CustodyError::CapabilityExpired));
    assert_eq!(err.urn(), "urn:chio:error:custody:capability-expired");
}

#[test]
fn dispatch_rejects_foreign_issuer_signature_fail_closed() {
    let (cap, _real_public) = signed_capability(AUDIENCE, 53);
    let foreign = Ed25519Backend::new(Keypair::from_seed(&[101u8; 32]));
    let foreign_public = foreign.public_key();
    let verifier = PasskeyCapabilityVerifier::new(AUDIENCE, foreign_public);
    let res = verifier.verify(&cap, fixed_now());
    assert!(matches!(res, Err(CustodyError::AssertionRejected(_))));
}

#[test]
fn verifier_is_send_sync_and_shared_behind_arc() {
    // No &mut self on the verifier surface (M10.P2.T5 soft-dep). The
    // verifier is consumable behind Arc<> across threads. We exercise
    // that explicitly so a future regression that introduces &mut self
    // would fail to compile this fixture.
    let (cap, public) = signed_capability(AUDIENCE, 53);
    let verifier = Arc::new(PasskeyCapabilityVerifier::new(AUDIENCE, public));
    let v_a = verifier.clone();
    let v_b = verifier.clone();
    let cap_a = cap.clone();
    let cap_b = cap.clone();
    let h_a = std::thread::spawn(move || v_a.verify(&cap_a, fixed_now()));
    let h_b = std::thread::spawn(move || v_b.verify(&cap_b, fixed_now()));
    let r_a = match h_a.join() {
        Ok(r) => r,
        Err(_) => panic!("verify thread A panicked"),
    };
    let r_b = match h_b.join() {
        Ok(r) => r,
        Err(_) => panic!("verify thread B panicked"),
    };
    assert!(r_a.is_ok());
    assert!(r_b.is_ok());
}
