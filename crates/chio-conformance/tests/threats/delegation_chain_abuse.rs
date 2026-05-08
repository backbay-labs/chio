// Threat test for threat ID `delegation_chain_abuse`.
//
// Threat: delegation_chain_abuse (Delegation chain abuse).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_kernel_core::verify_capability_with_trusted_and_floor` function
// directly. The function chains the legacy issuer-trust, signature,
// crypto-floor, and time-window checks in a single fail-closed pass and
// is the public verifier surface delegation chains route through. Drive
// it with three attacker inputs that exercise distinct deny branches:
//
//   1. UntrustedIssuer -- the attacker signs a capability with their
//      own key K_attacker, then presents it to a verifier whose trust
//      set contains only K_authority. Production MUST reject.
//   2. InvalidSignature -- the attacker forges a delegated capability
//      bearing the legitimate issuer's identity but mutates a
//      signed-body field after the legitimate issuer signed. Production
//      MUST reject before the time-window check is reached.
//   3. Expired -- the attacker resurrects a previously-valid
//      delegation past its expiry. Production MUST reject the stale
//      capability.
//
// Production call site:
// `crates/chio-kernel-core/src/capability_verify.rs:275`
// (`verify_capability_with_trusted_and_floor`).
//
// Revert-to-prove-it-fails recipe (trj5/A2 evidence backfill):
// In `crates/chio-kernel-core/src/capability_verify.rs`, locate the
// `if !trusted_issuers.contains(&token.issuer) { return
// Err(CapabilityError::UntrustedIssuer); }` guard inside
// `verify_capability_with_floor` (around line 158). Delete the guard
// (replace with `let _ = trusted_issuers;`). Re-run
// `cargo test -p chio-conformance --test threats -- delegation_chain_abuse`
// and the
// `assert!(matches!(err, CapabilityError::UntrustedIssuer))` arm MUST
// then fail because production now admits any-issuer capabilities.
// That fault injection demonstrates the assertion is wired to the
// production trust-set deny branch.

use chio_core::capability::{
    CapabilityCryptoFloor, CapabilityToken, CapabilityTokenBody, ChioScope,
};
use chio_core::crypto::Keypair;
use chio_kernel_core::capability_verify::{
    verify_capability_with_trusted_and_floor, CapabilityError,
};
use chio_kernel_core::clock::FixedClock;

fn signed_cap(
    issuer: &Keypair,
    subject: &Keypair,
    cap_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: cap_id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
    };
    match CapabilityToken::sign(body, issuer) {
        Ok(token) => token,
        Err(err) => panic!("capability fixture must sign: {err}"),
    }
}

#[test]
fn threat_delegation_chain_abuse_untrusted_issuer_rejected() {
    // covers: delegation_chain_abuse
    //
    // Attacker scenario: a delegated capability is signed by an
    // attacker key that is not in the verifier's trust root set.
    // Production verify_capability_with_trusted_and_floor MUST deny.
    let authority = Keypair::generate();
    let attacker = Keypair::generate();
    let subject = Keypair::generate();

    let token = signed_cap(&attacker, &subject, "cap-attacker-root", 100, 200);
    let clock = FixedClock::new(150);

    let err = match verify_capability_with_trusted_and_floor(
        &token,
        std::iter::once(authority.public_key()),
        &clock,
        CapabilityCryptoFloor::AllowClassical,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_trusted_and_floor MUST reject when the \
             token's issuer is not in the trusted set; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::UntrustedIssuer),
        "expected CapabilityError::UntrustedIssuer, got {err:?}"
    );
}

#[test]
fn threat_delegation_chain_abuse_tampered_signature_rejected() {
    // covers: delegation_chain_abuse
    //
    // Attacker scenario: an attacker mutates a signed delegation body
    // (here: the capability id). The canonical-JSON signing payload no
    // longer matches the signature; the production verifier MUST
    // reject before any time-window check fires.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let mut token = signed_cap(&authority, &subject, "cap-genuine", 100, 200);

    // Tamper the body without re-signing.
    token.id = "cap-attacker-claimed-id".to_string();

    let clock = FixedClock::new(150);
    let err = match verify_capability_with_trusted_and_floor(
        &token,
        std::iter::once(authority.public_key()),
        &clock,
        CapabilityCryptoFloor::AllowClassical,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_trusted_and_floor MUST reject a \
             tampered signed body; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::InvalidSignature),
        "expected CapabilityError::InvalidSignature, got {err:?}"
    );
}

#[test]
fn threat_delegation_chain_abuse_expired_capability_rejected() {
    // covers: delegation_chain_abuse
    //
    // Attacker scenario: an attacker resurrects a delegation past its
    // expires_at and tries to use it after the validity window has
    // closed. Production MUST reject.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_cap(&authority, &subject, "cap-stale", 100, 200);

    // Verify with a clock past expires_at.
    let clock = FixedClock::new(300);
    let err = match verify_capability_with_trusted_and_floor(
        &token,
        std::iter::once(authority.public_key()),
        &clock,
        CapabilityCryptoFloor::AllowClassical,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_trusted_and_floor MUST reject a \
             capability past its expires_at; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::Expired),
        "expected CapabilityError::Expired, got {err:?}"
    );
}

#[test]
fn threat_delegation_chain_abuse_legitimate_capability_round_trips() {
    // covers: delegation_chain_abuse
    //
    // Sanity arm: a freshly-issued capability whose issuer IS in the
    // trust set passes verification at a clock value inside its
    // validity window. Guards against an over-rejecting deny path
    // that would silently classify all delegations as abuse.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_cap(&authority, &subject, "cap-legit", 100, 200);

    let clock = FixedClock::new(150);
    if let Err(err) = verify_capability_with_trusted_and_floor(
        &token,
        std::iter::once(authority.public_key()),
        &clock,
        CapabilityCryptoFloor::AllowClassical,
    ) {
        panic!(
            "legitimate delegation MUST verify (otherwise the deny \
             guard is over-rejecting); got {err:?}"
        );
    }
}
