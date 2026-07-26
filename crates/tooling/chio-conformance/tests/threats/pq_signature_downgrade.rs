// Threat test for threat ID `pq_signature_downgrade`.
//
// Threat: pq_signature_downgrade (Post-quantum signature downgrade).
// Surfaces: trust_control, hosted_mcp, native_chio.
//
// Coverage strategy: import the production
// `chio_kernel_core::capability_verify::verify_capability_with_floor`
// directly. The downgrade attack is the family where an attacker
// presents a classical-only Ed25519 signed capability under a
// kernel that has been configured with `crypto_floor = pq_required`.
// Production MUST reject with `CapabilityError::CryptoFloorRejected`
// before any trust / time / budget surface is reached.
//
// Scope of this partial row: only verifier-side floor enforcement is
// exercised (`verify_capability_with_floor` -> `CapabilityToken::
// verify_signature_with_floor`). The hybrid-PQ wire-format SIGNING
// path (kernel minting hybrid-prefix signatures with ML-DSA-65 alongside
// Ed25519) is not wired, so the row "verifiers MUST dispatch from the
// signature prefix" is structural-only and that signing path is out of
// scope here. This conformance test pins the verifier's REJECTION of a
// downgrade attempt under `pq_required` -- the front line of defense
// that prevents an attacker from getting a classical-only token
// admitted on a PQ-required kernel.
//
// Three sub-vectors:
//
//   1. Floor downgrade. A token signed with classical Ed25519 is
//      presented to a verifier configured with
//      `CapabilityCryptoFloor::PqRequired`. Production MUST reject
//      with `CapabilityError::CryptoFloorRejected`.
//   2. Floor enforcement is selective. The same token under
//      `CapabilityCryptoFloor::AllowClassical` MUST verify
//      successfully so the test cannot trivially deny by misusing
//      the token fixture.
//   3. Floor wire identifiers stable. Pin the
//      `CapabilityCryptoFloor::as_str()` strings (`allow_classical`,
//      `allow_hybrid`, `pq_required`) so a future rename does not
//      silently invalidate the policy YAML loaders that map operator-
//      configured strings into this enum.
//
// Production call sites:
//   `crates/chio-kernel-core/src/capability_verify.rs:148`
//     (`verify_capability_with_floor`).
//   `crates/chio-core-types/src/capability.rs` (`CapabilityCryptoFloor`,
//     `CapabilityToken::verify_signature_with_floor`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-kernel-core/src/capability_verify.rs`, locate the
// `match token.verify_signature_with_floor(crypto_floor) { ... }`
// block inside `verify_capability_with_floor` (around line 162).
// Replace the
// `Err(error) => return Err(CapabilityError::CryptoFloorRejected(...))`
// arm with a no-op (e.g. `Err(_) => {}`). Re-run
// `cargo test -p chio-conformance --test threats -- pq_signature_downgrade`
// and the
// `assert!(matches!(err, CapabilityError::CryptoFloorRejected(_)))`
// arm in `classical_token_under_pq_required_rejected` MUST then
// fail because production now accepts classical-only tokens on a
// pq_required kernel.

use chio_core::capability::{
    crypto_floor::CapabilityCryptoFloor,
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_core::capability_verify::{verify_capability_with_floor, CapabilityError};
use chio_kernel_core::clock::FixedClock;
use chio_kernel_core::NoopBudgetRegistry;

fn signed_classical_token(
    issuer: &Keypair,
    subject: &Keypair,
    cap_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    // Classical Ed25519 signing (CapabilityToken::sign uses the issuer's
    // Ed25519 keypair under the hood; algorithm field is left as
    // None which downstream interprets as classical Ed25519).
    let body = CapabilityTokenBody {
        id: cap_id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    match CapabilityToken::sign(body, issuer) {
        Ok(token) => token,
        Err(err) => panic!("classical capability fixture must sign: {err}"),
    }
}

#[test]
fn threat_pq_signature_downgrade_classical_token_under_pq_required_rejected() {
    // covers: pq_signature_downgrade
    //
    // Attacker scenario: a kernel operator has dialed the crypto
    // floor to `pq_required` because the deployment environment
    // requires hybrid PQ signatures on every capability. An attacker
    // presents a classical-only Ed25519 token (perhaps because the
    // attacker's issuer has not migrated to hybrid signing).
    // Production MUST reject with `CryptoFloorRejected` before any
    // trust / time / budget logic runs.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_classical_token(&authority, &subject, "cap-classical", 100, 200);

    let clock = FixedClock::new(150);
    let mut budgets = NoopBudgetRegistry;
    let err = match verify_capability_with_floor(
        &token,
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::PqRequired,
        &mut budgets,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_floor MUST reject a classical-only \
             token under crypto_floor=pq_required; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::CryptoFloorRejected(_)),
        "expected CapabilityError::CryptoFloorRejected, got {err:?}"
    );
}

#[test]
fn threat_pq_signature_downgrade_classical_token_under_allow_classical_round_trips() {
    // covers: pq_signature_downgrade (sanity)
    //
    // Sanity arm: the SAME classical token verifies successfully
    // when the kernel's floor is `allow_classical`. This guards
    // against an over-rejecting deny path that would silently fail
    // every classical-only token regardless of floor.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_classical_token(&authority, &subject, "cap-classical", 100, 200);

    let clock = FixedClock::new(150);
    let mut budgets = NoopBudgetRegistry;
    if let Err(err) = verify_capability_with_floor(
        &token,
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    ) {
        panic!(
            "classical token MUST verify under allow_classical floor \
             (over-rejecting); got {err:?}"
        );
    }
}

#[test]
fn threat_pq_signature_downgrade_floor_wire_identifiers_pinned() {
    // covers: pq_signature_downgrade
    //
    // Pin the operator-facing wire identifiers so a rename of the
    // `CapabilityCryptoFloor` variants (or their `as_str()` mapping)
    // cannot silently invalidate every policy YAML that loads
    // `crypto_floor: pq_required`. If this fires, do NOT update the
    // strings without a coordinated update to chio-policy and the
    // operator manifests in tree.
    assert_eq!(
        CapabilityCryptoFloor::AllowClassical.as_str(),
        "allow_classical"
    );
    assert_eq!(CapabilityCryptoFloor::AllowHybrid.as_str(), "allow_hybrid");
    assert_eq!(CapabilityCryptoFloor::PqRequired.as_str(), "pq_required");

    // Pin the algebraic relationships used by the verifier internal
    // dispatch: the policy gate's "allows hybrid" / "allows classical
    // only" derivation. A regression here would change WHICH tokens
    // the floor admits.
    assert!(!CapabilityCryptoFloor::AllowClassical.allows_hybrid());
    assert!(CapabilityCryptoFloor::AllowHybrid.allows_hybrid());
    assert!(CapabilityCryptoFloor::PqRequired.allows_hybrid());
    assert!(CapabilityCryptoFloor::AllowClassical.allows_classical_only());
    assert!(CapabilityCryptoFloor::AllowHybrid.allows_classical_only());
    assert!(!CapabilityCryptoFloor::PqRequired.allows_classical_only());
}
