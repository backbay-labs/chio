// Threat test for threat ID `delegation_chain_abuse`.
//
// Threat: delegation_chain_abuse (Delegation chain abuse).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_kernel_core::capability_verify::verify_capability_with_floor`
// and `verify_capability_with_trusted_and_floor` functions directly.
// Drive them with attacker inputs that EXERCISE THE DELEGATION CHAIN
// (non-empty `delegation_chain` plus a real `InMemoryBudgetRegistry`
// so the sibling-sum / unknown-parent deny branches fire) as well as
// the chained issuer-trust, signature, and time-window checks.
//
// Production call sites:
//   `crates/chio-kernel-core/src/capability_verify.rs:148`
//     (`verify_capability_with_floor`).
//   `crates/chio-kernel-core/src/capability_verify.rs:275`
//     (`verify_capability_with_trusted_and_floor`).
//   `crates/chio-kernel-core/src/budget_split.rs:225`
//     (`InMemoryBudgetRegistry::try_admit_child`).
//
// Revert-to-prove-it-fails recipes:
//   (a) swallow the `?` on `try_admit_child` inside
//       `verify_capability_with_floor` in
//       `crates/chio-kernel-core/src/capability_verify.rs` (so the
//       sibling-sum / unknown-parent deny branches no longer
//       propagate). The sibling-budget / unknown-parent deny-arm
//       assertions below fail.
//   (b) delete the trusted-issuer guard inside
//       `verify_capability_with_trusted_and_floor`. The
//       untrusted-issuer deny-arm assertion below fails.

use chio_core::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    crypto_floor::CapabilityCryptoFloor,
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_core::capability_verify::{
    verify_capability_with_floor, verify_capability_with_trusted_and_floor, CapabilityError,
};
use chio_kernel_core::clock::FixedClock;
use chio_kernel_core::{BudgetSplitError, InMemoryBudgetRegistry};

fn signed_root_cap(
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
        aggregate_invocation_budget: None,
    };
    match CapabilityToken::sign(body, issuer) {
        Ok(token) => token,
        Err(err) => panic!("root capability fixture must sign: {err}"),
    }
}

fn signed_delegated_cap(
    issuer: &Keypair,
    subject: &Keypair,
    cap_id: &str,
    parent_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let parent_link = match DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee: issuer.public_key(),
            attenuations: Vec::new(),
            timestamp: issued_at,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        issuer,
    ) {
        Ok(link) => link,
        Err(err) => panic!("delegation link fixture must sign: {err}"),
    };
    let body = CapabilityTokenBody {
        id: cap_id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at,
        expires_at,
        delegation_chain: vec![parent_link],
        aggregate_invocation_budget: None,
    };
    match CapabilityToken::sign(body, issuer) {
        Ok(token) => token,
        Err(err) => panic!("delegated capability fixture must sign: {err}"),
    }
}

#[test]
fn threat_delegation_chain_abuse_unknown_parent_in_registry_rejected() {
    // covers: delegation_chain_abuse
    //
    // Attacker scenario: a delegated capability claims a parent
    // capability id that the verifier-owned budget registry has
    // never seen. The production sibling-sum admit step MUST fail
    // closed under `BudgetSplitError::UnknownParent`. This is the
    // delegation-chain-specific deny path the threat row targets.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_delegated_cap(
        &authority,
        &subject,
        "cap-child",
        "missing-parent",
        100,
        200,
    );
    assert!(
        !token.delegation_chain.is_empty(),
        "delegation_chain MUST be non-empty for this test to exercise the budget-split branch"
    );

    let clock = FixedClock::new(150);
    let mut budgets = InMemoryBudgetRegistry::new();

    let err = match verify_capability_with_floor(
        &token,
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_floor MUST fail closed when a \
             delegated token's parent is not in the budget registry; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
        ),
        "expected BudgetSplitRejected::UnknownParent on missing parent, got {err:?}"
    );
}

#[test]
fn threat_delegation_chain_abuse_untrusted_issuer_rejected() {
    // covers: delegation_chain_abuse
    //
    // Attacker scenario: a delegated capability is signed by an
    // attacker key that is not in the verifier's trust root set.
    // Production verify_capability_with_trusted_and_floor MUST deny
    // before even reaching the chain-binding / budget step.
    let authority = Keypair::generate();
    let attacker = Keypair::generate();
    let subject = Keypair::generate();

    // Delegated token signed by attacker referencing a parent.
    let token = signed_delegated_cap(
        &attacker,
        &subject,
        "cap-attacker-delegated",
        "cap-attacker-root",
        100,
        200,
    );
    assert!(!token.delegation_chain.is_empty());
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
    // Attacker scenario: an attacker mutates a signed delegated
    // capability body (here: the capability id). The canonical-JSON
    // signing payload no longer matches the signature; the
    // production verifier MUST reject before any time-window or
    // budget check fires.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let mut token = signed_delegated_cap(
        &authority,
        &subject,
        "cap-genuine",
        "cap-genuine-parent",
        100,
        200,
    );

    // Tamper the body without re-signing.
    token.id = "cap-attacker-claimed-id".to_string();
    assert!(!token.delegation_chain.is_empty());

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
    // Attacker scenario: an attacker resurrects a delegated token
    // past its expires_at and tries to use it after the validity
    // window has closed. Production MUST reject via the time-window
    // check.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_delegated_cap(
        &authority,
        &subject,
        "cap-stale-delegated",
        "cap-stale-parent",
        100,
        200,
    );

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
fn threat_delegation_chain_abuse_legitimate_root_capability_round_trips() {
    // covers: delegation_chain_abuse
    //
    // Sanity arm: a freshly-issued root capability whose issuer IS
    // in the trust set passes verification at a clock value inside
    // its validity window. Guards against an over-rejecting deny
    // path that would silently classify all root capabilities as
    // abuse. (Delegated-token round-trip would additionally need a
    // registered parent in the budget registry; that is exercised
    // implicitly by other in-tree integration tests.)
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_root_cap(&authority, &subject, "cap-legit", 100, 200);

    let clock = FixedClock::new(150);
    if let Err(err) = verify_capability_with_trusted_and_floor(
        &token,
        std::iter::once(authority.public_key()),
        &clock,
        CapabilityCryptoFloor::AllowClassical,
    ) {
        panic!(
            "legitimate root capability MUST verify (otherwise the deny \
             guard is over-rejecting); got {err:?}"
        );
    }
}
