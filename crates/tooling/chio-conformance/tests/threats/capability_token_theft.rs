// Threat test for threat ID `capability_token_theft`.
//
// Threat: capability_token_theft (Capability token theft).
// Surfaces: trust_control, hosted_mcp, native_chio.
//
// Coverage strategy: import the production
// `chio_kernel_core::capability_verify::verify_capability_with_floor`
// directly. A "stolen capability" attack is the family of attacks
// where an attacker obtains a signed token (or its signature material)
// and re-presents it under a context that diverges from what the
// issuer minted. Two canonical sub-vectors are exercised below; a
// third sanity arm pins the round-trip so an over-rejecting deny
// path cannot silently classify all tokens as stolen.
//
// The Lane B1 single-entry verifier (`verify_capability_full`, sibling
// of `verify_capability_with_floor` and shared canonical-JSON pre-image
// logic via `CapabilityToken::verify_signature_with_floor`) ensures
// every kernel/verifier caller now routes capability admission through
// one fail-closed surface; this conformance test pins that surface.
//
// Sub-vectors:
//
// 1. ScopeSuperset (R2 attack class). An attacker who obtained a
//    signed token mutates `scope` to expand authority beyond what the
//    issuer signed. The canonical-JSON signing pre-image now differs
//    and `CapabilityToken::verify_signature_with_floor` fails the
//    Ed25519 signature check; production returns
//    `CapabilityError::InvalidSignature`.
//
// 2. PartialSignature (R2 attack class). An attacker re-targets a
//    detached signature: they take a token signed by one issuer and
//    swap the `issuer` key field to point at a different (untrusted)
//    public key while keeping the original signature bytes. Production
//    rejects on the first check (`UntrustedIssuer`) before any
//    cryptographic work fires; this sub-vector pins the issuer-trust
//    deny branch independently from the signature check.
//
// 3. Round-trip sanity. A freshly-signed token whose issuer IS in the
//    trusted set verifies successfully under a clock inside its
//    validity window. This guards against a future regression that
//    stops admitting any token (an over-rejecting deny path would
//    silently render the threat row green by virtue of denying
//    everything).
//
// Production call sites:
//   `crates/chio-kernel-core/src/capability_verify.rs:148`
//     (`verify_capability_with_floor`).
//   `crates/chio-core-types/src/capability.rs` (`CapabilityToken::sign`,
//     `verify_signature_with_floor`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-kernel-core/src/capability_verify.rs`, locate the
// `if !trusted_issuers.contains(&token.issuer) { return
// Err(CapabilityError::UntrustedIssuer); }` guard inside
// `verify_capability_with_floor` (around line 158). Delete the guard
// (or replace `return Err(...)` with a no-op). Re-run
// `cargo test -p chio-conformance --test threats -- capability_token_theft`
// and the
// `assert!(matches!(err, CapabilityError::UntrustedIssuer))`
// arm in `partial_signature_retargeted_issuer_rejected` MUST then
// fail because production now admits tokens whose issuer is not in
// the trust set. Likewise, deleting the canonical-JSON signature
// check in `CapabilityToken::verify_signature_with_floor` breaks the
// `InvalidSignature` arm in `scope_superset_after_sign_rejected`.

use chio_core::capability::{
    crypto_floor::CapabilityCryptoFloor,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_core::capability_verify::{verify_capability_with_floor, CapabilityError};
use chio_kernel_core::clock::FixedClock;
use chio_kernel_core::NoopBudgetRegistry;

fn empty_scope() -> ChioScope {
    ChioScope::default()
}

fn read_only_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "fs".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn signed_root_cap(
    issuer: &Keypair,
    subject: &Keypair,
    cap_id: &str,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: cap_id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
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

#[test]
fn threat_capability_token_theft_scope_superset_after_sign_rejected() {
    // covers: capability_token_theft (ScopeSuperset attack class)
    //
    // Attacker scenario: an attacker obtains a signed read-only
    // capability and tries to expand its scope post-mint to also
    // grant Write. The canonical-JSON signing pre-image now differs
    // from what the issuer signed; production MUST return
    // `CapabilityError::InvalidSignature` before any time/budget
    // surfaces are reached.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let mut token = signed_root_cap(
        &authority,
        &subject,
        "cap-stolen-scope-expanded",
        read_only_scope(),
        100,
        200,
    );

    // Mutate scope to add an Invoke operation the issuer did not
    // authorize (the original grant only carried Read).
    if let Some(grant) = token.scope.grants.first_mut() {
        grant.operations.push(Operation::Invoke);
    } else {
        panic!("read_only_scope fixture MUST have at least one grant");
    }

    let clock = FixedClock::new(150);
    let mut budgets = NoopBudgetRegistry;
    let err = match verify_capability_with_floor(
        &token,
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_floor MUST reject a token whose scope \
             was widened after signing; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::InvalidSignature),
        "expected CapabilityError::InvalidSignature on scope superset, got {err:?}"
    );
}

#[test]
fn threat_capability_token_theft_partial_signature_retargeted_issuer_rejected() {
    // covers: capability_token_theft (PartialSignature attack class)
    //
    // Attacker scenario: an attacker harvests a signed token and
    // re-targets it by overwriting the `issuer` field to a public key
    // that is NOT in the verifier's trusted set, while keeping the
    // original signature bytes. The production verifier MUST deny on
    // the first issuer-trust check (`UntrustedIssuer`) before any
    // cryptographic work runs; this is the fail-closed escape hatch
    // that prevents an attacker from forcing the verifier to do a
    // signature-verify with attacker-chosen issuer material.
    let authority = Keypair::generate();
    let attacker = Keypair::generate();
    let subject = Keypair::generate();
    let mut token = signed_root_cap(
        &authority,
        &subject,
        "cap-stolen-issuer-retargeted",
        empty_scope(),
        100,
        200,
    );
    // Re-target to attacker's public key while keeping the original
    // signature bytes. Without re-signing the token, the issuer field
    // and the signature no longer agree.
    token.issuer = attacker.public_key();

    let clock = FixedClock::new(150);
    let mut budgets = NoopBudgetRegistry;
    let err = match verify_capability_with_floor(
        &token,
        // Attacker's key is NOT in the trusted set.
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_floor MUST reject when the token's \
             issuer is not in the trusted set; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::UntrustedIssuer),
        "expected CapabilityError::UntrustedIssuer on retargeted issuer, got {err:?}"
    );
}

#[test]
fn threat_capability_token_theft_replayed_after_expiry_rejected() {
    // covers: capability_token_theft (stolen-token-presented-after-expiry)
    //
    // Attacker scenario: an attacker obtains a valid token and tries
    // to use it after `expires_at`. Production MUST reject via the
    // time-window check; this is the temporal-stale variant of token
    // theft and the deny path that prevents replay across the
    // capability lifetime boundary.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_root_cap(
        &authority,
        &subject,
        "cap-stolen-stale",
        empty_scope(),
        100,
        200,
    );

    // Clock is past expires_at.
    let clock = FixedClock::new(500);
    let mut budgets = NoopBudgetRegistry;
    let err = match verify_capability_with_floor(
        &token,
        &[authority.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    ) {
        Ok(_) => panic!(
            "verify_capability_with_floor MUST reject a token presented \
             after its expires_at; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CapabilityError::Expired),
        "expected CapabilityError::Expired on post-expiry replay, got {err:?}"
    );
}

#[test]
fn threat_capability_token_theft_legitimate_token_round_trips() {
    // covers: capability_token_theft (sanity)
    //
    // Sanity arm: a freshly-issued token whose issuer IS in the trust
    // set passes verification at a clock value inside its validity
    // window. Guards against an over-rejecting deny path that would
    // silently classify every token as stolen.
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let token = signed_root_cap(&authority, &subject, "cap-legit", empty_scope(), 100, 200);

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
            "legitimate token MUST verify (otherwise the deny guard is \
             over-rejecting and capability_token_theft coverage is bogus); \
             got {err:?}"
        );
    }
}
