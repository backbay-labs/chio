//! Negative conformance test: chain-binding rejects inflated
//! `attenuation_proof.parent_scope_hash`.
//!
//! Threat: an issuer with true authority `scope_X` mints a token whose
//! `attenuation_proof.parent_scope_hash` claims `H(scope_BIGGER)` and
//! whose witness internally proves `child <= scope_BIGGER`. Without the
//! chain-binding rule, the witness verifies in isolation and the
//! verifier accepts the token even though the issuer never had authority
//! over `scope_BIGGER`.
//!
//! `verify_capability_with_floor_and_trust_root` closes this gap by
//! requiring `parent_scope_hash` to equal the trust-root scope hash
//! (direct issue) or `delegation_chain.last().scope_hash` (delegated).
//! The negative case below asserts the rejection; a positive control
//! confirms an honest token still verifies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::crypto_floor::CapabilityCryptoFloor;
use chio_core::capability::{
    attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_core::{verify_capability_with_floor_and_trust_root, CapabilityError, FixedClock};

/// Build a tool grant with the requested operation set.
fn grant(operations: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

/// Build a scope from a list of grants.
fn scope_with(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

/// Build the three scopes used by the inflated-parent attack:
///
/// - `scope_x`: the issuer's true authority (Invoke + Delegate).
/// - `scope_bigger`: an inflated authority claim (Invoke + Delegate +
///   ReadResult). Strictly larger than `scope_x` (extra operation).
/// - `scope_child`: a subset of `scope_bigger` that is NOT a subset of
///   `scope_x` (it requires `ReadResult`, which `scope_x` lacks).
fn three_scopes() -> (ChioScope, ChioScope, ChioScope) {
    let scope_x = scope_with(vec![grant(vec![Operation::Invoke, Operation::Delegate])]);
    let scope_bigger = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let scope_child = scope_with(vec![grant(vec![Operation::Invoke, Operation::ReadResult])]);
    (scope_x, scope_bigger, scope_child)
}

#[test]
fn attenuated_token_with_inflated_parent_scope_hash_is_rejected() {
    let (scope_x, scope_bigger, scope_child) = three_scopes();

    // Honest witness: child <= scope_BIGGER. This is the witness the
    // attacker would supply, since they cannot produce a witness for
    // child <= scope_X (child claims ReadResult, which scope_X lacks).
    let witness = compute_attenuation_witness(&scope_bigger, &scope_child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope_bigger).unwrap(),
        child_scope_hash: scope_hash(&scope_child).unwrap(),
        normalized_subset_proof: witness,
    };

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-attenuated-inflated-parent".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope_child,
        issued_at: 100,
        expires_at: 200,
        // Direct issue: empty delegation chain. The chain-binding rule
        // therefore requires parent_scope_hash == trust_root_scope_hash.
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("inflated-parent token signs (verifier must catch this, not signer)");

    // The verifier knows the issuer's TRUE authority is scope_X.
    let trust_root = scope_hash(&scope_x).unwrap();
    let clock = FixedClock::new(150);

    let err = verify_capability_with_floor_and_trust_root(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &trust_root,
    )
    .expect_err("chain-binding must reject inflated parent_scope_hash");

    match err {
        CapabilityError::AttenuationViolation(reason) => {
            assert!(
                reason.contains("chain-binding")
                    || reason.contains("parent_scope_hash")
                    || reason.contains("trust-root"),
                "expected chain-binding diagnostic, got: {reason}"
            );
        }
        other => panic!("expected AttenuationViolation, got: {other:?}"),
    }
}

#[test]
fn attenuated_token_with_honest_trust_root_parent_scope_hash_verifies() {
    // Positive control: the honest token has parent_scope_hash bound to
    // the issuer's trust-root authority. Witness proves child <= scope_X
    // and the verifier accepts.
    let (scope_x, _scope_bigger, _scope_child) = three_scopes();
    // Build a fresh child that IS a subset of scope_X.
    let scope_child = scope_with(vec![grant(vec![Operation::Invoke])]);
    let witness = compute_attenuation_witness(&scope_x, &scope_child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope_x).unwrap(),
        child_scope_hash: scope_hash(&scope_child).unwrap(),
        normalized_subset_proof: witness,
    };

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-attenuated-honest".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope_child,
        issued_at: 100,
        expires_at: 200,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("honest attenuated token signs");

    let trust_root = scope_hash(&scope_x).unwrap();
    let clock = FixedClock::new(150);

    let verified = verify_capability_with_floor_and_trust_root(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &trust_root,
    )
    .expect("honest attenuated token must verify under the trust-root binding");

    assert_eq!(verified.id, "cap-attenuated-honest");
}
