//! Negative conformance test: sibling-sum budget enforcement.
//!
//! Threat: a parent capability with `budget_share_bps = 5000` can mint
//! two children with `budget_share_bps = 4000` each. Per-token
//! validation only checks `<= 10000` per token; without a registry the
//! verifier accepts both children even though they jointly claim 80% of
//! the parent's budget while the parent itself only owns 50%.
//!
//! `verify_capability_with_floor` plus a real `BudgetRegistry`
//! (`InMemoryBudgetRegistry` here) closes the gap by rejecting the
//! second child with `CapabilityError::BudgetSplitRejected`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::crypto_floor::CapabilityCryptoFloor;
use chio_core::capability::{
    attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_core::{
    verify_capability_with_floor, BudgetRegistry, BudgetSplitError, CapabilityError, FixedClock,
    InMemoryBudgetRegistry,
};

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

fn scope_with(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

/// Build a child capability whose `delegation_chain` claims
/// descent from `parent_id` and whose `budget_share_bps` is `share`.
fn build_child(
    issuer: &Keypair,
    parent_id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
    child_id: &str,
    share: u16,
    delegation_chain: Vec<chio_core::capability::attenuation::DelegationLink>,
) -> CapabilityToken {
    let witness = compute_attenuation_witness(parent_scope, child_scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(parent_scope).unwrap(),
        child_scope_hash: scope_hash(child_scope).unwrap(),
        normalized_subset_proof: witness,
    };
    let _ = parent_id;
    let body = CapabilityTokenBody {
        id: child_id.to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::generate().public_key(),
        scope: child_scope.clone(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain,
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(share),
        },
        issuer,
    )
    .expect("child signs")
}

#[test]
fn parent_at_5000_bps_cannot_mint_two_children_at_4000_bps_each() {
    use chio_core::capability::attenuation::{DelegationLink, DelegationLinkBody};

    let parent_kp = Keypair::generate();
    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let child_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    // Parent capability id; the chain in each child points at this id.
    let parent_id = "cap-parent-5000bps";
    // Build two delegation chain entries (one per child). Each chain
    // has length 1: the parent delegated directly to the child.
    let mk_chain = |delegatee: chio_core::crypto::PublicKey| {
        let body = DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: parent_kp.public_key(),
            delegatee,
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
            aggregate_budget: None,
            cumulative_approval: None,
        };
        let link = DelegationLink::sign(body, &parent_kp).expect("delegation link signs");
        vec![link]
    };

    let child_a_subject = Keypair::generate();
    let child_b_subject = Keypair::generate();

    let child_a = build_child(
        &parent_kp,
        parent_id,
        &parent_scope,
        &child_scope,
        "cap-child-a",
        4_000,
        {
            let body = DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: parent_kp.public_key(),
                delegatee: child_a_subject.public_key(),
                attenuations: vec![],
                timestamp: 100,
                scope_hash: Some(scope_hash(&parent_scope).unwrap()),
                aggregate_budget: None,
                cumulative_approval: None,
            };
            vec![DelegationLink::sign(body, &parent_kp).expect("link a")]
        },
    );
    let child_b = build_child(
        &parent_kp,
        parent_id,
        &parent_scope,
        &child_scope,
        "cap-child-b",
        4_000,
        mk_chain(child_b_subject.public_key()),
    );

    let mut budgets = InMemoryBudgetRegistry::new();
    budgets
        .register_parent(parent_id.to_string(), 5_000)
        .expect("register parent");

    let clock = FixedClock::new(150);

    // First child fits: 4000 <= 5000 remaining.
    verify_capability_with_floor(
        &child_a,
        &[parent_kp.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect("first child must verify (4000 bps fits the 5000 bps parent share)");

    // Second child oversubscribes: 4000 + 4000 = 8000 > 5000.
    let err = verify_capability_with_floor(
        &child_b,
        &[parent_kp.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect_err("second child must be rejected by sibling-sum enforcement");

    match err {
        CapabilityError::BudgetSplitRejected(BudgetSplitError::OversubscribedSiblings {
            child_id,
            share_bps,
            current_total_child_bps,
            parent_share_bps,
        }) => {
            assert_eq!(child_id, "cap-child-b");
            assert_eq!(share_bps, 4_000);
            assert_eq!(current_total_child_bps, 4_000);
            assert_eq!(parent_share_bps, 5_000);
        }
        other => panic!("expected BudgetSplitRejected::OversubscribedSiblings, got: {other:?}"),
    }
}
