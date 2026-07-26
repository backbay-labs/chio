//! Cross-hop conformance test: sibling-sum enforcement composes
//! across delegation hops.
//!
//! Topology:
//!
//! - parent at 5000 bps
//! - child at 4000 bps (delegated from parent; admitted)
//! - grandchild_a at 3000 bps (delegated from child; admitted)
//! - grandchild_b at 3000 bps (delegated from child; rejected because
//!   3000 + 3000 = 6000 > 4000 = child's parent share)
//!
//! This is the cross-hop amplification case: even though each
//! grandchild's per-token share is well under the cap, the running
//! sum of admitted siblings under `child` exceeds `child`'s own
//! authority. The verifier must reject the second grandchild fail
//! closed at the verify step.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::crypto_floor::CapabilityCryptoFloor;
use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
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

fn sign_attenuated_with_chain(
    issuer: &Keypair,
    id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
    chain: Vec<DelegationLink>,
    share: u16,
) -> CapabilityToken {
    let witness = compute_attenuation_witness(parent_scope, child_scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(parent_scope).unwrap(),
        child_scope_hash: scope_hash(child_scope).unwrap(),
        normalized_subset_proof: witness,
    };
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::generate().public_key(),
        scope: child_scope.clone(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain: chain,
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
    .expect("token signs")
}

#[test]
fn parent_5000_child_4000_two_grandchildren_3000_each_second_rejected() {
    let kp = Keypair::generate();

    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let descendant_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    // Parent has share 5000, registered with the registry.
    let parent_id = "cap-parent-cross-hop";
    let mut budgets = InMemoryBudgetRegistry::new();
    budgets
        .register_parent(parent_id.to_string(), 5_000)
        .expect("register parent");

    // Build the child token: delegated from parent, share 4000.
    let child_id = "cap-child-cross-hop";
    let child_subject = Keypair::generate();
    let parent_to_child_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: kp.public_key(),
            delegatee: child_subject.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &kp,
    )
    .expect("parent->child link signs");
    let child = sign_attenuated_with_chain(
        &kp,
        child_id,
        &parent_scope,
        &descendant_scope,
        vec![parent_to_child_link.clone()],
        4_000,
    );

    let clock = FixedClock::new(150);

    // Verify the child: first delegation under parent admits 4000 of 5000.
    verify_capability_with_floor(
        &child,
        &[kp.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect("child must verify (4000 bps fits 5000 bps parent share)");

    // Now register the child as a parent with share 4000 so subsequent
    // grandchildren can be admitted against it.
    budgets
        .register_parent(child_id.to_string(), 4_000)
        .expect("register child as parent");

    // Build the two grandchildren. The chain length is 2: parent->child,
    // child->grandchild.
    let mk_grandchild = |gc_id: &str| {
        let gc_subject = Keypair::generate();
        let child_to_gc_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: child_id.to_string(),
                delegator: child_subject.public_key(),
                delegatee: gc_subject.public_key(),
                attenuations: vec![],
                timestamp: 110,
                scope_hash: Some(scope_hash(&parent_scope).unwrap()),
                aggregate_budget: None,
                cumulative_approval: None,
            },
            &child_subject,
        )
        .expect("child->grandchild link signs");
        sign_attenuated_with_chain(
            &kp,
            gc_id,
            &parent_scope,
            &descendant_scope,
            vec![parent_to_child_link.clone(), child_to_gc_link],
            3_000,
        )
    };

    let grandchild_a = mk_grandchild("cap-grandchild-a");
    let grandchild_b = mk_grandchild("cap-grandchild-b");

    // First grandchild fits: 3000 <= 4000 remaining under child.
    verify_capability_with_floor(
        &grandchild_a,
        &[kp.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect("first grandchild must verify (3000 bps fits 4000 bps child share)");

    // Second grandchild oversubscribes: 3000 + 3000 = 6000 > 4000.
    let err = verify_capability_with_floor(
        &grandchild_b,
        &[kp.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect_err("second grandchild must be rejected by cross-hop sibling-sum enforcement");

    match err {
        CapabilityError::BudgetSplitRejected(BudgetSplitError::OversubscribedSiblings {
            child_id: rejected_id,
            share_bps,
            current_total_child_bps,
            parent_share_bps,
        }) => {
            assert_eq!(rejected_id, "cap-grandchild-b");
            assert_eq!(share_bps, 3_000);
            assert_eq!(current_total_child_bps, 3_000);
            assert_eq!(parent_share_bps, 4_000);
        }
        other => panic!("expected BudgetSplitRejected::OversubscribedSiblings, got: {other:?}"),
    }
}
