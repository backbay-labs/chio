#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;

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

#[test]
fn capability_unknown_schema_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent).unwrap(),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
            },
            budget_share_bps: Some(10_000),
        },
        &issuer,
    )
    .unwrap();

    let mut bad = token;
    bad.schema = "chio.capability.v999".to_string();
    assert!(bad.verify_signature().is_err());
}

#[test]
fn forged_attenuation_proof_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let result = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: "00".repeat(32),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
            },
            budget_share_bps: None,
        },
        &issuer,
    );
    assert!(result.is_err());
}
