#[cfg(feature = "delegation")]
use super::attenuation::delegate;
use super::attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof};
use super::caveat::{Caveat, CaveatKind};
use super::scope::{ChioScope, Operation, ToolGrant};
use super::token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody};
use crate::crypto::Keypair;
use crate::error::Error;

fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: ops,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

#[test]
fn capability_caveats_reject_fail_closed_until_admission_enforces_them() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent).unwrap(),
        child_scope_hash: scope_hash(&child).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(&parent, &child).unwrap(),
    };
    let body = CapabilityTokenBody {
        id: "cap-caveated".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let caveat = Caveat {
        kind: CaveatKind::RestrictAudience,
        predicate: "session:abc".to_string(),
        sig: None,
    };

    let err = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: body.clone(),
            caveats: vec![caveat.clone()],
            scope_attenuations: vec![],
            attenuation_proof: proof.clone(),
            budget_share_bps: None,
        },
        &issuer,
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
    assert!(err.to_string().contains("caveats are not enforced"));

    let mut token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .unwrap();
    token.caveats = vec![caveat];
    assert!(token.verify_signature().is_err());
}

#[cfg(feature = "delegation")]
fn delegate_parent_token(
    parent_kp: &Keypair,
    subject_kp: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-parent".to_string(),
        issuer: parent_kp.public_key(),
        subject: subject_kp.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, parent_kp).unwrap()
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_child_grant_without_delegate_on_covering_parent_grant() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![
        make_grant("srv-a", "tool-x", vec![Operation::Invoke]),
        make_grant("srv-b", "delegator-only", vec![Operation::Delegate]),
    ]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
    assert!(err
        .to_string()
        .contains("not covered by a parent grant that authorizes delegation"));
}
