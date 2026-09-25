use super::{
    attenuation::{scope_hash, validate_delegation_chain_with_trust_root, DelegationLink},
    delegated_token::{issue_delegated_capability, DelegatedCapabilityRequest},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use crate::crypto::Keypair;

fn scope(delegable: bool, calls: u32) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "specialist".into(),
            tool_name: "review".into(),
            operations,
            constraints: vec![],
            max_invocations: Some(calls),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    }
}

fn root(issuer: &Keypair, holder: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "root".into(),
            issuer: issuer.public_key(),
            subject: holder.public_key(),
            scope: scope(true, 10),
            issued_at: 100,
            expires_at: 600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .unwrap()
}

fn child(
    parent: &CapabilityToken,
    issuer: &Keypair,
    holder: &Keypair,
    subject: &Keypair,
    id: &str,
    delegable: bool,
    share: u16,
) -> CapabilityToken {
    issue_delegated_capability(
        parent,
        DelegatedCapabilityRequest {
            id: id.into(),
            subject: subject.public_key(),
            scope: scope(delegable, 2),
            issued_at: parent.issued_at + 10,
            expires_at: parent.expires_at - 10,
            budget_share_bps: Some(share),
            nonce: [0; 16],
        },
        holder,
        issuer,
    )
    .unwrap()
    .0
}

#[test]
fn two_hop_child_retains_each_signed_scope_and_exact_leaf() {
    let issuer = Keypair::generate();
    let holder = Keypair::generate();
    let provider = Keypair::generate();
    let specialist = Keypair::generate();
    let parent = root(&issuer, &holder);
    let provider_cap = child(&parent, &issuer, &holder, &provider, "provider", true, 6000);
    let specialist_cap = child(
        &provider_cap,
        &issuer,
        &provider,
        &specialist,
        "specialist",
        false,
        2500,
    );
    assert_eq!(specialist_cap.delegation_chain.len(), 2);
    assert!(specialist_cap.verify_signature().unwrap());
    validate_delegation_chain_with_trust_root(
        &specialist_cap.delegation_chain,
        Some(2),
        &scope_hash(&parent.scope).unwrap(),
    )
    .unwrap();
    let serialized = serde_json::to_vec(&specialist_cap).unwrap();
    let decoded: CapabilityToken = serde_json::from_slice(&serialized).unwrap();
    assert!(decoded.verify_signature().unwrap());
    for mutation in ["id", "scope", "expiry", "budget", "issued"] {
        let mut changed = specialist_cap.clone();
        match mutation {
            "id" => changed.id = "substituted".into(),
            "scope" => changed.scope = scope(false, 1),
            "expiry" => changed.expires_at -= 1,
            "budget" => changed.budget_share_bps = Some(2000),
            "issued" => changed.issued_at += 1,
            _ => unreachable!(),
        }
        assert!(changed.validate_schema().is_err(), "{mutation}");
    }
}

#[test]
fn a_holder_cannot_pivot_the_signed_parent_scope_or_lifetime() {
    let issuer = Keypair::generate();
    let holder = Keypair::generate();
    let provider = Keypair::generate();
    let specialist = Keypair::generate();
    let parent = root(&issuer, &holder);
    let provider_cap = child(&parent, &issuer, &holder, &provider, "provider", true, 6000);
    let leaf = child(
        &provider_cap,
        &issuer,
        &provider,
        &specialist,
        "specialist",
        false,
        2500,
    );
    for mutation in [
        "parent_id",
        "ancestor_id",
        "timestamp",
        "expiry",
        "budget",
        "scope",
        "missing",
    ] {
        let mut chain = leaf.delegation_chain.clone();
        let mut body = chain[1].body();
        match mutation {
            "parent_id" => body.capability_id = "unrelated-parent".into(),
            "ancestor_id" => body.child_binding.as_mut().unwrap().capability_id = parent.id.clone(),
            "timestamp" => {
                body.timestamp = provider_cap.expires_at;
                body.child_binding.as_mut().unwrap().issued_at = body.timestamp;
                body.child_binding.as_mut().unwrap().expires_at = body.timestamp + 1;
            }
            "expiry" => {
                body.child_binding.as_mut().unwrap().expires_at = provider_cap.expires_at + 1
            }
            "budget" => body.child_binding.as_mut().unwrap().budget_share_bps = Some(6001),
            "scope" => body.scope_hash = Some(scope_hash(&scope(true, 50)).unwrap()),
            "missing" => body.child_binding = None,
            _ => unreachable!(),
        }
        // The malicious holder can sign its own link. A valid signature alone
        // must not grant authority that its predecessor did not delegate.
        chain[1] = DelegationLink::sign(body, &provider).unwrap();
        assert!(
            validate_delegation_chain_with_trust_root(
                &chain,
                Some(2),
                &scope_hash(&parent.scope).unwrap()
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn signing_rejects_wrong_holder_issuer_and_expansion() {
    let issuer = Keypair::generate();
    let holder = Keypair::generate();
    let stranger = Keypair::generate();
    let subject = Keypair::generate();
    let parent = root(&issuer, &holder);
    for mutation in ["holder", "issuer", "scope", "expiry", "predates", "same_id"] {
        let mut request = DelegatedCapabilityRequest {
            id: "child".into(),
            subject: subject.public_key(),
            scope: scope(false, 1),
            issued_at: 110,
            expires_at: 500,
            budget_share_bps: Some(5000),
            nonce: [0; 16],
        };
        match mutation {
            "scope" => request.scope = scope(false, 11),
            "expiry" => request.expires_at = 601,
            "predates" => request.issued_at = 99,
            "same_id" => request.id = parent.id.clone(),
            _ => {}
        }
        assert!(
            issue_delegated_capability(
                &parent,
                request,
                if mutation == "holder" {
                    &stranger
                } else {
                    &holder
                },
                if mutation == "issuer" {
                    &stranger
                } else {
                    &issuer
                },
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn removed_delegation_operation_cannot_be_restored_in_the_next_hop() {
    let issuer = Keypair::generate();
    let holder = Keypair::generate();
    let recipient = Keypair::generate();
    let parent = root(&issuer, &holder);
    let leaf = child(&parent, &issuer, &holder, &recipient, "leaf", false, 1000);
    assert!(issue_delegated_capability(
        &leaf,
        DelegatedCapabilityRequest {
            id: "another-child".into(),
            subject: Keypair::generate().public_key(),
            scope: scope(false, 1),
            issued_at: 120,
            expires_at: 400,
            budget_share_bps: Some(500),
            nonce: [0; 16],
        },
        &recipient,
        &issuer
    )
    .is_err());
}

#[test]
fn caveated_parent_is_not_silently_minted_without_its_condition() {
    use super::caveat::{Caveat, CaveatKind};
    let issuer = Keypair::generate();
    let holder = Keypair::generate();
    let mut parent = root(&issuer, &holder);
    parent.caveats = vec![Caveat {
        kind: CaveatKind::RestrictAudience,
        predicate: "internal".into(),
        sig: None,
    }];
    parent.signature = issuer.sign_canonical(&parent.signing_body()).unwrap().0;
    let result = issue_delegated_capability(
        &parent,
        DelegatedCapabilityRequest {
            id: "child".into(),
            subject: Keypair::generate().public_key(),
            scope: scope(false, 1),
            issued_at: 110,
            expires_at: 200,
            budget_share_bps: Some(1000),
            nonce: [0; 16],
        },
        &holder,
        &issuer,
    );
    assert!(result.is_err());
}
