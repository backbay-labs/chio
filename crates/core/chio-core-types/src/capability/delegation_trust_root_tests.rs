use crate::crypto::Keypair;

use super::attenuation::{
    validate_delegation_chain_with_trust_root, DelegationLink, DelegationLinkBody, ScopeHash,
};

#[test]
fn delegation_chain_trust_root_accepts_matching_first_scope_hash() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let root_hash: ScopeHash = "root-scope".to_string();
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-root".to_string(),
            delegator: kp_a.public_key(),
            delegatee: kp_b.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(root_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &kp_a,
    )
    .unwrap();

    validate_delegation_chain_with_trust_root(&[link], None, &root_hash).unwrap();
}

#[test]
fn delegation_chain_trust_root_rejects_mismatched_first_scope_hash() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let root_hash: ScopeHash = "root-scope".to_string();
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-root".to_string(),
            delegator: kp_a.public_key(),
            delegatee: kp_b.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some("different-scope".to_string()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &kp_a,
    )
    .unwrap();

    let err = validate_delegation_chain_with_trust_root(&[link], None, &root_hash).unwrap_err();
    assert!(err.to_string().contains("trust root"));
}

#[test]
fn delegation_chain_trust_root_rejects_multi_hop_without_per_hop_witnesses() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();
    let root_hash: ScopeHash = "root-scope".to_string();
    let link_1 = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-root".to_string(),
            delegator: kp_a.public_key(),
            delegatee: kp_b.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(root_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &kp_a,
    )
    .unwrap();
    let link_2 = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-hop-1".to_string(),
            delegator: kp_b.public_key(),
            delegatee: kp_c.public_key(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some("inflated-hop-scope".to_string()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &kp_b,
    )
    .unwrap();

    let err =
        validate_delegation_chain_with_trust_root(&[link_1, link_2], None, &root_hash).unwrap_err();
    assert!(err.to_string().contains("per-hop child-scope"));
}
