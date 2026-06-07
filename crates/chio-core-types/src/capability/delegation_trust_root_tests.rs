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
        },
        &kp_a,
    )
    .unwrap();

    let err = validate_delegation_chain_with_trust_root(&[link], None, &root_hash).unwrap_err();
    assert!(err.to_string().contains("trust root"));
}
