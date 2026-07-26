use crate::crypto::{sha256_hex, Keypair};

use super::governance::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, VerifiedApprovalSetBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};

#[test]
fn threshold_approval_proposal_and_set_bind_complete_artifacts() {
    let policy_authority = Keypair::generate();
    let subject = Keypair::generate();
    let proposal_deadline =
        ThresholdApprovalProposalBody::proposal_deadline(1_000, 900, 1_500, Some(1_800)).unwrap();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-1".to_string(),
            request_id: "request-1".to_string(),
            governed_intent_hash: sha256_hex(b"intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"capability"),
            policy_hash: sha256_hex(b"policy"),
            threshold: 2,
            eligible_set_digest: sha256_hex(b"eligible-set"),
            proposal_created_at: 1_000,
            proposal_deadline,
            policy_authority: policy_authority.public_key(),
        },
        &policy_authority,
    )
    .unwrap();

    assert_eq!(proposal.body.proposal_deadline, 1_500);
    assert!(proposal.verify_signature().unwrap());
    let mut proposal_json = serde_json::to_value(&proposal).unwrap();
    proposal_json
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<ThresholdApprovalProposal>(proposal_json).is_err());
    proposal.validate_at(1_499).unwrap();
    assert!(proposal.validate_at(1_500).is_err());

    let first = VerifiedApprovalSetBody::new(
        vec![sha256_hex(b"token-b"), sha256_hex(b"token-a")],
        &proposal,
    )
    .unwrap();
    assert!(VerifiedApprovalSetBody::new(vec![sha256_hex(b"token-a")], &proposal).is_err());
    let second = VerifiedApprovalSetBody::new(
        vec![sha256_hex(b"token-a"), sha256_hex(b"token-b")],
        &proposal,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.approval_set_hash().unwrap(),
        second.approval_set_hash().unwrap()
    );

    let mut changed = proposal.clone();
    changed.body.proposal_deadline -= 1;
    assert!(!changed.verify_signature().unwrap());
    assert_ne!(
        proposal.artifact_digest().unwrap(),
        changed.artifact_digest().unwrap()
    );
}
