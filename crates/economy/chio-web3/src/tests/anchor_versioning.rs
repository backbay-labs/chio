use super::*;

#[test]
fn anchor_inclusion_proof_versions_match_the_embedded_checkpoint_version() {
    let mut proof = sample_anchor_inclusion_proof();
    proof.schema = CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V1.to_string();

    assert!(matches!(
        validate_anchor_inclusion_proof(&proof),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("v1 anchor inclusion proofs must embed a v1 checkpoint statement")
    ));
}

#[test]
fn web3_checkpoint_verification_requires_valid_first_v2_chain_root() {
    let mut missing = sample_anchor_inclusion_proof();
    missing.receipt_inclusion.checkpoint_seq = 1;
    missing.checkpoint_statement.checkpoint_seq = 1;
    missing.checkpoint_statement.chain_root = None;
    if let Some(chain_anchor) = missing.chain_anchor.as_mut() {
        chain_anchor.anchored_checkpoint_seq = 1;
    }
    let body = checkpoint_statement_body(&missing.checkpoint_statement);
    let (signature, _) = operator_keypair().sign_canonical(&body).unwrap();
    missing.checkpoint_statement.signature = signature;

    assert!(matches!(
        verify_anchor_inclusion_proof(&missing),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("v2 checkpoint 1 must carry chain_root")
    ));

    let mut incorrect = missing;
    incorrect.checkpoint_statement.chain_root = Some(Hash::zero());
    let body = checkpoint_statement_body(&incorrect.checkpoint_statement);
    let (signature, _) = operator_keypair().sign_canonical(&body).unwrap();
    incorrect.checkpoint_statement.signature = signature;

    assert!(matches!(
        verify_anchor_inclusion_proof(&incorrect),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("does not commit its own chain leaf")
    ));
}

#[test]
fn web3_checkpoint_verification_rejects_tree_size_outside_signed_batch_range() {
    let mut proof = sample_anchor_inclusion_proof();
    proof.checkpoint_statement.tree_size = 2;
    proof.receipt_inclusion.proof.tree_size = 2;
    let body = checkpoint_statement_body(&proof.checkpoint_statement);
    let (signature, _) = operator_keypair().sign_canonical(&body).unwrap();
    proof.checkpoint_statement.signature = signature;

    assert!(matches!(
        verify_anchor_inclusion_proof(&proof),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("tree_size 2 does not match covered entry count 1")
    ));
}

#[test]
fn web3_checkpoint_verification_checks_tree_size_conversion_before_comparison() {
    let mut proof = sample_anchor_inclusion_proof();
    let claimed_tree_size = u64::from(u32::MAX) + 2;
    proof.checkpoint_statement.batch_start_seq = 1;
    proof.checkpoint_statement.batch_end_seq = claimed_tree_size;
    proof.checkpoint_statement.tree_size = claimed_tree_size;

    let expected_message = if usize::BITS == 32 {
        "tree_size cannot be represented by this platform's Merkle proof index"
    } else {
        "tree_size must match receipt inclusion proof"
    };
    assert!(matches!(
        validate_anchor_inclusion_proof(&proof),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains(expected_message)
    ));
}
