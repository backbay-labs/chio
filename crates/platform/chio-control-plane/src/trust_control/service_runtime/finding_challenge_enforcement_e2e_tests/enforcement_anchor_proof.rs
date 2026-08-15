use super::*;

pub(super) fn enforcement_anchor_proof(
    enforcement: &SignedFindingChallengeEnforcement,
) -> Result<AnchorInclusionProof, AnyError> {
    let mut proof = anchor_proof()?;
    let kernel = keypair(7);
    let mut receipt_body = proof.receipt.body();
    receipt_body.tool_server = chio_settle::FINDING_ENFORCEMENT_ANCHOR_TOOL_SERVER.to_string();
    receipt_body.tool_name = chio_settle::FINDING_ENFORCEMENT_ANCHOR_TOOL_NAME.to_string();
    receipt_body.action = ToolCallAction::from_parameters(
        chio_settle::finding_enforcement_anchor_parameters_for_artifact(enforcement)?,
    )?;
    receipt_body.decision = Some(Decision::Allow);
    proof.receipt = ChioReceipt::sign(receipt_body, &kernel)?;

    let receipt_bytes = canonical_json_bytes(&proof.receipt.body())?;
    let tree = MerkleTree::from_leaves(&[receipt_bytes.as_slice()])?;
    let merkle_root = tree.root();
    proof.receipt_inclusion.merkle_root = merkle_root;
    proof.receipt_inclusion.proof = tree.inclusion_proof(0)?;
    proof.checkpoint_statement.tree_size = tree.leaf_count() as u64;
    proof.checkpoint_statement.merkle_root = merkle_root;
    if let Some(chain_anchor) = proof.chain_anchor.as_mut() {
        chain_anchor.anchored_merkle_root = merkle_root;
    }
    let mut statement = serde_json::to_value(&proof.checkpoint_statement)?;
    statement
        .as_object_mut()
        .ok_or("checkpoint statement body is an object")?
        .remove("signature");
    let (signature, _) = kernel.sign_canonical(&statement)?;
    proof.checkpoint_statement.signature = signature;
    Ok(proof)
}

pub(super) fn anchor_evidence_hash(
    enforcement: &SignedFindingChallengeEnforcement,
) -> Result<String, AnyError> {
    let bytes = canonical_json_bytes(&enforcement_anchor_proof(enforcement)?.receipt.body())?;
    Ok(leaf_hash(&bytes).to_hex_prefixed())
}

pub(super) fn sample_anchor_evidence_hash() -> Result<String, AnyError> {
    let bytes = canonical_json_bytes(&anchor_proof()?.receipt.body())?;
    Ok(leaf_hash(&bytes).to_hex_prefixed())
}
