use chio_core::canonical_json_bytes;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::{Decision, ToolCallAction};

use super::*;

pub(super) fn enforcement_anchor_proof(
    verified: &VerifiedFindingEnforcement,
) -> AnchorInclusionProof {
    let mut proof = sample_anchor_proof();
    let kernel = Keypair::from_seed(&[7; 32]);
    let mut receipt_body = proof.receipt.body();
    receipt_body.tool_server = FINDING_ENFORCEMENT_ANCHOR_TOOL_SERVER.to_string();
    receipt_body.tool_name = FINDING_ENFORCEMENT_ANCHOR_TOOL_NAME.to_string();
    receipt_body.action =
        ToolCallAction::from_parameters(finding_enforcement_anchor_parameters(verified))
            .test_expect("enforcement anchor action");
    receipt_body.decision = Some(Decision::Allow);
    proof.receipt =
        ChioReceipt::sign(receipt_body, &kernel).test_expect("enforcement anchor receipt signs");

    let receipt_bytes = canonical_json_bytes(&proof.receipt.body())
        .test_expect("enforcement anchor receipt serializes");
    let tree = MerkleTree::from_leaves(&[receipt_bytes.as_slice()])
        .test_expect("enforcement anchor tree builds");
    let merkle_root = tree.root();
    proof.receipt_inclusion.merkle_root = merkle_root;
    proof.receipt_inclusion.proof = tree
        .inclusion_proof(0)
        .test_expect("enforcement anchor proof builds");
    proof.checkpoint_statement.tree_size = tree.leaf_count() as u64;
    proof.checkpoint_statement.merkle_root = merkle_root;
    if let Some(chain_anchor) = proof.chain_anchor.as_mut() {
        chain_anchor.anchored_merkle_root = merkle_root;
    }
    let mut statement = serde_json::to_value(&proof.checkpoint_statement)
        .test_expect("checkpoint statement serializes");
    statement
        .as_object_mut()
        .test_expect("checkpoint statement body is an object")
        .remove("signature");
    let (signature, _) = kernel
        .sign_canonical(&statement)
        .test_expect("checkpoint statement signs");
    proof.checkpoint_statement.signature = signature;
    proof
}
