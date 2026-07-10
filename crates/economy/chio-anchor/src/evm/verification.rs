use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::leaf_hash;
use chio_core::web3::anchors::{verify_anchor_inclusion_proof, AnchorInclusionProof};
use chio_egress_contract::HttpEgressContract;
use chio_web3_bindings::{ChioMerkleProof, IChioRootRegistry};
use serde_json::json;

use crate::AnchorError;

use super::hashing::{hash_to_b256, operator_key_hash};
use super::rpc::rpc_call;
use super::types::EvmAnchorTarget;
use super::validation::{parse_nonzero_evm_address, parse_validated_evm_anchor_target};

pub async fn verify_inclusion_onchain(
    target: &EvmAnchorTarget,
    proof: &AnchorInclusionProof,
    egress_contract: &HttpEgressContract,
) -> Result<bool, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    verify_anchor_inclusion_proof(proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let operator = parse_nonzero_evm_address(
        "proof binding settlement address",
        &proof.key_binding_certificate.certificate.settlement_address,
    )?;
    if operator != validated_target.operator {
        return Err(AnchorError::Verification(
            "proof binding settlement address does not match anchor target operator".to_string(),
        ));
    }
    let receipt_bytes = canonical_json_bytes(&proof.receipt.body())
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    let leaf = leaf_hash(&receipt_bytes);
    let evm_proof = ChioMerkleProof {
        audit_path: proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(proof.receipt_inclusion.proof.tree_size as u64),
    };
    let call = IChioRootRegistry::verifyInclusionDetailedForKeyHashCall {
        proof: evm_proof.into(),
        root: hash_to_b256(&proof.receipt_inclusion.merkle_root),
        leafHash: hash_to_b256(&leaf),
        operator,
        operatorKeyHash: operator_key_hash(&proof.key_binding_certificate)?,
    };
    let response = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let raw = response.as_str().ok_or_else(|| {
        AnchorError::Rpc(
            "eth_call verifyInclusionDetailedForKeyHash did not return data".to_string(),
        )
    })?;
    let bytes = hex::decode(raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let verified =
        IChioRootRegistry::verifyInclusionDetailedForKeyHashCall::abi_decode_returns(&bytes)
            .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    Ok(verified)
}
