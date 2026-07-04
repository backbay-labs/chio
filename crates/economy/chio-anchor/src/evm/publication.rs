use alloy_sol_types::SolCall;
use chio_core::web3::identity::SignedWeb3IdentityBinding;
use chio_egress_contract::HttpEgressContract;
use chio_kernel::checkpoint::KernelCheckpoint;
use chio_web3_bindings::IChioRootRegistry;
use serde_json::{json, Value};

use crate::AnchorError;

use super::hashing::{hash_to_b256, parse_hex_u64};
use super::operator_key_hash;
use super::rpc::rpc_call;
use super::types::{EvmAnchorTarget, EvmPublicationGuard, EvmPublicationReceipt};
use super::validation::parse_validated_evm_anchor_target;

pub async fn confirm_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    tx_hash: &str,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationReceipt, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    let receipt = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_getTransactionReceipt",
        json!([tx_hash]),
    )
    .await?;
    let block_number = parse_hex_u64(
        receipt
            .get("blockNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| AnchorError::Rpc("receipt missing blockNumber".to_string()))?,
    )?;
    let block_hash = receipt
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing blockHash".to_string()))?
        .to_string();
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing status".to_string()))?;
    if status != "0x1" {
        return Err(AnchorError::Rpc(format!(
            "publication transaction {} failed with status {}",
            tx_hash, status
        )));
    }

    let get_root = IChioRootRegistry::getRootCall {
        operator: validated_target.operator,
        checkpointSeq: checkpoint.body.checkpoint_seq,
    };
    let root_result = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(get_root.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let entry_hex = root_result
        .as_str()
        .ok_or_else(|| AnchorError::Rpc("eth_call getRoot did not return data".to_string()))?;
    let entry_bytes = hex::decode(entry_hex.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let stored = IChioRootRegistry::getRootCall::abi_decode_returns(&entry_bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    if stored.checkpointSeq != checkpoint.body.checkpoint_seq
        || stored.batchStartSeq != checkpoint.body.batch_start_seq
        || stored.batchEndSeq != checkpoint.body.batch_end_seq
        || stored.treeSize != checkpoint.body.tree_size as u64
        || stored.merkleRoot != hash_to_b256(&checkpoint.body.merkle_root)
        || stored.operatorKeyHash != operator_key_hash(binding)?
    {
        return Err(AnchorError::Verification(
            "root registry entry does not match the checkpoint being confirmed".to_string(),
        ));
    }

    Ok(EvmPublicationReceipt {
        tx_hash: tx_hash.to_string(),
        block_number,
        block_hash,
        published_at: stored.publishedAt,
    })
}

pub async fn inspect_publication_guard(
    target: &EvmAnchorTarget,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationGuard, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;

    let auth_call = IChioRootRegistry::isAuthorizedPublisherCall {
        operator: validated_target.operator,
        publisher: validated_target.publisher,
    };
    let auth_response = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(auth_call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let auth_raw = auth_response.as_str().ok_or_else(|| {
        AnchorError::Rpc("eth_call isAuthorizedPublisher did not return data".to_string())
    })?;
    let auth_bytes = hex::decode(auth_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let publisher_authorized =
        IChioRootRegistry::isAuthorizedPublisherCall::abi_decode_returns(&auth_bytes)
            .map_err(|error| AnchorError::Serialization(error.to_string()))?;

    let seq_call = IChioRootRegistry::getLatestSeqCall {
        operator: validated_target.operator,
    };
    let seq_response = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(seq_call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let seq_raw = seq_response
        .as_str()
        .ok_or_else(|| AnchorError::Rpc("eth_call getLatestSeq did not return data".to_string()))?;
    let seq_bytes = hex::decode(seq_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let latest_checkpoint_seq = IChioRootRegistry::getLatestSeqCall::abi_decode_returns(&seq_bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;

    Ok(EvmPublicationGuard {
        chain_id: target.chain_id.clone(),
        operator_address: target.operator_address.clone(),
        publisher_address: target.publisher_address.clone(),
        latest_checkpoint_seq,
        next_checkpoint_seq_min: latest_checkpoint_seq.saturating_add(1),
        publisher_authorized,
        requires_delegate_authorization: validated_target.publisher != validated_target.operator,
    })
}

pub async fn ensure_publication_ready(
    target: &EvmAnchorTarget,
    checkpoint_seq: u64,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationGuard, AnchorError> {
    let guard = inspect_publication_guard(target, egress_contract).await?;
    if !guard.publisher_authorized {
        return Err(AnchorError::Verification(format!(
            "publisher {} is not authorized for operator {} on {}",
            guard.publisher_address, guard.operator_address, guard.chain_id
        )));
    }
    if checkpoint_seq != guard.next_checkpoint_seq_min {
        return Err(AnchorError::Verification(format!(
            "checkpoint sequence {} must equal {} on {}",
            checkpoint_seq, guard.next_checkpoint_seq_min, guard.chain_id
        )));
    }
    Ok(guard)
}
