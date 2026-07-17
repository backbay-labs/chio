use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolCall;
use chio_core::web3::identity::{SignedWeb3IdentityBinding, Web3KeyBindingPurpose};
use chio_egress_contract::HttpEgressContract;
use chio_kernel::checkpoint::KernelCheckpoint;
use chio_web3_bindings::IChioRootRegistry;
use serde_json::{json, Value};

use crate::AnchorError;

use super::hashing::{hash_to_b256, parse_hex_u64};
use super::operator_key_hash;
use super::rpc::rpc_call;
use super::types::{EvmAnchorTarget, EvmPublicationGuard, EvmPublicationReceipt};
use super::validation::{parse_nonzero_evm_address, parse_validated_evm_anchor_target};

const ROOT_PUBLISHED_EVENT_SIGNATURE: &str =
    "RootPublished(address,address,uint64,bytes32,uint64,uint64,uint64,uint64,bytes32,uint64)";

pub async fn confirm_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    tx_hash: &str,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationReceipt, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    let tx_hash_b256 = parse_rpc_b256("transaction hash", tx_hash)?;
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
    let block_hash_b256 = parse_rpc_b256("receipt blockHash", &block_hash)?;
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
    let published = validate_publication_receipt(
        &receipt,
        target,
        checkpoint,
        binding,
        tx_hash_b256,
        block_hash_b256,
        block_number,
    )?;

    let get_root = IChioRootRegistry::getRootCall {
        operator: validated_target.operator,
        checkpointSeq: checkpoint.body.checkpoint_seq,
    };
    let root_result = call_get_root_at_verified_block(
        target,
        egress_contract,
        get_root.abi_encode(),
        block_hash_b256,
        block_number,
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
        || stored.publishedAt != published.published_at
        || stored.operatorEpoch != published.operator_epoch
    {
        return Err(AnchorError::Verification(
            "root registry entry does not match the checkpoint being confirmed".to_string(),
        ));
    }

    Ok(EvmPublicationReceipt {
        tx_hash: format_rpc_b256(tx_hash_b256),
        block_number,
        block_hash: format_rpc_b256(block_hash_b256),
        operator_key_hash: format_rpc_b256(operator_key_hash(binding)?),
        operator_epoch: published.operator_epoch,
        published_at: published.published_at,
    })
}

async fn call_get_root_at_verified_block(
    target: &EvmAnchorTarget,
    egress_contract: &HttpEgressContract,
    call_data: Vec<u8>,
    block_hash: B256,
    block_number: u64,
) -> Result<Value, AnchorError> {
    let call = json!({
        "to": target.contract_address,
        "data": format!("0x{}", hex::encode(call_data)),
    });
    let eip1898_result = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            call.clone(),
            {
                "blockHash": format_rpc_b256(block_hash),
                "requireCanonical": true
            }
        ]),
    )
    .await;
    match eip1898_result {
        Ok(result) => Ok(result),
        Err(error) if is_ganache_block_object_unsupported_error(&error) => {
            rpc_call(
                &target.rpc_url,
                egress_contract,
                "eth_call",
                json!([call, format!("0x{block_number:x}")]),
            )
            .await
        }
        Err(error) => Err(error),
    }
}

fn is_ganache_block_object_unsupported_error(error: &AnchorError) -> bool {
    let AnchorError::Rpc(message) = error else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    message.contains("(code -32700)")
        && lower.contains("cannot wrap")
        && lower.contains("\"object\"")
        && lower.contains("json-rpc type")
}

fn validate_publication_receipt(
    receipt: &Value,
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    tx_hash: B256,
    block_hash: B256,
    block_number: u64,
) -> Result<RootPublishedData, AnchorError> {
    let contract = parse_nonzero_evm_address("contract address", &target.contract_address)?;
    let operator = parse_nonzero_evm_address("operator address", &target.operator_address)?;
    let publisher = parse_nonzero_evm_address("publisher address", &target.publisher_address)?;
    let receipt_tx_hash = receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing transactionHash".to_string()))?;
    if parse_rpc_b256("receipt transactionHash", receipt_tx_hash)? != tx_hash {
        return Err(AnchorError::Verification(
            "publication receipt transaction hash mismatch".to_string(),
        ));
    }
    let receipt_to = receipt
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing to address".to_string()))?;
    if parse_nonzero_evm_address("receipt to address", receipt_to)? != contract {
        return Err(AnchorError::Verification(
            "publication receipt target contract mismatch".to_string(),
        ));
    }

    let expected_topic0 = root_published_topic0();
    let expected_operator_topic = topic_for_address(operator);
    let expected_publisher_topic = topic_for_address(publisher);
    let expected_checkpoint_topic = topic_for_u64(checkpoint.body.checkpoint_seq);
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| AnchorError::Rpc("receipt missing logs".to_string()))?;
    for log in logs {
        let Some(address) = log.get("address").and_then(Value::as_str) else {
            continue;
        };
        if parse_nonzero_evm_address("log address", address)? != contract {
            continue;
        }
        let Some(topics) = log.get("topics").and_then(Value::as_array) else {
            continue;
        };
        if topics.len() != 4 {
            continue;
        }
        if !topic_matches(&topics[0], &expected_topic0)
            || !topic_matches(&topics[1], &expected_operator_topic)
            || !topic_matches(&topics[2], &expected_publisher_topic)
            || !topic_matches(&topics[3], &expected_checkpoint_topic)
        {
            continue;
        }
        let Some(data) = log.get("data").and_then(Value::as_str) else {
            continue;
        };
        if !publication_log_metadata_matches(log, tx_hash, block_hash, block_number)? {
            continue;
        }
        let decoded = decode_root_published_data(data)?;
        if decoded.merkle_root == hash_to_b256(&checkpoint.body.merkle_root)
            && decoded.batch_start_seq == checkpoint.body.batch_start_seq
            && decoded.batch_end_seq == checkpoint.body.batch_end_seq
            && decoded.tree_size == checkpoint.body.tree_size as u64
            && decoded.operator_key_hash == operator_key_hash(binding)?
        {
            return Ok(decoded);
        }
    }
    Err(AnchorError::Verification(
        "publication receipt missing matching RootPublished log".to_string(),
    ))
}

fn publication_log_metadata_matches(
    log: &Value,
    tx_hash: B256,
    block_hash: B256,
    block_number: u64,
) -> Result<bool, AnchorError> {
    let log_tx_hash = log
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("RootPublished log missing transactionHash".to_string()))?;
    if parse_rpc_b256("RootPublished log transactionHash", log_tx_hash)? != tx_hash {
        return Ok(false);
    }
    let log_block_hash = log
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("RootPublished log missing blockHash".to_string()))?;
    if parse_rpc_b256("RootPublished log blockHash", log_block_hash)? != block_hash {
        return Ok(false);
    }
    let log_block_number = log
        .get("blockNumber")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("RootPublished log missing blockNumber".to_string()))?;
    Ok(parse_hex_u64(log_block_number)? == block_number)
}

struct RootPublishedData {
    merkle_root: B256,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    published_at: u64,
    operator_key_hash: B256,
    operator_epoch: u64,
}

fn decode_root_published_data(data: &str) -> Result<RootPublishedData, AnchorError> {
    let bytes = hex::decode(data.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    if bytes.len() != 32 * 7 {
        return Err(AnchorError::Rpc(
            "RootPublished log data has invalid length".to_string(),
        ));
    }
    Ok(RootPublishedData {
        merkle_root: word_b256(&bytes, 0),
        batch_start_seq: word_u64(&bytes, 1)?,
        batch_end_seq: word_u64(&bytes, 2)?,
        tree_size: word_u64(&bytes, 3)?,
        published_at: word_u64(&bytes, 4)?,
        operator_key_hash: word_b256(&bytes, 5),
        operator_epoch: word_u64(&bytes, 6)?,
    })
}

fn word_b256(bytes: &[u8], index: usize) -> B256 {
    B256::from_slice(&bytes[index * 32..(index + 1) * 32])
}

fn word_u64(bytes: &[u8], index: usize) -> Result<u64, AnchorError> {
    let word = &bytes[index * 32..(index + 1) * 32];
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(AnchorError::Rpc(
            "RootPublished uint64 word overflowed".to_string(),
        ));
    }
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(raw))
}

fn root_published_topic0() -> String {
    format!(
        "0x{}",
        hex::encode(keccak256(ROOT_PUBLISHED_EVENT_SIGNATURE.as_bytes()).as_slice())
    )
}

fn topic_for_address(address: Address) -> String {
    let mut bytes = [0_u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    format!("0x{}", hex::encode(bytes))
}

fn topic_for_u64(value: u64) -> String {
    format!("0x{value:064x}")
}

fn topic_matches(value: &Value, expected: &str) -> bool {
    value
        .as_str()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn parse_rpc_b256(label: &str, value: &str) -> Result<B256, AnchorError> {
    if value.trim() != value {
        return Err(AnchorError::Rpc(format!(
            "{label} must not include surrounding whitespace"
        )));
    }
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| AnchorError::Rpc(format!("{label} must be 0x-prefixed")))?;
    if raw.len() != 64 {
        return Err(AnchorError::Rpc(format!("{label} must be a 32-byte hash")));
    }
    let bytes = hex::decode(raw)
        .map_err(|error| AnchorError::Rpc(format!("{label} is not valid hex: {error}")))?;
    Ok(B256::from_slice(&bytes))
}

fn format_rpc_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

pub async fn inspect_publication_guard(
    target: &EvmAnchorTarget,
    binding: &SignedWeb3IdentityBinding,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationGuard, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    validate_anchor_binding_for_target(target, binding, validated_target.operator)?;
    let operator_key_hash = operator_key_hash(binding)?;

    let auth_call = IChioRootRegistry::isAuthorizedPublisherForKeyHashCall {
        operator: validated_target.operator,
        publisher: validated_target.publisher,
        operatorKeyHash: operator_key_hash,
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
        AnchorError::Rpc("eth_call isAuthorizedPublisherForKeyHash did not return data".to_string())
    })?;
    let auth_bytes = hex::decode(auth_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let publisher_authorized =
        IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_decode_returns(&auth_bytes)
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
        operator_key_hash: format_rpc_b256(operator_key_hash),
        publisher_address: target.publisher_address.clone(),
        latest_checkpoint_seq,
        next_checkpoint_seq_min: latest_checkpoint_seq.saturating_add(1),
        publisher_authorized,
        requires_delegate_authorization: validated_target.publisher != validated_target.operator,
    })
}

pub async fn ensure_publication_ready(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationGuard, AnchorError> {
    let guard = inspect_publication_guard(target, binding, egress_contract).await?;
    if !guard.publisher_authorized {
        return Err(AnchorError::Verification(format!(
            "publisher {} is not authorized for operator {} on {}",
            guard.publisher_address, guard.operator_address, guard.chain_id
        )));
    }
    if checkpoint.body.checkpoint_seq != guard.next_checkpoint_seq_min {
        return Err(AnchorError::Verification(format!(
            "checkpoint sequence {} must equal {} on {}",
            checkpoint.body.checkpoint_seq, guard.next_checkpoint_seq_min, guard.chain_id
        )));
    }
    if checkpoint.body.batch_start_seq > checkpoint.body.batch_end_seq {
        return Err(AnchorError::Verification(
            "invalid checkpoint batch range".to_string(),
        ));
    }
    let latest_batch_end_seq = if guard.latest_checkpoint_seq == 0 {
        0
    } else {
        fetch_latest_root_batch_end_seq(target, guard.latest_checkpoint_seq, egress_contract)
            .await?
    };
    let expected_batch_start_seq = latest_batch_end_seq.checked_add(1).ok_or_else(|| {
        AnchorError::Verification("latest root batch_end_seq overflowed u64".to_string())
    })?;
    if checkpoint.body.batch_start_seq != expected_batch_start_seq {
        return Err(AnchorError::Verification(format!(
            "checkpoint batch_start_seq {} must equal latest root batch_end_seq + 1 ({}) on {}",
            checkpoint.body.batch_start_seq, expected_batch_start_seq, guard.chain_id
        )));
    }
    Ok(guard)
}

fn validate_anchor_binding_for_target(
    target: &EvmAnchorTarget,
    binding: &SignedWeb3IdentityBinding,
    operator: Address,
) -> Result<(), AnchorError> {
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Anchor)
    {
        return Err(AnchorError::InvalidBinding(
            "binding certificate does not include anchor purpose".to_string(),
        ));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &target.chain_id)
    {
        return Err(AnchorError::InvalidBinding(format!(
            "binding certificate does not cover {}",
            target.chain_id
        )));
    }
    let binding_operator = parse_nonzero_evm_address(
        "binding settlement address",
        &binding.certificate.settlement_address,
    )?;
    if binding_operator != operator {
        return Err(AnchorError::InvalidBinding(format!(
            "binding settlement address {} does not match operator address {}",
            binding.certificate.settlement_address, target.operator_address
        )));
    }
    Ok(())
}

async fn fetch_latest_root_batch_end_seq(
    target: &EvmAnchorTarget,
    latest_checkpoint_seq: u64,
    egress_contract: &HttpEgressContract,
) -> Result<u64, AnchorError> {
    let validated_target = parse_validated_evm_anchor_target(target)?;
    let latest_root_call = IChioRootRegistry::getLatestRootCall {
        operator: validated_target.operator,
    };
    let latest_root_response = rpc_call(
        &target.rpc_url,
        egress_contract,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(latest_root_call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let latest_root_raw = latest_root_response.as_str().ok_or_else(|| {
        AnchorError::Rpc("eth_call getLatestRoot did not return data".to_string())
    })?;
    let latest_root_bytes = hex::decode(latest_root_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let latest_root = IChioRootRegistry::getLatestRootCall::abi_decode_returns(&latest_root_bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    if latest_root.checkpointSeq != latest_checkpoint_seq {
        return Err(AnchorError::Verification(format!(
            "latest root checkpoint sequence {} does not match latest sequence {}",
            latest_root.checkpointSeq, latest_checkpoint_seq
        )));
    }
    Ok(latest_root.batchEndSeq)
}
