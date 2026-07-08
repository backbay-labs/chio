//! EVM ABI encode/decode, log extraction, and JSON-RPC transport helpers.

use super::*;

pub(super) fn parse_log_entry(value: &Value) -> Result<EvmLogEntry, SettlementError> {
    let address = value
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing address".to_string()))?;
    parse_address(address, "log.address")?;
    let topics = value
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| SettlementError::Rpc("log missing topics".to_string()))?
        .iter()
        .map(|topic| {
            topic
                .as_str()
                .ok_or_else(|| SettlementError::Rpc("log topic was not a string".to_string()))
                .and_then(|topic| {
                    parse_b256_hex(topic, "log.topic")?;
                    Ok(topic.to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing data".to_string()))?
        .to_string();
    decode_hex_bytes(&data)?;
    let log_index = value
        .get("logIndex")
        .and_then(Value::as_str)
        .map(parse_hex_u64)
        .transpose()?;
    Ok(EvmLogEntry {
        address: address.to_string(),
        topics,
        data,
        log_index,
    })
}

pub(super) fn extract_escrow_created_id(
    receipt: &EvmTransactionReceipt,
    escrow_contract: &str,
) -> Result<String, SettlementError> {
    extract_event_topic(
        receipt,
        escrow_contract,
        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
        1,
        "escrow_id",
    )
}

pub(super) fn extract_bond_locked_identity(
    receipt: &EvmTransactionReceipt,
    bond_vault_contract: &str,
) -> Result<(String, String, String), SettlementError> {
    let log = find_single_contract_event(
        receipt,
        bond_vault_contract,
        "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
    )?;
    Ok((
        extract_topic_hex(log, 1, "vault_id")?,
        extract_topic_hex(log, 2, "bond_id")?,
        extract_topic_hex(log, 3, "facility_id")?,
    ))
}

pub(super) fn extract_event_topic(
    receipt: &EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
    topic_index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let log = find_single_contract_event(receipt, contract_address, event_signature)?;
    extract_topic_hex(log, topic_index, field)
}

pub(super) fn find_single_contract_event<'a>(
    receipt: &'a EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
) -> Result<&'a EvmLogEntry, SettlementError> {
    let contract = normalize_address(contract_address);
    let signature_hash = event_signature_hash(event_signature);
    let mut matches = receipt.logs.iter().filter(|log| {
        normalize_address(&log.address) == contract
            && log.topics.first().map(|topic| normalize_b256(topic)) == Some(signature_hash.clone())
    });
    let first = matches.next().ok_or_else(|| {
        SettlementError::InvalidDispatch(format!(
            "transaction {} did not emit {event_signature} from {contract_address}",
            receipt.tx_hash
        ))
    })?;
    if matches.next().is_some() {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} emitted multiple {event_signature} events from {contract_address}",
            receipt.tx_hash
        )));
    }
    Ok(first)
}

pub(super) fn extract_topic_hex(
    log: &EvmLogEntry,
    index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let topic = log.topics.get(index).ok_or_else(|| {
        SettlementError::InvalidDispatch(format!("{field} missing from contract event topics"))
    })?;
    Ok(format_b256(parse_b256_hex(topic, field)?))
}

pub(super) fn event_signature_hash(signature: &str) -> String {
    format_b256(keccak256(signature.as_bytes()))
}

pub(super) fn normalize_address(value: &str) -> String {
    value.to_ascii_lowercase()
}

pub(super) fn normalize_b256(value: &str) -> String {
    value.to_ascii_lowercase()
}

pub(super) async fn eth_call_raw(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    eth_call_raw_at_block(config, call, "latest").await
}

pub(super) async fn eth_call_raw_at_block(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
    block_tag: &str,
) -> Result<String, SettlementError> {
    let result = rpc_call(config, "eth_call", json!([request_value(call), block_tag])).await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_call returned non-string".to_string()))
}

pub(super) async fn rpc_call(
    config: &SettlementChainConfig,
    method: &str,
    params: Value,
) -> Result<Value, SettlementError> {
    config.validate_rpc_egress_contract()?;
    let contract = &config.egress_contract;
    let client = client_builder_with_contract(contract)
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build: {error}")))?;
    let request = client
        .post(&config.rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build request: {error}")))?;
    let response = send_with_contract(contract, &client, request)
        .await
        .map_err(|error| {
            SettlementError::Rpc(format!(
                "HttpEgressContract rejects settlement RPC dispatch: {error}"
            ))
        })?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        let data = error
            .data
            .as_ref()
            .map(|data| format!(" data {data}"))
            .unwrap_or_default();
        return Err(SettlementError::Rpc(format!(
            "{} (code {}){}",
            error.message, error.code, data
        )));
    }
    envelope
        .result
        .ok_or_else(|| SettlementError::Rpc(format!("{method} returned no result")))
}

pub(super) fn request_value(call: &PreparedEvmCall) -> Value {
    let mut value = json!({
        "from": call.from_address,
        "to": call.to_address,
        "data": call.data,
    });
    if let Some(gas_limit) = call.gas_limit {
        value["gas"] = Value::String(format!("0x{gas_limit:x}"));
    }
    value
}

pub(super) fn parse_eip155_chain_id(chain_id: &str) -> Result<u64, SettlementError> {
    let raw = chain_id
        .strip_prefix("eip155:")
        .ok_or_else(|| SettlementError::Unsupported(format!("unsupported chain id {chain_id}")))?;
    raw.parse::<u64>()
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))
}

pub(super) fn encode_call<C: SolCall>(call: C) -> String {
    format!("0x{}", hex::encode(call.abi_encode()))
}

pub(super) fn parse_address(value: &str, field: &str) -> Result<Address, SettlementError> {
    Address::from_str(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))
}

pub(super) fn parse_b256_hex(value: &str, field: &str) -> Result<B256, SettlementError> {
    let hash = Hash::from_hex(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))?;
    Ok(hash_to_b256(&hash))
}

pub(super) fn hash_to_b256(hash: &Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

pub(super) fn hash_string_id(value: &str) -> B256 {
    keccak256(value.as_bytes())
}

pub(super) fn format_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

pub(super) fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, SettlementError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Serialization(error.to_string()))
}

pub(super) fn parse_hex_u64(value: &str) -> Result<u64, SettlementError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| SettlementError::Rpc(error.to_string()))
}

pub(super) fn u256_to_u128(value: U256, field: &str) -> Result<u128, SettlementError> {
    let limbs = value.into_limbs();
    if limbs[2] != 0 || limbs[3] != 0 {
        return Err(SettlementError::InvalidInput(format!(
            "{field} does not fit u128"
        )));
    }
    Ok((u128::from(limbs[1]) << 64) | u128::from(limbs[0]))
}
