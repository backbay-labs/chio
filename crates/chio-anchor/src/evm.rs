use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::SolCall;
use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::leaf_hash;
use chio_core::web3::{
    verify_anchor_inclusion_proof, AnchorInclusionProof, SignedWeb3IdentityBinding,
    Web3ChainAnchorRecord, Web3KeyBindingPurpose,
};
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use chio_kernel::checkpoint::KernelCheckpoint;
use chio_web3_bindings::{ChioMerkleProof, IChioRootRegistry};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AnchorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmAnchorTarget {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmRootPublication {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub checkpoint_seq: u64,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub tree_size: u64,
    pub merkle_root: chio_core::hashing::Hash,
    pub operator_key_hash: String,
    pub call_data: String,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDelegateRegistration {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub delegate_address: String,
    pub expires_at: u64,
    pub call_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationGuard {
    pub chain_id: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub latest_checkpoint_seq: u64,
    pub next_checkpoint_seq_min: u64,
    pub publisher_authorized: bool,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: u64,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub fn operator_key_hash(binding: &SignedWeb3IdentityBinding) -> B256 {
    keccak256(binding.certificate.chio_public_key.as_bytes())
}

pub fn operator_key_hash_hex(binding: &SignedWeb3IdentityBinding) -> String {
    format!("0x{}", hex::encode(operator_key_hash(binding).as_slice()))
}

pub fn prepare_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEvmRootPublication, AnchorError> {
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
    if binding.certificate.settlement_address != target.operator_address {
        return Err(AnchorError::InvalidBinding(format!(
            "binding settlement address {} does not match operator address {}",
            binding.certificate.settlement_address, target.operator_address
        )));
    }
    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let call = IChioRootRegistry::publishRootCall {
        operator,
        merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
        checkpointSeq: checkpoint.body.checkpoint_seq,
        batchStartSeq: checkpoint.body.batch_start_seq,
        batchEndSeq: checkpoint.body.batch_end_seq,
        treeSize: checkpoint.body.tree_size as u64,
        operatorKeyHash: operator_key_hash(binding),
    };

    Ok(PreparedEvmRootPublication {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        publisher_address: target.publisher_address.clone(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        batch_start_seq: checkpoint.body.batch_start_seq,
        batch_end_seq: checkpoint.body.batch_end_seq,
        tree_size: checkpoint.body.tree_size as u64,
        merkle_root: checkpoint.body.merkle_root,
        operator_key_hash: operator_key_hash_hex(binding),
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
        requires_delegate_authorization: target.publisher_address != target.operator_address,
    })
}

pub fn prepare_delegate_registration(
    target: &EvmAnchorTarget,
    delegate_address: &str,
    expires_at: u64,
) -> Result<PreparedDelegateRegistration, AnchorError> {
    if delegate_address.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "delegate address is required".to_string(),
        ));
    }
    if expires_at == 0 {
        return Err(AnchorError::InvalidInput(
            "delegate expiry must be non-zero".to_string(),
        ));
    }

    let delegate = Address::from_str(delegate_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let call = IChioRootRegistry::registerDelegateCall {
        delegate,
        expiresAt: expires_at,
    };
    Ok(PreparedDelegateRegistration {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        delegate_address: delegate_address.to_string(),
        expires_at,
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
    })
}

pub async fn publish_root(
    publication: &PreparedEvmRootPublication,
    egress_contract: &HttpEgressContract,
) -> Result<String, AnchorError> {
    let gas_limit = estimate_publication_gas(publication, egress_contract)
        .await?
        .saturating_mul(12)
        .saturating_div(10)
        .saturating_add(50_000);
    let result = rpc_call(
        &publication.rpc_url,
        egress_contract,
        "eth_sendTransaction",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
            "gas": format!("0x{gas_limit:x}"),
        }]),
    )
    .await?;

    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| AnchorError::Rpc("eth_sendTransaction did not return a tx hash".to_string()))
}

async fn estimate_publication_gas(
    publication: &PreparedEvmRootPublication,
    egress_contract: &HttpEgressContract,
) -> Result<u64, AnchorError> {
    let result = rpc_call(
        &publication.rpc_url,
        egress_contract,
        "eth_estimateGas",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
        }]),
    )
    .await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            AnchorError::Rpc("eth_estimateGas did not return a string".to_string())
        })?,
    )
}

pub async fn confirm_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    tx_hash: &str,
    egress_contract: &HttpEgressContract,
) -> Result<EvmPublicationReceipt, AnchorError> {
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

    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let get_root = IChioRootRegistry::getRootCall {
        operator,
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
        || stored.operatorKeyHash != operator_key_hash(binding)
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
    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let publisher = Address::from_str(&target.publisher_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;

    let auth_call = IChioRootRegistry::isAuthorizedPublisherCall {
        operator,
        publisher,
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

    let seq_call = IChioRootRegistry::getLatestSeqCall { operator };
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
        requires_delegate_authorization: target.publisher_address != target.operator_address,
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
    if checkpoint_seq < guard.next_checkpoint_seq_min {
        return Err(AnchorError::Verification(format!(
            "checkpoint sequence {} must be >= {} on {}",
            checkpoint_seq, guard.next_checkpoint_seq_min, guard.chain_id
        )));
    }
    Ok(guard)
}

pub async fn verify_inclusion_onchain(
    target: &EvmAnchorTarget,
    proof: &AnchorInclusionProof,
    egress_contract: &HttpEgressContract,
) -> Result<bool, AnchorError> {
    verify_anchor_inclusion_proof(proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let operator = Address::from_str(&proof.key_binding_certificate.certificate.settlement_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
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
    let call = IChioRootRegistry::verifyInclusionDetailedCall {
        proof: evm_proof.into(),
        root: hash_to_b256(&proof.receipt_inclusion.merkle_root),
        leafHash: hash_to_b256(&leaf),
        operator,
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
        AnchorError::Rpc("eth_call verifyInclusionDetailed did not return data".to_string())
    })?;
    let bytes = hex::decode(raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let verified = IChioRootRegistry::verifyInclusionDetailedCall::abi_decode_returns(&bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    Ok(verified)
}

pub fn build_chain_anchor_record(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    confirmed: &EvmPublicationReceipt,
) -> Web3ChainAnchorRecord {
    Web3ChainAnchorRecord {
        chain_id: target.chain_id.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        tx_hash: confirmed.tx_hash.clone(),
        block_number: confirmed.block_number,
        block_hash: confirmed.block_hash.clone(),
        anchored_merkle_root: checkpoint.body.merkle_root,
        anchored_checkpoint_seq: checkpoint.body.checkpoint_seq,
    }
}

async fn rpc_call(
    rpc_url: &str,
    egress_contract: &HttpEgressContract,
    method: &str,
    params: Value,
) -> Result<Value, AnchorError> {
    validate_rpc_egress_contract(rpc_url, egress_contract)?;
    let client = client_builder_with_contract(egress_contract)
        .build()
        .map_err(|error| AnchorError::Rpc(format!("reqwest build: {error}")))?;
    let request = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .build()
        .map_err(|error| AnchorError::Rpc(format!("reqwest build request: {error}")))?;
    let response = send_with_contract(egress_contract, &client, request)
        .await
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "HttpEgressContract rejects anchor EVM RPC dispatch: {error}"
            ))
        })?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(AnchorError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    envelope
        .result
        .ok_or_else(|| AnchorError::Rpc(format!("{} returned no result", method)))
}

pub fn evm_anchor_devnet_rpc_egress_contract(
    rpc_url: &str,
) -> Result<HttpEgressContract, AnchorError> {
    devnet_rpc_egress_contract_for_url("chio-anchor-evm-devnet-rpc", rpc_url)
}

fn validate_rpc_egress_contract(
    rpc_url: &str,
    contract: &HttpEgressContract,
) -> Result<(), AnchorError> {
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "invalid anchor EVM RPC HttpEgressContract: {error}"
            ))
        })?;
    contract.enforce_url_with_dns(rpc_url, 0).map_err(|error| {
        AnchorError::Rpc(format!(
            "anchor EVM RPC URL is not allowed by HttpEgressContract: {error}"
        ))
    })?;
    Ok(())
}

fn devnet_rpc_egress_contract_for_url(
    namespace: &str,
    rpc_url: &str,
) -> Result<HttpEgressContract, AnchorError> {
    let url = Url::parse(rpc_url)
        .map_err(|error| AnchorError::Rpc(format!("invalid anchor EVM RPC URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| AnchorError::Rpc("anchor EVM RPC URL must include a host".to_string()))?;
    if !rpc_host_is_loopback(host) {
        return Err(AnchorError::InvalidInput(
            "devnet anchor EVM RPC egress contract requires a loopback RPC URL".to_string(),
        ));
    }
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(url.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(normalized_rpc_authority(&url, host));
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 64 * 1024 * 1024,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "invalid anchor EVM RPC HttpEgressContract: {error}"
            ))
        })?;
    contract.enforce_url_with_dns(rpc_url, 0).map_err(|error| {
        AnchorError::Rpc(format!(
            "anchor EVM RPC URL is not allowed by HttpEgressContract: {error}"
        ))
    })?;
    Ok(contract)
}

fn normalized_rpc_authority(url: &Url, host: &str) -> String {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn rpc_host_is_loopback(host: &str) -> bool {
    matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "localhost" | "localhost.localdomain"
    ) || host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn hash_to_b256(hash: &chio_core::hashing::Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

fn parse_hex_u64(value: &str) -> Result<u64, AnchorError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| AnchorError::Rpc(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use alloy_sol_types::SolCall;
    use chio_core::web3::{AnchorInclusionProof, SignedWeb3IdentityBinding, Web3KeyBindingPurpose};
    use chio_kernel::checkpoint::KernelCheckpoint;
    use chio_web3_bindings::IChioRootRegistry;
    use serde_json::{json, Value};

    use super::{
        build_chain_anchor_record, confirm_root_publication, ensure_publication_ready,
        evm_anchor_devnet_rpc_egress_contract, hash_to_b256, inspect_publication_guard,
        operator_key_hash, prepare_delegate_registration, prepare_root_publication, publish_root,
        validate_rpc_egress_contract, verify_inclusion_onchain, EvmAnchorTarget,
        EvmPublicationReceipt, HttpEgressContract,
    };

    trait TestResultOk<T, E> {
        fn test_expect(self, context: &'static str) -> T;
    }

    impl<T, E> TestResultOk<T, E> for Result<T, E> {
        fn test_expect(self, context: &'static str) -> T {
            match self {
                Ok(value) => value,
                Err(_) => panic!("{context}"),
            }
        }
    }

    trait TestResultErr<T, E> {
        fn test_expect_err(self, context: &'static str) -> E;
    }

    impl<T, E> TestResultErr<T, E> for Result<T, E> {
        fn test_expect_err(self, context: &'static str) -> E {
            match self {
                Ok(_) => panic!("{context} unexpectedly succeeded"),
                Err(error) => error,
            }
        }
    }

    fn bind_mock_json_rpc_listener() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::AddrNotAvailable
                        | std::io::ErrorKind::Unsupported
                ) =>
            {
                eprintln!("skipping EVM JSON-RPC test: loopback TCP bind unavailable: {err}");
                None
            }
            Err(err) => panic!("bind mock JSON-RPC listener: {err}"),
        }
    }

    struct MockJsonRpcServer {
        base_url: String,
        requests: Arc<Mutex<Vec<Value>>>,
        handle: thread::JoinHandle<()>,
    }

    struct MockRawHttpServer {
        base_url: String,
        handle: thread::JoinHandle<()>,
    }

    impl MockJsonRpcServer {
        fn spawn(envelopes: Vec<Value>) -> Option<Self> {
            let listener = bind_mock_json_rpc_listener()?;
            let address = listener.local_addr().test_expect("listener address");
            let base_url = format!("http://127.0.0.1:{}", address.port());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);

            let handle = thread::spawn(move || {
                for envelope in envelopes {
                    let (mut stream, _) = listener.accept().test_expect("accept mock request");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .test_expect("set read timeout");
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .test_expect("lock request log")
                        .push(parse_json_request(&request));
                    write_http_json_response(&mut stream, 200, &envelope);
                    stream.flush().test_expect("flush mock response");
                }
            });

            Some(Self {
                base_url,
                requests,
                handle,
            })
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn requests(&self) -> Vec<Value> {
            self.requests.lock().test_expect("lock request log").clone()
        }

        fn join(self) {
            self.handle.join().test_expect("join mock JSON-RPC server");
        }
    }

    impl MockRawHttpServer {
        fn spawn(response: String) -> Option<Self> {
            let listener = bind_mock_json_rpc_listener()?;
            let address = listener.local_addr().test_expect("listener address");
            let base_url = format!("http://127.0.0.1:{}", address.port());

            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().test_expect("accept mock request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .test_expect("set read timeout");
                let _request = read_http_request(&mut stream);
                stream
                    .write_all(response.as_bytes())
                    .test_expect("write mock response");
                stream.flush().test_expect("flush mock response");
            });

            Some(Self { base_url, handle })
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn join(self) {
            self.handle.join().test_expect("join mock raw server");
        }
    }

    fn sample_primary_proof() -> AnchorInclusionProof {
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
        ))
        .test_expect("parse primary proof example")
    }

    fn sample_binding() -> SignedWeb3IdentityBinding {
        sample_primary_proof().key_binding_certificate
    }

    fn sample_checkpoint() -> KernelCheckpoint {
        crate::kernel_checkpoint_from_statement(&sample_primary_proof().checkpoint_statement)
    }

    fn sample_target(rpc_url: &str) -> EvmAnchorTarget {
        let binding = sample_binding();
        EvmAnchorTarget {
            chain_id: "eip155:8453".to_string(),
            rpc_url: rpc_url.to_string(),
            contract_address: "0x1000000000000000000000000000000000000003".to_string(),
            operator_address: binding.certificate.settlement_address.clone(),
            publisher_address: binding.certificate.settlement_address,
        }
    }

    fn sample_delegate_target(rpc_url: &str) -> EvmAnchorTarget {
        let mut target = sample_target(rpc_url);
        target.publisher_address = "0x1000000000000000000000000000000000000004".to_string();
        target
    }

    fn sample_rpc_contract(rpc_url: &str) -> HttpEgressContract {
        evm_anchor_devnet_rpc_egress_contract(rpc_url).test_expect("devnet anchor egress contract")
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        })
    }

    fn rpc_error(code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": code,
                "message": message,
            }
        })
    }

    fn encode_hex(data: Vec<u8>) -> String {
        format!("0x{}", hex::encode(data))
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).test_expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8(request).test_expect("request should be valid UTF-8")
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn parse_json_request(request: &str) -> Value {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        serde_json::from_str(body).test_expect("request body should be JSON")
    }

    fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http_status_text(status),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .test_expect("write mock response");
    }

    fn http_status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    #[test]
    fn prepare_root_publication_rejects_missing_anchor_purpose() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        binding.certificate.purpose = vec![Web3KeyBindingPurpose::Settle];

        let error = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect_err("binding without anchor purpose should fail");

        assert!(matches!(error, crate::AnchorError::InvalidBinding(_)));
        assert!(error.to_string().contains("anchor purpose"));
    }

    #[test]
    fn prepare_root_publication_rejects_out_of_scope_chain() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        binding.certificate.chain_scope = vec!["eip155:1".to_string()];

        let error = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect_err("binding should reject uncovered chain");

        assert!(matches!(error, crate::AnchorError::InvalidBinding(_)));
        assert!(error.to_string().contains("does not cover"));
    }

    #[test]
    fn prepare_root_publication_rejects_settlement_address_mismatch() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        binding.certificate.settlement_address =
            "0x1000000000000000000000000000000000000009".to_string();

        let error = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect_err("binding should reject settlement mismatch");

        assert!(matches!(error, crate::AnchorError::InvalidBinding(_)));
        assert!(error
            .to_string()
            .contains("does not match operator address"));
    }

    #[test]
    fn prepare_root_publication_rejects_invalid_operator_address() {
        let checkpoint = sample_checkpoint();
        let mut target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        target.operator_address = "not-an-address".to_string();
        binding.certificate.settlement_address = target.operator_address.clone();

        let error = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect_err("invalid operator address should fail");

        assert!(matches!(error, crate::AnchorError::InvalidInput(_)));
    }

    #[test]
    fn prepare_delegate_registration_rejects_invalid_delegate_inputs() {
        let target = sample_target("http://127.0.0.1:8545");

        let blank = prepare_delegate_registration(&target, "   ", 30)
            .test_expect_err("blank delegate should fail");
        assert!(blank.to_string().contains("delegate address is required"));

        let zero = prepare_delegate_registration(&target, &target.publisher_address, 0)
            .test_expect_err("zero delegate expiry should fail");
        assert!(zero.to_string().contains("must be non-zero"));

        let invalid = prepare_delegate_registration(&target, "invalid-address", 30)
            .test_expect_err("invalid delegate address should fail");
        assert!(matches!(invalid, crate::AnchorError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn publish_root_estimates_gas_and_submits_transaction() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!("0x5208")),
            rpc_result(json!("0xabc123")),
        ]) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication =
            prepare_root_publication(&sample_target(server.base_url()), &checkpoint, &binding)
                .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract(server.base_url());

        let tx_hash = publish_root(&publication, &egress_contract)
            .await
            .test_expect("publish root");

        assert_eq!(tx_hash, "0xabc123");
        let requests = server.requests();
        server.join();

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["method"], "eth_estimateGas");
        assert_eq!(requests[1]["method"], "eth_sendTransaction");
        assert_eq!(
            requests[1]["params"][0]["gas"],
            json!(format!("0x{:x}", 21_000_u64 * 12 / 10 + 50_000))
        );
    }

    #[tokio::test]
    async fn publish_root_rejects_non_string_transaction_hash() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!("0x5208")),
            rpc_result(json!({ "txHash": "0xabc123" })),
        ]) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication =
            prepare_root_publication(&sample_target(server.base_url()), &checkpoint, &binding)
                .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = publish_root(&publication, &egress_contract)
            .await
            .test_expect_err("non-string tx hash should fail");

        server.join();
        assert!(error.to_string().contains("did not return a tx hash"));
    }

    #[tokio::test]
    async fn publish_root_surfaces_rpc_error_envelope() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!("0x5208")),
            rpc_error(-32000, "denied"),
        ]) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication =
            prepare_root_publication(&sample_target(server.base_url()), &checkpoint, &binding)
                .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = publish_root(&publication, &egress_contract)
            .await
            .test_expect_err("RPC error should fail");

        server.join();
        assert!(error.to_string().contains("denied"));
        assert!(error.to_string().contains("-32000"));
    }

    #[test]
    fn validate_rpc_egress_contract_accepts_hostname_rpc() {
        let egress_contract = HttpEgressContract {
            tenant_egress_namespace: "chio-anchor-unit-rpc".to_string(),
            allowed_schemes: std::collections::BTreeSet::from(["https".to_string()]),
            allowed_authority_set: std::collections::BTreeSet::from(["rpc.example".to_string()]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 64 * 1024 * 1024,
        };

        validate_rpc_egress_contract("https://rpc.example", &egress_contract)
            .test_expect("hostname RPC dispatch is resolver-enforced");
    }

    #[test]
    fn devnet_rpc_egress_contract_only_authorizes_loopback() {
        assert!(evm_anchor_devnet_rpc_egress_contract("http://127.0.0.1:8545").is_ok());
        assert!(evm_anchor_devnet_rpc_egress_contract("http://localhost:8545").is_ok());
        for rpc_url in [
            "http://10.0.0.5:8545",
            "http://192.168.1.20:8545",
            "http://172.16.0.2:8545",
            "http://203.0.113.10:8545",
        ] {
            let error = evm_anchor_devnet_rpc_egress_contract(rpc_url)
                .test_expect_err("non-loopback devnet RPC URL should fail");
            assert!(
                error.to_string().contains("requires a loopback RPC URL"),
                "unexpected devnet egress error for {rpc_url}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn publish_root_does_not_self_authorize_rpc_url_authority() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication = prepare_root_publication(
            &sample_target("http://127.0.0.1:8545"),
            &checkpoint,
            &binding,
        )
        .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract("http://127.0.0.1:9545");

        let error = publish_root(&publication, &egress_contract)
            .await
            .test_expect_err("RPC URL must not authorize itself");
        let message = error.to_string();

        assert!(
            message.contains("HttpEgressContract") && message.contains("is not allowed"),
            "unexpected anchor RPC self-authorization denial: {message}"
        );
    }

    #[tokio::test]
    async fn publish_root_rejects_rpc_redirects() {
        let Some(server) = MockRawHttpServer::spawn(
            "HTTP/1.1 302 Found\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        ) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication =
            prepare_root_publication(&sample_target(server.base_url()), &checkpoint, &binding)
                .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = publish_root(&publication, &egress_contract)
            .await
            .test_expect_err("RPC redirect should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("redirect chain length"),
            "unexpected anchor RPC redirect denial: {message}"
        );
    }

    #[tokio::test]
    async fn publish_root_rejects_oversized_rpc_response() {
        let Some(server) = MockRawHttpServer::spawn(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n"
                .to_string(),
        ) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let publication =
            prepare_root_publication(&sample_target(server.base_url()), &checkpoint, &binding)
                .test_expect("prepare publication");
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = publish_root(&publication, &egress_contract)
            .await
            .test_expect_err("oversized RPC response should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("response size"),
            "unexpected anchor RPC response-size denial: {message}"
        );
    }

    #[tokio::test]
    async fn confirm_root_publication_decodes_matching_registry_entry() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let stored = encode_hex(IChioRootRegistry::getRootCall::abi_encode_returns(
            &IChioRootRegistry::RootEntry {
                merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
                checkpointSeq: checkpoint.body.checkpoint_seq,
                batchStartSeq: checkpoint.body.batch_start_seq,
                batchEndSeq: checkpoint.body.batch_end_seq,
                treeSize: checkpoint.body.tree_size as u64,
                publishedAt: 1_744_000_123_u64,
                operatorKeyHash: operator_key_hash(&binding),
            },
        ));
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({
                "blockNumber": "0x2a",
                "blockHash": "0xabc",
                "status": "0x1",
            })),
            rpc_result(json!(stored)),
        ]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let receipt = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            "0xdeadbeef",
            &egress_contract,
        )
        .await
        .test_expect("confirm publication");

        let requests = server.requests();
        server.join();

        assert_eq!(receipt.tx_hash, "0xdeadbeef");
        assert_eq!(receipt.block_number, 42);
        assert_eq!(receipt.published_at, 1_744_000_123);
        assert_eq!(requests[0]["method"], "eth_getTransactionReceipt");
        assert_eq!(requests[1]["method"], "eth_call");
    }

    #[tokio::test]
    async fn confirm_root_publication_rejects_failed_transaction_status() {
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(json!({
            "blockNumber": "0x2a",
            "blockHash": "0xabc",
            "status": "0x0",
        }))]) else {
            return;
        };
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            "0xdeadbeef",
            &egress_contract,
        )
        .await
        .test_expect_err("failed tx status should fail");

        server.join();
        assert!(error.to_string().contains("failed with status 0x0"));
    }

    #[tokio::test]
    async fn confirm_root_publication_rejects_registry_mismatch() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let stored = encode_hex(IChioRootRegistry::getRootCall::abi_encode_returns(
            &IChioRootRegistry::RootEntry {
                merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
                checkpointSeq: checkpoint.body.checkpoint_seq,
                batchStartSeq: checkpoint.body.batch_start_seq,
                batchEndSeq: checkpoint.body.batch_end_seq,
                treeSize: checkpoint.body.tree_size as u64 + 1,
                publishedAt: 1_744_000_123_u64,
                operatorKeyHash: operator_key_hash(&binding),
            },
        ));
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({
                "blockNumber": "0x2a",
                "blockHash": "0xabc",
                "status": "0x1",
            })),
            rpc_result(json!(stored)),
        ]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            "0xdeadbeef",
            &egress_contract,
        )
        .await
        .test_expect_err("mismatched registry entry should fail");

        server.join();
        assert!(error
            .to_string()
            .contains("root registry entry does not match"));
    }

    #[tokio::test]
    async fn inspect_publication_guard_decodes_authorization_and_sequence() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let guard = inspect_publication_guard(&target, &egress_contract)
            .await
            .test_expect("inspect guard");

        server.join();
        assert!(guard.publisher_authorized);
        assert_eq!(guard.latest_checkpoint_seq, 41);
        assert_eq!(guard.next_checkpoint_seq_min, 42);
        assert!(guard.requires_delegate_authorization);
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_unauthorized_publisher() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherCall::abi_encode_returns(&false)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, 42, &egress_contract)
            .await
            .test_expect_err("unauthorized publisher should fail");

        server.join();
        assert!(error.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_checkpoint_regression() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, 41, &egress_contract)
            .await
            .test_expect_err("checkpoint regression should fail");

        server.join();
        assert!(error.to_string().contains("must be >="));
    }

    #[tokio::test]
    async fn ensure_publication_ready_accepts_next_checkpoint() {
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let guard = ensure_publication_ready(&target, 42, &egress_contract)
            .await
            .test_expect("checkpoint 42 should be accepted");

        server.join();
        assert_eq!(guard.next_checkpoint_seq_min, 42);
    }

    #[tokio::test]
    async fn verify_inclusion_onchain_decodes_registry_verdict() {
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
            IChioRootRegistry::verifyInclusionDetailedCall::abi_encode_returns(&true)
        )))]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let proof = sample_primary_proof();
        let egress_contract = sample_rpc_contract(server.base_url());

        let verified = verify_inclusion_onchain(&target, &proof, &egress_contract)
            .await
            .test_expect("verify inclusion");

        let requests = server.requests();
        server.join();

        assert!(verified);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "eth_call");
    }

    #[test]
    fn build_chain_anchor_record_copies_confirmation_metadata() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let confirmed = EvmPublicationReceipt {
            tx_hash: "0xdeadbeef".to_string(),
            block_number: 42,
            block_hash: "0xabc".to_string(),
            published_at: 1_744_000_123,
        };

        let record = build_chain_anchor_record(&target, &checkpoint, &confirmed);

        assert_eq!(record.chain_id, target.chain_id);
        assert_eq!(record.contract_address, target.contract_address);
        assert_eq!(record.operator_address, target.operator_address);
        assert_eq!(record.tx_hash, confirmed.tx_hash);
        assert_eq!(record.block_number, confirmed.block_number);
        assert_eq!(record.anchored_merkle_root, checkpoint.body.merkle_root);
    }
}
