mod egress;
mod hashing;
mod preparation;
mod publication;
mod records;
mod rpc;
mod types;
mod validation;
mod verification;

pub use egress::evm_anchor_devnet_rpc_egress_contract;
#[cfg(test)]
use egress::validate_rpc_egress_contract;
#[cfg(test)]
use hashing::hash_to_b256;
pub use preparation::{prepare_delegate_registration, prepare_root_publication};
pub use publication::{
    confirm_root_publication, ensure_publication_ready, inspect_publication_guard,
};
pub use records::build_chain_anchor_record;
pub use rpc::publish_root;
pub use types::{
    EvmAnchorTarget, EvmPublicationGuard, EvmPublicationReceipt, PreparedDelegateRegistration,
    PreparedEvmRootPublication,
};
pub use verification::verify_inclusion_onchain;

use crate::AnchorError;

#[cfg(test)]
use chio_egress_contract::HttpEgressContract;

pub(crate) use validation::parse_validated_evm_anchor_target;

pub fn operator_key_hash(
    binding: &chio_core::web3::identity::SignedWeb3IdentityBinding,
) -> Result<alloy_primitives::B256, AnchorError> {
    hashing::operator_key_hash(binding)
}

pub fn operator_key_hash_hex(
    binding: &chio_core::web3::identity::SignedWeb3IdentityBinding,
) -> Result<String, AnchorError> {
    hashing::operator_key_hash_hex(binding)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use alloy_primitives::keccak256;
    use alloy_sol_types::SolCall;
    use chio_core::crypto::PublicKey;
    use chio_core::web3::anchors::AnchorInclusionProof;
    use chio_core::web3::identity::{SignedWeb3IdentityBinding, Web3KeyBindingPurpose};
    use chio_kernel::checkpoint::KernelCheckpoint;
    use chio_web3_bindings::IChioRootRegistry;
    use serde_json::{json, Value};

    use super::{
        build_chain_anchor_record, confirm_root_publication, ensure_publication_ready,
        evm_anchor_devnet_rpc_egress_contract, hash_to_b256, inspect_publication_guard,
        operator_key_hash, operator_key_hash_hex, prepare_delegate_registration,
        prepare_root_publication, publish_root, validate_rpc_egress_contract,
        verify_inclusion_onchain, EvmAnchorTarget, EvmPublicationReceipt, HttpEgressContract,
    };

    use chio_test_support::prelude::*;

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
            "../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
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

    const CONFIRM_TX_HASH: &str =
        "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead";
    const CONFIRM_BLOCK_HASH: &str =
        "0xabababababababababababababababababababababababababababababababab";

    fn successful_publication_receipt(
        target: &EvmAnchorTarget,
        checkpoint: &KernelCheckpoint,
        binding: &SignedWeb3IdentityBinding,
        tx_hash: &str,
    ) -> Value {
        json!({
            "blockNumber": "0x2a",
            "blockHash": CONFIRM_BLOCK_HASH,
            "transactionHash": tx_hash,
            "to": target.contract_address,
            "status": "0x1",
            "logs": [root_published_log(target, checkpoint, binding, tx_hash)],
        })
    }

    fn root_published_log(
        target: &EvmAnchorTarget,
        checkpoint: &KernelCheckpoint,
        binding: &SignedWeb3IdentityBinding,
        tx_hash: &str,
    ) -> Value {
        let operator_key_hash = operator_key_hash(binding).test_expect("operator key hash");
        let mut data = Vec::with_capacity(32 * 7);
        data.extend_from_slice(hash_to_b256(&checkpoint.body.merkle_root).as_slice());
        push_abi_u64(&mut data, checkpoint.body.batch_start_seq);
        push_abi_u64(&mut data, checkpoint.body.batch_end_seq);
        push_abi_u64(&mut data, checkpoint.body.tree_size as u64);
        push_abi_u64(&mut data, 1_744_000_123_u64);
        data.extend_from_slice(operator_key_hash.as_slice());
        push_abi_u64(&mut data, 1);
        json!({
            "address": target.contract_address,
            "topics": [
                root_published_topic0(),
                address_topic(&target.operator_address),
                address_topic(&target.publisher_address),
                u64_topic(checkpoint.body.checkpoint_seq),
            ],
            "data": format!("0x{}", hex::encode(data)),
            "transactionHash": tx_hash,
            "blockHash": CONFIRM_BLOCK_HASH,
            "blockNumber": "0x2a",
        })
    }

    fn push_abi_u64(data: &mut Vec<u8>, value: u64) {
        data.extend_from_slice(&[0_u8; 24]);
        data.extend_from_slice(&value.to_be_bytes());
    }

    fn root_published_topic0() -> String {
        format!(
            "0x{}",
            hex::encode(
                keccak256(
                    "RootPublished(address,address,uint64,bytes32,uint64,uint64,uint64,uint64,bytes32,uint64)"
                        .as_bytes()
                )
                .as_slice()
            )
        )
    }

    fn address_topic(address: &str) -> String {
        let address_hex = address
            .strip_prefix("0x")
            .test_expect("test EVM address has 0x prefix");
        format!("0x{}{}", "0".repeat(24), address_hex.to_ascii_lowercase())
    }

    fn u64_topic(value: u64) -> String {
        format!("0x{value:064x}")
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
    fn prepare_root_publication_accepts_operator_address_case_mismatch() {
        let checkpoint = sample_checkpoint();
        let mut target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        target.operator_address = "0x735f1ba389d9d350501db8fbbb5b52477dcadda8".to_string();
        binding.certificate.settlement_address =
            "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();

        let prepared = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect("matching EVM operator addresses should prepare");

        assert_eq!(prepared.operator_address, target.operator_address);
    }

    #[test]
    fn prepare_root_publication_rejects_non_ed25519_operator_key() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let mut binding = sample_binding();
        let mut encoded_point = [0u8; 65];
        encoded_point[0] = 0x04;
        binding.certificate.chio_public_key =
            PublicKey::from_p256_sec1(&encoded_point).test_expect("P-256 key parses");

        let error = prepare_root_publication(&target, &checkpoint, &binding)
            .test_expect_err("non-Ed25519 operator key should fail");

        assert!(matches!(error, crate::AnchorError::InvalidBinding(_)));
        assert!(error.to_string().contains("Ed25519"));
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
    fn evm_anchor_target_validation_rejects_malformed_boundary_fields() {
        let target = sample_target("http://127.0.0.1:8545");
        target.validate().test_expect("sample target is valid");

        let mut bad_chain = target.clone();
        bad_chain.chain_id = "8453".to_string();
        let chain_error = bad_chain
            .validate()
            .test_expect_err("non-CAIP EVM chain id should fail");
        assert!(chain_error.to_string().contains("eip155"));

        let mut bad_rpc = target.clone();
        bad_rpc.rpc_url = "ws://127.0.0.1:8545".to_string();
        let rpc_error = bad_rpc
            .validate()
            .test_expect_err("non-HTTP RPC URL should fail");
        assert!(rpc_error.to_string().contains("http or https"));

        let mut bad_contract = target.clone();
        bad_contract.contract_address = "0xabc".to_string();
        let contract_error = bad_contract
            .validate()
            .test_expect_err("short contract address should fail");
        assert!(contract_error.to_string().contains("contract address"));

        let mut zero_publisher = target;
        zero_publisher.publisher_address = "0x0000000000000000000000000000000000000000".to_string();
        let publisher_error = zero_publisher
            .validate()
            .test_expect_err("zero publisher address should fail");
        assert!(publisher_error.to_string().contains("publisher address"));
        assert!(publisher_error.to_string().contains("zero address"));
    }

    #[test]
    fn prepare_root_publication_rejects_invalid_contract_and_publisher_addresses() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let mut invalid_contract = sample_target("http://127.0.0.1:8545");
        invalid_contract.contract_address = "0xabc".to_string();

        let contract_error = prepare_root_publication(&invalid_contract, &checkpoint, &binding)
            .test_expect_err("invalid contract address should fail");

        assert!(matches!(
            contract_error,
            crate::AnchorError::InvalidInput(_)
        ));
        assert!(contract_error.to_string().contains("contract address"));

        let mut invalid_publisher = sample_target("http://127.0.0.1:8545");
        invalid_publisher.publisher_address = "invalid-publisher".to_string();

        let publisher_error = prepare_root_publication(&invalid_publisher, &checkpoint, &binding)
            .test_expect_err("invalid publisher address should fail");

        assert!(matches!(
            publisher_error,
            crate::AnchorError::InvalidInput(_)
        ));
        assert!(publisher_error.to_string().contains("publisher address"));
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

    #[test]
    fn prepare_delegate_registration_rejects_invalid_target_boundary() {
        let mut target = sample_target("http://127.0.0.1:8545");
        target.contract_address = "0xabc".to_string();

        let error = prepare_delegate_registration(
            &target,
            "0x1000000000000000000000000000000000000004",
            30,
        )
        .test_expect_err("invalid target contract should fail before delegate registration");

        assert!(matches!(error, crate::AnchorError::InvalidInput(_)));
        assert!(error.to_string().contains("contract address"));
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
                operatorKeyHash: operator_key_hash(&binding).test_expect("operator key hash"),
                operatorEpoch: 1,
            },
        ));
        let target = sample_target("http://127.0.0.1:0");
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(successful_publication_receipt(
                &target,
                &checkpoint,
                &binding,
                CONFIRM_TX_HASH,
            )),
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
            CONFIRM_TX_HASH,
            &egress_contract,
        )
        .await
        .test_expect("confirm publication");

        let requests = server.requests();
        server.join();

        assert_eq!(receipt.tx_hash, CONFIRM_TX_HASH);
        assert_eq!(receipt.block_hash, CONFIRM_BLOCK_HASH);
        assert_eq!(receipt.block_number, 42);
        assert_eq!(receipt.published_at, 1_744_000_123);
        assert_eq!(
            receipt.operator_key_hash,
            format!(
                "0x{}",
                hex::encode(
                    operator_key_hash(&binding)
                        .test_expect("operator key hash")
                        .as_slice()
                )
            )
        );
        assert_eq!(requests[0]["method"], "eth_getTransactionReceipt");
        assert_eq!(requests[1]["method"], "eth_call");
        assert_eq!(requests[1]["params"][1]["blockHash"], CONFIRM_BLOCK_HASH);
        assert_eq!(requests[1]["params"][1]["requireCanonical"], true);
    }

    #[tokio::test]
    async fn confirm_root_publication_retries_with_block_number_for_ganache_block_object_error() {
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
                operatorKeyHash: operator_key_hash(&binding).test_expect("operator key hash"),
                operatorEpoch: 1,
            },
        ));
        let target = sample_target("http://127.0.0.1:0");
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(successful_publication_receipt(
                &target,
                &checkpoint,
                &binding,
                CONFIRM_TX_HASH,
            )),
            rpc_error(-32700, r#"Cannot wrap a "object" as a json-rpc type"#),
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
            CONFIRM_TX_HASH,
            &egress_contract,
        )
        .await
        .test_expect("confirm publication through Ganache fallback");

        let requests = server.requests();
        server.join();

        assert_eq!(receipt.tx_hash, CONFIRM_TX_HASH);
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1]["method"], "eth_call");
        assert_eq!(requests[1]["params"][1]["blockHash"], CONFIRM_BLOCK_HASH);
        assert_eq!(requests[1]["params"][1]["requireCanonical"], true);
        assert_eq!(requests[2]["method"], "eth_call");
        assert_eq!(requests[2]["params"][1], "0x2a");
    }

    #[tokio::test]
    async fn confirm_root_publication_rejects_failed_transaction_status() {
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(json!({
            "blockNumber": "0x2a",
            "blockHash": CONFIRM_BLOCK_HASH,
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
            CONFIRM_TX_HASH,
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
                operatorKeyHash: operator_key_hash(&binding).test_expect("operator key hash"),
                operatorEpoch: 1,
            },
        ));
        let target = sample_target("http://127.0.0.1:0");
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(successful_publication_receipt(
                &target,
                &checkpoint,
                &binding,
                CONFIRM_TX_HASH,
            )),
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
            CONFIRM_TX_HASH,
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
    async fn confirm_root_publication_rejects_receipt_without_matching_event() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let target = sample_target("http://127.0.0.1:0");
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(json!({
            "blockNumber": "0x2a",
            "blockHash": CONFIRM_BLOCK_HASH,
            "transactionHash": CONFIRM_TX_HASH,
            "to": target.contract_address,
            "status": "0x1",
            "logs": [],
        }))]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            CONFIRM_TX_HASH,
            &egress_contract,
        )
        .await
        .test_expect_err("receipt without event should fail");

        let requests = server.requests();
        server.join();
        assert_eq!(requests.len(), 1);
        assert!(error
            .to_string()
            .contains("missing matching RootPublished log"));
    }

    #[tokio::test]
    async fn confirm_root_publication_rejects_short_receipt_block_hash() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let target = sample_target("http://127.0.0.1:0");
        let mut receipt =
            successful_publication_receipt(&target, &checkpoint, &binding, CONFIRM_TX_HASH);
        receipt["blockHash"] = json!("0xabc");
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(receipt)]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            CONFIRM_TX_HASH,
            &egress_contract,
        )
        .await
        .test_expect_err("short block hash should fail");

        let requests = server.requests();
        server.join();
        assert_eq!(requests.len(), 1);
        assert!(error.to_string().contains("receipt blockHash"));
    }

    #[tokio::test]
    async fn confirm_root_publication_rejects_log_block_hash_mismatch() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let target = sample_target("http://127.0.0.1:0");
        let mut receipt =
            successful_publication_receipt(&target, &checkpoint, &binding, CONFIRM_TX_HASH);
        receipt["logs"][0]["blockHash"] =
            json!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(receipt)]) else {
            return;
        };
        let target = sample_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = confirm_root_publication(
            &target,
            &checkpoint,
            &binding,
            CONFIRM_TX_HASH,
            &egress_contract,
        )
        .await
        .test_expect_err("log block hash mismatch should fail");

        let requests = server.requests();
        server.join();
        assert_eq!(requests.len(), 1);
        assert!(error
            .to_string()
            .contains("missing matching RootPublished log"));
    }

    #[tokio::test]
    async fn inspect_publication_guard_decodes_authorization_and_sequence() {
        let binding = sample_binding();
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let guard = inspect_publication_guard(&target, &binding, &egress_contract)
            .await
            .test_expect("inspect guard");

        server.join();
        assert!(guard.publisher_authorized);
        assert_eq!(
            guard.operator_key_hash,
            operator_key_hash_hex(&binding).test_expect("operator key hash")
        );
        assert_eq!(guard.latest_checkpoint_seq, 41);
        assert_eq!(guard.next_checkpoint_seq_min, 42);
        assert!(guard.requires_delegate_authorization);
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_unauthorized_publisher() {
        let checkpoint = sample_checkpoint();
        let binding = sample_binding();
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&false)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, &checkpoint, &binding, &egress_contract)
            .await
            .test_expect_err("unauthorized publisher should fail");

        server.join();
        assert!(error.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_checkpoint_regression() {
        let mut checkpoint = sample_checkpoint();
        checkpoint.body.checkpoint_seq = 41;
        let binding = sample_binding();
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, &checkpoint, &binding, &egress_contract)
            .await
            .test_expect_err("checkpoint regression should fail");

        server.join();
        assert!(error.to_string().contains("must equal"));
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_skipped_checkpoint_sequence() {
        let mut checkpoint = sample_checkpoint();
        checkpoint.body.checkpoint_seq = 44;
        let binding = sample_binding();
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, &checkpoint, &binding, &egress_contract)
            .await
            .test_expect_err("skipped checkpoint sequence should fail");

        server.join();
        assert!(error.to_string().contains("must equal"));
    }

    #[tokio::test]
    async fn ensure_publication_ready_accepts_next_checkpoint() {
        let mut checkpoint = sample_checkpoint();
        checkpoint.body.checkpoint_seq = 42;
        checkpoint.body.batch_start_seq = 10;
        checkpoint.body.batch_end_seq = 20;
        let binding = sample_binding();
        let latest_root = IChioRootRegistry::RootEntry {
            merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
            checkpointSeq: checkpoint.body.checkpoint_seq - 1,
            batchStartSeq: 1,
            batchEndSeq: checkpoint.body.batch_start_seq - 1,
            treeSize: checkpoint.body.tree_size as u64,
            publishedAt: 1_744_000_123_u64,
            operatorKeyHash: operator_key_hash(&binding).test_expect("operator key hash"),
            operatorEpoch: 1,
        };
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestRootCall::abi_encode_returns(&latest_root)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let guard = ensure_publication_ready(&target, &checkpoint, &binding, &egress_contract)
            .await
            .test_expect("checkpoint 42 should be accepted");

        server.join();
        assert_eq!(guard.next_checkpoint_seq_min, 42);
    }

    #[tokio::test]
    async fn ensure_publication_ready_rejects_batch_gap_against_latest_root() {
        let mut checkpoint = sample_checkpoint();
        checkpoint.body.checkpoint_seq = 42;
        checkpoint.body.batch_start_seq = 10;
        checkpoint.body.batch_end_seq = 20;
        let binding = sample_binding();
        let latest_root = IChioRootRegistry::RootEntry {
            merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
            checkpointSeq: checkpoint.body.checkpoint_seq - 1,
            batchStartSeq: 1,
            batchEndSeq: checkpoint.body.batch_start_seq - 2,
            treeSize: checkpoint.body.tree_size as u64,
            publishedAt: 1_744_000_123_u64,
            operatorKeyHash: operator_key_hash(&binding).test_expect("operator key hash"),
            operatorEpoch: 1,
        };
        let Some(server) = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioRootRegistry::isAuthorizedPublisherForKeyHashCall::abi_encode_returns(&true)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestSeqCall::abi_encode_returns(&41_u64)
            ))),
            rpc_result(json!(encode_hex(
                IChioRootRegistry::getLatestRootCall::abi_encode_returns(&latest_root)
            ))),
        ]) else {
            return;
        };
        let target = sample_delegate_target(server.base_url());
        let egress_contract = sample_rpc_contract(server.base_url());

        let error = ensure_publication_ready(&target, &checkpoint, &binding, &egress_contract)
            .await
            .test_expect_err("batch gap should fail preflight");

        server.join();
        assert!(error.to_string().contains("batch_start_seq"));
    }

    #[tokio::test]
    async fn verify_inclusion_onchain_decodes_registry_verdict() {
        let Some(server) = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
            IChioRootRegistry::verifyInclusionDetailedForKeyHashCall::abi_encode_returns(&true)
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
        let call_data = hex::decode(
            requests[0]["params"][0]["data"]
                .as_str()
                .test_expect("eth_call data is string")
                .trim_start_matches("0x"),
        )
        .test_expect("eth_call data decodes");
        let decoded =
            IChioRootRegistry::verifyInclusionDetailedForKeyHashCall::abi_decode(&call_data)
                .test_expect("verifyInclusionDetailedForKeyHash call decodes");
        assert_eq!(
            decoded.operatorKeyHash,
            operator_key_hash(&proof.key_binding_certificate).test_expect("operator key hash")
        );
    }

    #[tokio::test]
    async fn verify_inclusion_onchain_rejects_target_operator_mismatch() {
        let mut target = sample_target("http://127.0.0.1:8545");
        target.operator_address = "0x1000000000000000000000000000000000000009".to_string();
        let proof = sample_primary_proof();
        let egress_contract = sample_rpc_contract("http://127.0.0.1:8545");

        let error = verify_inclusion_onchain(&target, &proof, &egress_contract)
            .await
            .test_expect_err("target operator mismatch should fail before RPC");

        assert!(error
            .to_string()
            .contains("does not match anchor target operator"));
    }

    #[test]
    fn build_chain_anchor_record_copies_confirmation_metadata() {
        let checkpoint = sample_checkpoint();
        let target = sample_target("http://127.0.0.1:8545");
        let confirmed = EvmPublicationReceipt {
            tx_hash: "0xdeadbeef".to_string(),
            block_number: 42,
            block_hash: "0xabc".to_string(),
            operator_key_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            operator_epoch: 1,
            published_at: 1_744_000_123,
        };

        let record = build_chain_anchor_record(&target, &checkpoint, &confirmed);

        assert_eq!(record.chain_id, target.chain_id);
        assert_eq!(record.contract_address, target.contract_address);
        assert_eq!(record.operator_address, target.operator_address);
        assert_eq!(record.tx_hash, confirmed.tx_hash);
        assert_eq!(record.block_number, confirmed.block_number);
        assert_eq!(record.block_hash, confirmed.block_hash);
        assert_eq!(record.operator_key_hash, confirmed.operator_key_hash);
        assert_eq!(record.operator_epoch, confirmed.operator_epoch);
        assert_eq!(record.anchored_merkle_root, checkpoint.body.merkle_root);
    }
}
