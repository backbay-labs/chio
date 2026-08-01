use super::*;
use crate::SettlementPolicyConfig;
use chio_core::credit::{
    CapitalBookQuery, CapitalBookSourceKind, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionArtifact, CapitalExecutionInstructionSupportBoundary,
    CapitalExecutionIntendedState, CapitalExecutionRail, CapitalExecutionReconciledState,
    CapitalExecutionRole, CapitalExecutionWindow, CreditBondArtifact, CreditBondDisposition,
    CreditBondFinding, CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport,
    CreditBondSupportBoundary, CreditBondTerms, CreditFacilityCapitalSource, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery, ExposureLedgerSummary,
};
use chio_core::crypto::Keypair;
use chio_core::hashing::sha256_hex;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::SignedExportEnvelope,
};
use chio_core::web3::identity::{
    Web3IdentityBindingCertificate, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};
use chio_core::web3::settlement::{Web3SettlementDispatchArtifact, Web3SettlementLifecycleState};
use secp256k1::ecdsa::RecoveryId;
use secp256k1::PublicKey as SecpPublicKey;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use chio_test_support::prelude::*;

macro_rules! assert_not_prepared_evm_submission {
    ($type:ty) => {
        const _: fn() = || {
            trait AmbiguousIfPrepared<A> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfPrepared<()> for T {}
            struct Invalid;
            impl<T: ?Sized + PreparedEvmSubmission> AmbiguousIfPrepared<Invalid> for T {}
            let _ = <$type as AmbiguousIfPrepared<_>>::marker;
        };
    };
}

assert_not_prepared_evm_submission!(PreparedEvmCall);
assert_not_prepared_evm_submission!(PreparedAuthorizedChannelMerkleReleaseV1);
assert_not_prepared_evm_submission!(PreparedRootPublication);
assert_not_prepared_evm_submission!(PreparedMerkleRelease);
assert_not_prepared_evm_submission!(PreparedDualSignRelease);
assert_not_prepared_evm_submission!(PreparedEscrowRefund);
assert_not_prepared_evm_submission!(PreparedBondRelease);
assert_not_prepared_evm_submission!(PreparedBondImpair);
assert_not_prepared_evm_submission!(PreparedBondExpiry);

fn sample_config() -> SettlementChainConfig {
    sample_config_with_rpc_url("http://127.0.0.1:8545".to_string())
}

fn sample_config_with_rpc_url(rpc_url: String) -> SettlementChainConfig {
    SettlementChainConfig {
        chain_id: "eip155:31337".to_string(),
        network_name: "Ganache".to_string(),
        egress_contract: crate::settlement_devnet_rpc_egress_contract(&rpc_url)
            .test_expect("devnet egress contract"),
        rpc_url,
        escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
        bond_vault_contract: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
        identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
        root_registry_contract: "0x3a167ACFC3348a8f8df11BF383aF3cA86a8A2B42".to_string(),
        operator_address: "0x8d6d63c22D114C18C2a0dA6Db0A8972Ed9C40343".to_string(),
        settlement_token_symbol: "mUSDC".to_string(),
        settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
        oracle: crate::SettlementOracleConfig::default(),
        evidence_substrate: crate::SettlementEvidenceConfig::default(),
        policy: SettlementPolicyConfig::default(),
    }
}

fn test_submission(call: PreparedEvmCall) -> PreparedErc20Approval {
    PreparedErc20Approval {
        owner_address: call.from_address.clone(),
        token_address: "0x1000000000000000000000000000000000000003".to_owned(),
        spender_address: call.to_address.clone(),
        amount_minor_units: 1,
        call,
    }
}

fn hostname_rpc_contract(authority: &str) -> chio_egress_contract::HttpEgressContract {
    chio_egress_contract::HttpEgressContract {
        tenant_egress_namespace: "chio-settle-evm-unit-rpc".to_string(),
        allowed_schemes: std::collections::BTreeSet::from(["https".to_string()]),
        allowed_authority_set: std::collections::BTreeSet::from([authority.to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 64 * 1024 * 1024,
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
    fn spawn(responses: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind mock RPC listener");
        let address = listener.local_addr().test_expect("listener address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().test_expect("accept mock RPC connection");
                let request = read_http_request(&mut stream);
                request_log
                    .lock()
                    .test_expect("request log lock")
                    .push(parse_json_request(&request));
                write_http_json_response(&mut stream, 200, &response);
            }
        });
        Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        }
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().test_expect("request log lock").clone()
    }

    fn join(self) {
        self.handle
            .join()
            .test_expect("mock RPC thread should exit cleanly");
    }
}

impl MockRawHttpServer {
    fn spawn(response: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind mock raw HTTP listener");
        let address = listener.local_addr().test_expect("listener address");
        let base_url = format!("http://{}", address);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .test_expect("accept mock raw HTTP request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .test_expect("set read timeout");
            let _request = read_http_request(&mut stream);
            stream
                .write_all(response.as_bytes())
                .test_expect("write mock raw HTTP response");
            stream.flush().test_expect("flush mock raw HTTP response");
        });
        Self { base_url, handle }
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn join(self) {
        self.handle
            .join()
            .test_expect("mock raw HTTP thread should exit cleanly");
    }
}

fn sample_dispatch() -> Web3SettlementDispatchArtifact {
    serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .test_unwrap()
}

fn hex_dispatch() -> Web3SettlementDispatchArtifact {
    let mut dispatch = sample_dispatch();
    dispatch.escrow_id =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    dispatch.settlement_path = Web3SettlementPath::DualSignature;
    dispatch.support_boundary.anchor_proof_required = false;
    dispatch.support_boundary.oracle_evidence_required_for_fx = false;
    dispatch
}

fn sample_primary_proof() -> AnchorInclusionProof {
    serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))
    .test_expect("parse primary proof example")
}

fn batched_primary_proof() -> AnchorInclusionProof {
    let mut proof = sample_primary_proof();
    let receipt_bytes =
        canonical_json_bytes(&proof.receipt.body()).test_expect("proof receipt serializes");
    let peer_receipt = b"peer receipt";
    let leaves: Vec<&[u8]> = vec![receipt_bytes.as_slice(), peer_receipt.as_slice()];
    let tree = MerkleTree::from_leaves(&leaves).test_expect("batched tree builds");
    let merkle_root = tree.root();
    proof.receipt_inclusion.merkle_root = merkle_root;
    proof.receipt_inclusion.proof = tree.inclusion_proof(0).test_expect("proof builds");
    proof.checkpoint_statement.tree_size = tree.leaf_count() as u64;
    proof.checkpoint_statement.merkle_root = merkle_root;
    if let Some(chain_anchor) = proof.chain_anchor.as_mut() {
        chain_anchor.anchored_merkle_root = merkle_root;
    }
    let mut body = serde_json::to_value(&proof.checkpoint_statement)
        .test_expect("checkpoint statement serializes");
    body.as_object_mut()
        .test_expect("checkpoint statement body is an object")
        .remove("signature");
    let (signature, _) = operator_keypair()
        .sign_canonical(&body)
        .test_expect("checkpoint statement signs");
    proof.checkpoint_statement.signature = signature;
    proof
}

fn align_config_to_anchor_proof(config: &mut SettlementChainConfig, proof: &AnchorInclusionProof) {
    let chain_anchor = proof
        .chain_anchor
        .as_ref()
        .test_expect("sample proof includes chain anchor");
    config.chain_id = chain_anchor.chain_id.clone();
    config.root_registry_contract = chain_anchor.contract_address.clone();
    config.operator_address = chain_anchor.operator_address.clone();
}

fn sample_anchor_content_binding() -> SettlementAnchorContentBinding {
    SettlementAnchorContentBinding {
        execution_receipt_id: "receipt-web3-1".to_string(),
        settlement_reference: "settlement-web3-1".to_string(),
    }
}

fn operator_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn instruction_keypair() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

fn bond_keypair() -> Keypair {
    Keypair::from_seed(&[11u8; 32])
}

fn custodian_keypair() -> Keypair {
    Keypair::from_seed(&[13u8; 32])
}

fn sample_binding_for_config(config: &SettlementChainConfig) -> SignedWeb3IdentityBinding {
    let operator = operator_keypair();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", operator.public_key().to_hex()),
        chio_public_key: operator.public_key(),
        chain_scope: vec![config.chain_id.clone()],
        purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        settlement_address: config.operator_address.clone(),
        issued_at: 1_743_292_800,
        expires_at: 1_774_828_800,
        nonce: "evm-unit-binding".to_string(),
    };
    let (signature, _) = operator
        .sign_canonical(&certificate)
        .test_expect("binding signature");
    SignedWeb3IdentityBinding {
        certificate,
        signature,
    }
}

fn sample_capital_instruction(
    config: &SettlementChainConfig,
    beneficiary_address: &str,
    instruction_id: &str,
    amount_units: u64,
) -> SignedCapitalExecutionInstruction {
    let keypair = instruction_keypair();
    let custodian = custodian_keypair();
    let custodian_id = custodian.public_key().to_hex();
    SignedExportEnvelope::sign(
        CapitalExecutionInstructionArtifact {
            schema: chio_core::credit::CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: instruction_id.to_string(),
            issued_at: 1_743_292_800,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:facility:facility-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: Some(format!("governed-{instruction_id}")),
            completion_flow_row_id: Some(format!(
                "economic-completion-flow:governed-{instruction_id}"
            )),
            action: CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: amount_units,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::OperatorTreasury,
                    &keypair,
                    1_743_292_700,
                    1_743_300_000,
                    Some("governed release".to_string()),
                )
                .test_expect("treasury authority proof"),
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::Custodian,
                    &custodian,
                    1_743_292_750,
                    1_743_300_000,
                    Some("official web3 stack".to_string()),
                )
                .test_expect("custodian authority proof"),
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 1_743_292_800,
                not_after: 1_743_300_000,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Web3,
                rail_id: "ganache-devnet-usdc".to_string(),
                custody_provider_id: custodian_id,
                source_account_ref: Some("vault:facility-main".to_string()),
                destination_account_ref: Some(beneficiary_address.to_string()),
                jurisdiction: Some(config.chain_id.clone()),
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::NotObserved,
            related_instruction_id: None,
            observed_execution: None,
            support_boundary: CapitalExecutionInstructionSupportBoundary {
                capital_book_authoritative: true,
                external_execution_authoritative: false,
                automatic_dispatch_supported: true,
                custody_neutral_instruction_supported: false,
            },
            evidence_refs: Vec::new(),
            description: "release escrow over the unit-test devnet".to_string(),
        },
        &keypair,
    )
    .test_expect("capital instruction")
}

fn sample_receipt(
    keypair: &Keypair,
    capability_id: &str,
    receipt_id: &str,
    amount_units: u64,
    beneficiary_address: &str,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_743_292_800,
            capability_id: capability_id.to_string(),
            tool_server: "chio-settle".to_string(),
            tool_name: "release_escrow".to_string(),
            action: ToolCallAction::from_parameters(json!({
                "amount": amount_units,
                "currency": "USD",
                "to": beneficiary_address,
            }))
            .test_expect("receipt params"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(format!("settlement:{receipt_id}").as_bytes()),
            policy_hash: sha256_hex(b"policy:web3"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_expect("receipt")
}

fn sample_credit_bond(
    bond_id: &str,
    facility_id: &str,
    collateral_units: u64,
    reserve_units: u64,
) -> SignedCreditBond {
    let keypair = bond_keypair();
    SignedCreditBond::sign(
        CreditBondArtifact {
            schema: chio_core::credit::CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
            bond_id: bond_id.to_string(),
            issued_at: 1_743_292_800,
            expires_at: 1_743_300_000,
            lifecycle_state: CreditBondLifecycleState::Active,
            supersedes_bond_id: None,
            report: CreditBondReport {
                schema: chio_core::credit::CREDIT_BOND_REPORT_SCHEMA.to_string(),
                generated_at: 1_743_292_800,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                exposure: ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                scorecard: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.97,
                    anomaly_count: 0,
                    probationary: false,
                },
                disposition: CreditBondDisposition::Hold,
                prerequisites: CreditBondPrerequisites {
                    active_facility_required: false,
                    active_facility_met: true,
                    runtime_assurance_met: true,
                    certification_required: false,
                    certification_met: true,
                    currency_coherent: true,
                },
                support_boundary: CreditBondSupportBoundary::default(),
                latest_facility_id: Some(facility_id.to_string()),
                terms: Some(CreditBondTerms {
                    facility_id: facility_id.to_string(),
                    credit_limit: MonetaryAmount {
                        units: collateral_units.saturating_mul(10),
                        currency: "USD".to_string(),
                    },
                    collateral_amount: MonetaryAmount {
                        units: collateral_units,
                        currency: "USD".to_string(),
                    },
                    reserve_requirement_amount: MonetaryAmount {
                        units: reserve_units,
                        currency: "USD".to_string(),
                    },
                    outstanding_exposure_amount: MonetaryAmount {
                        units: 0,
                        currency: "USD".to_string(),
                    },
                    reserve_ratio_bps: 10_000,
                    coverage_ratio_bps: 10_000,
                    capital_source: CreditFacilityCapitalSource::OperatorInternal,
                }),
                findings: vec![CreditBondFinding {
                    code: CreditBondReasonCode::ReserveHeld,
                    description: "reserve state is held".to_string(),
                    evidence_refs: Vec::new(),
                }],
            },
        },
        &keypair,
    )
    .test_expect("credit bond")
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
        },
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
fn amount_scaling_matches_usdc_convention() {
    let config = sample_config();
    let scaled = scale_chio_amount_to_token_minor_units(
        &MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
        &config,
    )
    .test_unwrap();
    assert_eq!(scaled, 1_500_000);
    let restored = scale_token_minor_units_to_chio_amount(scaled, "USD", &config).test_unwrap();
    assert_eq!(restored.units, 150);
}

#[test]
fn dual_sign_digest_and_signature_are_recoverable() {
    let config = sample_config();
    let escrow_id = parse_b256_hex(
        "0x9e7e9d75ef18f8924a938f06c9838a8d6c6b9600dba88b35d28f6d54e2a71803",
        "escrow_id",
    )
    .test_unwrap();
    let receipt_hash = parse_b256_hex(
        "0x8d4f1c4eff7a6ec4cb9f3d5347ea50ccaa43d562e2eb06b1e0dab0633d14c0e3",
        "receipt_hash",
    )
    .test_unwrap();
    let digest = dual_sign_digest(
        &config,
        &config.escrow_contract,
        &escrow_id,
        &receipt_hash,
        1_500_000,
        1,
    )
    .test_unwrap();
    let signature = sign_digest(
        "0x1000000000000000000000000000000000000000000000000000000000000002",
        &digest,
    )
    .test_unwrap();
    let message = Message::from_digest(*digest.as_ref());
    let secp = Secp256k1::new();
    let recovery_id = RecoveryId::try_from((signature.v - 27) as i32).test_unwrap();
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&hex::decode(signature.r.trim_start_matches("0x")).test_unwrap());
    bytes[32..].copy_from_slice(&hex::decode(signature.s.trim_start_matches("0x")).test_unwrap());
    let recoverable = RecoverableSignature::from_compact(&bytes, recovery_id).test_unwrap();
    let recovered = secp.recover_ecdsa(message, &recoverable).test_unwrap();
    let expected = SecpPublicKey::from_secret_key(
        &secp,
        &SecretKey::from_byte_array(
            hex::decode("1000000000000000000000000000000000000000000000000000000000000002")
                .test_unwrap()
                .try_into()
                .test_unwrap(),
        )
        .test_unwrap(),
    );
    assert_eq!(recovered, expected);
}

#[test]
fn prepares_erc20_approval_call_payloads() {
    let prepared = prepare_erc20_approval(
        "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8",
        "0x1000000000000000000000000000000000000001",
        "0x1000000000000000000000000000000000000002",
        42_000,
    )
    .test_unwrap();

    assert_eq!(prepared.amount_minor_units, 42_000);
    assert_eq!(prepared.call.from_address, prepared.owner_address);
    assert_eq!(prepared.call.to_address, prepared.token_address);
    assert!(prepared.call.data.starts_with("0x095ea7b3"));
}

#[test]
fn prepares_refund_and_bond_expiry_calls() {
    let config = sample_config();
    let dispatch = hex_dispatch();

    let refund = prepare_escrow_refund(
        &config,
        &dispatch,
        "0x1000000000000000000000000000000000000009",
    )
    .test_unwrap();
    assert_eq!(refund.escrow_id, dispatch.escrow_id);
    assert_eq!(refund.call.to_address, config.escrow_contract);
    assert!(refund.call.data.starts_with("0x"));

    let expiry = prepare_bond_expiry(
        &config,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0x1000000000000000000000000000000000000009",
    )
    .test_unwrap();
    assert_eq!(expiry.chain_id, config.chain_id);
    assert_eq!(expiry.call.to_address, config.bond_vault_contract);
}

#[test]
fn builds_failure_and_reversal_receipts() {
    let dispatch = hex_dispatch();

    let failure = build_failure_receipt(
        &dispatch,
        "exec-failed".to_string(),
        "settlement-ref".to_string(),
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "node rejected tx".to_string(),
    )
    .test_unwrap();
    assert_eq!(
        failure.lifecycle_state,
        Web3SettlementLifecycleState::Failed
    );
    assert_eq!(failure.failure_reason.as_deref(), Some("node rejected tx"));

    let reversal = build_reversal_receipt(
        &dispatch,
        "exec-reversed".to_string(),
        "settlement-ref".to_string(),
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        dispatch.settlement_amount.clone(),
        "exec-failed".to_string(),
        true,
    )
    .test_unwrap();
    assert_eq!(
        reversal.lifecycle_state,
        Web3SettlementLifecycleState::ChargedBack
    );
    assert_eq!(reversal.reversal_of.as_deref(), Some("exec-failed"));
}

#[test]
fn finalize_escrow_dispatch_reads_the_created_id_from_receipt_logs() {
    let dispatch = hex_dispatch();
    let prepared = PreparedEscrowCreate {
        expected_escrow_id: "0xdeadbeef".to_string(),
        capability_commitment: "0xfeedface".to_string(),
        settlement_amount_minor_units: 1_500_000,
        dispatch: dispatch.clone(),
        call: PreparedEvmCall {
            from_address: dispatch
                .capital_instruction
                .body
                .rail
                .destination_account_ref
                .clone()
                .unwrap_or_default(),
            to_address: dispatch.escrow_contract.clone(),
            data: "0x".to_string(),
            gas_limit: None,
        },
    };
    let observed_id = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let receipt = EvmTransactionReceipt {
            tx_hash: "0xabc".to_string(),
            block_number: 1,
            block_hash: "0x01".to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: dispatch.escrow_contract.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![EvmLogEntry {
                address: dispatch.escrow_contract.clone(),
                topics: vec![
                    event_signature_hash(
                        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
                    ),
                    observed_id.to_string(),
                ],
                data: "0x".to_string(),
                log_index: Some(0),
            }],
        };

    let finalized = finalize_escrow_dispatch(&prepared, &receipt).test_unwrap();

    assert_eq!(finalized.expected_escrow_id, observed_id);
    assert_eq!(finalized.dispatch.escrow_id, observed_id);
}

#[test]
fn finalize_bond_lock_reads_identity_topics_from_receipt_logs() {
    let bond_id_hash = format_b256(hash_string_id("bond-1"));
    let facility_id_hash = format_b256(hash_string_id("facility-1"));
    let prepared = PreparedBondLock {
        vault_id: "0xold".to_string(),
        bond_id_hash: bond_id_hash.clone(),
        facility_id_hash: facility_id_hash.clone(),
        operator_key_hash: format_b256(B256::from([0x33; 32])),
        collateral_minor_units: 5,
        reserve_requirement_minor_units: 2,
        call: PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
            data: "0x".to_string(),
            gas_limit: None,
        },
    };
    let vault_id = "0x2222222222222222222222222222222222222222222222222222222222222222";
    let receipt = EvmTransactionReceipt {
        tx_hash: "0xdef".to_string(),
        block_number: 1,
        block_hash: "0x02".to_string(),
        status: true,
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: prepared.call.to_address.clone(),
        gas_used: 21_000,
        observed_at: 1_744_000_000,
        logs: vec![EvmLogEntry {
            address: prepared.call.to_address.clone(),
            topics: vec![
                event_signature_hash(
                    "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
                ),
                vault_id.to_string(),
                bond_id_hash,
                facility_id_hash,
            ],
            data: "0x".to_string(),
            log_index: Some(0),
        }],
    };

    let finalized = finalize_bond_lock(&prepared, &receipt).test_unwrap();

    assert_eq!(finalized.vault_id, vault_id);
}

#[tokio::test]
async fn rpc_helpers_cover_static_validation_gas_estimation_and_submission() {
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!("0xdeadbeef")),
        rpc_result(json!("0x5208")),
        rpc_result(json!("0x5208")),
        rpc_result(json!(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )),
    ]);
    let config = sample_config_with_rpc_url(server.base_url());
    let call = PreparedEvmCall {
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: "0x1000000000000000000000000000000000000002".to_string(),
        data: "0xdeadbeef".to_string(),
        gas_limit: None,
    };
    let prepared = test_submission(call);

    let validation = static_validate_call(&config, prepared.call())
        .await
        .test_expect("eth_call should succeed");
    let estimated = estimate_call_gas(&config, prepared.call())
        .await
        .test_expect("gas estimate should succeed");
    let tx_hash = submit_call(&config, &prepared)
        .await
        .test_expect("submission should succeed");

    let requests = server.requests();
    server.join();

    assert_eq!(validation, "0xdeadbeef");
    assert_eq!(estimated, 21_000);
    assert_eq!(
        tx_hash,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(requests[0]["method"], "eth_call");
    assert_eq!(requests[1]["method"], "eth_estimateGas");
    assert_eq!(requests[2]["method"], "eth_estimateGas");
    assert_eq!(requests[3]["method"], "eth_sendTransaction");
    assert_eq!(requests[3]["params"][0]["gas"], json!("0x125c0"));
}

#[test]
fn rpc_config_accepts_hostname_rpc_url_with_pinned_resolver() {
    let mut config = sample_config();
    config.rpc_url = "https://mainnet-rpc.example.com".to_string();
    config.egress_contract = hostname_rpc_contract("mainnet-rpc.example.com");

    config
        .validate_rpc_egress_contract()
        .test_expect("hostname RPC dispatch is resolver-enforced");
}

#[tokio::test]
async fn submit_call_respects_explicit_gas_limit() {
    let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ))]);
    let config = sample_config_with_rpc_url(server.base_url());
    let call = PreparedEvmCall {
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: "0x1000000000000000000000000000000000000002".to_string(),
        data: "0xdeadbeef".to_string(),
        gas_limit: Some(50_000),
    };
    let prepared = test_submission(call);

    let tx_hash = submit_call(&config, &prepared)
        .await
        .test_expect("submission should succeed");

    let requests = server.requests();
    server.join();

    assert_eq!(
        tx_hash,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], "eth_sendTransaction");
    assert_eq!(requests[0]["params"][0]["gas"], json!("0xc350"));
}

#[tokio::test]
async fn submit_call_rejects_money_exit_selectors_before_rpc() {
    let config = sample_config();
    for selector in prepare::GUARDED_MONEY_EXIT_SELECTORS {
        let prepared = PreparedErc20Approval {
            owner_address: config.operator_address.clone(),
            token_address: config.settlement_token_address.clone(),
            spender_address: config.escrow_contract.clone(),
            amount_minor_units: 1,
            call: PreparedEvmCall {
                from_address: config.operator_address.clone(),
                to_address: config.escrow_contract.clone(),
                data: format!("0x{}", hex::encode(selector)),
                gas_limit: Some(50_000),
            },
        };

        let error = submit_call(&config, &prepared)
            .await
            .test_expect_err("money-exit selector must be rejected before RPC");
        assert!(matches!(error, SettlementError::Unsupported(_)));
    }
}

#[tokio::test]
async fn submit_call_rejects_rpc_redirects() {
    let server = MockRawHttpServer::spawn(
            "HTTP/1.1 302 Found\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
    let config = sample_config_with_rpc_url(server.base_url());
    let call = PreparedEvmCall {
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: "0x1000000000000000000000000000000000000002".to_string(),
        data: "0xdeadbeef".to_string(),
        gas_limit: Some(50_000),
    };
    let prepared = test_submission(call);

    let error = submit_call(&config, &prepared)
        .await
        .test_expect_err("submission RPC redirect should fail");
    let message = error.to_string();

    server.join();
    assert!(
        message.contains("HttpEgressContract") && message.contains("redirect chain length"),
        "unexpected settlement RPC redirect denial: {message}"
    );
}

#[tokio::test]
async fn submit_call_rejects_oversized_rpc_responses() {
    let server = MockRawHttpServer::spawn(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
    let config = sample_config_with_rpc_url(server.base_url());
    let call = PreparedEvmCall {
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: "0x1000000000000000000000000000000000000002".to_string(),
        data: "0xdeadbeef".to_string(),
        gas_limit: Some(50_000),
    };
    let prepared = test_submission(call);

    let error = submit_call(&config, &prepared)
        .await
        .test_expect_err("oversized submission RPC response should fail");
    let message = error.to_string();

    server.join();
    assert!(
        message.contains("HttpEgressContract") && message.contains("response size"),
        "unexpected settlement RPC response-size denial: {message}"
    );
}

#[tokio::test]
async fn confirm_transaction_decodes_receipt_and_block() {
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!({
            "blockHash": "0xabc",
            "blockNumber": "0x64",
            "status": "0x1",
            "gasUsed": "0x5208",
            "from": "0x1000000000000000000000000000000000000001",
            "to": "0x1000000000000000000000000000000000000002",
            "logs": [{
                "address": "0x1000000000000000000000000000000000000002",
                "topics": [
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                ],
                "data": "0x",
                "logIndex": "0x0"
            }]
        })),
        rpc_result(json!({ "timestamp": "0x6553f100" })),
    ]);
    let config = sample_config_with_rpc_url(server.base_url());

    let receipt = confirm_transaction(
        &config,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .await
    .test_expect("receipt should decode");

    let requests = server.requests();
    server.join();

    assert_eq!(receipt.block_number, 100);
    assert_eq!(receipt.block_hash, "0xabc");
    assert!(receipt.status);
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(receipt.observed_at, 1_700_000_000);
    assert_eq!(receipt.logs.len(), 1);
    assert_eq!(requests[0]["method"], "eth_getTransactionReceipt");
    assert_eq!(requests[1]["method"], "eth_getBlockByHash");
}

#[tokio::test]
async fn confirm_transaction_surfaces_rpc_and_shape_failures() {
    let error_server = MockJsonRpcServer::spawn(vec![rpc_error(-32000, "boom")]);
    let error_config = sample_config_with_rpc_url(error_server.base_url());
    let error = confirm_transaction(
        &error_config,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .await
    .test_expect_err("RPC error should fail");
    error_server.join();
    assert!(matches!(error, SettlementError::Rpc(_)));

    let missing_server = MockJsonRpcServer::spawn(vec![rpc_result(json!({
        "blockNumber": "0x64",
        "status": "0x1",
        "gasUsed": "0x5208",
        "from": "0x1000000000000000000000000000000000000001",
        "to": "0x1000000000000000000000000000000000000002",
        "logs": []
    }))]);
    let missing_config = sample_config_with_rpc_url(missing_server.base_url());
    let error = confirm_transaction(
        &missing_config,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .await
    .test_expect_err("missing block hash should fail");
    missing_server.join();
    assert!(error.to_string().contains("receipt missing blockHash"));
}

#[tokio::test]
async fn snapshot_readers_decode_contract_state() {
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!(encode_hex(
            IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                terms: IChioEscrow::EscrowTerms {
                    capabilityId: B256::from([0x11; 32]),
                    depositor: Address::from_str("0x1000000000000000000000000000000000000001")
                        .test_unwrap(),
                    beneficiary: Address::from_str("0x1000000000000000000000000000000000000002",)
                        .test_unwrap(),
                    token: Address::from_str("0x1000000000000000000000000000000000000003")
                        .test_unwrap(),
                    maxAmount: U256::from(1_500_000_u64),
                    deadline: U256::from(1_700_003_000_u64),
                    operator: Address::from_str("0x1000000000000000000000000000000000000004")
                        .test_unwrap(),
                    operatorKeyHash: B256::from([0x22; 32]),
                },
                deposited: U256::from(1_500_000_u64),
                released: U256::from(250_000_u64),
                refunded: true,
            })
        ))),
        rpc_result(json!({
            "number": "0x65",
            "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "timestamp": "0x6553f100"
        })),
        rpc_result(json!(encode_hex(
            IChioBondVault::getBondCall::abi_encode_returns(&IChioBondVault::getBondReturn {
                terms: IChioBondVault::BondTerms {
                    bondId: B256::from([0x31; 32]),
                    facilityId: B256::from([0x32; 32]),
                    principal: Address::from_str("0x1000000000000000000000000000000000000005",)
                        .test_unwrap(),
                    token: Address::from_str("0x1000000000000000000000000000000000000006")
                        .test_unwrap(),
                    collateralAmount: U256::from(2_000_000_u64),
                    reserveRequirementAmount: U256::from(250_000_u64),
                    expiresAt: U256::from(1_800_000_000_u64),
                    reserveRequirementRatioBps: 2500,
                    operator: Address::from_str("0x1000000000000000000000000000000000000007",)
                        .test_unwrap(),
                    operatorKeyHash: B256::from([0x33; 32]),
                },
                lockedAmount: U256::from(2_000_000_u64),
                slashedAmount: U256::from(125_000_u64),
                released: false,
                expired: true,
            })
        ))),
    ]);
    let config = sample_config_with_rpc_url(server.base_url());

    let escrow = read_escrow_snapshot(
        &config,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .await
    .test_expect("escrow snapshot should decode");
    let bond = read_bond_snapshot(
        &config,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .await
    .test_expect("bond snapshot should decode");

    let requests = server.requests();
    server.join();

    assert_eq!(escrow.deadline, 1_700_003_000);
    assert_eq!(escrow.deposited_minor_units, 1_500_000);
    assert_eq!(escrow.released_minor_units, 250_000);
    assert_eq!(escrow.remaining_minor_units, 1_250_000);
    assert!(escrow.refunded);
    assert_eq!(bond.expires_at, 1_800_000_000);
    assert_eq!(bond.locked_minor_units, 2_000_000);
    assert_eq!(bond.reserve_requirement_minor_units, 250_000);
    assert_eq!(bond.reserve_requirement_ratio_bps, 2500);
    assert_eq!(bond.observed_at, 1_700_000_000);
    assert_eq!(bond.slashed_minor_units, 125_000);
    assert!(!bond.released);
    assert!(bond.expired);
    assert_eq!(requests[0]["method"], "eth_call");
    assert_eq!(requests[1]["method"], "eth_getBlockByNumber");
    assert_eq!(requests[2]["method"], "eth_call");
    assert_eq!(requests[2]["params"][1], "0x65");
}

#[tokio::test]
async fn prepare_web3_escrow_dispatch_derives_expected_identity() {
    let expected_escrow_id = B256::from([0x33; 32]);
    let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
        IChioEscrow::deriveEscrowIdCall::abi_encode_returns(&expected_escrow_id)
    )))]);
    let config = sample_config_with_rpc_url(server.base_url());
    let binding = sample_binding_for_config(&config);
    let request = EscrowDispatchRequest {
        dispatch_id: "dispatch-unit-1".to_string(),
        issued_at: 1_743_292_800,
        trust_profile_id: "chio.unit".to_string(),
        contract_package_id: "chio.contracts.unit".to_string(),
        capability_id: "cap-escrow-unit".to_string(),
        depositor_address: "0x1000000000000000000000000000000000000001".to_string(),
        beneficiary_address: "0x1000000000000000000000000000000000000002".to_string(),
        capital_instruction: sample_capital_instruction(
            &config,
            "0x1000000000000000000000000000000000000002",
            "cei-unit-1",
            150,
        ),
        settlement_path: Web3SettlementPath::MerkleProof,
        oracle_evidence_required_for_fx: false,
        note: Some("unit escrow dispatch".to_string()),
    };

    let prepared = prepare_web3_escrow_dispatch(&config, &request, &binding)
        .await
        .test_expect("dispatch should prepare");

    let requests = server.requests();
    server.join();

    assert_eq!(prepared.expected_escrow_id, format_b256(expected_escrow_id));
    assert_eq!(prepared.dispatch.escrow_id, format_b256(expected_escrow_id));
    assert_eq!(prepared.settlement_amount_minor_units, 1_500_000);
    assert_eq!(
        prepared.capability_commitment,
        format_b256(hash_string_id("cap-escrow-unit"))
    );
    assert_eq!(prepared.call.to_address, config.escrow_contract);
    assert_eq!(prepared.commitment().lane_kind, "evm_merkle_proof");
    assert_eq!(requests[0]["method"], "eth_call");
}

#[tokio::test]
async fn prepare_web3_escrow_dispatch_rejects_binding_and_instruction_mismatches() {
    let config = sample_config();
    let mut binding = sample_binding_for_config(&config);
    binding.certificate.purpose = vec![Web3KeyBindingPurpose::Anchor];
    binding.signature = operator_keypair()
        .sign_canonical(&binding.certificate)
        .test_expect("binding signature")
        .0;

    let valid_request = EscrowDispatchRequest {
        dispatch_id: "dispatch-unit-2".to_string(),
        issued_at: 1_743_292_800,
        trust_profile_id: "chio.unit".to_string(),
        contract_package_id: "chio.contracts.unit".to_string(),
        capability_id: "cap-escrow-unit".to_string(),
        depositor_address: "0x1000000000000000000000000000000000000001".to_string(),
        beneficiary_address: "0x1000000000000000000000000000000000000002".to_string(),
        capital_instruction: sample_capital_instruction(
            &config,
            "0x1000000000000000000000000000000000000002",
            "cei-unit-2",
            150,
        ),
        settlement_path: Web3SettlementPath::MerkleProof,
        oracle_evidence_required_for_fx: false,
        note: None,
    };

    let binding_error = prepare_web3_escrow_dispatch(&config, &valid_request, &binding)
        .await
        .test_expect_err("binding without settle purpose should fail");
    assert!(binding_error
        .to_string()
        .contains("binding does not include Settle purpose"));

    let mismatch_request = EscrowDispatchRequest {
        capital_instruction: sample_capital_instruction(
            &config,
            "0x1000000000000000000000000000000000000003",
            "cei-unit-3",
            150,
        ),
        ..valid_request.clone()
    };
    let binding = sample_binding_for_config(&config);
    let instruction_error = prepare_web3_escrow_dispatch(&config, &mismatch_request, &binding)
        .await
        .test_expect_err("mismatched beneficiary should fail");
    assert!(instruction_error
        .to_string()
        .contains("beneficiary address must match capital instruction destination_account_ref"));

    let mut provenance_request = valid_request;
    provenance_request
        .capital_instruction
        .body
        .completion_flow_row_id = Some("economic-completion-flow:other-receipt".to_string());
    let provenance_error = prepare_web3_escrow_dispatch(&config, &provenance_request, &binding)
        .await
        .test_expect_err("mismatched completion-flow provenance should fail");
    drop(provenance_error);
}

#[tokio::test]
async fn prepare_merkle_release_and_dual_sign_release_cover_full_and_partial_paths() {
    let mut config = sample_config();
    let proof = sample_primary_proof();
    let mut dispatch = sample_dispatch();
    dispatch.escrow_id =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    config.chain_id = dispatch.chain_id.clone();
    config.escrow_contract = dispatch.escrow_contract.clone();
    align_config_to_anchor_proof(&mut config, &proof);

    let anchor_content = sample_anchor_content_binding();
    let full = prepare_merkle_release(
        &config,
        &dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect("full merkle release should prepare");
    let partial_amount = MonetaryAmount {
        units: dispatch.settlement_amount.units / 2,
        currency: dispatch.settlement_amount.currency.clone(),
    };
    let partial = prepare_merkle_release(
        &config,
        &dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Partial(partial_amount.clone()),
    )
    .test_expect("partial merkle release should prepare");

    assert!(!full.partial);
    assert!(partial.partial);
    assert_eq!(full.escrow_id, dispatch.escrow_id);
    assert_eq!(full.call.to_address, config.escrow_contract);
    assert_eq!(partial.observed_amount, partial_amount);
    assert!(partial.settlement_amount_minor_units < full.settlement_amount_minor_units);
    let batched = prepare_merkle_release(
        &config,
        &dispatch,
        &batched_primary_proof(),
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect("batched anchor proof should prepare");
    assert_eq!(batched.escrow_id, dispatch.escrow_id);
    let batched_call_data = hex::decode(batched.call.data.trim_start_matches("0x"))
        .test_expect("batched call data decodes");
    let decoded_batched_call =
        IChioEscrow::releaseWithProofDetailedCall::abi_decode(&batched_call_data)
            .test_expect("batched release call decodes");
    assert!(decoded_batched_call.proof.auditPath.is_empty());
    assert_eq!(decoded_batched_call.proof.leafIndex, U256::from(0_u8));
    assert_eq!(decoded_batched_call.proof.treeSize, U256::from(1_u8));
    assert_ne!(
        batched.merkle_root,
        batched_primary_proof()
            .receipt_inclusion
            .merkle_root
            .to_hex_prefixed()
    );
    let proof_receipt_bytes =
        canonical_json_bytes(&proof.receipt.body()).test_expect("proof receipt serializes");
    assert_eq!(
        full.receipt_hash,
        format_b256(keccak256(&proof_receipt_bytes))
    );
    assert_ne!(full.receipt_hash, full.receipt_leaf_hash);
    assert_ne!(
        full.merkle_root,
        proof.receipt_inclusion.merkle_root.to_hex_prefixed()
    );
    let mut mismatched_receipt_dispatch = dispatch.clone();
    mismatched_receipt_dispatch.capital_instruction = sample_capital_instruction(
        &config,
        &dispatch.beneficiary_address,
        "different-receipt",
        dispatch.settlement_amount.units,
    );
    let mismatched_receipt_error = prepare_merkle_release(
        &config,
        &mismatched_receipt_dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("anchor receipt mismatch should fail");
    assert!(mismatched_receipt_error
        .to_string()
        .contains("governed_receipt_id"));
    let mut wrong_content = anchor_content.clone();
    wrong_content.settlement_reference = "settlement-other".to_string();
    let mismatched_content_error = prepare_merkle_release(
        &config,
        &dispatch,
        &proof,
        &wrong_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("anchor receipt content hash mismatch should fail");
    assert!(mismatched_content_error
        .to_string()
        .contains("content hash"));
    let root_publication = prepare_merkle_release_root_publication(&config, &dispatch, &full, 2, 2)
        .test_expect("typed settlement root publication should prepare");
    assert_eq!(
        root_publication.call().from_address,
        config.operator_address
    );
    assert_eq!(
        root_publication.call().to_address,
        config.root_registry_contract
    );

    let mut forged_root_release = full.clone();
    forged_root_release.merkle_root =
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let forged_root_error =
        prepare_merkle_release_root_publication(&config, &dispatch, &forged_root_release, 2, 2)
            .test_expect_err("forged release root should fail");
    assert!(forged_root_error.to_string().contains("merkle_root"));

    let mut forged_amount_release = full.clone();
    forged_amount_release.settlement_amount_minor_units += 1;
    let forged_amount_error =
        prepare_merkle_release_root_publication(&config, &dispatch, &forged_amount_release, 2, 2)
            .test_expect_err("forged release amount should fail");
    assert!(forged_amount_error
        .to_string()
        .contains("settlement_amount_minor_units"));

    let mut forged_call_release = full.clone();
    let call_data = decode_hex_bytes(&forged_call_release.call.data)
        .test_expect("release call data should decode");
    let release_call = IChioEscrow::releaseWithProofDetailedCall::abi_decode(&call_data)
        .test_expect("release call should decode");
    forged_call_release.call.data = encode_call(IChioEscrow::releaseWithProofDetailedCall {
        root: B256::from([0xcc; 32]),
        ..release_call
    });
    let forged_call_error =
        prepare_merkle_release_root_publication(&config, &dispatch, &forged_call_release, 2, 2)
            .test_expect_err("forged release call should fail");
    assert!(forged_call_error.to_string().contains("call data"));

    let mut mismatched_root_config = config.clone();
    mismatched_root_config.chain_id = "eip155:42161".to_string();
    let invalid_root_config =
        prepare_merkle_release_root_publication(&mismatched_root_config, &dispatch, &full, 2, 2)
            .test_expect_err("root publication chain drift should fail");
    assert!(invalid_root_config.to_string().contains("chain_id"));

    let mut mismatched_root_escrow_config = config.clone();
    mismatched_root_escrow_config.escrow_contract =
        "0x765F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();
    let invalid_root_escrow = prepare_merkle_release_root_publication(
        &mismatched_root_escrow_config,
        &dispatch,
        &full,
        2,
        2,
    )
    .test_expect_err("root publication escrow drift should fail");
    assert!(invalid_root_escrow.to_string().contains("escrow_contract"));

    let mut mismatched_root_token_config = config.clone();
    mismatched_root_token_config.settlement_token_address =
        "0x465F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();
    let invalid_root_token = prepare_merkle_release_root_publication(
        &mismatched_root_token_config,
        &dispatch,
        &full,
        2,
        2,
    )
    .test_expect_err("root publication token drift should fail");
    assert!(invalid_root_token
        .to_string()
        .contains("settlement_token_address"));

    let mut invalid_dispatch = dispatch.clone();
    invalid_dispatch.operator_key_hash = "0x1234".to_string();
    let invalid_key_hash = prepare_merkle_release(
        &config,
        &invalid_dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("malformed operator key hash should fail");
    assert!(invalid_key_hash.to_string().contains("operator_key_hash"));

    let mut missing_chain_anchor_proof = proof.clone();
    missing_chain_anchor_proof.chain_anchor = None;
    let missing_chain_anchor = prepare_merkle_release(
        &config,
        &dispatch,
        &missing_chain_anchor_proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("missing chain anchor should fail");
    assert!(missing_chain_anchor.to_string().contains("chain_anchor"));

    let mut wrong_registry_proof = proof.clone();
    wrong_registry_proof
        .chain_anchor
        .as_mut()
        .test_expect("sample proof has chain anchor")
        .contract_address = "0x2000000000000000000000000000000000000001".to_string();
    let wrong_registry = prepare_merkle_release(
        &config,
        &dispatch,
        &wrong_registry_proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("wrong registry anchor should fail");
    assert!(wrong_registry
        .to_string()
        .contains("root_registry_contract"));

    let mut wrong_operator_config = config.clone();
    wrong_operator_config.operator_address =
        "0x2000000000000000000000000000000000000002".to_string();
    let wrong_operator = prepare_merkle_release(
        &wrong_operator_config,
        &dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("wrong operator anchor should fail");
    assert!(wrong_operator.to_string().contains("operator_address"));

    let mut wrong_key_proof = proof.clone();
    wrong_key_proof
        .chain_anchor
        .as_mut()
        .test_expect("sample proof has chain anchor")
        .operator_key_hash =
        "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();
    let wrong_key = prepare_merkle_release(
        &config,
        &dispatch,
        &wrong_key_proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("wrong operator key anchor should fail");
    assert!(wrong_key.to_string().contains("operator_key_hash"));

    let mut mismatched_escrow_config = config.clone();
    mismatched_escrow_config.escrow_contract =
        "0x765F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();
    let invalid_escrow_contract = prepare_merkle_release(
        &mismatched_escrow_config,
        &dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("escrow contract drift should fail");
    assert!(invalid_escrow_contract
        .to_string()
        .contains("escrow_contract"));

    let mut invalid_token_dispatch = dispatch.clone();
    invalid_token_dispatch.settlement_token_address =
        "0x465F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();
    let invalid_token = prepare_merkle_release(
        &config,
        &invalid_token_dispatch,
        &proof,
        &anchor_content,
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("settlement token drift should fail");
    assert!(invalid_token
        .to_string()
        .contains("settlement_token_address"));

    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let registry_block_hash = "0xabababababababababababababababababababababababababababababababab";
    let settlement_key = signer_address_from_private_key(operator_private_key).test_unwrap();
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
        rpc_result(json!(encode_hex(
            IChioIdentityRegistry::getOperatorCall::abi_encode_returns(
                &IChioIdentityRegistry::OperatorRecord {
                    edKeyHash: parse_b256_hex(
                        &dual_dispatch.operator_key_hash,
                        "dual_dispatch.operator_key_hash",
                    )
                    .test_unwrap(),
                    settlementKey: settlement_key,
                    registeredAt: 7,
                    operatorEpoch: 1,
                    active: true,
                },
            )
        ))),
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
    ]);
    let mut dual_config = sample_config_with_rpc_url(server.base_url());
    dual_config.chain_id = dual_dispatch.chain_id.clone();
    dual_config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-unit",
        "rcpt-dual-unit",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let release = prepare_dual_sign_release(
        &dual_config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect("dual-sign release should prepare");

    assert_eq!(release.call.to_address, dual_config.escrow_contract);
    assert_eq!(release.observed_amount, dual_dispatch.settlement_amount);
    assert_eq!(release.operator_epoch, 1);
    assert_eq!(release.identity_registry_evidence.block_number, 101);
    assert_eq!(
        release.identity_registry_evidence.block_hash,
        registry_block_hash
    );
    assert_eq!(
        release.identity_registry_evidence.operator_key_hash,
        dual_dispatch.operator_key_hash
    );
    assert_eq!(
        release.identity_registry_evidence.settlement_key,
        format!("{settlement_key:?}")
    );
    assert_eq!(release.identity_registry_evidence.registered_at, 7);
    assert_eq!(release.identity_registry_evidence.operator_epoch, 1);
    assert!(release.identity_registry_evidence.active);
    assert!(release.signature.v >= 27);
    assert!(release.digest.starts_with("0x"));
    let requests = server.requests();
    assert_eq!(requests[0]["method"], "eth_getBlockByNumber");
    assert_eq!(requests[0]["params"], json!(["latest", false]));
    assert_eq!(requests[1]["method"], "eth_call");
    assert_eq!(requests[1]["params"][1], "0x65");
    assert_eq!(requests[2]["method"], "eth_getBlockByNumber");
    assert_eq!(requests[2]["params"], json!(["0x65", false]));
    server.join();
}

#[tokio::test]
async fn dual_sign_release_rejects_identity_registry_key_hash_mismatch() {
    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let registry_block_hash = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
        rpc_result(json!(encode_hex(
            IChioIdentityRegistry::getOperatorCall::abi_encode_returns(
                &IChioIdentityRegistry::OperatorRecord {
                    edKeyHash: B256::from([0x99; 32]),
                    settlementKey: signer_address_from_private_key(operator_private_key)
                        .test_unwrap(),
                    registeredAt: 1,
                    operatorEpoch: 1,
                    active: true,
                },
            )
        ))),
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
    ]);
    let mut config = sample_config_with_rpc_url(server.base_url());
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-mismatch",
        "rcpt-dual-mismatch",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("registry key hash mismatch should block dual-sign prep");
    assert!(error.to_string().contains("operator key hash"));
    server.join();
}

#[tokio::test]
async fn dual_sign_release_rejects_unpinned_registry_block() {
    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let server = MockJsonRpcServer::spawn(vec![rpc_result(json!({
        "number": "0x65",
        "timestamp": "0x6553f100"
    }))]);
    let mut config = sample_config_with_rpc_url(server.base_url());
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-unpinned",
        "rcpt-dual-unpinned",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("missing registry block hash should block dual-sign prep");
    assert!(error.to_string().contains("block missing hash"));
    server.join();
}

#[tokio::test]
async fn prepare_bond_lock_release_and_impair_cover_positive_paths() {
    let expected_vault_id = B256::from([0x44; 32]);
    let server = MockJsonRpcServer::spawn(vec![rpc_result(json!(encode_hex(
        IChioBondVault::deriveVaultIdCall::abi_encode_returns(&expected_vault_id)
    )))]);
    let primary_proof = sample_primary_proof();
    let mut config = sample_config_with_rpc_url(server.base_url());
    align_config_to_anchor_proof(&mut config, &primary_proof);
    let bond = sample_credit_bond("bond-unit", "facility-unit", 400, 250);
    let prepared = prepare_bond_lock(
        &config,
        &BondLockRequest {
            principal_address: "0x1000000000000000000000000000000000000005".to_string(),
            bond,
        },
        &sample_binding_for_config(&config),
    )
    .await
    .test_expect("bond lock should prepare");

    let requests = server.requests();
    server.join();

    assert_eq!(prepared.vault_id, format_b256(expected_vault_id));
    assert_eq!(prepared.collateral_minor_units, 4_000_000);
    assert_eq!(prepared.reserve_requirement_minor_units, 2_500_000);
    assert_eq!(prepared.call.to_address, config.bond_vault_contract);
    assert_eq!(requests[0]["method"], "eth_call");
    let fixture_operator_key_hash = primary_proof
        .chain_anchor
        .as_ref()
        .test_expect("sample proof includes chain anchor")
        .operator_key_hash
        .clone();
    assert_eq!(
        fixture_operator_key_hash,
        "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975"
    );
    assert_eq!(prepared.operator_key_hash, fixture_operator_key_hash);
    let prepared_snapshot = EvmBondSnapshot {
        vault_id: prepared.vault_id.clone(),
        principal_address: "0x1000000000000000000000000000000000000005".to_string(),
        operator_key_hash: prepared.operator_key_hash.clone(),
        expires_at: 1_800_000_000,
        observed_at: 1_799_999_000,
        locked_minor_units: prepared.collateral_minor_units,
        reserve_requirement_minor_units: prepared.reserve_requirement_minor_units,
        reserve_requirement_ratio_bps: 6_250,
        slashed_minor_units: 0,
        released: false,
        expired: false,
    };

    let release = prepare_bond_release(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &primary_proof,
    )
    .test_expect("bond release should prepare");
    let impair = prepare_bond_impair(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000006".to_string()],
        &[MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        }],
        &primary_proof,
    )
    .test_expect("bond impair should prepare");

    assert_eq!(release.call.to_address, config.bond_vault_contract);
    assert_eq!(release.vault_id, prepared.vault_id);
    assert_eq!(release.operator_key_hash, prepared.operator_key_hash);
    let anchor_root = primary_proof
        .receipt_inclusion
        .merkle_root
        .to_hex_prefixed();
    assert_ne!(release.merkle_root, anchor_root);
    assert_eq!(impair.slash_amount_minor_units, 2_500_000);
    assert_eq!(impair.call.to_address, config.bond_vault_contract);
    assert_eq!(impair.operator_key_hash, prepared.operator_key_hash);
    assert_ne!(impair.merkle_root, anchor_root);
    assert_ne!(release.merkle_root, impair.merkle_root);

    let batched_proof = batched_primary_proof();
    let batched_release = prepare_bond_release(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &batched_proof,
    )
    .test_expect("batched bond release proof should prepare");
    let batched_release_call = IChioBondVault::releaseBondDetailedCall::abi_decode(
        &decode_hex_bytes(&batched_release.call.data)
            .test_expect("batched release call data decodes"),
    )
    .test_expect("batched release call decodes");
    assert!(batched_release_call.proof.auditPath.is_empty());
    assert_eq!(batched_release_call.proof.leafIndex, U256::from(0_u8));
    assert_eq!(batched_release_call.proof.treeSize, U256::from(1_u8));
    assert_ne!(
        batched_release.merkle_root,
        batched_proof
            .receipt_inclusion
            .merkle_root
            .to_hex_prefixed()
    );

    let wrong_bond_operator_key_hash = format_b256(B256::from([0x22; 32]));
    let mut wrong_bond_snapshot = prepared_snapshot.clone();
    wrong_bond_snapshot.operator_key_hash = wrong_bond_operator_key_hash.clone();
    let wrong_bond_key_release = prepare_bond_release(
        &config,
        &config.operator_address,
        &wrong_bond_snapshot,
        &primary_proof,
    )
    .test_expect_err("bond release rejects bond operator key drift");
    assert!(wrong_bond_key_release
        .to_string()
        .contains("operator_key_hash"));
    let wrong_bond_key_impair = prepare_bond_impair(
        &config,
        &config.operator_address,
        &wrong_bond_snapshot,
        &MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000006".to_string()],
        &[MonetaryAmount {
            units: 250,
            currency: "USD".to_string(),
        }],
        &primary_proof,
    )
    .test_expect_err("bond impair rejects bond operator key drift");
    assert!(wrong_bond_key_impair
        .to_string()
        .contains("operator_key_hash"));

    let root_publication = prepare_bond_proof_root_publication(
        &config,
        &prepared_snapshot,
        PreparedBondProofRoot::Impair(&impair),
        2,
        2,
    )
    .test_expect("bond proof root publication should prepare");
    assert_eq!(
        root_publication.call().from_address,
        config.operator_address
    );
    assert_eq!(
        root_publication.call().to_address,
        config.root_registry_contract
    );
    let publish_call = IChioRootRegistry::publishRootCall::abi_decode(
        &decode_hex_bytes(&root_publication.call().data)
            .test_expect("publish root calldata decodes"),
    )
    .test_expect("publish root call decodes");
    assert_eq!(
        publish_call.merkleRoot,
        parse_b256_hex(&impair.merkle_root, "root").test_expect("impair root parses")
    );
    assert_eq!(publish_call.treeSize, 1);
    let mut tampered_impair_root = impair.clone();
    tampered_impair_root.merkle_root = format_b256(B256::from([0x99; 32]));
    let tampered_root_error = prepare_bond_proof_root_publication(
        &config,
        &prepared_snapshot,
        PreparedBondProofRoot::Impair(&tampered_impair_root),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects tampered prepared root");
    assert!(tampered_root_error.to_string().contains("merkle_root"));

    let decoded_impair_call = IChioBondVault::impairBondDetailedCall::abi_decode(
        &decode_hex_bytes(&impair.call.data).test_expect("impair call data decodes"),
    )
    .test_expect("impair call decodes");
    let mut tampered_impair_call = impair.clone();
    tampered_impair_call.call.data = encode_call(IChioBondVault::impairBondDetailedCall {
        root: B256::from([0xcc; 32]),
        ..decoded_impair_call
    });
    let tampered_call_error = prepare_bond_proof_root_publication(
        &config,
        &prepared_snapshot,
        PreparedBondProofRoot::Impair(&tampered_impair_call),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects tampered impair calldata");
    assert!(tampered_call_error.to_string().contains("merkle_root"));

    let decoded_zero_beneficiary_impair_call = IChioBondVault::impairBondDetailedCall::abi_decode(
        &decode_hex_bytes(&impair.call.data).test_expect("impair call data decodes"),
    )
    .test_expect("impair call decodes");
    let mut zero_beneficiary_impair = impair.clone();
    zero_beneficiary_impair.call.data = encode_call(IChioBondVault::impairBondDetailedCall {
        beneficiaries: vec![Address::ZERO],
        shares: decoded_zero_beneficiary_impair_call.shares.clone(),
        ..decoded_zero_beneficiary_impair_call
    });
    let zero_beneficiary_publication = prepare_bond_proof_root_publication(
        &config,
        &prepared_snapshot,
        PreparedBondProofRoot::Impair(&zero_beneficiary_impair),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects zero beneficiary impair distribution");
    assert!(zero_beneficiary_publication
        .to_string()
        .contains("InvalidSlashDistribution"));

    let decoded_release_call = IChioBondVault::releaseBondDetailedCall::abi_decode(
        &decode_hex_bytes(&release.call.data).test_expect("release call data decodes"),
    )
    .test_expect("release call decodes");
    let mut tampered_release_call = release.clone();
    tampered_release_call.call.data = encode_call(IChioBondVault::releaseBondDetailedCall {
        root: B256::from([0xdd; 32]),
        ..decoded_release_call
    });
    let tampered_release_error = prepare_bond_proof_root_publication(
        &config,
        &prepared_snapshot,
        PreparedBondProofRoot::Release(&tampered_release_call),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects tampered release calldata");
    assert!(tampered_release_error.to_string().contains("call data"));

    let mut wrong_publication_config = config.clone();
    wrong_publication_config.chain_id = "eip155:42161".to_string();
    let wrong_publication = prepare_bond_proof_root_publication(
        &wrong_publication_config,
        &prepared_snapshot,
        PreparedBondProofRoot::Impair(&impair),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects prepared chain drift");
    assert!(wrong_publication.to_string().contains("chain_id"));

    let mut released_publication_snapshot = prepared_snapshot.clone();
    released_publication_snapshot.released = true;
    let closed_publication = prepare_bond_proof_root_publication(
        &config,
        &released_publication_snapshot,
        PreparedBondProofRoot::Release(&release),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects released snapshot");
    assert!(closed_publication.to_string().contains("already closed"));

    let mut time_expired_publication_snapshot = prepared_snapshot.clone();
    time_expired_publication_snapshot.observed_at =
        time_expired_publication_snapshot.expires_at + 1;
    let time_expired_publication = prepare_bond_proof_root_publication(
        &config,
        &time_expired_publication_snapshot,
        PreparedBondProofRoot::Release(&release),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects time-expired snapshot");
    assert!(time_expired_publication.to_string().contains("expires_at"));

    let mut over_impair_publication_snapshot = prepared_snapshot.clone();
    over_impair_publication_snapshot.slashed_minor_units = 2_000_001;
    let over_impair_publication = prepare_bond_proof_root_publication(
        &config,
        &over_impair_publication_snapshot,
        PreparedBondProofRoot::Impair(&impair),
        2,
        2,
    )
    .test_expect_err("bond root publication rejects over-impairing snapshot");
    assert!(over_impair_publication
        .to_string()
        .contains("remaining bond collateral"));

    let mut wrong_chain_proof = primary_proof.clone();
    wrong_chain_proof
        .chain_anchor
        .as_mut()
        .test_expect("sample proof includes chain anchor")
        .chain_id = "eip155:42161".to_string();
    let wrong_chain = prepare_bond_release(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &wrong_chain_proof,
    )
    .test_expect_err("bond release rejects chain drift");
    assert!(wrong_chain.to_string().contains("chain_anchor.chain_id"));

    let mut wrong_registry_proof = primary_proof.clone();
    wrong_registry_proof
        .chain_anchor
        .as_mut()
        .test_expect("sample proof includes chain anchor")
        .contract_address = "0x2000000000000000000000000000000000000001".to_string();
    let wrong_registry = prepare_bond_release(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &wrong_registry_proof,
    )
    .test_expect_err("bond release rejects registry drift");
    assert!(wrong_registry
        .to_string()
        .contains("root_registry_contract"));

    let mut wrong_operator_config = config.clone();
    wrong_operator_config.operator_address =
        "0x2000000000000000000000000000000000000002".to_string();
    let wrong_operator = prepare_bond_release(
        &wrong_operator_config,
        &wrong_operator_config.operator_address,
        &prepared_snapshot,
        &primary_proof,
    )
    .test_expect_err("bond release rejects operator drift");
    assert!(wrong_operator.to_string().contains("operator_address"));

    let mut zero_operator_key_proof = primary_proof.clone();
    zero_operator_key_proof
        .chain_anchor
        .as_mut()
        .test_expect("sample proof includes chain anchor")
        .operator_key_hash =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let zero_operator_key = prepare_bond_release(
        &config,
        &config.operator_address,
        &prepared_snapshot,
        &zero_operator_key_proof,
    )
    .test_expect_err("bond release rejects zero operator key hash");
    let zero_operator_key_message = zero_operator_key.to_string();
    assert!(
        zero_operator_key_message.contains("operator key hash")
            || zero_operator_key_message.contains("operator_key_hash")
            || zero_operator_key_message.contains("verification"),
        "{zero_operator_key_message}"
    );
}

#[test]
fn bond_proof_leaf_matches_solidity_abi_vector() {
    let mut config = sample_config();
    config.bond_vault_contract = "0x1000000000000000000000000000000000000008".to_string();
    let leaf = bond_proof_leaf(
        &config,
        B256::from([0x44; 32]),
        B256::from([0x77; 32]),
        B256::from([0x55; 32]),
        1,
        2_500_000,
        B256::from([0x66; 32]),
    )
    .test_expect("bond proof leaf should hash");

    assert_eq!(
        format_b256(leaf),
        "0x3a66861348ce8a462d949911aee62b7c4f011d600927e8f19a23391756844aa6"
    );
}

#[test]
fn bond_distribution_hash_matches_solidity_abi_vector() {
    let hash = bond_distribution_hash(
        &[Address::from_str("0x1000000000000000000000000000000000000006").test_expect("address")],
        &[U256::from(2_500_000_u64)],
    );

    assert_eq!(
        format_b256(hash),
        "0x683300ebc7d25bc113b428e572e2b6698732a9ed36a33e26e849fafe65613496"
    );
}

#[test]
fn settlement_prep_helpers_fail_closed_on_invalid_inputs() {
    let proof = sample_primary_proof();
    let mut config = sample_config();
    align_config_to_anchor_proof(&mut config, &proof);
    let invalid_dispatch = hex_dispatch();
    let sample_bond_snapshot = EvmBondSnapshot {
        vault_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        principal_address: "0x1000000000000000000000000000000000000005".to_string(),
        operator_key_hash: "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975"
            .to_string(),
        expires_at: 1_800_000_000,
        observed_at: 1_799_999_000,
        locked_minor_units: 4_000_000,
        reserve_requirement_minor_units: 2_500_000,
        reserve_requirement_ratio_bps: 6_250,
        slashed_minor_units: 0,
        released: false,
        expired: false,
    };
    let mut released_snapshot = sample_bond_snapshot.clone();
    released_snapshot.released = true;
    let closed_release_error = prepare_bond_release(
        &config,
        &config.operator_address,
        &released_snapshot,
        &proof,
    )
    .test_expect_err("released bond snapshot should fail before calldata");
    assert!(closed_release_error.to_string().contains("already closed"));

    let mut expired_snapshot = sample_bond_snapshot.clone();
    expired_snapshot.expired = true;
    let closed_impair_error = prepare_bond_impair(
        &config,
        &config.operator_address,
        &expired_snapshot,
        &MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000002".to_string()],
        &[MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("expired bond snapshot should fail before calldata");
    assert!(closed_impair_error.to_string().contains("already closed"));

    let mut time_expired_snapshot = sample_bond_snapshot.clone();
    time_expired_snapshot.observed_at = time_expired_snapshot.expires_at + 1;
    let time_expired_release = prepare_bond_release(
        &config,
        &config.operator_address,
        &time_expired_snapshot,
        &proof,
    )
    .test_expect_err("time-expired bond snapshot should fail before release calldata");
    assert!(time_expired_release.to_string().contains("expires_at"));
    let time_expired_impair = prepare_bond_impair(
        &config,
        &config.operator_address,
        &time_expired_snapshot,
        &MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000002".to_string()],
        &[MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("time-expired bond snapshot should fail before impair calldata");
    assert!(time_expired_impair.to_string().contains("expires_at"));

    let over_impair_error = prepare_bond_impair(
        &config,
        &config.operator_address,
        &sample_bond_snapshot,
        &MonetaryAmount {
            units: 401,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000002".to_string()],
        &[MonetaryAmount {
            units: 401,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("over-impairment should fail before calldata");
    assert!(over_impair_error
        .to_string()
        .contains("remaining bond collateral"));

    let share_error = prepare_bond_impair(
        &config,
        &config.operator_address,
        &sample_bond_snapshot,
        &MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000002".to_string()],
        &[MonetaryAmount {
            units: 9,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("mismatched shares should fail");
    assert!(share_error
        .to_string()
        .contains("slash shares must sum to slash_amount"));

    let zero_slash_error = prepare_bond_impair(
        &config,
        &config.operator_address,
        &sample_bond_snapshot,
        &MonetaryAmount {
            units: 0,
            currency: "USD".to_string(),
        },
        &["0x1000000000000000000000000000000000000002".to_string()],
        &[MonetaryAmount {
            units: 0,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("zero slash should fail");
    assert!(zero_slash_error
        .to_string()
        .contains("slash_amount must be greater than zero"));

    let zero_beneficiary_error = prepare_bond_impair(
        &config,
        &config.operator_address,
        &sample_bond_snapshot,
        &MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        &["0x0000000000000000000000000000000000000000".to_string()],
        &[MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        }],
        &proof,
    )
    .test_expect_err("zero beneficiary should fail");
    assert!(zero_beneficiary_error
        .to_string()
        .contains("InvalidSlashDistribution"));

    let many_beneficiaries = (0..17_u64)
        .map(|index| format!("0x{:040x}", 0x1000_u64 + index))
        .collect::<Vec<_>>();
    let many_shares = (0..17)
        .map(|_| MonetaryAmount {
            units: 1,
            currency: "USD".to_string(),
        })
        .collect::<Vec<_>>();
    let many_beneficiaries_error = prepare_bond_impair(
        &config,
        "0x1000000000000000000000000000000000000001",
        &sample_bond_snapshot,
        &MonetaryAmount {
            units: 17,
            currency: "USD".to_string(),
        },
        &many_beneficiaries,
        &many_shares,
        &proof,
    )
    .test_expect_err("too many beneficiaries should fail");
    assert!(many_beneficiaries_error
        .to_string()
        .contains("beneficiary count"));

    let finalize_error = finalize_escrow_dispatch(
        &PreparedEscrowCreate {
            expected_escrow_id: "0xdeadbeef".to_string(),
            capability_commitment: "0xfeedface".to_string(),
            settlement_amount_minor_units: 1_500_000,
            dispatch: invalid_dispatch.clone(),
            call: PreparedEvmCall {
                from_address: invalid_dispatch.beneficiary_address.clone(),
                to_address: invalid_dispatch.escrow_contract.clone(),
                data: "0x".to_string(),
                gas_limit: None,
            },
        },
        &EvmTransactionReceipt {
            tx_hash: "0xabc".to_string(),
            block_number: 1,
            block_hash: "0x01".to_string(),
            status: false,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: invalid_dispatch.escrow_contract.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![],
        },
    )
    .test_expect_err("failed receipt should fail closed");
    assert!(finalize_error
        .to_string()
        .contains("failed before escrow identity could be finalized"));
}

#[test]
fn helper_parsers_and_request_serialization_fail_closed() {
    let request = request_value(&PreparedEvmCall {
        from_address: "0x1000000000000000000000000000000000000001".to_string(),
        to_address: "0x1000000000000000000000000000000000000002".to_string(),
        data: "0xdeadbeef".to_string(),
        gas_limit: Some(21_000),
    });
    assert_eq!(request["gas"], serde_json::json!("0x5208"));

    let chain_error = parse_eip155_chain_id("solana:mainnet").test_expect_err("unsupported id");
    assert!(matches!(chain_error, SettlementError::Unsupported(_)));

    let log_error = parse_log_entry(&serde_json::json!({
        "address": "0x1000000000000000000000000000000000000001",
        "topics": ["0x1111111111111111111111111111111111111111111111111111111111111111"],
        "data": "not-hex"
    }))
    .test_expect_err("bad log payload");
    assert!(matches!(log_error, SettlementError::Serialization(_)));

    let overflow =
        u256_to_u128(U256::from_limbs([0, 0, 1, 0]), "field").test_expect_err("overflowed u128");
    assert!(matches!(overflow, SettlementError::InvalidInput(_)));
}
