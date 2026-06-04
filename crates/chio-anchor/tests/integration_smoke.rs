#![cfg(feature = "web3")]

use chio_anchor::{
    assess_functions_verification, build_anchor_discovery_artifact_with_runtime,
    checkpoint_statement_from_kernel, kernel_checkpoint_from_statement, AnchorDiscoveryChain,
    AnchorDiscoveryFreshnessStatus, AnchorDiscoveryServiceEndpoint, AnchorEmergencyControls,
    AnchorEmergencyMode, AnchorLaneHealthStatus, AnchorLaneKind, AnchorLaneRuntimeStatus,
    AnchorRuntimeReport, AnchorServiceConfig, ChainlinkFunctionsTarget, FunctionsFallbackStatus,
    FunctionsVerificationPolicy, FunctionsVerificationPurpose, FunctionsVerificationResponse,
    PreparedFunctionsVerificationRequest, CHIO_ANCHOR_DISCOVERY_SCHEMA,
};
use chio_core::crypto::Keypair;
use chio_core::hashing::{sha256, Hash};
use chio_core::web3::{
    SignedWeb3IdentityBinding, Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
    CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};
use chio_kernel::checkpoint::{build_checkpoint, CheckpointError};

use chio_test_support::prelude::*;

#[test]
fn anchor_public_types_capture_discovery_shape() {
    let endpoint = AnchorDiscoveryServiceEndpoint {
        chains: vec![AnchorDiscoveryChain {
            chain_id: "eip155:8453".to_string(),
            contract_address: "0x1000000000000000000000000000000000000001".to_string(),
            operator_address: "0x1000000000000000000000000000000000000002".to_string(),
            publisher_address: "0x1000000000000000000000000000000000000002".to_string(),
            requires_delegate_authorization: false,
        }],
        bitcoin_anchor_method: Some("opentimestamps".to_string()),
        ots_calendars: vec!["https://calendar.example".to_string()],
        solana_cluster: Some("devnet".to_string()),
        publication_policy: None,
        chain_runtime: Vec::new(),
        current_freshness: None,
    };

    assert_eq!(endpoint.chains.len(), 1);
    assert_eq!(endpoint.chains[0].chain_id, "eip155:8453");
    assert_eq!(AnchorLaneKind::BitcoinOts, AnchorLaneKind::BitcoinOts);
    assert_eq!(CHIO_ANCHOR_DISCOVERY_SCHEMA, "chio.anchor-discovery.v1");
}

#[test]
fn anchor_discovery_reports_publication_policy_and_current_freshness_state() {
    let keypair = Keypair::generate();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: "did:chio:operator-1".to_string(),
        chio_public_key: keypair.public_key(),
        chain_scope: vec!["eip155:8453".to_string()],
        purpose: vec![Web3KeyBindingPurpose::Anchor],
        settlement_address: "0x1000000000000000000000000000000000000002".to_string(),
        issued_at: 1_775_100_000,
        expires_at: 1_775_200_000,
        nonce: "bind-001".to_string(),
    };
    let signature = keypair
        .sign_canonical(&certificate)
        .test_expect("binding signature")
        .0;
    let binding = SignedWeb3IdentityBinding {
        certificate,
        signature,
    };
    let config = AnchorServiceConfig {
        evm_targets: vec![chio_anchor::EvmAnchorTarget {
            chain_id: "eip155:8453".to_string(),
            rpc_url: "https://rpc.example".to_string(),
            contract_address: "0x1000000000000000000000000000000000000001".to_string(),
            operator_address: "0x1000000000000000000000000000000000000002".to_string(),
            publisher_address: "0x1000000000000000000000000000000000000003".to_string(),
        }],
        ots_calendars: vec!["https://calendar.example".to_string()],
        solana_cluster: Some("devnet".to_string()),
    };
    let report = AnchorRuntimeReport {
        schema: "chio.anchor-runtime-report.v1".to_string(),
        generated_at: 1_775_137_800,
        controls: AnchorEmergencyControls::normal(1_775_137_700),
        lanes: vec![AnchorLaneRuntimeStatus {
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            status: AnchorLaneHealthStatus::Lagging,
            latest_checkpoint_seq: 42,
            indexed_checkpoint_seq: 41,
            reorg_depth: 0,
            last_published_at: Some(1_775_137_760),
            next_action: Some("publish checkpoint 42".to_string()),
            note: Some("one checkpoint behind registry".to_string()),
        }],
        indexers: Vec::new(),
        incidents: Vec::new(),
    };

    let artifact = build_anchor_discovery_artifact_with_runtime(&config, &binding, &report, 120)
        .test_expect("discovery artifact");

    let endpoint = artifact.service.service_endpoint;
    let policy = endpoint
        .publication_policy
        .test_expect("publication policy");
    assert_eq!(policy.primary_lane, AnchorLaneKind::EvmPrimary);
    assert!(policy.secondary_lanes.contains(&AnchorLaneKind::BitcoinOts));
    assert!(policy.secondary_lanes.contains(&AnchorLaneKind::SolanaMemo));
    assert!(policy.requires_trust_anchor_binding);
    assert!(policy.requires_witness_or_immutable_anchor_reference);
    assert!(policy.delegate_publication_allowed);
    assert_eq!(policy.emergency_mode, AnchorEmergencyMode::Normal);
    assert_eq!(endpoint.chains.len(), 1);
    assert!(endpoint.chains[0].requires_delegate_authorization);
    assert_eq!(artifact.root_publication_ownership.len(), 1);
    assert!(artifact.root_publication_ownership[0].delegate_publication_allowed);
    assert_eq!(
        artifact.root_publication_ownership[0].ownership_rule,
        "operator-owned-root delegate-published-via-root-registry-authorization"
    );

    let freshness = endpoint.current_freshness.test_expect("freshness state");
    assert_eq!(freshness.status, AnchorDiscoveryFreshnessStatus::Lagging);
    assert_eq!(freshness.latest_checkpoint_seq, 42);
    assert_eq!(freshness.indexed_checkpoint_seq, 41);
    assert_eq!(freshness.last_published_at, Some(1_775_137_760));
    assert_eq!(freshness.publication_age_secs, Some(40));

    assert_eq!(endpoint.chain_runtime.len(), 1);
    assert_eq!(endpoint.chain_runtime[0].chain_id, "eip155:8453");
    assert_eq!(
        endpoint.chain_runtime[0].status,
        AnchorDiscoveryFreshnessStatus::Lagging
    );
    assert!(!endpoint.chain_runtime[0].has_active_conflict);
    assert!(endpoint.chain_runtime[0].incident_codes.is_empty());
}

#[test]
fn checkpoint_statement_round_trips_kernel_checkpoint_fields() -> Result<(), CheckpointError> {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(
        7,
        40,
        42,
        &[
            b"receipt-40".to_vec(),
            b"receipt-41".to_vec(),
            b"receipt-42".to_vec(),
        ],
        &keypair,
    )?;

    let statement = checkpoint_statement_from_kernel(&checkpoint);
    assert_eq!(statement.checkpoint_seq, 7);
    assert_eq!(statement.batch_start_seq, 40);
    assert_eq!(statement.batch_end_seq, 42);
    assert_eq!(statement.tree_size, 3);
    assert_eq!(statement.merkle_root, checkpoint.body.merkle_root);
    assert_eq!(statement.issued_at, checkpoint.body.issued_at);
    assert_eq!(
        statement.previous_checkpoint_sha256,
        checkpoint.body.previous_checkpoint_sha256
    );
    assert_eq!(statement.kernel_key, checkpoint.body.kernel_key);
    assert_eq!(statement.signature, checkpoint.signature);

    let restored = kernel_checkpoint_from_statement(&statement);
    assert_eq!(restored.body.schema, statement.schema);
    assert_eq!(restored.body.checkpoint_seq, checkpoint.body.checkpoint_seq);
    assert_eq!(
        restored.body.batch_start_seq,
        checkpoint.body.batch_start_seq
    );
    assert_eq!(restored.body.batch_end_seq, checkpoint.body.batch_end_seq);
    assert_eq!(restored.body.tree_size, checkpoint.body.tree_size);
    assert_eq!(restored.body.merkle_root, checkpoint.body.merkle_root);
    assert_eq!(restored.body.issued_at, checkpoint.body.issued_at);
    assert_eq!(
        restored.body.previous_checkpoint_sha256,
        checkpoint.body.previous_checkpoint_sha256
    );
    assert_eq!(restored.body.kernel_key, checkpoint.body.kernel_key);
    assert_eq!(restored.signature, checkpoint.signature);

    Ok(())
}

#[test]
fn functions_verification_rejects_request_id_and_chain_mismatches() {
    let request = sample_functions_request();
    let mut response = matching_functions_response(&request);
    response.request_id = "chio.functions.eip155-8453.other".to_string();

    let id_error = assess_functions_verification(&request, &response);
    assert!(id_error.is_err());
    let id_message = id_error
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(id_message.contains("does not match request"));

    let mut response = matching_functions_response(&request);
    response.target_chain_id = "eip155:1".to_string();

    let chain_error = assess_functions_verification(&request, &response);
    assert!(chain_error.is_err());
    let chain_message = chain_error
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(chain_message.contains("does not match request chain"));
}

fn sample_functions_request() -> PreparedFunctionsVerificationRequest {
    let policy = FunctionsVerificationPolicy {
        max_batch_receipts: 4,
        max_request_size_bytes: 4096,
        max_callback_gas_limit: 300_000,
        max_return_bytes: 128,
        max_notional_value_usd_cents: 10_000,
        allow_direct_fund_release: false,
        require_receipt_event_log: true,
        challenge_window_secs: 600,
    };
    let receipt_batch_root = sha256(b"functions-batch-root");
    let request_payload_sha256 = sha256(b"functions-request-payload");

    PreparedFunctionsVerificationRequest {
        request_id: "chio.functions.eip155-8453.abcdef1234567890".to_string(),
        target: ChainlinkFunctionsTarget {
            chain_id: "eip155:8453".to_string(),
            router_address: "0x1000000000000000000000000000000000000001".to_string(),
            consumer_address: "0x1000000000000000000000000000000000000002".to_string(),
            don_id: "fun-base-mainnet".to_string(),
            subscription_id: 42,
            callback_gas_limit: 250_000,
        },
        purpose: FunctionsVerificationPurpose::AnchorAuditBatch,
        receipt_count: 2,
        request_size_bytes: 256,
        source_code_sha256: sha256(b"functions-source"),
        receipt_batch_root,
        batch_items: Vec::new(),
        request_payload_sha256,
        max_notional_value_usd_cents: 1_000,
        policy,
        note: None,
    }
}

fn matching_functions_response(
    request: &PreparedFunctionsVerificationRequest,
) -> FunctionsVerificationResponse {
    FunctionsVerificationResponse {
        request_id: request.request_id.clone(),
        target_chain_id: request.target.chain_id.clone(),
        status: FunctionsFallbackStatus::Verified,
        verified_receipt_count: request.receipt_count,
        returned_bytes: 32,
        receipt_batch_root: request.receipt_batch_root,
        result_payload_sha256: Hash::zero(),
        executed_at: 1_775_138_000,
        note: None,
    }
}
