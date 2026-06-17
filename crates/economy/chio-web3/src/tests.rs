use crate::anchors::{
    checkpoint_statement_body, validate_anchor_inclusion_proof,
    validate_oracle_conversion_evidence, verify_anchor_inclusion_proof, AnchorInclusionProof,
    OracleConversionEvidence, Web3ChainAnchorRecord, Web3CheckpointStatement, Web3ReceiptInclusion,
    CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA, CHIO_CHECKPOINT_STATEMENT_SCHEMA,
    CHIO_LINK_ORACLE_AUTHORITY, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
};
use crate::canonical::canonical_json_bytes;
use crate::capability::scope::MonetaryAmount;
use crate::chain::{validate_web3_chain_configuration, Web3ChainConfiguration};
use crate::contracts::{validate_web3_contract_package, Web3ContractPackage};
use crate::credit::{
    CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery, CapitalBookSourceKind,
    CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionRailKind,
    CapitalExecutionReconciledState, CapitalExecutionRole, CapitalExecutionWindow,
    SignedCapitalExecutionInstruction, CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::crypto::{sha256_hex, Keypair, Signature};
use crate::error::Web3ContractError;
use crate::identity::{
    validate_web3_identity_binding, verify_web3_identity_binding, SignedWeb3IdentityBinding,
    Web3IdentityBindingCertificate, Web3KeyBindingPurpose, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};
use crate::merkle::MerkleTree;
use crate::qualification::{validate_web3_qualification_matrix, Web3QualificationMatrix};
use crate::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use crate::settlement::{
    validate_web3_settlement_dispatch, validate_web3_settlement_execution_receipt,
    Web3SettlementDispatchArtifact, Web3SettlementExecutionReceiptArtifact,
    Web3SettlementLifecycleState, Web3SettlementSupportBoundary,
    CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA, CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use crate::settlement_proof::{
    verify_public_settlement_proof, PublicSettlementDisputePosture,
    PublicSettlementDisputeSnapshot, PublicSettlementProofBundle,
    CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA, CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA,
    CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA, CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND, CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED,
    CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND,
    CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED,
};
use crate::trust_profile::{
    validate_web3_trust_profile, Web3ChainFinalityRule, Web3DisputePolicy, Web3DisputeWindow,
    Web3FinalityMode, Web3RegulatedRole, Web3RegulatedRoleAssumption, Web3SettlementPath,
    Web3TrustProfile, CHIO_WEB3_TRUST_PROFILE_SCHEMA,
};
use serde_json::json;

fn operator_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn treasury_keypair() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

fn custodian_keypair() -> Keypair {
    Keypair::from_seed(&[11u8; 32])
}

fn beneficiary_keypair() -> Keypair {
    Keypair::from_seed(&[13u8; 32])
}

fn signed_identity_binding(
    signer: Keypair,
    settlement_address: &str,
    purpose: Vec<Web3KeyBindingPurpose>,
    chain_scope: Vec<&str>,
    nonce: &str,
) -> SignedWeb3IdentityBinding {
    signed_identity_binding_with_window(
        signer,
        settlement_address,
        purpose,
        chain_scope,
        nonce,
        1_743_292_800,
        1_774_828_800,
    )
}

fn signed_identity_binding_with_window(
    signer: Keypair,
    settlement_address: &str,
    purpose: Vec<Web3KeyBindingPurpose>,
    chain_scope: Vec<&str>,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> SignedWeb3IdentityBinding {
    let public_key = signer.public_key();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", public_key.to_hex()),
        chio_public_key: public_key,
        chain_scope: chain_scope.into_iter().map(str::to_string).collect(),
        purpose,
        settlement_address: settlement_address.to_string(),
        issued_at,
        expires_at,
        nonce: nonce.to_string(),
    };
    let Ok((signature, _)) = signer.sign_canonical(&certificate) else {
        panic!("sample identity binding signs");
    };
    SignedWeb3IdentityBinding {
        certificate,
        signature,
    }
}

fn sample_binding() -> SignedWeb3IdentityBinding {
    signed_identity_binding(
        operator_keypair(),
        "0x1111111111111111111111111111111111111111",
        vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        vec!["eip155:8453", "eip155:42161"],
        "0123456789abcdef0123456789abcdef",
    )
}

fn sample_beneficiary_binding() -> SignedWeb3IdentityBinding {
    signed_identity_binding(
        beneficiary_keypair(),
        "0x2222222222222222222222222222222222222222",
        vec![Web3KeyBindingPurpose::Settle],
        vec!["eip155:8453"],
        "beneficiary-identity-binding-0001",
    )
}

fn sample_trust_profile() -> Web3TrustProfile {
    Web3TrustProfile {
        schema: CHIO_WEB3_TRUST_PROFILE_SCHEMA.to_string(),
        profile_id: "chio.official-web3-stack".to_string(),
        chio_contract_version: "2.0".to_string(),
        primary_chain_id: "eip155:8453".to_string(),
        secondary_chain_ids: vec!["eip155:42161".to_string()],
        operator_binding: sample_binding(),
        proof_bundle_required: true,
        dispute_windows: vec![
            Web3DisputeWindow {
                settlement_path: Web3SettlementPath::DualSignature,
                challenge_window_secs: 600,
                recovery_window_secs: 3_600,
                dispute_policy: Web3DisputePolicy::OffChainArbitration,
            },
            Web3DisputeWindow {
                settlement_path: Web3SettlementPath::MerkleProof,
                challenge_window_secs: 900,
                recovery_window_secs: 86_400,
                dispute_policy: Web3DisputePolicy::TimeoutRefund,
            },
        ],
        finality_rules: vec![
            Web3ChainFinalityRule {
                chain_id: "eip155:8453".to_string(),
                mode: Web3FinalityMode::OptimisticL2,
                min_confirmations: 20,
            },
            Web3ChainFinalityRule {
                chain_id: "eip155:42161".to_string(),
                mode: Web3FinalityMode::L1Finalized,
                min_confirmations: 12,
            },
        ],
        regulated_roles: vec![
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Operator,
                actor_id: "chio-operator-main".to_string(),
                responsibility: "Originates governed dispatch and maintains local policy activation."
                    .to_string(),
                custody_boundary_explicit: true,
            },
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Custodian,
                actor_id: "custodian-base-main".to_string(),
                responsibility: "Holds settlement-side keys and custody accounts for the official stack."
                    .to_string(),
                custody_boundary_explicit: true,
            },
            Web3RegulatedRoleAssumption {
                role: Web3RegulatedRole::Arbitrator,
                actor_id: "settlement-dispute-panel".to_string(),
                responsibility: "Handles off-chain challenge and reversal review during dispute windows."
                    .to_string(),
                custody_boundary_explicit: true,
            },
        ],
        custody_boundary_note:
            "Chio governs intent, proofs, and policy admission; custodians and payment institutions remain explicit operators of record."
                .to_string(),
        local_policy_activation_required: true,
    }
}

fn sample_oracle_evidence() -> OracleConversionEvidence {
    OracleConversionEvidence {
        schema: CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA.to_string(),
        base: "ETH".to_string(),
        quote: "USD".to_string(),
        authority: CHIO_LINK_ORACLE_AUTHORITY.to_string(),
        rate_numerator: 300_000,
        rate_denominator: 100,
        source: "chainlink".to_string(),
        feed_address: "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612".to_string(),
        updated_at: 1_743_292_740,
        max_age_seconds: 3_600,
        cache_age_seconds: 45,
        converted_cost_units: 300,
        original_cost_units: 1_000_000_000_000_000,
        original_currency: "ETH".to_string(),
        grant_currency: "USD".to_string(),
    }
}

fn sample_receipt() -> ChioReceipt {
    let operator = operator_keypair();
    let parameters = json!({
        "to": "0x2222222222222222222222222222222222222222",
        "amount": 150,
        "currency": "USDC"
    });
    let action = ToolCallAction::from_parameters(parameters).unwrap();
    let body = ChioReceiptBody {
        id: "rcpt-web3-1".to_string(),
        timestamp: 1_743_292_800,
        capability_id: "cap-web3-1".to_string(),
        tool_server: "chio-settle".to_string(),
        tool_name: "release_escrow".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"web3-settlement"),
        policy_hash: sha256_hex(b"policy-web3"),
        evidence: vec![],
        metadata: Some(json!({
            "financial": {
                "grant_index": 0,
                "cost_charged": 150,
                "currency": "USD",
                "budget_remaining": 850,
                "budget_total": 1000,
                "delegation_depth": 1,
                "root_budget_holder": "subject-1",
                "payment_reference": "escrow-1",
                "settlement_status": "pending",
                "oracle_evidence": sample_oracle_evidence()
            }
        })),
        trust_level: chio_core_types::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: operator.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, &operator).unwrap()
}

fn sample_anchor_inclusion_proof() -> AnchorInclusionProof {
    let operator = operator_keypair();
    let receipt = sample_receipt();
    let receipt_body = receipt.body();
    let receipt_bytes = canonical_json_bytes(&receipt_body).unwrap();
    let tree = MerkleTree::from_leaves(&[receipt_bytes]).unwrap();
    let merkle_root = tree.root();
    let inclusion = Web3ReceiptInclusion {
        checkpoint_seq: 1_042,
        merkle_root,
        proof: tree.inclusion_proof(0).unwrap(),
    };
    let mut statement = Web3CheckpointStatement {
        schema: CHIO_CHECKPOINT_STATEMENT_SCHEMA.to_string(),
        checkpoint_seq: 1_042,
        batch_start_seq: 104_101,
        batch_end_seq: 104_200,
        tree_size: 1,
        merkle_root,
        issued_at: 1_743_292_800,
        previous_checkpoint_sha256: None,
        kernel_key: operator.public_key(),
        signature: Signature::from_hex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
    };
    let body = checkpoint_statement_body(&statement);
    let (signature, _) = operator.sign_canonical(&body).unwrap();
    statement.signature = signature;

    AnchorInclusionProof {
        schema: CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA.to_string(),
        receipt,
        receipt_inclusion: inclusion,
        checkpoint_statement: statement,
        chain_anchor: Some(Web3ChainAnchorRecord {
            chain_id: "eip155:8453".to_string(),
            contract_address: "0x1000000000000000000000000000000000000001".to_string(),
            operator_address: "0x1111111111111111111111111111111111111111".to_string(),
            tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            block_number: 12_345_678,
            block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            anchored_merkle_root: merkle_root,
            anchored_checkpoint_seq: 1_042,
        }),
        bitcoin_anchor: None,
        super_root_inclusion: None,
        key_binding_certificate: sample_binding(),
    }
}

fn sample_capital_instruction() -> SignedCapitalExecutionInstruction {
    let signer = treasury_keypair();
    let custodian = custodian_keypair();
    let custodian_id = custodian.public_key().to_hex();
    SignedCapitalExecutionInstruction::sign(
        crate::credit::CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-web3-1".to_string(),
            issued_at: 1_743_292_800,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:facility:facility-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: Some("rcpt-web3-1".to_string()),
            completion_flow_row_id: Some("economic-completion-flow:rcpt-web3-1".to_string()),
            action: CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::OperatorTreasury,
                    &signer,
                    1_743_292_790,
                    1_743_293_800,
                    Some("governed release".to_string()),
                )
                .unwrap(),
                CapitalExecutionAuthorityStep::signed(
                    CapitalExecutionRole::Custodian,
                    &custodian,
                    1_743_292_795,
                    1_743_293_800,
                    Some("official web3 stack".to_string()),
                )
                .unwrap(),
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 1_743_292_800,
                not_after: 1_743_293_800,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Web3,
                rail_id: "base-mainnet-usdc".to_string(),
                custody_provider_id: custodian_id,
                source_account_ref: Some("vault:facility-main".to_string()),
                destination_account_ref: Some(
                    "0x2222222222222222222222222222222222222222".to_string(),
                ),
                jurisdiction: Some("US".to_string()),
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
            evidence_refs: vec![
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rcpt-web3-1".to_string(),
                    observed_at: Some(1_743_292_800),
                    locator: Some("receipt:rcpt-web3-1".to_string()),
                },
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CommerceOrder,
                    reference_id: "order-public-settlement-1".to_string(),
                    observed_at: Some(1_743_292_800),
                    locator: Some("commerce-order:order-public-settlement-1".to_string()),
                },
            ],
            description: "release escrow over the official web3 rail".to_string(),
        },
        &signer,
    )
    .unwrap()
}

fn resign_dispatch_capital_instruction(dispatch: &mut Web3SettlementDispatchArtifact) {
    dispatch.capital_instruction = SignedCapitalExecutionInstruction::sign(
        dispatch.capital_instruction.body.clone(),
        &treasury_keypair(),
    )
    .unwrap();
}

fn sample_dispatch() -> Web3SettlementDispatchArtifact {
    Web3SettlementDispatchArtifact {
        schema: CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
        dispatch_id: "dispatch-web3-1".to_string(),
        issued_at: 1_743_292_800,
        trust_profile_id: "chio.official-web3-stack".to_string(),
        contract_package_id: "chio.official-web3-contracts".to_string(),
        chain_id: "eip155:8453".to_string(),
        capital_instruction: sample_capital_instruction(),
        bond: None,
        settlement_path: Web3SettlementPath::MerkleProof,
        settlement_amount: MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
        escrow_id: "escrow-web3-1".to_string(),
        escrow_contract: "0x1000000000000000000000000000000000000002".to_string(),
        bond_vault_contract: "0x1000000000000000000000000000000000000003".to_string(),
        beneficiary_address: "0x2222222222222222222222222222222222222222".to_string(),
        support_boundary: Web3SettlementSupportBoundary {
            real_dispatch_supported: true,
            anchor_proof_required: true,
            oracle_evidence_required_for_fx: true,
            custody_boundary_explicit: true,
            reversal_supported: true,
        },
        note: Some(
            "Dispatches one governed escrow release over the official Base-first contract stack."
                .to_string(),
        ),
    }
}

fn sample_execution_receipt() -> Web3SettlementExecutionReceiptArtifact {
    Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id: "receipt-web3-1".to_string(),
        issued_at: 1_743_292_860,
        dispatch: sample_dispatch(),
        observed_execution: CapitalExecutionObservation {
            observed_at: 1_743_292_860,
            external_reference_id:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            amount: MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
        },
        lifecycle_state: Web3SettlementLifecycleState::Settled,
        settlement_reference: "settlement-web3-1".to_string(),
        reconciled_anchor_proof: Some(sample_anchor_inclusion_proof()),
        oracle_evidence: Some(sample_oracle_evidence()),
        settled_amount: MonetaryAmount {
            units: 150,
            currency: "USD".to_string(),
        },
        reversal_of: None,
        failure_reason: None,
        note: Some(
            "Settled against an anchored receipt root and retained oracle provenance for the FX conversion."
                .to_string(),
        ),
    }
}

fn sample_public_settlement_proof_bundle() -> PublicSettlementProofBundle {
    PublicSettlementProofBundle {
        schema: CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA.to_string(),
        bundle_id: "public-settlement-proof-web3-1".to_string(),
        transaction_passport_id: "passport-public-settlement-1".to_string(),
        commerce_order_id: "order-public-settlement-1".to_string(),
        chain_id: "eip155:8453".to_string(),
        settlement_receipt: sample_execution_receipt(),
        chain_snapshot: serde_json::from_value(sample_public_settlement_chain_snapshot_json())
            .unwrap(),
        dispute_snapshot: Some(sample_public_settlement_dispute_snapshot()),
        required_confirmations: 20,
        observed_confirmations: 24,
        dispute_posture: PublicSettlementDisputePosture::Undisputed,
    }
}

fn sample_public_settlement_dispute_snapshot() -> PublicSettlementDisputeSnapshot {
    PublicSettlementDisputeSnapshot {
        schema: CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA.to_string(),
        dispute_id: "dispute-public-settlement-none".to_string(),
        posture: PublicSettlementDisputePosture::Undisputed,
        observed_at: 1_743_293_460,
        challenge_window_secs: 600,
        window_closed_at: 1_743_293_460,
        open_dispute_count: 0,
        linked_receipt_ids: Vec::new(),
        chain_event_tx_hashes: Vec::new(),
    }
}

fn sample_public_settlement_chain_snapshot_json() -> serde_json::Value {
    let registry_root = sample_anchor_inclusion_proof()
        .checkpoint_statement
        .merkle_root
        .to_hex_prefixed();
    let mut snapshot = json!({
        "chain_id": "eip155:8453",
        "observed_block_number": 12_345_678,
        "latest_block_number": 12_345_701,
        "max_block_lag": 128,
        "root_registry_address": "0x1000000000000000000000000000000000000001",
        "registry_root": registry_root,
        "block": {
            "block_number": 12_345_678,
            "block_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transaction_hashes": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ]
        },
        "escrow": {
            "escrow_id": "escrow-web3-1",
            "escrow_contract": "0x1000000000000000000000000000000000000002",
            "beneficiary_address": "0x2222222222222222222222222222222222222222",
            "locked_amount": {
                "units": 150,
                "currency": "USD"
            },
            "released_amount": {
                "units": 150,
                "currency": "USD"
            }
        },
        "bond": {
            "bond_vault_contract": "0x1000000000000000000000000000000000000003",
            "posted_amount": {
                "units": 150,
                "currency": "USD"
            },
            "minimum_required_amount": {
                "units": 150,
                "currency": "USD"
            }
        }
    });
    let Ok(binding) = serde_json::to_value(sample_beneficiary_binding()) else {
        panic!("sample beneficiary identity binding serializes");
    };
    snapshot["beneficiary_identity_binding"] = binding;
    snapshot
}

fn sample_public_settlement_proof_bundle_with_chain_snapshot(
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PublicSettlementProofBundle {
    let Ok(mut bundle) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    bundle["chain_snapshot"] = sample_public_settlement_chain_snapshot_json();
    mutate(&mut bundle);
    let Ok(bundle) = serde_json::from_value(bundle) else {
        panic!("sample public settlement proof bundle parses");
    };
    bundle
}

fn sample_public_settlement_proof_bundle_with_order_ref(
    order_id: &str,
) -> PublicSettlementProofBundle {
    let Ok(mut bundle_value) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    let Some(evidence_refs) = bundle_value["settlement_receipt"]["dispatch"]["capital_instruction"]
        ["body"]["evidenceRefs"]
        .as_array_mut()
    else {
        panic!("sample public settlement proof bundle has evidence refs");
    };
    evidence_refs.push(json!({
        "kind": "commerce_order",
        "referenceId": order_id,
        "observedAt": 1_743_292_800,
        "locator": format!("commerce-order:{order_id}")
    }));
    let Ok(mut bundle) = serde_json::from_value::<PublicSettlementProofBundle>(bundle_value) else {
        panic!("sample public settlement proof bundle parses");
    };
    resign_dispatch_capital_instruction(&mut bundle.settlement_receipt.dispatch);
    bundle
}

fn sample_chain_configuration() -> Web3ChainConfiguration {
    serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap()
}

#[test]
fn trust_profile_requires_local_policy_activation() {
    let mut profile = sample_trust_profile();
    profile.local_policy_activation_required = false;
    assert!(matches!(
        validate_web3_trust_profile(&profile),
        Err(Web3ContractError::InvalidBinding(_))
    ));
}

#[test]
fn identity_binding_signature_verifies() {
    verify_web3_identity_binding(&sample_binding()).unwrap();
}

#[test]
fn identity_binding_rejects_padded_chain_scope() {
    let mut binding = sample_binding();
    binding.certificate.chain_scope[0] = " eip155:8453".to_string();
    assert!(matches!(
        validate_web3_identity_binding(&binding),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("binding.chain_scope")
    ));
}

#[test]
fn anchor_inclusion_proof_verifies_receipt_and_merkle_root() {
    verify_anchor_inclusion_proof(&sample_anchor_inclusion_proof()).unwrap();
}

#[test]
fn oracle_evidence_requires_non_zero_denominator() {
    let mut evidence = sample_oracle_evidence();
    evidence.rate_denominator = 0;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(_))
    ));
}

#[test]
fn oracle_evidence_rejects_unknown_authority() {
    let mut evidence = sample_oracle_evidence();
    evidence.authority = "unknown_authority".to_string();
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(_))
    ));
}

#[test]
fn oracle_evidence_rejects_stale_cache_age() {
    let mut evidence = sample_oracle_evidence();
    evidence.cache_age_seconds = evidence.max_age_seconds + 1;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence is stale")
    ));
}

#[test]
fn oracle_evidence_rejects_converted_amount_mismatch() {
    let mut evidence = sample_oracle_evidence();
    evidence.converted_cost_units += 1;
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence converted_cost_units")
    ));
}

#[test]
fn oracle_evidence_rejects_currency_pair_mismatch() {
    let mut evidence = sample_oracle_evidence();
    evidence.quote = "EUR".to_string();
    assert!(matches!(
        validate_oracle_conversion_evidence(&evidence),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("oracle conversion evidence quote must match grant_currency")
    ));
}

#[test]
fn web3_chain_configuration_rejects_placeholder_addresses() {
    for address in [
        "0x0000000000000000000000000000000000000000",
        "0x1111111111111111111111111111111111111111",
        "0x1000000000000000000000000000000000000001",
        "0x2000000000000000000000000000000000000005",
        "0xnot-a-valid-address",
        "0x1234",
    ] {
        let mut configuration = sample_chain_configuration();
        configuration.deployments[0].root_registry_address = address.to_string();
        assert!(matches!(
            validate_web3_chain_configuration(&configuration),
            Err(Web3ContractError::InvalidBinding(message))
                if message.contains("web3_chain_configuration.deployments.root_registry_address")
        ));
    }
}

#[test]
fn web3_dispatch_requires_web3_rail_kind() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.rail.kind = CapitalExecutionRailKind::Api;
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn web3_dispatch_rejects_lowercase_settlement_currency() {
    let mut dispatch = sample_dispatch();
    dispatch.settlement_amount.currency = "usd".to_string();
    dispatch
        .capital_instruction
        .body
        .amount
        .as_mut()
        .unwrap()
        .currency = "usd".to_string();

    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("currency")
    ));
}

#[test]
fn web3_dispatch_requires_completion_flow_binding_for_transfers() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.completion_flow_row_id = None;
    resign_dispatch_capital_instruction(&mut dispatch);
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.completion_flow_row_id"
        ))
    ));
}

#[test]
fn web3_dispatch_rejects_mismatched_completion_flow_binding() {
    let mut dispatch = sample_dispatch();
    dispatch.capital_instruction.body.completion_flow_row_id =
        Some("economic-completion-flow:other-receipt".to_string());
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn merkle_settlement_receipt_requires_anchor_proof() {
    let mut receipt = sample_execution_receipt();
    receipt.reconciled_anchor_proof = None;
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn merkle_settlement_receipt_rejects_tampered_anchor_signature() {
    let mut receipt = sample_execution_receipt();
    let Some(anchor_proof) = receipt.reconciled_anchor_proof.as_mut() else {
        panic!("sample execution receipt has anchor proof");
    };
    anchor_proof.checkpoint_statement.signature = Signature::from_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("checkpoint statement signature verification failed")
    ));
}

#[test]
fn fx_sensitive_settlement_receipt_requires_oracle_evidence() {
    let mut receipt = sample_execution_receipt();
    receipt.oracle_evidence = None;
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
}

#[test]
fn settlement_receipt_rejects_oracle_grant_currency_mismatch() {
    let mut receipt = sample_execution_receipt();
    let oracle_evidence = receipt.oracle_evidence.as_mut().unwrap();
    oracle_evidence.quote = "EUR".to_string();
    oracle_evidence.grant_currency = "EUR".to_string();
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("oracle conversion grant_currency must match settlement currency")
    ));
}

#[test]
fn public_settlement_proof_emits_verifier_report() {
    let bundle = sample_public_settlement_proof_bundle();
    let report = verify_public_settlement_proof(&bundle).unwrap();

    assert_eq!(report.schema, CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA);
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.bundle_id, bundle.bundle_id);
    assert_eq!(report.chain_context.chain_id, "eip155:8453");
    assert_eq!(
        report.chain_context.bond_vault_contract,
        "0x1000000000000000000000000000000000000003"
    );
    assert_eq!(report.chain_context.posted_bond_amount.units, 150);
    assert_eq!(report.chain_context.minimum_bond_amount.units, 150);
    assert_eq!(
        report.chain_context.block_hash,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        report.chain_context.anchor_tx_hash,
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        report.chain_context.settlement_tx_hash,
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    let beneficiary_binding = sample_beneficiary_binding();
    assert_eq!(
        report.chain_context.beneficiary_address,
        beneficiary_binding.certificate.settlement_address
    );
    assert_eq!(
        report.chain_context.beneficiary_chio_identity,
        beneficiary_binding.certificate.chio_identity
    );
    assert_eq!(report.finality_decision.status, "final");
    assert_eq!(report.recomputed_settlement_state, "settled");
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND.to_string()));
}

#[test]
fn public_settlement_proof_rejects_wrong_chain_id() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.chain_id = "eip155:42161".to_string();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("settlement chain id mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_tampered_capital_instruction_signature() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .counterparty_id = "subject-tampered".to_string();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("capital instruction signature verification failed")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_commerce_order_binding() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.commerce_order_id.clear();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::MissingField(
            "public_settlement.commerce_order_id"
        ))
    ));
}

#[test]
fn public_settlement_proof_rejects_mismatched_commerce_order_evidence_ref() {
    let bundle = sample_public_settlement_proof_bundle_with_order_ref("order-public-settlement-2");

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement commerce order evidence mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_finality_below_threshold() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.observed_confirmations = 19;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("settlement finality below threshold")
    ));
}

#[test]
fn public_settlement_proof_rejects_inflated_observed_confirmations() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.observed_confirmations = 25;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement observed confirmations exceed chain snapshot")
    ));
}

#[test]
fn public_settlement_proof_rejects_stale_chain_snapshot() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["latest_block_number"] = json!(12_345_900);
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement chain snapshot is stale")
    ));
}

#[test]
fn public_settlement_proof_rejects_wrong_registry_root() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["registry_root"] =
            json!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement registry root mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_escrow_balance_below_required_amount() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["escrow"]["locked_amount"]["units"] = json!(149);
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement escrow balance below required amount")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_block_snapshot() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let Some(chain_snapshot) = bundle["chain_snapshot"].as_object_mut() else {
            panic!("sample public settlement chain snapshot is an object");
        };
        chain_snapshot.remove("block");
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement block snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_settlement_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement tx hash not included in block")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_event_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] =
            json!(["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]);
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event tx hash not included in block")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_beneficiary_identity_binding() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let Some(chain_snapshot) = bundle["chain_snapshot"].as_object_mut() else {
            panic!("sample public settlement chain snapshot is an object");
        };
        chain_snapshot.remove("beneficiary_identity_binding");
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement beneficiary identity binding missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_dispute_snapshot() {
    let Ok(mut bundle) = serde_json::to_value(sample_public_settlement_proof_bundle()) else {
        panic!("sample public settlement proof bundle serializes");
    };
    let Some(bundle_object) = bundle.as_object_mut() else {
        panic!("sample public settlement proof bundle is an object");
    };
    bundle_object.remove("dispute_snapshot");
    let Ok(bundle) = serde_json::from_value(bundle) else {
        panic!("sample public settlement proof bundle parses");
    };

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_beneficiary_identity_address_mismatch() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let wrong_binding = signed_identity_binding(
            beneficiary_keypair(),
            "0x3333333333333333333333333333333333333333",
            vec![Web3KeyBindingPurpose::Settle],
            vec!["eip155:8453"],
            "beneficiary-identity-binding-wrong-address",
        );
        let Ok(binding) = serde_json::to_value(wrong_binding) else {
            panic!("sample beneficiary identity binding serializes");
        };
        bundle["chain_snapshot"]["beneficiary_identity_binding"] = binding;
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("public settlement beneficiary identity binding address mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_beneficiary_binding_issued_after_execution() {
    let mut bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        let binding = signed_identity_binding_with_window(
            beneficiary_keypair(),
            "0x2222222222222222222222222222222222222222",
            vec![Web3KeyBindingPurpose::Settle],
            vec!["eip155:8453"],
            "beneficiary-identity-binding-after-execution",
            1_743_292_890,
            1_743_296_460,
        );
        let Ok(binding) = serde_json::to_value(binding) else {
            panic!("sample beneficiary identity binding serializes");
        };
        bundle["chain_snapshot"]["beneficiary_identity_binding"] = binding;
    });
    bundle.settlement_receipt.issued_at =
        bundle.settlement_receipt.observed_execution.observed_at + 60;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidBinding(message))
            if message.contains("public settlement beneficiary identity binding not valid at settlement time")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_bond_snapshot() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.chain_snapshot.bond = None;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement bond snapshot missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_bond_below_policy() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["bond"]["posted_amount"]["units"] = json!(149);
    });

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement bond below policy")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_oracle_evidence() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.oracle_evidence = None;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("receipt requires oracle_evidence")
    ));
}

#[test]
fn public_settlement_proof_rejects_observed_execution_outside_dispatch_window() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.observed_execution.observed_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("observed execution timestamp falls outside dispatch execution window")
    ));
}

#[test]
fn public_settlement_proof_rejects_failed_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Failed;
    bundle.settlement_receipt.failure_reason = Some("provider execution failed".to_string());

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_reorged_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reorged;
    bundle.settlement_receipt.failure_reason = Some("settlement transaction reorged".to_string());

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_missing_observed_execution_reference() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id
        .clear();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::MissingField(
            "web3_settlement_receipt.observed_execution.external_reference_id"
        ))
    ));
}

#[test]
fn public_settlement_proof_rejects_malformed_observed_execution_tx_hash() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id = "settlement-web3-reference".to_string();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("observed execution reference must be an eip155 transaction hash")
    ));
}

#[test]
fn public_settlement_proof_rejects_finality_with_active_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Challenged;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Challenged;
    dispute_snapshot.dispute_id = "dispute-public-settlement-challenged".to_string();
    dispute_snapshot.open_dispute_count = 1;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_closed_posture_with_open_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Closed;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Closed;
    dispute_snapshot.dispute_id = "dispute-public-settlement-closed".to_string();
    dispute_snapshot.open_dispute_count = 1;

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_refunded_posture_without_reversal() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();

    assert!(matches!(
        verify_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("refunded dispute posture requires reversed or timed out settlement")
    ));
}

#[test]
fn public_settlement_proof_reports_refunded_reversal_status() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reversed;
    bundle.settlement_receipt.reversal_of = Some("receipt-web3-original".to_string());
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();

    let report = verify_public_settlement_proof(&bundle).unwrap();

    assert_eq!(report.finality_decision.status, "refunded");
    assert_eq!(report.recomputed_settlement_state, "reversed");
    assert_eq!(
        report.dispute_posture,
        PublicSettlementDisputePosture::Refunded
    );
}

#[test]
fn invalid_settlement_constructor_preserves_message() {
    let error = Web3ContractError::invalid_settlement("settlement amount must match");
    assert!(matches!(
        error,
        Web3ContractError::InvalidSettlement(message)
            if message == "settlement amount must match"
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let trust_profile: Web3TrustProfile = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_TRUST_PROFILE.json"
    ))
    .unwrap();
    let contract_package: Web3ContractPackage = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
    ))
    .unwrap();
    let chain_configuration: Web3ChainConfiguration = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap();
    let anchor_proof: AnchorInclusionProof = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))
    .unwrap();
    let dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .unwrap();
    let receipt: Web3SettlementExecutionReceiptArtifact = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"
    ))
    .unwrap();
    let matrix: Web3QualificationMatrix = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json"
    ))
    .unwrap();

    validate_web3_trust_profile(&trust_profile).unwrap();
    verify_web3_identity_binding(&trust_profile.operator_binding).unwrap();
    validate_web3_contract_package(&contract_package).unwrap();
    validate_web3_chain_configuration(&chain_configuration).unwrap();
    validate_anchor_inclusion_proof(&anchor_proof).unwrap();
    verify_anchor_inclusion_proof(&anchor_proof).unwrap();
    validate_web3_settlement_dispatch(&dispatch).unwrap();
    validate_web3_settlement_execution_receipt(&receipt).unwrap();
    validate_web3_qualification_matrix(&matrix).unwrap();
}
