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

fn sample_binding() -> SignedWeb3IdentityBinding {
    let operator = operator_keypair();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", operator.public_key().to_hex()),
        chio_public_key: operator.public_key(),
        chain_scope: vec!["eip155:8453".to_string(), "eip155:42161".to_string()],
        purpose: vec![Web3KeyBindingPurpose::Anchor, Web3KeyBindingPurpose::Settle],
        settlement_address: "0x1111111111111111111111111111111111111111".to_string(),
        issued_at: 1_743_292_800,
        expires_at: 1_774_828_800,
        nonce: "0123456789abcdef0123456789abcdef".to_string(),
    };
    let (signature, _) = operator.sign_canonical(&certificate).unwrap();
    SignedWeb3IdentityBinding {
        certificate,
        signature,
    }
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
        original_cost_units: 100_000_000_000_000,
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
                CapitalExecutionAuthorityStep {
                    role: CapitalExecutionRole::OperatorTreasury,
                    principal_id: "treasury-1".to_string(),
                    approved_at: 1_743_292_790,
                    expires_at: 1_743_293_800,
                    note: Some("governed release".to_string()),
                },
                CapitalExecutionAuthorityStep {
                    role: CapitalExecutionRole::Custodian,
                    principal_id: "custodian-base-main".to_string(),
                    approved_at: 1_743_292_795,
                    expires_at: 1_743_293_800,
                    note: Some("official web3 stack".to_string()),
                },
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 1_743_292_800,
                not_after: 1_743_293_800,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Web3,
                rail_id: "base-mainnet-usdc".to_string(),
                custody_provider_id: "custodian-base-main".to_string(),
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
            evidence_refs: vec![CapitalBookEvidenceReference {
                kind: CapitalBookEvidenceKind::Receipt,
                reference_id: "rcpt-web3-1".to_string(),
                observed_at: Some(1_743_292_800),
                locator: Some("receipt:rcpt-web3-1".to_string()),
            }],
            description: "release escrow over the official web3 rail".to_string(),
        },
        &signer,
    )
    .unwrap()
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
fn fx_sensitive_settlement_receipt_requires_oracle_evidence() {
    let mut receipt = sample_execution_receipt();
    receipt.oracle_evidence = None;
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(_))
    ));
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
        "../../../docs/standards/CHIO_WEB3_TRUST_PROFILE.json"
    ))
    .unwrap();
    let contract_package: Web3ContractPackage = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
    ))
    .unwrap();
    let chain_configuration: Web3ChainConfiguration = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
    ))
    .unwrap();
    let anchor_proof: AnchorInclusionProof = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))
    .unwrap();
    let dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .unwrap();
    let receipt: Web3SettlementExecutionReceiptArtifact = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"
    ))
    .unwrap();
    let matrix: Web3QualificationMatrix = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json"
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
