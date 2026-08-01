use crate::error::Web3ContractError;
use crate::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementIdentityRegistryEvidenceBinding,
};
use crate::trust_profile::Web3SettlementPath;

use super::settlement_proof::public_settlement_witness_body_hash;
use super::tests::{
    sample_execution_receipt, sample_identity_registry_evidence,
    sample_identity_registry_evidence_binding, sample_public_settlement_proof_bundle,
    verify_sample_public_settlement_proof,
};

#[test]
fn dual_sign_settlement_receipt_requires_registry_evidence() {
    let mut receipt = sample_execution_receipt();
    receipt.dispatch.settlement_path = Web3SettlementPath::DualSignature;
    receipt.dispatch.support_boundary.anchor_proof_required = false;
    receipt.reconciled_anchor_proof = None;

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("identity_registry_evidence")
    ));
}

#[test]
fn dual_sign_settlement_receipt_rejects_registry_key_hash_mismatch() {
    let mut receipt = sample_execution_receipt();
    receipt.dispatch.settlement_path = Web3SettlementPath::DualSignature;
    receipt.dispatch.support_boundary.anchor_proof_required = false;
    receipt.reconciled_anchor_proof = None;
    let mut evidence = sample_identity_registry_evidence();
    evidence.operator_key_hash =
        "0x8888888888888888888888888888888888888888888888888888888888888888".to_string();
    receipt.identity_registry_evidence = Some(evidence);

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("operator_key_hash")
    ));
}

#[test]
fn dual_sign_settlement_receipt_requires_registry_evidence_binding() {
    let mut receipt = sample_execution_receipt();
    receipt.dispatch.settlement_path = Web3SettlementPath::DualSignature;
    receipt.dispatch.support_boundary.anchor_proof_required = false;
    receipt.reconciled_anchor_proof = None;
    receipt.identity_registry_evidence = Some(sample_identity_registry_evidence());

    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("identity_registry_evidence_binding")
    ));
}

#[test]
fn dual_sign_settlement_receipt_accepts_registry_evidence() {
    let mut receipt = sample_execution_receipt();
    receipt.dispatch.settlement_path = Web3SettlementPath::DualSignature;
    receipt.dispatch.support_boundary.anchor_proof_required = false;
    receipt.reconciled_anchor_proof = None;
    receipt.identity_registry_evidence = Some(sample_identity_registry_evidence());
    receipt.identity_registry_evidence_binding = Some(sample_identity_registry_evidence_binding());

    validate_web3_settlement_execution_receipt(&receipt).unwrap();
}

type RegistryBindingMutation = fn(&mut Web3SettlementIdentityRegistryEvidenceBinding);

#[test]
fn dual_sign_settlement_receipt_rejects_registry_binding_mismatches() {
    let cases: [(&str, RegistryBindingMutation); 3] = [
        (
            "contract",
            |binding: &mut Web3SettlementIdentityRegistryEvidenceBinding| {
                binding.identity_registry_contract =
                    "0x2000000000000000000000000000000000000004".to_string();
            },
        ),
        (
            "operator",
            |binding: &mut Web3SettlementIdentityRegistryEvidenceBinding| {
                binding.operator_address = "0x2000000000000000000000000000000000000001".to_string();
            },
        ),
        (
            "settlement_key",
            |binding: &mut Web3SettlementIdentityRegistryEvidenceBinding| {
                binding.settlement_key = "0x2000000000000000000000000000000000000001".to_string();
            },
        ),
    ];
    for (field, mutate) in cases {
        let mut receipt = sample_execution_receipt();
        receipt.dispatch.settlement_path = Web3SettlementPath::DualSignature;
        receipt.dispatch.support_boundary.anchor_proof_required = false;
        receipt.reconciled_anchor_proof = None;
        receipt.identity_registry_evidence = Some(sample_identity_registry_evidence());
        let mut binding = sample_identity_registry_evidence_binding();
        mutate(&mut binding);
        receipt.identity_registry_evidence_binding = Some(binding);

        assert!(
            matches!(
                validate_web3_settlement_execution_receipt(&receipt),
                Err(Web3ContractError::InvalidSettlement(message))
                    if message.contains("identity registry evidence")
            ),
            "expected {field} binding mismatch to fail"
        );
    }
}

#[test]
fn public_settlement_proof_binds_identity_registry_evidence_to_deployment_and_anchor() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.identity_registry_evidence =
        Some(sample_identity_registry_evidence());

    verify_sample_public_settlement_proof(&bundle).unwrap();

    let mut wrong_registry = bundle.clone();
    wrong_registry
        .settlement_receipt
        .identity_registry_evidence
        .as_mut()
        .expect("sample proof carries registry evidence")
        .identity_registry_contract = "0x2000000000000000000000000000000000000004".to_string();
    assert!(matches!(
        verify_sample_public_settlement_proof(&wrong_registry),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("identity registry evidence contract mismatch")
    ));

    let mut wrong_operator = bundle.clone();
    wrong_operator
        .settlement_receipt
        .identity_registry_evidence
        .as_mut()
        .expect("sample proof carries registry evidence")
        .operator_address = "0x2000000000000000000000000000000000000001".to_string();
    assert!(matches!(
        verify_sample_public_settlement_proof(&wrong_operator),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("identity registry evidence operator mismatch")
    ));

    let mut wrong_key = bundle.clone();
    wrong_key
        .settlement_receipt
        .identity_registry_evidence
        .as_mut()
        .expect("sample proof carries registry evidence")
        .operator_key_hash =
        "0x8888888888888888888888888888888888888888888888888888888888888888".to_string();
    assert!(matches!(
        verify_sample_public_settlement_proof(&wrong_key),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("operator_key_hash")
                || message.contains("identity registry evidence operator key mismatch")
    ));

    let mut wrong_settlement_key = bundle.clone();
    wrong_settlement_key
        .chain_snapshot
        .identity_registry_operator
        .as_mut()
        .expect("sample proof carries registry operator snapshot")
        .settlement_key = "0x2000000000000000000000000000000000000001".to_string();
    let witness = wrong_settlement_key
        .public_witness
        .as_mut()
        .expect("sample proof carries public witness");
    witness
        .identity_registry_operator
        .as_mut()
        .expect("sample proof witness carries registry operator snapshot")
        .settlement_key = "0x2000000000000000000000000000000000000001".to_string();
    witness.body_hash =
        public_settlement_witness_body_hash(witness).expect("sample witness body hashes");
    assert!(matches!(
        verify_sample_public_settlement_proof(&wrong_settlement_key),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("settlement key mismatch")
    ));

    let mut future_block = bundle;
    future_block
        .settlement_receipt
        .identity_registry_evidence
        .as_mut()
        .expect("sample proof carries registry evidence")
        .block_number = 12_345_679;
    assert!(matches!(
        verify_sample_public_settlement_proof(&future_block),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("block exceeds observed chain state")
                || message.contains("operator snapshot block mismatch")
    ));
}
