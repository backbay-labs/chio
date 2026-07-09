use crate::error::Web3ContractError;
use crate::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementIdentityRegistryEvidenceBinding,
};
use crate::trust_profile::Web3SettlementPath;

use super::tests::{
    sample_execution_receipt, sample_identity_registry_evidence,
    sample_identity_registry_evidence_binding,
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

#[test]
fn dual_sign_settlement_receipt_rejects_registry_binding_mismatches() {
    let cases: [(&str, fn(&mut Web3SettlementIdentityRegistryEvidenceBinding)); 3] = [
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
