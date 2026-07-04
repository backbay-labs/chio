use crate::error::Web3ContractError;
use crate::settlement::validate_web3_settlement_dispatch;
use serde_json::json;

use super::tests::{
    resign_dispatch_capital_instruction, sample_beneficiary_binding_for_address, sample_dispatch,
    sample_public_settlement_proof_bundle_with_chain_snapshot,
    verify_sample_public_settlement_proof,
};

#[test]
fn web3_dispatch_rejects_beneficiary_outside_signed_rail() {
    let mut dispatch = sample_dispatch();
    dispatch.beneficiary_address = "0x3333333333333333333333333333333333333333".to_string();
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("beneficiary_address must match")
    ));

    dispatch = sample_dispatch();
    dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = None;
    resign_dispatch_capital_instruction(&mut dispatch);
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.rail.destination_account_ref"
        ))
    ));
}

#[test]
fn web3_dispatch_accepts_equivalent_mixed_case_signed_rail_beneficiary() {
    let mut dispatch = sample_dispatch();
    dispatch.beneficiary_address = "0x1234567890ABCDEF1234567890ABCDEF12345678".to_string();
    dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = Some("0x1234567890abcdef1234567890abcdef12345678".to_string());
    resign_dispatch_capital_instruction(&mut dispatch);

    assert!(validate_web3_settlement_dispatch(&dispatch).is_ok());
}

#[test]
fn public_settlement_proof_accepts_settlement_tx_after_anchor_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    });
    assert!(verify_sample_public_settlement_proof(&bundle).is_ok());
}

#[test]
fn public_settlement_proof_rejects_anchor_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]);
    });
    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement anchor tx hash missing from block")
    ));
}

#[test]
fn public_settlement_proof_accepts_equivalent_mixed_case_evm_addresses() {
    let mut bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["deployment_provenance"]["root_registry_address"] =
            json!("0x1234567890ABCDEF1234567890ABCDEF12345678");
        bundle["deployment_provenance"]["escrow_contract"] =
            json!("0x2234567890ABCDEF1234567890ABCDEF12345678");
        bundle["deployment_provenance"]["bond_vault_contract"] =
            json!("0x3234567890ABCDEF1234567890ABCDEF12345678");
        bundle["settlement_receipt"]["dispatch"]["escrow_contract"] =
            json!("0x2234567890abcdef1234567890abcdef12345678");
        bundle["settlement_receipt"]["dispatch"]["bond_vault_contract"] =
            json!("0x3234567890abcdef1234567890abcdef12345678");
        bundle["settlement_receipt"]["reconciled_anchor_proof"]["chain_anchor"]
            ["contract_address"] = json!("0x1234567890abcdef1234567890abcdef12345678");
        bundle["chain_snapshot"]["root_registry_address"] =
            json!("0x1234567890abcdef1234567890abcdef12345678");
        bundle["chain_snapshot"]["escrow"]["escrow_contract"] =
            json!("0x2234567890ABCDEF1234567890ABCDEF12345678");
        bundle["chain_snapshot"]["bond"]["bond_vault_contract"] =
            json!("0x3234567890ABCDEF1234567890ABCDEF12345678");
    });
    bundle.settlement_receipt.dispatch.beneficiary_address =
        "0x4234567890ABCDEF1234567890ABCDEF12345678".to_string();
    bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = Some("0x4234567890abcdef1234567890abcdef12345678".to_string());
    resign_dispatch_capital_instruction(&mut bundle.settlement_receipt.dispatch);
    bundle.order_binding.beneficiary_address =
        "0x4234567890abcdef1234567890abcdef12345678".to_string();
    bundle.chain_snapshot.escrow.beneficiary_address =
        "0x4234567890abcdef1234567890abcdef12345678".to_string();
    bundle.chain_snapshot.beneficiary_identity_binding = Some(
        sample_beneficiary_binding_for_address("0x4234567890abcdef1234567890abcdef12345678"),
    );

    assert!(verify_sample_public_settlement_proof(&bundle).is_ok());
}

#[test]
fn public_settlement_proof_rejects_different_evm_addresses_after_normalization() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["escrow"]["escrow_contract"] =
            json!("0x1000000000000000000000000000000000000004");
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement escrow contract mismatch")
    ));
}
