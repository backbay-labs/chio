use crate::error::Web3ContractError;
use crate::settlement::validate_web3_settlement_dispatch;
use serde_json::json;

use super::tests::{
    resign_dispatch_capital_instruction, sample_dispatch,
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
