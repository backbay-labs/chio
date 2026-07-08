use crate::anchors::validate_anchor_inclusion_proof;
use crate::error::Web3ContractError;
use crate::settlement::Web3SettlementLifecycleState;
use crate::settlement_proof::{
    verify_public_settlement_proof, PublicSettlementBlockSnapshot, PublicSettlementDisputePosture,
};
use serde_json::json;

use super::tests::{
    sample_anchor_inclusion_proof, sample_public_settlement_proof_bundle,
    sample_public_settlement_proof_bundle_with_chain_snapshot,
    sample_public_settlement_verifier_trust, sign_sample_public_settlement_bundle,
    verify_sample_public_settlement_proof,
};

fn sample_dispute_event_tx_hash() -> String {
    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string()
}

fn sample_dispute_event_block() -> PublicSettlementBlockSnapshot {
    PublicSettlementBlockSnapshot {
        block_number: 12_345_679,
        block_hash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .to_string(),
        transaction_hashes: vec![sample_dispute_event_tx_hash()],
    }
}

#[test]
fn anchor_inclusion_proof_accepts_operator_address_case_mismatch() {
    let mut proof = sample_anchor_inclusion_proof();
    let Some(chain_anchor) = proof.chain_anchor.as_mut() else {
        panic!("sample anchor inclusion proof has chain anchor");
    };
    chain_anchor.operator_address = "0x735f1ba389d9d350501db8fbbb5b52477dcadda8".to_string();
    proof.key_binding_certificate.certificate.settlement_address =
        "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();

    validate_anchor_inclusion_proof(&proof).unwrap();
}

#[test]
fn public_settlement_proof_rejects_malformed_dispute_event_tx_hash() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] = json!(["not-a-tx-hash"]);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(_))
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_event_without_block_evidence() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] =
            json!(["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event block evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_resolved_dispute_without_event_evidence() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reversed;
    bundle.settlement_receipt.reversal_of = Some("receipt-web3-original".to_string());
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_slashed_dispute_without_event_evidence() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Slashed;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::ChargedBack;
    bundle.settlement_receipt.reversal_of = Some("receipt-web3-original".to_string());
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Slashed;
    dispute_snapshot.dispute_id = "dispute-public-settlement-slashed".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_closed_dispute_without_event_evidence() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Closed;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Closed;
    dispute_snapshot.dispute_id = "dispute-public-settlement-closed".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_event_without_trusted_block_evidence() {
    let event_block = sample_dispute_event_block();
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] =
            json!([sample_dispute_event_tx_hash()]);
        bundle["dispute_snapshot"]["chain_event_blocks"] = json!([event_block]);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event trusted block evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_event_missing_from_event_block() {
    let trusted_event_block = sample_dispute_event_block();
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["chain_event_tx_hashes"] =
            json!([sample_dispute_event_tx_hash()]);
        bundle["dispute_snapshot"]["chain_event_blocks"] = json!([{
            "block_number": 12_345_679_u64,
            "block_hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "transaction_hashes": [
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ]
        }]);
    });
    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![trusted_event_block];

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute event tx hash not included in event block")
    ));
}

#[test]
fn public_settlement_proof_reports_refunded_reversal_status() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reversed;
    bundle.settlement_receipt.reversal_of = Some("receipt-web3-original".to_string());
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![sample_dispute_event_tx_hash()];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    let report = verify_public_settlement_proof(&signed_bundle, &trust).unwrap();

    assert_eq!(report.finality_decision.status, "refunded");
    assert_eq!(report.recomputed_settlement_state, "reversed");
    assert_eq!(
        report.dispute_posture,
        PublicSettlementDisputePosture::Refunded
    );
}
