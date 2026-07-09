use alloy_primitives::keccak256;

use crate::anchors::validate_anchor_inclusion_proof;
use crate::canonical::canonical_json_bytes;
use crate::error::Web3ContractError;
use crate::hashing::Hash;
use crate::settlement::Web3SettlementLifecycleState;
use crate::settlement_proof::{
    verify_public_settlement_proof, PublicSettlementBlockSnapshot, PublicSettlementDisputePosture,
    PublicSettlementProofBundle, PublicSettlementRefundEvent, PublicSettlementRefundEventLog,
    PublicSettlementReleaseEvent, PublicSettlementReleaseEventKind,
    PublicSettlementReleaseEventLog,
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

fn bind_observed_settlement_tx(bundle: &mut PublicSettlementProofBundle, tx_hash: &str) {
    bundle.order_binding.settlement_tx_hash = tx_hash.to_string();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id = tx_hash.to_string();
}

fn sample_refund_event_log(
    bundle: &PublicSettlementProofBundle,
    block: &PublicSettlementBlockSnapshot,
    refund_tx_hash: &str,
) -> PublicSettlementRefundEventLog {
    PublicSettlementRefundEventLog {
        contract_address: bundle.chain_snapshot.escrow.escrow_contract.clone(),
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash: refund_tx_hash.to_string(),
        amount: bundle.settlement_receipt.settled_amount.clone(),
        block_number: block.block_number,
        block_hash: block.block_hash.clone(),
        log_index: 0,
    }
}

fn sample_release_event_block() -> PublicSettlementBlockSnapshot {
    PublicSettlementBlockSnapshot {
        block_number: 12_345_679,
        block_hash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_string(),
        transaction_hashes: vec![
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ],
    }
}

fn anchored_receipt_hash(bundle: &crate::settlement_proof::PublicSettlementProofBundle) -> String {
    let anchor_proof = bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .expect("sample proof has reconciled anchor proof");
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .expect("anchored receipt body canonicalizes");
    let receipt_hash = keccak256(receipt_bytes);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(receipt_hash.as_slice());
    Hash::from_bytes(bytes).to_hex_prefixed()
}

fn sample_release_event_log(
    bundle: &crate::settlement_proof::PublicSettlementProofBundle,
    event_block: &PublicSettlementBlockSnapshot,
) -> PublicSettlementReleaseEventLog {
    let partial =
        bundle.settlement_receipt.lifecycle_state == Web3SettlementLifecycleState::PartiallySettled;
    PublicSettlementReleaseEventLog {
        contract_address: bundle.chain_snapshot.escrow.escrow_contract.clone(),
        event: if partial {
            PublicSettlementReleaseEventKind::EscrowPartialRelease
        } else {
            PublicSettlementReleaseEventKind::EscrowReleased
        },
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        release_tx_hash: bundle
            .settlement_receipt
            .observed_execution
            .external_reference_id
            .clone(),
        receipt_hash: anchored_receipt_hash(bundle),
        amount: bundle.settlement_receipt.settled_amount.clone(),
        remaining_amount: partial.then(|| crate::capability::scope::MonetaryAmount {
            units: bundle.chain_snapshot.escrow.locked_amount.units
                - bundle.chain_snapshot.escrow.released_amount.units,
            currency: bundle.chain_snapshot.escrow.locked_amount.currency.clone(),
        }),
        block_number: event_block.block_number,
        block_hash: event_block.block_hash.clone(),
        log_index: 0,
    }
}

fn make_later_partial_release_bundle(
    with_release_event: bool,
) -> (
    crate::settlement_proof::PublicSettlementProofBundle,
    PublicSettlementBlockSnapshot,
    PublicSettlementReleaseEventLog,
) {
    let mut bundle = sample_public_settlement_proof_bundle();
    let release_block = sample_release_event_block();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::PartiallySettled;
    bundle.settlement_receipt.settled_amount.units = 30;
    bundle.settlement_receipt.observed_execution.amount.units = 30;
    bundle.chain_snapshot.escrow.released_amount.units = 50;
    if with_release_event {
        bundle.chain_snapshot.escrow.release_event = Some(PublicSettlementReleaseEvent {
            escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
            release_tx_hash: bundle
                .settlement_receipt
                .observed_execution
                .external_reference_id
                .clone(),
            receipt_hash: anchored_receipt_hash(&bundle),
            amount: bundle.settlement_receipt.settled_amount.clone(),
            remaining_amount: Some(crate::capability::scope::MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            partial: true,
            block: release_block.clone(),
        });
    }
    let release_log = sample_release_event_log(&bundle, &release_block);
    (bundle, release_block, release_log)
}

fn verify_sample_public_settlement_proof_with_release_event_evidence(
    bundle: &crate::settlement_proof::PublicSettlementProofBundle,
    event_block: PublicSettlementBlockSnapshot,
    event_log: PublicSettlementReleaseEventLog,
) -> Result<crate::settlement_proof::PublicSettlementVerifierReport, Web3ContractError> {
    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_release_event_blocks = vec![event_block];
    trust.trusted_release_event_logs = vec![event_log];
    verify_public_settlement_proof(&signed_bundle, &trust)
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
fn public_settlement_proof_accepts_later_partial_release_with_release_event() {
    let (bundle, release_block, release_log) = make_later_partial_release_bundle(true);
    let report = verify_sample_public_settlement_proof_with_release_event_evidence(
        &bundle,
        release_block,
        release_log,
    )
    .unwrap();

    assert_eq!(report.finality_decision.status, "partially_settled");
    assert_eq!(report.recomputed_settlement_state, "partially_settled");
}

#[test]
fn public_settlement_proof_accepts_later_partial_release_at_exact_finality_threshold() {
    let (mut bundle, mut release_block, mut release_log) = make_later_partial_release_bundle(true);
    let exact_release_block = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(u64::from(bundle.required_confirmations))
        .saturating_add(1);
    release_block.block_number = exact_release_block;
    release_log.block_number = exact_release_block;
    bundle
        .chain_snapshot
        .escrow
        .release_event
        .as_mut()
        .expect("sample carries release event")
        .block
        .block_number = exact_release_block;

    verify_sample_public_settlement_proof_with_release_event_evidence(
        &bundle,
        release_block,
        release_log,
    )
    .unwrap();
}

#[test]
fn public_settlement_proof_rejects_later_partial_release_without_release_event() {
    let (mut bundle, release_block, release_log) = make_later_partial_release_bundle(false);
    sign_sample_public_settlement_bundle(&mut bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_release_event_blocks = vec![release_block];
    trust.trusted_release_event_logs = vec![release_log];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement escrow release event missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_partial_release_event_amount_mismatch() {
    let (mut bundle, release_block, release_log) = make_later_partial_release_bundle(true);
    bundle
        .chain_snapshot
        .escrow
        .release_event
        .as_mut()
        .expect("sample carries release event")
        .amount
        .units = 29;

    assert!(matches!(
        verify_sample_public_settlement_proof_with_release_event_evidence(
            &bundle,
            release_block,
            release_log,
        ),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement release event amount mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_partial_release_without_trusted_log() {
    let (mut bundle, release_block, _) = make_later_partial_release_bundle(true);
    sign_sample_public_settlement_bundle(&mut bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_release_event_blocks = vec![release_block];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("trusted release event log evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_partial_release_missing_remaining_amount() {
    let (mut bundle, release_block, release_log) = make_later_partial_release_bundle(true);
    bundle
        .chain_snapshot
        .escrow
        .release_event
        .as_mut()
        .expect("sample carries release event")
        .remaining_amount = None;

    assert!(matches!(
        verify_sample_public_settlement_proof_with_release_event_evidence(
            &bundle,
            release_block,
            release_log,
        ),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("partial release event remaining amount missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_partial_release_event_untrusted_block() {
    let (mut bundle, _, release_log) = make_later_partial_release_bundle(true);
    sign_sample_public_settlement_bundle(&mut bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_release_event_logs = vec![release_log];

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("trusted release event block")
    ));
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

#[test]
fn public_settlement_proof_accepts_refunded_timed_out_escrow_with_zero_released_amount() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let refund_tx_hash = sample_dispute_event_tx_hash();
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bind_observed_settlement_tx(&mut bundle, &refund_tx_hash);
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    bundle.chain_snapshot.escrow.refund_event = Some(PublicSettlementRefundEvent {
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash: refund_tx_hash.clone(),
        amount: bundle.settlement_receipt.settled_amount.clone(),
        block: event_block.clone(),
    });
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![refund_tx_hash.clone()];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block.clone()];
    trust.trusted_refund_event_logs = vec![sample_refund_event_log(
        &bundle,
        &event_block,
        &refund_tx_hash,
    )];
    trust.verifier_now_unix_seconds = Some(verifier_now);
    let report = verify_public_settlement_proof(&signed_bundle, &trust).unwrap();

    assert_eq!(report.finality_decision.status, "refunded");
    assert_eq!(report.recomputed_settlement_state, "timed_out");
}

#[test]
fn public_settlement_proof_rejects_timed_out_refund_tx_mismatch() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    bundle.chain_snapshot.escrow.refund_event = Some(PublicSettlementRefundEvent {
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash: sample_dispute_event_tx_hash(),
        amount: bundle.settlement_receipt.settled_amount.clone(),
        block: event_block.clone(),
    });
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![sample_dispute_event_tx_hash()];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    trust.verifier_now_unix_seconds = Some(verifier_now);

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("refund event tx hash mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_timed_out_refund_without_trusted_refund_log() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let refund_tx_hash = sample_dispute_event_tx_hash();
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bind_observed_settlement_tx(&mut bundle, &refund_tx_hash);
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    bundle.chain_snapshot.escrow.refund_event = Some(PublicSettlementRefundEvent {
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash: refund_tx_hash.clone(),
        amount: bundle.settlement_receipt.settled_amount.clone(),
        block: event_block.clone(),
    });
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![refund_tx_hash];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    trust.verifier_now_unix_seconds = Some(verifier_now);

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("trusted refund event log evidence missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_timed_out_refund_without_refund_event() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![sample_dispute_event_tx_hash()];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    trust.verifier_now_unix_seconds = Some(verifier_now);

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("refund event missing")
    ));
}

#[test]
fn public_settlement_proof_rejects_timed_out_refund_wrong_event_amount() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let refund_tx_hash = sample_dispute_event_tx_hash();
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bind_observed_settlement_tx(&mut bundle, &refund_tx_hash);
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    let mut wrong_amount = bundle.settlement_receipt.settled_amount.clone();
    wrong_amount.units -= 1;
    bundle.chain_snapshot.escrow.refund_event = Some(PublicSettlementRefundEvent {
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash: refund_tx_hash.clone(),
        amount: wrong_amount,
        block: event_block.clone(),
    });
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![refund_tx_hash];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    trust.verifier_now_unix_seconds = Some(verifier_now);

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("refund event amount mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_refund_event_not_declared_as_dispute_event() {
    let mut bundle = sample_public_settlement_proof_bundle();
    let event_block = sample_dispute_event_block();
    let refund_tx_hash =
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let refund_block = PublicSettlementBlockSnapshot {
        block_number: event_block.block_number + 1,
        block_hash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_string(),
        transaction_hashes: vec![refund_tx_hash.clone()],
    };
    let timeout_at = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .execution_window
        .not_after
        + 1;
    bind_observed_settlement_tx(&mut bundle, &refund_tx_hash);
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::TimedOut;
    bundle.settlement_receipt.failure_reason = Some("escrow refunded after deadline".to_string());
    bundle.settlement_receipt.observed_execution.observed_at = timeout_at;
    bundle.settlement_receipt.issued_at = timeout_at;
    bundle.chain_snapshot.escrow.released_amount.units = 0;
    bundle.chain_snapshot.escrow.refunded = true;
    bundle.chain_snapshot.escrow.refund_event = Some(PublicSettlementRefundEvent {
        escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
        refund_tx_hash,
        amount: bundle.settlement_receipt.settled_amount.clone(),
        block: refund_block,
    });
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-timeout-refund".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    dispute_snapshot.chain_event_tx_hashes = vec![sample_dispute_event_tx_hash()];
    dispute_snapshot.chain_event_blocks = vec![event_block.clone()];
    dispute_snapshot.challenge_window_secs = 600;
    dispute_snapshot.window_closed_at = timeout_at + dispute_snapshot.challenge_window_secs;
    dispute_snapshot.observed_at = dispute_snapshot.window_closed_at;
    let verifier_now = dispute_snapshot.observed_at + 1;

    let mut signed_bundle = bundle.clone();
    sign_sample_public_settlement_bundle(&mut signed_bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.trusted_dispute_event_blocks = vec![event_block];
    trust.verifier_now_unix_seconds = Some(verifier_now);

    assert!(matches!(
        verify_public_settlement_proof(&signed_bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("refund tx hash missing from dispute event evidence")
    ));
}
