use super::*;

#[test]
fn public_purchase_output_bound_cannot_reject_a_kernel_captured_output() {
    assert_eq!(
        FINDING_PURCHASE_MAX_OUTPUT_BYTES,
        chio_kernel::tool_outcome::MAX_RAW_INVOCATION_OUTCOME_BYTES
    );
}

/// Terminal selection and realized spend come from the durable kernel
/// verdict and outcome, never from coordinator-call parameters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_finalization_uses_the_durable_verdict_and_capture() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-overspend-1", "nonce-overspend-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let purchase_store = lane.authority.finding_purchase_store();
    let allocation_id = lane.deployment.web.allocation_id.clone();
    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();
    purchase_store.register_community_fund_destination(
        &allocation_id,
        COMMUNITY_FUND_DESTINATION,
        now,
    )?;

    let mut future_body = response.receipt.body();
    future_body.timestamp = now.saturating_add(1);
    let future_receipt = ChioReceipt::sign(future_body, &keypair(40))?;
    assert!(matches!(
        lane.coordinator.finalize_delivery(
            &reservation_id,
            &future_receipt,
            &lane.deployment.web.admission,
            &lane.deployment.web.backing,
            now,
        ),
        Err(PurchaseCoordinatorError::TerminalEvidence(message))
            if message.contains("ahead of the finalization clock")
    ));

    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let refused = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    );
    assert!(matches!(
        refused,
        Err(PurchaseCoordinatorError::TerminalEvidence(_))
    ));

    // The refusal left the buyer payout unadmitted, kept the purchase slot
    // reserved, and wrote no terminal record. Buyer payout promotion belongs
    // to the same transaction as a valid settlement record.
    assert_eq!(
        purchase_store.list_payout_destinations(&allocation_id)?,
        vec![(0_u8, COMMUNITY_FUND_DESTINATION.to_string())]
    );
    let slot = purchase_store
        .get_slot(&reservation_id)?
        .ok_or_else(|| missing("slot after the refused settlement"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::Reserved);
    let purchase_key = derive_purchase_key(
        &lane.purchase.accepted_bid_envelope_sha256,
        &derive_payment_operation_id(&reservation_id),
    );
    assert!(purchase_store.get_purchase_record(&purchase_key)?.is_none());

    let record = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    verify_signed_purchase_record(&record, &keypair(16).public_key())?;
    assert_eq!(record.body.accepted_price, usd(PRICE_UNITS));
    assert_eq!(record.body.realized_spend, usd(PRICE_UNITS));
    assert!(purchase_store
        .get_purchase_record(&record.body.purchase_key)?
        .is_some());
    assert_eq!(
        purchase_store.list_payout_destinations(&allocation_id)?,
        vec![
            (0_u8, COMMUNITY_FUND_DESTINATION.to_string()),
            (1_u8, BUYER_PAYOUT.to_string()),
        ]
    );
    Ok(())
}
