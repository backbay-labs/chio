use super::*;

#[test]
fn sales_block_atomically_rejects_new_participation_intent_but_preserves_replay() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let (admission, admission_envelope) = activate_participation_admission(&fixture, &finding_id);
    let admission_envelope_sha256 = chio_core::sha256_hex(admission_envelope.as_bytes());
    let admission_fence = FindingParticipationAdmissionFence {
        admission_id: &admission.admission_id,
        admission_envelope_sha256: &admission_envelope_sha256,
    };
    install_status(&fixture, &finding_id, FindingStatusProofKind::NonInclusion);
    let amount = usd(3);
    let schedule_sha256 = hex64('5');
    let instruction_sha256 = hex64('8');
    let first_event = FindingFeeEvent::ParticipationEpoch { epoch_index: 1 };
    let first = FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule_sha256,
        event: &first_event,
        finding_id: &finding_id,
        listing_id: LISTING_ID,
        payer: "venue-operator",
        amount: &amount,
        pool_principal_id: "pool:audit",
        rail_destination: "rail:venue-ledger:audit-pool",
        instruction_sha256: &instruction_sha256,
    };
    assert_eq!(
        fixture
            .store
            .begin_live_participation_fee_intent(
                &first,
                &admission_fence,
                STATUS_FEED,
                STATUS_AUTHORIZATION_SHA256,
                NOW,
                NOW,
                300,
            )
            .expect("insert participation intent before block")
            .outcome,
        FindingFeeIntentOutcome::Inserted
    );
    fixture
        ._authority
        .finding_purchase_store()
        .block_new_slots(LISTING_ID, NOW + 1)
        .expect("block listing sales");
    assert_eq!(
        fixture
            .store
            .begin_live_participation_fee_intent(
                &first,
                &admission_fence,
                STATUS_FEED,
                STATUS_AUTHORIZATION_SHA256,
                NOW,
                NOW + 1,
                300,
            )
            .expect("recover exact participation intent after block")
            .outcome,
        FindingFeeIntentOutcome::ExistingIntent
    );

    let second_event = FindingFeeEvent::ParticipationEpoch { epoch_index: 2 };
    let second = FindingFeeIntent {
        event: &second_event,
        ..first
    };
    let rejected = fixture.store.begin_live_participation_fee_intent(
        &second,
        &admission_fence,
        STATUS_FEED,
        STATUS_AUTHORIZATION_SHA256,
        NOW,
        NOW + 1,
        300,
    );
    assert!(matches!(
        rejected,
        Err(FindingMarketStoreError::Conflict(ref detail))
            if detail.contains("sales are blocked")
    ));
    let rejected_key =
        finding_fee_idempotency_key(&schedule_sha256, &second_event, &finding_id, LISTING_ID);
    assert!(fixture
        .store
        .get_fee_event(&rejected_key)
        .expect("read rejected participation intent")
        .is_none());
}
