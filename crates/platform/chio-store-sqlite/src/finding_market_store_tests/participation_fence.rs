use super::*;

pub(super) fn activate_participation_admission(
    fixture: &Fixture,
    finding_id: &str,
) -> (FindingAdmission, String) {
    let artifact = publish_finding(
        &fixture.store,
        finding_id,
        "regression/participation-fence",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    let backing = backing_body(finding_id, "vault:participation-fence");
    let backing_envelope = envelope_string(&backing, &keypair(21));
    let backing_sha256 = chio_core::sha256_hex(backing_envelope.as_bytes());
    fixture
        .store
        .register_allocation(&backing_envelope, &backing, NOW)
        .expect("register participation-fenced allocation");
    let publication = begin_intent(
        &fixture.store,
        &FindingFeeEvent::Publication,
        finding_id,
        5,
        &hex64('6'),
    );
    let epoch_zero = begin_intent(
        &fixture.store,
        &FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
        finding_id,
        3,
        &hex64('8'),
    );
    reconcile(&fixture.store, &publication.idempotency_key, &hex64('7'), 5)
        .expect("reconcile participation publication fee");
    reconcile(&fixture.store, &epoch_zero.idempotency_key, &hex64('9'), 3)
        .expect("reconcile participation epoch zero");
    let admission = admission_body(
        finding_id,
        &chio_core::sha256_hex(artifact.as_bytes()),
        &backing,
        &backing_sha256,
    );
    let envelope = envelope_string(&admission, &keypair(31));
    fixture
        .store
        .prepare_listing_activation_without_status_for_test(&envelope, &admission, NOW)
        .expect("prepare participation-fenced admission");
    fixture
        .store
        .activate_listing(&envelope, &admission, NOW)
        .expect("activate participation-fenced admission");
    (admission, envelope)
}

#[test]
fn participation_fee_intent_rejects_a_superseded_admission_snapshot() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let (first_admission, first_envelope) = activate_participation_admission(&fixture, &finding_id);
    install_status(&fixture, &finding_id, FindingStatusProofKind::NonInclusion);

    let second_backing = backing_body(&finding_id, "vault:participation-fence-2");
    let second_backing_envelope = envelope_string(&second_backing, &keypair(21));
    let second_backing_sha256 = chio_core::sha256_hex(second_backing_envelope.as_bytes());
    fixture
        .store
        .register_allocation(&second_backing_envelope, &second_backing, NOW + 1)
        .expect("register superseding participation allocation");
    let artifact = fixture
        .store
        .get_finding_bytes(&finding_id)
        .expect("read participation finding")
        .expect("participation finding exists");
    let second_admission = admission_body(
        &finding_id,
        &chio_core::sha256_hex(artifact.as_bytes()),
        &second_backing,
        &second_backing_sha256,
    );
    let second_envelope = envelope_string(&second_admission, &keypair(31));
    fixture
        .store
        .prepare_listing_activation_without_status_for_test(
            &second_envelope,
            &second_admission,
            NOW + 2,
        )
        .expect("prepare superseding participation admission");
    fixture
        .store
        .activate_listing(&second_envelope, &second_admission, NOW + 2)
        .expect("activate superseding participation admission");

    let event = FindingFeeEvent::ParticipationEpoch { epoch_index: 1 };
    let amount = usd(3);
    let instruction_sha256 = hex64('8');
    let schedule_sha256 = hex64('5');
    let intent = FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule_sha256,
        event: &event,
        finding_id: &finding_id,
        listing_id: LISTING_ID,
        payer: "venue-operator",
        amount: &amount,
        pool_principal_id: "pool:audit",
        rail_destination: "rail:venue-ledger:audit-pool",
        instruction_sha256: &instruction_sha256,
    };
    let first_envelope_sha256 = chio_core::sha256_hex(first_envelope.as_bytes());
    let rejected = fixture.store.begin_live_participation_fee_intent(
        &intent,
        &FindingParticipationAdmissionFence {
            admission_id: &first_admission.admission_id,
            admission_envelope_sha256: &first_envelope_sha256,
        },
        STATUS_FEED,
        STATUS_AUTHORIZATION_SHA256,
        NOW,
        NOW + 2,
        300,
    );
    assert!(matches!(
        rejected,
        Err(FindingMarketStoreError::Conflict(ref detail))
            if detail.contains("current admission changed")
    ));
    let key = finding_fee_idempotency_key(&schedule_sha256, &event, &finding_id, LISTING_ID);
    assert!(fixture
        .store
        .get_fee_event(&key)
        .expect("read superseded-admission renewal")
        .is_none());
}
