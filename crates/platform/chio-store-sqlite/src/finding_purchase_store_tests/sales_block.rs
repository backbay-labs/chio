use super::*;

#[test]
fn sales_block_atomically_rejects_new_reservations_but_preserves_exact_replay() {
    let fixture = fixture();
    let existing = Purchase::new("pre-block", LISTING_ID, 100);
    assert_eq!(
        open_reservation(&fixture, &existing),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .block_new_slots(LISTING_ID, NOW + 1)
            .expect("block listing sales"),
        FindingPurchaseWriteOutcome::Inserted
    );

    assert_eq!(
        fixture
            .store
            .open_reservation(&existing.input(&fixture.allocation_id))
            .expect("recover exact reservation after block"),
        FindingPurchaseWriteOutcome::ExistingSame
    );

    let rejected = Purchase::new("post-block", LISTING_ID, 100);
    let result = fixture
        .store
        .open_reservation(&rejected.input(&fixture.allocation_id));
    assert!(matches!(
        result,
        Err(FindingPurchaseStoreError::Conflict(ref detail))
            if detail.contains("sales are blocked")
    ));
    assert!(fixture
        .store
        .get_reservation(&rejected.reservation_id)
        .expect("read rejected reservation")
        .is_none());
    assert!(fixture
        .store
        .get_encumbrance(&rejected.reservation_id)
        .expect("read rejected encumbrance")
        .is_none());
}
