use std::fs;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_allocation_id, FindingBondBacking, FindingBondClass, FindingCollateralVault,
    FINDING_BOND_BACKING_SCHEMA_V1,
};
use tempfile::TempDir;

use super::*;
use crate::finding_market_store::{FindingRecordInput, SqliteFindingMarketStore};
use crate::SqliteAuthorityStore;

const LISTING_ID: &str = "purchase-listing-01";
const OTHER_LISTING_ID: &str = "purchase-listing-02";
const NOW: u64 = 1_750_000_000;
const EXPIRES_AT: u64 = NOW + 3_600;
const PAYOUT_DESTINATION: &str = "0x000000000000000000000000000000000000002a";
/// The exposure cap `backing_body` registers for every fixture allocation.
const REGISTERED_EXPOSURE_CAP: u64 = 450;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    market: SqliteFindingMarketStore,
    store: SqliteFindingPurchaseStore,
    allocation_id: String,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let market = authority.finding_market_store();
    let store = authority.finding_purchase_store();
    publish_finding(&market);
    let allocation_id = consume_allocation(&market, "vault:finding-collateral", LISTING_ID);
    install_active_admission(&store, &allocation_id, LISTING_ID, &hex64('d'), &hex64('c'));
    Fixture {
        _temp: temp,
        _authority: authority,
        market,
        store,
        allocation_id,
    }
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn hex64(character: char) -> String {
    character.to_string().repeat(64)
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn envelope_string<T: serde::Serialize + Clone>(body: &T, signer: &Keypair) -> String {
    let signed = SignedExportEnvelope::sign(body.clone(), signer).expect("sign envelope");
    String::from_utf8(canonical_json_bytes(&signed).expect("canonical envelope"))
        .expect("utf8 envelope")
}

fn publish_finding(market: &SqliteFindingMarketStore) {
    let finding_id = hex64('a');
    let artifact = format!("{{\"finding_id\":\"{finding_id}\"}}");
    market
        .put_finding(
            &FindingRecordInput {
                finding_id: &finding_id,
                artifact_json: &artifact,
                topic: "purchase-store-test",
                context_sha256: &hex64('0'),
                issued_at: 1_700_000_000,
                expires_at: 1_900_000_000,
            },
            NOW,
        )
        .expect("publish finding");
}

/// Purchase-store tests seed the sibling admission table directly because
/// their subject is the reservation transaction, not fee reconciliation or
/// admission-envelope validation. The helper still uses the serving-owner
/// write fence and synchronizes its authority anchor.
fn install_active_admission(
    store: &SqliteFindingPurchaseStore,
    allocation_id: &str,
    listing_id: &str,
    admission_id: &str,
    admission_envelope_sha256: &str,
) {
    let finding_id = hex64('a');
    let mut connection = store.connection().expect("purchase store connection");
    let transaction = store
        .begin_write(&mut connection)
        .expect("begin admission seed");
    transaction
        .execute(
            "UPDATE admissions SET state = 'superseded' WHERE state = 'active' AND finding_id = ?1",
            [&finding_id],
        )
        .expect("supersede active admission");
    transaction
        .execute(
            r#"
            INSERT INTO admissions (
                admission_id, finding_id, listing_id, backing_allocation_id,
                admission_envelope_sha256, admission_envelope_json,
                expires_at, activated_at, state
            ) VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, ?7, 'active')
            "#,
            params![
                admission_id,
                &finding_id,
                listing_id,
                allocation_id,
                admission_envelope_sha256,
                1_900_000_000_i64,
                NOW as i64,
            ],
        )
        .expect("insert active admission");
    store
        .commit_write(transaction)
        .expect("commit admission seed");
    store
        .sync_after_write(&connection)
        .expect("sync admission seed");
}

fn supersede_active_admission(store: &SqliteFindingPurchaseStore) {
    let finding_id = hex64('a');
    let mut connection = store.connection().expect("purchase store connection");
    let transaction = store
        .begin_write(&mut connection)
        .expect("begin admission supersession");
    transaction
        .execute(
            "UPDATE admissions SET state = 'superseded' WHERE state = 'active' AND finding_id = ?1",
            [&finding_id],
        )
        .expect("supersede active admission");
    store
        .commit_write(transaction)
        .expect("commit admission supersession");
    store
        .sync_after_write(&connection)
        .expect("sync admission supersession");
}

/// Collateral backing one finding on one listing. The purchase store binds
/// a reservation to the allocation that backs exactly that pair, so the
/// listing a fixture allocation names is what its sales must sell.
fn backing_body(ledger_account: &str, listing_id: &str) -> FindingBondBacking {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: keypair(21).public_key(),
        seller: keypair(22).public_key(),
        authorization_envelope_sha256: hex64('1'),
        finding_id: hex64('a'),
        listing_id: listing_id.to_string(),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
        fee_requirement_sha256: hex64('4'),
        fee_schedule_envelope_sha256: hex64('5'),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(500),
        maximum_sale_exposure: usd(REGISTERED_EXPOSURE_CAP),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: ledger_account.to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = compute_allocation_id(&backing).expect("allocation id");
    backing
}

fn register_allocation(
    market: &SqliteFindingMarketStore,
    ledger_account: &str,
    listing_id: &str,
) -> String {
    let backing = backing_body(ledger_account, listing_id);
    let envelope = envelope_string(&backing, &keypair(21));
    market
        .register_allocation(&envelope, &backing, NOW)
        .expect("register allocation");
    backing.allocation_id
}

fn consume_allocation(
    market: &SqliteFindingMarketStore,
    ledger_account: &str,
    listing_id: &str,
) -> String {
    let allocation_id = register_allocation(market, ledger_account, listing_id);
    market
        .consume_allocation(&allocation_id)
        .expect("consume allocation");
    allocation_id
}

/// One purchase's identifiers and digests, owned so the borrowed input
/// struct can point at them.
struct Purchase {
    reservation_id: String,
    purchase_intent_id: String,
    payment_operation_id: String,
    encumbrance_id: String,
    listing_id: String,
    payer_hex: String,
    finding_id: String,
    bid_envelope_sha256: String,
    ask_digest: String,
    admission_envelope_sha256: String,
    amount_units: u64,
    expires_at: u64,
}

impl Purchase {
    fn new(tag: &str, listing_id: &str, amount_units: u64) -> Self {
        Self {
            reservation_id: format!("reservation-{tag}"),
            purchase_intent_id: format!("intent-{tag}"),
            payment_operation_id: format!("payment-{tag}"),
            encumbrance_id: format!("encumbrance-{tag}"),
            listing_id: listing_id.to_owned(),
            payer_hex: hex64('b'),
            finding_id: hex64('a'),
            bid_envelope_sha256: chio_core::sha256_hex(format!("bid-{tag}").as_bytes()),
            ask_digest: chio_core::sha256_hex(format!("ask-{tag}").as_bytes()),
            admission_envelope_sha256: hex64('c'),
            amount_units,
            expires_at: EXPIRES_AT,
        }
    }

    fn expiring_at(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    fn input<'a>(&'a self, allocation_id: &'a str) -> FindingPurchaseReservationInput<'a> {
        FindingPurchaseReservationInput {
            reservation_id: &self.reservation_id,
            purchase_intent_id: &self.purchase_intent_id,
            authoritative_payment_operation_id: &self.payment_operation_id,
            payer_hex: &self.payer_hex,
            agent_id: "agent-buyer-01",
            finding_id: &self.finding_id,
            listing_id: &self.listing_id,
            bid_envelope_sha256: &self.bid_envelope_sha256,
            ask_digest: &self.ask_digest,
            admission_envelope_sha256: &self.admission_envelope_sha256,
            amount_units: self.amount_units,
            currency: "USD",
            expires_at: self.expires_at,
            encumbrance_id: &self.encumbrance_id,
            allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW,
        }
    }
}

fn open_reservation(fixture: &Fixture, purchase: &Purchase) -> FindingPurchaseWriteOutcome {
    fixture
        .store
        .open_reservation(&purchase.input(&fixture.allocation_id))
        .expect("open reservation")
}

/// Exposure the fixture allocation still carries at `now`, which is the
/// quantity its registered cap bounds.
fn outstanding_exposure(fixture: &Fixture, now: u64) -> u64 {
    fixture
        .store
        .list_outstanding_exposure_total(&fixture.allocation_id, now)
        .expect("outstanding exposure")
}

fn record_bytes(tag: &str) -> Vec<u8> {
    format!("{{\"schema\":\"chio.finding.purchase-record.v1\",\"tag\":\"{tag}\"}}").into_bytes()
}

fn reservation_state(fixture: &Fixture, reservation_id: &str) -> FindingPurchaseReservationState {
    fixture
        .store
        .get_reservation(reservation_id)
        .expect("get reservation")
        .expect("reservation present")
        .state
}

fn encumbrance(fixture: &Fixture, reservation_id: &str) -> FindingPurchaseEncumbranceRecord {
    fixture
        .store
        .get_encumbrance(reservation_id)
        .expect("get encumbrance")
        .expect("encumbrance present")
}

fn slot(fixture: &Fixture, reservation_id: &str) -> FindingPurchaseSlotRecord {
    fixture
        .store
        .get_slot(reservation_id)
        .expect("get slot")
        .expect("slot present")
}

#[test]
fn open_reservation_inserts_replays_and_rejects_conflicts() {
    let fixture = fixture();
    let purchase = Purchase::new("alpha", LISTING_ID, 100);
    assert_eq!(
        open_reservation(&fixture, &purchase),
        FindingPurchaseWriteOutcome::Inserted
    );
    let stored = fixture
        .store
        .get_reservation(&purchase.reservation_id)
        .expect("get reservation")
        .expect("reservation present");
    assert_eq!(
        stored,
        FindingPurchaseReservationRecord {
            reservation_id: purchase.reservation_id.clone(),
            purchase_intent_id: purchase.purchase_intent_id.clone(),
            authoritative_payment_operation_id: purchase.payment_operation_id.clone(),
            payer_hex: purchase.payer_hex.clone(),
            agent_id: "agent-buyer-01".to_string(),
            finding_id: purchase.finding_id.clone(),
            listing_id: LISTING_ID.to_string(),
            bid_envelope_sha256: purchase.bid_envelope_sha256.clone(),
            ask_digest: purchase.ask_digest.clone(),
            admission_envelope_sha256: purchase.admission_envelope_sha256.clone(),
            amount_units: 100,
            currency: "USD".to_string(),
            expires_at: EXPIRES_AT,
            state: FindingPurchaseReservationState::Open,
            created_at: NOW,
            updated_at: NOW,
        },
        "every reservation column must round-trip, so a column-index swap fails here"
    );
    assert_eq!(
        fixture
            .store
            .get_reservation_by_intent(&purchase.purchase_intent_id)
            .expect("get by intent")
            .expect("reservation present"),
        stored
    );
    assert_eq!(outstanding_exposure(&fixture, NOW), 100);

    assert_eq!(
        open_reservation(&fixture, &purchase),
        FindingPurchaseWriteOutcome::ExistingSame,
        "an identical replay must not double-book exposure"
    );
    assert_eq!(outstanding_exposure(&fixture, NOW), 100);

    let mut conflicting = purchase.input(&fixture.allocation_id);
    conflicting.amount_units = 101;
    assert!(
        matches!(
            fixture.store.open_reservation(&conflicting),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "conflicting parameters under an existing reservation id must reject"
    );

    let mut reused_intent = Purchase::new("beta", LISTING_ID, 10);
    reused_intent
        .purchase_intent_id
        .clone_from(&purchase.purchase_intent_id);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&reused_intent.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "one purchase intent cannot fence two reservations"
    );

    let mut reused_payment = Purchase::new("gamma", LISTING_ID, 10);
    reused_payment
        .payment_operation_id
        .clone_from(&purchase.payment_operation_id);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&reused_payment.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "one payment operation cannot fence two reservations"
    );

    let mut reused_encumbrance = Purchase::new("delta", LISTING_ID, 10);
    reused_encumbrance
        .encumbrance_id
        .clone_from(&purchase.encumbrance_id);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&reused_encumbrance.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "one encumbrance id cannot back two reservations"
    );
    assert!(fixture
        .store
        .get_reservation("reservation-absent")
        .expect("absent reservation lookup")
        .is_none());
}

#[test]
fn open_reservation_requires_a_matching_active_admission() {
    let fixture = fixture();
    let mut mismatched = Purchase::new("mismatched-admission", LISTING_ID, 10);
    mismatched.admission_envelope_sha256 = hex64('f');
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&mismatched.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a digest other than the finding's active admission must reject"
    );
    assert!(fixture
        .store
        .get_reservation(&mismatched.reservation_id)
        .expect("mismatched reservation lookup")
        .is_none());
    assert!(fixture
        .store
        .get_encumbrance(&mismatched.reservation_id)
        .expect("mismatched encumbrance lookup")
        .is_none());

    supersede_active_admission(&fixture.store);
    let missing = Purchase::new("missing-admission", LISTING_ID, 10);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&missing.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a finding without an active admission must reject"
    );
    assert!(fixture
        .store
        .get_reservation(&missing.reservation_id)
        .expect("missing-admission reservation lookup")
        .is_none());
    assert!(fixture
        .store
        .get_encumbrance(&missing.reservation_id)
        .expect("missing-admission encumbrance lookup")
        .is_none());
    assert_eq!(outstanding_exposure(&fixture, NOW), 0);
}

#[test]
fn exact_replay_rejects_after_its_admission_is_superseded() {
    let fixture = fixture();
    let superseded = Purchase::new("superseded-admission", LISTING_ID, 10);
    assert_eq!(
        open_reservation(&fixture, &superseded),
        FindingPurchaseWriteOutcome::Inserted
    );

    install_active_admission(
        &fixture.store,
        &fixture.allocation_id,
        LISTING_ID,
        &hex64('e'),
        &hex64('f'),
    );
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&superseded.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "idempotence must not bypass the current-admission predicate"
    );

    let mut current = Purchase::new("current-admission", LISTING_ID, 10);
    current.admission_envelope_sha256 = hex64('f');
    assert_eq!(
        open_reservation(&fixture, &current),
        FindingPurchaseWriteOutcome::Inserted,
        "the replacement active admission must remain purchasable"
    );
    assert_eq!(outstanding_exposure(&fixture, NOW), 20);
}

#[test]
fn exposure_is_bounded_exactly_at_the_registered_cap() {
    let fixture = fixture();
    // Each `open_reservation` is its own immediate transaction, so the
    // second call reads the first call's committed exposure: two callers
    // racing the same allocation cannot both pass the check.
    open_reservation(&fixture, &Purchase::new("alpha", LISTING_ID, 200));
    open_reservation(&fixture, &Purchase::new("beta", LISTING_ID, 200));
    assert_eq!(outstanding_exposure(&fixture, NOW), 400);

    let over = Purchase::new("gamma", LISTING_ID, 51);
    let rejected = fixture
        .store
        .open_reservation(&over.input(&fixture.allocation_id));
    match rejected {
        Err(FindingPurchaseStoreError::ExposureOvercommitted {
            outstanding,
            requested,
            maximum,
            ..
        }) => {
            assert_eq!((outstanding, requested, maximum), (400, 51, 450));
        }
        other => panic!("one unit past the cap must reject, got {other:?}"),
    }
    assert!(
        fixture
            .store
            .get_reservation(&over.reservation_id)
            .expect("rejected reservation lookup")
            .is_none(),
        "a rejected reservation must leave no durable state"
    );

    // Exactly at the cap is admitted: the bound is sum + new > cap.
    let exact = Purchase::new("delta", LISTING_ID, 50);
    assert_eq!(
        open_reservation(&fixture, &exact),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(outstanding_exposure(&fixture, NOW), 450);
    assert!(
        matches!(
            fixture.store.open_reservation(
                &Purchase::new("epsilon", LISTING_ID, 1).input(&fixture.allocation_id)
            ),
            Err(FindingPurchaseStoreError::ExposureOvercommitted { .. })
        ),
        "a full allocation admits nothing further"
    );

    // Releasing exposure frees capacity for the next purchase.
    fixture
        .store
        .release_reservation(&exact.reservation_id, NOW + 1)
        .expect("release");
    assert_eq!(outstanding_exposure(&fixture, NOW + 1), 400);
    assert_eq!(
        open_reservation(&fixture, &Purchase::new("zeta", LISTING_ID, 50)),
        FindingPurchaseWriteOutcome::Inserted
    );
}

#[test]
fn reservation_requires_a_consumed_allocation() {
    let fixture = fixture();
    let live = register_allocation(&fixture.market, "vault:finding-collateral-live", LISTING_ID);
    let purchase = Purchase::new("alpha", LISTING_ID, 10);
    assert!(
        matches!(
            fixture.store.open_reservation(&purchase.input(&live)),
            Err(FindingPurchaseStoreError::AllocationNotConsumed(_))
        ),
        "a live allocation has not been activated and cannot back a sale"
    );
    assert!(
        matches!(
            fixture.store.open_reservation(&purchase.input(&hex64('f'))),
            Err(FindingPurchaseStoreError::AllocationNotConsumed(_))
        ),
        "an unknown allocation must reject"
    );
    let mut over_cap = purchase.input(&fixture.allocation_id);
    over_cap.maximum_sale_exposure_units = REGISTERED_EXPOSURE_CAP + 1;
    assert!(
        matches!(
            fixture.store.open_reservation(&over_cap),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a cap above the one the allocation registered must reject"
    );
}

#[test]
fn slot_ordinals_are_monotonic_within_each_listing() {
    let fixture = fixture();
    let first = Purchase::new("alpha", LISTING_ID, 10);
    let second = Purchase::new("beta", LISTING_ID, 10);
    let other = Purchase::new("gamma", OTHER_LISTING_ID, 10);
    for purchase in [&first, &second] {
        open_reservation(&fixture, purchase);
    }
    // A second listing sells under its own collateral, so the slot lines
    // this test separates belong to separately backed sales.
    let other_allocation = consume_allocation(
        &fixture.market,
        "vault:finding-collateral-other",
        OTHER_LISTING_ID,
    );
    install_active_admission(
        &fixture.store,
        &other_allocation,
        OTHER_LISTING_ID,
        &hex64('e'),
        &hex64('c'),
    );
    fixture
        .store
        .open_reservation(&other.input(&other_allocation))
        .expect("open reservation on the other listing");
    assert_eq!(
        fixture
            .store
            .reserve_slot(&first.reservation_id, NOW + 1)
            .expect("first slot"),
        1
    );
    assert_eq!(
        fixture
            .store
            .reserve_slot(&second.reservation_id, NOW + 2)
            .expect("second slot"),
        2
    );
    assert_eq!(
        fixture
            .store
            .reserve_slot(&other.reservation_id, NOW + 3)
            .expect("other listing slot"),
        1,
        "slot lines are per listing"
    );
    assert_eq!(
        fixture
            .store
            .reserve_slot(&first.reservation_id, NOW + 4)
            .expect("idempotent slot"),
        1,
        "a reservation already holding a slot keeps it"
    );
    assert_eq!(
        reservation_state(&fixture, &first.reservation_id),
        FindingPurchaseReservationState::SlotReserved
    );
    assert_eq!(
        fixture
            .store
            .open_slot_floor(LISTING_ID)
            .expect("slot floor"),
        Some(1)
    );

    // Closing the floor slot moves the cutoff to the next open ordinal,
    // and a later reservation never reuses a retired ordinal.
    fixture
        .store
        .release_reservation(&first.reservation_id, NOW + 5)
        .expect("release first");
    assert_eq!(
        fixture
            .store
            .open_slot_floor(LISTING_ID)
            .expect("slot floor"),
        Some(2)
    );
    let third = Purchase::new("delta", LISTING_ID, 10);
    open_reservation(&fixture, &third);
    assert_eq!(
        fixture
            .store
            .reserve_slot(&third.reservation_id, NOW + 6)
            .expect("third slot"),
        3
    );
    fixture
        .store
        .release_reservation(&second.reservation_id, NOW + 7)
        .expect("release second");
    fixture
        .store
        .release_reservation(&third.reservation_id, NOW + 8)
        .expect("release third");
    assert_eq!(
        fixture
            .store
            .open_slot_floor(LISTING_ID)
            .expect("slot floor"),
        None,
        "an idle listing has no cutoff"
    );
    assert_eq!(
        fixture
            .store
            .open_slot_floor("purchase-listing-unknown")
            .expect("unknown listing floor"),
        None
    );

    let expired = Purchase::new("epsilon", LISTING_ID, 10).expiring_at(NOW + 10);
    open_reservation(&fixture, &expired);
    assert!(
        matches!(
            fixture
                .store
                .reserve_slot(&expired.reservation_id, NOW + 10),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a reservation at its expiry cannot take a fresh slot"
    );
    assert!(
        matches!(
            fixture.store.reserve_slot("reservation-absent", NOW + 1),
            Err(FindingPurchaseStoreError::NotFound)
        ),
        "an unknown reservation cannot take a slot"
    );
}

#[test]
fn close_slot_with_record_settles_atomically_and_replays() {
    let fixture = fixture();
    let purchase = Purchase::new("alpha", LISTING_ID, 100);
    open_reservation(&fixture, &purchase);
    fixture
        .store
        .reserve_slot(&purchase.reservation_id, NOW + 1)
        .expect("reserve slot");
    let bytes = record_bytes("alpha");
    let digest = chio_core::sha256_hex(&bytes);
    let purchase_key = hex64('d');
    let delivery = FindingPurchaseDeliveryInput {
        reservation_id: &purchase.reservation_id,
        purchase_key: &purchase_key,
        record_json: &bytes,
        record_sha256: &digest,
        delivery_receipt_id: "receipt-delivery-alpha",
        payout_destination: PAYOUT_DESTINATION,
        retention_expires_at: NOW + 100_000,
        now: NOW + 2,
    };

    let mut tampered = delivery;
    tampered.record_sha256 = &purchase_key;
    assert!(
        matches!(
            fixture.store.close_slot_with_record(&tampered),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "record bytes that do not match the claimed digest must reject"
    );
    assert!(fixture
        .store
        .list_payout_destinations(&fixture.allocation_id)
        .expect("destinations after rejected close")
        .is_empty());

    assert_eq!(
        fixture
            .store
            .close_slot_with_record(&delivery)
            .expect("settle purchase"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .list_payout_destinations(&fixture.allocation_id)
            .expect("destination admitted with close"),
        vec![(1, PAYOUT_DESTINATION.to_owned())]
    );
    assert_eq!(
        reservation_state(&fixture, &purchase.reservation_id),
        FindingPurchaseReservationState::Consumed
    );
    let closed = slot(&fixture, &purchase.reservation_id);
    assert_eq!(closed.state, FindingPurchaseSlotState::ClosedRecord);
    assert_eq!(closed.closed_at, Some(NOW + 2));
    let retained = encumbrance(&fixture, &purchase.reservation_id);
    assert_eq!(retained.state, FindingPurchaseEncumbranceState::Retained);
    assert_eq!(retained.retention_expires_at, Some(NOW + 100_000));
    assert_eq!(
        outstanding_exposure(&fixture, NOW + 3),
        100,
        "settled exposure stays encumbered through its retention horizon"
    );
    assert_eq!(
        fixture
            .store
            .open_slot_floor(LISTING_ID)
            .expect("slot floor"),
        None
    );
    assert_eq!(
        fixture
            .store
            .get_purchase_record(&purchase_key)
            .expect("get purchase record")
            .expect("purchase record present"),
        FindingPurchaseRecordRow {
            purchase_key: purchase_key.clone(),
            reservation_id: purchase.reservation_id.clone(),
            record_json: bytes.clone(),
            record_sha256: digest.clone(),
            delivery_receipt_id: "receipt-delivery-alpha".to_string(),
            recorded_at: NOW + 2,
        }
    );

    assert_eq!(
        fixture
            .store
            .close_slot_with_record(&delivery)
            .expect("replay settlement"),
        FindingPurchaseWriteOutcome::ExistingSame
    );
    assert_eq!(
        fixture
            .store
            .list_payout_destinations(&fixture.allocation_id)
            .expect("destinations after replay"),
        vec![(1, PAYOUT_DESTINATION.to_owned())],
        "an exact close replay must not consume another destination slot"
    );

    let mut conflicting_destination = delivery;
    conflicting_destination.payout_destination = "0x000000000000000000000000000000000000002b";
    assert!(
        matches!(
            fixture
                .store
                .close_slot_with_record(&conflicting_destination),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a settled replay cannot bind a second payout destination"
    );
    assert_eq!(
        fixture
            .store
            .list_payout_destinations(&fixture.allocation_id)
            .expect("destinations after conflicting replay"),
        vec![(1, PAYOUT_DESTINATION.to_owned())]
    );

    // The transition clock may advance across a retry, while the liability
    // horizon is an authoritative fact derived from the sale and backing.
    let mut later = delivery;
    later.now = NOW + 50;
    assert_eq!(
        fixture
            .store
            .close_slot_with_record(&later)
            .expect("replay settlement from a later clock"),
        FindingPurchaseWriteOutcome::ExistingSame
    );
    assert_eq!(
        encumbrance(&fixture, &purchase.reservation_id).retention_expires_at,
        Some(NOW + 100_000),
        "a replay never moves the retention horizon the settlement pinned"
    );

    let mut conflicting_retention = delivery;
    conflicting_retention.retention_expires_at = NOW + 200_000;
    assert!(
        matches!(
            fixture.store.close_slot_with_record(&conflicting_retention),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a replay cannot substitute a different liability horizon"
    );

    let mut conflicting = delivery;
    conflicting.delivery_receipt_id = "receipt-delivery-other";
    assert!(
        matches!(
            fixture.store.close_slot_with_record(&conflicting),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a replay under different delivery parameters must reject"
    );
    assert!(
        matches!(
            fixture
                .store
                .release_reservation(&purchase.reservation_id, NOW + 3),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a settled purchase cannot be released"
    );
    assert!(fixture
        .store
        .get_purchase_record(&hex64('e'))
        .expect("absent purchase record lookup")
        .is_none());
}

#[test]
fn retained_exposure_counts_until_its_retention_horizon_lapses() {
    let fixture = fixture();
    let settled = Purchase::new("alpha", LISTING_ID, 100);
    open_reservation(&fixture, &settled);
    fixture
        .store
        .reserve_slot(&settled.reservation_id, NOW + 1)
        .expect("reserve slot");
    let bytes = record_bytes("alpha");
    let digest = chio_core::sha256_hex(&bytes);
    let horizon = NOW + 1_000;
    fixture
        .store
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &settled.reservation_id,
            purchase_key: &hex64('d'),
            record_json: &bytes,
            record_sha256: &digest,
            delivery_receipt_id: "receipt-delivery-alpha",
            payout_destination: PAYOUT_DESTINATION,
            retention_expires_at: horizon,
            now: NOW + 2,
        })
        .expect("settle purchase");
    assert_eq!(
        encumbrance(&fixture, &settled.reservation_id).state,
        FindingPurchaseEncumbranceState::Retained
    );
    assert_eq!(
        outstanding_exposure(&fixture, horizon - 1),
        100,
        "settling a sale does not free the collateral backing its liability"
    );
    assert_eq!(
        outstanding_exposure(&fixture, horizon),
        0,
        "the horizon lapses once the trusted time reaches it"
    );

    // While the horizon holds, the retained liability occupies the cap, so
    // one allocation cannot back unbounded settled sales.
    let crowded = Purchase::new("beta", LISTING_ID, REGISTERED_EXPOSURE_CAP - 99);
    let mut input = crowded.input(&fixture.allocation_id);
    input.created_at = NOW + 3;
    match fixture.store.open_reservation(&input) {
        Err(FindingPurchaseStoreError::ExposureOvercommitted {
            outstanding,
            requested,
            maximum,
            ..
        }) => assert_eq!(
            (outstanding, requested, maximum),
            (100, REGISTERED_EXPOSURE_CAP - 99, REGISTERED_EXPOSURE_CAP)
        ),
        other => panic!("retained exposure must occupy the cap, got {other:?}"),
    }
    assert!(
        fixture
            .store
            .get_reservation(&crowded.reservation_id)
            .expect("rejected reservation lookup")
            .is_none(),
        "a rejected reservation must leave no durable state"
    );

    // Past the horizon the same sale fits, because the retained exposure
    // has stopped counting.
    input.created_at = horizon;
    assert_eq!(
        fixture
            .store
            .open_reservation(&input)
            .expect("reserve once the horizon has lapsed"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        outstanding_exposure(&fixture, horizon),
        REGISTERED_EXPOSURE_CAP - 99
    );
}

#[test]
fn allocation_must_back_the_reservations_finding_and_listing() {
    let fixture = fixture();
    // The fixture allocation backs finding hex64('a') on LISTING_ID.
    let other_listing = Purchase::new("alpha", OTHER_LISTING_ID, 10);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&other_listing.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::AllocationNotBoundToSale { .. })
        ),
        "collateral backing one listing cannot be encumbered for another"
    );
    let mut other_finding = Purchase::new("beta", LISTING_ID, 10);
    other_finding.finding_id = hex64('e');
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&other_finding.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::AllocationNotBoundToSale { .. })
        ),
        "collateral backing one finding cannot be encumbered for another"
    );
    for rejected in [&other_listing, &other_finding] {
        assert!(
            fixture
                .store
                .get_reservation(&rejected.reservation_id)
                .expect("rejected reservation lookup")
                .is_none(),
            "a rejected reservation must leave no durable state"
        );
    }
    assert_eq!(
        outstanding_exposure(&fixture, NOW),
        0,
        "a misdirected sale must not encumber the allocation it named"
    );

    // The allocation that does back the sale admits it, and the other
    // listing sells under the collateral registered for that listing.
    assert_eq!(
        open_reservation(&fixture, &Purchase::new("gamma", LISTING_ID, 10)),
        FindingPurchaseWriteOutcome::Inserted
    );
    let other_allocation = consume_allocation(
        &fixture.market,
        "vault:finding-collateral-other",
        OTHER_LISTING_ID,
    );
    install_active_admission(
        &fixture.store,
        &other_allocation,
        OTHER_LISTING_ID,
        &hex64('e'),
        &hex64('c'),
    );
    assert_eq!(
        fixture
            .store
            .open_reservation(&other_listing.input(&other_allocation))
            .expect("reserve against the backing allocation"),
        FindingPurchaseWriteOutcome::Inserted
    );
}

#[test]
fn reserve_replays_across_a_later_clock() {
    let fixture = fixture();
    let purchase = Purchase::new("alpha", LISTING_ID, 100);
    open_reservation(&fixture, &purchase);
    let mut later = purchase.input(&fixture.allocation_id);
    later.created_at = NOW + 30;
    later.expires_at = EXPIRES_AT + 30;
    assert_eq!(
        fixture
            .store
            .open_reservation(&later)
            .expect("replay from a later clock"),
        FindingPurchaseWriteOutcome::ExistingSame,
        "a retry of one reserve must not be stranded by the clock it retries from"
    );
    let stored = fixture
        .store
        .get_reservation(&purchase.reservation_id)
        .expect("get reservation")
        .expect("reservation present");
    assert_eq!(
        (stored.created_at, stored.expires_at),
        (NOW, EXPIRES_AT),
        "a replay never extends the fence the first call committed"
    );
    assert_eq!(
        outstanding_exposure(&fixture, NOW + 30),
        100,
        "a replay must not double-book exposure"
    );
    let mut different = later;
    different.amount_units = 101;
    assert!(
        matches!(
            fixture.store.open_reservation(&different),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a later clock does not excuse a different purchase"
    );
}

#[test]
fn close_slot_with_deny_releases_exposure_and_retains_the_denial() {
    let fixture = fixture();
    let purchase = Purchase::new("alpha", LISTING_ID, 100);
    open_reservation(&fixture, &purchase);
    fixture
        .store
        .reserve_slot(&purchase.reservation_id, NOW + 1)
        .expect("reserve slot");
    let bytes = record_bytes("denied-alpha");
    let digest = chio_core::sha256_hex(&bytes);
    let deny = FindingPurchaseDenyInput {
        reservation_id: &purchase.reservation_id,
        failed_delivery_id: "failed-delivery-alpha",
        record_json: &bytes,
        record_sha256: &digest,
        deny_receipt_id: "receipt-deny-alpha",
        now: NOW + 2,
    };
    assert_eq!(
        fixture
            .store
            .close_slot_with_deny(&deny)
            .expect("deny delivery"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        reservation_state(&fixture, &purchase.reservation_id),
        FindingPurchaseReservationState::Released
    );
    assert_eq!(
        slot(&fixture, &purchase.reservation_id).state,
        FindingPurchaseSlotState::ClosedDeny
    );
    let released = encumbrance(&fixture, &purchase.reservation_id);
    assert_eq!(released.state, FindingPurchaseEncumbranceState::Released);
    assert_eq!(released.retention_expires_at, None);
    assert_eq!(outstanding_exposure(&fixture, NOW + 2), 0);
    assert_eq!(
        fixture
            .store
            .get_failed_delivery_record("failed-delivery-alpha")
            .expect("get failed delivery")
            .expect("failed delivery present"),
        FindingFailedDeliveryRow {
            failed_delivery_id: "failed-delivery-alpha".to_string(),
            reservation_id: purchase.reservation_id.clone(),
            record_json: bytes.clone(),
            record_sha256: digest.clone(),
            deny_receipt_id: "receipt-deny-alpha".to_string(),
            recorded_at: NOW + 2,
        }
    );
    assert_eq!(
        fixture
            .store
            .close_slot_with_deny(&deny)
            .expect("replay denial"),
        FindingPurchaseWriteOutcome::ExistingSame
    );
    let mut conflicting = deny;
    conflicting.deny_receipt_id = "receipt-deny-other";
    assert!(
        matches!(
            fixture.store.close_slot_with_deny(&conflicting),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a replay under different denial parameters must reject"
    );

    // A predispatch abort leaves no denial record, so a later denial call
    // for that reservation cannot masquerade as an idempotent replay.
    let aborted = Purchase::new("beta", LISTING_ID, 10);
    open_reservation(&fixture, &aborted);
    fixture
        .store
        .reserve_slot(&aborted.reservation_id, NOW + 3)
        .expect("reserve slot");
    fixture
        .store
        .release_reservation(&aborted.reservation_id, NOW + 4)
        .expect("abort predispatch");
    assert!(
        matches!(
            fixture
                .store
                .close_slot_with_deny(&FindingPurchaseDenyInput {
                    reservation_id: &aborted.reservation_id,
                    failed_delivery_id: "failed-delivery-beta",
                    record_json: &bytes,
                    record_sha256: &digest,
                    deny_receipt_id: "receipt-deny-beta",
                    now: NOW + 5,
                }),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "a reservation released without a denial cannot accept one later"
    );
}

#[test]
fn release_and_expiry_never_leave_a_slot_reserved() {
    let fixture = fixture();
    let unslotted = Purchase::new("alpha", LISTING_ID, 10);
    open_reservation(&fixture, &unslotted);
    fixture
        .store
        .release_reservation(&unslotted.reservation_id, NOW + 1)
        .expect("release open reservation");
    assert_eq!(
        reservation_state(&fixture, &unslotted.reservation_id),
        FindingPurchaseReservationState::Released
    );
    assert_eq!(
        encumbrance(&fixture, &unslotted.reservation_id).state,
        FindingPurchaseEncumbranceState::Released
    );
    assert!(fixture
        .store
        .get_slot(&unslotted.reservation_id)
        .expect("slot lookup")
        .is_none());
    fixture
        .store
        .release_reservation(&unslotted.reservation_id, NOW + 2)
        .expect("release replays idempotently");

    let slotted = Purchase::new("beta", LISTING_ID, 10);
    open_reservation(&fixture, &slotted);
    fixture
        .store
        .reserve_slot(&slotted.reservation_id, NOW + 3)
        .expect("reserve slot");
    fixture
        .store
        .release_reservation(&slotted.reservation_id, NOW + 4)
        .expect("release slot-reserved reservation");
    assert_eq!(
        slot(&fixture, &slotted.reservation_id).state,
        FindingPurchaseSlotState::ClosedDeny,
        "a released reservation must never leave its slot reserved"
    );
    assert!(
        fixture
            .store
            .get_failed_delivery_record("failed-delivery-beta")
            .expect("failed delivery lookup")
            .is_none(),
        "a predispatch abort writes no failed-delivery record"
    );

    // Expiry sweeps whatever is still live, releasing exposure and
    // closing slots, and never touches a settled purchase.
    let settled = Purchase::new("gamma", LISTING_ID, 10);
    open_reservation(&fixture, &settled);
    fixture
        .store
        .reserve_slot(&settled.reservation_id, NOW + 5)
        .expect("reserve slot");
    let bytes = record_bytes("gamma");
    let digest = chio_core::sha256_hex(&bytes);
    fixture
        .store
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &settled.reservation_id,
            purchase_key: &hex64('d'),
            record_json: &bytes,
            record_sha256: &digest,
            delivery_receipt_id: "receipt-delivery-gamma",
            payout_destination: PAYOUT_DESTINATION,
            retention_expires_at: EXPIRES_AT + 100_000,
            now: NOW + 6,
        })
        .expect("settle purchase");

    let stale_open = Purchase::new("delta", LISTING_ID, 10);
    let stale_slotted = Purchase::new("epsilon", LISTING_ID, 10);
    open_reservation(&fixture, &stale_open);
    open_reservation(&fixture, &stale_slotted);
    fixture
        .store
        .reserve_slot(&stale_slotted.reservation_id, NOW + 7)
        .expect("reserve slot");
    assert_eq!(
        fixture
            .store
            .expire_reservations(NOW + 8, 16)
            .expect("nothing is due yet"),
        0
    );
    assert_eq!(
        fixture
            .store
            .expire_reservations(EXPIRES_AT, 1)
            .expect("bounded sweep"),
        1,
        "the batch limit bounds one transaction"
    );
    assert_eq!(
        fixture
            .store
            .expire_reservations(EXPIRES_AT, 16)
            .expect("remaining sweep"),
        1
    );
    for purchase in [&stale_open, &stale_slotted] {
        assert_eq!(
            reservation_state(&fixture, &purchase.reservation_id),
            FindingPurchaseReservationState::Expired
        );
        assert_eq!(
            encumbrance(&fixture, &purchase.reservation_id).state,
            FindingPurchaseEncumbranceState::Released
        );
    }
    assert_eq!(
        slot(&fixture, &stale_slotted.reservation_id).state,
        FindingPurchaseSlotState::ClosedDeny
    );
    assert_eq!(
        reservation_state(&fixture, &settled.reservation_id),
        FindingPurchaseReservationState::Consumed,
        "expiry must not disturb a settled purchase"
    );
    assert_eq!(
        fixture
            .store
            .expire_reservations(EXPIRES_AT, 16)
            .expect("idle sweep"),
        0
    );
    assert_eq!(
        fixture
            .store
            .open_slot_floor(LISTING_ID)
            .expect("slot floor"),
        None
    );
}

#[test]
fn a_lapsed_reservation_stops_encumbering_the_allocation_at_the_next_reserve() {
    let fixture = fixture();
    // A reservation that takes most of the cap and a slot, then is
    // abandoned: nothing settles it, denies it, or sweeps it.
    let abandoned = Purchase::new("alpha", LISTING_ID, 400);
    open_reservation(&fixture, &abandoned);
    fixture
        .store
        .reserve_slot(&abandoned.reservation_id, NOW + 1)
        .expect("reserve slot");

    // While the reservation is live its exposure occupies the cap.
    let crowded = Purchase::new("beta", LISTING_ID, 200);
    assert!(
        matches!(
            fixture
                .store
                .open_reservation(&crowded.input(&fixture.allocation_id)),
            Err(FindingPurchaseStoreError::ExposureOvercommitted { .. })
        ),
        "live exposure keeps occupying the cap"
    );

    // Past its expiry the reservation is dead weight: the next reserve
    // expires it in the same transaction and checks the cap against live
    // exposure only, so an abandoned purchase cannot lock the seller out.
    let next = Purchase::new("gamma", LISTING_ID, 200);
    let mut input = next.input(&fixture.allocation_id);
    input.created_at = EXPIRES_AT;
    input.expires_at = EXPIRES_AT + 3_600;
    assert_eq!(
        fixture
            .store
            .open_reservation(&input)
            .expect("a lapsed reservation must not encumber the seller"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        reservation_state(&fixture, &abandoned.reservation_id),
        FindingPurchaseReservationState::Expired
    );
    assert_eq!(
        encumbrance(&fixture, &abandoned.reservation_id).state,
        FindingPurchaseEncumbranceState::Released
    );
    assert_eq!(
        slot(&fixture, &abandoned.reservation_id).state,
        FindingPurchaseSlotState::ClosedDeny
    );
    assert_eq!(outstanding_exposure(&fixture, EXPIRES_AT), 200);
}

#[test]
fn the_exposure_query_follows_reservation_expiry_without_a_sweep() {
    let fixture = fixture();
    // One abandoned open reservation and one purchase holding a slot,
    // both carrying the same expiry, and no sweep ever runs.
    let abandoned = Purchase::new("alpha", LISTING_ID, 100);
    open_reservation(&fixture, &abandoned);
    let in_flight = Purchase::new("beta", LISTING_ID, 150);
    open_reservation(&fixture, &in_flight);
    fixture
        .store
        .reserve_slot(&in_flight.reservation_id, NOW + 1)
        .expect("reserve slot");
    assert_eq!(
        outstanding_exposure(&fixture, NOW + 2),
        250,
        "live reservations encumber in full"
    );

    // Past the expiry the open reservation can never take a slot, so it
    // stops counting even though nothing has swept it. The slot-holding
    // purchase may still settle, so it must keep counting: dropping it
    // here would let a new reservation overcommit against exposure that
    // can still be retained.
    assert_eq!(outstanding_exposure(&fixture, EXPIRES_AT), 150);
    assert_eq!(
        reservation_state(&fixture, &abandoned.reservation_id),
        FindingPurchaseReservationState::Open,
        "the figure moved on expiry alone, not on a sweep"
    );

    // The in-flight purchase settles past its expiry, exactly the path
    // the query kept counting for: its exposure survives as a retained
    // encumbrance through the settlement's own horizon.
    let bytes = record_bytes("beta");
    let digest = chio_core::sha256_hex(&bytes);
    let purchase_key = hex64('d');
    fixture
        .store
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &in_flight.reservation_id,
            purchase_key: &purchase_key,
            record_json: &bytes,
            record_sha256: &digest,
            delivery_receipt_id: "receipt-delivery-beta",
            payout_destination: PAYOUT_DESTINATION,
            retention_expires_at: EXPIRES_AT + 100_000,
            now: EXPIRES_AT,
        })
        .expect("settle the in-flight purchase past its expiry");
    assert_eq!(
        outstanding_exposure(&fixture, EXPIRES_AT + 1),
        150,
        "settlement carries the exposure into retention without a gap"
    );
}

#[test]
fn an_overcommitted_retry_advances_past_each_expiry_batch() {
    const LARGE_CAP: u64 = 1_024;

    let fixture = fixture();
    let mut backing = backing_body("vault:expiry-batch", LISTING_ID);
    backing.locked_amount = usd(LARGE_CAP + 50);
    backing.maximum_sale_exposure = usd(LARGE_CAP);
    backing.allocation_id = String::new();
    backing.allocation_id = compute_allocation_id(&backing).expect("large allocation id");
    let allocation_id = backing.allocation_id.clone();
    let envelope = envelope_string(&backing, &keypair(21));
    fixture
        .market
        .register_allocation(&envelope, &backing, NOW)
        .expect("register large allocation");
    fixture
        .market
        .consume_allocation(&allocation_id)
        .expect("consume large allocation");

    for index in 0..=MAX_EXPIRY_BATCH {
        let purchase =
            Purchase::new(&format!("expiry-batch-{index}"), LISTING_ID, 1).expiring_at(NOW + 1);
        let mut input = purchase.input(&allocation_id);
        input.maximum_sale_exposure_units = LARGE_CAP;
        fixture
            .store
            .open_reservation(&input)
            .expect("open batch reservation");
        fixture
            .store
            .reserve_slot(&purchase.reservation_id, NOW)
            .expect("reserve batch slot");
    }

    let next = Purchase::new("after-expiry-batch", LISTING_ID, LARGE_CAP);
    let mut input = next.input(&allocation_id);
    input.maximum_sale_exposure_units = LARGE_CAP;
    input.created_at = NOW + 1;
    let first = fixture
        .store
        .open_reservation(&input)
        .expect_err("one expired row remains after the bounded cleanup");
    assert!(matches!(
        first,
        FindingPurchaseStoreError::ExposureOvercommitted {
            outstanding: 1,
            requested: LARGE_CAP,
            maximum: LARGE_CAP,
            ..
        }
    ));

    assert_eq!(
        fixture
            .store
            .open_reservation(&input)
            .expect("the retry advances to the remaining expired row"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .list_outstanding_exposure_total(&allocation_id, NOW + 1)
            .expect("large allocation exposure"),
        LARGE_CAP
    );
}

#[test]
fn blocking_sales_stops_the_slot_line_and_the_wait_predicate_is_exact() {
    let fixture = fixture();
    let first = Purchase::new("alpha", LISTING_ID, 10);
    let second = Purchase::new("beta", LISTING_ID, 10);
    let third = Purchase::new("gamma", LISTING_ID, 10);
    for purchase in [&first, &second, &third] {
        open_reservation(&fixture, purchase);
    }
    assert_eq!(
        fixture
            .store
            .reserve_slot(&first.reservation_id, NOW + 1)
            .expect("first slot"),
        1
    );
    assert_eq!(
        fixture
            .store
            .reserve_slot(&second.reservation_id, NOW + 1)
            .expect("second slot"),
        2
    );
    assert!(
        !fixture
            .store
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "a listing sells until it is blocked"
    );

    // The wait predicate counts only the slots at or below the cutoff.
    assert!(
        fixture
            .store
            .all_slots_closed_at_or_below(LISTING_ID, 0)
            .expect("wait predicate"),
        "slot ordinals start at one, so a zero cutoff waits for nothing"
    );
    assert!(
        !fixture
            .store
            .all_slots_closed_at_or_below(LISTING_ID, 1)
            .expect("wait predicate"),
        "slot one is still reserved"
    );
    assert_eq!(
        fixture
            .store
            .closed_settled_purchase_keys_at_or_below(LISTING_ID, &fixture.allocation_id, 2,)
            .expect("atomic closure and claim enumeration"),
        None,
        "an open slot cannot be observed beside an apparently complete claim set"
    );

    assert_eq!(
        fixture
            .store
            .block_new_slots(LISTING_ID, NOW + 2)
            .expect("block sales"),
        FindingPurchaseWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .block_new_slots(LISTING_ID, NOW + 3)
            .expect("replay block"),
        FindingPurchaseWriteOutcome::ExistingSame
    );
    assert!(fixture
        .store
        .sales_blocked(LISTING_ID)
        .expect("sales blocked"));
    assert!(
        matches!(
            fixture.store.reserve_slot(&third.reservation_id, NOW + 4),
            Err(FindingPurchaseStoreError::SalesBlocked(_))
        ),
        "no reservation may take a fresh slot once the listing is blocked"
    );
    assert!(
        fixture
            .store
            .get_slot(&third.reservation_id)
            .expect("slot lookup")
            .is_none(),
        "a refused reserve leaves no durable slot"
    );
    assert_eq!(
        fixture
            .store
            .reserve_slot(&first.reservation_id, NOW + 4)
            .expect("idempotent slot"),
        1,
        "a reservation already holding a slot keeps it, because it opens nothing new"
    );

    // A blocked listing still closes the purchases already in flight, and
    // the predicate flips exactly when the last pre-cutoff slot closes.
    let bytes = record_bytes("alpha");
    let digest = chio_core::sha256_hex(&bytes);
    fixture
        .store
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &first.reservation_id,
            purchase_key: &hex64('d'),
            record_json: &bytes,
            record_sha256: &digest,
            delivery_receipt_id: "receipt-delivery-alpha",
            payout_destination: PAYOUT_DESTINATION,
            retention_expires_at: NOW + 100_000,
            now: NOW + 5,
        })
        .expect("settle under a block");
    assert!(fixture
        .store
        .all_slots_closed_at_or_below(LISTING_ID, 1)
        .expect("wait predicate"));
    assert!(
        !fixture
            .store
            .all_slots_closed_at_or_below(LISTING_ID, 2)
            .expect("wait predicate"),
        "slot two is still reserved"
    );
    fixture
        .store
        .release_reservation(&second.reservation_id, NOW + 6)
        .expect("abort under a block");
    assert!(
        fixture
            .store
            .all_slots_closed_at_or_below(LISTING_ID, 2)
            .expect("wait predicate"),
        "an aborted purchase closes its slot exactly as a settled one does"
    );
    assert_eq!(
        fixture
            .store
            .closed_settled_purchase_keys_at_or_below(LISTING_ID, &fixture.allocation_id, 2,)
            .expect("atomic closure and claim enumeration"),
        Some(vec![hex64('d')]),
        "the complete set is returned from the same snapshot that proves closure"
    );

    // Blocks are per listing.
    assert!(
        !fixture
            .store
            .sales_blocked(OTHER_LISTING_ID)
            .expect("sales blocked"),
        "blocking one listing must not block another"
    );
    assert!(fixture
        .store
        .all_slots_closed_at_or_below(OTHER_LISTING_ID, 9)
        .expect("wait predicate"));
}

#[test]
fn a_sales_block_episode_lifts_once_and_is_never_erased() {
    let connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .expect("purchase schema");
    connection
        .execute_batch(
            r#"
            INSERT INTO listing_sales_blocks (
                listing_id, block_ordinal, state, blocked_at, lifted_at
            ) VALUES ('listing-01', 1, 'blocked', 10, NULL);
            "#,
        )
        .expect("raise a block");

    assert!(
        connection
            .execute_batch(
                r#"
                INSERT INTO listing_sales_blocks (
                    listing_id, block_ordinal, state, blocked_at, lifted_at
                ) VALUES ('listing-01', 2, 'blocked', 11, NULL);
                "#,
            )
            .is_err(),
        "a listing carries at most one live block, so a lift is never ambiguous"
    );
    assert!(
        connection
            .execute_batch(
                "UPDATE listing_sales_blocks SET blocked_at = 99 WHERE block_ordinal = 1;"
            )
            .is_err(),
        "the raise is frozen at the time it was recorded"
    );
    assert!(
        connection
            .execute_batch("DELETE FROM listing_sales_blocks;")
            .is_err(),
        "a block episode is retained, never deleted"
    );

    connection
        .execute_batch(
            r#"
            UPDATE listing_sales_blocks SET state = 'lifted', lifted_at = 20
            WHERE block_ordinal = 1;
            "#,
        )
        .expect("lift the block");
    assert!(
        connection
            .execute_batch(
                r#"
                UPDATE listing_sales_blocks SET state = 'blocked', lifted_at = NULL
                WHERE block_ordinal = 1;
                "#,
            )
            .is_err(),
        "a released episode is never reblocked in place"
    );
    assert!(
        connection
            .execute_batch(
                "UPDATE listing_sales_blocks SET lifted_at = 30 WHERE block_ordinal = 1;"
            )
            .is_err(),
        "a lift is stamped exactly once"
    );

    // The listing may be blocked again, and the released episode keeps its
    // own raise and release beside the new one.
    connection
        .execute_batch(
            r#"
            INSERT INTO listing_sales_blocks (
                listing_id, block_ordinal, state, blocked_at, lifted_at
            ) VALUES ('listing-01', 2, 'blocked', 40, NULL);
            "#,
        )
        .expect("raise a second block");
    let retained: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM listing_sales_blocks WHERE listing_id = 'listing-01'",
            [],
            |row| row.get(0),
        )
        .expect("count episodes");
    assert_eq!(retained, 2);
}

#[test]
fn a_listing_keyed_sales_block_carries_across_to_the_episode_line() {
    let mut connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .expect("purchase schema");
    // Rewind the sales block to the listing-keyed shape the earlier
    // revision provisioned, carrying two listings blocked under it.
    connection
        .execute_batch(
            r#"
            DROP TABLE listing_sales_blocks;

            CREATE TABLE listing_sales_blocks (
                listing_id TEXT NOT NULL PRIMARY KEY
                    CHECK (length(listing_id) BETWEEN 1 AND 512),
                blocked_at INTEGER NOT NULL CHECK (blocked_at > 0)
            );

            CREATE TRIGGER listing_sales_blocks_immutable
            BEFORE UPDATE ON listing_sales_blocks
            BEGIN
                SELECT RAISE(ABORT, 'listing sales block is immutable');
            END;

            CREATE TRIGGER listing_sales_blocks_no_delete
            BEFORE DELETE ON listing_sales_blocks
            BEGIN
                SELECT RAISE(ABORT, 'listing sales block must be retained');
            END;

            INSERT INTO listing_sales_blocks (listing_id, blocked_at)
            VALUES ('listing-01', 10), ('listing-02', 11);
            "#,
        )
        .expect("rewind to the listing-keyed block");
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {};",
            crate::CHIO_SQLITE_APPLICATION_ID
        ))
        .expect("stamp the application id");
    crate::stamp_schema_version(
        &connection,
        FINDING_PURCHASE_SCHEMA_KEY,
        FINDING_PURCHASE_LISTING_KEYED_BLOCK_VERSION,
    )
    .expect("stamp the earlier revision");

    initialize_finding_purchase_schema(&mut connection).expect("open across the revision");

    let mut statement = connection
        .prepare(
            r#"
            SELECT listing_id, block_ordinal, state, blocked_at, lifted_at
            FROM listing_sales_blocks ORDER BY listing_id ASC
            "#,
        )
        .expect("prepare episode read");
    let episodes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .expect("read episodes")
        .collect::<Result<Vec<_>, _>>()
        .expect("episode rows");
    assert_eq!(
        episodes,
        vec![
            ("listing-01".to_owned(), 1, "blocked".to_owned(), 10, None),
            ("listing-02".to_owned(), 1, "blocked".to_owned(), 11, None),
        ],
        "a block that was never lifted stays live across the upgrade, at the time it was raised"
    );

    // The open re-verifies the schema shape, so the parked table is gone
    // and reopening is a no-op.
    drop(statement);
    initialize_finding_purchase_schema(&mut connection).expect("reopen at the current revision");
}

fn rewind_to_rail_only_payout_destinations(connection: &Connection) {
    connection
        .execute_batch(
            r#"
            DROP TABLE payout_destinations;

            CREATE TABLE payout_destinations (
                allocation_id TEXT NOT NULL
                    CHECK (length(allocation_id) = 64 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
                destination TEXT NOT NULL CHECK (
                    length(destination) BETWEEN 3 AND 512
                    AND destination GLOB '?*:?*'
                ),
                slot_index INTEGER NOT NULL CHECK (slot_index BETWEEN 0 AND 15),
                admitted_at INTEGER NOT NULL CHECK (admitted_at > 0),
                PRIMARY KEY (allocation_id, destination)
            );

            CREATE UNIQUE INDEX payout_destinations_slot
                ON payout_destinations(allocation_id, slot_index);

            CREATE TRIGGER payout_destinations_immutable
            BEFORE UPDATE ON payout_destinations
            BEGIN
                SELECT RAISE(ABORT, 'admitted payout destination is immutable');
            END;

            CREATE TRIGGER payout_destinations_no_delete
            BEFORE DELETE ON payout_destinations
            BEGIN
                SELECT RAISE(ABORT, 'admitted payout destination must be retained');
            END;
            "#,
        )
        .expect("rewind to the rail-only payout table");
}

#[test]
fn rail_only_community_destination_carries_across_to_slot_aware_schema() {
    let mut connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .expect("purchase schema");
    rewind_to_rail_only_payout_destinations(&connection);
    connection
        .execute(
            r#"
            INSERT INTO payout_destinations (
                allocation_id, destination, slot_index, admitted_at
            ) VALUES (?1, 'rail:venue-ledger:community-fund', 0, ?2)
            "#,
            params![hex64('a'), i64::try_from(NOW).expect("test time fits")],
        )
        .expect("insert legacy community destination");
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {};",
            crate::CHIO_SQLITE_APPLICATION_ID
        ))
        .expect("stamp the application id");
    crate::stamp_schema_version(&connection, FINDING_PURCHASE_SCHEMA_KEY, 3)
        .expect("stamp the earlier revision");

    initialize_finding_purchase_schema(&mut connection).expect("migrate rail-only payout table");

    let destination: String = connection
        .query_row(
            "SELECT destination FROM payout_destinations WHERE slot_index = 0",
            [],
            |row| row.get(0),
        )
        .expect("read migrated community destination");
    assert_eq!(destination, "rail:venue-ledger:community-fund");
    initialize_finding_purchase_schema(&mut connection).expect("reopen at the current revision");
}

#[test]
fn rail_only_buyer_destination_aborts_schema_migration() {
    let mut connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .expect("purchase schema");
    rewind_to_rail_only_payout_destinations(&connection);
    connection
        .execute(
            r#"
            INSERT INTO payout_destinations (
                allocation_id, destination, slot_index, admitted_at
            ) VALUES (?1, 'rail:venue-ledger:legacy-buyer', 1, ?2)
            "#,
            params![hex64('a'), i64::try_from(NOW).expect("test time fits")],
        )
        .expect("insert legacy buyer destination");
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {};",
            crate::CHIO_SQLITE_APPLICATION_ID
        ))
        .expect("stamp the application id");
    crate::stamp_schema_version(&connection, FINDING_PURCHASE_SCHEMA_KEY, 3)
        .expect("stamp the earlier revision");

    assert!(
        initialize_finding_purchase_schema(&mut connection).is_err(),
        "an unauthenticated destination translation must fail closed"
    );
    let retained: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM payout_destinations WHERE slot_index = 1",
            [],
            |row| row.get(0),
        )
        .expect("read rolled-back legacy destination");
    assert_eq!(retained, 1, "the failed migration preserves the legacy row");
    let parked: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'payout_destinations_legacy'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .expect("check migration rollback");
    assert!(!parked, "the failed migration rolls back its table rename");
}

#[test]
fn payout_destination_slots_are_bounded_and_idempotent() {
    let fixture = fixture();
    let allocation_id = &fixture.allocation_id;
    let community = "rail:venue-ledger:community-fund";
    let admitted = fixture
        .store
        .register_community_fund_destination(allocation_id, community, NOW)
        .expect("register community fund");
    assert_eq!(admitted.slot_index, 0);
    assert_eq!(admitted.outcome, FindingPurchaseWriteOutcome::Inserted);
    let replay = fixture
        .store
        .register_community_fund_destination(allocation_id, community, NOW + 1)
        .expect("replay community fund");
    assert_eq!(replay.slot_index, 0);
    assert_eq!(replay.outcome, FindingPurchaseWriteOutcome::ExistingSame);
    assert_eq!(
        replay.admitted_at, NOW,
        "a replay reports the original admission time"
    );
    assert!(
        matches!(
            fixture.store.register_community_fund_destination(
                allocation_id,
                "rail:venue-ledger:other-fund",
                NOW + 2
            ),
            Err(FindingPurchaseStoreError::Conflict(_))
        ),
        "the reserved community slot cannot be rebound"
    );
    assert!(
        matches!(
            fixture
                .store
                .admit_payout_destination(allocation_id, "untagged-destination", NOW),
            Err(FindingPurchaseStoreError::Invariant(_))
        ),
        "a destination without an EVM address cannot be routed"
    );

    for index in 1..=15_u8 {
        let destination = format!("0x{index:040x}");
        let slot = fixture
            .store
            .admit_payout_destination(allocation_id, &destination, NOW + u64::from(index))
            .expect("admit buyer destination");
        assert_eq!(slot.slot_index, index, "buyer slots fill 1..=15 in order");
        assert_eq!(slot.outcome, FindingPurchaseWriteOutcome::Inserted);
    }
    let repeat = fixture
        .store
        .admit_payout_destination(
            allocation_id,
            "0x0000000000000000000000000000000000000007",
            NOW + 100,
        )
        .expect("repeat destination");
    assert_eq!(repeat.slot_index, 7);
    assert_eq!(repeat.outcome, FindingPurchaseWriteOutcome::ExistingSame);
    assert!(
        matches!(
            fixture.store.admit_payout_destination(
                allocation_id,
                "0x0000000000000000000000000000000000000010",
                NOW + 101
            ),
            Err(FindingPurchaseStoreError::DestinationSlotsExhausted(_))
        ),
        "the sixteenth distinct destination has no slot left"
    );
    let listed = fixture
        .store
        .list_payout_destinations(allocation_id)
        .expect("list destinations");
    assert_eq!(listed.len(), 16);
    assert_eq!(listed[0], (0, community.to_string()));
    assert_eq!(
        listed[15],
        (15, "0x000000000000000000000000000000000000000f".to_string())
    );

    // Slots are per allocation, so a second allocation starts empty.
    let other = consume_allocation(&fixture.market, "vault:finding-collateral-2", LISTING_ID);
    assert!(fixture
        .store
        .list_payout_destinations(&other)
        .expect("empty allocation")
        .is_empty());
    assert_eq!(
        fixture
            .store
            .admit_payout_destination(&other, "0x0000000000000000000000000000000000000001", NOW)
            .expect("admit on a fresh allocation")
            .slot_index,
        1
    );
}

#[test]
fn schema_shape_is_verified_on_every_open() {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    {
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        assert!(authority
            .finding_purchase_store()
            .get_reservation("reservation-absent")
            .expect("read on a clean schema")
            .is_none());
    }

    // Drop a lifecycle trigger out of band, the way a partial restore or a
    // hand-edited database would, and confirm the open refuses rather than
    // serving a schema that no longer enforces the lifecycle.
    {
        let raw = rusqlite::Connection::open(&database).expect("open raw connection");
        raw.execute_batch("DROP TRIGGER purchase_reservations_lifecycle;")
            .expect("drop the lifecycle trigger");
    }
    assert!(
        SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
        "a schema that differs from the canonical definition must fail the open"
    );

    // Restoring the canonical schema restores the open: every statement in
    // the schema is an idempotent guard.
    {
        let raw = rusqlite::Connection::open(&database).expect("open raw connection");
        raw.execute_batch(FINDING_PURCHASE_SCHEMA)
            .expect("restore the canonical schema");
    }
    SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen with intact schema");
}
