use std::fs;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_admission_id, compute_allocation_id, FindingAdmission, FindingAuthorityKeyPolicy,
    FindingBondBacking, FindingBondClass, FindingCollateralVault, FindingFeeEvent,
    FindingFeeTerminalBinding, FindingPoolBinding, FINDING_ADMISSION_SCHEMA_V1,
    FINDING_BOND_BACKING_SCHEMA_V1,
};
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

const LISTING_ID: &str = "finding-listing-01";
const NOW: u64 = 1_750_000_000;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    store: SqliteFindingMarketStore,
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
    let store = authority.finding_market_store();
    Fixture {
        _temp: temp,
        _authority: authority,
        store,
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

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn envelope_string<T: serde::Serialize + Clone>(body: &T, signer: &Keypair) -> String {
    let signed = SignedExportEnvelope::sign(body.clone(), signer).expect("sign envelope");
    String::from_utf8(canonical_json_bytes(&signed).expect("canonical envelope"))
        .expect("utf8 envelope")
}

fn publish_finding(
    store: &SqliteFindingMarketStore,
    finding_id: &str,
    topic: &str,
    context_sha256: &str,
    issued_at: u64,
    expires_at: u64,
) -> String {
    let artifact = format!("{{\"finding_id\":\"{finding_id}\",\"topic\":\"{topic}\"}}");
    let outcome = store
        .put_finding(
            &FindingRecordInput {
                finding_id,
                artifact_json: &artifact,
                topic,
                context_sha256,
                issued_at,
                expires_at,
            },
            NOW,
        )
        .expect("put finding");
    assert_eq!(outcome, FindingPutOutcome::Inserted);
    artifact
}

fn backing_body(finding_id: &str, ledger_account: &str) -> FindingBondBacking {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: keypair(21).public_key(),
        seller: keypair(22).public_key(),
        authorization_envelope_sha256: hex64('1'),
        finding_id: finding_id.to_string(),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
        fee_requirement_sha256: hex64('4'),
        fee_schedule_envelope_sha256: hex64('5'),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(500),
        maximum_sale_exposure: usd(450),
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

fn fee_terminal(
    event: FindingFeeEvent,
    amount_units: u64,
    instruction: &str,
    observation: &str,
) -> FindingFeeTerminalBinding {
    FindingFeeTerminalBinding {
        fee_schedule_envelope_sha256: hex64('5'),
        event,
        payer: "seller-42".to_string(),
        amount: usd(amount_units),
        pool_principal_id: "pool:audit".to_string(),
        rail_destination: "rail:venue-ledger:audit-pool".to_string(),
        instruction_sha256: instruction.to_string(),
        observation_sha256: observation.to_string(),
    }
}

fn admission_body(
    finding_id: &str,
    finding_artifact_sha256: &str,
    backing: &FindingBondBacking,
    backing_envelope_sha256: &str,
) -> FindingAdmission {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: keypair(31).public_key(),
        venue_id: "venue-wedge".to_string(),
        finding_id: finding_id.to_string(),
        finding_artifact_sha256: finding_artifact_sha256.to_string(),
        seller_authorization_envelope_sha256: hex64('1'),
        listing_id: LISTING_ID.to_string(),
        listing_envelope_sha256: hex64('2'),
        server_id: "finding-server".to_string(),
        metadata_url: format!("https://venue.example/v1/findings/{finding_id}"),
        pricing_hint_envelope_sha256: hex64('3'),
        capability_scope: format!("finding:{finding_id}"),
        publisher_operator_id: "venue-operator".to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: hex64('5'),
        verifier_report_id: hex64('4'),
        verifier_report_envelope_sha256: hex64('4'),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
        fee_terminals: vec![
            fee_terminal(FindingFeeEvent::Publication, 5, &hex64('6'), &hex64('7')),
            fee_terminal(
                FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                3,
                &hex64('8'),
                &hex64('9'),
            ),
        ],
        backing_allocation_id: backing.allocation_id.clone(),
        backing_envelope_sha256: backing_envelope_sha256.to_string(),
        audit_pool: FindingPoolBinding {
            principal_id: "pool:audit".to_string(),
            rail_destination: "rail:venue-ledger:audit-pool".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolBinding {
            principal_id: "pool:challenge-admin".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
    };
    admission.admission_id = compute_admission_id(&admission).expect("admission id");
    admission
}

fn begin_intent(
    store: &SqliteFindingMarketStore,
    event: &FindingFeeEvent,
    finding_id: &str,
    amount_units: u64,
    instruction: &str,
) -> FindingFeeEventRecord {
    let schedule = hex64('5');
    let amount = usd(amount_units);
    store
        .begin_fee_intent(&FindingFeeIntent {
            fee_schedule_envelope_sha256: &schedule,
            event,
            finding_id,
            listing_id: LISTING_ID,
            payer: "seller-42",
            amount: &amount,
            pool_principal_id: "pool:audit",
            rail_destination: "rail:venue-ledger:audit-pool",
            instruction_sha256: instruction,
        })
        .expect("begin fee intent")
        .record
}

fn reconcile(
    store: &SqliteFindingMarketStore,
    key: &str,
    observation: &str,
    amount_units: u64,
) -> Result<(), FindingMarketStoreError> {
    store.mark_fee_reconciled(
        key,
        observation,
        &usd(amount_units),
        "rail:venue-ledger:audit-pool",
    )
}

#[test]
fn put_finding_round_trips_exact_bytes_and_replays_idempotently() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let artifact = publish_finding(
        &fixture.store,
        &finding_id,
        "regression/topic",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    let served = fixture
        .store
        .get_finding_bytes(&finding_id)
        .expect("get finding")
        .expect("finding present");
    assert_eq!(served, artifact, "served bytes must be byte-identical");
    let replay = fixture
        .store
        .put_finding(
            &FindingRecordInput {
                finding_id: &finding_id,
                artifact_json: &artifact,
                topic: "regression/topic",
                context_sha256: &hex64('c'),
                issued_at: 1_700_000_000,
                expires_at: 1_900_000_000,
            },
            NOW + 10,
        )
        .expect("idempotent replay");
    assert_eq!(replay, FindingPutOutcome::ExactReplay);
}

#[test]
fn put_finding_rejects_conflicting_bytes_for_same_id() {
    let fixture = fixture();
    let finding_id = hex64('a');
    publish_finding(
        &fixture.store,
        &finding_id,
        "regression/topic",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    let conflicting = fixture.store.put_finding(
        &FindingRecordInput {
            finding_id: &finding_id,
            artifact_json: "{\"finding_id\":\"other bytes\"}",
            topic: "regression/topic",
            context_sha256: &hex64('c'),
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
        },
        NOW,
    );
    assert!(
        matches!(conflicting, Err(FindingMarketStoreError::Conflict(_))),
        "conflicting bytes for the same finding id must reject"
    );
}

#[test]
fn search_findings_paginates_and_filters_liveness() {
    let fixture = fixture();
    let context = hex64('c');
    let topic = "regression/topic";
    let artifact_a = publish_finding(
        &fixture.store,
        &hex64('a'),
        topic,
        &context,
        1_700_000_000,
        1_900_000_000,
    );
    let artifact_b = publish_finding(
        &fixture.store,
        &hex64('b'),
        topic,
        &context,
        1_700_000_000,
        1_900_000_000,
    );
    let artifact_d = publish_finding(
        &fixture.store,
        &hex64('d'),
        topic,
        &context,
        1_700_000_000,
        1_900_000_000,
    );
    // Expired at NOW: excluded by the upper liveness bound.
    publish_finding(
        &fixture.store,
        &hex64('e'),
        topic,
        &context,
        1_600_000_000,
        1_700_000_000,
    );
    // Future-issued at NOW: excluded by the lower liveness bound.
    publish_finding(
        &fixture.store,
        &hex64('f'),
        topic,
        &context,
        1_800_000_000,
        1_900_000_000,
    );
    let first_page = fixture
        .store
        .search_findings(None, Some(&context), None, 2, NOW)
        .expect("first page");
    assert_eq!(
        first_page
            .iter()
            .map(|row| row.finding_id.clone())
            .collect::<Vec<_>>(),
        vec![hex64('a'), hex64('b')]
    );
    // Full row equality, not just finding_id, so a column-index swap between
    // the adjacent (topic, context_sha256) or (issued_at, expires_at) pairs
    // would fail this test.
    assert_eq!(
        first_page[0],
        FindingSearchRow {
            finding_id: hex64('a'),
            artifact_sha256: chio_core::sha256_hex(artifact_a.as_bytes()),
            topic: topic.to_string(),
            context_sha256: context.clone(),
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
        }
    );
    assert_eq!(
        first_page[1],
        FindingSearchRow {
            finding_id: hex64('b'),
            artifact_sha256: chio_core::sha256_hex(artifact_b.as_bytes()),
            topic: topic.to_string(),
            context_sha256: context.clone(),
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
        }
    );
    let second_page = fixture
        .store
        .search_findings(None, Some(&context), Some(&hex64('b')), 2, NOW)
        .expect("second page");
    assert_eq!(
        second_page,
        vec![FindingSearchRow {
            finding_id: hex64('d'),
            artifact_sha256: chio_core::sha256_hex(artifact_d.as_bytes()),
            topic: topic.to_string(),
            context_sha256: context.clone(),
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
        }],
        "expired and future-issued findings must not appear, and the \
         surviving row must match on every column"
    );
    let by_topic = fixture
        .store
        .search_findings(Some("regression/"), None, None, 10, NOW)
        .expect("topic prefix page");
    assert_eq!(by_topic.len(), 3);
    let by_wrong_topic = fixture
        .store
        .search_findings(Some("unrelated/"), None, None, 10, NOW)
        .expect("unmatched prefix");
    assert!(by_wrong_topic.is_empty());
    assert!(
        matches!(
            fixture.store.search_findings(None, None, None, 10, NOW),
            Err(FindingMarketStoreError::Invariant(_))
        ),
        "an unfiltered scan must reject"
    );
    assert!(
        matches!(
            fixture
                .store
                .search_findings(None, Some(&context), Some("not-a-cursor"), 10, NOW),
            Err(FindingMarketStoreError::Invariant(_))
        ),
        "a malformed cursor must reject"
    );
}

#[test]
fn recipe_blob_is_content_addressed_and_idempotent() {
    let fixture = fixture();
    let bytes = b"{\"schema\":\"chio.finding.replay-recipe-input.v1\"}".to_vec();
    let digest = chio_core::sha256_hex(&bytes);
    let mismatch = fixture.store.put_recipe_blob(&hex64('a'), &bytes, NOW);
    assert!(
        matches!(mismatch, Err(FindingMarketStoreError::Conflict(_))),
        "a claimed digest that does not match the bytes must reject"
    );
    assert_eq!(
        fixture
            .store
            .put_recipe_blob(&digest, &bytes, NOW)
            .expect("put recipe"),
        FindingPutOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .put_recipe_blob(&digest, &bytes, NOW + 5)
            .expect("replay recipe"),
        FindingPutOutcome::ExactReplay
    );
    assert_eq!(
        fixture
            .store
            .get_recipe_blob(&digest)
            .expect("get recipe")
            .expect("recipe present"),
        bytes
    );
    assert!(fixture
        .store
        .get_recipe_blob(&hex64('b'))
        .expect("absent recipe lookup")
        .is_none());
}

#[test]
fn retained_recipe_dependency_survives_restart_and_rejects_deletion() {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");

    let dependency = b"retained replay dependency".to_vec();
    let digest = chio_core::sha256_hex(&dependency);
    {
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        authority
            .finding_market_store()
            .put_recipe_blob(&digest, &dependency, NOW)
            .expect("retain dependency");
    }

    let raw = rusqlite::Connection::open(&database).expect("open raw connection");
    let delete = raw.execute(
        "DELETE FROM recipe_blobs WHERE canonical_sha256 = ?1",
        [&digest],
    );
    assert!(
        delete.is_err(),
        "the retention trigger must reject deletion"
    );
    drop(raw);

    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen authority");
    assert_eq!(
        authority
            .finding_market_store()
            .get_recipe_blob(&digest)
            .expect("load retained dependency")
            .expect("dependency remains present"),
        dependency
    );
}

#[test]
fn allocation_exclusivity_and_single_consumption() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let collateral = keypair(21);
    let backing = backing_body(&finding_id, "vault:finding-collateral");
    let envelope = envelope_string(&backing, &collateral);
    fixture
        .store
        .register_allocation(&envelope, &backing, NOW)
        .expect("register allocation");
    let duplicate_id = fixture.store.register_allocation(&envelope, &backing, NOW);
    assert!(
        matches!(duplicate_id, Err(FindingMarketStoreError::Conflict(_))),
        "a reused allocation id must reject"
    );
    let second = backing_body(&finding_id, "vault:finding-collateral-2");
    let second_envelope = envelope_string(&second, &collateral);
    let same_triple = fixture
        .store
        .register_allocation(&second_envelope, &second, NOW);
    assert!(
        matches!(same_triple, Err(FindingMarketStoreError::Conflict(_))),
        "a second live allocation for the same finding listing must reject"
    );
    fixture
        .store
        .consume_allocation(&backing.allocation_id)
        .expect("consume once");
    let twice = fixture.store.consume_allocation(&backing.allocation_id);
    assert!(
        matches!(twice, Err(FindingMarketStoreError::Conflict(_))),
        "a second consumption must reject"
    );
    let reuse_after_consume = fixture.store.register_allocation(&envelope, &backing, NOW);
    assert!(
        matches!(
            reuse_after_consume,
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "re-registering a consumed allocation id must reject"
    );
    let snapshot = fixture
        .store
        .get_allocation(&backing.allocation_id)
        .expect("get allocation")
        .expect("allocation present");
    assert_eq!(snapshot.state, FindingAllocationState::Consumed);
    assert_eq!(snapshot.active_admission_id, None);
    assert_eq!(snapshot.accepted_at, NOW);
    assert_eq!(snapshot.backing, backing);
    // With no live allocation left, a fresh allocation id for the same
    // triple registers cleanly.
    fixture
        .store
        .register_allocation(&second_envelope, &second, NOW)
        .expect("register replacement allocation");
    assert!(fixture
        .store
        .get_allocation(&hex64('b'))
        .expect("absent allocation lookup")
        .is_none());
}

#[test]
fn fee_events_are_idempotent_and_reconcile_exactly() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let event = FindingFeeEvent::Publication;
    let record = begin_intent(&fixture.store, &event, &finding_id, 5, &hex64('6'));
    assert_eq!(record.state, FindingFeeState::Intent);
    let replay = begin_intent(&fixture.store, &event, &finding_id, 5, &hex64('6'));
    assert_eq!(
        replay, record,
        "an identical retry returns the existing row"
    );
    let schedule = hex64('5');
    let amount = usd(5);
    let conflicting = fixture.store.begin_fee_intent(&FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule,
        event: &event,
        finding_id: &finding_id,
        listing_id: LISTING_ID,
        payer: "someone-else",
        amount: &amount,
        pool_principal_id: "pool:audit",
        rail_destination: "rail:venue-ledger:audit-pool",
        instruction_sha256: &hex64('6'),
    });
    assert!(
        matches!(conflicting, Err(FindingMarketStoreError::Conflict(_))),
        "conflicting parameters under the same key must reject"
    );
    let wrong_amount = reconcile(&fixture.store, &record.idempotency_key, &hex64('7'), 6);
    assert!(
        matches!(wrong_amount, Err(FindingMarketStoreError::Conflict(_))),
        "a reconciliation with the wrong amount must reject"
    );
    let wrong_destination = fixture.store.mark_fee_reconciled(
        &record.idempotency_key,
        &hex64('7'),
        &usd(5),
        "rail:venue-ledger:elsewhere",
    );
    assert!(
        matches!(wrong_destination, Err(FindingMarketStoreError::Conflict(_))),
        "a reconciliation with the wrong destination must reject"
    );
    reconcile(&fixture.store, &record.idempotency_key, &hex64('7'), 5).expect("reconcile");
    reconcile(&fixture.store, &record.idempotency_key, &hex64('7'), 5)
        .expect("idempotent reconcile replay");
    let different_observation = reconcile(&fixture.store, &record.idempotency_key, &hex64('8'), 5);
    assert!(
        matches!(
            different_observation,
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "a different observation for a reconciled event must reject"
    );
    assert!(
        matches!(
            fixture.store.mark_fee_failed(&record.idempotency_key),
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "a reconciled event cannot fail"
    );
    let stored = fixture
        .store
        .get_fee_event(&record.idempotency_key)
        .expect("get fee event")
        .expect("fee event present");
    assert_eq!(stored.state, FindingFeeState::Reconciled);
    assert_eq!(
        stored.observation_sha256.as_deref(),
        Some(hex64('7').as_str())
    );
    // A failed charge stays retryable: fail, replay the intent, then a
    // later matched observation reconciles it.
    let epoch = FindingFeeEvent::ParticipationEpoch { epoch_index: 0 };
    let failed = begin_intent(&fixture.store, &epoch, &finding_id, 3, &hex64('8'));
    fixture
        .store
        .mark_fee_failed(&failed.idempotency_key)
        .expect("mark failed");
    fixture
        .store
        .mark_fee_failed(&failed.idempotency_key)
        .expect("idempotent failure replay");
    let retried = begin_intent(&fixture.store, &epoch, &finding_id, 3, &hex64('8'));
    assert_eq!(retried.state, FindingFeeState::Failed);
    reconcile(&fixture.store, &failed.idempotency_key, &hex64('9'), 3)
        .expect("failed charge reconciles on retry");
}

#[test]
fn paid_through_epoch_stops_at_gaps() {
    let fixture = fixture();
    let finding_id = hex64('a');
    assert_eq!(
        fixture
            .store
            .paid_through_epoch(&finding_id, LISTING_ID)
            .expect("empty listing"),
        None
    );
    for epoch_index in [0_u64, 1, 3] {
        let event = FindingFeeEvent::ParticipationEpoch { epoch_index };
        let record = begin_intent(&fixture.store, &event, &finding_id, 3, &hex64('8'));
        reconcile(&fixture.store, &record.idempotency_key, &hex64('9'), 3)
            .expect("reconcile epoch");
    }
    // Publication events never count toward participation epochs.
    let publication = begin_intent(
        &fixture.store,
        &FindingFeeEvent::Publication,
        &finding_id,
        5,
        &hex64('6'),
    );
    reconcile(&fixture.store, &publication.idempotency_key, &hex64('7'), 5)
        .expect("reconcile publication");
    assert_eq!(
        fixture
            .store
            .paid_through_epoch(&finding_id, LISTING_ID)
            .expect("gapped listing"),
        Some(1),
        "the gap at epoch 2 stops the contiguous count"
    );
    // A listing whose first reconciled epoch is 1 has not paid epoch 0.
    let other_finding = hex64('b');
    let event = FindingFeeEvent::ParticipationEpoch { epoch_index: 1 };
    let record = begin_intent(&fixture.store, &event, &other_finding, 3, &hex64('8'));
    reconcile(&fixture.store, &record.idempotency_key, &hex64('9'), 3).expect("reconcile epoch 1");
    assert_eq!(
        fixture
            .store
            .paid_through_epoch(&other_finding, LISTING_ID)
            .expect("epoch zero unpaid"),
        None
    );
}

#[test]
fn activate_listing_is_atomic_idempotent_and_supersedes() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let artifact = publish_finding(
        &fixture.store,
        &finding_id,
        "regression/topic",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    let artifact_sha256 = chio_core::sha256_hex(artifact.as_bytes());
    let collateral = keypair(21);
    let venue = keypair(31);
    let backing = backing_body(&finding_id, "vault:finding-collateral");
    let backing_envelope = envelope_string(&backing, &collateral);
    let backing_envelope_sha256 = chio_core::sha256_hex(backing_envelope.as_bytes());
    fixture
        .store
        .register_allocation(&backing_envelope, &backing, NOW)
        .expect("register allocation");
    let publication = begin_intent(
        &fixture.store,
        &FindingFeeEvent::Publication,
        &finding_id,
        5,
        &hex64('6'),
    );
    let epoch_zero = begin_intent(
        &fixture.store,
        &FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
        &finding_id,
        3,
        &hex64('8'),
    );
    reconcile(&fixture.store, &publication.idempotency_key, &hex64('7'), 5)
        .expect("reconcile publication");

    let admission = admission_body(
        &finding_id,
        &artifact_sha256,
        &backing,
        &backing_envelope_sha256,
    );
    let admission_envelope = envelope_string(&admission, &venue);

    // Finalization cannot bypass the durable prepare, even when some fee
    // events already exist. The allocation remains available until the
    // exact activation owns it.
    let unprepared = fixture
        .store
        .activate_listing(&admission_envelope, &admission, NOW);
    assert!(matches!(
        unprepared,
        Err(FindingMarketStoreError::Conflict(ref detail))
            if detail.contains("not durably prepared")
    ));
    assert_eq!(
        fixture
            .store
            .get_allocation(&backing.allocation_id)
            .expect("get unprepared allocation")
            .expect("unprepared allocation present")
            .state,
        FindingAllocationState::Live
    );

    // (i) Prepare claims the allocation before any fee can settle and
    // retains the exact prospective admission. Finalization still refuses
    // an unreconciled fee, leaving the attempt replayable.
    assert_eq!(
        fixture
            .store
            .prepare_listing_activation(&admission_envelope, &admission, NOW)
            .expect("prepare activation"),
        FindingActivationPreparationOutcome::Prepared
    );
    let unreconciled = fixture
        .store
        .activate_listing(&admission_envelope, &admission, NOW);
    assert!(
        matches!(unreconciled, Err(FindingMarketStoreError::Conflict(_))),
        "activation with an unreconciled fee event must reject"
    );
    assert!(fixture
        .store
        .get_current_admission(&finding_id)
        .expect("no admission after failed activation")
        .is_none());
    let live = fixture
        .store
        .get_allocation(&backing.allocation_id)
        .expect("get allocation")
        .expect("allocation present");
    assert_eq!(
        live.state,
        FindingAllocationState::Consumed,
        "the durable prepare must own the allocation before fee settlement"
    );
    let prepared = fixture
        .store
        .get_activation_attempt(&admission.admission_id)
        .expect("get prepare record")
        .expect("prepare record present");
    assert_eq!(prepared.state, FindingActivationAttemptState::Prepared);
    assert_eq!(prepared.envelope_json, admission_envelope);
    assert_eq!(
        fixture
            .store
            .prepare_listing_activation(&admission_envelope, &admission, NOW + 1)
            .expect("replay prepare"),
        FindingActivationPreparationOutcome::PendingReplay
    );
    let conflicting_envelope = envelope_string(&admission, &keypair(32));
    assert!(
        matches!(
            fixture
                .store
                .prepare_listing_activation(&conflicting_envelope, &admission, NOW + 1),
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "the same admission id cannot bind different prepare bytes"
    );

    // A competing admission for the same finding/listing cannot claim a
    // second allocation while the first prepare is pending.
    let second_backing = backing_body(&finding_id, "vault:finding-collateral-2");
    let second_backing_envelope = envelope_string(&second_backing, &collateral);
    let second_backing_sha256 = chio_core::sha256_hex(second_backing_envelope.as_bytes());
    fixture
        .store
        .register_allocation(&second_backing_envelope, &second_backing, NOW + 10)
        .expect("register second allocation");
    let second_admission = admission_body(
        &finding_id,
        &artifact_sha256,
        &second_backing,
        &second_backing_sha256,
    );
    assert_ne!(second_admission.admission_id, admission.admission_id);
    let second_envelope = envelope_string(&second_admission, &venue);
    assert!(matches!(
        fixture
            .store
            .prepare_listing_activation(&second_envelope, &second_admission, NOW + 10),
        Err(FindingMarketStoreError::Conflict(_))
    ));
    assert_eq!(
        fixture
            .store
            .get_allocation(&second_backing.allocation_id)
            .expect("get competing allocation")
            .expect("competing allocation present")
            .state,
        FindingAllocationState::Live,
        "a competing prepare must not consume another allocation"
    );
    assert_eq!(live.active_admission_id, None);

    // (ii) After reconciling, activation succeeds atomically.
    reconcile(&fixture.store, &epoch_zero.idempotency_key, &hex64('9'), 3)
        .expect("reconcile epoch zero");
    assert_eq!(
        fixture
            .store
            .activate_listing(&admission_envelope, &admission, NOW)
            .expect("activate"),
        FindingActivationOutcome::Activated
    );
    let consumed = fixture
        .store
        .get_allocation(&backing.allocation_id)
        .expect("get allocation")
        .expect("allocation present");
    assert_eq!(consumed.state, FindingAllocationState::Consumed);
    assert_eq!(
        consumed.active_admission_id.as_deref(),
        Some(admission.admission_id.as_str()),
        "the consumed allocation must name the admission that encumbers it"
    );
    let current = fixture
        .store
        .get_current_admission(&finding_id)
        .expect("get admission")
        .expect("admission present");
    assert_eq!(current.admission_id, admission.admission_id);
    assert_eq!(current.envelope_json, admission_envelope);
    assert_eq!(current.expires_at, admission.expires_at);
    assert_eq!(current.backing_allocation_id, backing.allocation_id);
    assert_eq!(current.allocation_state, FindingAllocationState::Consumed);
    assert_eq!(
        fixture
            .store
            .get_activation_attempt(&admission.admission_id)
            .expect("get activated attempt")
            .expect("activated attempt present")
            .state,
        FindingActivationAttemptState::Activated
    );

    // (iii) Re-running the same activation replays as a no-op success.
    assert_eq!(
        fixture
            .store
            .prepare_listing_activation(&admission_envelope, &admission, NOW + 5)
            .expect("replay completed prepare"),
        FindingActivationPreparationOutcome::AlreadyActivated
    );
    assert_eq!(
        fixture
            .store
            .activate_listing(&admission_envelope, &admission, NOW + 5)
            .expect("replay activation"),
        FindingActivationOutcome::ExactReplay
    );
    // Conflicting bytes under the same admission id reject.
    let tampered = envelope_string(&admission, &keypair(33));
    assert!(
        matches!(
            fixture
                .store
                .activate_listing(&tampered, &admission, NOW + 5),
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "different bytes under an existing admission id must reject"
    );

    // (iv) A superseding admission (fresh allocation, new admission id)
    // marks the prior admission superseded and becomes current.
    assert_eq!(
        fixture
            .store
            .prepare_listing_activation(&second_envelope, &second_admission, NOW + 20)
            .expect("prepare superseding admission"),
        FindingActivationPreparationOutcome::Prepared
    );
    assert_eq!(
        fixture
            .store
            .activate_listing(&second_envelope, &second_admission, NOW + 20)
            .expect("superseding activation"),
        FindingActivationOutcome::Activated
    );
    let superseding = fixture
        .store
        .get_current_admission(&finding_id)
        .expect("get superseding admission")
        .expect("superseding admission present");
    assert_eq!(
        superseding.admission_id, second_admission.admission_id,
        "the superseding admission is current; the unique active index \
         guarantees the prior row moved to superseded"
    );
    assert_eq!(superseding.envelope_json, second_envelope);
    let old_allocation = fixture
        .store
        .get_allocation(&backing.allocation_id)
        .expect("get superseded allocation")
        .expect("superseded allocation present");
    assert_eq!(old_allocation.state, FindingAllocationState::Consumed);
    assert_eq!(
        old_allocation.active_admission_id, None,
        "a superseded admission no longer actively binds its consumed allocation"
    );
    let new_allocation = fixture
        .store
        .get_allocation(&second_backing.allocation_id)
        .expect("get superseding allocation")
        .expect("superseding allocation present");
    assert_eq!(
        new_allocation.active_admission_id.as_deref(),
        Some(second_admission.admission_id.as_str())
    );

    // (v) Admission and the sales block contend under the same immediate
    // transaction. Once the block lands, a fresh activation cannot
    // consume its collateral or replace the active admission.
    fixture
        ._authority
        .finding_purchase_store()
        .block_new_slots(LISTING_ID, NOW + 21)
        .expect("block listing sales");
    let third_backing = backing_body(&finding_id, "vault:finding-collateral-3");
    let third_backing_envelope = envelope_string(&third_backing, &collateral);
    let third_backing_sha256 = chio_core::sha256_hex(third_backing_envelope.as_bytes());
    fixture
        .store
        .register_allocation(&third_backing_envelope, &third_backing, NOW + 22)
        .expect("register third allocation");
    let third_admission = admission_body(
        &finding_id,
        &artifact_sha256,
        &third_backing,
        &third_backing_sha256,
    );
    let third_envelope = envelope_string(&third_admission, &venue);
    assert!(
        matches!(
            fixture
                .store
                .prepare_listing_activation(&third_envelope, &third_admission, NOW + 23),
            Err(FindingMarketStoreError::Conflict(_))
        ),
        "a live sales block must refuse fresh activation"
    );
    assert_eq!(
        fixture
            .store
            .get_allocation(&third_backing.allocation_id)
            .expect("get third allocation")
            .expect("third allocation present")
            .state,
        FindingAllocationState::Live,
        "the refused activation cannot consume collateral"
    );
    assert_eq!(
        fixture
            .store
            .get_current_admission(&finding_id)
            .expect("get current admission")
            .expect("active admission remains")
            .admission_id,
        second_admission.admission_id,
        "the refused activation cannot supersede the active row"
    );
}

#[test]
fn begin_fee_intent_outcome_discriminates_fresh_pending_and_reconciled() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let event = FindingFeeEvent::Publication;
    let schedule = hex64('5');
    let amount = usd(5);
    let instruction = hex64('6');
    let intent = FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule,
        event: &event,
        finding_id: &finding_id,
        listing_id: LISTING_ID,
        payer: "seller-42",
        amount: &amount,
        pool_principal_id: "pool:audit",
        rail_destination: "rail:venue-ledger:audit-pool",
        instruction_sha256: &instruction,
    };

    let fresh = fixture
        .store
        .begin_fee_intent(&intent)
        .expect("fresh intent");
    assert_eq!(fresh.outcome, FindingFeeIntentOutcome::Inserted);
    assert_eq!(fresh.record.state, FindingFeeState::Intent);

    let pending_replay = fixture
        .store
        .begin_fee_intent(&intent)
        .expect("pending replay");
    assert_eq!(
        pending_replay.outcome,
        FindingFeeIntentOutcome::ExistingIntent
    );
    assert_eq!(pending_replay.record, fresh.record);

    fixture
        .store
        .mark_fee_failed(&fresh.record.idempotency_key)
        .expect("mark failed");
    let failed_replay = fixture
        .store
        .begin_fee_intent(&intent)
        .expect("failed replay");
    assert_eq!(
        failed_replay.outcome,
        FindingFeeIntentOutcome::ExistingIntent,
        "a failed, not-yet-settled intent must not read as already reconciled"
    );

    fixture
        .store
        .mark_fee_reconciled(
            &fresh.record.idempotency_key,
            &hex64('7'),
            &amount,
            "rail:venue-ledger:audit-pool",
        )
        .expect("reconcile");
    let reconciled_replay = fixture
        .store
        .begin_fee_intent(&intent)
        .expect("reconciled replay");
    assert_eq!(
        reconciled_replay.outcome,
        FindingFeeIntentOutcome::AlreadyReconciled,
        "a caller must be able to short-circuit a rail dispatch it already settled"
    );
    assert_eq!(reconciled_replay.record.state, FindingFeeState::Reconciled);

    // Conflicting parameters under the same key still reject regardless of
    // the discriminated outcome shape.
    let conflicting = fixture.store.begin_fee_intent(&FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule,
        event: &event,
        finding_id: &finding_id,
        listing_id: LISTING_ID,
        payer: "someone-else",
        amount: &amount,
        pool_principal_id: "pool:audit",
        rail_destination: "rail:venue-ledger:audit-pool",
        instruction_sha256: &instruction,
    });
    assert!(
        matches!(conflicting, Err(FindingMarketStoreError::Conflict(_))),
        "conflicting parameters under an existing idempotency key must still reject"
    );
}

#[test]
fn corrupted_content_is_caught_on_the_serve_path_and_by_the_explicit_sweep() {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");

    let finding_id = hex64('a');
    {
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        let store = authority.finding_market_store();
        publish_finding(
            &store,
            &finding_id,
            "regression/topic",
            &hex64('c'),
            1_700_000_000,
            1_900_000_000,
        );
        store
            .verify_stored_content_digests()
            .expect("a clean corpus passes the explicit sweep");
    }

    // Tamper with the stored digest directly, bypassing the store's write
    // path and its immutability trigger the way on-disk bit rot or an
    // out-of-band write would. The schema is re-applied afterward (every
    // statement in it is an idempotent guard) so only the corrupted row's
    // content, not the schema shape, differs from canonical.
    {
        let raw = rusqlite::Connection::open(&database).expect("open raw connection");
        raw.execute_batch("DROP TRIGGER findings_immutable;")
            .expect("drop immutability trigger for the tamper");
        let changed = raw
            .execute(
                "UPDATE findings SET artifact_sha256 = ?1 WHERE finding_id = ?2",
                rusqlite::params![hex64('9'), finding_id],
            )
            .expect("corrupt the stored digest");
        assert_eq!(changed, 1, "the tamper must touch exactly the one row");
        raw.execute_batch(FINDING_MARKET_SCHEMA)
            .expect("restore the canonical schema, including the dropped trigger");
    }

    // The schema shape is intact, so the open succeeds: content digests
    // are not swept on the open path.
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open with intact schema");
    let store = authority.finding_market_store();

    // Serving the corrupted row rejects, which is the guarantee that
    // actually protects a caller.
    assert!(
        matches!(
            store.get_finding_bytes(&finding_id),
            Err(FindingMarketStoreError::Invariant(_))
        ),
        "serving a corrupted finding must fail closed"
    );

    // And the explicit sweep finds it without anyone requesting the row.
    assert!(
        matches!(
            store.verify_stored_content_digests(),
            Err(FindingMarketStoreError::Invariant(_))
        ),
        "the explicit sweep must detect corruption in a retained row"
    );
}
