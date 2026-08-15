use std::fs;

use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

const NOW: u64 = 1_750_000_000;

struct Fixture {
    _temp: TempDir,
    database: std::path::PathBuf,
    lock_root: std::path::PathBuf,
    authority: SqliteAuthorityStore,
    store: SqliteFindingRecoveryStore,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("lock root");
    secure(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let store = authority.finding_recovery_store();
    seed_settled_purchase(&store);
    Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        store,
    }
}

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure permissions");
    }
}

fn hex(character: char) -> String {
    character.to_string().repeat(64)
}

fn seed_settled_purchase(store: &SqliteFindingRecoveryStore) {
    let mut connection = store.connection().expect("connection");
    let transaction = store.begin_write(&mut connection).expect("write");
    transaction
        .execute(
            r#"
            INSERT INTO purchase_reservations (
                reservation_id, purchase_intent_id,
                authoritative_payment_operation_id, payer_hex, agent_id,
                finding_id, listing_id, bid_envelope_sha256, ask_digest,
                admission_envelope_sha256, amount_units, currency, expires_at,
                state, created_at, updated_at
            ) VALUES (
                'reservation-recovery', 'intent-recovery', 'payment-recovery',
                ?1, 'agent-recovery', ?2, 'listing-recovery', ?3, ?4, ?5,
                10, 'USD', ?6, 'consumed', ?7, ?7
            )
            "#,
            rusqlite::params![
                hex('1'),
                hex('a'),
                hex('b'),
                hex('c'),
                hex('d'),
                i64::try_from(NOW + 3600).expect("expiry"),
                i64::try_from(NOW).expect("now"),
            ],
        )
        .expect("reservation");
    transaction
        .execute(
            r#"
            INSERT INTO purchase_records (
                purchase_key, reservation_id, record_json, record_sha256,
                delivery_receipt_id, recorded_at
            ) VALUES (?1, 'reservation-recovery', X'7B7D', ?2, 'receipt-original', ?3)
            "#,
            rusqlite::params![
                hex('e'),
                chio_core::sha256_hex(b"{}"),
                i64::try_from(NOW).expect("now"),
            ],
        )
        .expect("purchase record");
    store.commit(transaction).expect("commit");
    store.sync(&connection).expect("sync");
}

fn issuance(max_recoveries: u32) -> FindingRecoveryIssuanceInput<'static> {
    FindingRecoveryIssuanceInput {
        recovery_id: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        finding_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        listing_id: "listing-recovery",
        original_capability_id: "capability-original",
        original_delivery_receipt_id: "receipt-original",
        purchase_key: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        original_subject_key_hex:
            "1111111111111111111111111111111111111111111111111111111111111111",
        max_recoveries,
        issued_at: NOW,
    }
}

#[test]
fn issuance_is_deterministic_and_conflicting_remint_rejects() {
    let fixture = fixture();
    assert_eq!(
        fixture.store.issue(&issuance(2)).expect("issue"),
        FindingRecoveryWriteOutcome::Inserted
    );
    assert_eq!(
        fixture.store.issue(&issuance(2)).expect("reissue"),
        FindingRecoveryWriteOutcome::ExistingSame
    );
    assert!(matches!(
        fixture.store.issue(&issuance(3)),
        Err(FindingRecoveryStoreError::Conflict(_))
    ));
}

#[test]
fn remint_and_restart_share_one_nonresettable_quota() {
    let fixture = fixture();
    fixture.store.issue(&issuance(2)).expect("issue");
    assert_eq!(
        fixture
            .store
            .reserve_attempt(issuance(2).recovery_id, "request-1", 2, NOW + 1)
            .expect("attempt 1"),
        1
    );
    fixture.store.issue(&issuance(2)).expect("same remint");
    assert_eq!(
        fixture
            .store
            .reserve_attempt(issuance(2).recovery_id, "request-2", 2, NOW + 2)
            .expect("attempt 2"),
        2
    );
    assert_eq!(
        fixture
            .store
            .reserve_attempt(issuance(2).recovery_id, "request-1", 2, NOW + 3)
            .expect("idempotent replay"),
        1
    );
    assert!(matches!(
        fixture
            .store
            .reserve_attempt(issuance(2).recovery_id, "request-3", 2, NOW + 3),
        Err(FindingRecoveryStoreError::QuotaExhausted)
    ));

    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("restart");
    let restarted = authority.finding_recovery_store();
    assert!(matches!(
        restarted.reserve_attempt(issuance(2).recovery_id, "request-3", 2, NOW + 4),
        Err(FindingRecoveryStoreError::QuotaExhausted)
    ));
    drop(_temp);
}

#[test]
fn concurrent_attempts_cannot_overdraw_shared_quota() {
    let fixture = fixture();
    fixture.store.issue(&issuance(1)).expect("issue");
    let first = fixture.store.clone();
    let second = fixture.store.clone();
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(move || {
            first.reserve_attempt(issuance(1).recovery_id, "request-concurrent-a", 1, NOW + 1)
        });
        let second = scope.spawn(move || {
            second.reserve_attempt(issuance(1).recovery_id, "request-concurrent-b", 1, NOW + 1)
        });
        [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(FindingRecoveryStoreError::QuotaExhausted)))
            .count(),
        1
    );
}

#[test]
fn receipt_lineage_is_idempotent_and_substitution_resistant() {
    let fixture = fixture();
    fixture.store.issue(&issuance(2)).expect("issue");
    let lineage = FindingRecoveryReceiptLineageInput {
        recovery_receipt_id: "receipt-recovery-1",
        recovery_id: issuance(2).recovery_id,
        original_delivery_receipt_id: "receipt-original",
        purchase_key: issuance(2).purchase_key,
        recorded_at: NOW + 1,
    };
    assert_eq!(
        fixture
            .store
            .record_receipt_lineage(&lineage)
            .expect("record"),
        FindingRecoveryWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .record_receipt_lineage(&lineage)
            .expect("replay"),
        FindingRecoveryWriteOutcome::ExistingSame
    );
    let substituted_purchase_key = hex('9');
    let substituted = FindingRecoveryReceiptLineageInput {
        purchase_key: &substituted_purchase_key,
        ..lineage
    };
    assert!(matches!(
        fixture.store.record_receipt_lineage(&substituted),
        Err(FindingRecoveryStoreError::Conflict(_))
    ));
    let stored = fixture
        .store
        .get_receipt_lineage("receipt-recovery-1")
        .expect("read")
        .expect("lineage");
    assert_eq!(stored.original_delivery_receipt_id, "receipt-original");
}
