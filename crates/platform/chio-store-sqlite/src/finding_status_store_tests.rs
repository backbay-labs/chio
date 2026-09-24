use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

const FEED: &str = "venue-east/finding-status";
const OPERATOR: &str = "venue-east-status-operator";
const NOW: u64 = 1_900_000_000;
const MAX_EPOCH_AGE_SECS: u64 = 300;

struct DurableFixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
}

impl DurableFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        secure_temp_directory(temp.path());
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root).expect("create lock root");
        secure_temp_directory(&lock_root);
        SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
        Self {
            _temp: temp,
            database,
            lock_root,
        }
    }

    fn open(&self) -> SqliteAuthorityStore {
        SqliteAuthorityStore::open_serving(&self.database, &self.lock_root)
            .expect("open serving authority")
    }
}

fn secure_temp_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn hex64(character: char) -> String {
    character.to_string().repeat(64)
}

fn epoch<'a>(
    map_epoch: u64,
    epoch_id: &'a str,
    root_hash: &'a str,
    bytes: &'a [u8],
    key_epoch: u64,
) -> VerifiedFindingStatusEpochInput<'a> {
    VerifiedFindingStatusEpochInput {
        feed_id: FEED,
        operator_id: OPERATOR,
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch,
        epoch_id,
        root_hash,
        signed_epoch_bytes: bytes,
        operator_key: if key_epoch == 1 {
            "operator-key-v1"
        } else {
            "operator-key-v2"
        },
        operator_key_epoch: key_epoch,
        operator_authorization_sha256: if key_epoch == 1 {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        generated_at: NOW + map_epoch,
        valid_until: NOW + map_epoch + 600,
        recorded_at: NOW + map_epoch + 1,
    }
}

fn non_inclusion<'a>(
    map_epoch: u64,
    epoch_id: &'a str,
    root_hash: &'a str,
    finding_id: &'a str,
    bytes: &'a [u8],
) -> VerifiedFindingStatusProofInput<'a> {
    VerifiedFindingStatusProofInput {
        feed_id: FEED,
        operator_id: OPERATOR,
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch,
        epoch_id,
        root_hash,
        finding_id,
        kind: FindingStatusProofKind::NonInclusion,
        proof_bytes: bytes,
        status_value_bytes: None,
        retraction_intent_sha256: None,
        checked_at: NOW + map_epoch + 2,
        valid_until: NOW + map_epoch + 500,
        recorded_at: NOW + map_epoch + 3,
    }
}

fn inclusion<'a>(
    map_epoch: u64,
    epoch_id: &'a str,
    root_hash: &'a str,
    finding_id: &'a str,
    intent_sha256: &'a str,
    bytes: &'a [u8],
) -> VerifiedFindingStatusProofInput<'a> {
    VerifiedFindingStatusProofInput {
        feed_id: FEED,
        operator_id: OPERATOR,
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch,
        epoch_id,
        root_hash,
        finding_id,
        kind: FindingStatusProofKind::Inclusion,
        proof_bytes: bytes,
        status_value_bytes: Some(b"retracted"),
        retraction_intent_sha256: Some(intent_sha256),
        checked_at: NOW + map_epoch + 2,
        valid_until: NOW + map_epoch + 500,
        recorded_at: NOW + map_epoch + 3,
    }
}

/// Facts read back from the store's own public surface, so the shared rule
/// can be run against exactly the state the store decided on.
struct StoredFacts {
    floor_map_epoch: u64,
    operator_authorization_sha256: String,
    epoch_generated_at: u64,
    proof: chio_finding::FindingStatusProofFacts,
}

impl chio_finding::FindingStatusSource for StoredFacts {
    type Error = std::convert::Infallible;

    fn sticky_status(&self) -> Result<Option<chio_finding::FindingStickyStatus>, Self::Error> {
        Ok(None)
    }

    fn floor(&self) -> Result<Option<chio_finding::FindingStatusFloorFacts>, Self::Error> {
        Ok(Some(chio_finding::FindingStatusFloorFacts {
            map_epoch: self.floor_map_epoch,
            operator_authorization_sha256: self.operator_authorization_sha256.clone(),
        }))
    }

    fn proof_at(
        &self,
        _map_epoch: u64,
    ) -> Result<Option<chio_finding::FindingStatusProofFacts>, Self::Error> {
        Ok(Some(self.proof))
    }

    fn epoch_generated_at(&self, _map_epoch: u64) -> Result<Option<u64>, Self::Error> {
        Ok(Some(self.epoch_generated_at))
    }
}

/// The store's decision is the shared rule's verdict on the same durable
/// facts.
///
/// This pins the routing, not the rule: both sides run the same code, so a
/// change to the rule moves both together and is caught by the rule's own
/// tests in chio-finding. What this catches is the drift the seam exists to
/// prevent, a profile deciding legality with a policy of its own.
#[test]
fn the_store_decision_tracks_the_shared_rule_on_identical_facts() {
    let fixture = DurableFixture::new();
    let finding_id = hex64('1');
    let epoch_id = hex64('2');
    let root_hash = hex64('3');
    let authority = fixture.open();
    let store = authority.finding_status_store();
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_id,
            &root_hash,
            br#"{"schema":"chio.finding.status-epoch.v1","map_epoch":1}"#,
            1,
        ))
        .expect("persist epoch");
    store
        .observe_verified_non_inclusion(&non_inclusion(
            1,
            &epoch_id,
            &root_hash,
            &finding_id,
            br#"{"kind":"non_inclusion","map_epoch":1}"#,
        ))
        .expect("persist non-inclusion");

    let current = store.get_current_epoch(FEED).expect("current epoch");
    let proof = store
        .get_latest_proof(FEED, &finding_id)
        .expect("latest proof")
        .expect("proof exists");
    let facts = StoredFacts {
        floor_map_epoch: current.map_epoch,
        operator_authorization_sha256: current.operator_authorization_sha256.clone(),
        epoch_generated_at: current.generated_at,
        proof: chio_finding::FindingStatusProofFacts {
            kind: proof.kind,
            checked_at: proof.checked_at,
            valid_until: proof.valid_until,
        },
    };

    for trusted_now in [NOW + 1, NOW + 100, NOW + 302, NOW + 501, NOW + 900] {
        let admitted_by_store = matches!(
            store.status_for_purchase(FEED, &finding_id, trusted_now, MAX_EPOCH_AGE_SECS),
            Ok(FindingStatusDecision::VerifiedLive(_))
        );
        let admitted_by_rule = matches!(
            chio_finding::decide_finding_status(
                &facts,
                &chio_finding::FindingStatusAdmissionRequest {
                    trusted_now,
                    max_epoch_age_secs: MAX_EPOCH_AGE_SECS,
                    expected_operator_authorization_sha256: None,
                    operator_status_observed_at: None,
                },
            ),
            Ok(chio_finding::FindingStatusVerdict::VerifiedLive)
        );
        assert_eq!(
            admitted_by_store, admitted_by_rule,
            "store and shared rule disagree at {trusted_now}"
        );
    }
}

#[test]
fn floor_epoch_and_non_inclusion_survive_restart_with_exact_bytes() {
    let fixture = DurableFixture::new();
    let finding_id = hex64('1');
    let epoch_id = hex64('2');
    let root_hash = hex64('3');
    let epoch_bytes = br#"{"schema":"chio.finding.status-epoch.v1","map_epoch":1}"#;
    let proof_bytes = br#"{"kind":"non_inclusion","map_epoch":1}"#;
    {
        let authority = fixture.open();
        let store = authority.finding_status_store();
        let epoch = epoch(1, &epoch_id, &root_hash, epoch_bytes, 1);
        assert_eq!(
            store.observe_verified_epoch(&epoch).expect("persist epoch"),
            FindingStatusWriteOutcome::Inserted
        );
        let proof = non_inclusion(1, &epoch_id, &root_hash, &finding_id, proof_bytes);
        store
            .observe_verified_non_inclusion(&proof)
            .expect("persist non-inclusion");
    }

    let authority = fixture.open();
    let store = authority.finding_status_store();
    let current = store.get_current_epoch(FEED).expect("current epoch");
    assert_eq!(current.signed_epoch_bytes, epoch_bytes);
    assert_eq!(current.map_epoch, 1);
    let proof = store
        .get_latest_proof(FEED, &finding_id)
        .expect("latest proof")
        .expect("proof exists");
    assert_eq!(proof.proof_bytes, proof_bytes);
    assert_eq!(proof.signed_epoch_bytes, epoch_bytes);
    assert!(matches!(
        store
            .status_for_purchase(FEED, &finding_id, NOW + 100, MAX_EPOCH_AGE_SECS)
            .expect("fresh decision"),
        FindingStatusDecision::VerifiedLive(_)
    ));
    assert!(matches!(
        store.status_for_purchase(FEED, &finding_id, NOW + 302, MAX_EPOCH_AGE_SECS),
        Err(FindingStatusStoreError::StaleProof { .. })
    ));
    assert!(matches!(
        store.status_for_purchase(FEED, &finding_id, NOW + 501, MAX_EPOCH_AGE_SECS),
        Err(FindingStatusStoreError::StaleProof { .. })
    ));
}

#[test]
// The clock floor is part of the authenticated feed projection, not process memory.
fn trusted_time_high_water_survives_restart_and_rejects_rollback() {
    let fixture = DurableFixture::new();
    let epoch_id = hex64('a');
    let root_hash = hex64('b');
    let high_water = NOW + 100;
    {
        let authority = fixture.open();
        let store = authority.finding_status_store();
        store
            .observe_verified_epoch(&epoch(1, &epoch_id, &root_hash, b"clock-floor-epoch", 1))
            .expect("persist clock floor epoch");
        assert_eq!(
            store
                .observe_trusted_time(FEED, high_water)
                .expect("advance trusted time"),
            FindingStatusWriteOutcome::Inserted
        );
    }

    let authority = fixture.open();
    let store = authority.finding_status_store();
    assert_eq!(
        store
            .observe_trusted_time(FEED, high_water)
            .expect("exact high-water replay"),
        FindingStatusWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store.observe_trusted_time(FEED, high_water - 1),
        Err(FindingStatusStoreError::ClockRollback {
            high_water: retained,
            observed,
            ..
        }) if retained == high_water && observed == high_water - 1
    ));

    let next_epoch_id = hex64('c');
    let next_root_hash = hex64('d');
    assert!(matches!(
        store.observe_verified_epoch(&epoch(
            2,
            &next_epoch_id,
            &next_root_hash,
            b"clock-rollback-epoch",
            1,
        )),
        Err(FindingStatusStoreError::ClockRollback { .. })
    ));
}

#[test]
fn purchase_status_gate_rejects_a_different_operator_authorization() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let epoch_id = hex64('5');
    let root_hash = hex64('6');
    store
        .observe_verified_epoch(&epoch(1, &epoch_id, &root_hash, b"operator-bound-epoch", 1))
        .expect("persist epoch");
    store
        .observe_verified_non_inclusion(&non_inclusion(
            1,
            &epoch_id,
            &root_hash,
            &finding_id,
            b"operator-bound-proof",
        ))
        .expect("persist non-inclusion");

    let mut connection = store.connection().expect("open status connection");
    let transaction = store
        .begin_read(&mut connection)
        .expect("begin status read");
    let error = status_for_purchase_tx(
        &transaction,
        FEED,
        &finding_id,
        NOW + 20,
        MAX_EPOCH_AGE_SECS,
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        None,
    )
    .expect_err("different operator authorization must fail closed");
    assert!(matches!(error, FindingStatusStoreError::Conflict(_)));
}

#[test]
fn imported_inclusion_reconciles_a_matching_local_outbox_intent() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    let epoch_id = hex64('6');
    let root_hash = hex64('7');
    let intent_bytes = b"seller-signed-imported-retraction";
    let intent_sha256 = sha256_hex(intent_bytes);
    let current_epoch = epoch(1, &epoch_id, &root_hash, b"imported-epoch", 1);

    store
        .observe_verified_epoch(&current_epoch)
        .expect("persist imported epoch");
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &finding_id,
            source: FindingRetractionIntentSource::Voluntary,
            intent_bytes,
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist matching local intent");
    let proof = inclusion(
        1,
        &epoch_id,
        &root_hash,
        &finding_id,
        &intent_sha256,
        b"imported-inclusion-proof",
    );
    store
        .observe_verified_inclusion(&proof)
        .expect("import verified inclusion");

    let intent = store
        .get_retraction_intent(&intent_id)
        .expect("load intent")
        .expect("intent exists");
    assert_eq!(intent.state, FindingRetractionIntentState::Published);
    assert_eq!(intent.published_map_epoch, Some(1));
    let leaf = store
        .get_leaf(FEED, &finding_id)
        .expect("load leaf")
        .expect("leaf exists");
    assert_eq!(leaf.local_intent_id.as_deref(), Some(intent_id.as_str()));
    assert!(store
        .list_publication_candidates(
            FEED,
            current_epoch.operator_key,
            current_epoch.operator_authorization_sha256,
            NOW + 10,
            200,
        )
        .expect("query publication cadence")
        .is_empty());
}

#[test]
fn current_inclusion_replaces_the_same_findings_superseded_proof() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_sha256 = hex64('9');
    let epoch_one_id = hex64('a');
    let epoch_one_root = hex64('b');
    let epoch_two_id = hex64('c');
    let epoch_two_root = hex64('d');
    let proof_one = inclusion(
        1,
        &epoch_one_id,
        &epoch_one_root,
        &finding_id,
        &intent_sha256,
        b"inclusion-one",
    );
    store
        .advance_epoch(&FindingStatusEpochAdvance {
            epoch: epoch(1, &epoch_one_id, &epoch_one_root, b"epoch-one", 1),
            leaves: &[],
            proofs: &[proof_one],
        })
        .expect("persist first inclusion");
    let proof_two = inclusion(
        2,
        &epoch_two_id,
        &epoch_two_root,
        &finding_id,
        &intent_sha256,
        b"inclusion-two",
    );
    store
        .advance_epoch(&FindingStatusEpochAdvance {
            epoch: epoch(2, &epoch_two_id, &epoch_two_root, b"epoch-two", 1),
            leaves: &[],
            proofs: &[proof_two],
        })
        .expect("replace inclusion at the current floor");

    let connection = Connection::open(&fixture.database).expect("open proof reader");
    let (count, retained_epoch): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), MAX(map_epoch) FROM finding_status_proofs \
             WHERE feed_id = ?1 AND finding_id = ?2",
            params![FEED, finding_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read retained point proofs");
    assert_eq!((count, retained_epoch), (1, 2));
}

#[test]
fn retained_older_inclusion_becomes_sticky_without_lowering_the_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_sha256 = hex64('9');
    let epoch_one_id = hex64('a');
    let epoch_one_root = hex64('b');
    let epoch_two_id = hex64('c');
    let epoch_two_root = hex64('d');
    let epoch_one = epoch(1, &epoch_one_id, &epoch_one_root, b"retained-epoch-one", 1);
    store
        .observe_verified_epoch(&epoch_one)
        .expect("retain older epoch");
    store
        .observe_verified_epoch(&epoch(
            2,
            &epoch_two_id,
            &epoch_two_root,
            b"current-epoch-two",
            1,
        ))
        .expect("advance current floor");
    let old_retraction = inclusion(
        1,
        &epoch_one_id,
        &epoch_one_root,
        &finding_id,
        &intent_sha256,
        b"authenticated-old-retraction",
    );
    store
        .record_verified_retraction_against_current_floor(&epoch_one, &old_retraction)
        .expect("retain authenticated retraction tombstone");

    assert_eq!(store.get_feed_floor(FEED).expect("floor").map_epoch, 2);
    assert!(matches!(
        store
            .status_for_purchase(FEED, &finding_id, NOW + 20, MAX_EPOCH_AGE_SECS)
            .expect("sticky retraction decision"),
        FindingStatusDecision::Retracted(_)
    ));
}

#[test]
fn conflicting_current_epoch_inclusion_becomes_sticky_without_moving_the_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_sha256 = hex64('9');
    let retained_epoch_id = hex64('a');
    let retained_root = hex64('b');
    let conflicting_epoch_id = hex64('c');
    let conflicting_root = hex64('d');
    store
        .observe_verified_epoch(&epoch(
            1,
            &retained_epoch_id,
            &retained_root,
            b"retained-epoch-one",
            1,
        ))
        .expect("retain current epoch");
    let retraction = inclusion(
        1,
        &conflicting_epoch_id,
        &conflicting_root,
        &finding_id,
        &intent_sha256,
        b"authenticated-current-equivocation",
    );
    let conflicting_epoch = epoch(
        1,
        &conflicting_epoch_id,
        &conflicting_root,
        b"authenticated-current-equivocation-epoch",
        1,
    );
    store
        .record_verified_retraction_against_current_floor(&conflicting_epoch, &retraction)
        .expect("retain authenticated same-epoch retraction tombstone");

    let floor = store.get_feed_floor(FEED).expect("floor");
    assert_eq!(floor.map_epoch, 1);
    assert_eq!(floor.epoch_id, retained_epoch_id);
    assert_eq!(floor.root_hash, retained_root);
    let status = store
        .status_for_purchase(FEED, &finding_id, NOW + 20, MAX_EPOCH_AGE_SECS)
        .expect("sticky retraction decision");
    let FindingStatusDecision::Retracted(status) = status else {
        panic!("same-epoch equivocation must make retraction sticky");
    };
    assert_eq!(
        status.retracted_epoch_id.as_deref(),
        Some(conflicting_epoch_id.as_str())
    );
    assert_eq!(
        status.retracted_root_hash.as_deref(),
        Some(conflicting_root.as_str())
    );
}

#[test]
fn future_epoch_inclusion_becomes_sticky_without_advancing_the_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_sha256 = hex64('9');
    let retained_epoch_id = hex64('a');
    let retained_root = hex64('b');
    let future_epoch_id = hex64('c');
    let future_root = hex64('d');
    store
        .observe_verified_epoch(&epoch(
            1,
            &retained_epoch_id,
            &retained_root,
            b"retained-epoch-one",
            1,
        ))
        .expect("retain current epoch");
    let future_epoch = epoch(
        3,
        &future_epoch_id,
        &future_root,
        b"authenticated-future-epoch",
        1,
    );
    let future_retraction = inclusion(
        3,
        &future_epoch_id,
        &future_root,
        &finding_id,
        &intent_sha256,
        b"authenticated-future-retraction",
    );
    store
        .record_verified_retraction_against_current_floor(&future_epoch, &future_retraction)
        .expect("retain authenticated future retraction tombstone");

    let floor = store.get_feed_floor(FEED).expect("floor");
    assert_eq!(floor.map_epoch, 1);
    assert_eq!(floor.epoch_id, retained_epoch_id);
    assert_eq!(floor.root_hash, retained_root);
    let status = store
        .status_for_purchase(FEED, &finding_id, NOW + 20, MAX_EPOCH_AGE_SECS)
        .expect("sticky future retraction decision");
    let FindingStatusDecision::Retracted(status) = status else {
        panic!("future authenticated retraction must be sticky");
    };
    assert_eq!(status.retracted_map_epoch, Some(3));
    assert_eq!(
        status.retracted_epoch_id.as_deref(),
        Some(future_epoch_id.as_str())
    );
    assert_eq!(
        status.retracted_root_hash.as_deref(),
        Some(future_root.as_str())
    );
    assert_eq!(
        store
            .observe_verified_epoch(&future_epoch)
            .expect("advance to retained future epoch"),
        FindingStatusWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .get_feed_floor(FEED)
            .expect("advanced floor")
            .map_epoch,
        3
    );
    assert!(matches!(
        store
            .status_for_purchase(FEED, &finding_id, NOW + 20, MAX_EPOCH_AGE_SECS)
            .expect("sticky retraction after floor advance"),
        FindingStatusDecision::Retracted(_)
    ));
}

#[test]
fn atomic_retraction_classification_uses_the_latest_durable_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_sha256 = hex64('9');
    let epoch_one_id = hex64('a');
    let epoch_one_root = hex64('b');
    let epoch_two_id = hex64('c');
    let epoch_two_root = hex64('d');
    let retained_epoch_two_id = hex64('1');
    let retained_epoch_two_root = hex64('2');
    let epoch_three_id = hex64('e');
    let epoch_three_root = hex64('f');
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_one_id,
            &epoch_one_root,
            b"atomic-floor-one",
            1,
        ))
        .expect("retain first floor");
    let superseded_epoch = epoch(
        2,
        &epoch_two_id,
        &epoch_two_root,
        b"atomic-superseded-epoch",
        1,
    );
    let retraction = inclusion(
        2,
        &epoch_two_id,
        &epoch_two_root,
        &finding_id,
        &intent_sha256,
        b"atomic-superseded-retraction",
    );
    store
        .observe_verified_epoch(&epoch(
            2,
            &retained_epoch_two_id,
            &retained_epoch_two_root,
            b"atomic-retained-epoch-two",
            1,
        ))
        .expect("retain a conflicting second epoch");
    store
        .observe_verified_epoch(&epoch(
            3,
            &epoch_three_id,
            &epoch_three_root,
            b"atomic-floor-three",
            1,
        ))
        .expect("advance floor before retraction persistence");

    store
        .record_verified_retraction_against_current_floor(&superseded_epoch, &retraction)
        .expect("reclassify and retain authenticated retraction");

    assert_eq!(store.get_feed_floor(FEED).expect("floor").map_epoch, 3);
    assert!(matches!(
        store
            .status_for_purchase(FEED, &finding_id, NOW + 20, MAX_EPOCH_AGE_SECS)
            .expect("sticky retraction decision"),
        FindingStatusDecision::Retracted(_)
    ));
}

#[test]
fn cadence_enumerates_live_proofs_displaced_or_expired_at_the_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('1');
    let epoch_one_id = hex64('2');
    let epoch_one_root = hex64('3');
    let epoch_one = epoch(1, &epoch_one_id, &epoch_one_root, b"epoch-one", 1);
    let proof_one = non_inclusion(1, &epoch_one_id, &epoch_one_root, &finding_id, b"proof-one");
    store
        .advance_epoch(&FindingStatusEpochAdvance {
            epoch: epoch_one,
            leaves: &[],
            proofs: &[proof_one],
        })
        .expect("persist first live proof");
    assert!(store
        .list_non_inclusion_refresh_candidates(
            FEED,
            epoch_one.operator_key,
            epoch_one.operator_authorization_sha256,
            1_000,
            NOW + 10,
            200,
        )
        .expect("fresh candidates")
        .is_empty());
    let shortened_freshness = store
        .list_non_inclusion_refresh_candidates(
            FEED,
            epoch_one.operator_key,
            epoch_one.operator_authorization_sha256,
            5,
            NOW + 10,
            200,
        )
        .expect("shortened freshness candidates");
    assert_eq!(shortened_freshness.len(), 1);
    assert_eq!(shortened_freshness[0].finding_id, finding_id);

    let epoch_two_id = hex64('4');
    let epoch_two_root = hex64('5');
    store
        .observe_verified_epoch(&epoch(2, &epoch_two_id, &epoch_two_root, b"epoch-two", 1))
        .expect("advance feed floor");
    let displaced = store
        .list_non_inclusion_refresh_candidates(
            FEED,
            epoch_one.operator_key,
            epoch_one.operator_authorization_sha256,
            1_000,
            NOW + 10,
            200,
        )
        .expect("displaced candidates");
    assert_eq!(displaced.len(), 1);
    assert_eq!(displaced[0].finding_id, finding_id);
    assert_eq!(displaced[0].map_epoch, 1);

    let proof_two = non_inclusion(2, &epoch_two_id, &epoch_two_root, &finding_id, b"proof-two");
    store
        .observe_verified_non_inclusion(&proof_two)
        .expect("refresh live proof");
    let connection = Connection::open(&fixture.database).expect("open proof cache reader");
    let retained: Vec<i64> = connection
        .prepare(
            "SELECT map_epoch FROM finding_status_proofs \
             WHERE feed_id = ?1 AND finding_id = ?2 AND proof_kind = 'non_inclusion' \
             ORDER BY map_epoch",
        )
        .expect("prepare retained proof query")
        .query_map(params![FEED, finding_id], |row| row.get(0))
        .expect("query retained proofs")
        .collect::<Result<_, _>>()
        .expect("collect retained proofs");
    assert_eq!(retained, vec![2]);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM finding_status_epochs", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count retained signed epochs"),
        2
    );
    assert!(connection
        .execute(
            "DELETE FROM finding_status_proofs WHERE feed_id = ?1 AND finding_id = ?2",
            params![FEED, finding_id],
        )
        .is_err());
    assert!(store
        .list_non_inclusion_refresh_candidates(
            FEED,
            epoch_one.operator_key,
            epoch_one.operator_authorization_sha256,
            1_000,
            NOW + 10,
            200,
        )
        .expect("refreshed candidates")
        .is_empty());
    let expired = store
        .list_non_inclusion_refresh_candidates(
            FEED,
            epoch_one.operator_key,
            epoch_one.operator_authorization_sha256,
            1_000,
            proof_two.valid_until,
            200,
        )
        .expect("expired candidates");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].finding_id, finding_id);
    assert_eq!(expired[0].map_epoch, 2);
}

#[test]
fn cadence_does_not_reschedule_published_inclusions_after_operator_changes() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let live_finding_id = hex64('1');
    let retracted_finding_id = hex64('2');
    let intent_id = hex64('3');
    let epoch_id = hex64('4');
    let root_hash = hex64('5');
    let intent_bytes = b"seller-signed-retraction";
    let intent_sha256 = sha256_hex(intent_bytes);
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &retracted_finding_id,
            source: FindingRetractionIntentSource::Voluntary,
            intent_bytes,
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist retraction intent");
    let signed_epoch = epoch(1, &epoch_id, &root_hash, b"epoch-one", 1);
    let live_proof = non_inclusion(1, &epoch_id, &root_hash, &live_finding_id, b"live-proof");
    let retracted_proof = inclusion(
        1,
        &epoch_id,
        &root_hash,
        &retracted_finding_id,
        &intent_sha256,
        b"retracted-proof",
    );
    let leaf = VerifiedFindingStatusLeafInput {
        finding_id: &retracted_finding_id,
        status_value_bytes: b"retracted",
        retraction_intent_sha256: &intent_sha256,
        local_intent_id: Some(&intent_id),
    };
    store
        .advance_epoch(&FindingStatusEpochAdvance {
            epoch: signed_epoch,
            leaves: &[leaf],
            proofs: &[live_proof, retracted_proof],
        })
        .expect("publish both proof kinds");

    let publication_candidates = |operator_key: &str, authorization: &str| {
        store
            .list_publication_candidates(FEED, operator_key, authorization, NOW + 10, 200)
            .expect("query publication cadence")
    };
    let live_candidates = |operator_key: &str, authorization: &str| {
        store
            .list_non_inclusion_refresh_candidates(
                FEED,
                operator_key,
                authorization,
                1_000,
                NOW + 10,
                200,
            )
            .expect("query live-proof cadence")
    };
    assert!(publication_candidates(
        signed_epoch.operator_key,
        signed_epoch.operator_authorization_sha256,
    )
    .is_empty());
    assert!(live_candidates(
        signed_epoch.operator_key,
        signed_epoch.operator_authorization_sha256,
    )
    .is_empty());

    for (operator_key, authorization) in [
        ("operator-key-v2", hex64('b')),
        (signed_epoch.operator_key, hex64('c')),
    ] {
        let published = publication_candidates(operator_key, &authorization);
        assert!(published.is_empty());
        let live = live_candidates(operator_key, &authorization);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].finding_id, live_finding_id);
    }
}

#[test]
fn status_writes_advance_the_rollback_protected_projection() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('1');
    let epoch_id = hex64('2');
    let root_hash = hex64('3');
    let epoch = epoch(1, &epoch_id, &root_hash, b"signed-epoch", 1);
    store
        .observe_verified_epoch(&epoch)
        .expect("persist rollback-protected epoch");
    let proof = non_inclusion(1, &epoch_id, &root_hash, &finding_id, b"non-inclusion");
    store
        .observe_verified_non_inclusion(&proof)
        .expect("persist rollback-protected proof");

    let connection = Connection::open(&fixture.database).expect("open projection reader");
    let (local, global): (i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM finding_status_projection_commits),
                (SELECT COUNT(*) FROM authority_global_commits
                 WHERE projection_kind = 'finding_status'
                   AND projection_key = 'status')
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read status projection coverage");
    assert_eq!(local, 2);
    assert_eq!(global, 2);
}

#[test]
fn exact_status_artifacts_replay_at_a_later_observation_time() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('1');
    let epoch_id = hex64('2');
    let root_hash = hex64('3');
    let epoch_bytes = br#"{"schema":"chio.finding.status-epoch.v1","map_epoch":1}"#;
    let proof_bytes = br#"{"kind":"non_inclusion","map_epoch":1}"#;
    let epoch = epoch(1, &epoch_id, &root_hash, epoch_bytes, 1);
    let proof = non_inclusion(1, &epoch_id, &root_hash, &finding_id, proof_bytes);

    assert_eq!(
        store
            .advance_epoch(&FindingStatusEpochAdvance {
                epoch,
                leaves: &[],
                proofs: &[proof],
            })
            .expect("persist artifacts"),
        FindingStatusWriteOutcome::Inserted
    );

    let mut later_epoch = epoch;
    later_epoch.recorded_at += 10;
    let mut later_proof = proof;
    later_proof.recorded_at += 10;
    assert_eq!(
        store
            .advance_epoch(&FindingStatusEpochAdvance {
                epoch: later_epoch,
                leaves: &[],
                proofs: &[later_proof],
            })
            .expect("replay exact artifacts"),
        FindingStatusWriteOutcome::ExactReplay
    );
}

#[test]
fn exact_retraction_intent_replay_retains_the_first_server_time() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    let input = FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: FEED,
        operator_id: OPERATOR,
        finding_id: &finding_id,
        source: FindingRetractionIntentSource::Voluntary,
        intent_bytes: b"seller-signed-retraction",
        issued_at: NOW + 1,
        inclusion_deadline: NOW + 500,
        created_at: NOW + 2,
    };
    assert_eq!(
        store.issue_retraction_intent(&input).expect("issue intent"),
        FindingStatusWriteOutcome::Inserted
    );
    let replay = FindingRetractionIntentInput {
        created_at: NOW + 20,
        ..input
    };
    assert_eq!(
        store
            .issue_retraction_intent(&replay)
            .expect("replay at a later server time"),
        FindingStatusWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .get_retraction_intent(&intent_id)
            .expect("load intent")
            .expect("intent exists")
            .created_at,
        NOW + 2
    );
}

#[test]
fn new_retraction_intent_checks_liveness_inside_the_write_transaction() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    let input = FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: FEED,
        operator_id: OPERATOR,
        finding_id: &finding_id,
        source: FindingRetractionIntentSource::Voluntary,
        intent_bytes: b"seller-signed-retraction",
        issued_at: NOW + 1,
        inclusion_deadline: NOW + 500,
        created_at: NOW + 1,
    };
    let liveness = FindingRetractionIntentCommitLiveness {
        valid_from: NOW,
        valid_until: NOW + 1_000,
    };
    assert!(matches!(
        store.issue_retraction_intent_with_commit_clock(&input, liveness, || NOW + 500),
        Err(FindingStatusStoreError::Conflict(_))
    ));
    assert!(store
        .get_retraction_intent(&intent_id)
        .expect("load rejected intent")
        .is_none());

    assert_eq!(
        store
            .issue_retraction_intent_with_commit_clock(&input, liveness, || NOW + 2)
            .expect("commit while every liveness bound still holds"),
        FindingStatusWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .get_retraction_intent(&intent_id)
            .expect("load committed intent")
            .expect("intent exists")
            .created_at,
        NOW + 2
    );
    assert_eq!(
        store
            .issue_retraction_intent_with_commit_clock(
                &input,
                FindingRetractionIntentCommitLiveness {
                    valid_from: NOW,
                    valid_until: NOW + 400,
                },
                || panic!("exact replay must not consult expired admission material"),
            )
            .expect("recover exact replay after the commit boundary"),
        FindingStatusWriteOutcome::ExactReplay
    );
}

#[test]
fn voluntary_intent_commit_advances_and_obeys_the_durable_clock_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    store
        .observe_verified_epoch(&epoch(
            1,
            &hex64('a'),
            &hex64('b'),
            b"voluntary-clock-epoch",
            1,
        ))
        .expect("establish feed floor");
    store
        .observe_trusted_time(FEED, NOW + 50)
        .expect("advance feed time");
    let input = FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: FEED,
        operator_id: OPERATOR,
        finding_id: &finding_id,
        source: FindingRetractionIntentSource::Voluntary,
        intent_bytes: b"seller-signed-retraction",
        issued_at: NOW + 1,
        inclusion_deadline: NOW + 500,
        created_at: NOW + 1,
    };
    let liveness = FindingRetractionIntentCommitLiveness {
        valid_from: NOW,
        valid_until: NOW + 1_000,
    };
    let rollback = store
        .issue_retraction_intent_with_commit_clock(&input, liveness, || NOW + 40)
        .expect_err("regressed voluntary commit time must reject");
    assert!(matches!(
        rollback,
        FindingStatusStoreError::ClockRollback {
            high_water,
            observed,
            ..
        } if high_water == NOW + 50 && observed == NOW + 40
    ));
    assert!(store
        .get_retraction_intent(&intent_id)
        .expect("load rejected intent")
        .is_none());

    store
        .issue_retraction_intent_with_commit_clock(&input, liveness, || NOW + 60)
        .expect("commit at advancing trusted time");
    assert_eq!(
        store
            .get_feed_floor(FEED)
            .expect("load advanced floor")
            .advanced_at,
        NOW + 60
    );
}

#[test]
fn first_epoch_retains_the_pre_epoch_intent_clock() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    let input = FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: FEED,
        operator_id: OPERATOR,
        finding_id: &finding_id,
        source: FindingRetractionIntentSource::Voluntary,
        intent_bytes: b"pre-epoch-retraction",
        issued_at: NOW + 1,
        inclusion_deadline: NOW + 500,
        created_at: NOW + 1,
    };
    store
        .issue_retraction_intent_with_commit_clock(
            &input,
            FindingRetractionIntentCommitLiveness {
                valid_from: NOW,
                valid_until: NOW + 1_000,
            },
            || NOW + 100,
        )
        .expect("commit the intent before any epoch exists");

    let epoch_id = hex64('a');
    let root_hash = hex64('b');
    let rollback = store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_id,
            &root_hash,
            b"pre-epoch-clock-regression",
            1,
        ))
        .expect_err("the first epoch cannot regress the pre-epoch intent clock");
    assert!(matches!(
        rollback,
        FindingStatusStoreError::ClockRollback {
            high_water,
            observed,
            ..
        } if high_water == NOW + 100 && observed == NOW + 2
    ));

    let mut current = epoch(1, &epoch_id, &root_hash, b"pre-epoch-clock-current", 1);
    current.recorded_at = NOW + 101;
    store
        .observe_verified_epoch(&current)
        .expect("a current first epoch establishes the retained floor");
    assert_eq!(
        store
            .get_feed_floor(FEED)
            .expect("load first feed floor")
            .advanced_at,
        NOW + 101
    );
}

#[test]
fn dispatch_eligibility_replay_retains_the_original_authorization_time() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('4');
    let intent_id = hex64('5');
    let evidence = br#"{"schema":"chio.finding.impairment-finality.v1"}"#;
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &finding_id,
            source: FindingRetractionIntentSource::Enforcement,
            intent_bytes: b"signed-enforcement-intent",
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist intent");
    assert_eq!(
        store
            .mark_retraction_dispatch_eligible(
                &intent_id,
                evidence,
                500,
                FindingRetractionIntentCommitLiveness {
                    valid_from: NOW,
                    valid_until: NOW + 1_000,
                },
                || NOW + 3,
            )
            .expect("authorize dispatch"),
        FindingStatusWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .mark_retraction_dispatch_eligible(
                &intent_id,
                evidence,
                500,
                FindingRetractionIntentCommitLiveness {
                    valid_from: NOW,
                    valid_until: NOW + 1,
                },
                || panic!("exact replay must not sample the expired commit clock"),
            )
            .expect("replay the same finality evidence at a later retry clock"),
        FindingStatusWriteOutcome::ExactReplay
    );
    let retained = store
        .get_retraction_intent(&intent_id)
        .expect("load intent")
        .expect("intent remains durable");
    assert_eq!(retained.dispatch_eligible_at, Some(NOW + 3));
    assert_eq!(retained.issued_at, NOW + 3);
    assert_eq!(retained.inclusion_deadline, NOW + 503);
}

#[test]
fn dispatch_eligibility_rechecks_liveness_inside_the_write_transaction() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('8');
    let intent_id = hex64('9');
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &finding_id,
            source: FindingRetractionIntentSource::Enforcement,
            intent_bytes: b"signed-enforcement-intent",
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist intent");

    let refused = store
        .mark_retraction_dispatch_eligible(
            &intent_id,
            b"confirmed-finality",
            50,
            FindingRetractionIntentCommitLiveness {
                valid_from: NOW,
                valid_until: NOW + 100,
            },
            || NOW + 50,
        )
        .expect_err("an inclusion deadline at authority expiry must reject");
    assert!(matches!(refused, FindingStatusStoreError::Conflict(_)));
    let retained = store
        .get_retraction_intent(&intent_id)
        .expect("load waiting intent")
        .expect("intent remains durable");
    assert_eq!(
        retained.state,
        FindingRetractionIntentState::WaitingFinality
    );
    assert!(retained.finality_evidence_bytes.is_none());
    assert!(retained.dispatch_eligible_at.is_none());
}

#[test]
fn dispatch_eligibility_rejects_commit_clock_rollback_inside_the_transaction() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('a');
    let intent_id = hex64('b');
    let epoch_id = hex64('c');
    let root_hash = hex64('d');
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_id,
            &root_hash,
            br#"{"schema":"chio.finding.status-epoch.v1","map_epoch":1}"#,
            1,
        ))
        .expect("establish the feed clock floor");
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &finding_id,
            source: FindingRetractionIntentSource::Enforcement,
            intent_bytes: b"signed-enforcement-intent",
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist intent");
    store
        .observe_trusted_time(FEED, NOW + 50)
        .expect("advance the durable clock floor");

    let refused = store
        .mark_retraction_dispatch_eligible(
            &intent_id,
            b"confirmed-finality",
            50,
            FindingRetractionIntentCommitLiveness {
                valid_from: NOW,
                valid_until: NOW + 1_000,
            },
            || NOW + 40,
        )
        .expect_err("a regressed commit clock must reject");
    assert!(matches!(
        refused,
        FindingStatusStoreError::ClockRollback {
            high_water,
            observed,
            ..
        } if high_water == NOW + 50 && observed == NOW + 40
    ));
    let retained = store
        .get_retraction_intent(&intent_id)
        .expect("load waiting intent")
        .expect("intent remains durable");
    assert_eq!(
        retained.state,
        FindingRetractionIntentState::WaitingFinality
    );
    assert!(retained.finality_evidence_bytes.is_none());
}

#[test]
fn schema_v1_migration_moves_the_inclusion_window_to_finality() {
    let fixture = DurableFixture::new();
    let connection = Connection::open(&fixture.database).expect("open authority database");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER finding_retraction_intents_lifecycle;
            CREATE TRIGGER finding_retraction_intents_lifecycle
            BEFORE UPDATE ON finding_retraction_intents
            WHEN NEW.intent_id <> OLD.intent_id
              OR NEW.source <> OLD.source
              OR NEW.intent_sha256 <> OLD.intent_sha256
              OR NEW.intent_bytes <> OLD.intent_bytes
              OR NEW.issued_at <> OLD.issued_at
              OR NEW.inclusion_deadline <> OLD.inclusion_deadline
              OR NEW.created_at <> OLD.created_at
              OR NOT (
                  (OLD.state = 'waiting_finality' AND NEW.state = 'dispatch_eligible')
                  OR (OLD.state = 'dispatch_eligible' AND NEW.state = 'published')
              )
            BEGIN
                SELECT RAISE(ABORT, 'invalid finding retraction intent transition');
            END;
            "#,
        )
        .expect("restore revision one lifecycle trigger");
    crate::stamp_schema_version(&connection, FINDING_STATUS_SCHEMA_KEY, 1)
        .expect("stamp revision one");
    drop(connection);

    let authority = fixture.open();
    let store = authority.finding_status_store();
    let finding_id = hex64('6');
    let intent_id = hex64('7');
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED,
            operator_id: OPERATOR,
            finding_id: &finding_id,
            source: FindingRetractionIntentSource::Enforcement,
            intent_bytes: b"signed-enforcement-intent",
            issued_at: NOW + 1,
            inclusion_deadline: NOW + 500,
            created_at: NOW + 2,
        })
        .expect("persist intent after migration");
    store
        .mark_retraction_dispatch_eligible(
            &intent_id,
            b"finality",
            500,
            FindingRetractionIntentCommitLiveness {
                valid_from: NOW,
                valid_until: NOW + 1_000,
            },
            || NOW + 40,
        )
        .expect("start inclusion window at finality");

    let retained = store
        .get_retraction_intent(&intent_id)
        .expect("load intent")
        .expect("intent remains durable");
    assert_eq!(retained.issued_at, NOW + 40);
    assert_eq!(retained.inclusion_deadline, NOW + 540);
}

#[test]
fn schema_v2_migration_recreates_bounded_current_proof_retention() {
    let fixture = DurableFixture::new();
    let connection = Connection::open(&fixture.database).expect("open authority database");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER finding_status_proofs_no_delete;
            CREATE TRIGGER finding_status_proofs_no_delete
            BEFORE DELETE ON finding_status_proofs
            BEGIN
                SELECT RAISE(ABORT, 'finding status proof must be retained');
            END;
            "#,
        )
        .expect("restore revision two proof-retention trigger");
    crate::stamp_schema_version(&connection, FINDING_STATUS_SCHEMA_KEY, 2)
        .expect("stamp revision two");
    drop(connection);

    let authority = fixture.open();
    drop(authority);
    let connection = Connection::open(&fixture.database).expect("reopen authority database");
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
             AND name = 'finding_status_proofs_no_delete'",
            [],
            |row| row.get(0),
        )
        .expect("load migrated proof-retention trigger");
    assert!(!trigger_sql.contains("proof_kind <> 'non_inclusion'"));
    assert!(trigger_sql.contains("newer.map_epoch > OLD.map_epoch"));
}

#[test]
fn rollback_and_same_epoch_equivocation_reject_without_moving_floor() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let epoch_one_id = hex64('1');
    let epoch_one_root = hex64('2');
    let epoch_two_id = hex64('3');
    let epoch_two_root = hex64('4');
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_one_id,
            &epoch_one_root,
            b"signed-epoch-one",
            1,
        ))
        .expect("epoch one");
    store
        .observe_verified_epoch(&epoch(
            2,
            &epoch_two_id,
            &epoch_two_root,
            b"signed-epoch-two",
            1,
        ))
        .expect("epoch two");

    let mut rollback_epoch = epoch(1, &epoch_one_id, &epoch_one_root, b"signed-epoch-one", 1);
    rollback_epoch.recorded_at = NOW + 3;
    let rollback = store
        .observe_verified_epoch(&rollback_epoch)
        .expect_err("rollback must reject");
    assert!(matches!(
        rollback,
        FindingStatusStoreError::Rollback {
            current: 2,
            proposed: 1,
            ..
        }
    ));

    let other_root = hex64('5');
    let equivocation = store
        .observe_verified_epoch(&epoch(
            2,
            &epoch_two_id,
            &other_root,
            b"different-signed-epoch-two",
            1,
        ))
        .expect_err("equivocation must reject");
    assert!(matches!(
        equivocation,
        FindingStatusStoreError::Equivocation { map_epoch: 2, .. }
    ));
    assert_eq!(
        store.get_feed_floor(FEED).expect("floor").root_hash,
        epoch_two_root
    );
}

#[test]
fn pending_and_retracted_are_sticky_across_restart_and_contradiction() {
    let fixture = DurableFixture::new();
    let finding_id = hex64('6');
    let intent_id = hex64('7');
    let intent_bytes = br#"{"schema":"chio.finding.retraction-intent.v1"}"#;
    let intent_sha256 = sha256_hex(intent_bytes);
    let epoch_one_id = hex64('8');
    let epoch_one_root = hex64('9');
    let epoch_two_id = hex64('a');
    let epoch_two_root = hex64('b');
    {
        let authority = fixture.open();
        let store = authority.finding_status_store();
        store
            .observe_verified_epoch(&epoch(
                1,
                &epoch_one_id,
                &epoch_one_root,
                b"signed-epoch-one",
                1,
            ))
            .expect("epoch one");
        store
            .issue_retraction_intent(&FindingRetractionIntentInput {
                intent_id: &intent_id,
                feed_id: FEED,
                operator_id: OPERATOR,
                finding_id: &finding_id,
                source: FindingRetractionIntentSource::Voluntary,
                intent_bytes,
                issued_at: NOW + 1,
                inclusion_deadline: NOW + 500,
                created_at: NOW + 2,
            })
            .expect("issue voluntary intent");
        assert!(matches!(
            store
                .status_for_purchase(FEED, &finding_id, NOW + 2, MAX_EPOCH_AGE_SECS)
                .expect("pending decision"),
            FindingStatusDecision::Pending(_)
        ));

        let contradictory = non_inclusion(
            2,
            &epoch_two_id,
            &epoch_two_root,
            &finding_id,
            b"contradictory-proof",
        );
        let error = store
            .advance_epoch(&FindingStatusEpochAdvance {
                epoch: epoch(2, &epoch_two_id, &epoch_two_root, b"signed-epoch-two", 1),
                leaves: &[],
                proofs: &[contradictory],
            })
            .expect_err("pending contradiction must reject");
        assert!(matches!(
            error,
            FindingStatusStoreError::ContradictoryNonInclusion { .. }
        ));
        assert_eq!(store.get_feed_floor(FEED).expect("floor").map_epoch, 1);

        let leaf = VerifiedFindingStatusLeafInput {
            finding_id: &finding_id,
            status_value_bytes: b"retracted",
            retraction_intent_sha256: &intent_sha256,
            local_intent_id: Some(&intent_id),
        };
        let proof = inclusion(
            2,
            &epoch_two_id,
            &epoch_two_root,
            &finding_id,
            &intent_sha256,
            b"inclusion-proof-two",
        );
        store
            .advance_epoch(&FindingStatusEpochAdvance {
                epoch: epoch(2, &epoch_two_id, &epoch_two_root, b"signed-epoch-two", 1),
                leaves: &[leaf],
                proofs: &[proof],
            })
            .expect("publish inclusion");
    }

    let authority = fixture.open();
    let store = authority.finding_status_store();
    assert!(matches!(
        store
            .status_for_purchase(FEED, &finding_id, NOW + 30, MAX_EPOCH_AGE_SECS)
            .expect("retracted decision"),
        FindingStatusDecision::Retracted(_)
    ));
    assert_eq!(
        store
            .get_retraction_intent(&intent_id)
            .expect("load intent")
            .expect("intent exists")
            .state,
        FindingRetractionIntentState::Published
    );

    let epoch_three_id = hex64('c');
    let epoch_three_root = hex64('d');
    let contradictory = non_inclusion(
        3,
        &epoch_three_id,
        &epoch_three_root,
        &finding_id,
        b"contradictory-proof-three",
    );
    let error = store
        .advance_epoch(&FindingStatusEpochAdvance {
            epoch: epoch(
                3,
                &epoch_three_id,
                &epoch_three_root,
                b"signed-epoch-three",
                2,
            ),
            leaves: &[],
            proofs: &[contradictory],
        })
        .expect_err("retracted contradiction must reject");
    assert!(matches!(
        error,
        FindingStatusStoreError::ContradictoryNonInclusion { .. }
    ));
    assert_eq!(store.get_feed_floor(FEED).expect("floor").map_epoch, 2);
}

#[test]
fn missing_floor_or_current_status_evidence_fails_closed_after_restart() {
    let fixture = DurableFixture::new();
    let pending_finding = hex64('e');
    let intent_id = hex64('f');
    {
        let authority = fixture.open();
        let store = authority.finding_status_store();
        store
            .issue_retraction_intent(&FindingRetractionIntentInput {
                intent_id: &intent_id,
                feed_id: FEED,
                operator_id: OPERATOR,
                finding_id: &pending_finding,
                source: FindingRetractionIntentSource::Enforcement,
                intent_bytes: b"signed-enforcement-intent",
                issued_at: NOW + 1,
                inclusion_deadline: NOW + 500,
                created_at: NOW + 2,
            })
            .expect("persist pending intent");
    }
    {
        let authority = fixture.open();
        let store = authority.finding_status_store();
        assert!(matches!(
            store.get_current_epoch(FEED),
            Err(FindingStatusStoreError::MissingFloor { .. })
        ));
        assert!(matches!(
            store
                .status_for_purchase(FEED, &pending_finding, NOW + 10, MAX_EPOCH_AGE_SECS)
                .expect("sticky pending remains a deny"),
            FindingStatusDecision::Pending(_)
        ));

        let epoch_id = hex64('1');
        let root_hash = hex64('2');
        store
            .observe_verified_epoch(&epoch(1, &epoch_id, &root_hash, b"signed-first-epoch", 1))
            .expect("first epoch");
    }
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let unknown_finding = hex64('3');
    assert!(matches!(
        store.status_for_purchase(FEED, &unknown_finding, NOW + 20, MAX_EPOCH_AGE_SECS,),
        Err(FindingStatusStoreError::MissingState { .. })
    ));
}

#[test]
fn key_rotation_advances_one_floor_and_regression_or_substitution_rejects() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let epoch_one_id = hex64('4');
    let epoch_one_root = hex64('5');
    let epoch_two_id = hex64('6');
    let epoch_two_root = hex64('7');
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_one_id,
            &epoch_one_root,
            b"signed-key-epoch-one",
            1,
        ))
        .expect("first operator key");
    store
        .observe_verified_epoch(&epoch(
            2,
            &epoch_two_id,
            &epoch_two_root,
            b"signed-key-epoch-two",
            2,
        ))
        .expect("authorized key rotation");
    let floor = store.get_feed_floor(FEED).expect("rotated floor");
    assert_eq!(floor.map_epoch, 2);
    assert_eq!(floor.operator_key_epoch, 2);
    assert_eq!(floor.operator_id, OPERATOR);

    let epoch_three_id = hex64('8');
    let epoch_three_root = hex64('9');
    let regression = store
        .observe_verified_epoch(&epoch(
            3,
            &epoch_three_id,
            &epoch_three_root,
            b"regressed-key-epoch",
            1,
        ))
        .expect_err("key epoch regression must reject");
    assert!(matches!(regression, FindingStatusStoreError::Invariant(_)));

    let mut substitution = epoch(3, &epoch_three_id, &epoch_three_root, b"substituted-key", 2);
    substitution.operator_key = "different-key-at-same-epoch";
    let error = store
        .observe_verified_epoch(&substitution)
        .expect_err("same-key-epoch substitution must reject");
    assert!(matches!(error, FindingStatusStoreError::Invariant(_)));
    assert_eq!(store.get_feed_floor(FEED).expect("floor").map_epoch, 2);
}

#[test]
fn same_key_authorization_state_update_is_rejected() {
    let fixture = DurableFixture::new();
    let authority = fixture.open();
    let store = authority.finding_status_store();
    let epoch_one_id = hex64('a');
    let epoch_one_root = hex64('b');
    store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_one_id,
            &epoch_one_root,
            b"signed-before-revocation-update",
            1,
        ))
        .expect("first operator authorization");

    let epoch_two_id = hex64('c');
    let epoch_two_root = hex64('d');
    let mut updated = epoch(
        2,
        &epoch_two_id,
        &epoch_two_root,
        b"signed-after-revocation-update",
        1,
    );
    updated.operator_authorization_sha256 =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let error = store
        .observe_verified_epoch(&updated)
        .expect_err("same-key authorization equivocation must fail closed");
    assert!(error
        .to_string()
        .contains("authorization changed without key-epoch rotation"));

    let floor = store.get_feed_floor(FEED).expect("original floor");
    assert_eq!(floor.map_epoch, 1);
    assert_eq!(floor.operator_key_epoch, 1);
    assert_eq!(floor.operator_key, "operator-key-v1");
    assert_ne!(
        floor.operator_authorization_sha256,
        updated.operator_authorization_sha256
    );
}
