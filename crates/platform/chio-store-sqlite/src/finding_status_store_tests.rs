use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

const FEED: &str = "venue-east/finding-status";
const OPERATOR: &str = "venue-east-status-operator";
const NOW: u64 = 1_900_000_000;

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
            .status_for_purchase(FEED, &finding_id, NOW + 100)
            .expect("fresh decision"),
        FindingStatusDecision::VerifiedLive(_)
    ));
    assert!(matches!(
        store.status_for_purchase(FEED, &finding_id, NOW + 501),
        Err(FindingStatusStoreError::StaleProof { .. })
    ));
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
            .mark_retraction_dispatch_eligible(&intent_id, evidence, NOW + 3)
            .expect("authorize dispatch"),
        FindingStatusWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .mark_retraction_dispatch_eligible(&intent_id, evidence, NOW + 30)
            .expect("replay the same finality evidence at a later retry clock"),
        FindingStatusWriteOutcome::ExactReplay
    );
    let retained = store
        .get_retraction_intent(&intent_id)
        .expect("load intent")
        .expect("intent remains durable");
    assert_eq!(retained.dispatch_eligible_at, Some(NOW + 3));
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

    let rollback = store
        .observe_verified_epoch(&epoch(
            1,
            &epoch_one_id,
            &epoch_one_root,
            b"signed-epoch-one",
            1,
        ))
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
                .status_for_purchase(FEED, &finding_id, NOW + 2)
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
            .status_for_purchase(FEED, &finding_id, NOW + 30)
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
                .status_for_purchase(FEED, &pending_finding, NOW + 10)
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
        store.status_for_purchase(FEED, &unknown_finding, NOW + 20),
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
