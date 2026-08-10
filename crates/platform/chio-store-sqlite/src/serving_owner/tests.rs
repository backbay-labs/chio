use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use chio_core::capability::scope::MonetaryAmount;
use chio_core::sha256_hex;
use chio_kernel::budget_store::{
    BudgetAdmissionBinding, BudgetAuthorizationOutcome, BudgetAuthorizeCumulativeApprovalRequest,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetCumulativeApprovalAccountKey, BudgetCumulativeApprovalAuthorizationDecision,
    BudgetCumulativeApprovalRequest, BudgetEventAuthority, BudgetInvocationCaptureDecision,
    BudgetInvocationQuota, BudgetInvocationState, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldRequest,
};
use chio_kernel::{BudgetStore, CanonicalRevocationSet, RevocationStore};
use rusqlite::{params, Connection};
use tempfile::TempDir;

use super::*;

type AdmissionProjection = (i64, Vec<(String, i64)>, Vec<(i64, String)>);

fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_lock_root(&lock_root);
    (temp, database, lock_root)
}

#[test]
fn live_store_verifies_the_configured_database_identity() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");

    authority
        .verify_database_path(&database)
        .expect("configured database matches the serving owner");

    let foreign = temp.path().join("foreign.db");
    File::create(&foreign).expect("create foreign database path");
    assert!(matches!(
        authority.verify_database_path(&foreign),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

/// Tightens a fixture directory to owner-only access. Both `tempfile::tempdir` and
/// `fs::create_dir` inherit the process umask, and `validate_secure_directory`
/// refuses anything group or world writable.
pub(crate) fn secure_directory(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure directory");
    #[cfg(not(unix))]
    let _ = path;
}

pub(crate) fn create_lock_root(lock_root: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(lock_root).expect("create lock root");
}

fn database_snapshot(authority: &SqliteAuthorityStore, database: &Path, target: &Path) {
    let connection = authority.connection.lock().expect("authority connection");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot");
    fs::copy(database, target).expect("copy snapshot");
}

fn restore_database_in_place(database: &Path, snapshot: &Path) {
    let mut input = File::open(snapshot).expect("open snapshot");
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)
        .expect("open database for restore");
    std::io::copy(&mut input, &mut output).expect("restore database");
    output.sync_all().expect("sync restored database");
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display())));
    }
}

fn only_serving_lock(lock_root: &Path) -> PathBuf {
    fs::read_dir(lock_root)
        .expect("read lock root")
        .map(|entry| entry.expect("lock entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .expect("serving lock")
}

fn serving_lock_paths(lock_root: &Path) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(lock_root)
        .expect("read lock root")
        .map(|entry| entry.expect("lock entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn path_identity_marker(database: &Path, lock_root: &Path) -> PathBuf {
    super::path_identity::marker_path(
        lock_root,
        &fs::canonicalize(database).expect("canonical database path"),
    )
    .expect("path identity marker")
}

fn active_authority(authority: &SqliteAuthorityStore) -> BudgetEventAuthority {
    let fence = authority.mutation_fence();
    BudgetEventAuthority {
        authority_id: fence.store_uuid,
        lease_id: fence.lease_id,
        lease_epoch: fence.owner_epoch,
    }
}

fn structured_request(authority: Option<BudgetEventAuthority>) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: "cap-structured".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: "operation-structured".to_string(),
            revocation_set: CanonicalRevocationSet::canonicalize(
                vec!["cap-structured".to_string()],
            )
            .expect("canonical revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-structured".to_string()),
        event_id: Some("event-structured".to_string()),
        authority,
    }
}

fn provision_structured_authority(database: &Path, lock_root: &Path) -> BudgetEventAuthority {
    SqliteAuthorityStore::provision(database, lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(database, lock_root).expect("open serving");
    let active = active_authority(&authority);
    let budget = authority.budget_store();
    assert!(matches!(
        budget
            .authorize_budget_hold(structured_request(Some(active.clone())))
            .expect("authorize structured hold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    drop(budget);
    drop(authority);
    active
}

#[test]
fn joint_store_owns_budget_and_revocation_with_one_fence() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let budget = authority.budget_store();
    let revocation = authority.revocation_store();

    assert!(matches!(
        budget
            .authorize_budget_hold(structured_request(Some(active_authority(&authority))))
            .expect("structured budget write"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(revocation.revoke("cap").expect("revoke"));
    let observation = revocation.observe_revocation("cap").expect("observe");
    assert!(observation.revoked);
    let commit = observation.commit.expect("commit metadata");
    assert_eq!(commit.commit_index, 2);
    assert_eq!(
        commit.authority.authority_id,
        authority.mutation_fence().store_uuid
    );
    assert_eq!(authority.mutation_fence().owner_epoch, 1);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::AlreadyServing(_))
    ));
}

#[test]
fn a_legacy_global_projection_constraint_is_rejected_rather_than_migrated() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let connection = Connection::open(&database).expect("open authority database");
    let table_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("global commit table SQL");
    let legacy_table_sql = table_sql.replace(
        "'baseline', 'admission', 'budget', 'revocation', 'frost', 'payment', 'economic', 'channel_release_publication', 'factor_assignment_authority_set', 'fiscal', 'finding_challenge'",
        "'baseline', 'admission', 'budget', 'revocation'",
    );
    let transaction = connection
        .unchecked_transaction()
        .expect("begin legacy fixture");
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER authority_global_commits_immutable;
            DROP TRIGGER authority_global_commits_no_delete;
            DROP INDEX authority_global_commits_projection;
            ALTER TABLE authority_global_commits
                RENAME TO authority_global_commits_current;
            "#,
        )
        .expect("remove current global commit schema");
    transaction
        .execute_batch(&legacy_table_sql)
        .expect("create legacy global commit table");
    transaction
        .execute_batch(concat!(
            "INSERT INTO authority_global_commits\n",
            "SELECT * FROM authority_global_commits_current;\n",
            "DROP TABLE authority_global_commits_current;\n",
            "CREATE INDEX authority_global_commits_projection\n",
            "ON authority_global_commits(\n",
            "    projection_kind, projection_key, projection_sequence\n",
            ");\n",
            "CREATE TRIGGER authority_global_commits_immutable\n",
            "BEFORE UPDATE ON authority_global_commits\n",
            "BEGIN\n",
            "    SELECT RAISE(ABORT, 'global authority commit is immutable');\n",
            "END;\n",
            "CREATE TRIGGER authority_global_commits_no_delete\n",
            "BEFORE DELETE ON authority_global_commits\n",
            "BEGIN\n",
            "    SELECT RAISE(ABORT, 'global authority commit is immutable');\n",
            "END;",
        ))
        .expect("populate legacy global commit table");
    transaction.commit().expect("commit legacy fixture");

    // Only the canonical schema is accepted; a non-canonical catalog is refused
    // instead of being adapted in place.
    assert!(matches!(
        super::global_commit_chain::initialize_global_commit_schema(&connection),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn budget_only_snapshot_rollback_is_rejected_by_the_global_anchor() {
    let (temp, database, lock_root) = fixture();
    let snapshot = temp.path().join("before-budget.db");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    database_snapshot(&authority, &database, &snapshot);
    authority
        .budget_store()
        .authorize_budget_hold(structured_request(Some(active_authority(&authority))))
        .expect("budget mutation");
    drop(authority);

    restore_database_in_place(&database, &snapshot);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn revocation_only_snapshot_rollback_is_rejected_by_the_global_anchor() {
    let (temp, database, lock_root) = fixture();
    let snapshot = temp.path().join("before-revocation.db");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    database_snapshot(&authority, &database, &snapshot);
    authority
        .revocation_store()
        .revoke("rollback-revocation")
        .expect("revocation mutation");
    drop(authority);

    restore_database_in_place(&database, &snapshot);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn finding_challenge_snapshot_rollback_is_rejected_by_the_global_anchor() {
    use crate::finding_challenge_store::{
        FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass,
        FindingChallengeSubmission,
    };

    let (temp, database, lock_root) = fixture();
    let snapshot = temp.path().join("before-finding-challenge.db");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    database_snapshot(&authority, &database, &snapshot);
    authority
        .finding_challenge_store()
        .submit_challenge(&FindingChallengeSubmission {
            challenge_id: "rollback-challenge",
            finding_id: &"a".repeat(64),
            listing_id: "rollback-listing",
            challenge_envelope_sha256: &sha256_hex(b"rollback-challenge-envelope"),
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(&"b".repeat(64)),
            submitted_at: 1_750_000_000,
        })
        .expect("challenge mutation");
    drop(authority);

    restore_database_in_place(&database, &snapshot);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn finding_market_projection_commits_manually_admitted_buyer_slots() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let purchases = authority.finding_purchase_store();
    let allocation_id = "a".repeat(64);
    purchases
        .register_community_fund_destination(
            &allocation_id,
            "0xcccccccccccccccccccccccccccccccccccccccc",
            1_750_000_000,
        )
        .expect("register community fund");
    let before: String = Connection::open(&database)
        .expect("open projection reader")
        .query_row(
            r#"
            SELECT authority_projection_digest FROM authority_global_commits
            WHERE projection_kind = 'finding_challenge'
            ORDER BY commit_sequence DESC LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .expect("read projection before buyer slot");

    purchases
        .admit_payout_destination(
            &allocation_id,
            "0x000000000000000000000000000000000000002a",
            1_750_000_001,
        )
        .expect("admit buyer payout slot");
    let after: String = Connection::open(&database)
        .expect("open projection reader")
        .query_row(
            r#"
            SELECT authority_projection_digest FROM authority_global_commits
            WHERE projection_kind = 'finding_challenge'
            ORDER BY commit_sequence DESC LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .expect("read projection after buyer slot");

    assert_ne!(
        before, after,
        "an actionable buyer slot must change the committed market projection"
    );
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn finding_market_projection_rejects_v9_snapshot_with_uncommitted_manual_slot() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let allocation_id = "a".repeat(64);
    authority
        .finding_purchase_store()
        .register_community_fund_destination(
            &allocation_id,
            "0xcccccccccccccccccccccccccccccccccccccccc",
            1_750_000_000,
        )
        .expect("register community fund");
    drop(authority);

    // A v9 digest excludes unattached buyer slots, so inserting one offline
    // leaves that legacy digest unchanged even though the current projection
    // must reject the newly capacity-consuming row.
    Connection::open(&database)
        .expect("open authority offline")
        .execute(
            r#"
            INSERT INTO payout_destinations (
                allocation_id, destination, slot_index, admitted_at
            ) VALUES (?1, ?2, 1, ?3)
            "#,
            params![
                allocation_id,
                "0x000000000000000000000000000000000000002a",
                1_750_000_001_i64,
            ],
        )
        .expect("insert uncommitted manual buyer slot");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn finding_challenge_projection_rejects_offline_state_tampering() {
    use crate::finding_challenge_store::{
        FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass,
        FindingChallengeSubmission,
    };

    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    authority
        .finding_challenge_store()
        .submit_challenge(&FindingChallengeSubmission {
            challenge_id: "tamper-challenge",
            finding_id: &"a".repeat(64),
            listing_id: "tamper-listing",
            challenge_envelope_sha256: &sha256_hex(b"tamper-challenge-envelope"),
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(&"b".repeat(64)),
            submitted_at: 1_750_000_000,
        })
        .expect("challenge mutation");
    drop(authority);

    let connection = Connection::open(&database).expect("open authority offline");
    assert_eq!(
        connection
            .execute(
                "UPDATE challenges SET updated_at = updated_at + 1 WHERE challenge_id = ?1",
                ["tamper-challenge"],
            )
            .expect("tamper challenge state"),
        1
    );
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn finding_challenge_projection_covers_retained_outcome_bytes() {
    use crate::finding_challenge_store::{
        FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass,
        FindingChallengeSubmission,
    };

    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    authority
        .finding_challenge_store()
        .submit_challenge(&FindingChallengeSubmission {
            challenge_id: "outcome-tamper-challenge",
            finding_id: &"a".repeat(64),
            listing_id: "outcome-tamper-listing",
            challenge_envelope_sha256: &sha256_hex(b"outcome-tamper-challenge-envelope"),
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(&"b".repeat(64)),
            submitted_at: 1_750_000_000,
        })
        .expect("challenge mutation");
    drop(authority);

    let outcome = br#"{"outcome":"offline-tamper"}"#;
    Connection::open(&database)
        .expect("open authority offline")
        .execute(
            r#"
            INSERT INTO finding_challenge_outcomes (
                outcome_envelope_sha256, challenge_id,
                outcome_envelope_json, recorded_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                sha256_hex(outcome),
                "outcome-tamper-challenge",
                outcome.as_slice(),
                1_750_000_001_i64,
            ],
        )
        .expect("tamper retained outcome");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn budget_database_ahead_of_anchor_recovers_only_a_valid_chain_extension() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let lock = only_serving_lock(&lock_root);
    let prior_anchor = fs::read(&lock).expect("read prior anchor");
    authority
        .budget_store()
        .authorize_budget_hold(structured_request(Some(active_authority(&authority))))
        .expect("budget mutation");
    drop(authority);

    fs::write(&lock, prior_anchor).expect("restore prior anchor");
    File::open(&lock)
        .expect("open anchor")
        .sync_all()
        .expect("sync anchor");
    let recovered = SqliteAuthorityStore::open_serving(&database, &lock_root)
        .expect("recover DB-ahead global chain");
    assert!(recovered
        .budget_store()
        .get_usage("cap-structured", 0)
        .expect("read recovered usage")
        .is_some());
}

#[test]
fn baseline_verification_rejects_live_projection_tampering() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    Connection::open(&database)
        .expect("tamper connection")
        .execute(
            r#"
            UPDATE chio_authority_migrations
            SET completed_index = 2
            WHERE migration_key = 'revocation-admission-authority-v1'
            "#,
            [],
        )
        .expect("tamper baseline projection");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("baseline does not match its live projection")
    ));
}

#[test]
fn initial_provision_refuses_nonempty_legacy_authority_state() {
    let (_temp, database, lock_root) = fixture();
    let legacy = SqliteBudgetStore::open(&database).expect("legacy budget store");
    assert!(legacy
        .try_increment("legacy-capability", 0, Some(1))
        .expect("legacy usage mutation"));
    drop(legacy);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure database mode");

    let error = SqliteAuthorityStore::provision(&database, &lock_root)
        .expect_err("legacy authority state must be rejected");
    assert!(
        matches!(
            &error,
            SqliteServingOwnerError::Invalid(message)
                if message.contains("baseline refuses nonempty safety table")
        ),
        "unexpected error: {error}"
    );

    let connection = Connection::open(&database).expect("reopen refused database");
    assert!(
        !owner_table_exists(&connection).expect("owner table probe"),
        "a refused provision must not leave an owner table behind"
    );
    drop(connection);
    assert_eq!(
        fs::read_dir(&lock_root).expect("read lock root").count(),
        0,
        "a refused provision must not leave a lock file behind"
    );

    let legacy = SqliteBudgetStore::open(&database).expect("legacy budget store still opens");
    assert!(!legacy
        .try_increment("legacy-capability", 0, Some(1))
        .expect("legacy usage survives the refusal"));
    drop(legacy);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure database mode");

    let repeated = SqliteAuthorityStore::provision(&database, &lock_root)
        .expect_err("a refused provision must stay refused rather than wedge");
    assert!(
        matches!(
            &repeated,
            SqliteServingOwnerError::Invalid(message)
                if message.contains("baseline refuses nonempty safety table")
        ),
        "unexpected error: {repeated}"
    );
}

#[test]
fn a_failed_provision_cleans_up_only_what_it_created() {
    let (_temp, database, lock_root) = fixture();
    const STORE_UUID: &str = "018bcfe5-6800-7000-8000-0000000000a1";
    let lock_path = lock_root.join(format!("{STORE_UUID}.lock"));

    let error = {
        let _scope = scope_fixed_authority_ids_for_current_thread(STORE_UUID, Vec::<String>::new())
            .expect("fixed identity scope");
        fs::write(&lock_path, b"occupied").expect("occupy the lock path");
        SqliteAuthorityStore::provision(&database, &lock_root)
            .expect_err("provisioning must fail on an occupied lock path")
    };
    assert!(
        !matches!(error, SqliteServingOwnerError::OutcomeUnknown(_)),
        "unexpected error: {error}"
    );
    assert_eq!(
        fs::read(&lock_path).expect("occupied lock file survives"),
        b"occupied",
        "a failed provision must not remove a lock file it did not create"
    );

    let connection = Connection::open(&database).expect("reopen database");
    assert!(
        !owner_table_exists(&connection).expect("owner table probe"),
        "a failed provision must not leave an owner table behind"
    );
    drop(connection);

    // Nothing was left behind, so the store provisions normally once the
    // occupied path is cleared instead of wedging as a partial provision.
    fs::remove_file(&lock_path).expect("clear the occupied lock path");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("reprovision");
    SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
}

#[test]
fn serving_open_rejects_unjournaled_valid_revocation_commit() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    assert!(authority
        .revocation_store()
        .revoke("journaled-revocation")
        .expect("journaled revoke"));
    drop(authority);

    let mut connection = Connection::open(&database).expect("direct connection");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable foreign keys");
    let transaction = connection.transaction().expect("tamper transaction");
    let next_index: i64 = transaction
        .query_row(
            "SELECT head_index + 1 FROM admission_authority_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("next authority index");
    transaction
        .execute(
            r#"
            INSERT INTO revoked_capabilities (
                capability_id, revoked_at, admission_authority_commit_index
            ) VALUES ('unjournaled-revocation', 42, ?1)
            "#,
            [next_index],
        )
        .expect("insert valid revocation projection");
    transaction
        .execute(
            r#"
            INSERT INTO admission_authority_commits (
                commit_index, kind, capability_id
            ) VALUES (?1, 'revocation', 'unjournaled-revocation')
            "#,
            [next_index],
        )
        .expect("insert valid revocation commit");
    transaction
        .execute(
            "UPDATE admission_authority_meta SET head_index = ?1 WHERE singleton = 1",
            [next_index],
        )
        .expect("advance authority head");
    transaction.commit().expect("commit local mutation");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("projection coverage is not exact")
    ));
}

#[test]
fn provisioned_store_rejects_independent_mutable_opens() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");

    assert!(matches!(
        SqliteBudgetStore::open(&database),
        Err(BudgetStoreError::Fenced {
            expected_epoch: 0,
            actual_epoch: Some(0),
        })
    ));
    assert!(SqliteRevocationStore::open(&database).is_err());
}

#[test]
#[ignore = "child-process serving-owner helper"]
fn serving_owner_child_process() {
    let Some(database) = std::env::var_os("CHIO_TEST_SERVING_DATABASE") else {
        return;
    };
    let lock_root =
        std::env::var_os("CHIO_TEST_SERVING_LOCK_ROOT").expect("child process lock root");
    let ready = std::env::var_os("CHIO_TEST_SERVING_READY").expect("child process ready path");
    let release =
        std::env::var_os("CHIO_TEST_SERVING_RELEASE").expect("child process release path");
    let authority = SqliteAuthorityStore::open_serving(database, lock_root).expect("child owner");
    fs::write(ready, b"ready").expect("signal child readiness");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !Path::new(&release).exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "parent did not release child serving owner"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    drop(authority);
}

#[test]
fn concurrent_process_open_is_fenced_before_serving() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let ready = temp.path().join("child-ready");
    let release = temp.path().join("child-release");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("serving_owner::tests::serving_owner_child_process")
        .arg("--ignored")
        .arg("--nocapture")
        .env("CHIO_TEST_SERVING_DATABASE", &database)
        .env("CHIO_TEST_SERVING_LOCK_ROOT", &lock_root)
        .env("CHIO_TEST_SERVING_READY", &ready)
        .env("CHIO_TEST_SERVING_RELEASE", &release)
        .spawn()
        .expect("spawn serving child");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child process did not acquire the serving owner");
    }

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root);
    fs::write(&release, b"release").expect("release serving child");
    let status = child.wait().expect("wait for serving child");
    assert!(status.success());
    assert!(matches!(
        second,
        Err(SqliteServingOwnerError::AlreadyServing(_))
    ));
}

#[test]
fn stale_serving_epoch_fences_budget_and_revocation_access() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let budget = authority.budget_store();
    let revocation = authority.revocation_store();
    let current = authority.mutation_fence();

    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute(
            r#"
            UPDATE chio_serving_owner
            SET owner_epoch = ?1, lease_id = 'replacement-lease'
            WHERE singleton = 1
            "#,
            params![i64::try_from(current.owner_epoch + 1).expect("epoch")],
        )
        .expect("advance epoch");

    assert!(matches!(
        budget.try_increment("cap", 0, Some(1)),
        Err(BudgetStoreError::Fenced {
            expected_epoch: 1,
            actual_epoch: Some(2),
        })
    ));
    for result in [
        revocation.is_revoked("cap").map(|_| ()),
        revocation.latest_revocation_index().map(|_| ()),
        revocation.list_revocations(10, None).map(|_| ()),
        revocation.observe_revocation("cap").map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(RevocationStoreError::Fenced {
                expected_epoch: 1,
                actual_epoch: Some(2),
            })
        ));
    }
}

#[test]
fn joint_structured_mutations_require_the_exact_active_authority() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let budget = authority.budget_store();
    let active = active_authority(&authority);

    assert!(budget
        .authorize_budget_hold(structured_request(None))
        .is_err());
    let mut forged = active.clone();
    forged.lease_id = "forged-lease".to_string();
    assert!(budget
        .authorize_budget_hold(structured_request(Some(forged)))
        .is_err());
    assert_eq!(budget.max_mutation_event_seq().expect("event head"), 0);

    let request = structured_request(Some(active));
    assert!(matches!(
        budget
            .authorize_budget_hold(request.clone())
            .expect("authorized"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(budget.authorize_budget_hold(request).is_ok());
}

#[test]
fn joint_authorization_replay_uses_stored_revocation_head() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let revocations = authority.revocation_store();
    let mut request = structured_request(Some(active));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("initial observation")
        .commit;
    let budget = authority.budget_store();
    let original = budget
        .authorize_budget_hold(request.clone())
        .expect("authorize");

    assert!(revocations.revoke("unrelated-capability").expect("revoke"));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("new observation")
        .commit;
    assert_eq!(
        budget
            .authorize_budget_hold(request)
            .expect("replay at newer revocation head"),
        original
    );
}

#[test]
fn fresh_joint_authorization_rejects_historical_revocation_fence() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let historical = first
        .revocation_store()
        .observe_revocation("cap-structured")
        .expect("historical observation")
        .commit;
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let mut request = structured_request(Some(active_authority(&second)));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = historical;
    assert!(second
        .budget_store()
        .authorize_budget_hold(request)
        .as_ref()
        .is_err_and(|error| error.to_string().contains("active sqlite authority head")));
}

#[test]
fn serving_lease_history_preserves_only_real_historical_revocation_commits() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let revocations = first.revocation_store();
    assert!(revocations.revoke("unrelated-first").expect("revoke"));
    let historical = revocations
        .observe_revocation("cap-structured")
        .expect("historical observation")
        .commit
        .expect("historical commit");
    {
        let connection = first.connection.lock().expect("connection lock");
        verify_historical_revocation_commit(&connection, &historical)
            .expect("active historical provenance");
    }
    drop(revocations);
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let current = second
        .revocation_store()
        .observe_revocation("cap-structured")
        .expect("current observation")
        .commit
        .expect("current commit");
    let connection = second.connection.lock().expect("connection lock");
    verify_historical_revocation_commit(&connection, &historical)
        .expect("closed lease remains valid");
    verify_historical_revocation_commit(&connection, &current).expect("open lease is valid");

    let leases = connection
        .prepare(
            r#"
            SELECT owner_epoch, start_head_index, end_head_index
            FROM chio_serving_leases ORDER BY owner_epoch
            "#,
        )
        .expect("prepare lease query")
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .expect("query leases")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect leases");
    assert_eq!(leases, vec![(1, 1, Some(2)), (2, 2, None)]);

    let mut forged = historical.clone();
    forged.authority.lease_id = "forged-lease".to_string();
    assert!(verify_historical_revocation_commit(&connection, &forged).is_err());

    let mut nonexistent = historical;
    nonexistent.commit_index = current.commit_index + 1;
    assert!(verify_historical_revocation_commit(&connection, &nonexistent).is_err());
}

#[test]
fn serving_open_rejects_corrupted_lease_history() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    drop(authority);

    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER chio_serving_leases_close_only;
            UPDATE chio_serving_leases SET lease_id = 'forged-lease';
            "#,
        )
        .expect("corrupt lease history");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("active serving lease")
    ));
}

#[test]
fn serving_open_rejects_forged_historical_revocation_provenance() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let revocations = first.revocation_store();
    assert!(revocations.revoke("unrelated-first").expect("revoke"));
    let mut request = structured_request(Some(active_authority(&first)));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("revocation observation")
        .commit;
    first
        .budget_store()
        .authorize_budget_hold(request)
        .expect("authorize hold");
    drop(revocations);
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    drop(second);
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute(
            "UPDATE budget_hold_revocation_commits SET lease_id = 'forged-old-lease'",
            [],
        )
        .expect("corrupt hold provenance");
    connection
        .execute(
            "UPDATE budget_event_revocation_commits SET lease_id = 'forged-old-lease'",
            [],
        )
        .expect("corrupt event provenance");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("forged revocation provenance")
    ));
}

#[test]
fn serving_open_rejects_forged_historical_budget_authority() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let mut request = structured_request(Some(active_authority(&first)));
    first
        .budget_store()
        .authorize_budget_hold(request.clone())
        .expect("authorize hold");
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    request.authority = Some(active_authority(&second));
    let connection = Connection::open(&database).expect("tamper connection");
    let global_head_before: i64 = connection
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("global head");
    connection
        .execute(
            "UPDATE budget_authorization_holds SET lease_id = 'forged-old-lease'",
            [],
        )
        .expect("corrupt hold authority");
    connection
        .execute(
            "UPDATE budget_mutation_events SET lease_id = 'forged-old-lease'",
            [],
        )
        .expect("corrupt event authority");
    assert!(matches!(
        second.budget_store().get_usage("capability-a", 0),
        Err(chio_kernel::BudgetStoreError::OutcomeUnknown(_))
    ));
    assert!(matches!(
        second.budget_store().authorize_budget_hold(request),
        Err(chio_kernel::BudgetStoreError::OutcomeUnknown(_))
    ));
    let global_head_after: i64 = connection
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("global head after tamper");
    assert_eq!(global_head_after, global_head_before);
    drop(connection);
    drop(second);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("forged serving authority")
    ));
}

#[test]
fn revoked_leaf_or_ancestor_is_atomically_denied_without_reservations() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let revocations = authority.revocation_store();
    let budget = authority.budget_store();

    for (suffix, capability_id, revoked_id, members) in [
        (
            "leaf",
            "cap-revoked-leaf",
            "cap-revoked-leaf",
            vec!["cap-revoked-leaf".to_string()],
        ),
        (
            "ancestor",
            "cap-revoked-descendant",
            "cap-revoked-ancestor",
            vec![
                "cap-revoked-ancestor".to_string(),
                "cap-revoked-descendant".to_string(),
            ],
        ),
    ] {
        assert!(revocations.revoke(revoked_id).expect("revoke member"));
        let observation = revocations
            .observe_revocation(capability_id)
            .expect("observe current head")
            .commit;
        let mut request = structured_request(Some(active.clone()));
        request.capability_id = capability_id.to_string();
        request.hold_id = Some(format!("hold-revoked-{suffix}"));
        request.event_id = Some(format!("event-revoked-{suffix}"));
        let admission = request
            .admission_binding
            .as_mut()
            .expect("admission binding");
        admission.operation_id = format!("operation-revoked-{suffix}");
        admission.revocation_set =
            CanonicalRevocationSet::canonicalize(members).expect("canonical members");
        admission.last_observed_revocation = observation;

        assert!(matches!(
            budget
                .authorize_budget_hold(request.clone())
                .expect("durable denial"),
            BudgetAuthorizeHoldDecision::Denied(_)
        ));
        assert!(budget
            .get_usage(capability_id, 0)
            .expect("usage lookup")
            .is_none());
        assert!(budget
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(capability_id, 0))
            .expect("quota lookup")
            .is_none());
        assert!(budget
            .hold_authority(request.hold_id.as_deref().expect("hold id"))
            .expect("hold lookup")
            .is_none());
        let event = budget
            .mutation_event_for_event_id(request.event_id.as_deref().expect("event id"))
            .expect("event lookup")
            .expect("denial event");
        assert_eq!(
            event.authorization_outcome,
            Some(BudgetAuthorizationOutcome::Denied)
        );
        assert_eq!(event.invocation_state_after, BudgetInvocationState::Denied);
        assert_eq!(event.usage_seq, None);
    }
}

#[test]
fn authorization_then_revocation_replays_the_serialized_authorization() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let revocations = authority.revocation_store();
    let budget = authority.budget_store();
    let mut request = structured_request(Some(active));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("initial observation")
        .commit;
    let authorized = budget
        .authorize_budget_hold(request.clone())
        .expect("serialized authorization");
    assert!(matches!(
        authorized,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    assert!(revocations
        .revoke("cap-structured")
        .expect("later revocation"));
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("new observation")
        .commit;
    assert_eq!(
        budget
            .authorize_budget_hold(request)
            .expect("exact serialized replay"),
        authorized
    );
}

#[test]
fn denied_authorization_tombstones_the_hold_identity() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let revocations = authority.revocation_store();
    let budget = authority.budget_store();
    assert!(revocations.revoke("cap-structured").expect("revoke"));
    let mut denied = structured_request(Some(active.clone()));
    denied
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("observation")
        .commit;
    assert!(matches!(
        budget
            .authorize_budget_hold(denied.clone())
            .expect("denied"),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));

    let mut reuse = structured_request(Some(active));
    reuse.capability_id = "cap-other".to_string();
    reuse.event_id = Some("event-other".to_string());
    let admission = reuse.admission_binding.as_mut().expect("admission binding");
    admission.operation_id = "operation-other".to_string();
    admission.revocation_set =
        CanonicalRevocationSet::canonicalize(vec!["cap-other".to_string()]).expect("canonical set");
    admission.last_observed_revocation = revocations
        .observe_revocation("cap-other")
        .expect("current observation")
        .commit;
    let error = budget
        .authorize_budget_hold(reuse)
        .expect_err("denied hold id must remain reserved");
    assert!(error
        .to_string()
        .contains("reused for a different authorization"));
}

#[test]
fn joint_hold_lifecycle_and_event_replays_survive_owner_epoch_rotation() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");

    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let mut authorization = structured_request(Some(active_authority(&first)));
    let revocations = first.revocation_store();
    authorization
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .last_observed_revocation = revocations
        .observe_revocation("cap-structured")
        .expect("revocation observation")
        .commit;
    let first_decision = first
        .budget_store()
        .authorize_budget_hold(authorization.clone())
        .expect("first authorization");
    drop(revocations);
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let second_authority = active_authority(&second);
    assert_eq!(second_authority.lease_epoch, 2);
    authorization.authority = Some(second_authority.clone());
    assert_eq!(
        second
            .budget_store()
            .authorize_budget_hold(authorization)
            .expect("cross-epoch authorization replay"),
        first_decision
    );
    let mut capture = BudgetCaptureInvocationRequest {
        capability_id: "cap-structured".to_string(),
        grant_index: 0,
        hold_id: "hold-structured".to_string(),
        event_id: "event-structured-capture".to_string(),
        trusted_time: None,
        authority: Some(second_authority),
    };
    let captured = match second
        .budget_store()
        .capture_invocation_reservations(capture.clone())
        .expect("cross-epoch capture")
    {
        BudgetInvocationCaptureDecision::Captured(decision) => decision,
        other => panic!("unexpected capture decision: {other:?}"),
    };
    drop(second);

    let third = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("third owner");
    let third_authority = active_authority(&third);
    capture.authority = Some(third_authority.clone());
    assert_eq!(
        third
            .budget_store()
            .capture_invocation_reservations(capture)
            .expect("cross-epoch capture replay"),
        BudgetInvocationCaptureDecision::AlreadyCaptured(captured)
    );
    let mut reconciliation = BudgetReconcileHoldRequest {
        capability_id: "cap-structured".to_string(),
        grant_index: 0,
        exposed_cost_units: 10,
        realized_spend_units: 7,
        hold_id: Some("hold-structured".to_string()),
        event_id: Some("event-structured-reconcile".to_string()),
        authority: Some(third_authority),
    };
    let reconciled = third
        .budget_store()
        .reconcile_budget_hold(reconciliation.clone())
        .expect("cross-epoch terminal mutation");
    drop(third);

    let fourth = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("fourth owner");
    reconciliation.authority = Some(active_authority(&fourth));
    assert_eq!(
        fourth
            .budget_store()
            .reconcile_budget_hold(reconciliation)
            .expect("cross-epoch terminal replay"),
        reconciled
    );
}

#[test]
fn joint_cumulative_approval_survives_owner_epoch_rotation() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let mut authorization = structured_request(Some(active_authority(&first)));
    let operation_id = authorization
        .admission_binding
        .as_ref()
        .expect("admission binding")
        .operation_id
        .clone();
    authorization.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
        operation_id: operation_id.clone(),
        account_key: BudgetCumulativeApprovalAccountKey {
            authority_id: "approval-authority".to_string(),
            owner_id: "approval-owner".to_string(),
            approval_budget_id: "approval-budget".to_string(),
            approval_budget_epoch: 1,
            root_grant_hash: "root-grant".to_string(),
            delegation_root_id: None,
            root_binding_digest: None,
            currency: "USD".to_string(),
        },
        authority_threshold: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        effective_threshold: MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        requested_authorized: MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
    });
    assert!(matches!(
        first
            .budget_store()
            .authorize_budget_hold(authorization.clone())
            .expect("pending cumulative authorization"),
        BudgetAuthorizeHoldDecision::ApprovalRequired(_)
    ));
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let mut approval = BudgetAuthorizeCumulativeApprovalRequest {
        capability_id: authorization.capability_id.clone(),
        grant_index: authorization.grant_index,
        operation_id,
        hold_id: authorization.hold_id.clone().expect("hold id"),
        admission_binding: authorization
            .admission_binding
            .clone()
            .expect("admission binding"),
        approval_set_digest: "b".repeat(64),
        event_id: "event-structured-approval".to_string(),
        authority: Some(active_authority(&second)),
    };
    let approved = second
        .budget_store()
        .authorize_cumulative_approval(approval.clone())
        .expect("cross-epoch approval");
    assert!(matches!(
        approved,
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(_)
    ));
    drop(second);

    let third = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("third owner");
    approval.authority = Some(active_authority(&third));
    let replayed = third
        .budget_store()
        .authorize_cumulative_approval(approval)
        .expect("cross-epoch approval replay");
    assert!(matches!(
        replayed,
        BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(_)
    ));
}

#[test]
fn joint_capture_replays_after_supplemental_authorization_expires() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let budget = authority.budget_store();
    let observation = authority
        .revocation_store()
        .observe_revocation("cap-structured")
        .expect("revocation observation");
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time before epoch")
        .as_secs()
        + 2;
    let mut authorization = structured_request(Some(active.clone()));
    authorization.invocation_quotas = vec![
        BudgetInvocationQuota {
            key: BudgetQuotaKey::grant("cap-structured", 0),
            max_invocations: 1,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
                owner_id: "supplemental-broker".to_string(),
                grant_index: None,
            },
            max_invocations: 1,
        },
    ];
    let admission = authorization
        .admission_binding
        .as_mut()
        .expect("admission binding");
    admission.last_observed_revocation = observation.commit;
    admission.supplemental_verifier_id = Some("supplemental-verifier".to_string());
    admission.supplemental_verifier_config_digest = Some("b".repeat(64));
    admission.supplemental_authorization_artifact_digest = Some("a".repeat(64));
    admission.supplemental_authorization_expires_at = Some(expires_at);
    budget
        .authorize_budget_hold(authorization)
        .expect("authorize supplemental hold");

    let capture = BudgetCaptureInvocationRequest {
        capability_id: "cap-structured".to_string(),
        grant_index: 0,
        hold_id: "hold-structured".to_string(),
        event_id: "event-structured-capture".to_string(),
        trusted_time: None,
        authority: Some(active),
    };
    let captured = match budget
        .capture_invocation_reservations(capture.clone())
        .expect("capture invocation")
    {
        BudgetInvocationCaptureDecision::Captured(decision) => decision,
        other => panic!("unexpected capture decision: {other:?}"),
    };
    let persisted_time: i64 = Connection::open(&database)
        .expect("audit connection")
        .query_row(
            "SELECT trusted_time FROM budget_mutation_events WHERE event_id = ?1",
            params![&capture.event_id],
            |row| row.get(0),
        )
        .expect("persisted trusted time");
    assert!(persisted_time > 0);
    assert!(u64::try_from(persisted_time).expect("trusted time") < expires_at);

    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time before epoch")
            .as_secs()
            >= expires_at
    );
    assert_eq!(
        budget
            .capture_invocation_reservations(capture)
            .expect("replay expired capture"),
        BudgetInvocationCaptureDecision::AlreadyCaptured(captured)
    );
}

#[test]
fn revocations_do_not_create_budget_replication_holes() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let active = active_authority(&authority);
    let budget = authority.budget_store();
    let revocation = authority.revocation_store();

    for suffix in ["one", "two"] {
        if suffix == "two" {
            assert!(revocation.revoke("revoked-between-events").expect("revoke"));
        }
        let capability_id = format!("cap-{suffix}");
        let mut request = structured_request(Some(active.clone()));
        request.capability_id = capability_id.clone();
        request.hold_id = Some(format!("hold-{suffix}"));
        request.event_id = Some(format!("event-{suffix}"));
        let admission = request
            .admission_binding
            .as_mut()
            .expect("admission binding");
        admission.operation_id = format!("operation-{suffix}");
        admission.revocation_set = CanonicalRevocationSet::canonicalize(vec![capability_id])
            .expect("canonical revocation set");
        assert!(matches!(
            budget.authorize_budget_hold(request).expect("budget event"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }

    assert_eq!(budget.max_mutation_event_seq().expect("budget head"), 2);
    assert_eq!(
        revocation
            .latest_revocation_index()
            .expect("authority head"),
        2
    );
    assert_eq!(
        budget.budget_ack_heads().expect("ack heads"),
        vec![(active.authority_id, 2)]
    );
}

#[test]
fn offline_provision_upgrade_is_fenced_and_idempotent() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
    let revocation = authority.revocation_store();
    assert!(revocation.revoke("cap-a").expect("revoke a"));
    assert!(revocation.revoke("cap-b").expect("revoke b"));
    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::AlreadyServing(_))
    ));
    drop(revocation);
    drop(authority);

    let before = admission_projection(&database);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("repeat provision");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("repeat provision twice");
    assert_eq!(admission_projection(&database), before);

    let connection = Connection::open(&database).expect("schema connection");
    crate::stamp_schema_version(&connection, "budget", 3).expect("old budget stamp");
    crate::stamp_schema_version(&connection, "revocation", 1).expect("old revocation stamp");
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("offline upgrade");
    let connection = Connection::open(&database).expect("verify schema connection");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            "budget",
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
            &["capability_grant_budgets"],
        )
        .expect("budget version"),
        BUDGET_STORE_SUPPORTED_SCHEMA_VERSION
    );
    assert_eq!(
        crate::check_schema_version(
            &connection,
            "revocation",
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
            &["revoked_capabilities"],
        )
        .expect("revocation version"),
        REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION
    );
    assert_eq!(admission_projection(&database), before);
}

fn admission_projection(database: &Path) -> AdmissionProjection {
    let connection = Connection::open(database).expect("projection connection");
    let head = connection
        .query_row(
            "SELECT head_index FROM admission_authority_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("authority head");
    let revocations = {
        let mut statement = connection
            .prepare(
                r#"
                SELECT capability_id, admission_authority_commit_index
                FROM revoked_capabilities ORDER BY capability_id
                "#,
            )
            .expect("revocation projection");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("revocation rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect revocations")
    };
    let commits = {
        let mut statement = connection
            .prepare(
                r#"
                SELECT commit_index, kind FROM admission_authority_commits
                ORDER BY commit_index
                "#,
            )
            .expect("commit projection");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("commit rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect commits")
    };
    (head, revocations, commits)
}

#[test]
fn database_symlink_and_hardlink_aliases_are_rejected() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&database, temp.path().join("alias.db"))
            .expect("create symlink");
        assert!(matches!(
            SqliteAuthorityStore::open_serving(temp.path().join("alias.db"), &lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    fs::hard_link(&database, temp.path().join("hardlink.db")).expect("create hard link");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn preprovision_snapshot_cannot_reset_local_path_identity() {
    let (temp, database, lock_root) = fixture();
    let snapshot = temp.path().join("preprovision.db");
    let database_file = create_database_file(&database).expect("create preprovision database");
    database_file
        .sync_all()
        .expect("sync preprovision database");
    drop(database_file);
    fs::copy(&database, &snapshot).expect("snapshot preprovision database");

    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let marker = path_identity_marker(&database, &lock_root);
    assert!(marker.exists());
    let original_locks = serving_lock_paths(&lock_root);
    assert_eq!(original_locks.len(), 1);

    restore_database_in_place(&database, &snapshot);
    let error = SqliteAuthorityStore::provision(&database, &lock_root)
        .expect_err("preprovision rollback must not mint a new identity");
    assert!(
        matches!(
            &error,
            SqliteServingOwnerError::Invalid(message)
                if message.contains("local path identity continuity marker remains")
                    && message.contains("not independent rollback protection")
        ),
        "unexpected error: {error}"
    );
    assert_eq!(serving_lock_paths(&lock_root), original_locks);
    assert!(marker.exists());
    let connection = Connection::open(&database).expect("open restored database");
    assert!(!owner_table_exists(&connection).expect("owner table probe"));
}

#[test]
fn missing_path_identity_migrates_only_after_anchor_proof_and_is_idempotent() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let marker = path_identity_marker(&database, &lock_root);
    fs::remove_file(&marker).expect("simulate crash before marker creation");
    File::open(&lock_root)
        .expect("open lock root")
        .sync_all()
        .expect("sync marker removal");

    SqliteAuthorityStore::provision(&database, &lock_root).expect("migrate marker");
    let migrated = fs::read(&marker).expect("read migrated marker");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("repeat provision");
    assert_eq!(fs::read(&marker).expect("read stable marker"), migrated);
    fs::remove_file(&marker).expect("simulate pre-marker open");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)
        .expect("migrate marker while opening");
    assert!(marker.exists());
    drop(authority);

    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision corrupt fixture");
    let marker = path_identity_marker(&database, &lock_root);
    fs::remove_file(&marker).expect("remove marker before anchor corruption");
    let anchor = only_serving_lock(&lock_root);
    fs::write(&anchor, b"corrupt-anchor").expect("corrupt rollback anchor");
    File::open(&anchor)
        .expect("open corrupt anchor")
        .sync_all()
        .expect("sync corrupt anchor");

    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(!marker.exists());
}

#[test]
fn replaced_or_hardlinked_path_identity_marker_is_rejected() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision hardlink fixture");
    let marker = path_identity_marker(&database, &lock_root);
    fs::hard_link(&marker, lock_root.join("extra-identity-link"))
        .expect("hardlink path identity marker");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("local path identity continuity marker security check")
    ));

    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision replacement fixture");
    let marker = path_identity_marker(&database, &lock_root);
    let replacement = temp.path().join("replacement.identity");
    fs::write(&replacement, fs::read(&marker).expect("read marker"))
        .expect("write replacement marker");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
        .expect("secure replacement mode");
    fs::rename(&replacement, &marker).expect("replace path identity marker");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("local path identity continuity marker inode changed")
    ));
}

#[test]
fn provisioning_rejects_unsafe_database_and_lock_root_modes() {
    let (temp, database, lock_root) = fixture();
    let target = temp.path().join("target.db");
    fs::write(&target, b"").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    std::os::unix::fs::symlink(&target, &database).expect("database symlink");
    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));

    fs::remove_file(&database).expect("remove symlink");
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o777)).expect("unsafe lock root");
    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));

    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700)).expect("safe lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).expect("unsafe db mode");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn serving_open_rejects_noncanonical_projection_members() {
    let (_temp, database, lock_root) = fixture();
    provision_structured_authority(&database, &lock_root);
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("disable checks for corruption fixture");
    connection
        .execute(
            r#"
            UPDATE budget_hold_authorization_artifacts
            SET artifact_digest = ?1 WHERE hold_id = 'hold-structured'
            "#,
            params!["A".repeat(64)],
        )
        .expect("corrupt artifact");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("non-canonical artifact")
    ));

    let (_temp, database, lock_root) = fixture();
    provision_structured_authority(&database, &lock_root);
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute(
            r#"
            UPDATE budget_hold_revocation_members
            SET member_index = 2 WHERE hold_id = 'hold-structured'
            "#,
            [],
        )
        .expect("corrupt revocation order");
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("non-canonical revocation")
    ));
}

#[test]
fn serving_open_rejects_invalid_revocation_commit_metadata() {
    let (_temp, database, lock_root) = fixture();
    let active = provision_structured_authority(&database, &lock_root);
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA ignore_check_constraints = ON;")
        .expect("configure corruption fixture");
    connection
        .execute(
            r#"
            INSERT INTO budget_hold_revocation_commits (
                hold_id, authority_id, lease_id, lease_epoch,
                guarantee_level, commit_index
            ) VALUES ('hold-structured', ?1, ?2, ?3, 'single_node_atomic', 0)
            "#,
            params![
                active.authority_id,
                active.lease_id,
                i64::try_from(active.lease_epoch).expect("lease epoch")
            ],
        )
        .expect("corrupt commit metadata");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn serving_open_rejects_partial_supplemental_projection() {
    let (_temp, database, lock_root) = fixture();
    provision_structured_authority(&database, &lock_root);
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute(
            r#"
            UPDATE budget_authorization_holds
            SET supplemental_verifier_id = 'partial-verifier'
            WHERE hold_id = 'hold-structured'
            "#,
            [],
        )
        .expect("corrupt supplemental projection");
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("incomplete supplemental authority binding")
    ));
}

#[test]
fn normalized_schema_rejects_cross_hold_operations_and_invalid_quota_indices() {
    let (_temp, database, lock_root) = fixture();
    provision_structured_authority(&database, &lock_root);
    let connection = Connection::open(&database).expect("direct connection");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable foreign keys");
    assert!(connection
        .execute(
            r#"
            INSERT INTO budget_invocation_quotas (
                profile, owner_id, grant_index, max_invocations
            ) VALUES ('chio.grant-invocation.v1', 'bad-quota', -1, 1)
            "#,
            [],
        )
        .is_err());
    assert!(connection
        .execute(
            r#"
            INSERT INTO budget_hold_authorization_artifacts (
                hold_id, artifact_index, artifact_digest
            ) VALUES ('hold-structured', 8, ?1)
            "#,
            params!["b".repeat(64)],
        )
        .is_err());
    assert!(connection
        .execute(
            r#"
            INSERT INTO budget_hold_revocation_members (
                hold_id, member_index, capability_id
            ) VALUES ('hold-structured', 256, 'out-of-range')
            "#,
            [],
        )
        .is_err());
    assert!(connection
        .execute(
            r#"
            INSERT INTO budget_hold_revocation_members (
                hold_id, member_index, capability_id
            ) VALUES ('hold-structured', 1, ?1)
            "#,
            params!["x".repeat(513)],
        )
        .is_err());
    connection
        .execute(
            r#"
            INSERT INTO budget_cumulative_approval_accounts (
                authority_id, owner_id, approval_budget_id,
                approval_budget_epoch, root_grant_hash, currency,
                authority_threshold_units
            ) VALUES ('approval-authority', 'owner', 'budget', 1,
                      'root-hash', 'USD', 10)
            "#,
            [],
        )
        .expect("approval account");
    assert!(connection
        .execute(
            r#"
            UPDATE budget_cumulative_approval_accounts
            SET currency = 'EUR'
            WHERE authority_id = 'approval-authority'
              AND owner_id = 'owner' AND approval_budget_id = 'budget'
              AND approval_budget_epoch = 1
            "#,
            [],
        )
        .is_err());
    connection
        .execute(
            r#"
            UPDATE budget_cumulative_approval_accounts
            SET reserved_authorized_units = 1, version = 1
            WHERE authority_id = 'approval-authority'
              AND owner_id = 'owner' AND approval_budget_id = 'budget'
              AND approval_budget_epoch = 1
            "#,
            [],
        )
        .expect("mutable cumulative counters");
    assert!(connection
        .execute(
            r#"
            UPDATE budget_invocation_quotas SET max_invocations = 2
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-structured' AND grant_index = 0
            "#,
            [],
        )
        .is_err());
    assert!(connection
        .execute(
            r#"
            INSERT INTO budget_cumulative_approval_operations (
                operation_id, hold_id, authority_id, owner_id,
                approval_budget_id, approval_budget_epoch,
                effective_threshold_units, requested_authorized_units,
                state, account_version
            ) VALUES ('different-operation', 'hold-structured',
                      'approval-authority', 'owner', 'budget', 1,
                      10, 1, 'pending_approval', 0)
            "#,
            [],
        )
        .is_err());
}

#[test]
fn serving_open_rejects_substituted_lease_history_trigger() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    Connection::open(&database)
        .expect("tamper connection")
        .execute_batch(
            r#"
            DROP TRIGGER chio_serving_leases_close_only;
            CREATE TRIGGER chio_serving_leases_close_only
            BEFORE UPDATE ON chio_serving_leases
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("replace lease trigger");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("serving lease schema")
    ));
}

#[test]
fn serving_open_rejects_unexpected_lease_history_trigger() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    Connection::open(&database)
        .expect("tamper connection")
        .execute_batch(
            r#"
            CREATE TRIGGER unrelated_lease_delete_hook
            BEFORE DELETE ON chio_serving_leases
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("add lease trigger");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("serving lease schema")
    ));
}

#[test]
fn serving_open_rejects_owner_update_trigger_before_epoch_mutation() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    Connection::open(&database)
        .expect("tamper connection")
        .execute_batch(
            r#"
            CREATE TABLE owner_update_probe (value INTEGER NOT NULL);
            INSERT INTO owner_update_probe (value) VALUES (0);
            CREATE TRIGGER capture_trusted_owner_epoch
            AFTER UPDATE ON chio_serving_owner
            BEGIN
                UPDATE owner_update_probe SET value = NEW.owner_epoch;
            END;
            "#,
        )
        .expect("install owner update trigger");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("serving owner schema")
    ));
    let connection = Connection::open(&database).expect("verify no mutation");
    let (owner_epoch, probe, leases): (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT owner_epoch FROM chio_serving_owner WHERE singleton = 1),
                (SELECT value FROM owner_update_probe),
                (SELECT COUNT(*) FROM chio_serving_leases)
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("unchanged owner state");
    assert_eq!((owner_epoch, probe, leases), (0, 0, 0));
}

#[test]
fn serving_open_rejects_weakened_lease_history_table() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let connection = Connection::open(&database).expect("tamper connection");
    connection
        .execute_batch("PRAGMA writable_schema = ON")
        .expect("enable writable schema");
    assert_eq!(
        connection
            .execute(
                r#"
                UPDATE sqlite_schema
                SET sql = 'CREATE TABLE chio_serving_leases (store_uuid TEXT)'
                WHERE type = 'table' AND name = 'chio_serving_leases'
                "#,
                [],
            )
            .expect("weaken lease table"),
        1
    );
    connection
        .execute_batch("PRAGMA writable_schema = OFF")
        .expect("disable writable schema");
    drop(connection);

    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
}

#[test]
fn database_identity_and_lock_error_helpers_fail_closed() {
    let (temp, database, _lock_root) = fixture();
    let file = create_database_file(&database).expect("create database");
    let expected = file.metadata().expect("database metadata");
    drop(file);
    let replacement = temp.path().join("replacement.db");
    let file = create_database_file(&replacement).expect("create replacement");
    drop(file);
    fs::rename(&replacement, &database).expect("replace database");
    assert!(matches!(
        validate_database_identity(&database, &expected),
        Err(SqliteServingOwnerError::Invalid(_))
    ));

    let error = classify_lock_error(
        &database,
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    );
    assert!(matches!(error, SqliteServingOwnerError::Io(_)));
}

#[test]
fn serving_open_rejects_unsafe_or_noncanonical_store_uuid() {
    for store_uuid in ["../escaped-lock", "019bf9ba-9ba0-7000-8000-00000000000A"] {
        let (_temp, database, lock_root) = fixture();
        SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
        Connection::open(&database)
            .expect("tamper connection")
            .execute(
                "UPDATE chio_serving_owner SET store_uuid = ?1 WHERE singleton = 1",
                params![store_uuid],
            )
            .expect("tamper store uuid");
        assert!(matches!(
            SqliteAuthorityStore::open_serving(&database, &lock_root),
            Err(SqliteServingOwnerError::Invalid(message))
                if message.contains("canonical UUID-v7")
        ));
    }
}

#[test]
fn replaced_or_hardlinked_serving_lock_is_rejected() {
    let (temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let connection = Connection::open(&database).expect("open provisioning record");
    let record = load_provisioning_record(&connection)
        .expect("load provisioning record")
        .expect("provisioning record");
    let wrong_path = lock_root.join("wrong.lock");
    let wrong_file = create_lock_file(&wrong_path).expect("create wrong lock");
    assert!(matches!(
        validate_open_lock_file(&lock_root, &wrong_file, &record),
        Err(SqliteServingOwnerError::Invalid(message))
            if message.contains("opened serving lock identity")
    ));
    drop(wrong_file);
    fs::remove_file(&wrong_path).expect("remove wrong lock");
    let lock = only_serving_lock(&lock_root);
    let replacement = temp.path().join("replacement.lock");
    fs::write(&replacement, b"").expect("replacement");
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&replacement, permissions).expect("replacement mode");
    fs::rename(&replacement, &lock).expect("replace serving lock");

    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));

    let (_temp2, database2, lock_root2) = fixture();
    SqliteAuthorityStore::provision(&database2, &lock_root2).expect("provision second");
    let lock2 = only_serving_lock(&lock_root2);
    fs::hard_link(&lock2, lock_root2.join("extra-link")).expect("hardlink serving lock");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database2, &lock_root2),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn concurrent_provisioning_creates_one_owner_and_one_lock() {
    let (_temp, database, lock_root) = fixture();
    let database = Arc::new(database);
    let lock_root = Arc::new(lock_root);
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let database = database.clone();
            let lock_root = lock_root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                SqliteAuthorityStore::provision(database.as_path(), lock_root.as_path())
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().expect("provision thread").expect("provision");
    }

    let connection = Connection::open(database.as_path()).expect("open db");
    let owners: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_serving_owner", [], |row| {
            row.get(0)
        })
        .expect("owner count");
    assert_eq!(owners, 1);
    let locks = fs::read_dir(lock_root.as_path())
        .expect("read locks")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "lock")
        })
        .count();
    assert_eq!(locks, 1);
}

#[path = "tests/provisioning.rs"]
mod provisioning;
#[path = "tests/scoped_identity.rs"]
mod scoped_identity;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
