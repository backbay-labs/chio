#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};

use super::*;
use crate::serving_owner::SqliteAuthorityStore;

fn admission(operation_id: &str, capability_id: &str) -> BudgetAdmissionBinding {
    BudgetAdmissionBinding {
        operation_id: operation_id.to_string(),
        revocation_set: CanonicalRevocationSet::canonicalize(vec![capability_id.to_string()])
            .expect("canonical revocation set"),
        authorization_artifact_digests: vec!["a".repeat(64)],
        last_observed_revocation: None,
        supplemental_verifier_id: None,
        supplemental_verifier_config_digest: None,
        supplemental_authorization_artifact_digest: None,
        supplemental_authorization_expires_at: None,
    }
}

fn quotas(capability_id: &str, maximum: u32) -> Vec<BudgetInvocationQuota> {
    let mut quotas = vec![
        BudgetInvocationQuota {
            key: BudgetQuotaKey::grant(capability_id, 0),
            max_invocations: maximum,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateCapabilityInvocation,
                owner_id: capability_id.to_string(),
                grant_index: None,
            },
            max_invocations: maximum,
        },
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateFamilyInvocation,
                owner_id: "family-a".to_string(),
                grant_index: None,
            },
            max_invocations: maximum,
        },
    ];
    quotas.sort_by(|left, right| left.key.cmp(&right.key));
    quotas
}

fn authorize_request(id: &str, exposure: u64, maximum: u32) -> BudgetAuthorizeHoldRequest {
    let capability_id = "cap-composite";
    let operation_id = format!("operation-{id}");
    BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index: 0,
        max_invocations: Some(maximum),
        invocation_quotas: quotas(capability_id, maximum),
        cumulative_approval: None,
        admission_binding: Some(admission(&operation_id, capability_id)),
        requested_exposure_units: exposure,
        max_cost_per_invocation: Some(exposure.max(1)),
        max_total_cost_units: Some(1_000),
        hold_id: Some(format!("hold-{id}")),
        event_id: Some(format!("event-{id}-authorize")),
        authority: None,
    }
}

fn cumulative_request(id: &str) -> BudgetAuthorizeHoldRequest {
    let operation_id = format!("operation-{id}");
    let mut request = authorize_request(id, 10, 2);
    request.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
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
    request
}

fn capture_request(id: &str) -> BudgetCaptureInvocationRequest {
    BudgetCaptureInvocationRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: format!("hold-{id}"),
        event_id: format!("event-{id}-capture-invocation"),
        trusted_time: None,
        authority: None,
    }
}

fn cancel_captured_request(id: &str) -> BudgetCancelCapturedBeforeDispatchRequest {
    BudgetCancelCapturedBeforeDispatchRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: format!("hold-{id}"),
        event_id: format!("event-{id}-cancel-captured"),
        authority: None,
    }
}

fn reverse_request(id: &str, exposure: u64) -> BudgetReverseHoldRequest {
    BudgetReverseHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        reversed_exposure_units: exposure,
        hold_id: Some(format!("hold-{id}")),
        event_id: Some(format!("event-{id}-reverse")),
        expected_cumulative_approval_state: None,
        authority: None,
    }
}

trait AuthorityBoundRequest {
    fn set_authority(&mut self, authority: BudgetEventAuthority);
}

macro_rules! authority_bound_request {
    ($($request:ty),+ $(,)?) => {
        $(
            impl AuthorityBoundRequest for $request {
                fn set_authority(&mut self, authority: BudgetEventAuthority) {
                    self.authority = Some(authority);
                }
            }
        )+
    };
}

authority_bound_request!(
    BudgetAuthorizeHoldRequest,
    BudgetCaptureInvocationRequest,
    BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
    BudgetReconcileHoldRequest,
    BudgetCaptureHoldRequest,
    BudgetAuthorizeCumulativeApprovalRequest,
    BudgetCancelCapturedBeforeDispatchRequest,
);

fn current_authority(store: &SqliteBudgetStore) -> BudgetEventAuthority {
    let fence = store
        .serving_owner
        .as_ref()
        .expect("provisioned serving owner")
        .fence
        .clone();
    BudgetEventAuthority {
        authority_id: fence.store_uuid,
        lease_id: fence.lease_id,
        lease_epoch: fence.owner_epoch,
    }
}

fn owned<T: AuthorityBoundRequest>(store: &SqliteBudgetStore, mut request: T) -> T {
    request.set_authority(current_authority(store));
    request
}

fn secure_create_dir_all(path: &Path, context: &'static str) {
    fs::create_dir_all(path).expect(context);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure directory");
    }
}

fn reopen(path: &Path) -> SqliteBudgetStore {
    secure_create_dir_all(path, "create authority root");
    let database = path.join("authority.sqlite3");
    let lock_root = path.join("locks");
    secure_create_dir_all(&lock_root, "create lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    SqliteAuthorityStore::open_serving(&database, &lock_root)
        .expect("open serving authority")
        .budget_store()
}

#[test]
fn denied_candidate_does_not_claim_the_operation_authorization_slot() {
    let path = unique_db_path("chio-composite-denied-candidate");
    let store = reopen(&path);
    let mut denied = authorize_request("candidate", 10, 2);
    denied.max_cost_per_invocation = Some(1);
    let denied_decision = store
        .authorize_budget_hold(owned(&store, denied.clone()))
        .expect("deny first candidate");
    assert!(matches!(
        denied_decision,
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    assert_eq!(
        store
            .authorize_budget_hold(owned(&store, denied.clone()))
            .expect("replay denied candidate"),
        denied_decision
    );

    let mut authorized = denied.clone();
    authorized.max_cost_per_invocation = Some(10);
    authorized.hold_id = Some("hold-candidate-fallback".to_string());
    authorized.event_id = Some("event-candidate-fallback-authorize".to_string());
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorized))
            .expect("authorize fallback candidate"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let mut conflicting = denied;
    conflicting.max_cost_per_invocation = Some(10);
    conflicting.hold_id = Some("hold-candidate-conflict".to_string());
    conflicting.event_id = Some("event-candidate-conflict-authorize".to_string());
    assert!(store
        .authorize_budget_hold(owned(&store, conflicting))
        .is_err());

    drop(store);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn v6_operation_authorization_index_migrates_to_ignore_denials() {
    let path = unique_db_path("chio-composite-v6-operation-index");
    let store = reopen(&path);
    let mut denied = authorize_request("candidate-migration", 10, 2);
    denied.max_cost_per_invocation = Some(1);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, denied.clone()))
            .expect("deny first candidate"),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    drop(store);

    let database = path.join("authority.sqlite3");
    let connection = Connection::open(&database).expect("open v7 database for downgrade fixture");
    connection
        .execute_batch(
            r#"
            DROP INDEX idx_budget_events_operation_authorize;
            CREATE UNIQUE INDEX idx_budget_events_operation_authorize
                ON budget_mutation_events(operation_id)
                WHERE operation_id IS NOT NULL
                  AND kind IN ('reserve_invocation', 'authorize_exposure');
            "#,
        )
        .expect("install v6 operation index");
    crate::stamp_schema_version(&connection, "budget", 6).expect("stamp v6 budget schema");
    drop(connection);

    let store = reopen(&path);
    let mut authorized = denied;
    authorized.max_cost_per_invocation = Some(10);
    authorized.hold_id = Some("hold-candidate-migration-fallback".to_string());
    authorized.event_id = Some("event-candidate-migration-fallback".to_string());
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorized))
            .expect("authorize fallback after v6 migration"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let connection = store
        .connection()
        .expect("inspect migrated operation index");
    let index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params!["idx_budget_events_operation_authorize"],
            |row| row.get(0),
        )
        .expect("load migrated operation index");
    assert!(index_sql.contains("authorization_outcome IS NOT 'denied'"));
    drop(connection);
    drop(store);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn composite_authorize_capture_and_settlement_survive_response_loss_and_restart() {
    for (id, monetary_capture) in [("reconcile", false), ("capture-spend", true)] {
        let path = unique_db_path(&format!("chio-composite-{id}"));
        let request = authorize_request(id, 10, 2);
        let store = reopen(&path);
        let authorized = store
            .authorize_budget_hold(owned(&store, request.clone()))
            .expect("authorize");
        assert!(matches!(
            authorized,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        drop(store);

        let store = reopen(&path);
        assert_eq!(
            store
                .authorize_budget_hold(owned(&store, request.clone()))
                .expect("replay authorization"),
            authorized
        );
        let capture_request = capture_request(id);
        let captured = store
            .capture_invocation_reservations(owned(&store, capture_request.clone()))
            .expect("capture invocation");
        let captured_decision = match &captured {
            BudgetInvocationCaptureDecision::Captured(decision) => decision.clone(),
            other => panic!("unexpected capture decision: {other:?}"),
        };
        for quota in quotas("cap-composite", 2) {
            let usage = store
                .get_invocation_quota_usage(&quota.key)
                .expect("quota usage")
                .expect("quota row");
            assert_eq!(usage.reserved_invocations, 0);
            assert_eq!(usage.captured_invocations, 1);
        }
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-composite"), Some(0))
                .expect("events")
                .len(),
            2
        );
        drop(store);

        let store = reopen(&path);
        match store
            .capture_invocation_reservations(owned(&store, capture_request))
            .expect("replay capture")
        {
            BudgetInvocationCaptureDecision::AlreadyCaptured(decision) => {
                assert_eq!(decision, captured_decision)
            }
            other => panic!("unexpected replay decision: {other:?}"),
        }
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-composite"), Some(0))
                .expect("events after replay")
                .len(),
            2
        );
        let settled = if monetary_capture {
            store
                .capture_budget_hold(owned(
                    &store,
                    BudgetCaptureHoldRequest {
                        capability_id: "cap-composite".to_string(),
                        grant_index: 0,
                        exposed_cost_units: 10,
                        realized_spend_units: 7,
                        hold_id: Some(format!("hold-{id}")),
                        event_id: Some(format!("event-{id}-capture-spend")),
                        authority: None,
                    },
                ))
                .expect("capture spend")
        } else {
            store
                .reconcile_budget_hold(owned(
                    &store,
                    BudgetReconcileHoldRequest {
                        capability_id: "cap-composite".to_string(),
                        grant_index: 0,
                        exposed_cost_units: 10,
                        realized_spend_units: 7,
                        hold_id: Some(format!("hold-{id}")),
                        event_id: Some(format!("event-{id}-reconcile")),
                        authority: None,
                    },
                ))
                .expect("reconcile")
        };
        assert_eq!(settled.realized_spend_units, 7);
        drop(store);

        let store = reopen(&path);
        let usage = store
            .get_usage("cap-composite", 0)
            .expect("usage")
            .expect("usage row");
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 7);
        let _ = fs::remove_file(path);
    }
}

#[test]
fn composite_release_and_reverse_restore_durable_reservations() {
    let path = unique_db_path("chio-composite-release-reverse");
    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("release", 10, 2)))
        .expect("authorize release");
    let released = store
        .release_budget_hold(owned(
            &store,
            BudgetReleaseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                released_exposure_units: 4,
                hold_id: Some("hold-release".to_string()),
                event_id: Some("event-release-partial".to_string()),
                authority: None,
            },
        ))
        .expect("partial release");
    assert_eq!(released.exposure_units, 4);
    drop(store);

    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("reverse", 0, 2)))
        .expect("authorize reversal");
    let reversed = store
        .reverse_budget_hold(owned(&store, reverse_request("reverse", 0)))
        .expect("reverse");
    assert_eq!(reversed.invocation_state, BudgetInvocationState::Reversed);
    drop(store);

    let store = reopen(&path);
    assert_eq!(
        store
            .reverse_budget_hold(owned(&store, reverse_request("reverse", 0)))
            .expect("replay reverse"),
        reversed
    );
    let quota = store
        .get_invocation_quota_usage(&BudgetQuotaKey::grant("cap-composite", 0))
        .expect("quota")
        .expect("quota row");
    assert_eq!(quota.reserved_invocations, 1);
    let _ = fs::remove_file(path);
}

#[test]
fn every_quota_participant_exhausts_atomically_and_maximum_is_immutable() {
    let path = unique_db_path("chio-composite-quota-exhaustion");
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorize_request("quota-one", 0, 1)))
            .expect("first authorization"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, authorize_request("quota-two", 0, 1)))
            .expect("denied authorization"),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    for quota in quotas("cap-composite", 1) {
        let usage = store
            .get_invocation_quota_usage(&quota.key)
            .expect("quota usage")
            .expect("quota row");
        assert_eq!(usage.reserved_invocations, 1);
        assert_eq!(usage.captured_invocations, 0);
    }
    let mut changed_max = authorize_request("quota-three", 0, 2);
    changed_max.max_invocations = Some(2);
    assert!(store
        .authorize_budget_hold(owned(&store, changed_max))
        .is_err());
    assert_eq!(store.max_mutation_event_seq().expect("event head"), 2);
    let _ = fs::remove_file(path);
}

#[test]
fn zero_limit_aggregate_quota_persists_and_replays_a_durable_denial() {
    let path = unique_db_path("chio-composite-zero-limit-denial");
    let request = authorize_request("zero-limit", 0, 0);
    let store = reopen(&path);
    let denied = store
        .authorize_budget_hold(owned(&store, request.clone()))
        .expect("zero-limit quota must produce a durable decision");
    assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));
    assert_eq!(
        store
            .authorize_budget_hold(owned(&store, request.clone()))
            .expect("zero-limit denial replay"),
        denied
    );
    {
        let connection = store.connection().expect("inspect zero-limit denial");
        let (event_quotas, live_quotas, holds): (i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM budget_event_quota_members
                     WHERE event_id = 'event-zero-limit-authorize'
                       AND max_invocations = 0),
                    (SELECT COUNT(*) FROM budget_invocation_quotas),
                    (SELECT COUNT(*) FROM budget_authorization_holds)
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("zero-limit projection counts");
        assert_eq!(event_quotas, 3);
        assert_eq!(live_quotas, 0);
        assert_eq!(holds, 0);
    }
    drop(store);

    let reopened = reopen(&path);
    assert_eq!(
        reopened
            .authorize_budget_hold(owned(&reopened, request))
            .expect("zero-limit denial replay after restart"),
        denied
    );
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn v9_event_quota_projection_migrates_without_losing_history() {
    let path = unique_db_path("chio-composite-v9-event-quota");
    let request = authorize_request("v9-event-quota", 0, 2);
    let store = reopen(&path);
    let authorized = store
        .authorize_budget_hold(owned(&store, request.clone()))
        .expect("seed v9 quota event");
    assert!(matches!(
        authorized,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    drop(store);

    let database = path.join("authority.sqlite3");
    let connection = Connection::open(&database).expect("open v10 database for downgrade fixture");
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            DROP TRIGGER IF EXISTS budget_event_quota_bounds_insert;
            ALTER TABLE budget_event_quota_members
                RENAME TO budget_event_quota_members_v10;
            CREATE TABLE budget_event_quota_members (
                event_id TEXT NOT NULL,
                profile TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                max_invocations INTEGER NOT NULL CHECK (max_invocations > 0),
                reserved_before INTEGER NOT NULL CHECK (reserved_before >= 0),
                captured_before INTEGER NOT NULL CHECK (
                    captured_before >= 0 AND reserved_before <= max_invocations
                    AND captured_before <= max_invocations - reserved_before
                ),
                reserved_after INTEGER NOT NULL CHECK (reserved_after >= 0),
                captured_after INTEGER NOT NULL CHECK (
                    captured_after >= 0 AND reserved_after <= max_invocations
                    AND captured_after <= max_invocations - reserved_after
                ),
                PRIMARY KEY (event_id, profile, owner_id, grant_index),
                FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id),
                CHECK (owner_id <> ''),
                CHECK (
                    (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                    OR
                    (profile IN (
                        'chio.aggregate-capability-invocation.v1',
                        'chio.aggregate-family-invocation.v1',
                        'chio.broker-capability-execution.v1'
                    ) AND grant_index = -1)
                )
            );
            INSERT INTO budget_event_quota_members
            SELECT * FROM budget_event_quota_members_v10;
            DROP TABLE budget_event_quota_members_v10;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .expect("install v9 event quota table");
    crate::stamp_schema_version(&connection, "budget", 9).expect("stamp v9 budget schema");
    drop(connection);

    let migrated = reopen(&path);
    let table_sql: String = migrated
        .connection()
        .expect("inspect migrated quota table")
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'budget_event_quota_members'",
            [],
            |row| row.get(0),
        )
        .expect("load event quota table definition");
    assert!(table_sql.contains("max_invocations >= 0"));
    assert_eq!(
        migrated
            .authorize_budget_hold(owned(&migrated, request))
            .expect("replay authorization after v9 migration"),
        authorized
    );
    drop(migrated);
    let _ = fs::remove_dir_all(path);
}

/// Every payment journal row rendered with its exact stored value and type, so a
/// table rebuild that alters or drops a row is visible in a single comparison.
fn payment_journal_rows(connection: &Connection) -> Vec<String> {
    let mut statement = connection
        .prepare("SELECT * FROM payment_journal ORDER BY operation_id")
        .expect("prepare payment journal scan");
    let column_count = statement.column_count();
    statement
        .query_map([], |row| {
            let mut rendered = String::new();
            for index in 0..column_count {
                let value: rusqlite::types::Value = row.get(index)?;
                rendered.push_str(&format!("{value:?};"));
            }
            Ok(rendered)
        })
        .expect("scan payment journal")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect payment journal rows")
}

const V10_PAYMENT_JOURNAL_SCHEMA: &str = r#"
PRAGMA foreign_keys = OFF;
DROP TRIGGER IF EXISTS payment_journal_identity_immutable;
DROP TRIGGER IF EXISTS payment_journal_no_delete;
DROP INDEX IF EXISTS idx_payment_journal_request;
DROP INDEX IF EXISTS idx_payment_journal_state;
DROP TABLE payment_journal;

CREATE TABLE payment_journal (
    operation_id TEXT PRIMARY KEY CHECK (operation_id <> '' AND length(operation_id) <= 512),
    journal_version INTEGER NOT NULL CHECK (
        journal_version BETWEEN 1 AND 9007199254740991
    ),
    request_namespace_digest TEXT NOT NULL CHECK (
        length(request_namespace_digest) = 64
        AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL CHECK (request_id <> '' AND length(request_id) <= 512),
    capability_id TEXT NOT NULL CHECK (capability_id <> '' AND length(capability_id) <= 512),
    grant_index INTEGER NOT NULL CHECK (grant_index BETWEEN 0 AND 4294967295),
    hold_id TEXT NOT NULL UNIQUE CHECK (hold_id <> '' AND length(hold_id) <= 512),
    rail TEXT NOT NULL CHECK (
        rail <> '' AND rail <> 'unspecified' AND length(rail) <= 512
    ),
    rail_mode TEXT NOT NULL CHECK (rail_mode IN ('reversible_hold', 'prepaid_final')),
    authorization_id TEXT CHECK (
        authorization_id IS NULL
        OR (authorization_id <> '' AND length(authorization_id) <= 512)
    ),
    transaction_id TEXT CHECK (
        transaction_id IS NULL
        OR (transaction_id <> '' AND length(transaction_id) <= 512)
    ),
    amount_units INTEGER NOT NULL CHECK (
        amount_units BETWEEN 1 AND 9007199254740991
    ),
    settle_action TEXT CHECK (settle_action IN ('capture', 'release')),
    settle_amount_units INTEGER CHECK (
        settle_amount_units BETWEEN 1 AND amount_units
    ),
    release_authority_kind TEXT CHECK (
        release_authority_kind IN (
            'pre_dispatch_no_effect',
            'transport_not_accepted',
            'contractual_zero_charge'
        )
    ),
    release_authority_evidence_id TEXT CHECK (
        release_authority_evidence_id IS NULL
        OR (release_authority_evidence_id <> ''
            AND length(release_authority_evidence_id) <= 512)
    ),
    release_authority_evidence_digest TEXT CHECK (
        release_authority_evidence_digest IS NULL
        OR (length(release_authority_evidence_digest) = 64
            AND release_authority_evidence_digest NOT GLOB '*[^0-9a-f]*')
    ),
    release_authority_operation_version INTEGER CHECK (
        release_authority_operation_version BETWEEN 1 AND 9007199254740991
    ),
    currency TEXT NOT NULL CHECK (
        length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'
    ),
    state TEXT NOT NULL CHECK (state IN (
        'hold_placed', 'authorized', 'settling', 'settled', 'closed',
        'reconcile_failed'
    )),
    created_at_unix_ms INTEGER NOT NULL CHECK (
        created_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms BETWEEN created_at_unix_ms AND 9007199254740991
    ),
    FOREIGN KEY (hold_id) REFERENCES budget_authorization_holds(hold_id),
    CHECK (
        (state = 'hold_placed'
         AND authorization_id IS NULL AND transaction_id IS NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind IS NULL
         AND release_authority_evidence_id IS NULL
         AND release_authority_evidence_digest IS NULL
         AND release_authority_operation_version IS NULL)
        OR
        (state = 'authorized' AND rail_mode = 'reversible_hold'
         AND authorization_id IS NOT NULL AND transaction_id IS NULL
         AND settle_action IS NULL AND settle_amount_units IS NULL
         AND release_authority_kind IS NULL
         AND release_authority_evidence_id IS NULL
         AND release_authority_evidence_digest IS NULL
         AND release_authority_operation_version IS NULL)
        OR
        (state = 'settling' AND rail_mode = 'reversible_hold'
         AND authorization_id IS NOT NULL AND transaction_id IS NULL
         AND (
            (settle_action = 'capture' AND settle_amount_units IS NOT NULL
             AND release_authority_kind IS NULL
             AND release_authority_evidence_id IS NULL
             AND release_authority_evidence_digest IS NULL
             AND release_authority_operation_version IS NULL)
            OR
            (settle_action = 'release' AND settle_amount_units IS NULL
             AND release_authority_kind IS NOT NULL
             AND release_authority_evidence_id IS NOT NULL
             AND release_authority_evidence_digest IS NOT NULL
             AND release_authority_operation_version IS NOT NULL)
         ))
        OR
        (state IN ('settled', 'closed') AND authorization_id IS NOT NULL
         AND (
            (rail_mode = 'prepaid_final' AND transaction_id IS NULL
             AND settle_action IS NULL AND settle_amount_units IS NULL
             AND release_authority_kind IS NULL
             AND release_authority_evidence_id IS NULL
             AND release_authority_evidence_digest IS NULL
             AND release_authority_operation_version IS NULL)
            OR
            (rail_mode = 'reversible_hold' AND transaction_id IS NOT NULL
             AND (
                (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (settle_action = 'release' AND settle_amount_units IS NULL
                 AND release_authority_kind IS NOT NULL
                 AND release_authority_evidence_id IS NOT NULL
                 AND release_authority_evidence_digest IS NOT NULL
                 AND release_authority_operation_version IS NOT NULL)
             ))
         ))
        OR state = 'reconcile_failed'
    )
);

CREATE UNIQUE INDEX idx_payment_journal_request
    ON payment_journal(request_namespace_digest, request_id);
CREATE INDEX idx_payment_journal_state
    ON payment_journal(state, updated_at_unix_ms);

CREATE TRIGGER payment_journal_identity_immutable
BEFORE UPDATE OF operation_id, request_namespace_digest, request_id,
                 capability_id, grant_index, hold_id, rail, rail_mode,
                 amount_units, currency, created_at_unix_ms
ON payment_journal
BEGIN
    SELECT RAISE(ABORT, 'payment journal identity is immutable');
END;

CREATE TRIGGER payment_journal_no_delete
BEFORE DELETE ON payment_journal
BEGIN
    SELECT RAISE(ABORT, 'payment journal is append-preserving');
END;
PRAGMA foreign_keys = ON;
"#;

const INSERT_PAYMENT_JOURNAL_ROW: &str = r#"
INSERT INTO payment_journal (
    operation_id, journal_version, request_namespace_digest, request_id,
    capability_id, grant_index, hold_id, rail, rail_mode,
    authorization_id, transaction_id, amount_units, settle_action,
    settle_amount_units, release_authority_kind,
    release_authority_evidence_id, release_authority_evidence_digest,
    release_authority_operation_version, currency, state,
    created_at_unix_ms, updated_at_unix_ms
) VALUES (
    ?1, 1, ?2, ?3, 'cap-composite', 0, ?4, 'rail-test', 'reversible_hold',
    ?5, NULL, 250, ?6, NULL, ?7, ?8, ?9, ?10, 'USD', ?11,
    1700000000000, 1700000000001
)
"#;

#[test]
fn v10_payment_journal_migrates_to_accept_pre_authorization_cancellation() {
    let path = unique_db_path("chio-composite-v10-payment-journal");
    secure_create_dir_all(&path, "create budget root");
    let database = path.join("budget.sqlite3");
    let store = SqliteBudgetStore::open(&database).expect("open budget store");
    for id in [
        "journal-authorized",
        "journal-released",
        "journal-cancelled",
        "journal-duplicate",
    ] {
        assert!(matches!(
            store
                .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                    capability_id: "cap-journal".to_string(),
                    grant_index: 0,
                    max_invocations: Some(8),
                    requested_exposure_units: 10,
                    max_cost_per_invocation: Some(10),
                    max_total_cost_units: Some(1_000),
                    hold_id: Some(format!("hold-{id}")),
                    event_id: Some(format!("event-{id}-authorize")),
                    authority: None,
                    invocation_quotas: Vec::new(),
                    cumulative_approval: None,
                    admission_binding: None,
                })
                .expect("seed payment journal hold"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }
    let provisioned_sql: String = store
        .connection()
        .expect("inspect provisioned payment journal")
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'payment_journal'",
            [],
            |row| row.get(0),
        )
        .expect("load provisioned payment journal definition");
    drop(store);

    let connection = Connection::open(&database).expect("open v10 database for downgrade fixture");
    connection
        .execute_batch(V10_PAYMENT_JOURNAL_SCHEMA)
        .expect("install v10 payment journal table");
    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-authorized",
                "a".repeat(64),
                "request-journal-authorized",
                "hold-journal-authorized",
                "authorization-journal-authorized",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "authorized",
            ],
        )
        .expect("seed authorized journal row");
    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-released",
                "b".repeat(64),
                "request-journal-released",
                "hold-journal-released",
                "authorization-journal-released",
                "release",
                "pre_dispatch_no_effect",
                "evidence-journal-released",
                "c".repeat(64),
                7_i64,
                "settling",
            ],
        )
        .expect("seed releasing journal row");
    connection
        .execute(
            r#"
            INSERT INTO payment_release_evidence (
                operation_id, evidence_id, evidence_kind, operation_version,
                canonical_bundle, bundle_digest, created_at_unix_ms
            ) VALUES (
                'operation-journal-released', 'evidence-journal-released',
                'pre_dispatch_no_effect', 7, X'0102', ?1, 1700000000001
            )
            "#,
            params!["c".repeat(64)],
        )
        .expect("seed release evidence row");
    let rejected = connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-cancelled",
                "d".repeat(64),
                "request-journal-cancelled",
                "hold-journal-cancelled",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "closed",
            ],
        )
        .expect_err("v10 rejects a hold cancelled before authorization");
    assert!(
        rejected.to_string().contains("CHECK constraint failed"),
        "unexpected v10 rejection: {rejected}"
    );
    let seeded = payment_journal_rows(&connection);
    assert_eq!(seeded.len(), 2);
    crate::stamp_schema_version(&connection, "budget", 10).expect("stamp v10 budget schema");
    drop(connection);

    let migrated = SqliteBudgetStore::open(&database).expect("reopen budget store");
    let connection = migrated
        .connection()
        .expect("inspect migrated payment journal");
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'payment_journal'",
            [],
            |row| row.get(0),
        )
        .expect("load payment journal definition");
    assert!(table_sql.contains("state = 'closed'"));
    assert_eq!(table_sql, provisioned_sql);
    assert_eq!(payment_journal_rows(&connection), seeded);

    let restored: Vec<String> = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE tbl_name = 'payment_journal' AND type IN ('index', 'trigger')
                 ORDER BY name",
            )
            .expect("prepare payment journal object scan");
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("scan payment journal objects")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect payment journal objects");
        names
    };
    for object in [
        "idx_payment_journal_request",
        "idx_payment_journal_state",
        "payment_journal_identity_immutable",
        "payment_journal_no_delete",
    ] {
        assert!(
            restored.iter().any(|name| name == object),
            "payment journal rebuild lost `{object}`: {restored:?}"
        );
    }

    let evidence_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'payment_release_evidence'",
            [],
            |row| row.get(0),
        )
        .expect("load release evidence definition");
    assert!(evidence_sql.contains("REFERENCES payment_journal(operation_id)"));
    let (evidence_rows, violations): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM payment_release_evidence),
                    (SELECT COUNT(*) FROM pragma_foreign_key_check)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count release evidence and foreign key violations");
    assert_eq!(evidence_rows, 1);
    assert_eq!(violations, 0);

    connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-cancelled",
                "d".repeat(64),
                "request-journal-cancelled",
                "hold-journal-cancelled",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "closed",
            ],
        )
        .expect("v11 accepts a hold cancelled before authorization");
    let append_preserving = connection
        .execute(
            "DELETE FROM payment_journal WHERE operation_id = 'operation-journal-cancelled'",
            [],
        )
        .expect_err("payment journal delete guard survives the rebuild");
    assert!(
        append_preserving
            .to_string()
            .contains("payment journal is append-preserving"),
        "unexpected delete outcome: {append_preserving}"
    );
    let duplicate_request = connection
        .execute(
            INSERT_PAYMENT_JOURNAL_ROW,
            params![
                "operation-journal-duplicate",
                "d".repeat(64),
                "request-journal-cancelled",
                "hold-journal-duplicate",
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<i64>,
                "closed",
            ],
        )
        .expect_err("request uniqueness survives the rebuild");
    assert!(
        duplicate_request.to_string().contains("UNIQUE"),
        "unexpected duplicate outcome: {duplicate_request}"
    );
    let settled = payment_journal_rows(&connection);
    assert_eq!(settled.len(), 3);
    drop(connection);
    drop(migrated);

    let reopened = SqliteBudgetStore::open(&database).expect("reopen migrated budget store");
    let connection = reopened
        .connection()
        .expect("inspect twice-opened payment journal");
    assert_eq!(payment_journal_rows(&connection), settled);
    drop(connection);
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[cfg(unix)]
#[test]
fn provision_refuses_populated_legacy_budget_state() {
    let path = unique_db_path("chio-composite-legacy-quota");
    secure_create_dir_all(&path, "create legacy authority root");
    let database = path.join("authority.sqlite3");
    {
        let legacy = SqliteBudgetStore::open(&database).expect("open legacy store");
        assert!(legacy
            .try_increment("cap-composite", 0, Some(2))
            .expect("legacy increment"));
    }
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure legacy database mode");
    let lock_root = path.join("locks");
    secure_create_dir_all(&lock_root, "create lock root");

    let error = SqliteAuthorityStore::provision(&database, &lock_root)
        .expect_err("populated legacy safety state must not acquire an unproven baseline");
    assert!(
        error
            .to_string()
            .contains("baseline refuses nonempty safety table `budget_mutation_events`"),
        "unexpected provisioning error: {error}"
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn captured_hold_redundantly_persists_authority_time() {
    let path = unique_db_path("chio-composite-capture-time");
    let store = reopen(&path);
    store
        .authorize_budget_hold(owned(&store, authorize_request("capture-time", 0, 2)))
        .expect("authorize");
    store
        .capture_invocation_reservations(owned(&store, capture_request("capture-time")))
        .expect("capture");
    {
        let connection = store.connection().expect("connection");
        let (hold_time, event_time): (Option<i64>, Option<i64>) = connection
            .query_row(
                r#"
                SELECT hold.trusted_capture_time, event.trusted_time
                FROM budget_authorization_holds AS hold
                JOIN budget_mutation_events AS event ON event.hold_id = hold.hold_id
                WHERE hold.hold_id = 'hold-capture-time'
                  AND event.kind = 'capture_invocation'
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("capture time projection");
        assert!(hold_time.is_some());
        assert_eq!(hold_time, event_time);
        assert!(connection
            .execute(
                "UPDATE budget_authorization_holds SET trusted_capture_time = trusted_capture_time + 1 WHERE hold_id = 'hold-capture-time'",
                [],
            )
            .is_err());
    }
    drop(store);
    drop(reopen(&path));
    let _ = fs::remove_dir_all(path);
}

#[test]
fn cumulative_approval_attach_is_exact_idempotent_and_survives_capture() {
    let path = unique_db_path("chio-composite-cumulative");
    let request = cumulative_request("cumulative");
    let binding = request
        .admission_binding
        .clone()
        .expect("admission binding");
    let store = reopen(&path);
    let pending = store
        .authorize_budget_hold(owned(&store, request.clone()))
        .expect("pending authorization");
    let pending_usage = match pending {
        BudgetAuthorizeHoldDecision::ApprovalRequired(decision) => decision.cumulative_approval,
        other => panic!("unexpected pending decision: {other:?}"),
    };
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("pending operation lookup")
            .expect("pending operation"),
        pending_usage
    );
    drop(store);

    let approval = BudgetAuthorizeCumulativeApprovalRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        operation_id: "operation-cumulative".to_string(),
        hold_id: "hold-cumulative".to_string(),
        admission_binding: binding,
        approval_set_digest: "b".repeat(64),
        event_id: "event-cumulative-approval".to_string(),
        authority: None,
    };
    let store = reopen(&path);
    let attached = store
        .authorize_cumulative_approval(owned(&store, approval.clone()))
        .expect("attach approval");
    assert!(matches!(
        attached,
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(_)
    ));
    let approved_usage = match &attached {
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(decision) => decision
            .cumulative_approval
            .clone()
            .expect("approved cumulative projection"),
        other => panic!("unexpected approval decision: {other:?}"),
    };
    assert!(matches!(
        store
            .authorize_cumulative_approval(owned(&store, approval.clone()))
            .expect("replay approval"),
        BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(_)
    ));
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("approved operation lookup"),
        Some(approved_usage)
    );
    let mut forged = approval.clone();
    forged.capability_id = "other-capability".to_string();
    assert!(store
        .authorize_cumulative_approval(owned(&store, forged))
        .is_err());
    drop(store);

    let store = reopen(&path);
    let capture = store
        .capture_invocation_reservations(owned(&store, capture_request("cumulative")))
        .expect("capture approved invocation");
    let captured_usage = match capture {
        BudgetInvocationCaptureDecision::Captured(decision) => decision
            .cumulative_approval
            .expect("captured cumulative projection"),
        other => panic!("unexpected capture decision: {other:?}"),
    };
    drop(store);
    let store = reopen(&path);
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-cumulative")
            .expect("restarted operation lookup"),
        Some(captured_usage)
    );
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("missing-operation")
            .expect("missing operation lookup"),
        None
    );
    let account = store
        .get_cumulative_approval_account_usage(
            &request
                .cumulative_approval
                .as_ref()
                .expect("cumulative request")
                .account_key,
        )
        .expect("account usage")
        .expect("account row");
    assert_eq!(account.reserved_authorized.units, 0);
    assert_eq!(account.captured_authorized.units, 10);
    let cancellation_request = cancel_captured_request("cumulative");
    let cancelled = store
        .cancel_captured_before_dispatch(owned(&store, cancellation_request.clone()))
        .expect("cancel captured cumulative invocation");
    let cancelled_usage = match cancelled {
        BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(decision) => decision
            .cumulative_approval
            .expect("cancelled cumulative projection"),
        other => panic!("unexpected cancellation decision: {other:?}"),
    };
    assert_eq!(
        cancelled_usage.state,
        BudgetCumulativeApprovalState::ReversedBeforeDispatch
    );
    assert!(matches!(
        store
            .cancel_captured_before_dispatch(owned(&store, cancellation_request))
            .expect("replay captured cumulative cancellation"),
        BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(_)
    ));
    drop(store);
    let store = reopen(&path);
    let account = store
        .get_cumulative_approval_account_usage(
            &request
                .cumulative_approval
                .as_ref()
                .expect("cumulative request")
                .account_key,
        )
        .expect("cancelled account usage")
        .expect("cancelled account row");
    assert_eq!(account.reserved_authorized.units, 0);
    assert_eq!(account.captured_authorized.units, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn below_threshold_cumulative_operation_captures_without_attachment() {
    let path = unique_db_path("chio-composite-cumulative-below-threshold");
    let mut request = cumulative_request("below-threshold");
    request
        .cumulative_approval
        .as_mut()
        .expect("cumulative request")
        .effective_threshold
        .units = 100;
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, request))
            .expect("authorize below threshold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(matches!(
        store
            .capture_invocation_reservations(owned(&store, capture_request("below-threshold")))
            .expect("capture below threshold"),
        BudgetInvocationCaptureDecision::Captured(_)
    ));
    drop(store);

    let store = reopen(&path);
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("operation-below-threshold")
            .expect("operation lookup")
            .expect("operation projection")
            .state,
        BudgetCumulativeApprovalState::Captured
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn cumulative_approval_state_flip_cannot_skip_attachment() {
    let path = unique_db_path("chio-composite-cumulative-state-flip");
    let store = reopen(&path);
    assert!(matches!(
        store
            .authorize_budget_hold(owned(&store, cumulative_request("state-flip")))
            .expect("create pending cumulative operation"),
        BudgetAuthorizeHoldDecision::ApprovalRequired(_)
    ));
    store
        .connection()
        .expect("connection")
        .execute_batch(
            r#"
            UPDATE budget_event_cumulative_approval
            SET state_after = 'authorized'
            WHERE operation_id = 'operation-state-flip';
            UPDATE budget_cumulative_approval_operations
            SET state = 'authorized'
            WHERE operation_id = 'operation-state-flip';
            "#,
        )
        .expect("forge coordinated cumulative state");

    let error = store
        .capture_invocation_reservations(owned(&store, capture_request("state-flip")))
        .expect_err("capture must require the missing approval attachment");
    assert!(
        error.to_string().contains("invalid reservation history"),
        "unexpected error: {error}"
    );
    drop(store);

    let database = path.join("authority.sqlite3");
    let error = match SqliteAuthorityStore::open_serving(&database, path.join("locks")) {
        Ok(_) => panic!("serving must reject a cumulative approval state flip"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("cumulative approval state machine"),
        "unexpected error: {error}"
    );
    let _ = fs::remove_dir_all(path);
}

#[test]
fn serving_rejects_structured_hold_event_frontier_corruption() {
    for (id, corruption) in [
        (
            "invocation",
            "UPDATE budget_authorization_holds SET invocation_state = 'captured'",
        ),
        (
            "disposition",
            "UPDATE budget_authorization_holds SET disposition = 'released'",
        ),
    ] {
        let path = unique_db_path(&format!("chio-composite-hold-frontier-{id}"));
        let store = reopen(&path);
        store
            .authorize_budget_hold(owned(&store, authorize_request(id, 10, 2)))
            .expect("create structured hold");
        drop(store);

        let database = path.join("authority.sqlite3");
        Connection::open(&database)
            .expect("open raw database")
            .execute(corruption, [])
            .expect("corrupt structured hold frontier");
        let error = match SqliteAuthorityStore::open_serving(&database, path.join("locks")) {
            Ok(_) => panic!("serving must reject structured {id} frontier corruption"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("durable event frontier"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn serving_rejects_cumulative_operation_corruption_hidden_by_account_totals() {
    for (id, corruption) in [
        (
            "request",
            r#"
            UPDATE budget_cumulative_approval_operations
            SET requested_authorized_units = requested_authorized_units + 1;
            UPDATE budget_cumulative_approval_accounts
            SET reserved_authorized_units = reserved_authorized_units + 1;
            "#,
        ),
        (
            "frontier",
            r#"
            UPDATE budget_cumulative_approval_operations
            SET state = 'authorized', account_version = account_version + 1;
            UPDATE budget_cumulative_approval_accounts
            SET version = version + 1;
            "#,
        ),
    ] {
        let path = unique_db_path(&format!("chio-composite-cumulative-corrupt-{id}"));
        let store = reopen(&path);
        store
            .authorize_budget_hold(owned(&store, cumulative_request(id)))
            .expect("create pending cumulative operation");
        drop(store);

        let database = path.join("authority.sqlite3");
        Connection::open(&database)
            .expect("open raw database")
            .execute_batch(corruption)
            .expect("corrupt cumulative projection");
        let error = match SqliteAuthorityStore::open_serving(&database, path.join("locks")) {
            Ok(_) => panic!("serving must reject cumulative {id} corruption"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("cumulative approval operation"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn approval_vs_reversal_and_last_unit_admission_are_serialized() {
    let path = unique_db_path("chio-composite-cas-races");
    let store = reopen(&path);
    let request = cumulative_request("race");
    let binding = request.admission_binding.clone().expect("binding");
    store
        .authorize_budget_hold(owned(&store, request))
        .expect("pending authorization");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(2));
    let approval_store = store.clone();
    let approval_barrier = barrier.clone();
    let approval = std::thread::spawn(move || {
        approval_barrier.wait();
        approval_store.authorize_cumulative_approval(owned(
            &approval_store,
            BudgetAuthorizeCumulativeApprovalRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                operation_id: "operation-race".to_string(),
                hold_id: "hold-race".to_string(),
                admission_binding: binding,
                approval_set_digest: "c".repeat(64),
                event_id: "event-race-approval".to_string(),
                authority: None,
            },
        ))
    });
    let reverse_store = store.clone();
    let reverse = std::thread::spawn(move || {
        barrier.wait();
        let mut request = reverse_request("race", 10);
        request.expected_cumulative_approval_state =
            Some(BudgetCumulativeApprovalState::PendingApproval);
        reverse_store.reverse_budget_hold(owned(&reverse_store, request))
    });
    let winners = usize::from(approval.join().expect("approval thread").is_ok())
        + usize::from(reverse.join().expect("reverse thread").is_ok());
    assert_eq!(winners, 1);
    drop(store);

    let _ = fs::remove_file(&path);

    let last_path = unique_db_path("chio-composite-last-unit-race");
    let last_unit = Arc::new(reopen(&last_path));
    last_unit
        .authorize_budget_hold(owned(&last_unit, authorize_request("last-seed", 0, 2)))
        .expect("seed reservation");
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["last-one", "last-two"]
        .into_iter()
        .map(|id| {
            let store = last_unit.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.authorize_budget_hold(owned(&store, authorize_request(id, 0, 2)))
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|thread| thread.join().expect("admission thread").expect("decision"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)))
            .count(),
        1
    );
    let _ = fs::remove_file(last_path);
}

fn supplemental_admission(
    operation_id: &str,
    capability_id: &str,
    expires_at: u64,
) -> BudgetAdmissionBinding {
    let mut binding = admission(operation_id, capability_id);
    binding.last_observed_revocation = Some(RevocationCommitMetadata {
        authority: BudgetEventAuthority {
            authority_id: "revocation-authority".to_string(),
            lease_id: "revocation-lease".to_string(),
            lease_epoch: 1,
        },
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        commit_index: 1,
    });
    binding.supplemental_verifier_id = Some("supplemental-verifier".to_string());
    binding.supplemental_verifier_config_digest = Some("b".repeat(64));
    binding.supplemental_authorization_artifact_digest = Some("a".repeat(64));
    binding.supplemental_authorization_expires_at = Some(expires_at);
    binding
}

fn supplemental_request(id: &str, expires_at: u64) -> BudgetAuthorizeHoldRequest {
    let capability_id = "cap-composite";
    let mut request = authorize_request(id, 10, 2);
    request.admission_binding = Some(supplemental_admission(
        &format!("operation-{id}"),
        capability_id,
        expires_at,
    ));
    request.invocation_quotas.push(BudgetInvocationQuota {
        key: BudgetQuotaKey {
            profile: BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
            owner_id: capability_id.to_string(),
            grant_index: None,
        },
        max_invocations: 2,
    });
    request
        .invocation_quotas
        .sort_by(|left, right| left.key.cmp(&right.key));
    request
}

#[test]
fn millisecond_shaped_supplemental_expiry_is_rejected() {
    let path = unique_db_path("chio-composite-supplemental-expiry-unit");
    let store = reopen(&path);

    let request = supplemental_request("ms-expiry", 1_767_225_600_000);
    let error = store
        .authorize_budget_hold(owned(&store, request))
        .expect_err("a millisecond expiry cannot be compared against a seconds clock");
    assert!(
        error.to_string().contains("not expressed in seconds"),
        "unexpected error: {error}"
    );

    // The same binding with a seconds-shaped expiry clears the unit gate and is
    // carried on to the remaining admission checks.
    let request = supplemental_request("seconds-expiry", 1_767_225_600);
    let error = store
        .authorize_budget_hold(owned(&store, request))
        .expect_err("this fixture carries no live revocation head");
    assert!(
        !error.to_string().contains("not expressed in seconds"),
        "a seconds expiry must not be rejected as a unit error: {error}"
    );

    let _ = fs::remove_dir_all(path);
}
