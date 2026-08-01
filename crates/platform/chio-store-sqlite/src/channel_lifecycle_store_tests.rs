use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::receipt::decision::ToolCallAction;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationStore,
    AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, SideEffectClass,
};
use rusqlite::{params, Transaction};
use tempfile::TempDir;

use super::*;
use crate::{SqliteAuthorityStore, SqliteServingOwnerError};

#[path = "channel_lifecycle_store_tests/prepared.rs"]
mod prepared;
#[path = "channel_lifecycle_store_tests/reservation.rs"]
mod reservation;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    authority: SqliteAuthorityStore,
    store: SqliteChannelLifecycleStore,
    fence: StoreMutationFence,
}

fn fixture() -> TestResult<Fixture> {
    let temp = tempfile::tempdir()?;
    secure_temp_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))?;
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.channel_lifecycle_store();
    let fence = authority.mutation_fence();
    Ok(Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    })
}

fn identifier(field: &'static str, value: &str) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new(field, value)?)
}

fn admission_digest(field: &'static str, value: &str) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(field, digest(value))?)
}

fn channel_action() -> TestResult<ToolCallAction> {
    Ok(ToolCallAction::from_parameters(serde_json::json!({
        "channel": "request"
    }))?)
}

fn prepared_operation(
    fence: &StoreMutationFence,
    request_id: &str,
) -> TestResult<AdmissionOperationV1> {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "channel-store-authority",
    )?)?;
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        observation_attempt_zero: true,
        obligation: true,
        channel: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let action = channel_action()?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", request_id)?,
        capability_id: identifier("capability_id", "channel-capability")?,
        authorization_capability_hash: admission_digest(
            "authorization_capability_hash",
            "channel-authorization",
        )?,
        request_binding: AdmissionRequestBindingV1::new(
            AdmissionDigest::try_new("immutable_request_hash", action.parameter_hash)?,
            requirements,
        )?,
        policy_hash: admission_digest("policy_hash", "channel-policy")?,
        effect_class: SideEffectClass::Monetary,
    })?;
    Ok(AdmissionOperationV1::prepare(binding, fence.owner_epoch)?)
}

fn begin_operation(fixture: &Fixture, operation: &AdmissionOperationV1) -> TestResult {
    let operation_json = canonical_json_bytes(&operation.to_persisted())?;
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    transaction.execute(
        r#"
        INSERT INTO admission_operations (
            operation_id, request_namespace_digest, request_id,
            operation_json, state, terminal, coordinator_lease_epoch,
            version, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, 'prepared', 0, ?5, 1, 1000, 1000)
        "#,
        params![
            operation.binding().operation_id().as_str(),
            operation.binding().request_namespace_digest().as_str(),
            operation.binding().request_id().as_str(),
            operation_json,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    crate::admission_operation_store::append_operation_commit_with_participant(
        &transaction,
        operation,
        &operation_json,
        None,
        "begin",
        None,
        &fixture.store.serving_owner,
        1000,
    )?;
    transaction.commit()?;
    fixture
        .store
        .serving_owner
        .sync_authority_anchor(&connection)?;
    Ok(())
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn insert_state(
    transaction: &Transaction<'_>,
    fence: &StoreMutationFence,
    checkpoint_sequence: u64,
    checkpoint_digest: &str,
) -> TestResult {
    transaction.execute(
        r#"
        INSERT INTO channel_state_records (
            channel_id, sequence, state_kind, state_digest,
            checkpoint_sequence, checkpoint_digest, state_json, operation_id,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        ) VALUES (?1, 0, 'initial', ?2, ?3, ?4, X'7b7d', NULL, ?5, ?6, ?7, 1000)
        "#,
        params![
            digest("channel"),
            digest("state-zero"),
            i64::try_from(checkpoint_sequence)?,
            checkpoint_digest,
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

fn insert_lifecycle(
    transaction: &Transaction<'_>,
    fence: &StoreMutationFence,
    checkpoint_sequence: u64,
    checkpoint_digest: &str,
) -> TestResult {
    transaction.execute(
        r#"
        INSERT INTO channel_lifecycle_records (
            channel_id, open_intent_digest, open_intent_json,
            open_digest, open_json, lifecycle_json, escrow_json,
            lifecycle_state, latest_state_digest, latest_sequence,
            state_version, lifecycle_fence, live_reservation_id, operation_id,
            channel_head_digest, escrow_head_digest,
            checkpoint_sequence, checkpoint_digest, record_version,
            store_uuid, store_lease_id, store_owner_epoch, updated_at_unix_ms
        ) VALUES (
            ?1, ?2, X'7b7d', ?3, X'7b7d', X'7b7d', X'7b7d',
            'open', ?4, 0, 1, 1, NULL, NULL, ?5, ?6, ?7, ?8, 1,
            ?9, ?10, ?11, 1000
        )
        "#,
        params![
            digest("channel"),
            digest("open-intent"),
            digest("open"),
            digest("state-zero"),
            digest("channel-head"),
            digest("escrow-head"),
            i64::try_from(checkpoint_sequence)?,
            checkpoint_digest,
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

fn insert_plan(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
    checkpoint_sequence: u64,
    checkpoint_digest: &str,
) -> TestResult {
    transaction.execute(
        r#"
        INSERT INTO channel_prepared_admission_plans (
            operation_id, request_id, request_namespace_digest,
            request_binding_digest, provider_binding_digest, reservation_id,
            channel_id, open_digest,
            prior_state_digest, prior_sequence, reservation_proposal_digest,
            lifecycle_state, state_version, lifecycle_fence,
            live_reservation_id, lifecycle_operation_id,
            channel_head_digest, escrow_head_digest,
            checkpoint_sequence, checkpoint_digest,
            plan_digest, plan_json,
            store_uuid, store_lease_id, store_owner_epoch, created_at_unix_ms
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10,
            'open', 1, 1, NULL, NULL, ?11, ?12, ?13, ?14,
            ?15, X'7b7d', ?16, ?17, ?18, 1000
        )
        "#,
        params![
            operation.binding().operation_id().as_str(),
            operation.binding().request_id().as_str(),
            operation.binding().request_namespace_digest().as_str(),
            operation.binding().request_binding_hash().as_str(),
            digest("provider-qualification"),
            digest("reservation"),
            digest("channel"),
            digest("open"),
            digest("state-zero"),
            digest("proposal"),
            digest("channel-head"),
            digest("escrow-head"),
            i64::try_from(checkpoint_sequence)?,
            checkpoint_digest,
            digest("prepared-plan"),
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

fn insert_reservation(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
) -> TestResult {
    let descriptor_key = format!(
        "reservation:{}",
        operation.binding().operation_id().as_str()
    );
    transaction.execute(
        r#"
        INSERT INTO economic_state_stages (
            batch_id, checkpoint_sequence, checkpoint_digest,
            base_view_json, batch_json, committed_view_json,
            operation_binding_json, descriptor_kind, descriptor_key,
            descriptor_digest, descriptor_json, status, reason,
            stage_version, snapshot_digest, created_at_unix_ms,
            updated_at_unix_ms
        ) VALUES (
            ?1, 2, ?2, X'7b7d', X'7b7d', NULL, NULL,
            'chio.channel.transition-replay.v1', ?3, ?4, X'7b7d',
            'db_staged', NULL, 1, ?5, 1050, 1050
        )
        "#,
        params![
            digest("stage-batch"),
            digest("ready-checkpoint"),
            descriptor_key,
            digest("{}"),
            digest("stage-snapshot"),
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO channel_reservation_records (
            reservation_id, operation_id, channel_id, prior_sequence, sequence,
            prepared_plan_digest,
            reservation_digest, reservation_json,
            authority_pins_digest, authority_pins_json,
            request_binding_digest, provider_binding_digest,
            stage_batch_id, stage_descriptor_kind, stage_descriptor_key,
            stage_descriptor_digest, base_checkpoint_sequence, base_checkpoint_digest,
            ready_checkpoint_digest, ready_checkpoint_sequence,
            ready_effect_head_digest,
            replay_protocol_digest, replay_content_digest, replay_json,
            disposition, record_version,
            store_uuid, store_lease_id, store_owner_epoch, updated_at_unix_ms
        ) VALUES (
            ?1, ?2, ?3, 0, 1, ?4, ?5, X'7b7d', ?6, X'7b7d', ?7, ?8,
            ?9, 'chio.channel.transition-replay.v1', ?10, ?11, 1, ?12,
            ?13, 2, ?14, ?15, ?11, X'7b7d', 'live', 1, ?16, ?17, ?18, 1100
        )
        "#,
        params![
            digest("reservation"),
            operation.binding().operation_id().as_str(),
            digest("channel"),
            digest("prepared-plan"),
            digest("signed-reservation"),
            digest("authority-pins"),
            operation.binding().request_binding_hash().as_str(),
            digest("provider-qualification"),
            digest("stage-batch"),
            format!(
                "reservation:{}",
                operation.binding().operation_id().as_str()
            ),
            digest("{}"),
            digest("checkpoint-one"),
            digest("ready-checkpoint"),
            digest("ready-head"),
            digest("replay-protocol"),
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

#[test]
fn checkpoint_identity_binds_state_lifecycle_and_prepared_base() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "checkpoint-request")?;
    begin_operation(&fixture, &operation)?;
    let checkpoint_digest = digest("checkpoint-one");
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    insert_state(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    assert!(insert_lifecycle(&transaction, &fixture.fence, 2, &checkpoint_digest).is_err());
    insert_lifecycle(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    assert!(insert_plan(
        &transaction,
        &operation,
        &fixture.fence,
        2,
        &checkpoint_digest,
    )
    .is_err());
    insert_plan(
        &transaction,
        &operation,
        &fixture.fence,
        1,
        &checkpoint_digest,
    )?;
    transaction.rollback()?;
    Ok(())
}

#[test]
fn signed_remote_state_does_not_require_a_local_producer_operation() -> TestResult {
    let fixture = fixture()?;
    let checkpoint_digest = digest("remote-state-checkpoint");
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    transaction.execute(
        r#"
        INSERT INTO channel_state_records (
            channel_id, sequence, state_kind, state_digest,
            checkpoint_sequence, checkpoint_digest, state_json, operation_id,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        ) VALUES (?1, 1, 'signed', ?2, 3, ?3, X'7b7d', NULL, ?4, ?5, ?6, 1000)
        "#,
        params![
            digest("remote-channel"),
            digest("remote-signed-state"),
            checkpoint_digest,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.rollback()?;
    Ok(())
}

#[test]
fn lifecycle_replay_is_immutable() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "replay-request")?;
    begin_operation(&fixture, &operation)?;
    let checkpoint_digest = digest("checkpoint-one");
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    insert_state(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    insert_lifecycle(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    insert_plan(
        &transaction,
        &operation,
        &fixture.fence,
        1,
        &checkpoint_digest,
    )?;
    insert_reservation(&transaction, &operation, &fixture.fence)?;
    assert!(transaction
        .execute(
            r#"
            UPDATE channel_reservation_records
            SET replay_protocol_digest = ?1, replay_content_digest = ?1,
                replay_json = X'7b2261223a317d',
                record_version = 2, updated_at_unix_ms = 1300
            WHERE reservation_id = ?2
            "#,
            params![digest("substituted-replay"), digest("reservation")],
        )
        .is_err());
    transaction.rollback()?;
    Ok(())
}

#[test]
fn terminal_reservation_disposition_cannot_reopen_or_switch() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "disposition-request")?;
    begin_operation(&fixture, &operation)?;
    let checkpoint_digest = digest("checkpoint-one");
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    insert_state(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    insert_lifecycle(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    insert_plan(
        &transaction,
        &operation,
        &fixture.fence,
        1,
        &checkpoint_digest,
    )?;
    insert_reservation(&transaction, &operation, &fixture.fence)?;
    transaction.execute(
        r#"
        UPDATE channel_reservation_records
        SET disposition = 'consumed', record_version = 2, updated_at_unix_ms = 1200
        WHERE reservation_id = ?1
        "#,
        [digest("reservation")],
    )?;
    for disposition in ["live", "cancelled", "incident"] {
        assert!(transaction
            .execute(
                r#"
                UPDATE channel_reservation_records
                SET disposition = ?1, record_version = 3, updated_at_unix_ms = 1300
                WHERE reservation_id = ?2
                "#,
                params![disposition, digest("reservation")],
            )
            .is_err());
    }
    transaction.rollback()?;
    Ok(())
}

#[test]
fn stale_serving_fence_cannot_mutate_channel_state() -> TestResult {
    let fixture = fixture()?;
    let stale = StoreMutationFence {
        store_uuid: fixture.fence.store_uuid.clone(),
        lease_id: "stale-lease".to_owned(),
        owner_epoch: fixture.fence.owner_epoch,
    };
    let checkpoint_digest = digest("checkpoint-one");
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    assert!(insert_state(&transaction, &stale, 1, &checkpoint_digest).is_err());
    transaction.rollback()?;
    Ok(())
}

#[test]
fn prepared_operation_and_plan_rollback_together() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "atomic-request")?;
    let encoded = canonical_json_bytes(&operation.to_persisted())?;
    let checkpoint_digest = digest("checkpoint-one");
    let mut connection = fixture.store.connection()?;
    connection.execute_batch(
        r#"
        CREATE TEMP TRIGGER fail_channel_prepared_plan
        BEFORE INSERT ON channel_prepared_admission_plans
        BEGIN
            SELECT RAISE(ROLLBACK, 'injected channel plan rollback');
        END;
        "#,
    )?;
    let transaction = connection.transaction()?;
    insert_state(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    insert_lifecycle(&transaction, &fixture.fence, 1, &checkpoint_digest)?;
    transaction.execute(
        r#"
        INSERT INTO admission_operations (
            operation_id, request_namespace_digest, request_id,
            operation_json, state, terminal, coordinator_lease_epoch,
            version, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, 'prepared', 0, ?5, 1, 1000, 1000)
        "#,
        params![
            operation.binding().operation_id().as_str(),
            operation.binding().request_namespace_digest().as_str(),
            operation.binding().request_id().as_str(),
            encoded,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    assert!(insert_plan(
        &transaction,
        &operation,
        &fixture.fence,
        1,
        &checkpoint_digest,
    )
    .is_err());
    drop(transaction);
    connection.execute_batch("DROP TRIGGER fail_channel_prepared_plan")?;
    let counts: (i64, i64, i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_operations WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM channel_state_records),
            (SELECT COUNT(*) FROM channel_lifecycle_records),
            (SELECT COUNT(*) FROM channel_prepared_admission_plans)
        "#,
        [operation.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(counts, (0, 0, 0, 0));
    Ok(())
}

#[test]
fn second_serving_owner_is_denied() -> TestResult {
    let fixture = fixture()?;
    let second = SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root);
    assert!(matches!(
        second,
        Err(SqliteServingOwnerError::AlreadyServing(_))
    ));
    Ok(())
}

fn secure_temp_directory(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
