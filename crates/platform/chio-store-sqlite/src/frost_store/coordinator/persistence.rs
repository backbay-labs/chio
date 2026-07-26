use std::collections::BTreeMap;

use chio_core::StoreMutationFence;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::Serialize;

use super::{coordinator_projection_key, invalid, StoredCoordinator};
use crate::frost_store::commit::{append_projection_commit, prefixed_digest, ProjectionMutation};
use crate::frost_store::{FrostCoordinatorSessionState, FrostStoreError, SqliteFrostStore};

pub(super) fn insert_coordinator(
    transaction: &Transaction<'_>,
    stored: &StoredCoordinator,
) -> Result<(), FrostStoreError> {
    let commitments_json = encode_byte_map(&stored.commitments)?;
    let signing_participants_json = stored
        .signing_participants
        .as_ref()
        .map(canonical_bytes)
        .transpose()?;
    let shares_json = encode_byte_map(&stored.shares)?;
    transaction
        .execute(
            r#"
            INSERT INTO frost_coordinator_sessions (
                session_id, authorization_slot_id, scope_id, key_epoch,
                authorization_id, signing_message_digest, roster_digest,
                coordinator_id, resource_fence, authorization_body_json,
                roster_json, bound_checkpoint_digest, bound_checkpoint_json,
                state, row_version, commitments_json, signing_participants_json,
                signing_package, signing_package_digest, shares_json,
                authorization_blob, authorization_blob_digest, availability_receipt,
                burn_reason, coordinator_worker_id, coordinator_lease_id,
                coordinator_owner_epoch, lease_expires_at_unix_ms,
                source_store_uuid, source_lease_id, source_owner_epoch,
                created_at_unix_ms, updated_at_unix_ms, record_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31,
                ?32, ?33, ?34
            )
            "#,
            params![
                &stored.session_id,
                &stored.authorization_slot_id,
                &stored.scope_id,
                sqlite_u64(stored.key_epoch, "coordinator key epoch")?,
                &stored.authorization_id,
                &stored.signing_message_digest,
                &stored.roster_digest,
                &stored.coordinator_id,
                sqlite_u64(stored.resource_fence, "coordinator resource fence")?,
                &stored.authorization_body_json,
                &stored.roster_json,
                &stored.bound_checkpoint_digest,
                &stored.bound_checkpoint_json,
                stored.state.as_str(),
                sqlite_u64(stored.row_version, "coordinator row version")?,
                &commitments_json,
                signing_participants_json.as_deref(),
                stored.signing_package.as_deref(),
                stored.signing_package_digest.as_deref(),
                &shares_json,
                stored.authorization_blob.as_deref(),
                stored.authorization_blob_digest.as_deref(),
                stored.availability_receipt.as_deref(),
                stored.burn_reason.as_deref(),
                &stored.coordinator_worker_id,
                &stored.coordinator_lease_id,
                sqlite_u64(
                    stored.coordinator_owner_epoch,
                    "coordinator lease owner epoch"
                )?,
                sqlite_u64(stored.lease_expires_at_unix_ms, "coordinator lease expiry")?,
                &stored.source_fence.store_uuid,
                &stored.source_fence.lease_id,
                sqlite_u64(
                    stored.source_fence.owner_epoch,
                    "coordinator store owner epoch"
                )?,
                sqlite_u64(stored.created_at_unix_ms, "coordinator created time")?,
                sqlite_u64(stored.updated_at_unix_ms, "coordinator updated time")?,
                &stored.record_digest,
            ],
        )
        .map_err(crate::frost_store::sqlite_error)?;
    Ok(())
}

pub(super) fn update_coordinator(
    transaction: &Transaction<'_>,
    stored: &StoredCoordinator,
    previous_version: u64,
) -> Result<(), FrostStoreError> {
    let commitments_json = encode_byte_map(&stored.commitments)?;
    let signing_participants_json = stored
        .signing_participants
        .as_ref()
        .map(canonical_bytes)
        .transpose()?;
    let shares_json = encode_byte_map(&stored.shares)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE frost_coordinator_sessions
            SET state = ?1, row_version = ?2, commitments_json = ?3,
                signing_participants_json = ?4, signing_package = ?5,
                signing_package_digest = ?6, shares_json = ?7,
                authorization_blob = ?8, authorization_blob_digest = ?9,
                availability_receipt = ?10, burn_reason = ?11,
                coordinator_worker_id = ?12, coordinator_lease_id = ?13,
                coordinator_owner_epoch = ?14, lease_expires_at_unix_ms = ?15,
                source_store_uuid = ?16, source_lease_id = ?17,
                source_owner_epoch = ?18, updated_at_unix_ms = ?19,
                record_digest = ?20
            WHERE session_id = ?21 AND row_version = ?22
            "#,
            params![
                stored.state.as_str(),
                sqlite_u64(stored.row_version, "coordinator row version")?,
                &commitments_json,
                signing_participants_json.as_deref(),
                stored.signing_package.as_deref(),
                stored.signing_package_digest.as_deref(),
                &shares_json,
                stored.authorization_blob.as_deref(),
                stored.authorization_blob_digest.as_deref(),
                stored.availability_receipt.as_deref(),
                stored.burn_reason.as_deref(),
                &stored.coordinator_worker_id,
                &stored.coordinator_lease_id,
                sqlite_u64(
                    stored.coordinator_owner_epoch,
                    "coordinator lease owner epoch"
                )?,
                sqlite_u64(stored.lease_expires_at_unix_ms, "coordinator lease expiry")?,
                &stored.source_fence.store_uuid,
                &stored.source_fence.lease_id,
                sqlite_u64(
                    stored.source_fence.owner_epoch,
                    "coordinator store owner epoch"
                )?,
                sqlite_u64(stored.updated_at_unix_ms, "coordinator updated time")?,
                &stored.record_digest,
                &stored.session_id,
                sqlite_u64(previous_version, "previous coordinator row version")?,
            ],
        )
        .map_err(crate::frost_store::sqlite_error)?;
    if changed != 1 {
        return Err(FrostStoreError::Conflict(
            "coordinator session changed during transition",
        ));
    }
    Ok(())
}

pub(super) fn append_coordinator_commit(
    transaction: &Transaction<'_>,
    store: &SqliteFrostStore,
    stored: &StoredCoordinator,
    mutation_kind: &str,
    fence: &StoreMutationFence,
) -> Result<(), FrostStoreError> {
    append_projection_commit(
        transaction,
        store,
        &coordinator_projection_key(&stored.session_id),
        ProjectionMutation {
            sequence: stored.row_version,
            projection_type: "coordinator",
            mutation_kind,
            record_digest: &stored.record_digest,
        },
        fence,
    )
}

pub(super) fn load_coordinator_by_slot_query(
    connection: &Connection,
    slot_id: &str,
) -> Result<Option<StoredCoordinator>, FrostStoreError> {
    connection
        .query_row(
            &format!("{} WHERE authorization_slot_id = ?1", coordinator_select()),
            [slot_id],
            stored_coordinator_from_row,
        )
        .optional()
        .map_err(crate::frost_store::sqlite_error)
}

pub(super) fn load_coordinator_query(
    connection: &Connection,
    session_id: &str,
) -> Result<Option<StoredCoordinator>, FrostStoreError> {
    connection
        .query_row(
            &format!("{} WHERE session_id = ?1", coordinator_select()),
            [session_id],
            stored_coordinator_from_row,
        )
        .optional()
        .map_err(crate::frost_store::sqlite_error)
}

fn coordinator_select() -> &'static str {
    r#"
    SELECT session_id, authorization_slot_id, scope_id, key_epoch,
           authorization_id, signing_message_digest, roster_digest,
           coordinator_id, resource_fence, authorization_body_json,
           roster_json, bound_checkpoint_digest, bound_checkpoint_json,
           state, row_version, commitments_json, signing_participants_json,
           signing_package, signing_package_digest, shares_json,
           authorization_blob, authorization_blob_digest, availability_receipt,
           burn_reason, coordinator_worker_id, coordinator_lease_id,
           coordinator_owner_epoch, lease_expires_at_unix_ms,
           source_store_uuid, source_lease_id, source_owner_epoch,
           created_at_unix_ms, updated_at_unix_ms, record_digest
    FROM frost_coordinator_sessions
    "#
}

fn stored_coordinator_from_row(row: &Row<'_>) -> rusqlite::Result<StoredCoordinator> {
    let commitments_json = row.get::<_, Vec<u8>>(15)?;
    let commitments = decode_byte_map(&commitments_json, 15)?;
    let signing_participants_json = row.get::<_, Option<Vec<u8>>>(16)?;
    let signing_participants = signing_participants_json
        .as_deref()
        .map(|bytes| decode_canonical(bytes, 16))
        .transpose()?;
    let shares_json = row.get::<_, Vec<u8>>(19)?;
    let shares = decode_byte_map(&shares_json, 19)?;
    let state = FrostCoordinatorSessionState::parse(row.get::<_, String>(13)?.as_str())
        .map_err(to_sql_conversion)?;
    Ok(StoredCoordinator {
        session_id: row.get(0)?,
        authorization_slot_id: row.get(1)?,
        scope_id: row.get(2)?,
        key_epoch: sqlite_read_u64(row, 3)?,
        authorization_id: row.get(4)?,
        signing_message_digest: row.get(5)?,
        roster_digest: row.get(6)?,
        coordinator_id: row.get(7)?,
        resource_fence: sqlite_read_u64(row, 8)?,
        authorization_body_json: row.get(9)?,
        roster_json: row.get(10)?,
        bound_checkpoint_digest: row.get(11)?,
        bound_checkpoint_json: row.get(12)?,
        state,
        row_version: sqlite_read_u64(row, 14)?,
        commitments,
        signing_participants,
        signing_package: row.get(17)?,
        signing_package_digest: row.get(18)?,
        shares,
        authorization_blob: row.get(20)?,
        authorization_blob_digest: row.get(21)?,
        availability_receipt: row.get(22)?,
        burn_reason: row.get(23)?,
        coordinator_worker_id: row.get(24)?,
        coordinator_lease_id: row.get(25)?,
        coordinator_owner_epoch: sqlite_read_u64(row, 26)?,
        lease_expires_at_unix_ms: sqlite_read_u64(row, 27)?,
        source_fence: StoreMutationFence {
            store_uuid: row.get(28)?,
            lease_id: row.get(29)?,
            owner_epoch: sqlite_read_u64(row, 30)?,
        },
        created_at_unix_ms: sqlite_read_u64(row, 31)?,
        updated_at_unix_ms: sqlite_read_u64(row, 32)?,
        record_digest: row.get(33)?,
    })
}

pub(super) fn prefixed_coordinator_digest<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<String, FrostStoreError> {
    prefixed_digest(prefix, value)
}

fn encode_byte_map(values: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, FrostStoreError> {
    canonical_bytes(
        &values
            .iter()
            .map(|(key, value)| (key.as_str(), hex::encode(value)))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn decode_byte_map(bytes: &[u8], column: usize) -> rusqlite::Result<BTreeMap<String, Vec<u8>>> {
    let encoded: BTreeMap<String, String> = decode_canonical(bytes, column)?;
    encoded
        .into_iter()
        .map(|(key, value)| {
            hex::decode(&value)
                .map(|bytes| (key, bytes))
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        column,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })
        })
        .collect()
}

fn decode_canonical<T>(bytes: &[u8], column: usize) -> rusqlite::Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            Box::new(error),
        )
    })?;
    let canonical = chio_core::canonical::canonical_json_bytes(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            Box::new(error),
        )
    })?;
    if canonical != bytes {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            "non-canonical coordinator JSON".into(),
        ));
    }
    Ok(value)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, FrostStoreError> {
    chio_core::canonical::canonical_json_bytes(value).map_err(|error| invalid(error.to_string()))
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, FrostStoreError> {
    i64::try_from(value).map_err(|_| invalid(format!("{field} exceeds SQLite range")))
}

fn sqlite_read_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            "negative coordinator integer".into(),
        )
    })
}

fn to_sql_conversion(error: FrostStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(13, rusqlite::types::Type::Text, Box::new(error))
}
