use chio_core::capability::scope::MonetaryAmount;
use chio_credit::obligation::{ObligationDispositionTransitionV1, ObligationDispositionV1};
use chio_settle::channel::SignedChannelReservationV1;

use super::*;

mod head;

pub(super) use head::append_disposition_transition as append_obligation_disposition_transition;
#[cfg(test)]
pub(super) use head::append_settlement_transition as append_obligation_settlement_transition;

#[derive(Deserialize)]
struct PersistedObligationProjectionV1 {
    source: PersistedObligationSourceV1,
    atom: ObligationAtomV1,
    disposition_record: ObligationDispositionRecordV1,
}

#[derive(Deserialize)]
struct PersistedObligationSourceV1 {
    source_authority_digest: String,
    source_record_id: String,
    source_record_digest: String,
    source_recorded_at_unix_ms: u64,
    consumer_receipt_id: String,
    consumer_receipt_digest: String,
}

#[derive(Deserialize)]
struct PersistedChannelTerminalV1 {
    reservation_id: String,
    reservation_digest: String,
    receipt_id: String,
    receipt_digest: String,
    actual_charge: MonetaryAmount,
    obligation_atom_id: Option<String>,
    obligation_atom_digest: Option<String>,
    signed_reservation: SignedChannelReservationV1,
}

struct StoredAtomRow {
    operation_id: String,
    atom_digest: String,
    source_receipt_id: String,
    source_receipt_digest: String,
    atom_json: Vec<u8>,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

struct StoredDispositionRow {
    version: i64,
    lifecycle_fence: i64,
    atom_digest: String,
    disposition_digest: String,
    operation_id: String,
    record_json: Vec<u8>,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

struct StoredSettlementRow {
    version: i64,
    lifecycle_fence: i64,
    atom_digest: String,
    lifecycle_digest: String,
    operation_id: String,
    record_json: Vec<u8>,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

pub(super) fn insert_obligation_projection(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    obligation_json: Option<&[u8]>,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(obligation_json) = obligation_json else {
        return Ok(());
    };
    let projection = decode_projection(obligation_json)?;
    validate_projection(&projection, channel_json, projection_trusted_time_unix_ms)?;
    let produced =
        ObligationDispositionRecordV1::produced(&projection.atom).map_err(obligation_error)?;
    insert_atom(
        transaction,
        operation_id,
        &projection.atom,
        committed_at_unix_ms,
        fence,
    )?;
    insert_disposition(
        transaction,
        operation_id,
        &projection.atom,
        &produced,
        committed_at_unix_ms,
        fence,
    )?;
    if projection.disposition_record != produced {
        insert_disposition(
            transaction,
            operation_id,
            &projection.atom,
            &projection.disposition_record,
            committed_at_unix_ms,
            fence,
        )?;
    }
    let settlement_lifecycle =
        ObligationSettlementLifecycleV1::pending(&projection.atom).map_err(obligation_error)?;
    insert_settlement_lifecycle(
        transaction,
        operation_id,
        &projection.atom,
        &settlement_lifecycle,
        committed_at_unix_ms,
        fence,
    )?;
    head::insert_initial(
        transaction,
        operation_id,
        &projection.atom,
        &projection.disposition_record,
        &settlement_lifecycle,
        committed_at_unix_ms,
        fence,
    )?;
    Ok(())
}

pub(super) fn verify_obligation_projection(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    obligation_json: Option<&[u8]>,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let initial_source_row_count: i64 = connection
        .query_row(
            r#"
            SELECT (SELECT COUNT(*) FROM obligation_atoms WHERE operation_id = ?1)
                 + (SELECT COUNT(*) FROM obligation_head_commits
                    WHERE source_operation_id = ?1
                      AND source_kind = 'initial_projection')
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let Some(obligation_json) = obligation_json else {
        if initial_source_row_count != 0 {
            return Err(invariant(
                "terminal projection without an obligation has obligation state",
            ));
        }
        return Ok(());
    };
    let projection = decode_projection(obligation_json)?;
    validate_projection(&projection, channel_json, projection_trusted_time_unix_ms)?;
    let source_row_count: i64 = connection
        .query_row(
            r#"
            SELECT (SELECT COUNT(*) FROM obligation_atoms WHERE operation_id = ?1)
                 + (SELECT COUNT(*) FROM obligation_disposition_records WHERE operation_id = ?1)
                 + (SELECT COUNT(*) FROM obligation_settlement_lifecycle_records
                    WHERE operation_id = ?1)
                 + (SELECT COUNT(*) FROM obligation_head_commits
                    WHERE source_operation_id = ?1)
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let stored = load_durable_obligation(connection, projection.atom.obligation_id())?
        .ok_or_else(|| invariant("terminal obligation is absent from canonical storage"))?;
    let disposition_rows = load_disposition_rows(connection, projection.atom.obligation_id())?;
    let projected_row = disposition_rows
        .iter()
        .find(|row| {
            stored_u64(row.version, "obligation_disposition_version")
                .is_ok_and(|version| version == projection.disposition_record.version())
        })
        .ok_or_else(|| invariant("terminal obligation disposition is absent"))?;
    let projected_disposition: ObligationDispositionRecordV1 =
        decode_canonical(&projected_row.record_json, "obligation disposition")?;
    if stored.atom != projection.atom || projected_disposition != projection.disposition_record {
        return Err(invariant(
            "canonical obligation differs from its terminal projection",
        ));
    }
    let atom_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM obligation_atoms WHERE obligation_id = ?1 AND operation_id = ?2",
            params![projection.atom.obligation_id(), operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let prefix_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1 AND version <= ?2",
            params![
                projection.atom.obligation_id(),
                sqlite_i64(
                    projection.disposition_record.version(),
                    "obligation_disposition_version"
                )?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let projected_version = sqlite_i64(
        projection.disposition_record.version(),
        "obligation_disposition_version",
    )?;
    let expected_source_rows = projected_version
        .checked_add(3)
        .ok_or_else(|| invariant("terminal obligation source row count overflow"))?;
    if atom_count != 1
        || prefix_count != projected_version
        || source_row_count != expected_source_rows
    {
        return Err(invariant(
            "terminal obligation lacks its exact canonical prefix",
        ));
    }
    verify_projection_metadata(
        connection,
        operation_id,
        projection.atom.obligation_id(),
        projection.disposition_record.version(),
        committed_at_unix_ms,
        fence,
    )
}

pub(super) fn load_durable_obligation(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Option<DurableObligationV1>, AdmissionOperationStoreError> {
    let atom_row = connection
        .query_row(
            r#"
            SELECT operation_id, atom_digest, source_receipt_id, source_receipt_digest,
                   atom_json, committed_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM obligation_atoms
            WHERE obligation_id = ?1
            "#,
            [obligation_id],
            |row| {
                Ok(StoredAtomRow {
                    operation_id: row.get(0)?,
                    atom_digest: row.get(1)?,
                    source_receipt_id: row.get(2)?,
                    source_receipt_digest: row.get(3)?,
                    atom_json: row.get(4)?,
                    committed_at_unix_ms: row.get(5)?,
                    store_uuid: row.get(6)?,
                    store_lease_id: row.get(7)?,
                    store_owner_epoch: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(atom_row) = atom_row else {
        return Ok(None);
    };
    let atom: ObligationAtomV1 = decode_canonical(&atom_row.atom_json, "obligation atom")?;
    atom.validate().map_err(obligation_error)?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    if atom.obligation_id() != obligation_id
        || atom_digest != atom_row.atom_digest
        || atom.source_receipt_id() != atom_row.source_receipt_id
        || atom.source_receipt_digest() != atom_row.source_receipt_digest
    {
        return Err(invariant("stored obligation atom columns are inconsistent"));
    }
    verify_exact_lease(
        connection,
        &atom_row.store_uuid,
        &atom_row.store_lease_id,
        atom_row.store_owner_epoch,
    )?;
    let rows = load_disposition_rows(connection, obligation_id)?;
    if rows.is_empty() {
        return Err(invariant("stored obligation lacks a disposition"));
    }
    let mut previous: Option<ObligationDispositionRecordV1> = None;
    for row in &rows {
        let disposition: ObligationDispositionRecordV1 =
            decode_canonical(&row.record_json, "obligation disposition")?;
        disposition
            .validate_against(&atom)
            .map_err(obligation_error)?;
        if matches!(
            disposition.last_transition(),
            ObligationDispositionTransitionV1::Assign { operation_id, .. }
                if operation_id != &row.operation_id
        ) {
            return Err(invariant(
                "stored assignment disposition has different operation provenance",
            ));
        }
        let valid_successor = match &previous {
            None => {
                disposition
                    == ObligationDispositionRecordV1::produced(&atom).map_err(obligation_error)?
            }
            Some(previous) => previous.validate_successor(&atom, &disposition).is_ok(),
        };
        if !valid_successor
            || disposition.version() != stored_u64(row.version, "obligation_disposition_version")?
            || disposition.lifecycle_fence()
                != stored_u64(
                    row.lifecycle_fence,
                    "obligation_disposition_lifecycle_fence",
                )?
            || disposition.atom_digest() != row.atom_digest
            || disposition.digest(&atom).map_err(obligation_error)? != row.disposition_digest
        {
            return Err(invariant(
                "stored obligation disposition columns are inconsistent",
            ));
        }
        verify_exact_lease(
            connection,
            &row.store_uuid,
            &row.store_lease_id,
            row.store_owner_epoch,
        )?;
        if disposition.version() == 1
            && (row.operation_id != atom_row.operation_id
                || row.committed_at_unix_ms != atom_row.committed_at_unix_ms
                || row.store_uuid != atom_row.store_uuid
                || row.store_lease_id != atom_row.store_lease_id
                || row.store_owner_epoch != atom_row.store_owner_epoch)
        {
            return Err(invariant(
                "produced obligation disposition differs from its atom commit",
            ));
        }
        previous = Some(disposition);
    }
    let disposition = previous.ok_or_else(|| invariant("stored obligation lacks a disposition"))?;
    let settlement_rows = load_settlement_rows(connection, obligation_id)?;
    if settlement_rows.is_empty() {
        return Err(invariant("stored obligation lacks a settlement lifecycle"));
    }
    let mut settlement_lifecycle: Option<ObligationSettlementLifecycleV1> = None;
    for row in &settlement_rows {
        let lifecycle: ObligationSettlementLifecycleV1 =
            decode_canonical(&row.record_json, "obligation settlement lifecycle")?;
        lifecycle
            .validate_against(&atom)
            .map_err(obligation_error)?;
        let valid_successor = match &settlement_lifecycle {
            None => {
                lifecycle
                    == ObligationSettlementLifecycleV1::pending(&atom).map_err(obligation_error)?
            }
            Some(previous) => previous.validate_successor(&atom, &lifecycle).is_ok(),
        };
        if !valid_successor
            || lifecycle.version() != stored_u64(row.version, "obligation_settlement_version")?
            || lifecycle.lifecycle_fence()
                != stored_u64(row.lifecycle_fence, "obligation_settlement_lifecycle_fence")?
            || atom_digest != row.atom_digest
            || lifecycle.digest(&atom).map_err(obligation_error)? != row.lifecycle_digest
        {
            return Err(invariant(
                "stored obligation settlement lifecycle columns are inconsistent",
            ));
        }
        verify_exact_lease(
            connection,
            &row.store_uuid,
            &row.store_lease_id,
            row.store_owner_epoch,
        )?;
        if lifecycle.version() == 1
            && (row.operation_id != atom_row.operation_id
                || row.committed_at_unix_ms != atom_row.committed_at_unix_ms
                || row.store_uuid != atom_row.store_uuid
                || row.store_lease_id != atom_row.store_lease_id
                || row.store_owner_epoch != atom_row.store_owner_epoch)
        {
            return Err(invariant(
                "pending obligation settlement lifecycle differs from its atom commit",
            ));
        }
        settlement_lifecycle = Some(lifecycle);
    }
    let settlement_lifecycle = settlement_lifecycle
        .ok_or_else(|| invariant("stored obligation lacks a settlement lifecycle"))?;
    let head_commits = load_head_commit_rows(connection, obligation_id)?;
    let latest_head_commit = verify_head_commit_chain(
        connection,
        obligation_id,
        &atom_row,
        &rows,
        &settlement_rows,
        &head_commits,
    )?;
    let head = head::load_row(connection, obligation_id)?
        .ok_or_else(|| invariant("stored obligation lacks its authoritative head"))?;
    let snapshot_version = stored_u64(head.snapshot_version, "obligation_snapshot_version")?;
    let resource_fence = stored_u64(head.resource_fence, "obligation_resource_fence")?;
    if head.head_sequence != latest_head_commit.head_sequence
        || head.head_digest != latest_head_commit.head_digest
        || head.atom_digest != atom_digest
        || stored_u64(
            head.disposition_version,
            "obligation_head_disposition_version",
        )? != disposition.version()
        || stored_u64(
            head.disposition_lifecycle_fence,
            "obligation_head_disposition_lifecycle_fence",
        )? != disposition.lifecycle_fence()
        || stored_u64(
            head.settlement_version,
            "obligation_head_settlement_version",
        )? != settlement_lifecycle.version()
        || stored_u64(
            head.settlement_lifecycle_fence,
            "obligation_head_settlement_lifecycle_fence",
        )? != settlement_lifecycle.lifecycle_fence()
        || snapshot_version == 0
        || resource_fence == 0
        || head.snapshot_version != latest_head_commit.snapshot_version
        || head.resource_fence != latest_head_commit.resource_fence
        || head.updated_at_unix_ms != latest_head_commit.committed_at_unix_ms
        || head.store_uuid != latest_head_commit.store_uuid
        || head.store_lease_id != latest_head_commit.store_lease_id
        || head.store_owner_epoch != latest_head_commit.store_owner_epoch
    {
        return Err(invariant(
            "stored obligation head differs from its current state",
        ));
    }
    verify_exact_lease(
        connection,
        &head.store_uuid,
        &head.store_lease_id,
        head.store_owner_epoch,
    )?;
    Ok(Some(DurableObligationV1 {
        atom,
        disposition,
        settlement_lifecycle,
        head_sequence: stored_u64(head.head_sequence, "obligation_head_sequence")?,
        head_digest: head.head_digest,
        snapshot_version,
        resource_fence,
    }))
}

pub(super) fn load_obligation_atom_by_operation(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Option<ObligationAtomV1>, AdmissionOperationStoreError> {
    let atom_json = connection
        .query_row(
            "SELECT atom_json FROM obligation_atoms WHERE operation_id = ?1",
            [operation_id.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    atom_json
        .map(|bytes| decode_canonical(&bytes, "obligation atom"))
        .transpose()
}

pub(super) fn load_durable_obligation_at_head(
    connection: &Connection,
    obligation_id: &str,
    head_sequence: u64,
    head_digest: &str,
) -> Result<Option<DurableObligationV1>, AdmissionOperationStoreError> {
    let Some(current) = load_durable_obligation(connection, obligation_id)? else {
        return Ok(None);
    };
    let historical = connection
        .query_row(
            r#"
            SELECT disposition_version, disposition_digest,
                   settlement_version, settlement_lifecycle_digest,
                   snapshot_version, resource_fence
            FROM obligation_head_commits
            WHERE obligation_id = ?1 AND head_sequence = ?2 AND head_digest = ?3
            "#,
            params![
                obligation_id,
                sqlite_i64(head_sequence, "obligation_head_sequence")?,
                head_digest,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        disposition_version,
        disposition_digest,
        settlement_version,
        settlement_digest,
        snapshot_version,
        resource_fence,
    )) = historical
    else {
        return Ok(None);
    };
    let disposition_json = connection
        .query_row(
            "SELECT record_json FROM obligation_disposition_records WHERE obligation_id = ?1 AND version = ?2",
            params![obligation_id, disposition_version],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(sqlite_error)?;
    let disposition: ObligationDispositionRecordV1 =
        decode_canonical(&disposition_json, "historical obligation disposition")?;
    let settlement_json = connection
        .query_row(
            "SELECT record_json FROM obligation_settlement_lifecycle_records WHERE obligation_id = ?1 AND version = ?2",
            params![obligation_id, settlement_version],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(sqlite_error)?;
    let settlement_lifecycle: ObligationSettlementLifecycleV1 = decode_canonical(
        &settlement_json,
        "historical obligation settlement lifecycle",
    )?;
    if disposition
        .digest(current.atom())
        .map_err(obligation_error)?
        != disposition_digest
        || settlement_lifecycle
            .digest(current.atom())
            .map_err(obligation_error)?
            != settlement_digest
    {
        return Err(invariant(
            "historical obligation head differs from its retained records",
        ));
    }
    Ok(Some(DurableObligationV1 {
        atom: current.atom,
        disposition,
        settlement_lifecycle,
        head_sequence,
        head_digest: head_digest.to_owned(),
        snapshot_version: stored_u64(snapshot_version, "obligation_snapshot_version")?,
        resource_fence: stored_u64(resource_fence, "obligation_resource_fence")?,
    }))
}

fn decode_projection(
    bytes: &[u8],
) -> Result<PersistedObligationProjectionV1, AdmissionOperationStoreError> {
    serde_json::from_slice(bytes).map_err(|error| {
        invariant(format!(
            "terminal obligation projection is invalid: {error}"
        ))
    })
}

fn validate_projection(
    projection: &PersistedObligationProjectionV1,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    projection.atom.validate().map_err(obligation_error)?;
    projection
        .disposition_record
        .validate_against(&projection.atom)
        .map_err(obligation_error)?;
    let atom_digest = projection.atom.digest().map_err(obligation_error)?;
    if projection.source.source_record_id != projection.atom.obligation_id()
        || projection.source.source_record_digest != atom_digest
        || projection.source.source_authority_digest
            != projection.atom.pre_action_authority_digest()
        || projection.source.source_recorded_at_unix_ms != projection.atom.created_at_unix_ms()
        || projection.source.consumer_receipt_id != projection.atom.source_receipt_id()
        || projection.source.consumer_receipt_digest != projection.atom.source_receipt_digest()
        || projection.atom.created_at_unix_ms() != projection_trusted_time_unix_ms
    {
        return Err(invariant(
            "terminal obligation source does not match its exact atom",
        ));
    }
    let produced =
        ObligationDispositionRecordV1::produced(&projection.atom).map_err(obligation_error)?;
    if projection.disposition_record != produced {
        let expected = produced
            .advance(
                &projection.atom,
                projection.disposition_record.last_transition().clone(),
            )
            .map_err(obligation_error)?;
        if projection.disposition_record != expected {
            return Err(invariant(
                "terminal obligation disposition is not a direct atom transition",
            ));
        }
    }
    match projection.disposition_record.disposition() {
        ObligationDispositionV1::Channelized {
            channel_id,
            reservation_id,
        } => validate_channel_projection(
            projection,
            channel_json.ok_or_else(|| {
                invariant("channelized obligation lacks its channel terminal record")
            })?,
            channel_id,
            reservation_id,
        ),
        _ if channel_json.is_some() => Err(invariant(
            "channel terminal projection has a non-channelized obligation",
        )),
        _ => Ok(()),
    }
}

fn validate_channel_projection(
    projection: &PersistedObligationProjectionV1,
    channel_json: &[u8],
    channel_id: &str,
    reservation_id: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let channel: PersistedChannelTerminalV1 = serde_json::from_slice(channel_json)
        .map_err(|error| invariant(format!("channel terminal projection is invalid: {error}")))?;
    channel
        .signed_reservation
        .body
        .validate()
        .map_err(|error| invariant(format!("invalid channel reservation: {error}")))?;
    let reservation_digest = channel
        .signed_reservation
        .digest()
        .map_err(|error| invariant(format!("invalid channel reservation: {error}")))?;
    let atom_digest = projection.atom.digest().map_err(obligation_error)?;
    let transition_matches = matches!(
        projection.disposition_record.last_transition(),
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id: transitioned_channel,
            reservation_id: transitioned_reservation,
            authority_digest,
        } if transitioned_channel == channel_id
            && transitioned_reservation == reservation_id
            && authority_digest == &channel.reservation_digest
    );
    if channel.actual_charge.units == 0
        || &channel.actual_charge != projection.atom.amount()
        || channel.reservation_id != reservation_id
        || channel.signed_reservation.body.reservation_id != reservation_id
        || channel.signed_reservation.body.channel_id != channel_id
        || channel.reservation_digest != reservation_digest
        || channel.obligation_atom_id.as_deref() != Some(projection.atom.obligation_id())
        || channel.obligation_atom_digest.as_deref() != Some(atom_digest.as_str())
        || channel.receipt_id != projection.atom.source_receipt_id()
        || channel.receipt_digest != projection.atom.source_receipt_digest()
        || channel.reservation_digest != projection.atom.pre_action_authority_digest()
        || !transition_matches
    {
        return Err(invariant(
            "channel terminal record does not match its canonical obligation",
        ));
    }
    Ok(())
}

fn insert_atom(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let atom_json = canonical_json_bytes(atom)
        .map_err(|error| invariant(format!("obligation atom encoding failed: {error}")))?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_atoms (
                obligation_id, operation_id, atom_digest, source_receipt_id,
                source_receipt_digest, atom_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                atom.obligation_id(),
                operation_id.as_str(),
                atom_digest,
                atom.source_receipt_id(),
                atom.source_receipt_digest(),
                atom_json,
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("obligation atom did not insert exactly once"));
    }
    Ok(())
}

fn insert_disposition(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let record_json = canonical_json_bytes(disposition)
        .map_err(|error| invariant(format!("obligation disposition encoding failed: {error}")))?;
    let disposition_digest = disposition.digest(atom).map_err(obligation_error)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_disposition_records (
                obligation_id, version, lifecycle_fence, atom_digest,
                disposition_digest, operation_id, record_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                disposition.obligation_id(),
                sqlite_i64(disposition.version(), "obligation_disposition_version")?,
                sqlite_i64(
                    disposition.lifecycle_fence(),
                    "obligation_disposition_lifecycle_fence"
                )?,
                disposition.atom_digest(),
                disposition_digest,
                operation_id.as_str(),
                record_json,
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "obligation disposition did not insert exactly once",
        ));
    }
    Ok(())
}

fn insert_settlement_lifecycle(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    lifecycle: &ObligationSettlementLifecycleV1,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    lifecycle.validate_against(atom).map_err(obligation_error)?;
    let record_json = canonical_json_bytes(lifecycle).map_err(|error| {
        invariant(format!(
            "obligation settlement lifecycle encoding failed: {error}"
        ))
    })?;
    let lifecycle_digest = lifecycle.digest(atom).map_err(obligation_error)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_settlement_lifecycle_records (
                obligation_id, version, lifecycle_fence, atom_digest,
                lifecycle_digest, operation_id, record_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                atom.obligation_id(),
                sqlite_i64(lifecycle.version(), "obligation_settlement_version")?,
                sqlite_i64(
                    lifecycle.lifecycle_fence(),
                    "obligation_settlement_lifecycle_fence"
                )?,
                atom.digest().map_err(obligation_error)?,
                lifecycle_digest,
                operation_id.as_str(),
                record_json,
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "obligation settlement lifecycle did not insert exactly once",
        ));
    }
    Ok(())
}

fn load_disposition_rows(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Vec<StoredDispositionRow>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT version, lifecycle_fence, atom_digest, disposition_digest,
                   operation_id, record_json, committed_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM obligation_disposition_records
            WHERE obligation_id = ?1
            ORDER BY version
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([obligation_id], |row| {
            Ok(StoredDispositionRow {
                version: row.get(0)?,
                lifecycle_fence: row.get(1)?,
                atom_digest: row.get(2)?,
                disposition_digest: row.get(3)?,
                operation_id: row.get(4)?,
                record_json: row.get(5)?,
                committed_at_unix_ms: row.get(6)?,
                store_uuid: row.get(7)?,
                store_lease_id: row.get(8)?,
                store_owner_epoch: row.get(9)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(rows)
}

fn load_settlement_rows(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Vec<StoredSettlementRow>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT version, lifecycle_fence, atom_digest, lifecycle_digest,
                   operation_id, record_json, committed_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM obligation_settlement_lifecycle_records
            WHERE obligation_id = ?1
            ORDER BY version
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([obligation_id], |row| {
            Ok(StoredSettlementRow {
                version: row.get(0)?,
                lifecycle_fence: row.get(1)?,
                atom_digest: row.get(2)?,
                lifecycle_digest: row.get(3)?,
                operation_id: row.get(4)?,
                record_json: row.get(5)?,
                committed_at_unix_ms: row.get(6)?,
                store_uuid: row.get(7)?,
                store_lease_id: row.get(8)?,
                store_owner_epoch: row.get(9)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(rows)
}

fn load_head_commit_rows(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Vec<head::CommitRow>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT head_sequence, previous_head_digest, head_digest, atom_digest,
                   disposition_version, disposition_lifecycle_fence,
                   disposition_digest, settlement_version,
                   settlement_lifecycle_fence, settlement_lifecycle_digest,
                   snapshot_version, resource_fence, source_kind,
                   source_operation_id, participant_digest,
                   participant_commit_sequence, committed_at_unix_ms,
                   store_uuid, store_lease_id, store_owner_epoch
            FROM obligation_head_commits
            WHERE obligation_id = ?1
            ORDER BY head_sequence
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([obligation_id], |row| {
            Ok(head::CommitRow {
                head_sequence: row.get(0)?,
                previous_head_digest: row.get(1)?,
                head_digest: row.get(2)?,
                atom_digest: row.get(3)?,
                disposition_version: row.get(4)?,
                disposition_lifecycle_fence: row.get(5)?,
                disposition_digest: row.get(6)?,
                settlement_version: row.get(7)?,
                settlement_lifecycle_fence: row.get(8)?,
                settlement_lifecycle_digest: row.get(9)?,
                snapshot_version: row.get(10)?,
                resource_fence: row.get(11)?,
                source_kind: row.get(12)?,
                source_operation_id: row.get(13)?,
                participant_digest: row.get(14)?,
                participant_commit_sequence: row.get(15)?,
                committed_at_unix_ms: row.get(16)?,
                store_uuid: row.get(17)?,
                store_lease_id: row.get(18)?,
                store_owner_epoch: row.get(19)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(rows)
}

fn verify_head_commit_chain<'a>(
    connection: &Connection,
    obligation_id: &str,
    atom: &StoredAtomRow,
    dispositions: &[StoredDispositionRow],
    settlements: &[StoredSettlementRow],
    commits: &'a [head::CommitRow],
) -> Result<&'a head::CommitRow, AdmissionOperationStoreError> {
    if commits.is_empty() {
        return Err(invariant("stored obligation lacks a head commit"));
    }
    let mut previous: Option<&head::CommitRow> = None;
    for (index, commit) in commits.iter().enumerate() {
        let sequence = stored_u64(commit.head_sequence, "obligation_head_sequence")?;
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invariant("obligation head sequence overflow"))?;
        let disposition_version = stored_u64(
            commit.disposition_version,
            "obligation_head_disposition_version",
        )?;
        let settlement_version = stored_u64(
            commit.settlement_version,
            "obligation_head_settlement_version",
        )?;
        let disposition_index = disposition_version
            .checked_sub(1)
            .ok_or_else(|| invariant("obligation disposition version is zero"))?;
        let settlement_index = settlement_version
            .checked_sub(1)
            .ok_or_else(|| invariant("obligation settlement version is zero"))?;
        let disposition = dispositions
            .get(
                usize::try_from(disposition_index)
                    .map_err(|_| invariant("obligation disposition version is too large"))?,
            )
            .ok_or_else(|| invariant("obligation head references an absent disposition"))?;
        let settlement = settlements
            .get(
                usize::try_from(settlement_index)
                    .map_err(|_| invariant("obligation settlement version is too large"))?,
            )
            .ok_or_else(|| invariant("obligation head references an absent settlement"))?;
        let previous_digest = previous.map_or(head::GENESIS_DIGEST, |row| row.head_digest.as_str());
        let (
            source_kind,
            source_operation_id,
            committed_at,
            store_uuid,
            lease_id,
            owner_epoch,
            source_rows_match,
        ) = match previous {
            None => (
                "initial_projection",
                atom.operation_id.as_str(),
                atom.committed_at_unix_ms,
                atom.store_uuid.as_str(),
                atom.store_lease_id.as_str(),
                atom.store_owner_epoch,
                disposition.operation_id == atom.operation_id
                    && disposition.committed_at_unix_ms == atom.committed_at_unix_ms
                    && disposition.store_uuid == atom.store_uuid
                    && disposition.store_lease_id == atom.store_lease_id
                    && disposition.store_owner_epoch == atom.store_owner_epoch
                    && settlement.operation_id == atom.operation_id
                    && settlement.committed_at_unix_ms == atom.committed_at_unix_ms
                    && settlement.store_uuid == atom.store_uuid
                    && settlement.store_lease_id == atom.store_lease_id
                    && settlement.store_owner_epoch == atom.store_owner_epoch,
            ),
            Some(previous)
                if previous.disposition_version.checked_add(1)
                    == Some(commit.disposition_version)
                    && commit.settlement_version == previous.settlement_version =>
            {
                (
                    "disposition_transition",
                    disposition.operation_id.as_str(),
                    disposition.committed_at_unix_ms,
                    disposition.store_uuid.as_str(),
                    disposition.store_lease_id.as_str(),
                    disposition.store_owner_epoch,
                    true,
                )
            }
            Some(previous)
                if commit.disposition_version == previous.disposition_version
                    && previous.settlement_version.checked_add(1)
                        == Some(commit.settlement_version) =>
            {
                (
                    "settlement_lifecycle",
                    settlement.operation_id.as_str(),
                    settlement.committed_at_unix_ms,
                    settlement.store_uuid.as_str(),
                    settlement.store_lease_id.as_str(),
                    settlement.store_owner_epoch,
                    true,
                )
            }
            Some(_) => {
                return Err(invariant(
                    "obligation head commit does not advance exactly one lifecycle",
                ));
            }
        };
        let snapshot_version =
            stored_u64(commit.snapshot_version, "obligation_head_snapshot_version")?;
        let resource_fence = stored_u64(commit.resource_fence, "obligation_head_resource_fence")?;
        let preimage = head::CommitPreimageV1 {
            domain: "chio.obligation.head-commit.v1",
            obligation_id,
            head_sequence: sequence,
            previous_head_digest: &commit.previous_head_digest,
            atom_digest: &commit.atom_digest,
            disposition_version,
            disposition_lifecycle_fence: stored_u64(
                commit.disposition_lifecycle_fence,
                "obligation_head_disposition_lifecycle_fence",
            )?,
            disposition_digest: &commit.disposition_digest,
            settlement_version,
            settlement_lifecycle_fence: stored_u64(
                commit.settlement_lifecycle_fence,
                "obligation_head_settlement_lifecycle_fence",
            )?,
            settlement_lifecycle_digest: &commit.settlement_lifecycle_digest,
            snapshot_version,
            resource_fence,
            source_kind: &commit.source_kind,
            source_operation_id: &commit.source_operation_id,
            participant_digest: commit.participant_digest.as_deref(),
            participant_commit_sequence: commit
                .participant_commit_sequence
                .map(|sequence| stored_u64(sequence, "participant_commit_sequence"))
                .transpose()?,
            committed_at_unix_ms: stored_u64(
                commit.committed_at_unix_ms,
                "obligation_head_committed_at_unix_ms",
            )?,
            store_uuid: &commit.store_uuid,
            store_lease_id: &commit.store_lease_id,
            store_owner_epoch: stored_u64(
                commit.store_owner_epoch,
                "obligation_head_store_owner_epoch",
            )?,
        };
        if sequence != expected_sequence
            || commit.previous_head_digest != previous_digest
            || commit.atom_digest != atom.atom_digest
            || stored_u64(disposition.version, "obligation_disposition_version")?
                != disposition_version
            || commit.disposition_lifecycle_fence != commit.disposition_version
            || commit.disposition_digest != disposition.disposition_digest
            || commit.settlement_lifecycle_fence != commit.settlement_version
            || stored_u64(settlement.version, "obligation_settlement_version")?
                != settlement_version
            || commit.settlement_lifecycle_digest != settlement.lifecycle_digest
            || snapshot_version != sequence
            || resource_fence != sequence
            || commit.source_kind != source_kind
            || commit.source_operation_id != source_operation_id
            || !source_rows_match
            || (sequence == 1) != commit.participant_digest.is_none()
            || (sequence == 1) != commit.participant_commit_sequence.is_none()
            || previous.is_some_and(|row| commit.committed_at_unix_ms < row.committed_at_unix_ms)
            || commit.committed_at_unix_ms != committed_at
            || commit.store_uuid != store_uuid
            || commit.store_lease_id != lease_id
            || commit.store_owner_epoch != owner_epoch
            || head::digest(&preimage)? != commit.head_digest
        {
            return Err(invariant("stored obligation head commit is inconsistent"));
        }
        if let Some(participant_digest) = commit.participant_digest.as_deref() {
            verify_head_participant_commit(connection, commit, participant_digest)?;
        }
        verify_exact_lease(
            connection,
            &commit.store_uuid,
            &commit.store_lease_id,
            commit.store_owner_epoch,
        )?;
        previous = Some(commit);
    }
    previous.ok_or_else(|| invariant("stored obligation lacks a head commit"))
}

fn verify_head_participant_commit(
    connection: &Connection,
    head: &head::CommitRow,
    participant_digest: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let exists: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM admission_operation_commits
                WHERE commit_sequence = ?1
                  AND operation_id = ?2
                  AND mutation_kind = 'participant_update'
                  AND participant_digest = ?3
                  AND recorded_at_unix_ms = ?4
                  AND store_uuid = ?5
                  AND store_lease_id = ?6
                  AND store_owner_epoch = ?7
            )
            "#,
            params![
                head.participant_commit_sequence,
                &head.source_operation_id,
                participant_digest,
                head.committed_at_unix_ms,
                &head.store_uuid,
                &head.store_lease_id,
                head.store_owner_epoch,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exists {
        return Err(invariant(
            "obligation head lacks its exact admission participant commit",
        ));
    }
    Ok(())
}

fn verify_projection_metadata(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    obligation_id: &str,
    projected_disposition_version: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let invalid: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM obligation_atoms
                WHERE obligation_id = ?1
                  AND (operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
                UNION ALL
                SELECT 1 FROM obligation_disposition_records
                WHERE obligation_id = ?1
                  AND version <= ?7
                  AND (operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
                UNION ALL
                SELECT 1 FROM obligation_settlement_lifecycle_records
                WHERE obligation_id = ?1
                  AND version = 1
                  AND (operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
                UNION ALL
                SELECT 1 FROM obligation_head_commits
                WHERE obligation_id = ?1
                  AND head_sequence = 1
                  AND (source_operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
            )
            "#,
            params![
                obligation_id,
                operation_id.as_str(),
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
                sqlite_i64(
                    projected_disposition_version,
                    "obligation_disposition_version"
                )?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid {
        return Err(invariant(
            "canonical obligation is not bound to its terminal projection fence",
        ));
    }
    Ok(())
}

fn verify_exact_lease(
    connection: &Connection,
    store_uuid: &str,
    store_lease_id: &str,
    store_owner_epoch: i64,
) -> Result<(), AdmissionOperationStoreError> {
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
            "#,
            params![store_uuid, store_owner_epoch, store_lease_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if count != 1 {
        return Err(invariant("canonical obligation has no exact serving lease"));
    }
    Ok(())
}

fn decode_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T, AdmissionOperationStoreError> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| invariant(format!("{label} is invalid: {error}")))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| invariant(format!("{label} encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(invariant(format!("{label} is not canonical")));
    }
    Ok(value)
}

fn obligation_error(
    error: chio_credit::obligation::ObligationError,
) -> AdmissionOperationStoreError {
    invariant(format!("invalid canonical obligation: {error}"))
}

fn obligation_sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        invariant(format!(
            "canonical obligation conflicts with durable state: {error}"
        ))
    } else {
        sqlite_error(error)
    }
}
