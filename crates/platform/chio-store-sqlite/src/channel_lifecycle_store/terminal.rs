use chio_core::economic_continuity::{EconomicContentV1, EconomicResourceKeyV1};
use chio_kernel::admission_operation::VerifiedChannelTerminalProjectionV1;
use chio_settle::channel::{
    ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1, ChannelLifecycleStatusV1,
    ChannelLifecycleViewV1, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
};

use super::*;

struct RetainedTerminalReservation {
    reservation_id: String,
    channel_id: String,
    sequence: u64,
    reservation_digest: String,
    reservation_json: Vec<u8>,
    ready_checkpoint_sequence: u64,
    ready_checkpoint_digest: String,
    disposition: ChannelReservationDispositionV1,
    record_version: u64,
    lifecycle_record_version: u64,
}

pub(crate) fn consume_channel_terminal_projection_tx(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
    apply_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let (retained, prior_lifecycle, prior_escrow) =
        qualify_terminal_reservation(transaction, projection)?;
    match retained.disposition {
        ChannelReservationDispositionV1::Consumed => verify_consumed_projection(
            transaction,
            projection,
            &retained,
            retained.lifecycle_record_version,
            retained.record_version,
        ),
        ChannelReservationDispositionV1::Live => apply_consumed_projection(
            transaction,
            projection,
            &retained,
            &prior_lifecycle,
            &prior_escrow,
            apply_fence,
            trusted_now_unix_ms,
        ),
        _ => Err(ChannelLifecycleStoreError::Conflict),
    }
}

pub(crate) fn verify_consumed_channel_terminal_projection_tx(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
) -> Result<(), ChannelLifecycleStoreError> {
    let (retained, _, _) = qualify_terminal_reservation(transaction, projection)?;
    if retained.disposition != ChannelReservationDispositionV1::Consumed {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    verify_consumed_projection(
        transaction,
        projection,
        &retained,
        retained.lifecycle_record_version,
        retained.record_version,
    )
}

fn qualify_terminal_reservation(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
) -> Result<
    (
        RetainedTerminalReservation,
        ChannelLifecycleViewV1,
        ChannelEscrowReservationViewV1,
    ),
    ChannelLifecycleStoreError,
> {
    let reservation = projection.signed_reservation();
    let reservation_digest = reservation.digest().map_err(channel_error)?;
    let retained =
        load_terminal_reservation(transaction, projection.operation_binding().operation_id())?;
    if retained.reservation_id != reservation.body.reservation_id
        || retained.channel_id != reservation.body.channel_id
        || retained.sequence != reservation.body.next_sequence
        || retained.reservation_digest != reservation_digest
        || retained.reservation_json
            != encode(
                reservation,
                MAX_CHANNEL_ARTIFACT_BYTES,
                "terminal signed channel reservation",
            )?
    {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    let (prior_lifecycle, prior_escrow) = qualify_predecessor(projection, &retained)?;
    Ok((retained, prior_lifecycle, prior_escrow))
}

fn load_terminal_reservation(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<RetainedTerminalReservation, ChannelLifecycleStoreError> {
    transaction
        .query_row(
            r#"
            SELECT reservation.reservation_id, reservation.channel_id,
                   reservation.sequence, reservation.reservation_digest,
                   reservation.reservation_json,
                   reservation.ready_checkpoint_sequence,
                   reservation.ready_checkpoint_digest,
                   reservation.disposition, reservation.record_version,
                   lifecycle.record_version
            FROM channel_reservation_records AS reservation
            JOIN channel_lifecycle_records AS lifecycle
              ON lifecycle.channel_id = reservation.channel_id
            WHERE reservation.operation_id = ?1
            "#,
            [operation_id.as_str()],
            |row| {
                Ok(RetainedTerminalReservation {
                    reservation_id: row.get(0)?,
                    channel_id: row.get(1)?,
                    sequence: stored_u64_sql(row.get(2)?, "reservation_sequence")?,
                    reservation_digest: row.get(3)?,
                    reservation_json: row.get(4)?,
                    ready_checkpoint_sequence: stored_u64_sql(
                        row.get(5)?,
                        "ready_checkpoint_sequence",
                    )?,
                    ready_checkpoint_digest: row.get(6)?,
                    disposition: ChannelReservationDispositionV1::parse(&row.get::<_, String>(7)?)
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7,
                                rusqlite::types::Type::Text,
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    error.to_string(),
                                )
                                .into(),
                            )
                        })?,
                    record_version: stored_u64_sql(row.get(8)?, "reservation_record_version")?,
                    lifecycle_record_version: stored_u64_sql(
                        row.get(9)?,
                        "lifecycle_record_version",
                    )?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or(ChannelLifecycleStoreError::NotFound)
}

fn qualify_predecessor(
    projection: &VerifiedChannelTerminalProjectionV1,
    retained: &RetainedTerminalReservation,
) -> Result<(ChannelLifecycleViewV1, ChannelEscrowReservationViewV1), ChannelLifecycleStoreError> {
    let channel_key = &projection.completed_effect_slot().resource_key;
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: channel_key.scope_id.clone(),
        resource_id: retained.channel_id.clone(),
    };
    let channel_head = projection
        .predecessor_view()
        .head(channel_key)
        .ok_or_else(|| invalid("channel terminal predecessor lost its channel head"))?;
    let escrow_head = projection
        .predecessor_view()
        .head(&escrow_key)
        .ok_or_else(|| invalid("channel terminal predecessor lost its escrow head"))?;
    let lifecycle: ChannelLifecycleViewV1 = decode_inline(&channel_head.state)?;
    let escrow: ChannelEscrowReservationViewV1 = decode_inline(&escrow_head.state)?;
    let reservation = projection.signed_reservation();
    let terminal_lifecycle = projection.terminal_lifecycle();
    let terminal_escrow = projection.terminal_escrow();
    if channel_key.resource_family != CHANNEL_LIFECYCLE_RESOURCE_FAMILY
        || channel_key.resource_id != retained.channel_id
        || channel_head
            .digest()
            .map_err(|error| invalid(error.to_string()))?
            != projection.prior_channel_head_digest().as_str()
        || escrow_head
            .digest()
            .map_err(|error| invalid(error.to_string()))?
            != projection.prior_escrow_head_digest().as_str()
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != retained.channel_id
        || lifecycle.latest_state_digest != reservation.body.prior_state_digest
        || lifecycle.latest_sequence.checked_add(1) != Some(retained.sequence)
        || lifecycle.live_reservation_id.as_deref() != Some(retained.reservation_id.as_str())
        || lifecycle.operation_id.as_deref()
            != Some(projection.operation_binding().operation_id().as_str())
        || lifecycle.state_version.checked_add(1) != Some(terminal_lifecycle.state_version)
        || lifecycle.lifecycle_fence.checked_add(1) != Some(terminal_lifecycle.lifecycle_fence)
        || channel_head.resource_version != lifecycle.state_version
        || channel_head.lifecycle_fence != lifecycle.lifecycle_fence
        || channel_head.operation_id != lifecycle.operation_id
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != retained.channel_id
        || escrow.version.checked_add(1) != Some(terminal_escrow.version)
        || escrow.lifecycle_fence.checked_add(1) != Some(terminal_escrow.lifecycle_fence)
        || escrow_head.resource_version != escrow.version
        || escrow_head.lifecycle_fence != escrow.lifecycle_fence
    {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok((lifecycle, escrow))
}

fn decode_inline<T: serde::de::DeserializeOwned>(
    content: &EconomicContentV1,
) -> Result<T, ChannelLifecycleStoreError> {
    let EconomicContentV1::Inline { value } = content else {
        return Err(invalid(
            "channel terminal predecessor content is not inline",
        ));
    };
    serde_json::from_value(value.clone()).map_err(|error| invalid(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn apply_consumed_projection(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
    retained: &RetainedTerminalReservation,
    prior_lifecycle: &ChannelLifecycleViewV1,
    prior_escrow: &ChannelEscrowReservationViewV1,
    apply_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let terminal_lifecycle = projection.terminal_lifecycle();
    let terminal_escrow = projection.terminal_escrow();
    let next_state = projection.signed_next_state();
    let next_state_digest = next_state.digest().map_err(channel_error)?;
    let next_state_json = encode(
        next_state,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal signed channel state",
    )?;
    transaction
        .execute(
            r#"
            INSERT INTO channel_state_records (
                channel_id, sequence, state_kind, state_digest,
                checkpoint_sequence, checkpoint_digest, state_json, operation_id,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            ) VALUES (?1, ?2, 'signed', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(channel_id, sequence) DO NOTHING
            "#,
            params![
                &retained.channel_id,
                sqlite_i64(retained.sequence, "terminal_sequence")?,
                &next_state_digest,
                sqlite_i64(
                    projection.terminal_batch().checkpoint_sequence,
                    "terminal_checkpoint_sequence"
                )?,
                projection.checkpoint_digest().as_str(),
                &next_state_json,
                projection.operation_binding().operation_id().as_str(),
                &apply_fence.store_uuid,
                &apply_fence.lease_id,
                sqlite_i64(apply_fence.owner_epoch, "terminal_store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "terminal_recorded_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    verify_terminal_state(transaction, projection, retained)?;

    let prior_lifecycle_json = encode(
        prior_lifecycle,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "prior channel lifecycle",
    )?;
    let prior_escrow_json = encode(
        prior_escrow,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "prior channel escrow",
    )?;
    let terminal_lifecycle_json = encode(
        terminal_lifecycle,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal channel lifecycle",
    )?;
    let terminal_escrow_json = encode(
        terminal_escrow,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal channel escrow",
    )?;
    let changed = transaction
        .execute(
            r#"
            UPDATE channel_lifecycle_records
            SET lifecycle_json = ?1, escrow_json = ?2, lifecycle_state = 'open',
                latest_state_digest = ?3, latest_sequence = ?4,
                state_version = ?5, lifecycle_fence = ?6,
                live_reservation_id = NULL, operation_id = NULL,
                channel_head_digest = ?7, escrow_head_digest = ?8,
                checkpoint_sequence = ?9, checkpoint_digest = ?10,
                record_version = record_version + 1,
                store_uuid = ?11, store_lease_id = ?12, store_owner_epoch = ?13,
                updated_at_unix_ms = ?14
            WHERE channel_id = ?15 AND lifecycle_json = ?16 AND escrow_json = ?17
              AND lifecycle_state = 'open' AND latest_state_digest = ?18
              AND latest_sequence = ?19 AND state_version = ?20
              AND lifecycle_fence = ?21 AND live_reservation_id = ?22
              AND operation_id = ?23 AND channel_head_digest = ?24
              AND escrow_head_digest = ?25 AND checkpoint_sequence = ?26
              AND checkpoint_digest = ?27 AND record_version = ?28
            "#,
            params![
                terminal_lifecycle_json,
                terminal_escrow_json,
                &terminal_lifecycle.latest_state_digest,
                sqlite_i64(
                    terminal_lifecycle.latest_sequence,
                    "terminal_latest_sequence"
                )?,
                sqlite_i64(terminal_lifecycle.state_version, "terminal_state_version")?,
                sqlite_i64(
                    terminal_lifecycle.lifecycle_fence,
                    "terminal_lifecycle_fence"
                )?,
                projection.terminal_channel_head_digest().as_str(),
                projection.terminal_escrow_head_digest().as_str(),
                sqlite_i64(
                    projection.terminal_batch().checkpoint_sequence,
                    "terminal_checkpoint_sequence"
                )?,
                projection.checkpoint_digest().as_str(),
                &apply_fence.store_uuid,
                &apply_fence.lease_id,
                sqlite_i64(apply_fence.owner_epoch, "terminal_store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "terminal_updated_at_unix_ms")?,
                &retained.channel_id,
                prior_lifecycle_json,
                prior_escrow_json,
                &prior_lifecycle.latest_state_digest,
                sqlite_i64(prior_lifecycle.latest_sequence, "prior_latest_sequence")?,
                sqlite_i64(prior_lifecycle.state_version, "prior_state_version")?,
                sqlite_i64(prior_lifecycle.lifecycle_fence, "prior_lifecycle_fence")?,
                &retained.reservation_id,
                projection.operation_binding().operation_id().as_str(),
                projection.prior_channel_head_digest().as_str(),
                projection.prior_escrow_head_digest().as_str(),
                sqlite_i64(
                    retained.ready_checkpoint_sequence,
                    "ready_checkpoint_sequence"
                )?,
                &retained.ready_checkpoint_digest,
                sqlite_i64(
                    retained.lifecycle_record_version,
                    "prior_lifecycle_record_version"
                )?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ChannelLifecycleStoreError::Fenced);
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE channel_reservation_records
            SET disposition = 'consumed', record_version = record_version + 1,
                store_uuid = ?1, store_lease_id = ?2, store_owner_epoch = ?3,
                updated_at_unix_ms = ?4
            WHERE operation_id = ?5 AND reservation_id = ?6
              AND disposition = 'live' AND record_version = ?7
            "#,
            params![
                &apply_fence.store_uuid,
                &apply_fence.lease_id,
                sqlite_i64(apply_fence.owner_epoch, "terminal_store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "terminal_updated_at_unix_ms")?,
                projection.operation_binding().operation_id().as_str(),
                &retained.reservation_id,
                sqlite_i64(retained.record_version, "reservation_record_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ChannelLifecycleStoreError::Fenced);
    }
    verify_consumed_projection(
        transaction,
        projection,
        retained,
        retained
            .lifecycle_record_version
            .checked_add(1)
            .ok_or_else(|| invalid("channel lifecycle record version overflowed"))?,
        retained
            .record_version
            .checked_add(1)
            .ok_or_else(|| invalid("channel reservation record version overflowed"))?,
    )
}

fn verify_consumed_projection(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
    retained: &RetainedTerminalReservation,
    expected_lifecycle_record_version: u64,
    expected_reservation_record_version: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    verify_terminal_state(transaction, projection, retained)?;
    let lifecycle_json = encode(
        projection.terminal_lifecycle(),
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal channel lifecycle",
    )?;
    let escrow_json = encode(
        projection.terminal_escrow(),
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal channel escrow",
    )?;
    let exact_lifecycle = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_lifecycle_records
            WHERE channel_id = ?1 AND lifecycle_json = ?2 AND escrow_json = ?3
              AND lifecycle_state = 'open' AND latest_state_digest = ?4
              AND latest_sequence = ?5 AND state_version = ?6
              AND lifecycle_fence = ?7 AND live_reservation_id IS NULL
              AND operation_id IS NULL AND channel_head_digest = ?8
              AND escrow_head_digest = ?9 AND checkpoint_sequence = ?10
              AND checkpoint_digest = ?11 AND record_version = ?12
            "#,
            params![
                &retained.channel_id,
                lifecycle_json,
                escrow_json,
                &projection.terminal_lifecycle().latest_state_digest,
                sqlite_i64(
                    projection.terminal_lifecycle().latest_sequence,
                    "terminal_latest_sequence"
                )?,
                sqlite_i64(
                    projection.terminal_lifecycle().state_version,
                    "terminal_state_version"
                )?,
                sqlite_i64(
                    projection.terminal_lifecycle().lifecycle_fence,
                    "terminal_lifecycle_fence"
                )?,
                projection.terminal_channel_head_digest().as_str(),
                projection.terminal_escrow_head_digest().as_str(),
                sqlite_i64(
                    projection.terminal_batch().checkpoint_sequence,
                    "terminal_checkpoint_sequence"
                )?,
                projection.checkpoint_digest().as_str(),
                sqlite_i64(expected_lifecycle_record_version, "terminal_record_version")?,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    let exact_reservation = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_reservation_records
            WHERE operation_id = ?1 AND reservation_id = ?2
              AND reservation_digest = ?3 AND disposition = 'consumed'
              AND record_version = ?4
            "#,
            params![
                projection.operation_binding().operation_id().as_str(),
                &retained.reservation_id,
                projection.reservation_digest().as_str(),
                sqlite_i64(
                    expected_reservation_record_version,
                    "terminal_reservation_record_version"
                )?,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact_lifecycle || !exact_reservation {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}

fn verify_terminal_state(
    transaction: &Transaction<'_>,
    projection: &VerifiedChannelTerminalProjectionV1,
    retained: &RetainedTerminalReservation,
) -> Result<(), ChannelLifecycleStoreError> {
    let state = projection.signed_next_state();
    let state_digest = state.digest().map_err(channel_error)?;
    let state_json = encode(
        state,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "terminal signed channel state",
    )?;
    let exact = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_state_records
            WHERE channel_id = ?1 AND sequence = ?2 AND state_kind = 'signed'
              AND state_digest = ?3 AND checkpoint_sequence = ?4
              AND checkpoint_digest = ?5 AND state_json = ?6 AND operation_id = ?7
            "#,
            params![
                &retained.channel_id,
                sqlite_i64(retained.sequence, "terminal_sequence")?,
                state_digest,
                sqlite_i64(
                    projection.terminal_batch().checkpoint_sequence,
                    "terminal_checkpoint_sequence"
                )?,
                projection.checkpoint_digest().as_str(),
                state_json,
                projection.operation_binding().operation_id().as_str(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}
