use super::*;

pub(super) fn exact_ready_effect_head_digest(
    advance: &VerifiedEconomicStateBatchAdvance,
    operation_id: &str,
    reservation_digest: &str,
) -> Result<String, ChannelLifecycleStoreError> {
    let mut effects = advance.batch().effect_slots.iter().filter(|effect| {
        effect.operation_id == operation_id
            && effect.effect_kind == CHANNEL_SERVICE_DISPATCH_EFFECT_KIND
            && effect.parameters_digest == reservation_digest
            && effect.state == EconomicEffectStateV1::Ready
    });
    let effect = effects
        .next()
        .ok_or_else(|| invalid("channel reservation batch lost its ready effect"))?;
    if effects.next().is_some() {
        return Err(invalid(
            "channel reservation batch has multiple ready effects",
        ));
    }
    let key = effect.resource_head_key();
    let mut transitions = advance
        .batch()
        .transitions
        .iter()
        .filter(|transition| transition.resource_key == key);
    let transition = transitions
        .next()
        .ok_or_else(|| invalid("channel reservation batch lost its ready effect head"))?;
    if transitions.next().is_some() {
        return Err(invalid(
            "channel reservation batch has multiple ready effect heads",
        ));
    }
    transition
        .next_head
        .digest()
        .map_err(|error| invalid(error.to_string()))
}

pub(super) fn qualify_reservation_against_prepared(
    prepared: &ChannelPreparedAdmissionRecordV1,
    reservation: &SignedChannelReservationV1,
    replay_request: &chio_core::economic_continuity::EconomicRequestBindingV1,
) -> Result<(), ChannelLifecycleStoreError> {
    let plan = prepared.plan();
    let body = &reservation.body;
    if plan.reservation != *body
        || plan.service.request != *replay_request
        || body.operation_id != prepared.operation().binding().operation_id().as_str()
        || body.request_id != prepared.operation().binding().request_id().as_str()
        || body.channel_id != plan.signed_open.body.channel_id
        || body.open_digest != plan.signed_open.digest().map_err(channel_error)?
        || body.service_binding_digest != plan.service.digest().map_err(channel_error)?
    {
        return Err(invalid(
            "signed channel reservation does not match its prepared plan",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelReservationParticipantCommitment<'a> {
    format: &'static str,
    operation_id: &'a str,
    reservation_id: &'a str,
    reservation_digest: &'a str,
    prepared_plan_digest: &'a str,
    authority_pins_digest: &'a str,
    replay_protocol_digest: &'a str,
    replay_content_digest: &'a str,
    stage_batch_id: &'a str,
    stage_descriptor_digest: &'a str,
    ready_effect_head_digest: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn channel_reservation_participant_digest(
    prepared: &ChannelPreparedAdmissionRecordV1,
    reservation_digest: &str,
    authority_pins_digest: &str,
    replay_protocol_digest: &str,
    replay_content_digest: &str,
    economic_stage: &EconomicStateStageRecord,
    ready_effect_head_digest: &str,
) -> Result<String, ChannelLifecycleStoreError> {
    let descriptor = economic_stage
        .descriptor()
        .ok_or_else(|| invalid("channel economic stage lost its replay descriptor"))?;
    let commitment = ChannelReservationParticipantCommitment {
        format: "chio.sqlite-channel-reservation-participant.v1",
        operation_id: prepared.operation().binding().operation_id().as_str(),
        reservation_id: &prepared.plan().reservation.reservation_id,
        reservation_digest,
        prepared_plan_digest: prepared.plan_digest(),
        authority_pins_digest,
        replay_protocol_digest,
        replay_content_digest,
        stage_batch_id: &economic_stage.batch().batch_id,
        stage_descriptor_digest: descriptor.digest(),
        ready_effect_head_digest,
    };
    canonical_json_bytes(&commitment)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invalid(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_pending_reservation_tx(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedAdmissionRecordV1,
    reservation: &SignedChannelReservationV1,
    reservation_digest: &str,
    reservation_json: &[u8],
    authority_pins_digest: &str,
    authority_pins_json: &[u8],
    replay_bytes: &[u8],
    replay_protocol_digest: &str,
    replay_content_digest: &str,
    economic_stage: &EconomicStateStageRecord,
    ready_effect_head_digest: &str,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let descriptor = economic_stage
        .descriptor()
        .ok_or_else(|| invalid("channel economic stage lost its replay descriptor"))?;
    let body = &reservation.body;
    let plan = prepared.plan();
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO channel_reservation_records (
                reservation_id, operation_id, channel_id, prior_sequence, sequence,
                prepared_plan_digest, reservation_digest, reservation_json,
                authority_pins_digest, authority_pins_json,
                request_binding_digest, provider_binding_digest,
                stage_batch_id, stage_descriptor_kind, stage_descriptor_key,
                stage_descriptor_digest, base_checkpoint_sequence,
                base_checkpoint_digest, ready_checkpoint_digest,
                ready_checkpoint_sequence, ready_effect_head_digest,
                replay_protocol_digest, replay_content_digest, replay_json,
                disposition, record_version, store_uuid, store_lease_id,
                store_owner_epoch, updated_at_unix_ms
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                ?24, 'pending_anchor', 1, ?25, ?26, ?27, ?28
            )
            "#,
            params![
                &body.reservation_id,
                &body.operation_id,
                &body.channel_id,
                sqlite_i64(
                    body.next_sequence
                        .checked_sub(1)
                        .ok_or_else(|| invalid("channel reservation sequence underflowed"))?,
                    "prior_sequence"
                )?,
                sqlite_i64(body.next_sequence, "sequence")?,
                prepared.plan_digest(),
                reservation_digest,
                reservation_json,
                authority_pins_digest,
                authority_pins_json,
                prepared
                    .operation()
                    .binding()
                    .request_binding_hash()
                    .as_str(),
                &plan.service.provider.qualification_digest,
                &economic_stage.batch().batch_id,
                descriptor.kind(),
                descriptor.key(),
                descriptor.digest(),
                sqlite_i64(
                    economic_stage.base_view().checkpoint_sequence,
                    "base_checkpoint_sequence"
                )?,
                &economic_stage.base_view().checkpoint_digest,
                &economic_stage.batch().checkpoint_digest,
                sqlite_i64(
                    economic_stage.batch().checkpoint_sequence,
                    "ready_checkpoint_sequence"
                )?,
                ready_effect_head_digest,
                replay_protocol_digest,
                replay_content_digest,
                replay_bytes,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "updated_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}

struct StoredChannelReservation {
    reservation_id: String,
    operation_id: String,
    channel_id: String,
    prior_sequence: u64,
    sequence: u64,
    prepared_plan_digest: String,
    reservation_digest: String,
    reservation_json: Vec<u8>,
    authority_pins_digest: String,
    authority_pins_json: Vec<u8>,
    request_binding_digest: String,
    provider_binding_digest: String,
    stage_batch_id: String,
    stage_descriptor_kind: String,
    stage_descriptor_key: String,
    stage_descriptor_digest: String,
    base_checkpoint_sequence: u64,
    base_checkpoint_digest: String,
    ready_checkpoint_digest: String,
    ready_checkpoint_sequence: u64,
    ready_effect_head_digest: String,
    replay_protocol_digest: String,
    replay_content_digest: String,
    replay_json: Vec<u8>,
    disposition: ChannelReservationDispositionV1,
    record_version: u64,
    updated_at_unix_ms: u64,
}

fn read_stored_channel_reservation(row: &Row<'_>) -> rusqlite::Result<StoredChannelReservation> {
    Ok(StoredChannelReservation {
        reservation_id: row.get(0)?,
        operation_id: row.get(1)?,
        channel_id: row.get(2)?,
        prior_sequence: stored_u64_sql(row.get(3)?, "prior_sequence")?,
        sequence: stored_u64_sql(row.get(4)?, "sequence")?,
        prepared_plan_digest: row.get(5)?,
        reservation_digest: row.get(6)?,
        reservation_json: row.get(7)?,
        authority_pins_digest: row.get(8)?,
        authority_pins_json: row.get(9)?,
        request_binding_digest: row.get(10)?,
        provider_binding_digest: row.get(11)?,
        stage_batch_id: row.get(12)?,
        stage_descriptor_kind: row.get(13)?,
        stage_descriptor_key: row.get(14)?,
        stage_descriptor_digest: row.get(15)?,
        base_checkpoint_sequence: stored_u64_sql(row.get(16)?, "base_checkpoint_sequence")?,
        base_checkpoint_digest: row.get(17)?,
        ready_checkpoint_digest: row.get(18)?,
        ready_checkpoint_sequence: stored_u64_sql(row.get(19)?, "ready_checkpoint_sequence")?,
        ready_effect_head_digest: row.get(20)?,
        replay_protocol_digest: row.get(21)?,
        replay_content_digest: row.get(22)?,
        replay_json: row.get(23)?,
        disposition: ChannelReservationDispositionV1::parse(&row.get::<_, String>(24)?).map_err(
            |error| {
                rusqlite::Error::FromSqlConversionFailure(
                    24,
                    rusqlite::types::Type::Text,
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()).into(),
                )
            },
        )?,
        record_version: stored_u64_sql(row.get(25)?, "record_version")?,
        updated_at_unix_ms: stored_u64_sql(row.get(26)?, "updated_at_unix_ms")?,
    })
}

pub(super) fn load_channel_reservation_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
) -> Result<Option<ChannelReservationStageRecordV1>, ChannelLifecycleStoreError> {
    let stored = transaction
        .query_row(
            r#"
            SELECT reservation_id, operation_id, channel_id, prior_sequence, sequence,
                   prepared_plan_digest, reservation_digest, reservation_json,
                   authority_pins_digest, authority_pins_json,
                   request_binding_digest, provider_binding_digest,
                   stage_batch_id, stage_descriptor_kind, stage_descriptor_key,
                   stage_descriptor_digest, base_checkpoint_sequence,
                   base_checkpoint_digest, ready_checkpoint_digest,
                   ready_checkpoint_sequence, ready_effect_head_digest,
                   replay_protocol_digest, replay_content_digest, replay_json,
                   disposition, record_version, updated_at_unix_ms
            FROM channel_reservation_records WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            read_stored_channel_reservation,
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let expected_pins_json = expected_authority_pins
        .canonical_bytes()
        .map_err(channel_error)?;
    let retained_pins =
        ChannelTransitionReplayAuthorityPinsV1::from_canonical_bytes(&stored.authority_pins_json)
            .map_err(channel_error)?;
    if retained_pins != *expected_authority_pins
        || stored.authority_pins_json != expected_pins_json
        || stored.authority_pins_digest
            != expected_authority_pins.digest().map_err(channel_error)?
    {
        return Err(invalid(
            "retained channel reservation authority pins differ from configuration",
        ));
    }
    let reservation: SignedChannelReservationV1 = serde_json::from_slice(&stored.reservation_json)
        .map_err(|error| invalid(error.to_string()))?;
    if encode(
        &reservation,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "signed channel reservation",
    )? != stored.reservation_json
        || reservation.digest().map_err(channel_error)? != stored.reservation_digest
    {
        return Err(invalid("retained signed channel reservation is corrupt"));
    }
    let replay = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
        &stored.replay_json,
        expected_authority_pins,
    )
    .map_err(channel_error)?;
    if replay.descriptor().kind() != ChannelTransitionReplayKindV1::Reservation
        || replay.verified_reservation_proposal().artifact() != &reservation
        || replay.descriptor().digest() != stored.replay_protocol_digest
        || sha256_hex(&stored.replay_json) != stored.replay_content_digest
    {
        return Err(invalid("retained channel reservation replay is corrupt"));
    }
    let economic_stage =
        crate::economic_state_cache::load_stage_tx(transaction, &stored.stage_batch_id)
            .map_err(economic_error)?
            .ok_or_else(|| invalid("channel reservation lost its economic stage"))?;
    let descriptor = economic_stage
        .descriptor()
        .ok_or_else(|| invalid("channel reservation economic stage lost its descriptor"))?;
    let current = verify_economic_state_view(
        economic_stage.base_view().clone(),
        &expected_authority_pins.anchor_pins(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    let advance = verify_economic_state_batch_advance(
        &current,
        economic_stage.batch().clone(),
        &expected_authority_pins.anchor_pins(),
        &replay,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let ready_effect_head_digest = exact_ready_effect_head_digest(
        &advance,
        &reservation.body.operation_id,
        &stored.reservation_digest,
    )?;
    let operation = crate::admission_operation_store::load_operation_for_participant_tx(
        transaction,
        operation_id,
    )
    .map_err(admission_error)?
    .ok_or(ChannelLifecycleStoreError::NotFound)?;
    let prepared = load_prepared_record(
        transaction,
        operation.clone(),
        stored.disposition == ChannelReservationDispositionV1::PendingAnchor,
    )?
    .ok_or(ChannelLifecycleStoreError::NotFound)?;
    qualify_reservation_against_prepared(&prepared, &reservation, replay.descriptor().request())?;
    let expected_prior = reservation
        .body
        .next_sequence
        .checked_sub(1)
        .ok_or_else(|| invalid("channel reservation sequence underflowed"))?;
    if stored.operation_id != operation_id.as_str()
        || stored.reservation_id != reservation.body.reservation_id
        || stored.channel_id != reservation.body.channel_id
        || stored.prior_sequence != expected_prior
        || stored.sequence != reservation.body.next_sequence
        || stored.prepared_plan_digest != prepared.plan_digest()
        || stored.request_binding_digest != operation.binding().request_binding_hash().as_str()
        || stored.provider_binding_digest != prepared.plan().service.provider.qualification_digest
        || stored.stage_descriptor_kind != CHANNEL_TRANSITION_REPLAY_FORMAT
        || stored.stage_descriptor_kind != descriptor.kind()
        || stored.stage_descriptor_key != replay.descriptor().key()
        || stored.stage_descriptor_key != descriptor.key()
        || stored.stage_descriptor_digest != descriptor.digest()
        || stored.stage_descriptor_digest != stored.replay_content_digest
        || stored.base_checkpoint_sequence != economic_stage.base_view().checkpoint_sequence
        || stored.base_checkpoint_digest != economic_stage.base_view().checkpoint_digest
        || stored.ready_checkpoint_sequence != economic_stage.batch().checkpoint_sequence
        || stored.ready_checkpoint_digest != economic_stage.batch().checkpoint_digest
        || stored.ready_effect_head_digest != ready_effect_head_digest
        || replay.descriptor().expected_batch_digest() != stored.ready_checkpoint_digest
        || !reservation_status_matches_stage(stored.disposition, economic_stage.status())
    {
        return Err(invalid(
            "retained channel reservation projection is inconsistent",
        ));
    }
    Ok(Some(ChannelReservationStageRecordV1 {
        operation,
        reservation,
        authority_pins: retained_pins,
        replay_bytes: stored.replay_json,
        economic_stage,
        disposition: stored.disposition,
        record_version: stored.record_version,
        updated_at_unix_ms: stored.updated_at_unix_ms,
    }))
}

fn reservation_status_matches_stage(
    disposition: ChannelReservationDispositionV1,
    stage: EconomicStateStageStatus,
) -> bool {
    match disposition {
        ChannelReservationDispositionV1::PendingAnchor => matches!(
            stage,
            EconomicStateStageStatus::DbStaged | EconomicStateStageStatus::EconomicAnchorAdvanced
        ),
        ChannelReservationDispositionV1::Live
        | ChannelReservationDispositionV1::Consumed
        | ChannelReservationDispositionV1::Cancelled
        | ChannelReservationDispositionV1::Incident => {
            stage == EconomicStateStageStatus::DbFinalized
        }
    }
}

pub(super) fn qualify_exact_staged_replay(
    existing: &ChannelReservationStageRecordV1,
    operation: &AdmissionOperationV1,
    advance: &VerifiedEconomicStateBatchAdvance,
    replay_bytes: &[u8],
    reservation_digest: &str,
) -> Result<(), ChannelLifecycleStoreError> {
    if existing.operation() != operation
        || existing.reservation().digest().map_err(channel_error)? != reservation_digest
        || existing.replay_bytes() != replay_bytes
        || existing.economic_stage().base_view() != advance.current().view()
        || existing.economic_stage().batch() != advance.batch()
        || existing.disposition() != ChannelReservationDispositionV1::PendingAnchor
    {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn qualify_exact_recovery_authority(
    existing: &ChannelReservationStageRecordV1,
    recovery_lease: &AdmissionRecoveryLease,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let binding = existing
        .economic_stage()
        .operation_binding()
        .ok_or_else(|| invalid("channel reservation stage lost its operation authority"))?;
    if binding.operation_id() != existing.operation().binding().operation_id().as_str()
        || binding.operation_state() != existing.operation().state()
        || binding.operation_version() != existing.operation().version()
        || binding.coordinator_lease_id() != recovery_lease.coordinator_lease_id().as_str()
        || binding.coordinator_lease_epoch() != recovery_lease.coordinator_lease_epoch()
        || binding.recovery_claimant_id() != recovery_lease.claimant_id().as_str()
        || binding.recovery_expires_at_unix_ms() != recovery_lease.expires_at_unix_ms()
        || binding.store_fence() != recovery_lease.store_fence()
        || binding.not_after_unix_ms() != Some(existing.reservation().body.expires_at_unix_ms)
        || trusted_now_unix_ms >= recovery_lease.expires_at_unix_ms()
        || trusted_now_unix_ms >= existing.reservation().body.expires_at_unix_ms
    {
        return Err(ChannelLifecycleStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn publish_live_lifecycle_tx(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedAdmissionRecordV1,
    admitted: &VerifiedAdmittedChannelReservationV1,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let snapshot = admitted.snapshot();
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    let plan = prepared.plan();
    if lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.live_reservation_id.as_deref()
            != Some(admitted.artifact().body.reservation_id.as_str())
        || lifecycle.operation_id.as_deref()
            != Some(prepared.operation().binding().operation_id().as_str())
        || escrow.status != ChannelEscrowReservationStatusV1::Open
    {
        return Err(invalid(
            "anchored channel reservation is not a live open lifecycle",
        ));
    }
    let lifecycle_json = encode(
        lifecycle,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "live channel lifecycle",
    )?;
    let escrow_json = encode(
        escrow,
        MAX_CHANNEL_ARTIFACT_BYTES,
        "live channel escrow reservation",
    )?;
    let changed = transaction
        .execute(
            r#"
            UPDATE channel_lifecycle_records
            SET lifecycle_json = ?1, escrow_json = ?2, lifecycle_state = 'open',
                latest_state_digest = ?3, latest_sequence = ?4,
                state_version = ?5, lifecycle_fence = ?6,
                live_reservation_id = ?7, operation_id = ?8,
                channel_head_digest = ?9, escrow_head_digest = ?10,
                checkpoint_sequence = ?11, checkpoint_digest = ?12,
                record_version = record_version + 1,
                store_uuid = ?13, store_lease_id = ?14, store_owner_epoch = ?15,
                updated_at_unix_ms = ?16
            WHERE channel_id = ?17 AND lifecycle_state = 'open'
              AND latest_state_digest = ?18 AND latest_sequence = ?19
              AND state_version = ?20 AND lifecycle_fence = ?21
              AND live_reservation_id IS NULL AND operation_id IS NULL
              AND channel_head_digest = ?22 AND escrow_head_digest = ?23
              AND checkpoint_sequence = ?24 AND checkpoint_digest = ?25
              AND record_version = 1
            "#,
            params![
                lifecycle_json,
                escrow_json,
                &lifecycle.latest_state_digest,
                sqlite_i64(lifecycle.latest_sequence, "latest_sequence")?,
                sqlite_i64(lifecycle.state_version, "state_version")?,
                sqlite_i64(lifecycle.lifecycle_fence, "lifecycle_fence")?,
                lifecycle.live_reservation_id.as_deref(),
                lifecycle.operation_id.as_deref(),
                snapshot.channel_head_digest(),
                snapshot.escrow_head_digest(),
                sqlite_i64(snapshot.checkpoint_sequence(), "checkpoint_sequence")?,
                snapshot.checkpoint_digest(),
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "updated_at_unix_ms")?,
                &plan.reservation.channel_id,
                &plan.lifecycle.latest_state_digest,
                sqlite_i64(plan.lifecycle.latest_sequence, "prior_latest_sequence")?,
                sqlite_i64(plan.lifecycle.state_version, "prior_state_version")?,
                sqlite_i64(plan.lifecycle.lifecycle_fence, "prior_lifecycle_fence")?,
                &plan.channel_head_digest,
                &plan.escrow_head_digest,
                sqlite_i64(plan.checkpoint_sequence, "prior_checkpoint_sequence")?,
                &plan.checkpoint_digest,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ChannelLifecycleStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn qualify_finalized_channel_tx(
    transaction: &Transaction<'_>,
    record: &ChannelReservationStageRecordV1,
    admitted: &VerifiedAdmittedChannelReservationV1,
) -> Result<(), ChannelLifecycleStoreError> {
    let operation = record.operation();
    let reservation_digest = record.reservation().digest().map_err(channel_error)?;
    let lifecycle = admitted.snapshot().lifecycle();
    let exact_lifecycle = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_lifecycle_records
            WHERE channel_id = ?1 AND lifecycle_state = 'open'
              AND latest_state_digest = ?2 AND latest_sequence = ?3
              AND state_version = ?4 AND lifecycle_fence = ?5
              AND live_reservation_id = ?6 AND operation_id = ?7
              AND channel_head_digest = ?8 AND escrow_head_digest = ?9
              AND checkpoint_sequence = ?10 AND checkpoint_digest = ?11
            "#,
            params![
                &record.reservation().body.channel_id,
                &lifecycle.latest_state_digest,
                sqlite_i64(lifecycle.latest_sequence, "latest_sequence")?,
                sqlite_i64(lifecycle.state_version, "state_version")?,
                sqlite_i64(lifecycle.lifecycle_fence, "lifecycle_fence")?,
                &record.reservation().body.reservation_id,
                operation.binding().operation_id().as_str(),
                admitted.snapshot().channel_head_digest(),
                admitted.snapshot().escrow_head_digest(),
                sqlite_i64(
                    admitted.snapshot().checkpoint_sequence(),
                    "checkpoint_sequence"
                )?,
                admitted.snapshot().checkpoint_digest(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if operation.state() != AdmissionOperationState::ReadyToDispatch
        || operation
            .channel_reservation_digest()
            .is_none_or(|digest| digest.as_str() != reservation_digest)
        || record.economic_stage().status() != EconomicStateStageStatus::DbFinalized
        || !exact_lifecycle
    {
        return Err(invalid(
            "finalized channel reservation projection is inconsistent",
        ));
    }
    Ok(())
}
