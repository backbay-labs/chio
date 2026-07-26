use super::*;

pub(super) fn encode_prepared_plan(
    operation: &AdmissionOperationV1,
    prepared: &ChannelPreparedReservationV1,
    fence: &StoreMutationFence,
) -> Result<EncodedPreparedPlan, ChannelLifecycleStoreError> {
    let plan_digest = prepared.digest().map_err(channel_error)?;
    let plan_json = encode(prepared, MAX_CHANNEL_PREPARED_PLAN_BYTES, "prepared plan")?;
    let open_intent_digest = prepared
        .signed_open_intent
        .digest()
        .map_err(channel_error)?;
    let open_digest = prepared.signed_open.digest().map_err(channel_error)?;
    let (prior_state_kind, prior_state_digest, prior_sequence, prior_state_json) =
        match &prepared.prior_state {
            RetainedChannelStateV1::Initial { body } => (
                "initial",
                body.digest().map_err(channel_error)?,
                body.seq,
                encode(body, MAX_CHANNEL_ARTIFACT_BYTES, "initial channel state")?,
            ),
            RetainedChannelStateV1::Signed { state } => (
                "signed",
                state.digest().map_err(channel_error)?,
                state.body.seq,
                encode(state, MAX_CHANNEL_ARTIFACT_BYTES, "signed channel state")?,
            ),
        };
    let reservation = &prepared.reservation;
    let lifecycle = &prepared.lifecycle;
    let escrow = &prepared.escrow;
    let service = &prepared.service;
    let expected_next = prior_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("channel prior sequence overflowed"))?;
    let expected_reservation_id = derive_channel_reservation_id(
        &reservation.channel_id,
        &open_digest,
        &reservation.request_id,
        expected_next,
        &prior_state_digest,
    )
    .map_err(channel_error)?;
    let expected_dispatch_version = expected_dispatch_committed_version(
        operation.binding().kind(),
        operation.binding().participant_requirements(),
        operation.version(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    let expected_expiry_ms = prepared
        .signed_open_intent
        .body
        .channel_expiry_unix_secs
        .checked_mul(1_000)
        .ok_or_else(|| invalid("channel expiry overflows milliseconds"))?;
    let proposal_digest = reservation.proposal_digest().map_err(channel_error)?;
    let service_digest = service.digest().map_err(channel_error)?;
    let prior_body = match &prepared.prior_state {
        RetainedChannelStateV1::Initial { body } => body.as_ref(),
        RetainedChannelStateV1::Signed { state } => &state.body,
    };
    let proposal_matches = operation
        .channel_reservation_proposal_digest()
        .is_some_and(|digest| digest.as_str() == proposal_digest);
    if operation.state() != AdmissionOperationState::Prepared
        || operation.version() != 1
        || !operation.binding().participant_requirements().channel
        || !proposal_matches
        || prepared.signed_open.body.open_intent_digest != open_intent_digest
        || prepared.signed_open.body.channel_id != reservation.channel_id
        || (prior_state_kind == "initial"
            && (prior_sequence != 0
                || prepared.signed_open.body.initial_state_digest != prior_state_digest))
        || (prior_state_kind == "signed" && prior_sequence == 0)
        || prior_body.channel_id != reservation.channel_id
        || reservation.open_digest != open_digest
        || reservation.operation_id != operation.binding().operation_id().as_str()
        || reservation.request_id != operation.binding().request_id().as_str()
        || reservation.request_id != service.request.request_id
        || reservation.next_sequence != expected_next
        || reservation.prior_state_digest != prior_state_digest
        || reservation.service_binding_digest != service_digest
        || reservation.reservation_id != expected_reservation_id
        || service.request.request_namespace_digest
            != operation.binding().request_namespace_digest().as_str()
        || service.request.request_binding_digest
            != operation.binding().request_binding_hash().as_str()
        || service.action_digest != operation.binding().action_parameter_hash().as_str()
        || service.admission_handoff.operation_version != expected_dispatch_version
        || service.admission_handoff.lifecycle_fence != operation.coordinator_lease_epoch()
        || service.admission_handoff.store_fence != *fence
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != reservation.channel_id
        || lifecycle.latest_state_digest != prior_state_digest
        || lifecycle.latest_sequence != prior_sequence
        || lifecycle.state_version != reservation.channel_state_expected_version
        || lifecycle.lifecycle_fence != reservation.lifecycle_fence
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != reservation.channel_id
        || escrow.open_digest != open_digest
        || escrow.escrow_reference != prepared.signed_open_intent.body.escrow_reference
        || escrow.lifecycle_fence != lifecycle.lifecycle_fence
        || reservation.expires_at_unix_ms <= prepared.observed_at_unix_ms
        || reservation.expires_at_unix_ms > expected_expiry_ms
    {
        return Err(invalid(
            "prepared channel plan does not match its admission operation and retained state",
        ));
    }
    Ok(EncodedPreparedPlan {
        plan_digest,
        plan_json,
        open_intent_digest,
        open_intent_json: encode(
            &prepared.signed_open_intent,
            MAX_CHANNEL_ARTIFACT_BYTES,
            "signed channel open intent",
        )?,
        open_digest,
        open_json: encode(
            &prepared.signed_open,
            MAX_CHANNEL_ARTIFACT_BYTES,
            "signed channel open",
        )?,
        prior_state_kind,
        prior_state_digest,
        prior_sequence,
        prior_state_json,
        reservation_proposal_digest: proposal_digest,
        lifecycle_json: encode(
            &prepared.lifecycle,
            MAX_CHANNEL_ARTIFACT_BYTES,
            "channel lifecycle",
        )?,
        escrow_json: encode(
            &prepared.escrow,
            MAX_CHANNEL_ARTIFACT_BYTES,
            "channel escrow",
        )?,
    })
}

pub(super) fn insert_or_verify_state(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedReservationV1,
    encoded: &EncodedPreparedPlan,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    transaction
        .execute(
            r#"
            INSERT INTO channel_state_records (
                channel_id, sequence, state_kind, state_digest,
                checkpoint_sequence, checkpoint_digest, state_json, operation_id,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10, ?11)
            ON CONFLICT(channel_id, sequence) DO NOTHING
            "#,
            params![
                &prepared.reservation.channel_id,
                sqlite_i64(encoded.prior_sequence, "prior_sequence")?,
                encoded.prior_state_kind,
                &encoded.prior_state_digest,
                sqlite_i64(prepared.checkpoint_sequence, "checkpoint_sequence")?,
                &prepared.checkpoint_digest,
                &encoded.prior_state_json,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "recorded_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    verify_state(transaction, prepared, encoded)
}

fn verify_state(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedReservationV1,
    encoded: &EncodedPreparedPlan,
) -> Result<(), ChannelLifecycleStoreError> {
    let stored = transaction
        .query_row(
            r#"
            SELECT state_kind, state_digest, checkpoint_sequence,
                   checkpoint_digest, state_json
            FROM channel_state_records
            WHERE channel_id = ?1 AND sequence = ?2
            "#,
            params![
                &prepared.reservation.channel_id,
                sqlite_i64(encoded.prior_sequence, "prior_sequence")?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((kind, digest, checkpoint_sequence, checkpoint_digest, state_json)) = stored else {
        return Err(ChannelLifecycleStoreError::NotFound);
    };
    if kind != encoded.prior_state_kind
        || digest != encoded.prior_state_digest
        || stored_u64(checkpoint_sequence, "checkpoint_sequence")? != prepared.checkpoint_sequence
        || checkpoint_digest != prepared.checkpoint_digest
        || state_json != encoded.prior_state_json
    {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn insert_or_verify_lifecycle(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedReservationV1,
    encoded: &EncodedPreparedPlan,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    transaction
        .execute(
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
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?9,
                ?10, ?11, NULL, NULL, ?12, ?13, ?14, ?15, 1,
                ?16, ?17, ?18, ?19
            ) ON CONFLICT(channel_id) DO NOTHING
            "#,
            params![
                &prepared.reservation.channel_id,
                &encoded.open_intent_digest,
                &encoded.open_intent_json,
                &encoded.open_digest,
                &encoded.open_json,
                &encoded.lifecycle_json,
                &encoded.escrow_json,
                &encoded.prior_state_digest,
                sqlite_i64(encoded.prior_sequence, "prior_sequence")?,
                sqlite_i64(prepared.lifecycle.state_version, "state_version")?,
                sqlite_i64(prepared.lifecycle.lifecycle_fence, "lifecycle_fence")?,
                &prepared.channel_head_digest,
                &prepared.escrow_head_digest,
                sqlite_i64(prepared.checkpoint_sequence, "checkpoint_sequence")?,
                &prepared.checkpoint_digest,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "updated_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    verify_lifecycle(transaction, prepared, encoded)
}

fn verify_lifecycle(
    transaction: &Transaction<'_>,
    prepared: &ChannelPreparedReservationV1,
    encoded: &EncodedPreparedPlan,
) -> Result<(), ChannelLifecycleStoreError> {
    let stored = transaction
        .query_row(
            r#"
            SELECT open_intent_digest, open_intent_json, open_digest, open_json,
                   lifecycle_json, escrow_json, lifecycle_state,
                   latest_state_digest, latest_sequence, state_version,
                   lifecycle_fence, live_reservation_id, operation_id,
                   channel_head_digest, escrow_head_digest,
                   checkpoint_sequence, checkpoint_digest, record_version
            FROM channel_lifecycle_records WHERE channel_id = ?1
            "#,
            [&prepared.reservation.channel_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, i64>(17)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(stored) = stored else {
        return Err(ChannelLifecycleStoreError::NotFound);
    };
    if stored.0 != encoded.open_intent_digest
        || stored.1 != encoded.open_intent_json
        || stored.2 != encoded.open_digest
        || stored.3 != encoded.open_json
        || stored.4 != encoded.lifecycle_json
        || stored.5 != encoded.escrow_json
        || stored.6 != "open"
        || stored.7 != encoded.prior_state_digest
        || stored_u64(stored.8, "latest_sequence")? != encoded.prior_sequence
        || stored_u64(stored.9, "state_version")? != prepared.lifecycle.state_version
        || stored_u64(stored.10, "lifecycle_fence")? != prepared.lifecycle.lifecycle_fence
        || stored.11.is_some()
        || stored.12.is_some()
        || stored.13 != prepared.channel_head_digest
        || stored.14 != prepared.escrow_head_digest
        || stored_u64(stored.15, "checkpoint_sequence")? != prepared.checkpoint_sequence
        || stored.16 != prepared.checkpoint_digest
        || stored_u64(stored.17, "record_version")? != 1
    {
        return Err(ChannelLifecycleStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn insert_prepared_plan(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    prepared: &ChannelPreparedReservationV1,
    encoded: &EncodedPreparedPlan,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelLifecycleStoreError> {
    let changed = transaction
        .execute(
            r#"
            INSERT INTO channel_prepared_admission_plans (
                operation_id, request_id, request_namespace_digest,
                request_binding_digest, provider_binding_digest, reservation_id,
                channel_id, open_digest, prior_state_digest, prior_sequence,
                reservation_proposal_digest, lifecycle_state,
                state_version, lifecycle_fence,
                live_reservation_id, lifecycle_operation_id,
                channel_head_digest, escrow_head_digest,
                checkpoint_sequence, checkpoint_digest, plan_digest, plan_json,
                store_uuid, store_lease_id, store_owner_epoch, created_at_unix_ms
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'open',
                ?12, ?13, NULL, NULL, ?14, ?15, ?16, ?17, ?18, ?19,
                ?20, ?21, ?22, ?23
            )
            "#,
            params![
                operation.binding().operation_id().as_str(),
                operation.binding().request_id().as_str(),
                operation.binding().request_namespace_digest().as_str(),
                operation.binding().request_binding_hash().as_str(),
                &prepared.service.provider.qualification_digest,
                &prepared.reservation.reservation_id,
                &prepared.reservation.channel_id,
                &encoded.open_digest,
                &encoded.prior_state_digest,
                sqlite_i64(encoded.prior_sequence, "prior_sequence")?,
                &encoded.reservation_proposal_digest,
                sqlite_i64(prepared.lifecycle.state_version, "state_version")?,
                sqlite_i64(prepared.lifecycle.lifecycle_fence, "lifecycle_fence")?,
                &prepared.channel_head_digest,
                &prepared.escrow_head_digest,
                sqlite_i64(prepared.checkpoint_sequence, "checkpoint_sequence")?,
                &prepared.checkpoint_digest,
                &encoded.plan_digest,
                &encoded.plan_json,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "created_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invalid("prepared plan insert did not affect one row"));
    }
    Ok(())
}

pub(super) fn load_prepared_record(
    transaction: &Transaction<'_>,
    stored_operation: AdmissionOperationV1,
    require_base_lifecycle: bool,
) -> Result<Option<ChannelPreparedAdmissionRecordV1>, ChannelLifecycleStoreError> {
    let stored = transaction
        .query_row(
            r#"
            SELECT request_id, request_namespace_digest, request_binding_digest,
                   provider_binding_digest, reservation_id, channel_id, open_digest,
                   prior_state_digest, prior_sequence, reservation_proposal_digest,
                   lifecycle_state, state_version, lifecycle_fence,
                   live_reservation_id, lifecycle_operation_id,
                   channel_head_digest, escrow_head_digest,
                   checkpoint_sequence, checkpoint_digest, plan_digest, plan_json,
                   store_uuid, store_lease_id, store_owner_epoch, created_at_unix_ms
            FROM channel_prepared_admission_plans WHERE operation_id = ?1
            "#,
            [stored_operation.binding().operation_id().as_str()],
            read_stored_prepared_plan,
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let plan: ChannelPreparedReservationV1 =
        serde_json::from_slice(&stored.plan_json).map_err(|error| {
            invalid(format!(
                "stored channel prepared plan is invalid JSON: {error}"
            ))
        })?;
    let canonical = encode(
        &plan,
        MAX_CHANNEL_PREPARED_PLAN_BYTES,
        "stored prepared plan",
    )?;
    if canonical != stored.plan_json {
        return Err(invalid(
            "stored channel prepared plan is not canonical JSON",
        ));
    }
    let proposal_digest = stored_operation
        .channel_reservation_proposal_digest()
        .cloned()
        .ok_or_else(|| invalid("retained admission operation lost its channel proposal"))?;
    let begin_operation = AdmissionOperationV1::prepare(
        stored_operation.binding().clone(),
        stored.store_fence.owner_epoch,
    )
    .and_then(|operation| {
        operation.with_initial_channel_reservation_proposal_digest(proposal_digest)
    })
    .map_err(|error| invalid(error.to_string()))?;
    let encoded = encode_prepared_plan(&begin_operation, &plan, &stored.store_fence)?;
    let begin_count: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = 'begin'
            "#,
            [stored_operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if begin_count != 1 {
        return Err(invalid(
            "prepared channel plan does not have exactly one admission begin commit",
        ));
    }
    let (
        begin_version,
        begin_operation_digest,
        begin_recovery_digest,
        begin_participant,
        begin_store_uuid,
        begin_store_lease_id,
        begin_store_owner_epoch,
        begin_recorded_at_unix_ms,
    ): (
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        i64,
        i64,
    ) = transaction
        .query_row(
            r#"
            SELECT operation_version, operation_digest, recovery_claim_digest,
                   participant_digest, store_uuid, store_lease_id,
                   store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = 'begin'
            "#,
            [stored_operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let operation_json =
        canonical_json_bytes(&begin_operation.to_persisted()).map_err(|error| {
            invalid(format!(
                "retained admission operation encoding failed: {error}"
            ))
        })?;
    let expected_operation_digest = sha256_hex(&operation_json);
    let historical_fence_exists: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM chio_serving_leases
                WHERE store_uuid = ?1 AND lease_id = ?2 AND owner_epoch = ?3
            )
            "#,
            params![
                &stored.store_fence.store_uuid,
                &stored.store_fence.lease_id,
                sqlite_i64(stored.store_fence.owner_epoch, "store_owner_epoch")?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if stored_operation
        .channel_reservation_proposal_digest()
        .map(AdmissionDigest::as_str)
        != Some(encoded.reservation_proposal_digest.as_str())
        || stored_u64(begin_version, "begin_operation_version")? != 1
        || begin_operation_digest != expected_operation_digest
        || begin_recovery_digest.is_some()
        || begin_participant.as_deref() != Some(encoded.plan_digest.as_str())
        || begin_store_uuid != stored.store_fence.store_uuid
        || begin_store_lease_id != stored.store_fence.lease_id
        || stored_u64(begin_store_owner_epoch, "begin_store_owner_epoch")?
            != stored.store_fence.owner_epoch
        || stored_u64(begin_recorded_at_unix_ms, "begin_recorded_at_unix_ms")?
            != stored.created_at_unix_ms
        || !historical_fence_exists
        || stored.request_id != stored_operation.binding().request_id().as_str()
        || stored.request_namespace_digest
            != stored_operation
                .binding()
                .request_namespace_digest()
                .as_str()
        || stored.request_binding_digest
            != stored_operation.binding().request_binding_hash().as_str()
        || stored.provider_binding_digest != plan.service.provider.qualification_digest
        || stored.reservation_id != plan.reservation.reservation_id
        || stored.channel_id != plan.reservation.channel_id
        || stored.open_digest != encoded.open_digest
        || stored.prior_state_digest != encoded.prior_state_digest
        || stored.prior_sequence != encoded.prior_sequence
        || stored.reservation_proposal_digest != encoded.reservation_proposal_digest
        || stored.lifecycle_state != "open"
        || stored.state_version != plan.lifecycle.state_version
        || stored.lifecycle_fence != plan.lifecycle.lifecycle_fence
        || stored.live_reservation_id.is_some()
        || stored.lifecycle_operation_id.is_some()
        || stored.channel_head_digest != plan.channel_head_digest
        || stored.escrow_head_digest != plan.escrow_head_digest
        || stored.checkpoint_sequence != plan.checkpoint_sequence
        || stored.checkpoint_digest != plan.checkpoint_digest
        || stored.plan_digest != encoded.plan_digest
        || stored.created_at_unix_ms < plan.observed_at_unix_ms
        || stored.created_at_unix_ms >= plan.reservation.expires_at_unix_ms
    {
        return Err(invalid(
            "retained channel prepared plan evidence is inconsistent",
        ));
    }
    verify_state(transaction, &plan, &encoded).map_err(retained_projection_error)?;
    if require_base_lifecycle {
        verify_lifecycle(transaction, &plan, &encoded).map_err(retained_projection_error)?;
    }
    Ok(Some(ChannelPreparedAdmissionRecordV1 {
        operation: stored_operation,
        plan,
        plan_digest: stored.plan_digest,
        store_fence: stored.store_fence,
        created_at_unix_ms: stored.created_at_unix_ms,
    }))
}

fn read_stored_prepared_plan(row: &Row<'_>) -> rusqlite::Result<StoredPreparedPlan> {
    Ok(StoredPreparedPlan {
        request_id: row.get(0)?,
        request_namespace_digest: row.get(1)?,
        request_binding_digest: row.get(2)?,
        provider_binding_digest: row.get(3)?,
        reservation_id: row.get(4)?,
        channel_id: row.get(5)?,
        open_digest: row.get(6)?,
        prior_state_digest: row.get(7)?,
        prior_sequence: stored_u64_sql(row.get(8)?, "prior_sequence")?,
        reservation_proposal_digest: row.get(9)?,
        lifecycle_state: row.get(10)?,
        state_version: stored_u64_sql(row.get(11)?, "state_version")?,
        lifecycle_fence: stored_u64_sql(row.get(12)?, "lifecycle_fence")?,
        live_reservation_id: row.get(13)?,
        lifecycle_operation_id: row.get(14)?,
        channel_head_digest: row.get(15)?,
        escrow_head_digest: row.get(16)?,
        checkpoint_sequence: stored_u64_sql(row.get(17)?, "checkpoint_sequence")?,
        checkpoint_digest: row.get(18)?,
        plan_digest: row.get(19)?,
        plan_json: row.get(20)?,
        store_fence: StoreMutationFence {
            store_uuid: row.get(21)?,
            lease_id: row.get(22)?,
            owner_epoch: stored_u64_sql(row.get(23)?, "store_owner_epoch")?,
        },
        created_at_unix_ms: stored_u64_sql(row.get(24)?, "created_at_unix_ms")?,
    })
}
