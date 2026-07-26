use super::*;

pub(super) fn validate_candidate(
    candidate: &ChannelReleasePublisherCandidate,
) -> Result<(), ChannelReleasePublisherError> {
    for (field, digest) in [
        ("channel_id", candidate.channel_id.as_str()),
        ("open_digest", candidate.open_digest.as_str()),
        ("close_digest", candidate.close_digest.as_str()),
        ("close_body_digest", candidate.close_body_digest.as_str()),
        (
            "effective_close_digest",
            candidate.effective_close_digest.as_str(),
        ),
        ("final_state_digest", candidate.final_state_digest.as_str()),
        (
            "source_checkpoint_digest",
            candidate.source_checkpoint_digest.as_str(),
        ),
        (
            "source_channel_head_digest",
            candidate.source_channel_head_digest.as_str(),
        ),
        (
            "source_escrow_head_digest",
            candidate.source_escrow_head_digest.as_str(),
        ),
        (
            "closing_checkpoint_digest",
            candidate.closing_checkpoint_digest.as_str(),
        ),
        (
            "closing_channel_head_digest",
            candidate.closing_channel_head_digest.as_str(),
        ),
        (
            "closing_escrow_head_digest",
            candidate.closing_escrow_head_digest.as_str(),
        ),
        (
            "asset_binding_digest",
            candidate.asset_binding_digest.as_str(),
        ),
        (
            "original_dispatch_digest",
            candidate.original_dispatch_digest.as_str(),
        ),
        ("frost_slot_id", candidate.frost_slot_id.as_str()),
        (
            "frost_authorization_id",
            candidate.frost_authorization_id.as_str(),
        ),
        (
            "frost_action_digest",
            candidate.frost_action_digest.as_str(),
        ),
        (
            "frost_envelope_digest",
            candidate.frost_envelope_digest.as_str(),
        ),
        (
            "frost_roster_digest",
            candidate.frost_roster_digest.as_str(),
        ),
        ("publication_root", candidate.publication_root.as_str()),
        ("root_operation_id", candidate.root_operation_id.as_str()),
        (
            "root_effect_slot_id",
            candidate.root_effect_slot_id.as_str(),
        ),
        (
            "root_idempotency_key",
            candidate.root_idempotency_key.as_str(),
        ),
        ("root_call_digest", candidate.root_call_digest.as_str()),
        (
            "root_resource_head_digest",
            candidate.root_resource_head_digest.as_str(),
        ),
        (
            "release_operation_id",
            candidate.release_operation_id.as_str(),
        ),
        (
            "release_effect_slot_id",
            candidate.release_effect_slot_id.as_str(),
        ),
        (
            "release_idempotency_key",
            candidate.release_idempotency_key.as_str(),
        ),
        (
            "release_call_digest",
            candidate.release_call_digest.as_str(),
        ),
        (
            "release_resource_head_digest",
            candidate.release_resource_head_digest.as_str(),
        ),
        (
            "authorization_digest",
            candidate.authorization_digest.as_str(),
        ),
        (
            "prepared_call_digest",
            candidate.prepared_call_digest.as_str(),
        ),
    ] {
        validate_digest(field, digest)?;
    }
    candidate
        .closing_lifecycle
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    candidate
        .closing_escrow
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let next_channel_version = candidate
        .source_channel_state_version
        .checked_add(1)
        .ok_or_else(|| invalid("channel state version overflowed"))?;
    let next_escrow_version = candidate
        .source_escrow_reservation_version
        .checked_add(1)
        .ok_or_else(|| invalid("escrow reservation version overflowed"))?;
    let next_publisher_fence = candidate
        .source_lifecycle_fence
        .checked_add(1)
        .ok_or_else(|| invalid("publisher fence overflowed"))?;
    let bound = parse_base_units(&candidate.bound_token_base_units)?;
    let release = parse_base_units(&candidate.release_token_base_units)?;
    let refund = parse_base_units(&candidate.refund_token_base_units)?;
    let prepared_call: chio_settle::PreparedEvmCall =
        serde_json::from_slice(&candidate.prepared_call_json).map_err(|error| {
            invalid(format!("prepared channel release call is invalid: {error}"))
        })?;
    let canonical_call = encode(&prepared_call, "prepared channel release call")?;
    let canonical_authorization = canonicalize_json(&candidate.authorization_json)?;
    if candidate.closing_lifecycle.status != ChannelLifecycleStatusV1::Closing
        || candidate.closing_escrow.status != ChannelEscrowReservationStatusV1::Closing
        || candidate.closing_lifecycle.channel_id != candidate.channel_id
        || candidate.closing_escrow.channel_id != candidate.channel_id
        || candidate.closing_escrow.open_digest != candidate.open_digest
        || candidate.closing_escrow.escrow_reference.chain_id != candidate.chain_id
        || candidate.closing_escrow.escrow_reference.escrow_contract != candidate.escrow_contract
        || candidate.closing_escrow.escrow_reference.escrow_id != candidate.escrow_id
        || candidate.closing_lifecycle.latest_state_digest != candidate.final_state_digest
        || candidate.closing_lifecycle.latest_sequence != candidate.final_state_sequence
        || candidate.closing_lifecycle.state_version != next_channel_version
        || candidate.closing_escrow.version != next_escrow_version
        || candidate.closing_lifecycle.lifecycle_fence != next_publisher_fence
        || candidate.closing_escrow.lifecycle_fence != next_publisher_fence
        || candidate.publisher_fence != next_publisher_fence
        || candidate
            .closing_lifecycle
            .pending_close_body_digest
            .as_deref()
            != Some(candidate.close_body_digest.as_str())
        || candidate
            .closing_escrow
            .pending_close_body_digest
            .as_deref()
            != Some(candidate.close_body_digest.as_str())
        || candidate.closing_lifecycle.live_reservation_id.is_some()
        || candidate.closing_lifecycle.operation_id.is_some()
        || candidate.closing_channel_predecessor_digest != candidate.source_channel_head_digest
        || candidate.closing_escrow_predecessor_digest != candidate.source_escrow_head_digest
        || candidate.closing_checkpoint_sequence <= candidate.source_checkpoint_sequence
        || candidate.frost_resource_id != candidate.channel_id
        || candidate.frost_resource_version != candidate.source_channel_state_version
        || candidate.frost_resource_fence != candidate.source_lifecycle_fence
        || candidate.root_operation_id == candidate.release_operation_id
        || candidate.root_effect_slot_id == candidate.release_effect_slot_id
        || candidate.root_idempotency_key == candidate.release_idempotency_key
        || candidate.root_call_digest == candidate.release_call_digest
        || candidate.root_effect_scope_id != candidate.frost_scope_id
        || candidate.release_effect_scope_id != candidate.frost_scope_id
        || candidate.root_effect_kind != CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND
        || candidate.release_effect_kind != CHANNEL_RELEASE_BROADCAST_EFFECT_KIND
        || candidate.release_call_digest != candidate.prepared_call_digest
        || candidate.root_resource_head_digest != candidate.closing_escrow_head_digest
        || candidate.release_resource_head_digest != candidate.closing_escrow_head_digest
        || prepared_call.from_address != candidate.beneficiary_address
        || prepared_call.to_address != candidate.escrow_contract
        || canonical_call != candidate.prepared_call_json
        || sha256_hex(&canonical_call) != candidate.prepared_call_digest
        || canonical_authorization != candidate.authorization_json
        || authorization_digest(&canonical_authorization) != candidate.authorization_digest
        || release.checked_add(refund) != Some(bound)
        || candidate.close_submission_cutoff_unix_ms >= candidate.escrow_deadline_unix_ms
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn validate_candidate_freshness(
    candidate: &ChannelReleasePublisherCandidate,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelReleasePublisherError> {
    if trusted_now_unix_ms < candidate.authorized_at_unix_ms
        || trusted_now_unix_ms < candidate.frost_issued_at_unix_ms
        || trusted_now_unix_ms >= candidate.close_submission_cutoff_unix_ms
        || trusted_now_unix_ms >= candidate.escrow_deadline_unix_ms
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn qualify_durable_closing(
    transaction: &Transaction<'_>,
    candidate: &ChannelReleasePublisherCandidate,
    lifecycle_json: &[u8],
    escrow_json: &[u8],
) -> Result<(), ChannelReleasePublisherError> {
    let exact = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_lifecycle_records
            WHERE channel_id = ?1 AND open_digest = ?2
              AND lifecycle_json = ?3 AND escrow_json = ?4
              AND lifecycle_state = 'closing'
              AND latest_state_digest = ?5 AND latest_sequence = ?6
              AND state_version = ?7 AND lifecycle_fence = ?8
              AND live_reservation_id IS NULL AND operation_id IS NULL
              AND channel_head_digest = ?9 AND escrow_head_digest = ?10
              AND checkpoint_sequence = ?11 AND checkpoint_digest = ?12
            "#,
            params![
                &candidate.channel_id,
                &candidate.open_digest,
                lifecycle_json,
                escrow_json,
                &candidate.final_state_digest,
                sqlite_i64(candidate.final_state_sequence, "final_state_sequence")?,
                sqlite_i64(
                    candidate.closing_lifecycle.state_version,
                    "closing_state_version"
                )?,
                sqlite_i64(candidate.publisher_fence, "publisher_fence")?,
                &candidate.closing_channel_head_digest,
                &candidate.closing_escrow_head_digest,
                sqlite_i64(
                    candidate.closing_checkpoint_sequence,
                    "closing_checkpoint_sequence"
                )?,
                &candidate.closing_checkpoint_digest,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn qualify_durable_release_execution(
    transaction: &Transaction<'_>,
    candidate: &ChannelReleasePublisherCandidate,
    fence: &StoreMutationFence,
) -> Result<EconomicEffectSlotV1, ChannelReleasePublisherError> {
    let root_operation_id = AdmissionOperationId::from_persisted(&candidate.root_operation_id)
        .map_err(|error| invalid(error.to_string()))?;
    let release_operation_id =
        AdmissionOperationId::from_persisted(&candidate.release_operation_id)
            .map_err(|error| invalid(error.to_string()))?;
    let root_operation = crate::admission_operation_store::load_operation_for_participant_tx(
        transaction,
        &root_operation_id,
    )
    .map_err(admission_error)?
    .ok_or(ChannelReleasePublisherError::Fenced)?;
    let release_operation = crate::admission_operation_store::load_operation_for_participant_tx(
        transaction,
        &release_operation_id,
    )
    .map_err(admission_error)?
    .ok_or(ChannelReleasePublisherError::Fenced)?;
    let root_head = load_finalized_effect_head(
        transaction,
        &candidate.root_effect_scope_id,
        &candidate.root_effect_slot_id,
    )?;
    let release_head = load_finalized_effect_head(
        transaction,
        &candidate.release_effect_scope_id,
        &candidate.release_effect_slot_id,
    )?;
    qualify_release_execution(
        candidate,
        &root_operation,
        &release_operation,
        &root_head,
        &release_head,
        fence,
    )?;
    economic_effect_slot_from_head(&release_head).map_err(|error| invalid(error.to_string()))
}

pub(super) fn qualify_exact_dispatch_slot(
    candidate: &ChannelReleasePublisherCandidate,
    durable_slot: &EconomicEffectSlotV1,
    dispatch_slot: &EconomicEffectSlotV1,
    commit_id: &str,
) -> Result<(), ChannelReleasePublisherError> {
    validate_digest("economic dispatch commit_id", commit_id)?;
    candidate.verify_dispatch_slot(dispatch_slot)?;
    if encode(durable_slot, "durable channel release effect slot")?
        != encode(dispatch_slot, "verified channel release effect slot")?
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn load_finalized_effect_head(
    transaction: &Transaction<'_>,
    scope_id: &str,
    slot_id: &str,
) -> Result<EconomicResourceHeadV1, ChannelReleasePublisherError> {
    let key = EconomicResourceKeyV1 {
        resource_family: "effect_slot".to_owned(),
        scope_id: scope_id.to_owned(),
        resource_id: slot_id.to_owned(),
    };
    key.validate().map_err(|error| invalid(error.to_string()))?;
    let key_json = encode(&key, "channel release effect key")?;
    let key_digest = sha256_hex(&key_json);
    let stored = transaction
        .query_row(
            r#"
            SELECT current.resource_key_json, current.head_digest, current.head_json,
                   staged.head_digest, staged.head_json
            FROM economic_state_heads AS current
            JOIN economic_state_stage_heads AS staged
              ON staged.batch_id = current.source_batch_id
             AND staged.resource_key_digest = current.resource_key_digest
            JOIN economic_state_stages AS stage
              ON stage.batch_id = current.source_batch_id
             AND stage.status = 'db_finalized'
            WHERE current.resource_key_digest = ?1
            "#,
            [&key_digest],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or(ChannelReleasePublisherError::Fenced)?;
    let (stored_key, current_digest, current_head, staged_digest, staged_head) = stored;
    if stored_key != key_json || current_digest != staged_digest || current_head != staged_head {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    let head: EconomicResourceHeadV1 = serde_json::from_slice(&current_head)
        .map_err(|error| invalid(format!("channel release effect head is invalid: {error}")))?;
    if encode(&head, "channel release effect head")? != current_head
        || head.resource_key != key
        || head.digest().map_err(|error| invalid(error.to_string()))? != current_digest
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(head)
}

pub(super) fn qualify_release_execution(
    candidate: &ChannelReleasePublisherCandidate,
    root_operation: &AdmissionOperationV1,
    release_operation: &AdmissionOperationV1,
    root_head: &EconomicResourceHeadV1,
    release_head: &EconomicResourceHeadV1,
    fence: &StoreMutationFence,
) -> Result<(), ChannelReleasePublisherError> {
    qualify_governed_operation(
        root_operation,
        &candidate.root_operation_id,
        &candidate.root_call_digest,
        &candidate.authorization_digest,
        AdmissionOperationState::EconomicMutationApplied,
    )?;
    qualify_governed_operation(
        release_operation,
        &candidate.release_operation_id,
        &candidate.release_call_digest,
        &candidate.authorization_digest,
        AdmissionOperationState::MutationSubmitted,
    )?;
    let root_slot =
        economic_effect_slot_from_head(root_head).map_err(|error| invalid(error.to_string()))?;
    let release_slot =
        economic_effect_slot_from_head(release_head).map_err(|error| invalid(error.to_string()))?;
    qualify_effect_binding(
        candidate,
        root_operation,
        root_head,
        &root_slot,
        &candidate.root_effect_slot_id,
        &candidate.root_effect_scope_id,
        &candidate.root_effect_kind,
        &candidate.root_idempotency_key,
        &candidate.root_call_digest,
        &candidate.root_resource_head_digest,
        EconomicEffectStateV1::Completed,
        fence,
    )?;
    qualify_effect_binding(
        candidate,
        release_operation,
        release_head,
        &release_slot,
        &candidate.release_effect_slot_id,
        &candidate.release_effect_scope_id,
        &candidate.release_effect_kind,
        &candidate.release_idempotency_key,
        &candidate.release_call_digest,
        &candidate.release_resource_head_digest,
        EconomicEffectStateV1::DispatchCommitted,
        fence,
    )?;
    qualify_root_publication_result(candidate, root_head, &root_slot)
}

pub(super) fn qualify_governed_operation(
    operation: &AdmissionOperationV1,
    operation_id: &str,
    call_digest: &str,
    authorization_digest: &str,
    expected_state: AdmissionOperationState,
) -> Result<(), ChannelReleasePublisherError> {
    let binding = operation.binding();
    if binding.kind() != AdmissionOperationKind::GovernedEconomicMutation
        || binding.effect_class() != SideEffectClass::Monetary
        || binding.operation_id().as_str() != operation_id
        || binding.action_parameter_hash().as_str() != call_digest
        || binding.immutable_request_hash().as_str() != authorization_digest
        || operation.state() != expected_state
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn qualify_effect_binding(
    candidate: &ChannelReleasePublisherCandidate,
    operation: &AdmissionOperationV1,
    head: &EconomicResourceHeadV1,
    slot: &EconomicEffectSlotV1,
    slot_id: &str,
    scope_id: &str,
    effect_kind: &str,
    idempotency_key: &str,
    call_digest: &str,
    resource_head_digest: &str,
    expected_state: EconomicEffectStateV1,
    fence: &StoreMutationFence,
) -> Result<(), ChannelReleasePublisherError> {
    let binding = operation.binding();
    let handoff_version_matches = if expected_state == EconomicEffectStateV1::Completed {
        slot.admission_handoff.operation_version.checked_add(1) == Some(operation.version())
    } else {
        slot.admission_handoff.operation_version == operation.version()
    };
    let frost = slot.frost.as_ref();
    if slot.slot_id != slot_id
        || slot.resource_key.scope_id != scope_id
        || slot.operation_id != binding.operation_id().as_str()
        || slot.effect_kind != effect_kind
        || slot.idempotency_key != idempotency_key
        || slot.parameters_digest != call_digest
        || slot.resource_head_digest != resource_head_digest
        || slot.action_digest != candidate.frost_action_digest
        || slot.state != expected_state
        || slot.request.request_namespace_digest != binding.request_namespace_digest().as_str()
        || slot.request.request_id != binding.request_id().as_str()
        || slot.request.request_binding_digest != binding.request_binding_hash().as_str()
        || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::MutationSubmitted
        || !handoff_version_matches
        || slot.admission_handoff.lifecycle_fence != operation.coordinator_lease_epoch()
        || slot.admission_handoff.store_fence != *fence
        || frost.is_none_or(|frost| {
            frost.authorization_slot_id != candidate.frost_slot_id
                || frost.authorization_id != candidate.frost_authorization_id
                || frost.action_digest != candidate.frost_action_digest
                || frost.signed_envelope_digest != candidate.frost_envelope_digest
        })
        || head.resource_key != slot.resource_head_key()
        || head.operation_id.as_deref() != Some(operation.binding().operation_id().as_str())
        || head.effect_idempotency_key.as_deref() != Some(idempotency_key)
        || head.lifecycle_state
            != match expected_state {
                EconomicEffectStateV1::Completed => "completed",
                EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
                _ => return Err(invalid("unsupported channel release effect state")),
            }
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn qualify_root_publication_result(
    candidate: &ChannelReleasePublisherCandidate,
    head: &EconomicResourceHeadV1,
    slot: &EconomicEffectSlotV1,
) -> Result<(), ChannelReleasePublisherError> {
    let Some(EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = slot.terminal.as_ref()
    else {
        return Err(ChannelReleasePublisherError::Fenced);
    };
    let Some(terminal) = head.terminal_result.as_ref() else {
        return Err(ChannelReleasePublisherError::Fenced);
    };
    let EconomicContentV1::Inline { value } = result else {
        return Err(ChannelReleasePublisherError::Fenced);
    };
    let publication: ChannelRootPublicationResultV1 = serde_json::from_value(value.clone())
        .map_err(|error| {
            invalid(format!(
                "channel root publication result is invalid: {error}"
            ))
        })?;
    if terminal.result_id != *result_id
        || terminal.result_digest != *result_digest
        || terminal.result != *result
        || publication.schema != CHANNEL_ROOT_PUBLICATION_RESULT_SCHEMA
        || publication.publication_root != candidate.publication_root
        || publication.call_digest != candidate.root_call_digest
        || !is_evm_transaction_hash(&publication.transaction_hash)
    {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}
