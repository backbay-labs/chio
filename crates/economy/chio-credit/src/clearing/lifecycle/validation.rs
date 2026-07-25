use super::*;

pub(super) fn reservation_root(
    reservations: &[ClearingReservationHeadBindingV1],
) -> Result<String, ClearingError> {
    let mut reservations = reservations.iter().collect::<Vec<_>>();
    reservations.sort_by_key(|reservation| reservation.source_sequence);
    let digests = reservations
        .iter()
        .map(|reservation| reservation.disposition.digest(&reservation.atom))
        .collect::<Result<Vec<_>, _>>()?;
    domain_digest(RESERVATION_ROOT_DOMAIN, &digests)
}

pub(super) fn reservation_head_root(
    reservations: &[ClearingReservationHeadBindingV1],
) -> Result<String, ClearingError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct HeadLeaf<'a> {
        resource_key: &'a EconomicResourceKeyV1,
        expected_head_digest: &'a str,
    }
    let leaves = reservations
        .iter()
        .map(|reservation| HeadLeaf {
            resource_key: &reservation.resource_key,
            expected_head_digest: &reservation.expected_head_digest,
        })
        .collect::<Vec<_>>();
    domain_digest(RESERVATION_HEAD_ROOT_DOMAIN, &leaves)
}

pub(super) fn checked_transition_count(input_count: u64) -> Result<usize, ClearingError> {
    usize::try_from(input_count)
        .map_err(|_| ClearingError::ArithmeticOverflow)?
        .checked_add(2)
        .ok_or(ClearingError::ArithmeticOverflow)
}

pub(in crate::clearing) fn validate_round_core(
    core: &NettingRoundCoreV1,
) -> Result<(), ClearingError> {
    if core.schema != CLEARING_ROUND_CORE_SCHEMA {
        return Err(ClearingError::InvalidField("round_core_schema"));
    }
    validate_text("round_id", &core.round_id)?;
    validate_positive("epoch", core.epoch)?;
    validate_text("governance_scope_id", &core.governance_scope_id)?;
    validate_text("clearing_authority_id", &core.clearing_authority_id)?;
    validate_positive(
        "clearing_authority_key_epoch",
        core.clearing_authority_key_epoch,
    )?;
    validate_currency(&core.currency)?;
    if core.algorithm_version != CLEARING_ALGORITHM_V1 {
        return Err(ClearingError::InvalidField("algorithm_version"));
    }
    validate_digest(
        "participant_snapshot_digest",
        &core.participant_snapshot_digest,
    )?;
    validate_digest("input_manifest_digest", &core.input_manifest_digest)?;
    validate_positive("input_count", core.input_count)?;
    let transition_count = checked_transition_count(core.input_count)?;
    if transition_count > MAX_ECONOMIC_TRANSITIONS {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    validate_digest("reservation_root", &core.reservation_root)?;
    validate_positive(
        "dispute_window_ends_at_unix_ms",
        core.dispute_window_ends_at_unix_ms,
    )?;
    validate_positive("generated_at_unix_ms", core.generated_at_unix_ms)?;
    if core.dispute_window_ends_at_unix_ms <= core.generated_at_unix_ms {
        return Err(ClearingError::InvalidField("dispute_window"));
    }
    Ok(())
}

pub(in crate::clearing) fn validate_round_head(
    head: &EconomicResourceHeadV1,
    record: &ClearingRoundLifecycleRecordV1,
) -> Result<(), ClearingError> {
    let expected_state = serde_json::to_value(record)
        .map_err(|error| ClearingError::Canonicalization(error.to_string()))?;
    let dispatch_binding_valid = matches!(
        (
            record.state,
            head.operation_id.as_deref(),
            head.effect_idempotency_key.as_deref(),
        ),
        (
            ClearingRoundLifecycleStateV1::Dispatching | ClearingRoundLifecycleStateV1::Incident,
            Some(_),
            Some(_)
        ) | (_, None, None)
    );
    if head.resource_key.resource_family != CLEARING_ROUND_RESOURCE_FAMILY
        || head.resource_key.scope_id != record.governance_scope_id
        || head.resource_key.resource_id != record.round_id
        || head.resource_version != record.row_version
        || head.lifecycle_fence != record.fence
        || head.lifecycle_state != record.state.as_str()
        || !matches!(&head.state, EconomicContentV1::Inline { value } if value == &expected_state)
        || !dispatch_binding_valid
        || head.terminal_result.is_some()
    {
        return Err(ClearingError::InvalidField("current_round_head"));
    }
    Ok(())
}
