use chio_core_types::economic_continuity::{
    EconomicActionAuthorizationV1, EconomicAdmissionHandoffStateV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicPreparedEffectV1, EconomicRequestReplayV1,
};

use super::*;

pub fn compose_clearing_dispatch_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    signed_intent: &SignedClearingSettlementIntentV1,
    effect_slot: EconomicEffectSlotV1,
    trusted_clock_high_water: u64,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    let authority_digest = signed_intent.digest()?;
    verify_dispatch_slot_binding(
        current_round_head,
        signed_intent,
        &effect_slot,
        &authority_digest,
    )?;
    let operation_id = effect_slot.operation_id.clone();
    let request_replay = EconomicRequestReplayV1 {
        request: effect_slot.request.clone(),
        operation_id: operation_id.clone(),
        effect_slot_ids: vec![effect_slot.slot_id.clone()],
    };
    request_replay
        .validate()
        .map_err(|_| ClearingError::InvalidField("dispatch_request_replay"))?;
    let effect_slot_digest = effect_slot
        .digest()
        .map_err(|_| ClearingError::InvalidField("dispatch_effect_slot"))?;
    let mut projection = compose_lifecycle_transition(
        current_round_head,
        reservations,
        ClearingRoundTransitionV1::BeginDispatch {
            operation_id: operation_id.clone(),
            intent_id: signed_intent.body.intent_id.clone(),
            intent_digest: signed_intent.body.digest()?,
            effect_slot_id: effect_slot.slot_id.clone(),
            effect_slot_digest: effect_slot_digest.clone(),
            authority_digest,
        },
        trusted_clock_high_water,
    )?;
    if projection.transitions.len() >= MAX_ECONOMIC_TRANSITIONS {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let proof_digest = projection.proof.digest()?;
    let prepared_effect = EconomicPreparedEffectV1 {
        operation_id: operation_id.clone(),
        action_digest: effect_slot.action_digest.clone(),
        effect_slot_id: effect_slot.slot_id.clone(),
        effect_slot_digest,
        authorization: EconomicActionAuthorizationV1::Direct,
    };
    let round_transition = projection
        .transitions
        .iter_mut()
        .find(|transition| transition.resource_key == current_round_head.resource_key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    round_transition.next_head.operation_id = Some(operation_id.clone());
    round_transition.next_head.effect_idempotency_key = Some(effect_slot.idempotency_key.clone());
    round_transition.prepared_effect = Some(prepared_effect);
    round_transition
        .next_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("next_round_head"))?;
    projection.transitions.push(EconomicStateTransitionV1 {
        resource_key: effect_slot.resource_head_key(),
        expected_head_digest: None,
        next_head: ready_effect_slot_head(&effect_slot, trusted_clock_high_water)?,
        transition_proof_digest: proof_digest,
        prepared_effect: None,
    });
    projection
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    projection.effect_slots = vec![effect_slot];
    projection.request_replays = vec![request_replay];
    projection.operation_id = Some(operation_id);
    Ok(projection)
}

pub(super) fn verify_dispatch_slot_binding(
    current_round_head: &EconomicResourceHeadV1,
    signed_intent: &SignedClearingSettlementIntentV1,
    effect_slot: &EconomicEffectSlotV1,
    authority_digest: &str,
) -> Result<(), ClearingError> {
    effect_slot
        .validate()
        .map_err(|_| ClearingError::InvalidField("dispatch_effect_slot"))?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round_head)?;
    record.validate()?;
    validate_round_head(current_round_head, &record)?;
    let intent = &signed_intent.body;
    let parameters_digest = intent.digest()?;
    if !matches!(
        record.state,
        ClearingRoundLifecycleStateV1::Finalized
            | ClearingRoundLifecycleStateV1::Dispatching
            | ClearingRoundLifecycleStateV1::Reconciling
            | ClearingRoundLifecycleStateV1::Incident
    ) || intent.round_core_digest != record.round_core_digest
        || effect_slot.anchor_id != current_round_head.anchor_id
        || effect_slot.namespace != current_round_head.namespace
        || effect_slot.resource_key != current_round_head.resource_key
        || effect_slot.effect_kind != CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND
        || effect_slot.action_digest != authority_digest
        || effect_slot.parameters_digest != parameters_digest
        || effect_slot.resource_head_digest
            != current_round_head
                .digest()
                .map_err(|_| ClearingError::InvalidField("current_round_head"))?
        || effect_slot.idempotency_key != intent.dispatch_idempotency_key
        || current_round_head.operation_id.as_deref() == Some(effect_slot.operation_id.as_str())
        || effect_slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::DispatchCommitted
        || effect_slot.state != EconomicEffectStateV1::Ready
        || effect_slot.terminal.is_some()
        || effect_slot.frost.is_some()
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn ready_effect_slot_head(
    slot: &EconomicEffectSlotV1,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let state = inline_content(slot)?;
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: slot.anchor_id.clone(),
        namespace: slot.namespace.clone(),
        resource_key: slot.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ClearingError::InvalidField("dispatch_effect_slot"))?,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: None,
    };
    head.validate()
        .map_err(|_| ClearingError::InvalidField("dispatch_effect_slot_head"))?;
    Ok(head)
}

pub(super) fn verify_dispatch_projection(
    batch: &EconomicStateBatchV1,
    proof: &ClearingRoundTransitionProofV1,
    current_round: &EconomicResourceHeadV1,
    round_transition: &EconomicStateTransitionV1,
    source_record: &ClearingRoundLifecycleRecordV1,
) -> Result<(), ClearingError> {
    let ClearingRoundTransitionV1::BeginDispatch {
        operation_id,
        intent_id: _,
        intent_digest,
        effect_slot_id,
        effect_slot_digest,
        authority_digest,
    } = &proof.transition
    else {
        return Err(ClearingError::IllegalLifecycleTransition);
    };
    let [slot] = batch.effect_slots.as_slice() else {
        return Err(ClearingError::IncompleteLifecycleProjection);
    };
    let [replay] = batch.request_replays.as_slice() else {
        return Err(ClearingError::IncompleteLifecycleProjection);
    };
    slot.validate()
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
    let actual_effect_slot_digest = slot
        .digest()
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
    let expected_prepared = EconomicPreparedEffectV1 {
        operation_id: operation_id.clone(),
        action_digest: authority_digest.clone(),
        effect_slot_id: slot.slot_id.clone(),
        effect_slot_digest: effect_slot_digest.clone(),
        authorization: EconomicActionAuthorizationV1::Direct,
    };
    let slot_transition = batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key == slot.resource_head_key())
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    let expected_slot_head =
        ready_effect_slot_head(slot, round_transition.next_head.trusted_clock_high_water)?;
    if !matches!(
        source_record.state,
        ClearingRoundLifecycleStateV1::Finalized
            | ClearingRoundLifecycleStateV1::Dispatching
            | ClearingRoundLifecycleStateV1::Reconciling
            | ClearingRoundLifecycleStateV1::Incident
    ) || batch.operation_id.as_deref() != Some(operation_id)
        || slot.operation_id != *operation_id
        || slot.slot_id != *effect_slot_id
        || slot.parameters_digest != *intent_digest
        || actual_effect_slot_digest != *effect_slot_digest
        || slot.action_digest != *authority_digest
        || slot.resource_key != current_round.resource_key
        || slot.anchor_id != current_round.anchor_id
        || slot.namespace != current_round.namespace
        || slot.effect_kind != CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND
        || slot.resource_head_digest != proof.source_round_head_digest
        || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::DispatchCommitted
        || slot.state != EconomicEffectStateV1::Ready
        || slot.terminal.is_some()
        || slot.frost.is_some()
        || round_transition.prepared_effect.as_ref() != Some(&expected_prepared)
        || round_transition.next_head.operation_id.as_deref() != Some(operation_id)
        || round_transition.next_head.effect_idempotency_key.as_deref()
            != Some(slot.idempotency_key.as_str())
        || slot_transition.expected_head_digest.is_some()
        || slot_transition.next_head != expected_slot_head
        || slot_transition.prepared_effect.is_some()
        || replay.request != slot.request
        || replay.operation_id != *operation_id
        || replay.effect_slot_ids.len() != 1
        || replay.effect_slot_ids[0] != slot.slot_id
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    Ok(())
}
