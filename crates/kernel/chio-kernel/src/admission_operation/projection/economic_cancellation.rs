use chio_core_types::economic_continuity::{
    economic_effect_slot_from_head, EconomicAdmissionHandoffStateV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicEffectTerminalV1, EconomicNoEffectKindV1,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, VerifiedEconomicEffectCancellationAdvance,
};

use super::*;

const ECONOMIC_CANCELLATION_REPLAY_DOMAIN: &[u8] = b"chio.economic-cancellation-replay.v1\0";

#[derive(Serialize)]
struct EconomicCancellationReplayBinding<'a> {
    slot: &'a chio_core_types::economic_continuity::EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
    checkpoint_sequence: u64,
    checkpoint_digest: &'a str,
}

fn cancellation_replay_digest_from_parts(
    slot: &chio_core_types::economic_continuity::EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
    checkpoint_sequence: u64,
    checkpoint_digest: &str,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    let binding = EconomicCancellationReplayBinding {
        slot,
        kind,
        checkpoint_sequence,
        checkpoint_digest,
    };
    let bytes = canonical_json_bytes(&binding)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage = Vec::with_capacity(ECONOMIC_CANCELLATION_REPLAY_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(ECONOMIC_CANCELLATION_REPLAY_DOMAIN);
    preimage.extend_from_slice(&bytes);
    AdmissionDigest::try_new("economic_cancellation_replay_digest", sha256_hex(&preimage))
}

fn cancellation_replay_digest(
    cancellation: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    cancellation_replay_digest_from_parts(
        cancellation.slot(),
        cancellation.kind(),
        cancellation.checkpoint_sequence(),
        cancellation.checkpoint_digest(),
    )
}

pub fn verify_economic_cancellation_terminal_advance(
    base_view: &EconomicStateAnchorViewV1,
    batch: &EconomicStateBatchV1,
    projection: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectSlotV1, AdmissionOperationError> {
    let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
    if batch.transitions.len() != 1
        || !batch.effect_slots.is_empty()
        || !batch.request_replays.is_empty()
        || batch.transitions[0].prepared_effect.is_some()
    {
        return Err(mismatch());
    }
    let transition = &batch.transitions[0];
    if transition.resource_key.resource_family != "effect_slot" {
        return Err(mismatch());
    }
    let expected_head = base_view
        .head(&transition.resource_key)
        .ok_or_else(mismatch)?;
    let current_slot = economic_effect_slot_from_head(expected_head).map_err(|_| mismatch())?;
    let resulting_slot =
        economic_effect_slot_from_head(&transition.next_head).map_err(|_| mismatch())?;
    current_slot
        .validate_successor(&resulting_slot)
        .map_err(|_| mismatch())?;
    let Some(EconomicEffectTerminalV1::NoEffect { kind, .. }) = resulting_slot.terminal.as_ref()
    else {
        return Err(mismatch());
    };
    let kind = *kind;
    let source = projection.source_operation();
    let terminal = projection.terminal_operation();
    let binding = source.binding();
    let context = projection.context();
    let common_binding_matches = current_slot.state == EconomicEffectStateV1::Ready
        && resulting_slot.state == EconomicEffectStateV1::NoEffect
        && transition.next_head.lifecycle_state == "no_effect"
        && batch.operation_id.as_deref() == Some(binding.operation_id().as_str())
        && resulting_slot.operation_id == binding.operation_id().as_str()
        && resulting_slot.request.request_namespace_digest
            == binding.request_namespace_digest().as_str()
        && resulting_slot.request.request_id == binding.request_id().as_str()
        && resulting_slot.request.request_binding_digest == binding.request_binding_hash().as_str()
        && resulting_slot.parameters_digest == binding.action_parameter_hash().as_str()
        && resulting_slot.admission_handoff.operation_version == source.version()
        && resulting_slot.admission_handoff.lifecycle_fence == source.coordinator_lease_epoch()
        && resulting_slot.admission_handoff.store_fence == context.store_fence
        && transition.next_head.head_version > expected_head.head_version;
    if !common_binding_matches {
        return Err(mismatch());
    }
    let replay_digest = cancellation_replay_digest_from_parts(
        &resulting_slot,
        kind,
        batch.checkpoint_sequence,
        &batch.checkpoint_digest,
    )?;
    match (binding.kind(), kind, terminal.state()) {
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
        ) => {
            let dispatch = source.dispatch_commit().ok_or_else(mismatch)?;
            let replay_matches = matches!(
                terminal.terminal_replay(),
                Some(AdmissionTerminalReplay::Incident { incident_id, .. })
                    if incident_id.as_str() == replay_digest.as_str()
            );
            if source.state() != AdmissionOperationState::DispatchCommitted
                || resulting_slot.admission_handoff.state
                    != EconomicAdmissionHandoffStateV1::DispatchCommitted
                || dispatch.committed_version != source.version()
                || dispatch.coordinator_lease_epoch != source.coordinator_lease_epoch()
                || dispatch.store_fence != context.store_fence
                || !replay_matches
            {
                return Err(mismatch());
            }
            let record = projection
                .records()
                .iter()
                .find(|record| record.kind() == AdmissionProjectionRecordKind::ReleaseProof)
                .ok_or_else(mismatch)?;
            let proof = VerifiedTransportNotAccepted::from_canonical_record_verified(
                record.canonical_json(),
                source,
                context,
            )
            .map_err(|_| mismatch())?;
            proof
                .verify_economic_cancellation_binding(
                    &resulting_slot,
                    expected_head,
                    &transition.next_head,
                    batch,
                )
                .map_err(|_| mismatch())?;
        }
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            EconomicNoEffectKindV1::PermanentlyNotApplied,
            AdmissionOperationState::EconomicMutationNotApplied,
        ) => {
            let replay_matches = matches!(
                terminal.terminal_replay(),
                Some(AdmissionTerminalReplay::EconomicMutation {
                    result_id,
                    result_digest,
                    ..
                }) if result_id.as_str() == replay_digest.as_str()
                    && result_digest == &replay_digest
            );
            if source.state() != AdmissionOperationState::MutationSubmitted
                || resulting_slot.admission_handoff.state
                    != EconomicAdmissionHandoffStateV1::MutationSubmitted
                || !replay_matches
            {
                return Err(mismatch());
            }
            let record = projection
                .records()
                .iter()
                .find(|record| {
                    record.kind() == AdmissionProjectionRecordKind::EconomicMutationResult
                })
                .ok_or_else(mismatch)?;
            let result: GovernedEconomicMutationResultBinding =
                serde_json::from_slice(record.canonical_json()).map_err(|_| mismatch())?;
            result.verify_anchored_cancellation(
                &resulting_slot,
                expected_head,
                &transition.next_head,
                &batch.checkpoint_digest,
            )?;
        }
        _ => return Err(mismatch()),
    }
    Ok(resulting_slot)
}

pub fn verify_economic_cancellation_terminal_replay(
    operation: &AdmissionOperationV1,
    cancellation: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<(), AdmissionOperationError> {
    let replay_digest = cancellation_replay_digest_from_parts(
        cancellation.slot(),
        cancellation.kind(),
        cancellation.batch().checkpoint_sequence,
        &cancellation.batch().checkpoint_digest,
    )?;
    let slot = cancellation.slot();
    let handoff_version_matches = slot
        .admission_handoff
        .operation_version
        .checked_add(1)
        .is_some_and(|version| version == operation.version());
    let binding_matches = slot.operation_id == operation.binding().operation_id().as_str()
        && slot.request.request_namespace_digest
            == operation.replay_key().request_namespace_digest.as_str()
        && slot.request.request_id == operation.replay_key().request_id.as_str()
        && slot.request.request_binding_digest
            == operation.binding().request_binding_hash().as_str()
        && handoff_version_matches
        && slot.admission_handoff.lifecycle_fence == operation.coordinator_lease_epoch();
    let replay_matches = match (
        operation.binding().kind(),
        operation.state(),
        cancellation.kind(),
        operation.terminal_replay(),
    ) {
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
            EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
            Some(AdmissionTerminalReplay::Incident { incident_id, .. }),
        ) => incident_id.as_str() == replay_digest.as_str(),
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            AdmissionOperationState::EconomicMutationNotApplied,
            EconomicNoEffectKindV1::PermanentlyNotApplied,
            Some(AdmissionTerminalReplay::EconomicMutation {
                result_id,
                result_digest,
                ..
            }),
        ) => {
            result_id.as_str() == replay_digest.as_str()
                && result_digest.as_str() == replay_digest.as_str()
        }
        _ => false,
    };
    if !binding_matches || !replay_matches {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

pub fn verified_economic_cancellation_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    cancellation: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let Some(EconomicEffectTerminalV1::NoEffect {
        proof_id: _,
        proof_digest: _,
        ..
    }) = &cancellation.slot().terminal
    else {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    };
    let replay_digest = cancellation_replay_digest(cancellation)?;
    match (operation.binding().kind(), cancellation.kind()) {
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
        ) => {
            let proof = VerifiedTransportNotAccepted::from_verified_economic_effect(
                cancellation,
                operation,
                &context,
            )
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
            let evidence = AdmissionIncident {
                binding: AdmissionExactProjectionBindingV1::from_verified(
                    operation,
                    &context,
                    AdmissionOperationState::NotAcceptedAfterDispatchCommit,
                )?,
                record_id: AdmissionIdentifier::try_new(
                    "economic_cancellation_incident_id",
                    replay_digest.as_str().to_owned(),
                )?,
                record_digest: replay_digest,
            };
            Ok(
                AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit {
                    context,
                    proof: Box::new(proof),
                    evidence: Box::new(AdmissionReceiptOrIncident::Incident(Box::new(evidence))),
                },
            )
        }
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            EconomicNoEffectKindV1::PermanentlyNotApplied,
        ) => mutation_not_applied(operation, context, cancellation, replay_digest),
        _ => Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
}

fn mutation_not_applied(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    cancellation: &VerifiedEconomicEffectCancellationAdvance,
    replay_digest: AdmissionDigest,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let slot = cancellation.slot();
    if operation.state() != AdmissionOperationState::MutationSubmitted
        || slot.state != EconomicEffectStateV1::NoEffect
        || slot.operation_id != operation.binding().operation_id().as_str()
        || slot.request.request_namespace_digest
            != operation.replay_key().request_namespace_digest.as_str()
        || slot.request.request_id != operation.replay_key().request_id.as_str()
        || slot.request.request_binding_digest
            != operation.binding().request_binding_hash().as_str()
        || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::MutationSubmitted
        || slot.admission_handoff.operation_version != operation.version()
        || slot.admission_handoff.lifecycle_fence != operation.coordinator_lease_epoch()
        || slot.admission_handoff.store_fence != context.store_fence
        || cancellation.resulting_head_version() <= cancellation.expected_head_version()
        || cancellation.resulting_resource_version() <= cancellation.expected_resource_version()
    {
        return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
    }
    let result_binding = GovernedEconomicMutationResultBinding {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::EconomicMutationNotApplied,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "economic_mutation_cancellation_record_id",
            replay_digest.as_str().to_owned(),
        )?,
        record_digest: replay_digest.clone(),
        participant_id: AdmissionIdentifier::try_new(
            "economic_mutation_participant_id",
            slot.target.target_id.clone(),
        )?,
        participant_key_epoch: slot.target.target_key_epoch,
        resource_id: AdmissionIdentifier::try_new(
            "economic_mutation_resource_id",
            slot.slot_id.clone(),
        )?,
        expected_resource_version: cancellation.expected_resource_version(),
        resulting_resource_version: cancellation.resulting_resource_version(),
        expected_resource_fence: AdmissionIdentifier::try_new(
            "economic_mutation_expected_resource_fence",
            format!(
                "effect-slot-fence:{}",
                cancellation.expected_lifecycle_fence()
            ),
        )?,
        resulting_resource_fence: AdmissionIdentifier::try_new(
            "economic_mutation_resulting_resource_fence",
            format!(
                "effect-slot-fence:{}",
                cancellation.resulting_lifecycle_fence()
            ),
        )?,
        immutable_request_digest: operation.binding().request_binding_hash().clone(),
        signature_digest: AdmissionDigest::try_new(
            "economic_mutation_cancellation_signature_digest",
            cancellation.checkpoint_digest().to_owned(),
        )?,
        status: EconomicMutationTerminalStatus::PermanentlyNotApplied,
        anchored_effect: true,
    };
    result_binding.validate_against(operation, &context)?;
    let audit_event = GovernedMutationAuditEvent {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::EconomicMutationNotApplied,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "economic_mutation_cancellation_audit_id",
            format!("{}:audit", replay_digest.as_str()),
        )?,
        record_digest: AdmissionDigest::try_new(
            "economic_mutation_cancellation_audit_digest",
            cancellation.checkpoint_digest().to_owned(),
        )?,
    };
    Ok(AdmissionTerminalProjection::EconomicMutationNotApplied {
        context,
        result: Box::new(VerifiedEconomicMutationNotApplied(result_binding)),
        audit_event: Box::new(audit_event),
    })
}
