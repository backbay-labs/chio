use chio_credit::factor::{VerifiedAssignmentAcknowledgementV1, VerifiedAssignmentNotAppliedV1};

use super::*;

pub fn verified_factor_assignment_applied_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    acknowledgement: &VerifiedAssignmentAcknowledgementV1,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let body = acknowledgement.body();
    validate_source(
        operation,
        &context,
        body.operation_id(),
        body.normalized_request_digest(),
        body.assignment_authorization_set_digest(),
        body.acknowledged_at_unix_ms(),
    )?;
    if body.resulting_disposition_version()
        != body
            .prior_disposition_version()
            .checked_add(1)
            .ok_or(AdmissionOperationError::InvalidEconomicMutationBinding)?
        || body.resulting_snapshot_version()
            != body
                .expected_snapshot_version()
                .checked_add(1)
                .ok_or(AdmissionOperationError::InvalidEconomicMutationBinding)?
        || body.resulting_resource_fence()
            != body
                .expected_resource_fence()
                .checked_add(1)
                .ok_or(AdmissionOperationError::InvalidEconomicMutationBinding)?
    {
        return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
    }
    let result = result_binding(
        operation,
        &context,
        AdmissionOperationState::EconomicMutationApplied,
        body.acknowledgement_id(),
        acknowledgement.envelope_digest(),
        acknowledgement.signature_digest(),
        body.authority_id(),
        body.authority_key_epoch(),
        body.obligation_id(),
        body.expected_snapshot_version(),
        body.resulting_snapshot_version(),
        body.expected_resource_fence(),
        body.resulting_resource_fence(),
        EconomicMutationTerminalStatus::Applied,
    )?;
    let audit_event = audit_event(
        operation,
        &context,
        AdmissionOperationState::EconomicMutationApplied,
        body.acknowledgement_id(),
        acknowledgement.envelope_digest(),
    )?;
    Ok(AdmissionTerminalProjection::EconomicMutationApplied {
        context,
        result: Box::new(VerifiedEconomicMutationApplied(result)),
        audit_event: Box::new(audit_event),
    })
}

pub fn verified_factor_assignment_not_applied_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    result: &VerifiedAssignmentNotAppliedV1,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let body = result.body();
    validate_source(
        operation,
        &context,
        body.operation_id(),
        body.normalized_request_digest(),
        body.assignment_authorization_set_digest(),
        body.decided_at_unix_ms(),
    )?;
    let result_binding = result_binding(
        operation,
        &context,
        AdmissionOperationState::EconomicMutationNotApplied,
        body.result_id(),
        result.envelope_digest(),
        result.signature_digest(),
        body.authority_id(),
        body.authority_key_epoch(),
        body.obligation_id(),
        body.expected_snapshot_version(),
        body.observed_snapshot_version(),
        body.expected_resource_fence(),
        body.resource_fence(),
        EconomicMutationTerminalStatus::PermanentlyNotApplied,
    )?;
    let audit_event = audit_event(
        operation,
        &context,
        AdmissionOperationState::EconomicMutationNotApplied,
        body.result_id(),
        result.envelope_digest(),
    )?;
    Ok(AdmissionTerminalProjection::EconomicMutationNotApplied {
        context,
        result: Box::new(VerifiedEconomicMutationNotApplied(result_binding)),
        audit_event: Box::new(audit_event),
    })
}

fn validate_source(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    operation_id: &str,
    normalized_request_digest: &str,
    authorization_set_digest: &str,
    authority_time_unix_ms: u64,
) -> Result<(), AdmissionOperationError> {
    if operation.binding().kind() != AdmissionOperationKind::GovernedEconomicMutation
        || operation.state() != AdmissionOperationState::MutationSubmitted
        || operation.binding().operation_id().as_str() != operation_id
        || operation.binding().immutable_request_hash().as_str() != normalized_request_digest
        || operation
            .supplemental_authorization_digest()
            .is_none_or(|digest| digest.as_str() != authorization_set_digest)
        || authority_time_unix_ms > context.trusted_time_unix_ms
    {
        return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
    }
    context.validate()
}

#[allow(clippy::too_many_arguments)]
fn result_binding(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projected_state: AdmissionOperationState,
    record_id: &str,
    envelope_digest: &str,
    signature_digest: &str,
    authority_id: &str,
    authority_key_epoch: u64,
    obligation_id: &str,
    expected_version: u64,
    resulting_version: u64,
    expected_fence: u64,
    resulting_fence: u64,
    status: EconomicMutationTerminalStatus,
) -> Result<GovernedEconomicMutationResultBinding, AdmissionOperationError> {
    let invalid = |_| AdmissionOperationError::InvalidEconomicMutationBinding;
    let binding = GovernedEconomicMutationResultBinding {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            context,
            projected_state,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "factor_assignment_result_id",
            record_id.to_owned(),
        )
        .map_err(invalid)?,
        record_digest: AdmissionDigest::try_new(
            "factor_assignment_result_digest",
            envelope_digest.to_owned(),
        )
        .map_err(invalid)?,
        participant_id: AdmissionIdentifier::try_new(
            "factor_assignment_authority_id",
            authority_id.to_owned(),
        )
        .map_err(invalid)?,
        participant_key_epoch: authority_key_epoch,
        resource_id: AdmissionIdentifier::try_new(
            "factor_assignment_obligation_id",
            obligation_id.to_owned(),
        )
        .map_err(invalid)?,
        expected_resource_version: expected_version,
        resulting_resource_version: resulting_version,
        expected_resource_fence: AdmissionIdentifier::try_new(
            "factor_assignment_expected_resource_fence",
            format!("factor-assignment-resource-fence:{expected_fence}"),
        )
        .map_err(invalid)?,
        resulting_resource_fence: AdmissionIdentifier::try_new(
            "factor_assignment_resulting_resource_fence",
            format!("factor-assignment-resource-fence:{resulting_fence}"),
        )
        .map_err(invalid)?,
        immutable_request_digest: operation.binding().request_binding_hash().clone(),
        signature_digest: AdmissionDigest::try_new(
            "factor_assignment_signature_digest",
            signature_digest.to_owned(),
        )
        .map_err(invalid)?,
        status,
        anchored_effect: false,
    };
    binding.validate_against(operation, context)?;
    Ok(binding)
}

fn audit_event(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projected_state: AdmissionOperationState,
    result_id: &str,
    envelope_digest: &str,
) -> Result<GovernedMutationAuditEvent, AdmissionOperationError> {
    let invalid = |_| AdmissionOperationError::InvalidEconomicMutationBinding;
    Ok(GovernedMutationAuditEvent {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            context,
            projected_state,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "factor_assignment_audit_id",
            format!("{result_id}:audit"),
        )
        .map_err(invalid)?,
        record_digest: AdmissionDigest::try_new(
            "factor_assignment_audit_digest",
            envelope_digest.to_owned(),
        )
        .map_err(invalid)?,
    })
}
