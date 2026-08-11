use super::*;

const OUTCOME_UNKNOWN_REPLAY_DOMAIN: &[u8] = b"chio.outcome-unknown-after-dispatch.v1\0";

#[derive(Serialize)]
struct OutcomeUnknownReplayBinding<'a> {
    operation_id: &'a AdmissionOperationId,
    operation_version: u64,
    request_binding_hash: &'a AdmissionDigest,
    dispatch_commit: &'a AdmissionDispatchCommitBindingV1,
    context: &'a AdmissionProjectionContext,
}

pub fn verified_outcome_unknown_after_dispatch_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    if !matches!(
        operation.binding().kind(),
        AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse
    ) || operation.state() != AdmissionOperationState::DispatchCommitted
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let dispatch_commit = operation
        .dispatch_commit()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let binding = OutcomeUnknownReplayBinding {
        operation_id: operation.binding().operation_id(),
        operation_version: operation.version(),
        request_binding_hash: operation.binding().request_binding_hash(),
        dispatch_commit,
        context: &context,
    };
    let bytes = canonical_json_bytes(&binding)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage = Vec::with_capacity(OUTCOME_UNKNOWN_REPLAY_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(OUTCOME_UNKNOWN_REPLAY_DOMAIN);
    preimage.extend_from_slice(&bytes);
    let replay_digest =
        AdmissionDigest::try_new("outcome_unknown_replay_digest", sha256_hex(&preimage))?;
    let incident = AdmissionIncident {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "outcome_unknown_incident_id",
            replay_digest.as_str().to_owned(),
        )?,
        record_digest: replay_digest,
    };
    Ok(AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    })
}
