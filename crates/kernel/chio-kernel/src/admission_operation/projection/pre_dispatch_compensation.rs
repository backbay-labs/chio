use super::*;

const PRE_DISPATCH_COMPENSATION_REPLAY_DOMAIN: &[u8] =
    b"chio.pre-dispatch-compensation-replay.v1\0";

#[derive(Serialize)]
struct PreDispatchCompensationReplayBinding<'a> {
    operation_id: &'a AdmissionOperationId,
    operation_version: u64,
    request_binding_hash: &'a AdmissionDigest,
    context: &'a AdmissionProjectionContext,
    proof: &'a VerifiedPreDispatchNoEffect,
}

pub fn verified_pre_dispatch_compensation_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    if !matches!(
        operation.binding().kind(),
        AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse
    ) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let proof = VerifiedPreDispatchNoEffect::from_qualified_operation_snapshot(operation, &context)
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    pre_dispatch_compensation_projection(operation, context, proof)
}

pub(crate) fn verified_released_pre_dispatch_compensation_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    verifier_policy: serde_json::Value,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    if !matches!(
        operation.binding().kind(),
        AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse
    ) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let proof = VerifiedPreDispatchNoEffect::from_qualified_released_operation_snapshot(
        operation,
        &context,
        verifier_policy,
    )
    .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    pre_dispatch_compensation_projection(operation, context, proof)
}

#[cfg(any(test, feature = "admission-test-support"))]
pub fn verified_released_pre_dispatch_compensation_projection_for_test(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    verifier_policy: serde_json::Value,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    verified_released_pre_dispatch_compensation_projection(operation, context, verifier_policy)
}

fn pre_dispatch_compensation_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    proof: VerifiedPreDispatchNoEffect,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let binding = PreDispatchCompensationReplayBinding {
        operation_id: operation.binding().operation_id(),
        operation_version: operation.version(),
        request_binding_hash: operation.binding().request_binding_hash(),
        context: &context,
        proof: &proof,
    };
    let bytes = canonical_json_bytes(&binding)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage =
        Vec::with_capacity(PRE_DISPATCH_COMPENSATION_REPLAY_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(PRE_DISPATCH_COMPENSATION_REPLAY_DOMAIN);
    preimage.extend_from_slice(&bytes);
    let replay_digest = AdmissionDigest::try_new(
        "pre_dispatch_compensation_replay_digest",
        sha256_hex(&preimage),
    )?;
    let incident = AdmissionIncident {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::CompensatedBeforeDispatch,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "pre_dispatch_compensation_incident_id",
            replay_digest.as_str().to_owned(),
        )?,
        record_digest: replay_digest,
    };
    Ok(AdmissionTerminalProjection::CompensatedBeforeDispatch {
        context,
        proof: Box::new(proof),
        evidence: Box::new(AdmissionReceiptOrIncident::Incident(Box::new(incident))),
    })
}
