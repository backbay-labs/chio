use super::*;

pub(super) struct ValidatedTransportArtifacts {
    pub(super) signed: SignedTransportStatusArtifactV1,
    pub(super) checkpoint: ProviderAttemptCheckpointV1,
    pub(super) checkpoint_digest: AdmissionDigest,
    pub(super) cancellation_digest: AdmissionDigest,
}

pub(super) fn validate_artifacts(
    artifacts: &[ImmutableReleaseArtifactV1],
    verified_at_unix_ms: u64,
) -> Result<ValidatedTransportArtifacts, ToolOutcomeError> {
    let [signed_artifact, checkpoint_artifact, policy_artifact] = artifacts else {
        return Err(ToolOutcomeError::Binding(
            "transport_release.artifact_count",
        ));
    };
    let signed: SignedTransportStatusArtifactV1 = parse_artifact_value(signed_artifact)?;
    let checkpoint: ProviderAttemptCheckpointV1 = parse_artifact_value(checkpoint_artifact)?;
    let _: VerifierPolicyArtifactV1 = parse_artifact_value(policy_artifact)?;
    checkpoint
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    signed
        .cancellation
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    positive("transport_release.verified_at", verified_at_unix_ms)?;
    let proof = BASE64
        .decode(&signed.no_acceptance_proof_base64)
        .map_err(|_| ToolOutcomeError::Invalid("transport_release.proof_base64"))?;
    let ProviderAttemptPhaseV1::Cancelled {
        cancellation: checkpoint_cancellation,
        ..
    } = &checkpoint.phase
    else {
        return Err(ToolOutcomeError::Binding(
            "transport_release.checkpoint_phase",
        ));
    };
    if signed.cancellation.attempt != checkpoint.attempt
        || signed.cancellation != *checkpoint_cancellation
        || usize::try_from(signed.cancellation.no_acceptance_proof_size_bytes) != Ok(proof.len())
        || signed.cancellation.no_acceptance_proof_sha256 != sha256_hex(&proof)
        || signed.observed_at_unix_ms < signed.cancellation.cancelled_at
        || signed.observed_at_unix_ms > verified_at_unix_ms
    {
        return Err(ToolOutcomeError::Binding("transport_release.artifacts"));
    }
    Ok(ValidatedTransportArtifacts {
        checkpoint_digest: imported_digest(
            "transport_release.checkpoint_digest",
            checkpoint
                .digest()
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?,
        cancellation_digest: imported_digest(
            "transport_release.signed_status_digest",
            signed
                .cancellation
                .digest()
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?,
        signed,
        checkpoint,
    })
}
