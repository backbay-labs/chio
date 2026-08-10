use super::*;

const KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA: &str = "chio.kernel-url-elicitation-no-effect.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelUrlElicitationNoEffectArtifactV1 {
    schema: String,
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    dispatch_commit: AdmissionDispatchCommitBindingV1,
    provider_attempt: ProviderAttemptBindingV1,
    message: String,
    elicitations: Vec<crate::CreateElicitationOperation>,
    elicitation_count: u64,
    elicitation_evidence_digest: AdmissionDigest,
    observed_at_unix_ms: u64,
}

#[derive(Serialize)]
struct KernelUrlElicitationEvidence<'a> {
    message: &'a str,
    elicitations: &'a [crate::CreateElicitationOperation],
}

impl VerifiedTransportNotAccepted {
    pub(crate) fn from_kernel_url_elicitation(
        message: &str,
        elicitations: &[crate::CreateElicitationOperation],
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<Self, ToolOutcomeError> {
        validate_kernel_url_elicitation_input(message, elicitations)?;
        validate_projection_context(operation, context)?;
        if operation.state() != AdmissionOperationState::DispatchCommitted {
            return Err(ToolOutcomeError::Binding(
                "kernel_url_elicitation.operation",
            ));
        }
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding(
                "kernel_url_elicitation.dispatch_commit",
            ))?;
        validate_retained_dispatch_commit(operation, commit)?;
        let attempt = operation
            .provider_attempt()
            .ok_or(ToolOutcomeError::Binding(
                "kernel_url_elicitation.provider_attempt",
            ))?;
        attempt
            .validate()
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        let elicitation_count = u64::try_from(elicitations.len())
            .map_err(|_| ToolOutcomeError::Invalid("kernel_url_elicitation.count"))?;
        positive("kernel_url_elicitation.count", elicitation_count)?;
        let elicitation_evidence_digest = domain_digest(
            KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA,
            &KernelUrlElicitationEvidence {
                message,
                elicitations,
            },
        )?;
        let artifact = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::KernelUrlElicitation,
            release_id(
                "kernel_url_elicitation_evidence_id",
                format!(
                    "{}:url-elicitation",
                    operation.binding().operation_id().as_str()
                ),
            )?,
            serde_json::to_value(KernelUrlElicitationNoEffectArtifactV1 {
                schema: KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA.to_owned(),
                operation_id: operation.binding().operation_id().clone(),
                request_id: operation.replay_key().request_id.clone(),
                request_binding_hash: operation.binding().request_binding_hash().clone(),
                dispatch_commit: commit.clone(),
                provider_attempt: attempt.clone(),
                message: message.to_owned(),
                elicitations: elicitations.to_vec(),
                elicitation_count,
                elicitation_evidence_digest,
                observed_at_unix_ms: context.trusted_time_unix_ms,
            })
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let qualification_digest = domain_digest(
            KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA,
            &(attempt.transport_id.as_str(), attempt.transport_key_epoch),
        )?;
        let proof = Self {
            operation_id: operation.binding().operation_id().clone(),
            operation_version: operation.version(),
            request_id: operation.replay_key().request_id.clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            dispatch_operation_version: commit.committed_version,
            dispatch_fence: commit.store_fence.owner_epoch,
            projection_coordinator_lease_id: context.coordinator_lease_id.clone(),
            projection_coordinator_lease_epoch: context.coordinator_lease_epoch,
            projection_store_fence: context.store_fence.clone(),
            transport_attempt_id: release_id("transport_attempt_id", attempt.attempt_id.clone())?,
            transport_identity: release_id("transport_identity", attempt.transport_id.clone())?,
            transport_key_epoch: attempt.transport_key_epoch,
            signed_status_digest: artifact.digest.clone(),
            qualification_digest: qualification_digest.clone(),
            cancellation_fence: operation.version(),
            verified_at_unix_ms: context.trusted_time_unix_ms,
            verifier_identity: release_id(
                "kernel_url_elicitation_verifier",
                "kernel-url-elicitation-v1",
            )?,
            monotonic_checkpoint_digest: artifact.digest.clone(),
            verifier_policy_digest: qualification_digest,
            artifacts: vec![artifact],
        };
        proof.validate_against(operation, context)?;
        Ok(proof)
    }

    pub(super) fn validate_kernel_url_elicitation_evidence(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(), ToolOutcomeError> {
        let [artifact] = self.artifacts.as_slice() else {
            return Err(ToolOutcomeError::Binding(
                "kernel_url_elicitation.artifact_count",
            ));
        };
        artifact.validate()?;
        let evidence: KernelUrlElicitationNoEffectArtifactV1 = parse_artifact_value(artifact)?;
        validate_kernel_url_elicitation_input(&evidence.message, &evidence.elicitations)?;
        let attempt = operation
            .provider_attempt()
            .ok_or(ToolOutcomeError::Binding(
                "kernel_url_elicitation.provider_attempt",
            ))?;
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding(
                "kernel_url_elicitation.dispatch_commit",
            ))?;
        let expected_qualification = domain_digest(
            KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA,
            &(attempt.transport_id.as_str(), attempt.transport_key_epoch),
        )?;
        let expected_elicitation_count = u64::try_from(evidence.elicitations.len())
            .map_err(|_| ToolOutcomeError::Invalid("kernel_url_elicitation.count"))?;
        let expected_evidence_digest = domain_digest(
            KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA,
            &KernelUrlElicitationEvidence {
                message: &evidence.message,
                elicitations: &evidence.elicitations,
            },
        )?;
        positive("kernel_url_elicitation.count", evidence.elicitation_count)?;
        if evidence.schema != KERNEL_URL_ELICITATION_NO_EFFECT_SCHEMA
            || evidence.operation_id != *operation.binding().operation_id()
            || evidence.request_id != operation.replay_key().request_id
            || evidence.request_binding_hash != *operation.binding().request_binding_hash()
            || evidence.dispatch_commit != *commit
            || evidence.provider_attempt != *attempt
            || evidence.message.is_empty()
            || evidence.elicitations.iter().any(|elicitation| {
                !matches!(
                    elicitation,
                    crate::CreateElicitationOperation::Url {
                        message,
                        url,
                        elicitation_id,
                        ..
                    } if !message.is_empty() && !url.is_empty() && !elicitation_id.is_empty()
                )
            })
            || evidence.elicitation_count != expected_elicitation_count
            || evidence.elicitation_evidence_digest != expected_evidence_digest
            || evidence.observed_at_unix_ms != self.verified_at_unix_ms
            || self.operation_id != evidence.operation_id
            || self.request_id != evidence.request_id
            || self.request_binding_hash != evidence.request_binding_hash
            || self.transport_attempt_id.as_str() != attempt.attempt_id
            || self.transport_identity.as_str() != attempt.transport_id
            || self.transport_key_epoch != attempt.transport_key_epoch
            || self.signed_status_digest != artifact.digest
            || self.monotonic_checkpoint_digest != artifact.digest
            || self.qualification_digest != expected_qualification
            || self.verifier_policy_digest != expected_qualification
            || self.cancellation_fence != operation.version()
            || self.verifier_identity.as_str() != "kernel-url-elicitation-v1"
        {
            return Err(ToolOutcomeError::Binding(
                "kernel_url_elicitation.artifacts",
            ));
        }
        Ok(())
    }
}
