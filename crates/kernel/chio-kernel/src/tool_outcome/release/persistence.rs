//! Owned persisted monetary-release evidence. Decoding never restores authority.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonetaryReleaseEvidenceKindV1 {
    BeforeDispatchNoEffect,
    NotAcceptedAfterDispatch,
    ContractualZeroCharge,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonetaryReleaseEvidenceV1 {
    pub(super) schema: &'static str,
    pub(super) evidence_id: AdmissionDigest,
    pub(super) evidence_kind: MonetaryReleaseEvidenceKindV1,
    pub(super) operation_id: AdmissionOperationId,
    pub(super) operation_version: u64,
    pub(super) verifier_policy_digest: AdmissionDigest,
    pub(super) source_binding_base64: String,
    pub(super) source_binding_digest: AdmissionDigest,
    pub(super) source_artifacts: Vec<ImmutableReleaseArtifactV1>,
    pub(super) bundle_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedImmutableReleaseArtifactV1 {
    pub kind: ReleaseEvidenceArtifactKindV1,
    pub evidence_id: AdmissionIdentifier,
    pub digest: AdmissionDigest,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedMonetaryReleaseEvidenceV1 {
    pub schema: String,
    pub evidence_id: AdmissionDigest,
    pub evidence_kind: MonetaryReleaseEvidenceKindV1,
    pub operation_id: AdmissionOperationId,
    pub operation_version: u64,
    pub verifier_policy_digest: AdmissionDigest,
    pub source_binding_base64: String,
    pub source_binding_digest: AdmissionDigest,
    pub source_artifacts: Vec<PersistedImmutableReleaseArtifactV1>,
    pub bundle_digest: AdmissionDigest,
}

#[derive(Serialize)]
struct ReleaseEvidenceBody<'a> {
    schema: &'a str,
    evidence_kind: MonetaryReleaseEvidenceKindV1,
    operation_id: &'a AdmissionOperationId,
    operation_version: u64,
    verifier_policy_digest: &'a AdmissionDigest,
    source_binding_base64: &'a str,
    source_binding_digest: &'a AdmissionDigest,
    source_artifacts: &'a [ImmutableReleaseArtifactV1],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "binding", rename_all = "snake_case")]
enum ReleaseSourceBindingV1 {
    BeforeDispatchNoEffect(Box<PreDispatchReleaseSourceV1>),
    NotAcceptedAfterDispatch(Box<TransportReleaseSourceV1>),
    ContractualZeroCharge(Box<ZeroChargeReleaseSourceV1>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreDispatchReleaseSourceV1 {
    operation_id: AdmissionOperationId,
    operation_version: u64,
    request_binding_hash: AdmissionDigest,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    verification_store_fence: StoreMutationFence,
    verified_at_unix_ms: u64,
    participant_manifest: PreDispatchParticipantManifestV1,
    complete_participant_query_root: AdmissionDigest,
    verifier_policy_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportReleaseSourceV1 {
    operation_id: AdmissionOperationId,
    operation_version: u64,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    dispatch_operation_version: u64,
    dispatch_fence: u64,
    projection_coordinator_lease_id: AdmissionIdentifier,
    projection_coordinator_lease_epoch: u64,
    projection_store_fence: StoreMutationFence,
    transport_attempt_id: AdmissionIdentifier,
    transport_identity: AdmissionIdentifier,
    transport_key_epoch: u64,
    signed_status_digest: AdmissionDigest,
    qualification_digest: AdmissionDigest,
    cancellation_fence: u64,
    verified_at_unix_ms: u64,
    verifier_identity: AdmissionIdentifier,
    monotonic_checkpoint_digest: AdmissionDigest,
    verifier_policy_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZeroChargeReleaseSourceV1 {
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    operation_version: u64,
    outcome_version: u64,
    projection_coordinator_lease_id: AdmissionIdentifier,
    projection_coordinator_lease_epoch: u64,
    projection_store_fence: StoreMutationFence,
    verified_at_unix_ms: u64,
    tool_outcome_id: AdmissionDigest,
    evaluation_id: AdmissionDigest,
    pricing_verdict_digest: AdmissionDigest,
    currency: String,
    verifier_policy_digest: AdmissionDigest,
}

impl From<&ImmutableReleaseArtifactV1> for PersistedImmutableReleaseArtifactV1 {
    fn from(value: &ImmutableReleaseArtifactV1) -> Self {
        Self {
            kind: value.kind,
            evidence_id: value.evidence_id.clone(),
            digest: value.digest.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<PersistedImmutableReleaseArtifactV1> for ImmutableReleaseArtifactV1 {
    fn from(value: PersistedImmutableReleaseArtifactV1) -> Self {
        Self {
            kind: value.kind,
            evidence_id: value.evidence_id,
            digest: value.digest,
            value: value.value,
        }
    }
}

impl MonetaryReleaseAuthority {
    pub fn evidence_bundle(&self) -> Result<MonetaryReleaseEvidenceV1, ToolOutcomeError> {
        let (kind, operation_id, operation_version, policy, artifacts, source) = match self {
            Self::NoEffect(VerifiedNoEffectProof::BeforeDispatch(proof)) => (
                MonetaryReleaseEvidenceKindV1::BeforeDispatchNoEffect,
                &proof.snapshot.operation_id,
                proof.snapshot.operation_version,
                &proof.snapshot.verifier_policy_digest,
                &proof.snapshot.artifacts,
                ReleaseSourceBindingV1::BeforeDispatchNoEffect(Box::new(
                    PreDispatchReleaseSourceV1 {
                        operation_id: proof.snapshot.operation_id.clone(),
                        operation_version: proof.snapshot.operation_version,
                        request_binding_hash: proof.snapshot.request_binding_hash.clone(),
                        coordinator_lease_id: proof.snapshot.coordinator_lease_id.clone(),
                        coordinator_lease_epoch: proof.snapshot.coordinator_lease_epoch,
                        verification_store_fence: proof.snapshot.verification_store_fence.clone(),
                        verified_at_unix_ms: proof.snapshot.verified_at_unix_ms,
                        participant_manifest: proof.snapshot.participant_manifest.clone(),
                        complete_participant_query_root: proof
                            .snapshot
                            .complete_participant_query_root
                            .clone(),
                        verifier_policy_digest: proof.snapshot.verifier_policy_digest.clone(),
                    },
                )),
            ),
            Self::NoEffect(VerifiedNoEffectProof::NotAcceptedAfterDispatch(proof)) => (
                MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch,
                &proof.operation_id,
                proof.operation_version,
                &proof.verifier_policy_digest,
                &proof.artifacts,
                ReleaseSourceBindingV1::NotAcceptedAfterDispatch(Box::new(
                    TransportReleaseSourceV1 {
                        operation_id: proof.operation_id.clone(),
                        operation_version: proof.operation_version,
                        request_id: proof.request_id.clone(),
                        request_binding_hash: proof.request_binding_hash.clone(),
                        dispatch_operation_version: proof.dispatch_operation_version,
                        dispatch_fence: proof.dispatch_fence,
                        projection_coordinator_lease_id: proof
                            .projection_coordinator_lease_id
                            .clone(),
                        projection_coordinator_lease_epoch: proof
                            .projection_coordinator_lease_epoch,
                        projection_store_fence: proof.projection_store_fence.clone(),
                        transport_attempt_id: proof.transport_attempt_id.clone(),
                        transport_identity: proof.transport_identity.clone(),
                        transport_key_epoch: proof.transport_key_epoch,
                        signed_status_digest: proof.signed_status_digest.clone(),
                        qualification_digest: proof.qualification_digest.clone(),
                        cancellation_fence: proof.cancellation_fence,
                        verified_at_unix_ms: proof.verified_at_unix_ms,
                        verifier_identity: proof.verifier_identity.clone(),
                        monotonic_checkpoint_digest: proof.monotonic_checkpoint_digest.clone(),
                        verifier_policy_digest: proof.verifier_policy_digest.clone(),
                    },
                )),
            ),
            Self::ContractualZeroCharge(proof) => (
                MonetaryReleaseEvidenceKindV1::ContractualZeroCharge,
                &proof.operation_id,
                proof.operation_version,
                &proof.verifier_policy_digest,
                &proof.artifacts,
                ReleaseSourceBindingV1::ContractualZeroCharge(Box::new(
                    ZeroChargeReleaseSourceV1 {
                        operation_id: proof.operation_id.clone(),
                        request_id: proof.request_id.clone(),
                        request_binding_hash: proof.request_binding_hash.clone(),
                        operation_version: proof.operation_version,
                        outcome_version: proof.outcome_version,
                        projection_coordinator_lease_id: proof
                            .projection_coordinator_lease_id
                            .clone(),
                        projection_coordinator_lease_epoch: proof
                            .projection_coordinator_lease_epoch,
                        projection_store_fence: proof.projection_store_fence.clone(),
                        verified_at_unix_ms: proof.verified_at_unix_ms,
                        tool_outcome_id: proof.tool_outcome_id.clone(),
                        evaluation_id: proof.evaluation_id.clone(),
                        pricing_verdict_digest: proof.pricing_verdict_digest.clone(),
                        currency: proof.currency.clone(),
                        verifier_policy_digest: proof.verifier_policy_digest.clone(),
                    },
                )),
            ),
        };
        MonetaryReleaseEvidenceV1::new(
            kind,
            operation_id.clone(),
            operation_version,
            policy.clone(),
            artifacts.clone(),
            source,
        )
    }
}

impl MonetaryReleaseEvidenceV1 {
    fn new(
        evidence_kind: MonetaryReleaseEvidenceKindV1,
        operation_id: AdmissionOperationId,
        operation_version: u64,
        verifier_policy_digest: AdmissionDigest,
        source_artifacts: Vec<ImmutableReleaseArtifactV1>,
        source: ReleaseSourceBindingV1,
    ) -> Result<Self, ToolOutcomeError> {
        let source_binding = canonical(&source)?;
        let source_binding_base64 = BASE64.encode(&source_binding);
        let source_binding_digest = digest_bytes("release.source_binding_digest", &source_binding)?;
        let body = ReleaseEvidenceBody {
            schema: MONETARY_RELEASE_EVIDENCE_SCHEMA,
            evidence_kind,
            operation_id: &operation_id,
            operation_version,
            verifier_policy_digest: &verifier_policy_digest,
            source_binding_base64: &source_binding_base64,
            source_binding_digest: &source_binding_digest,
            source_artifacts: &source_artifacts,
        };
        let body_bytes = bounded(
            "monetary_release_evidence",
            &body,
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
        )?;
        let bundle = Self {
            schema: MONETARY_RELEASE_EVIDENCE_SCHEMA,
            evidence_id: domain_digest("chio.monetary-release-evidence.identity.v1", &body)?,
            evidence_kind,
            operation_id,
            operation_version,
            verifier_policy_digest,
            source_binding_base64,
            source_binding_digest,
            source_artifacts,
            bundle_digest: digest_bytes("release.bundle_digest", &body_bytes)?,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    #[must_use]
    pub fn evidence_id(&self) -> &AdmissionDigest {
        &self.evidence_id
    }

    #[must_use]
    pub fn bundle_digest(&self) -> &AdmissionDigest {
        &self.bundle_digest
    }

    pub fn to_persisted(&self) -> PersistedMonetaryReleaseEvidenceV1 {
        PersistedMonetaryReleaseEvidenceV1 {
            schema: self.schema.to_owned(),
            evidence_id: self.evidence_id.clone(),
            evidence_kind: self.evidence_kind,
            operation_id: self.operation_id.clone(),
            operation_version: self.operation_version,
            verifier_policy_digest: self.verifier_policy_digest.clone(),
            source_binding_base64: self.source_binding_base64.clone(),
            source_binding_digest: self.source_binding_digest.clone(),
            source_artifacts: self.source_artifacts.iter().map(Into::into).collect(),
            bundle_digest: self.bundle_digest.clone(),
        }
    }

    pub fn from_persisted(
        value: PersistedMonetaryReleaseEvidenceV1,
    ) -> Result<Self, ToolOutcomeError> {
        if value.schema != MONETARY_RELEASE_EVIDENCE_SCHEMA {
            return Err(ToolOutcomeError::Invalid("release_evidence.schema"));
        }
        let bundle = Self {
            schema: MONETARY_RELEASE_EVIDENCE_SCHEMA,
            evidence_id: value.evidence_id,
            evidence_kind: value.evidence_kind,
            operation_id: value.operation_id,
            operation_version: value.operation_version,
            verifier_policy_digest: value.verifier_policy_digest,
            source_binding_base64: value.source_binding_base64,
            source_binding_digest: value.source_binding_digest,
            source_artifacts: value.source_artifacts.into_iter().map(Into::into).collect(),
            bundle_digest: value.bundle_digest,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ToolOutcomeError> {
        bounded(
            "monetary_release_evidence",
            &self.to_persisted(),
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
        )
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ToolOutcomeError> {
        if bytes.len() > MAX_MONETARY_RELEASE_EVIDENCE_BYTES {
            return Err(ToolOutcomeError::TooLarge {
                field: "monetary_release_evidence",
                actual: bytes.len(),
                maximum: MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
            });
        }
        let persisted = serde_json::from_slice::<PersistedMonetaryReleaseEvidenceV1>(bytes)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        let bundle = Self::from_persisted(persisted)?;
        if bundle.canonical_bytes()? != bytes {
            return Err(ToolOutcomeError::Invalid(
                "release_evidence.noncanonical_bytes",
            ));
        }
        Ok(bundle)
    }

    pub(super) fn validate(&self) -> Result<(), ToolOutcomeError> {
        let kinds: &[ReleaseEvidenceArtifactKindV1] = match self.evidence_kind {
            MonetaryReleaseEvidenceKindV1::BeforeDispatchNoEffect => &[
                ReleaseEvidenceArtifactKindV1::ParticipantQuerySnapshot,
                ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            ],
            MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch => &[
                ReleaseEvidenceArtifactKindV1::SignedTransportStatus,
                ReleaseEvidenceArtifactKindV1::MonotonicAttemptCheckpoint,
                ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            ],
            MonetaryReleaseEvidenceKindV1::ContractualZeroCharge => &[
                ReleaseEvidenceArtifactKindV1::TerminalToolOutcome,
                ReleaseEvidenceArtifactKindV1::TerminalPostReturnEvaluation,
                ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            ],
        };
        if self.schema != MONETARY_RELEASE_EVIDENCE_SCHEMA
            || self.source_artifacts.len() != kinds.len()
        {
            return Err(ToolOutcomeError::Invalid("release_evidence.shape"));
        }
        positive("release_evidence.operation_version", self.operation_version)?;
        for (artifact, kind) in self.source_artifacts.iter().zip(kinds) {
            artifact.validate()?;
            if artifact.kind != *kind {
                return Err(ToolOutcomeError::Binding("release_evidence.artifact_kind"));
            }
        }
        let source = self.source_binding()?;
        self.validate_source(&source)?;
        let body = self.body();
        let bytes = bounded(
            "monetary_release_evidence",
            &body,
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
        )?;
        if digest_bytes("release.bundle_digest", &bytes)? != self.bundle_digest
            || domain_digest("chio.monetary-release-evidence.identity.v1", &body)?
                != self.evidence_id
        {
            return Err(ToolOutcomeError::Binding("release_evidence.bundle"));
        }
        Ok(())
    }

    pub(crate) fn validate_recovery_context(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), ToolOutcomeError> {
        self.validate()?;
        if self.operation_id != *operation.binding().operation_id()
            || self.operation_version != operation.version()
            || self.operation_version != context.expected_operation_version
        {
            return Err(ToolOutcomeError::Binding("release_evidence.operation"));
        }
        match self.source_binding()? {
            ReleaseSourceBindingV1::BeforeDispatchNoEffect(source) => {
                validate_pre_dispatch_context(operation, context)?;
                source.participant_manifest.validate_for(operation)?;
                validate_source_projection(
                    &source.verification_store_fence,
                    &source.coordinator_lease_id,
                    source.coordinator_lease_epoch,
                    source.verified_at_unix_ms,
                    context,
                )
            }
            ReleaseSourceBindingV1::NotAcceptedAfterDispatch(source) => {
                validate_projection_context(operation, context)?;
                let commit = operation
                    .dispatch_commit()
                    .ok_or(ToolOutcomeError::Binding(
                        "release_evidence.transport_dispatch_commit",
                    ))?;
                if source.request_id != operation.replay_key().request_id
                    || source.request_id != context.request_id
                    || source.request_binding_hash != *operation.binding().request_binding_hash()
                    || source.dispatch_operation_version != commit.committed_version
                    || source.dispatch_fence != commit.store_fence.owner_epoch
                {
                    return Err(ToolOutcomeError::Binding(
                        "release_evidence.transport_operation",
                    ));
                }
                validate_source_projection(
                    &source.projection_store_fence,
                    &source.projection_coordinator_lease_id,
                    source.projection_coordinator_lease_epoch,
                    source.verified_at_unix_ms,
                    context,
                )
            }
            ReleaseSourceBindingV1::ContractualZeroCharge(source) => {
                validate_projection_context(operation, context)?;
                if source.request_id != operation.replay_key().request_id
                    || source.request_id != context.request_id
                    || source.request_binding_hash != *operation.binding().request_binding_hash()
                {
                    return Err(ToolOutcomeError::Binding(
                        "release_evidence.zero_charge_operation",
                    ));
                }
                validate_source_projection(
                    &source.projection_store_fence,
                    &source.projection_coordinator_lease_id,
                    source.projection_coordinator_lease_epoch,
                    source.verified_at_unix_ms,
                    context,
                )?;
                validate_zero_charge_records(&source, &self.source_artifacts, Some(operation))
            }
        }
    }

    pub fn revalidate_authority(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<MonetaryReleaseAuthority, ToolOutcomeError> {
        self.validate_recovery_context(operation, context)?;
        Err(ToolOutcomeError::ReleaseAuthorityUnavailable(
            "persisted evidence requires a qualified co-located authority query",
        ))
    }

    #[cfg(test)]
    pub(super) fn with_projection_epoch_for_test(
        &self,
        coordinator_lease_epoch: u64,
    ) -> Result<Self, ToolOutcomeError> {
        let mut source = self.source_binding()?;
        let mut source_artifacts = self.source_artifacts.clone();
        match &mut source {
            ReleaseSourceBindingV1::BeforeDispatchNoEffect(source) => {
                source.coordinator_lease_epoch = coordinator_lease_epoch;
                source.participant_manifest.coordinator_lease_epoch = coordinator_lease_epoch;
                source_artifacts[0] = ImmutableReleaseArtifactV1::new(
                    ReleaseEvidenceArtifactKindV1::ParticipantQuerySnapshot,
                    source_artifacts[0].evidence_id.clone(),
                    serde_json::to_value(&source.participant_manifest)
                        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
                )?;
                source.complete_participant_query_root = source_artifacts[0].digest.clone();
            }
            ReleaseSourceBindingV1::NotAcceptedAfterDispatch(source) => {
                source.projection_coordinator_lease_epoch = coordinator_lease_epoch;
            }
            ReleaseSourceBindingV1::ContractualZeroCharge(source) => {
                source.projection_coordinator_lease_epoch = coordinator_lease_epoch;
            }
        }
        Self::new(
            self.evidence_kind,
            self.operation_id.clone(),
            self.operation_version,
            self.verifier_policy_digest.clone(),
            source_artifacts,
            source,
        )
    }

    #[cfg(test)]
    pub(super) fn with_request_binding_hash_for_test(
        &self,
        request_binding_hash: AdmissionDigest,
    ) -> Result<Self, ToolOutcomeError> {
        let mut source = self.source_binding()?;
        let mut source_artifacts = self.source_artifacts.clone();
        match &mut source {
            ReleaseSourceBindingV1::BeforeDispatchNoEffect(source) => {
                source.request_binding_hash = request_binding_hash.clone();
                source.participant_manifest.request_binding_hash = request_binding_hash;
                source_artifacts[0] = ImmutableReleaseArtifactV1::new(
                    ReleaseEvidenceArtifactKindV1::ParticipantQuerySnapshot,
                    source_artifacts[0].evidence_id.clone(),
                    serde_json::to_value(&source.participant_manifest)
                        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
                )?;
                source.complete_participant_query_root = source_artifacts[0].digest.clone();
            }
            ReleaseSourceBindingV1::NotAcceptedAfterDispatch(source) => {
                source.request_binding_hash = request_binding_hash;
            }
            ReleaseSourceBindingV1::ContractualZeroCharge(source) => {
                source.request_binding_hash = request_binding_hash;
            }
        }
        Self::new(
            self.evidence_kind,
            self.operation_id.clone(),
            self.operation_version,
            self.verifier_policy_digest.clone(),
            source_artifacts,
            source,
        )
    }

    fn body(&self) -> ReleaseEvidenceBody<'_> {
        ReleaseEvidenceBody {
            schema: self.schema,
            evidence_kind: self.evidence_kind,
            operation_id: &self.operation_id,
            operation_version: self.operation_version,
            verifier_policy_digest: &self.verifier_policy_digest,
            source_binding_base64: &self.source_binding_base64,
            source_binding_digest: &self.source_binding_digest,
            source_artifacts: &self.source_artifacts,
        }
    }

    fn source_binding(&self) -> Result<ReleaseSourceBindingV1, ToolOutcomeError> {
        let bytes = BASE64
            .decode(&self.source_binding_base64)
            .map_err(|_| ToolOutcomeError::Invalid("release_evidence.source_binding_base64"))?;
        if BASE64.encode(&bytes) != self.source_binding_base64
            || digest_bytes("release.source_binding_digest", &bytes)? != self.source_binding_digest
        {
            return Err(ToolOutcomeError::Binding("release_evidence.source_binding"));
        }
        let source = serde_json::from_slice::<ReleaseSourceBindingV1>(&bytes)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        if canonical(&source)? != bytes {
            return Err(ToolOutcomeError::Invalid(
                "release_evidence.source_binding_noncanonical",
            ));
        }
        Ok(source)
    }

    fn validate_source(&self, source: &ReleaseSourceBindingV1) -> Result<(), ToolOutcomeError> {
        match (self.evidence_kind, source) {
            (
                MonetaryReleaseEvidenceKindV1::BeforeDispatchNoEffect,
                ReleaseSourceBindingV1::BeforeDispatchNoEffect(source),
            ) => validate_pre_dispatch_source(self, source),
            (
                MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch,
                ReleaseSourceBindingV1::NotAcceptedAfterDispatch(source),
            ) => validate_transport_source(self, source),
            (
                MonetaryReleaseEvidenceKindV1::ContractualZeroCharge,
                ReleaseSourceBindingV1::ContractualZeroCharge(source),
            ) => validate_zero_charge_source(self, source),
            _ => Err(ToolOutcomeError::Binding("release_evidence.source_kind")),
        }
    }
}

fn validate_source_projection(
    historical_fence: &StoreMutationFence,
    historical_coordinator_lease_id: &AdmissionIdentifier,
    historical_coordinator_lease_epoch: u64,
    verified_at_unix_ms: u64,
    context: &AdmissionProjectionContext,
) -> Result<(), ToolOutcomeError> {
    validate_successor_fence(historical_fence, &context.store_fence)?;
    positive("release_evidence.verified_at", verified_at_unix_ms)?;
    if verified_at_unix_ms > context.trusted_time_unix_ms
        || historical_coordinator_lease_epoch != context.coordinator_lease_epoch
        || (historical_fence == &context.store_fence
            && historical_coordinator_lease_id != &context.coordinator_lease_id)
    {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.projection_lineage",
        ));
    }
    Ok(())
}

fn validate_pre_dispatch_source(
    bundle: &MonetaryReleaseEvidenceV1,
    source: &PreDispatchReleaseSourceV1,
) -> Result<(), ToolOutcomeError> {
    let manifest: PreDispatchParticipantManifestV1 =
        parse_artifact_value(&bundle.source_artifacts[0])?;
    let _: VerifierPolicyArtifactV1 = parse_artifact_value(&bundle.source_artifacts[1])?;
    positive("release_evidence.verified_at", source.verified_at_unix_ms)?;
    validate_store_fence(&source.verification_store_fence)?;
    if source.operation_id != bundle.operation_id
        || source.operation_version != bundle.operation_version
        || source.verifier_policy_digest != bundle.verifier_policy_digest
        || source.complete_participant_query_root != bundle.source_artifacts[0].digest
        || source.verifier_policy_digest != bundle.source_artifacts[1].digest
        || source.participant_manifest != manifest
        || source.request_binding_hash != manifest.request_binding_hash
        || source.coordinator_lease_id != manifest.coordinator_lease_id
        || source.coordinator_lease_epoch != manifest.coordinator_lease_epoch
        || source.verification_store_fence != manifest.verification_store_fence
        || source.verified_at_unix_ms != manifest.verified_at_unix_ms
    {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.predispatch_source",
        ));
    }
    Ok(())
}

fn validate_transport_source(
    bundle: &MonetaryReleaseEvidenceV1,
    source: &TransportReleaseSourceV1,
) -> Result<(), ToolOutcomeError> {
    let evidence =
        transport::validate_artifacts(&bundle.source_artifacts, source.verified_at_unix_ms)?;
    let signed = &evidence.signed;
    let checkpoint = &evidence.checkpoint;
    let attempt = &checkpoint.attempt;
    let invocation_blob = checkpoint.phase.invocation_blob();
    validate_store_fence(&source.projection_store_fence)?;
    if source.operation_id != bundle.operation_id
        || source.operation_version != bundle.operation_version
        || source.verifier_policy_digest != bundle.verifier_policy_digest
        || source.verifier_policy_digest != bundle.source_artifacts[2].digest
        || signed.verifier_identity != source.verifier_identity
        || signed.qualification_digest != source.qualification_digest
        || evidence.cancellation_digest != source.signed_status_digest
        || signed.cancellation.cancellation_fence != source.cancellation_fence
        || evidence.checkpoint_digest != source.monotonic_checkpoint_digest
        || attempt.operation_id != source.operation_id.as_str()
        || attempt.attempt_id != source.transport_attempt_id.as_str()
        || attempt.transport_id != source.transport_identity.as_str()
        || attempt.transport_key_epoch != source.transport_key_epoch
        || invocation_blob.request_digest != source.request_binding_hash.as_str()
    {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.transport_source",
        ));
    }
    Ok(())
}

fn validate_zero_charge_source(
    bundle: &MonetaryReleaseEvidenceV1,
    source: &ZeroChargeReleaseSourceV1,
) -> Result<(), ToolOutcomeError> {
    if source.operation_id != bundle.operation_id
        || source.operation_version != bundle.operation_version
        || source.verifier_policy_digest != bundle.verifier_policy_digest
        || source.verifier_policy_digest != bundle.source_artifacts[2].digest
    {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.zero_charge_source",
        ));
    }
    validate_zero_charge_records(source, &bundle.source_artifacts, None)
}

fn validate_zero_charge_records(
    source: &ZeroChargeReleaseSourceV1,
    artifacts: &[ImmutableReleaseArtifactV1],
    operation: Option<&AdmissionOperationV1>,
) -> Result<(), ToolOutcomeError> {
    let outcome = ToolOutcomeRecordV1::from_persisted(parse_artifact_value(&artifacts[0])?)?;
    let evaluation =
        PostReturnEvaluationRecordV1::from_persisted(parse_artifact_value(&artifacts[1])?)?;
    let _: VerifierPolicyArtifactV1 = parse_artifact_value(&artifacts[2])?;
    if let Some(operation) = operation {
        outcome.validate_against(operation)?;
        evaluation.validate_against(operation, &outcome)?;
    }
    let ResolvedToolOutcomeV1::Resolved {
        evaluation_id,
        pricing_verdict_digest,
        settlement_disposition: SettlementDispositionV1::ContractualZeroCharge { currency },
        ..
    } = &outcome.disposition
    else {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.zero_charge_disposition",
        ));
    };
    if outcome.operation_id != source.operation_id
        || outcome.request_id != source.request_id
        || outcome.outcome_id != source.tool_outcome_id
        || outcome.version != source.outcome_version
        || outcome.recorded_at_unix_ms > source.verified_at_unix_ms
        || evaluation.operation_id != source.operation_id
        || evaluation.tool_outcome_id != source.tool_outcome_id
        || evaluation.evaluation_id != source.evaluation_id
        || evaluation.trusted_time_unix_ms > source.verified_at_unix_ms
        || evaluation_id != &source.evaluation_id
        || pricing_verdict_digest != &source.pricing_verdict_digest
        || currency != &source.currency
    {
        return Err(ToolOutcomeError::Binding(
            "release_evidence.zero_charge_records",
        ));
    }
    Ok(())
}
