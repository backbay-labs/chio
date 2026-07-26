//! Frozen post-return evaluation journal and recovery contract.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPhaseV1 {
    OutputGuard,
    Pricing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationModeV1 {
    Pure,
    ExternalStateful { call_id: AdmissionIdentifier },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenEvaluationStepV1 {
    pub phase: EvaluationPhaseV1,
    pub position: u32,
    pub component_id: AdmissionIdentifier,
    pub component_version: AdmissionIdentifier,
    pub implementation_digest: AdmissionDigest,
    pub mode: EvaluationModeV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostReturnNormalizedRequestContextV1 {
    normalized: Value,
    digest: AdmissionDigest,
}

impl PostReturnNormalizedRequestContextV1 {
    #[allow(dead_code)]
    pub(crate) fn from_verified_normalization(normalized: Value) -> Result<Self, ToolOutcomeError> {
        let bytes = bounded(
            "normalized_request_context",
            &normalized,
            MAX_FROZEN_INPUT_BYTES,
        )?;
        Ok(Self {
            normalized,
            digest: digest_bytes("normalized_request_context.digest", &bytes)?,
        })
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        let bytes = bounded(
            "normalized_request_context",
            &self.normalized,
            MAX_FROZEN_INPUT_BYTES,
        )?;
        if digest_bytes("normalized_request_context.digest", &bytes)? != self.digest {
            return Err(ToolOutcomeError::Binding(
                "normalized_request_context.digest",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostReturnExactInputsV1 {
    schema: String,
    operation_id: AdmissionOperationId,
    pub(super) operation_version: u64,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    capability_id: AdmissionIdentifier,
    policy_hash: AdmissionDigest,
    dispatch_commit: AdmissionDispatchCommitBindingV1,
    outcome_recording_fence: StoreMutationFence,
    outcome_recorded_at_unix_ms: u64,
    tool_outcome_id: AdmissionDigest,
    tool_outcome_version: u64,
    raw_output_digest: AdmissionDigest,
    tool_server: AdmissionIdentifier,
    tool_name: AdmissionIdentifier,
    provider_attempt: ProviderAttemptBindingV1,
    transport_terminal_evidence_digest: AdmissionDigest,
    reported_cost: Option<MonetaryAmount>,
    normalized_request_context: PostReturnNormalizedRequestContextV1,
    trusted_time_unix_ms: u64,
}

impl PostReturnExactInputsV1 {
    #[allow(dead_code)]
    fn from_records(
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
        normalized_request_context: PostReturnNormalizedRequestContextV1,
        trusted_time_unix_ms: u64,
    ) -> Result<Self, ToolOutcomeError> {
        validate_committed_operation(
            operation,
            operation
                .dispatch_commit()
                .ok_or(ToolOutcomeError::Binding("exact_inputs.dispatch_commit"))?,
        )?;
        outcome.validate_against(operation)?;
        let exact = Self {
            schema: POST_RETURN_EXACT_INPUTS_SCHEMA.to_owned(),
            operation_id: operation.binding().operation_id().clone(),
            operation_version: operation.version(),
            request_id: operation.replay_key().request_id,
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            capability_id: operation.binding().capability_id().clone(),
            policy_hash: operation.binding().policy_hash().clone(),
            dispatch_commit: outcome.dispatch_commit.clone(),
            outcome_recording_fence: outcome.recording_fence.clone(),
            outcome_recorded_at_unix_ms: outcome.recorded_at_unix_ms,
            tool_outcome_id: outcome.outcome_id.clone(),
            tool_outcome_version: outcome.version,
            raw_output_digest: outcome.raw_output.digest().clone(),
            tool_server: outcome.tool_server.clone(),
            tool_name: outcome.tool_name.clone(),
            provider_attempt: outcome.provider_attempt.clone(),
            transport_terminal_evidence_digest: outcome.transport_terminal_evidence_digest.clone(),
            reported_cost: outcome.reported_cost.clone(),
            normalized_request_context,
            trusted_time_unix_ms,
        };
        exact.validate_against(operation, outcome)?;
        Ok(exact)
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        if self.schema != POST_RETURN_EXACT_INPUTS_SCHEMA {
            return Err(ToolOutcomeError::Invalid("exact_inputs.schema"));
        }
        positive(
            "exact_inputs.tool_outcome_version",
            self.tool_outcome_version,
        )?;
        positive("exact_inputs.operation_version", self.operation_version)?;
        positive("exact_inputs.trusted_time", self.trusted_time_unix_ms)?;
        positive(
            "exact_inputs.dispatch_commit.committed_version",
            self.dispatch_commit.committed_version,
        )?;
        positive(
            "exact_inputs.dispatch_commit.coordinator_lease_epoch",
            self.dispatch_commit.coordinator_lease_epoch,
        )?;
        validate_store_fence(&self.dispatch_commit.store_fence)?;
        validate_successor_fence(
            &self.dispatch_commit.store_fence,
            &self.outcome_recording_fence,
        )?;
        positive(
            "exact_inputs.outcome_recorded_at",
            self.outcome_recorded_at_unix_ms,
        )?;
        if self.operation_version < self.dispatch_commit.committed_version {
            return Err(ToolOutcomeError::Binding("exact_inputs.operation_version"));
        }
        if self.trusted_time_unix_ms < self.outcome_recorded_at_unix_ms {
            return Err(ToolOutcomeError::Invalid("exact_inputs.trusted_time"));
        }
        if let Some(cost) = &self.reported_cost {
            amount(cost)?;
        }
        self.normalized_request_context.validate()
    }

    #[allow(dead_code)]
    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
    ) -> Result<(), ToolOutcomeError> {
        self.validate()?;
        outcome.validate_against(operation)?;
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding("exact_inputs.dispatch_commit"))?;
        let recorded_return_version = recorded_return_version(outcome)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.operation_version > operation.version()
            || self.request_id != operation.replay_key().request_id
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.capability_id != *operation.binding().capability_id()
            || self.policy_hash != *operation.binding().policy_hash()
            || self.dispatch_commit != *commit
            || self.outcome_recording_fence != outcome.recording_fence
            || self.outcome_recorded_at_unix_ms != outcome.recorded_at_unix_ms
            || self.tool_outcome_id != outcome.outcome_id
            || self.tool_outcome_version != recorded_return_version
            || self.raw_output_digest != *outcome.raw_output.digest()
            || self.tool_server != outcome.tool_server
            || self.tool_name != outcome.tool_name
            || self.provider_attempt != outcome.provider_attempt
            || self.transport_terminal_evidence_digest != outcome.transport_terminal_evidence_digest
            || self.reported_cost != outcome.reported_cost
        {
            return Err(ToolOutcomeError::Binding("exact_inputs.records"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvaluationResultRefV1 {
    pub step_index: u32,
    pub call_id: AdmissionIdentifier,
    pub result_digest: AdmissionDigest,
    pub result_blob_ref: ContentAddressedBlobRefV1,
    pub verifier_identity: AdmissionIdentifier,
    pub verifier_key_epoch: u64,
    pub authenticated_at_unix_ms: u64,
}

impl ExternalEvaluationResultRefV1 {
    #[allow(dead_code)]
    pub(crate) fn new(
        step_index: u32,
        step: &FrozenEvaluationStepV1,
        result_digest: AdmissionDigest,
        verifier_identity: AdmissionIdentifier,
        verifier_key_epoch: u64,
        authenticated_at_unix_ms: u64,
    ) -> Result<Self, ToolOutcomeError> {
        let EvaluationModeV1::ExternalStateful { call_id } = &step.mode else {
            return Err(ToolOutcomeError::Invalid("external_result.pure_step"));
        };
        positive("external_result.verifier_key_epoch", verifier_key_epoch)?;
        positive("external_result.authenticated_at", authenticated_at_unix_ms)?;
        Ok(Self {
            step_index,
            call_id: call_id.clone(),
            result_blob_ref: ContentAddressedBlobRefV1::new(result_digest.clone()),
            result_digest,
            verifier_identity,
            verifier_key_epoch,
            authenticated_at_unix_ms,
        })
    }

    fn validate_for(
        &self,
        index: usize,
        step: &FrozenEvaluationStepV1,
        evaluation_trusted_time_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        let EvaluationModeV1::ExternalStateful { call_id } = &step.mode else {
            return Err(ToolOutcomeError::Binding("external_result.step_mode"));
        };
        if usize::try_from(self.step_index).ok() != Some(index) || self.call_id != *call_id {
            return Err(ToolOutcomeError::Binding("external_result.step"));
        }
        self.result_blob_ref.validate()?;
        if self.result_blob_ref.digest() != &self.result_digest {
            return Err(ToolOutcomeError::Binding("external_result.blob_ref"));
        }
        positive(
            "external_result.verifier_key_epoch",
            self.verifier_key_epoch,
        )?;
        positive(
            "external_result.authenticated_at",
            self.authenticated_at_unix_ms,
        )?;
        if self.authenticated_at_unix_ms < evaluation_trusted_time_unix_ms {
            return Err(ToolOutcomeError::Binding(
                "external_result.evaluation_trusted_time",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationStepResultV1 {
    pub(super) step_index: u32,
    pub(super) input_dependency_digest: AdmissionDigest,
    pub(super) result_digest: AdmissionDigest,
    pub(super) external_result: Option<ExternalEvaluationResultRefV1>,
}

impl EvaluationStepResultV1 {
    #[allow(dead_code)]
    pub(crate) fn pure(
        step_index: u32,
        input_dependency_digest: AdmissionDigest,
        result_digest: AdmissionDigest,
    ) -> Self {
        Self {
            step_index,
            input_dependency_digest,
            result_digest,
            external_result: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn external(
        input_dependency_digest: AdmissionDigest,
        external_result: ExternalEvaluationResultRefV1,
    ) -> Self {
        Self {
            step_index: external_result.step_index,
            input_dependency_digest,
            result_digest: external_result.result_digest.clone(),
            external_result: Some(external_result),
        }
    }

    fn validate_for(
        &self,
        index: usize,
        step: &FrozenEvaluationStepV1,
        expected_dependency: &AdmissionDigest,
        evaluation_trusted_time_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        if usize::try_from(self.step_index).ok() != Some(index)
            || &self.input_dependency_digest != expected_dependency
        {
            return Err(ToolOutcomeError::Binding("step_result.order_or_dependency"));
        }
        match (&step.mode, &self.external_result) {
            (EvaluationModeV1::Pure, None) => Ok(()),
            (EvaluationModeV1::ExternalStateful { .. }, Some(result)) => {
                result.validate_for(index, step, evaluation_trusted_time_unix_ms)?;
                if result.result_digest != self.result_digest {
                    return Err(ToolOutcomeError::Binding("step_result.external_result"));
                }
                Ok(())
            }
            _ => Err(ToolOutcomeError::Binding("step_result.evidence_kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationFreezeV1 {
    AmbiguousExternalResult {
        step_index: u32,
        evidence_digest: AdmissionDigest,
    },
    ExternalResultConflict {
        step_index: u32,
        evidence_digest: AdmissionDigest,
    },
    AuthenticatedResultUnavailable {
        step_index: u32,
        evidence_digest: AdmissionDigest,
    },
}

impl EvaluationFreezeV1 {
    fn step_index(&self) -> u32 {
        match self {
            Self::AmbiguousExternalResult { step_index, .. }
            | Self::ExternalResultConflict { step_index, .. }
            | Self::AuthenticatedResultUnavailable { step_index, .. } => *step_index,
        }
    }

    #[allow(dead_code)]
    fn evidence_digest(&self) -> &AdmissionDigest {
        match self {
            Self::AmbiguousExternalResult {
                evidence_digest, ..
            }
            | Self::ExternalResultConflict {
                evidence_digest, ..
            }
            | Self::AuthenticatedResultUnavailable {
                evidence_digest, ..
            } => evidence_digest,
        }
    }

    fn validate(&self, step_count: usize) -> Result<(), ToolOutcomeError> {
        if usize::try_from(self.step_index()).map_or(true, |index| index >= step_count) {
            return Err(ToolOutcomeError::Invalid("evaluation_freeze.step_index"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostReturnResolutionV1 {
    pub(super) resolved_output: ContentAddressedBlobRefV1,
    pub(super) resolved_output_size_bytes: u64,
    pub(super) terminal_dependency_root_digest: AdmissionDigest,
    pub(super) post_guard_decision_digest: AdmissionDigest,
    pub(super) pricing_verdict_digest: AdmissionDigest,
    pub(super) settlement_disposition: SettlementDispositionV1,
}

impl PostReturnResolutionV1 {
    #[allow(dead_code)]
    pub(crate) fn from_output(
        evaluation: &PostReturnEvaluationRecordV1,
        output: &Value,
        post_guard_decision_digest: AdmissionDigest,
        pricing_verdict_digest: AdmissionDigest,
        settlement_disposition: SettlementDispositionV1,
    ) -> Result<Self, ToolOutcomeError> {
        Self::from_output_bounded(
            evaluation,
            output,
            post_guard_decision_digest,
            pricing_verdict_digest,
            settlement_disposition,
            MAX_RESOLVED_OUTPUT_BYTES,
        )
    }

    #[allow(dead_code)]
    fn from_output_bounded(
        evaluation: &PostReturnEvaluationRecordV1,
        output: &Value,
        post_guard_decision_digest: AdmissionDigest,
        pricing_verdict_digest: AdmissionDigest,
        settlement_disposition: SettlementDispositionV1,
        maximum: usize,
    ) -> Result<Self, ToolOutcomeError> {
        let bytes = bounded("resolved_output", output, maximum)?;
        Self::from_signing_preimage(
            evaluation,
            bytes,
            post_guard_decision_digest,
            pricing_verdict_digest,
            settlement_disposition,
        )
        .map(|(resolution, _)| resolution)
    }

    pub(crate) fn from_signing_preimage(
        evaluation: &PostReturnEvaluationRecordV1,
        signing_preimage: Vec<u8>,
        post_guard_decision_digest: AdmissionDigest,
        pricing_verdict_digest: AdmissionDigest,
        settlement_disposition: SettlementDispositionV1,
    ) -> Result<(Self, CanonicalResolvedOutputBlobV1), ToolOutcomeError> {
        evaluation.validate()?;
        if !matches!(evaluation.state, PostReturnEvaluationStateV1::Evaluating)
            || evaluation.step_results.len() != evaluation.frozen_steps.len()
        {
            return Err(ToolOutcomeError::Invalid(
                "resolution.incomplete_evaluation",
            ));
        }
        settlement_disposition.validate()?;
        let blob = CanonicalResolvedOutputBlobV1::from_signing_preimage(signing_preimage)?;
        let record = Self {
            resolved_output: blob.blob_ref().clone(),
            resolved_output_size_bytes: u64::try_from(blob.bytes().len())
                .map_err(|_| ToolOutcomeError::Overflow("resolved_output_size_bytes"))?,
            terminal_dependency_root_digest: evaluation.step_result_root()?,
            post_guard_decision_digest,
            pricing_verdict_digest,
            settlement_disposition,
        };
        record.validate()?;
        Ok((record, blob))
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        self.resolved_output.validate()?;
        if usize::try_from(self.resolved_output_size_bytes)
            .map_or(true, |size| size > MAX_RESOLVED_OUTPUT_BYTES)
        {
            return Err(ToolOutcomeError::Invalid(
                "resolution.resolved_output_size_bytes",
            ));
        }
        self.settlement_disposition.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PostReturnEvaluationStateV1 {
    Evaluating,
    Resolved { resolution: PostReturnResolutionV1 },
    Frozen { freeze: EvaluationFreezeV1 },
}

impl PostReturnEvaluationStateV1 {
    #[allow(dead_code)]
    fn name(&self) -> &'static str {
        match self {
            Self::Evaluating => "evaluating",
            Self::Resolved { .. } => "resolved",
            Self::Frozen { .. } => "frozen",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PostReturnEvaluationRecordV1 {
    pub(super) schema: &'static str,
    pub(super) evaluation_id: AdmissionDigest,
    pub(super) operation_id: AdmissionOperationId,
    pub(super) tool_outcome_id: AdmissionDigest,
    pub(super) tool_outcome_version: u64,
    pub(super) raw_output_digest: AdmissionDigest,
    pub(super) plan_digest: AdmissionDigest,
    pub(super) frozen_steps: Vec<FrozenEvaluationStepV1>,
    pub(super) trusted_time_unix_ms: u64,
    pub(super) exact_inputs: PostReturnExactInputsV1,
    pub(super) exact_inputs_digest: AdmissionDigest,
    pub(super) step_results: Vec<EvaluationStepResultV1>,
    pub(super) state: PostReturnEvaluationStateV1,
    pub(super) version: u64,
    pub(super) lifecycle_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedPostReturnEvaluationRecordV1 {
    pub schema: String,
    pub evaluation_id: AdmissionDigest,
    pub operation_id: AdmissionOperationId,
    pub tool_outcome_id: AdmissionDigest,
    pub tool_outcome_version: u64,
    pub raw_output_digest: AdmissionDigest,
    pub plan_digest: AdmissionDigest,
    pub frozen_steps: Vec<FrozenEvaluationStepV1>,
    pub trusted_time_unix_ms: u64,
    pub exact_inputs: PostReturnExactInputsV1,
    pub exact_inputs_digest: AdmissionDigest,
    pub step_results: Vec<EvaluationStepResultV1>,
    pub state: PostReturnEvaluationStateV1,
    pub version: u64,
    pub lifecycle_digest: AdmissionDigest,
}

#[derive(Serialize)]
struct EvaluationIdentity<'a> {
    operation_id: &'a AdmissionOperationId,
    tool_outcome_id: &'a AdmissionDigest,
    tool_outcome_version: u64,
    raw_output_digest: &'a AdmissionDigest,
    plan_digest: &'a AdmissionDigest,
    trusted_time_unix_ms: u64,
    exact_inputs_digest: &'a AdmissionDigest,
}

#[derive(Serialize)]
struct EvaluationLifecycle<'a> {
    evaluation_id: &'a AdmissionDigest,
    step_results: &'a [EvaluationStepResultV1],
    state: &'a PostReturnEvaluationStateV1,
    version: u64,
}

fn evaluation_lifecycle_digest(
    evaluation_id: &AdmissionDigest,
    step_results: &[EvaluationStepResultV1],
    state: &PostReturnEvaluationStateV1,
    version: u64,
) -> Result<AdmissionDigest, ToolOutcomeError> {
    domain_digest(
        "chio.post-return-evaluation.lifecycle.v1",
        &EvaluationLifecycle {
            evaluation_id,
            step_results,
            state,
            version,
        },
    )
}

impl PostReturnEvaluationRecordV1 {
    pub fn to_persisted(&self) -> PersistedPostReturnEvaluationRecordV1 {
        PersistedPostReturnEvaluationRecordV1 {
            schema: self.schema.to_owned(),
            evaluation_id: self.evaluation_id.clone(),
            operation_id: self.operation_id.clone(),
            tool_outcome_id: self.tool_outcome_id.clone(),
            tool_outcome_version: self.tool_outcome_version,
            raw_output_digest: self.raw_output_digest.clone(),
            plan_digest: self.plan_digest.clone(),
            frozen_steps: self.frozen_steps.clone(),
            trusted_time_unix_ms: self.trusted_time_unix_ms,
            exact_inputs: self.exact_inputs.clone(),
            exact_inputs_digest: self.exact_inputs_digest.clone(),
            step_results: self.step_results.clone(),
            state: self.state.clone(),
            version: self.version,
            lifecycle_digest: self.lifecycle_digest.clone(),
        }
    }

    pub fn from_persisted(
        value: PersistedPostReturnEvaluationRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        if value.schema != POST_RETURN_EVALUATION_SCHEMA {
            return Err(ToolOutcomeError::Invalid("evaluation.schema"));
        }
        let record = Self {
            schema: POST_RETURN_EVALUATION_SCHEMA,
            evaluation_id: value.evaluation_id,
            operation_id: value.operation_id,
            tool_outcome_id: value.tool_outcome_id,
            tool_outcome_version: value.tool_outcome_version,
            raw_output_digest: value.raw_output_digest,
            plan_digest: value.plan_digest,
            frozen_steps: value.frozen_steps,
            trusted_time_unix_ms: value.trusted_time_unix_ms,
            exact_inputs: value.exact_inputs,
            exact_inputs_digest: value.exact_inputs_digest,
            step_results: value.step_results,
            state: value.state,
            version: value.version,
            lifecycle_digest: value.lifecycle_digest,
        };
        record.validate()?;
        Ok(record)
    }

    #[allow(dead_code)]
    pub(crate) fn prepare(
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
        frozen_steps: Vec<FrozenEvaluationStepV1>,
        trusted_time_unix_ms: u64,
        normalized_request_context: PostReturnNormalizedRequestContextV1,
    ) -> Result<Self, ToolOutcomeError> {
        outcome.validate_against(operation)?;
        if !matches!(outcome.disposition, ResolvedToolOutcomeV1::Returned) {
            return Err(ToolOutcomeError::Transition {
                state: outcome.disposition.name(),
                transition: "prepare_evaluation",
            });
        }
        validate_steps(&frozen_steps)?;
        positive("evaluation.trusted_time", trusted_time_unix_ms)?;
        let exact_inputs = PostReturnExactInputsV1::from_records(
            operation,
            outcome,
            normalized_request_context,
            trusted_time_unix_ms,
        )?;
        let exact_inputs_digest = digest_bytes(
            "evaluation.exact_inputs_digest",
            &bounded(
                "evaluation.exact_inputs",
                &exact_inputs,
                MAX_FROZEN_INPUT_BYTES,
            )?,
        )?;
        let plan_digest = domain_digest("chio.post-return-plan.v1", &frozen_steps)?;
        let identity = EvaluationIdentity {
            operation_id: &outcome.operation_id,
            tool_outcome_id: &outcome.outcome_id,
            tool_outcome_version: outcome.version,
            raw_output_digest: outcome.raw_output.digest(),
            plan_digest: &plan_digest,
            trusted_time_unix_ms,
            exact_inputs_digest: &exact_inputs_digest,
        };
        let evaluation_id = domain_digest("chio.post-return-evaluation.identity.v1", &identity)?;
        let step_results = Vec::new();
        let state = PostReturnEvaluationStateV1::Evaluating;
        let version = 1;
        let lifecycle_digest =
            evaluation_lifecycle_digest(&evaluation_id, &step_results, &state, version)?;
        let record = Self {
            schema: POST_RETURN_EVALUATION_SCHEMA,
            evaluation_id,
            operation_id: outcome.operation_id.clone(),
            tool_outcome_id: outcome.outcome_id.clone(),
            tool_outcome_version: outcome.version,
            raw_output_digest: outcome.raw_output.digest().clone(),
            plan_digest,
            frozen_steps,
            trusted_time_unix_ms,
            exact_inputs,
            exact_inputs_digest,
            step_results,
            state,
            version,
            lifecycle_digest,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn evaluation_id(&self) -> &AdmissionDigest {
        &self.evaluation_id
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn state(&self) -> &PostReturnEvaluationStateV1 {
        &self.state
    }

    pub(crate) fn trusted_time_unix_ms(&self) -> u64 {
        self.trusted_time_unix_ms
    }

    pub(crate) fn step_result_digest(&self, index: usize) -> Option<&AdmissionDigest> {
        self.step_results
            .get(index)
            .map(|result| &result.result_digest)
    }

    pub(crate) fn validate_replay_contract(
        &self,
        frozen_steps: &[FrozenEvaluationStepV1],
        normalized_request_context: &PostReturnNormalizedRequestContextV1,
    ) -> Result<(), ToolOutcomeError> {
        self.validate()?;
        if self.frozen_steps != frozen_steps
            || &self.exact_inputs.normalized_request_context != normalized_request_context
        {
            return Err(ToolOutcomeError::Binding("evaluation.replay_contract"));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
    ) -> Result<(), ToolOutcomeError> {
        self.validate()?;
        self.exact_inputs.validate_against(operation, outcome)?;
        let recorded_return_version = recorded_return_version(outcome)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.tool_outcome_id != outcome.outcome_id
            || self.tool_outcome_version != recorded_return_version
            || self.raw_output_digest != *outcome.raw_output.digest()
        {
            return Err(ToolOutcomeError::Binding("evaluation.records"));
        }
        Ok(())
    }

    pub(super) fn step_result_root(&self) -> Result<AdmissionDigest, ToolOutcomeError> {
        domain_digest("chio.post-return-step-results.v1", &self.step_results)
    }

    pub(crate) fn record_next_pure_result(
        &self,
        result_digest: AdmissionDigest,
    ) -> Result<Self, ToolOutcomeError> {
        let index = self.step_results.len();
        let step = self
            .frozen_steps
            .get(index)
            .ok_or(ToolOutcomeError::Invalid(
                "evaluation.no_step_result_expected",
            ))?;
        if step.mode != EvaluationModeV1::Pure {
            return Err(ToolOutcomeError::Invalid(
                "evaluation.next_step_is_not_pure",
            ));
        }
        let step_index = u32::try_from(index)
            .map_err(|_| ToolOutcomeError::Overflow("evaluation.step_index"))?;
        let input_dependency_digest = self.step_results.last().map_or_else(
            || self.exact_inputs_digest.clone(),
            |prior| prior.result_digest.clone(),
        );
        self.transition(
            self.version,
            PostReturnEvaluationTransitionV1::RecordStepResult(EvaluationStepResultV1::pure(
                step_index,
                input_dependency_digest,
                result_digest,
            )),
        )
    }

    pub(crate) fn resolve_with_signing_preimage(
        &self,
        signing_preimage: Vec<u8>,
        post_guard_decision_digest: AdmissionDigest,
        pricing_verdict_digest: AdmissionDigest,
        settlement_disposition: SettlementDispositionV1,
    ) -> Result<(Self, CanonicalResolvedOutputBlobV1), ToolOutcomeError> {
        let (resolution, blob) = PostReturnResolutionV1::from_signing_preimage(
            self,
            signing_preimage,
            post_guard_decision_digest,
            pricing_verdict_digest,
            settlement_disposition,
        )?;
        self.transition(
            self.version,
            PostReturnEvaluationTransitionV1::Resolve(resolution),
        )
        .map(|terminal| (terminal, blob))
    }

    pub(super) fn validate(&self) -> Result<(), ToolOutcomeError> {
        positive("evaluation.tool_outcome_version", self.tool_outcome_version)?;
        positive("evaluation.trusted_time", self.trusted_time_unix_ms)?;
        positive("evaluation.version", self.version)?;
        validate_steps(&self.frozen_steps)?;
        self.exact_inputs.validate()?;
        if self.exact_inputs.operation_id != self.operation_id
            || self.exact_inputs.tool_outcome_id != self.tool_outcome_id
            || self.exact_inputs.tool_outcome_version != self.tool_outcome_version
            || self.exact_inputs.raw_output_digest != self.raw_output_digest
            || self.exact_inputs.trusted_time_unix_ms != self.trusted_time_unix_ms
        {
            return Err(ToolOutcomeError::Binding("evaluation.exact_inputs"));
        }
        if domain_digest("chio.post-return-plan.v1", &self.frozen_steps)? != self.plan_digest {
            return Err(ToolOutcomeError::Binding("evaluation.plan_digest"));
        }
        if digest_bytes(
            "evaluation.exact_inputs_digest",
            &bounded(
                "evaluation.exact_inputs",
                &self.exact_inputs,
                MAX_FROZEN_INPUT_BYTES,
            )?,
        )? != self.exact_inputs_digest
        {
            return Err(ToolOutcomeError::Binding("evaluation.exact_inputs_digest"));
        }
        let expected = domain_digest(
            "chio.post-return-evaluation.identity.v1",
            &EvaluationIdentity {
                operation_id: &self.operation_id,
                tool_outcome_id: &self.tool_outcome_id,
                tool_outcome_version: self.tool_outcome_version,
                raw_output_digest: &self.raw_output_digest,
                plan_digest: &self.plan_digest,
                trusted_time_unix_ms: self.trusted_time_unix_ms,
                exact_inputs_digest: &self.exact_inputs_digest,
            },
        )?;
        if expected != self.evaluation_id {
            return Err(ToolOutcomeError::Binding("evaluation.evaluation_id"));
        }
        if self.lifecycle_digest
            != evaluation_lifecycle_digest(
                &self.evaluation_id,
                &self.step_results,
                &self.state,
                self.version,
            )?
        {
            return Err(ToolOutcomeError::Binding("evaluation.lifecycle_digest"));
        }
        validate_results(
            &self.frozen_steps,
            &self.step_results,
            &self.exact_inputs_digest,
            self.trusted_time_unix_ms,
        )?;
        let terminal_increment = u64::from(!matches!(
            &self.state,
            PostReturnEvaluationStateV1::Evaluating
        ));
        let expected_version = u64::try_from(self.step_results.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .and_then(|version| version.checked_add(terminal_increment))
            .ok_or(ToolOutcomeError::Overflow("evaluation.lifecycle_version"))?;
        if self.version != expected_version {
            return Err(ToolOutcomeError::Binding("evaluation.lifecycle_version"));
        }
        match &self.state {
            PostReturnEvaluationStateV1::Evaluating => Ok(()),
            PostReturnEvaluationStateV1::Resolved { resolution } => {
                resolution.validate()?;
                if self.step_results.len() != self.frozen_steps.len()
                    || resolution.terminal_dependency_root_digest != self.step_result_root()?
                {
                    return Err(ToolOutcomeError::Binding(
                        "evaluation.terminal_dependency_root",
                    ));
                }
                Ok(())
            }
            PostReturnEvaluationStateV1::Frozen { freeze } => {
                validate_freeze(freeze, &self.frozen_steps, self.step_results.len())
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn transition(
        &self,
        expected_version: u64,
        transition: PostReturnEvaluationTransitionV1,
    ) -> Result<Self, ToolOutcomeError> {
        self.validate()?;
        if self.version != expected_version {
            return Err(ToolOutcomeError::Cas {
                expected: expected_version,
                actual: self.version,
            });
        }
        if !matches!(self.state, PostReturnEvaluationStateV1::Evaluating) {
            return Err(ToolOutcomeError::Transition {
                state: self.state.name(),
                transition: transition.name(),
            });
        }
        let mut next = self.clone();
        next.version = next
            .version
            .checked_add(1)
            .ok_or(ToolOutcomeError::Overflow("evaluation.version"))?;
        match transition {
            PostReturnEvaluationTransitionV1::RecordStepResult(result) => {
                let index = self.step_results.len();
                let step = self
                    .frozen_steps
                    .get(index)
                    .ok_or(ToolOutcomeError::Invalid(
                        "evaluation.no_step_result_expected",
                    ))?;
                let dependency = self
                    .step_results
                    .last()
                    .map_or(&self.exact_inputs_digest, |prior| &prior.result_digest);
                result.validate_for(index, step, dependency, self.trusted_time_unix_ms)?;
                next.step_results.push(result);
            }
            PostReturnEvaluationTransitionV1::Resolve(resolution) => {
                if self.step_results.len() != self.frozen_steps.len()
                    || resolution.terminal_dependency_root_digest != self.step_result_root()?
                {
                    return Err(ToolOutcomeError::Invalid(
                        "evaluation.incomplete_step_results",
                    ));
                }
                resolution.validate()?;
                next.state = PostReturnEvaluationStateV1::Resolved { resolution };
            }
            PostReturnEvaluationTransitionV1::Freeze(freeze) => {
                validate_freeze(&freeze, &self.frozen_steps, self.step_results.len())?;
                next.state = PostReturnEvaluationStateV1::Frozen { freeze };
            }
        }
        next.lifecycle_digest = evaluation_lifecycle_digest(
            &next.evaluation_id,
            &next.step_results,
            &next.state,
            next.version,
        )?;
        next.validate()?;
        Ok(next)
    }

    pub fn replay_action(
        &self,
        step_index: u32,
    ) -> Result<PostReturnReplayActionV1, ToolOutcomeError> {
        let index = usize::try_from(step_index)
            .map_err(|_| ToolOutcomeError::Invalid("replay.step_index"))?;
        let step = self
            .frozen_steps
            .get(index)
            .ok_or(ToolOutcomeError::Invalid("replay.step_index"))?;
        match &self.state {
            PostReturnEvaluationStateV1::Resolved { .. } => {
                Ok(PostReturnReplayActionV1::DoNotRunResolved)
            }
            PostReturnEvaluationStateV1::Frozen { .. } => {
                Ok(PostReturnReplayActionV1::DoNotRunFrozen)
            }
            PostReturnEvaluationStateV1::Evaluating if index < self.step_results.len() => {
                Ok(PostReturnReplayActionV1::UseRecordedStepResult {
                    result_digest: self.step_results[index].result_digest.clone(),
                })
            }
            PostReturnEvaluationStateV1::Evaluating if index > self.step_results.len() => {
                Err(ToolOutcomeError::Invalid("replay.out_of_order"))
            }
            PostReturnEvaluationStateV1::Evaluating => match &step.mode {
                EvaluationModeV1::Pure => Ok(PostReturnReplayActionV1::ReplayPureFromFrozenInputs),
                EvaluationModeV1::ExternalStateful { call_id } => {
                    Ok(PostReturnReplayActionV1::LookupExternalResult {
                        call_id: call_id.clone(),
                    })
                }
            },
        }
    }

    pub fn validate_for_store_mutation(
        &self,
        trusted_now_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        self.validate()?;
        positive("evaluation.store_trusted_now", trusted_now_unix_ms)?;
        if trusted_now_unix_ms < self.trusted_time_unix_ms
            || self.step_results.iter().any(|result| {
                result
                    .external_result
                    .as_ref()
                    .is_some_and(|external| external.authenticated_at_unix_ms > trusted_now_unix_ms)
            })
        {
            return Err(ToolOutcomeError::Binding("evaluation.store_trusted_now"));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn terminal_evidence(
        &self,
    ) -> Result<PostReturnTerminalEvidenceV1, ToolOutcomeError> {
        self.validate()?;
        let PostReturnEvaluationStateV1::Resolved { resolution } = &self.state else {
            return Err(ToolOutcomeError::Invalid("terminal_evidence.unresolved"));
        };
        Ok(PostReturnTerminalEvidenceV1 {
            evaluation_id: self.evaluation_id.clone(),
            operation_id: self.operation_id.clone(),
            tool_outcome_id: self.tool_outcome_id.clone(),
            tool_outcome_version: self.tool_outcome_version,
            raw_output_digest: self.raw_output_digest.clone(),
            resolved_output: resolution.resolved_output.clone(),
            resolved_output_size_bytes: resolution.resolved_output_size_bytes,
            terminal_dependency_root_digest: resolution.terminal_dependency_root_digest.clone(),
            post_guard_decision_digest: resolution.post_guard_decision_digest.clone(),
            pricing_verdict_digest: resolution.pricing_verdict_digest.clone(),
            settlement_disposition: resolution.settlement_disposition.clone(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn freeze_evidence(&self) -> Result<PostReturnFreezeEvidenceV1, ToolOutcomeError> {
        self.validate()?;
        let PostReturnEvaluationStateV1::Frozen { freeze } = &self.state else {
            return Err(ToolOutcomeError::Invalid("freeze_evidence.not_frozen"));
        };
        Ok(PostReturnFreezeEvidenceV1 {
            evaluation_id: self.evaluation_id.clone(),
            operation_id: self.operation_id.clone(),
            tool_outcome_id: self.tool_outcome_id.clone(),
            tool_outcome_version: self.tool_outcome_version,
            raw_output_digest: self.raw_output_digest.clone(),
            freeze_evidence_digest: freeze.evidence_digest().clone(),
        })
    }
}

#[allow(dead_code)]
fn recorded_return_version(outcome: &ToolOutcomeRecordV1) -> Result<u64, ToolOutcomeError> {
    match outcome.disposition {
        ResolvedToolOutcomeV1::Returned => Ok(outcome.version),
        ResolvedToolOutcomeV1::Resolved { .. } | ResolvedToolOutcomeV1::Frozen { .. } => outcome
            .version
            .checked_sub(1)
            .ok_or(ToolOutcomeError::Binding("evaluation.outcome_version")),
    }
}

fn validate_steps(steps: &[FrozenEvaluationStepV1]) -> Result<(), ToolOutcomeError> {
    if steps.is_empty() || steps.len() > MAX_EVALUATION_STEPS {
        return Err(ToolOutcomeError::TooLarge {
            field: "evaluation.steps",
            actual: steps.len(),
            maximum: MAX_EVALUATION_STEPS,
        });
    }
    let mut guard_position = 0;
    let mut pricing_position = 0;
    let mut pricing_started = false;
    let mut external_call_ids = Vec::new();
    for step in steps {
        let expected = match step.phase {
            EvaluationPhaseV1::OutputGuard if !pricing_started => &mut guard_position,
            EvaluationPhaseV1::Pricing => {
                pricing_started = true;
                &mut pricing_position
            }
            EvaluationPhaseV1::OutputGuard => {
                return Err(ToolOutcomeError::Invalid("evaluation.steps.phase_order"));
            }
        };
        if step.position != *expected {
            return Err(ToolOutcomeError::Invalid("evaluation.steps.position"));
        }
        if let EvaluationModeV1::ExternalStateful { call_id } = &step.mode {
            if external_call_ids.contains(call_id) {
                return Err(ToolOutcomeError::Invalid(
                    "evaluation.steps.duplicate_call_id",
                ));
            }
            external_call_ids.push(call_id.clone());
        }
        *expected += 1;
    }
    Ok(())
}

fn validate_results(
    steps: &[FrozenEvaluationStepV1],
    results: &[EvaluationStepResultV1],
    exact_inputs_digest: &AdmissionDigest,
    evaluation_trusted_time_unix_ms: u64,
) -> Result<(), ToolOutcomeError> {
    if results.len() > steps.len() {
        return Err(ToolOutcomeError::TooLarge {
            field: "evaluation.step_results",
            actual: results.len(),
            maximum: steps.len(),
        });
    }
    for (index, result) in results.iter().enumerate() {
        let dependency = index
            .checked_sub(1)
            .map_or(exact_inputs_digest, |previous| {
                &results[previous].result_digest
            });
        result.validate_for(
            index,
            steps
                .get(index)
                .ok_or(ToolOutcomeError::Binding("step_result.step"))?,
            dependency,
            evaluation_trusted_time_unix_ms,
        )?;
    }
    Ok(())
}

fn validate_freeze(
    freeze: &EvaluationFreezeV1,
    steps: &[FrozenEvaluationStepV1],
    result_count: usize,
) -> Result<(), ToolOutcomeError> {
    freeze.validate(steps.len())?;
    if usize::try_from(freeze.step_index()).ok() != Some(result_count)
        || !matches!(
            steps.get(result_count).map(|step| &step.mode),
            Some(EvaluationModeV1::ExternalStateful { .. })
        )
    {
        return Err(ToolOutcomeError::Binding(
            "evaluation_freeze.next_external_step",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum PostReturnEvaluationTransitionV1 {
    RecordStepResult(EvaluationStepResultV1),
    Resolve(PostReturnResolutionV1),
    Freeze(EvaluationFreezeV1),
}

impl PostReturnEvaluationTransitionV1 {
    #[allow(dead_code)]
    fn name(&self) -> &'static str {
        match self {
            Self::RecordStepResult(_) => "record_step_result",
            Self::Resolve(_) => "resolve",
            Self::Freeze(_) => "freeze",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostReturnReplayActionV1 {
    ReplayPureFromFrozenInputs,
    UseRecordedStepResult { result_digest: AdmissionDigest },
    LookupExternalResult { call_id: AdmissionIdentifier },
    DoNotRunResolved,
    DoNotRunFrozen,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostReturnTerminalEvidenceV1 {
    pub(super) evaluation_id: AdmissionDigest,
    pub(super) operation_id: AdmissionOperationId,
    pub(super) tool_outcome_id: AdmissionDigest,
    pub(super) tool_outcome_version: u64,
    pub(super) raw_output_digest: AdmissionDigest,
    pub(super) resolved_output: ContentAddressedBlobRefV1,
    pub(super) resolved_output_size_bytes: u64,
    pub(super) terminal_dependency_root_digest: AdmissionDigest,
    pub(super) post_guard_decision_digest: AdmissionDigest,
    pub(super) pricing_verdict_digest: AdmissionDigest,
    pub(super) settlement_disposition: SettlementDispositionV1,
}

impl PostReturnTerminalEvidenceV1 {
    #[allow(dead_code)]
    pub(super) fn binds(&self, outcome: &ToolOutcomeRecordV1) -> Result<(), ToolOutcomeError> {
        if self.operation_id != outcome.operation_id
            || self.tool_outcome_id != outcome.outcome_id
            || self.tool_outcome_version != outcome.version
            || self.raw_output_digest != *outcome.raw_output.digest()
        {
            return Err(ToolOutcomeError::Binding("terminal_evidence.outcome"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PostReturnFreezeEvidenceV1 {
    pub(super) evaluation_id: AdmissionDigest,
    pub(super) operation_id: AdmissionOperationId,
    pub(super) tool_outcome_id: AdmissionDigest,
    pub(super) tool_outcome_version: u64,
    pub(super) raw_output_digest: AdmissionDigest,
    pub(super) freeze_evidence_digest: AdmissionDigest,
}

impl PostReturnFreezeEvidenceV1 {
    #[allow(dead_code)]
    pub(super) fn binds(&self, outcome: &ToolOutcomeRecordV1) -> Result<(), ToolOutcomeError> {
        if self.operation_id != outcome.operation_id
            || self.tool_outcome_id != outcome.outcome_id
            || self.tool_outcome_version != outcome.version
            || self.raw_output_digest != *outcome.raw_output.digest()
        {
            return Err(ToolOutcomeError::Binding("freeze_evidence.outcome"));
        }
        Ok(())
    }
}
