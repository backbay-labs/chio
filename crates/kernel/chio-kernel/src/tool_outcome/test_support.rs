use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::sha256_hex;
use serde_json::{json, Value};

use super::*;

fn identifier(value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new("tool_outcome_test_identifier", value)
        .unwrap_or_else(|error| panic!("invalid tool outcome test identifier: {error}"))
}

fn digest(value: &str) -> AdmissionDigest {
    AdmissionDigest::try_new("tool_outcome_test_digest", sha256_hex(value.as_bytes()))
        .unwrap_or_else(|error| panic!("invalid tool outcome test digest: {error}"))
}

pub fn returned_value(
    operation: &AdmissionOperationV1,
    recording_fence: StoreMutationFence,
    recorded_at_unix_ms: u64,
    value: Value,
    reported_cost: Option<MonetaryAmount>,
) -> Result<(CanonicalInvocationBlobV1, ToolOutcomeRecordV1), ToolOutcomeError> {
    let commit = operation
        .dispatch_commit()
        .ok_or(ToolOutcomeError::Binding("test_support.dispatch_commit"))?;
    let provider_attempt = operation
        .provider_attempt()
        .cloned()
        .ok_or(ToolOutcomeError::Binding("test_support.provider_attempt"))?;
    let raw = RawInvocationOutcomeV1::from_committed_dispatch(
        operation,
        commit,
        identifier("tool-outcome-test-server"),
        identifier("tool-outcome-test-tool"),
        provider_attempt,
        digest("transport-terminal"),
        0,
        7,
        InvocationStreamLimitsV1 {
            max_total_bytes: 1024,
            max_chunks: 16,
            max_duration_secs: 30,
        },
        InvocationOutputV1::Value { value },
        reported_cost,
        None,
        Vec::new(),
    )?;
    let blob = raw.canonical_blob()?;
    let outcome = ToolOutcomeRecordV1::record_tool_returned(
        operation,
        &raw,
        &blob,
        recording_fence,
        recorded_at_unix_ms,
    )?;
    Ok((blob, outcome))
}

pub fn prepared_evaluation(
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
    trusted_time_unix_ms: u64,
) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeError> {
    PostReturnEvaluationRecordV1::prepare(
        operation,
        outcome,
        vec![
            FrozenEvaluationStepV1 {
                phase: EvaluationPhaseV1::OutputGuard,
                position: 0,
                component_id: identifier("test-output-guard"),
                component_version: identifier("1.0.0"),
                implementation_digest: digest("test-output-guard-implementation"),
                mode: EvaluationModeV1::Pure,
            },
            FrozenEvaluationStepV1 {
                phase: EvaluationPhaseV1::Pricing,
                position: 0,
                component_id: identifier("test-pricing-policy"),
                component_version: identifier("1.0.0"),
                implementation_digest: digest("test-pricing-policy-implementation"),
                mode: EvaluationModeV1::ExternalStateful {
                    call_id: identifier("test-pricing-call"),
                },
            },
        ],
        trusted_time_unix_ms,
        PostReturnNormalizedRequestContextV1::from_verified_normalization(json!({
            "request": "normalized"
        }))?,
    )
}

pub fn record_pure_step(
    evaluation: &PostReturnEvaluationRecordV1,
) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeError> {
    evaluation.transition(
        evaluation.version(),
        PostReturnEvaluationTransitionV1::RecordStepResult(EvaluationStepResultV1::pure(
            0,
            evaluation.exact_inputs_digest.clone(),
            digest("test-output-guard-result"),
        )),
    )
}

pub fn record_external_step(
    evaluation: &PostReturnEvaluationRecordV1,
    authenticated_at_unix_ms: u64,
) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeError> {
    let step = evaluation
        .frozen_steps
        .get(1)
        .ok_or(ToolOutcomeError::Invalid("test_support.pricing_step"))?;
    let dependency = evaluation
        .step_results
        .last()
        .ok_or(ToolOutcomeError::Invalid("test_support.guard_result"))?
        .result_digest
        .clone();
    let external = ExternalEvaluationResultRefV1::new(
        1,
        step,
        digest("test-pricing-result"),
        identifier("test-pricing-verifier"),
        1,
        authenticated_at_unix_ms,
    )?;
    evaluation.transition(
        evaluation.version(),
        PostReturnEvaluationTransitionV1::RecordStepResult(EvaluationStepResultV1::external(
            dependency, external,
        )),
    )
}

pub fn resolve(
    outcome: &ToolOutcomeRecordV1,
    evaluation: &PostReturnEvaluationRecordV1,
    settlement_disposition: SettlementDispositionV1,
) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeError> {
    let (terminal_evaluation, terminal_outcome, _) =
        resolve_with_blob(outcome, evaluation, settlement_disposition)?;
    Ok((terminal_evaluation, terminal_outcome))
}

pub fn resolve_with_blob(
    outcome: &ToolOutcomeRecordV1,
    evaluation: &PostReturnEvaluationRecordV1,
    settlement_disposition: SettlementDispositionV1,
) -> Result<
    (
        PostReturnEvaluationRecordV1,
        ToolOutcomeRecordV1,
        CanonicalResolvedOutputBlobV1,
    ),
    ToolOutcomeError,
> {
    let (resolution, blob) = PostReturnResolutionV1::from_signing_preimage(
        evaluation,
        canonical_json_bytes(&json!({"allowed": true}))
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        digest("test-output-guard-decision"),
        digest("test-pricing-verdict"),
        settlement_disposition,
    )?;
    let terminal_evaluation = evaluation.transition(
        evaluation.version(),
        PostReturnEvaluationTransitionV1::Resolve(resolution),
    )?;
    let terminal_outcome = outcome.transition(
        outcome.version(),
        ToolOutcomeTransitionV1::Resolve(terminal_evaluation.terminal_evidence()?),
    )?;
    Ok((terminal_evaluation, terminal_outcome, blob))
}
