use serde::{Deserialize, Serialize};

use crate::apalache::{ItfInvariantEvaluation, ItfInvariantFailure};
use crate::{ActionCoverage, InvariantWitnessCoverage, RevocationProjection, TraceError};

pub const TRACE_VALIDATION_REPORT_SCHEMA: &str = "chio.trace-validation.v1";
pub const REVOCATION_INVARIANTS: [&str; 4] = [
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Passed,
    Failed,
}

impl ValidationStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Divergence {
    pub step: usize,
    pub projected_step: serde_json::Value,
    pub last_reachable_state: serde_json::Value,
    pub failed_conjunct: String,
    pub triage_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub itf_state_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apalache_evaluation: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceValidationReport {
    pub schema: String,
    pub spec: String,
    pub trace_id: String,
    pub status: ValidationStatus,
    pub trace_length: usize,
    pub authority_count: usize,
    pub capability_count: usize,
    pub invariants: Vec<String>,
    pub action_coverage: ActionCoverage,
    pub invariant_witnesses: InvariantWitnessCoverage,
    pub itf_state_count: usize,
    pub observer_keys: Vec<String>,
    pub observer_key_set_sha256: String,
    pub log_sha256: String,
    pub model_sha256: String,
    pub trace_check_model_sha256: String,
    pub trace_evaluation_model_sha256: String,
    pub itf_sha256: String,
    pub checker: String,
    pub checker_binary_sha256: String,
    pub timeout_binary_sha256: String,
    pub apalache_witness_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergence: Option<Divergence>,
}

impl TraceValidationReport {
    pub(crate) fn passed(projection: &RevocationProjection, checker: &str) -> Self {
        Self::new(projection, ValidationStatus::Passed, None, checker, "")
    }

    pub(crate) fn failed_invariant(
        projection: &RevocationProjection,
        failure: ItfInvariantFailure,
        evaluation: &ItfInvariantEvaluation,
        triage_template: &str,
        checker: &str,
    ) -> Result<Self, TraceError> {
        if failure.visible_step == 0 || failure.visible_step > projection.events.len() {
            return Err(TraceError::Apalache(format!(
                "invariant witness state {} has no visible trace step",
                failure.state_index
            )));
        }
        let projected_step = serde_json::to_value(&projection.events[failure.visible_step - 1])?;
        let last_reachable_state = failure.input_predecessor;
        let mut report = Self::new(
            projection,
            ValidationStatus::Failed,
            Some(Divergence {
                step: failure.visible_step,
                projected_step,
                last_reachable_state,
                failed_conjunct: failure.invariant,
                triage_template: triage_template.to_string(),
                itf_state_index: Some(failure.state_index),
                apalache_evaluation: Some(failure.evaluated_state),
            }),
            checker,
            &evaluation.witness_sha256,
        );
        report.bind_invariant_evaluation(evaluation);
        Ok(report)
    }

    pub(crate) fn failed(
        projection: &RevocationProjection,
        step: usize,
        failed_conjunct: &str,
        triage_template: &str,
        checker: &str,
    ) -> Result<Self, TraceError> {
        let projected_step = serde_json::to_value(&projection.events[step - 1])?;
        let last_reachable_state = projection.states.get(step - 1).cloned().ok_or_else(|| {
            TraceError::InvalidInput(format!(
                "projection has no state before divergent step {step}"
            ))
        })?;
        Ok(Self::new(
            projection,
            ValidationStatus::Failed,
            Some(Divergence {
                step,
                projected_step,
                last_reachable_state,
                failed_conjunct: failed_conjunct.to_string(),
                triage_template: triage_template.to_string(),
                itf_state_index: None,
                apalache_evaluation: None,
            }),
            checker,
            "",
        ))
    }

    fn new(
        projection: &RevocationProjection,
        status: ValidationStatus,
        divergence: Option<Divergence>,
        checker: &str,
        apalache_witness_sha256: &str,
    ) -> Self {
        Self {
            schema: TRACE_VALIDATION_REPORT_SCHEMA.to_string(),
            spec: "RevocationPropagation".to_string(),
            trace_id: projection.trace_id.clone(),
            status,
            trace_length: projection.events.len(),
            authority_count: projection.authority_count,
            capability_count: projection.capability_count,
            invariants: REVOCATION_INVARIANTS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            action_coverage: projection.action_coverage,
            invariant_witnesses: projection.invariant_witnesses,
            itf_state_count: projection.states.len(),
            observer_keys: projection.observer_keys.clone(),
            observer_key_set_sha256: chio_core_types::sha256_hex(
                projection.observer_keys.join("\n").as_bytes(),
            ),
            log_sha256: projection.log_sha256.clone(),
            model_sha256: chio_core_types::sha256_hex(super::apalache::REVOCATION_MODEL.as_bytes()),
            trace_check_model_sha256: chio_core_types::sha256_hex(
                super::apalache::TRACE_CHECK_MODEL.as_bytes(),
            ),
            trace_evaluation_model_sha256: chio_core_types::sha256_hex(
                super::apalache::TRACE_EVALUATE_MODEL.as_bytes(),
            ),
            itf_sha256: chio_core_types::sha256_hex(&projection.itf_json),
            checker: checker.to_string(),
            checker_binary_sha256: String::new(),
            timeout_binary_sha256: String::new(),
            apalache_witness_sha256: apalache_witness_sha256.to_string(),
            divergence,
        }
    }

    pub(crate) fn bind_invariant_evaluation(&mut self, evaluation: &ItfInvariantEvaluation) {
        self.apalache_witness_sha256 = evaluation.witness_sha256.clone();
        self.checker_binary_sha256 = evaluation.checker_binary_sha256.clone();
        self.timeout_binary_sha256 = evaluation.timeout_binary_sha256.clone();
    }
}
