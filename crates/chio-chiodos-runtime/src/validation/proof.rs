use std::collections::BTreeSet;

use crate::error::ChiodosRuntimeError;
use crate::schema::{
    CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA, CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
    CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
};
use crate::types::{
    RuntimeProofDrift, RuntimeProofDriftReport, RuntimeProofParityReport,
    RuntimeProofRegenerationInput, RuntimeProofRegenerationReport, RuntimeProofSourceRecord,
};
use crate::validation::common::{
    ensure_sha256_hash, validate_acceptance_failure_code, validate_non_empty, validate_state_label,
};
use crate::validation::evidence::validate_relative_evidence_path;

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_drift_report_schema",
            detail: format!(
                "runtime proof drift report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(
        &report.baseline_run_id,
        "runtime_proof_drift_empty_baseline",
    )?;
    validate_non_empty(
        &report.candidate_run_id,
        "runtime_proof_drift_empty_candidate",
    )?;
    ensure_sha256_hash(
        &report.baseline_manifest_sha256,
        "runtime_proof_drift_invalid_baseline_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_manifest_sha256,
        "runtime_proof_drift_invalid_candidate_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.baseline_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_baseline_proof_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_candidate_proof_hash",
    )?;
    for drift in &report.semantic_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.verifier_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.artifact_drifts {
        validate_non_empty(&drift.role, "runtime_proof_drift_empty_artifact_role")?;
        validate_relative_evidence_path(&drift.path, "runtime_proof_drift_invalid_artifact_path")?;
        ensure_sha256_hash(
            &drift.baseline_sha256,
            "runtime_proof_drift_invalid_baseline_artifact_hash",
        )?;
        ensure_sha256_hash(
            &drift.candidate_sha256,
            "runtime_proof_drift_invalid_candidate_artifact_hash",
        )?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_drift_missing_failure_code",
        "runtime_proof_drift_unexpected_failure_code",
    )?;
    if report.accepted
        && (!report.semantic_drifts.is_empty()
            || !report.artifact_drifts.is_empty()
            || !report.verifier_drifts.is_empty())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_drift_accepted_with_drifts",
            detail: "accepted runtime proof drift report cannot carry drift rows".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChiodosRuntimeError> {
    if input.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_input_schema",
            detail: format!(
                "runtime proof regeneration input declared unsupported schema {}",
                input.schema
            ),
        });
    }
    ensure_sha256_hash(
        &input.evidence_manifest_sha256,
        "runtime_proof_regeneration_input_invalid_manifest_hash",
    )?;
    ensure_sha256_hash(
        &input.workflow_run_report_sha256,
        "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &input.admission_report_sha256,
        "runtime_proof_regeneration_input_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &input.trust_bundle_sha256,
        "runtime_proof_regeneration_input_invalid_trust_bundle_hash",
    )?;
    ensure_sha256_hash(
        &input.verification_context_sha256,
        "runtime_proof_regeneration_input_invalid_context_hash",
    )?;
    if input.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_input_missing_source_records",
            detail: "runtime proof regeneration input must carry source records".to_string(),
        });
    }
    validate_runtime_proof_source_records(&input.source_records)
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_report_schema",
            detail: format!(
                "runtime proof regeneration report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_regeneration_missing_failure_code",
        "runtime_proof_regeneration_unexpected_failure_code",
    )?;
    if report.accepted && report.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_source_records",
            detail: "accepted runtime proof regeneration report must carry source records"
                .to_string(),
        });
    }
    if report.accepted && report.proof_package_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_package_hash",
            detail: "accepted runtime proof regeneration report must bind proof package hash"
                .to_string(),
        });
    }
    if report.accepted && report.verifier_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_verifier_report_hash",
            detail: "accepted runtime proof regeneration report must bind verifier report hash"
                .to_string(),
        });
    }
    if report.accepted && report.workflow_receipt_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_workflow_receipt_hash",
            detail: "accepted runtime proof regeneration report must bind workflow receipt hash"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_package_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_proof_regeneration_invalid_package_hash")?;
    }
    if let Some(hash) = report.verifier_report_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_verifier_report_hash",
        )?;
    }
    if let Some(hash) = report.workflow_receipt_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_workflow_receipt_hash",
        )?;
    }
    validate_runtime_proof_source_records(&report.source_records)?;
    Ok(())
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_parity_report_schema",
            detail: format!(
                "runtime proof parity report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.static_proof_package_sha256,
        "runtime_proof_parity_invalid_static_package_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_proof_package_sha256,
        "runtime_proof_parity_invalid_runtime_package_hash",
    )?;
    ensure_sha256_hash(
        &report.static_verifier_report_sha256,
        "runtime_proof_parity_invalid_static_report_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_verifier_report_sha256,
        "runtime_proof_parity_invalid_runtime_report_hash",
    )?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_parity_missing_failure_code",
        "runtime_proof_parity_unexpected_failure_code",
    )?;
    if report.compared_fields.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_missing_compared_fields",
            detail: "runtime proof parity report must name compared fields".to_string(),
        });
    }
    if report.accepted && !report.mismatches.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_accepted_with_mismatches",
            detail: "accepted runtime proof parity report cannot carry mismatches".to_string(),
        });
    }
    for mismatch in &report.mismatches {
        if mismatch.field.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_parity_empty_mismatch_field",
                detail: "runtime proof parity mismatch field is empty".to_string(),
            });
        }
        ensure_sha256_hash(
            &mismatch.static_value_sha256,
            "runtime_proof_parity_invalid_static_value_hash",
        )?;
        ensure_sha256_hash(
            &mismatch.runtime_value_sha256,
            "runtime_proof_parity_invalid_runtime_value_hash",
        )?;
    }
    Ok(())
}

fn validate_runtime_proof_source_records(
    source_records: &[RuntimeProofSourceRecord],
) -> Result<(), ChiodosRuntimeError> {
    let mut step_indices = BTreeSet::new();
    for record in source_records {
        if !step_indices.insert(record.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_regeneration_duplicate_source_record",
                detail: format!(
                    "runtime proof source record step {} is duplicated",
                    record.step_index
                ),
            });
        }
        ensure_sha256_hash(
            &record.admission_report_sha256,
            "runtime_proof_regeneration_invalid_admission_hash",
        )?;
        ensure_sha256_hash(
            &record.tool_receipt_sha256,
            "runtime_proof_regeneration_invalid_tool_receipt_hash",
        )?;
        ensure_sha256_hash(
            &record.bilateral_dsse_sha256,
            "runtime_proof_regeneration_invalid_dsse_hash",
        )?;
        ensure_sha256_hash(
            &record.workflow_step_sha256,
            "runtime_proof_regeneration_invalid_workflow_step_hash",
        )?;
    }
    Ok(())
}

fn validate_runtime_proof_drift(drift: &RuntimeProofDrift) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(&drift.field, "runtime_proof_drift_empty_field")?;
    ensure_sha256_hash(
        &drift.baseline_value_sha256,
        "runtime_proof_drift_invalid_baseline_value_hash",
    )?;
    ensure_sha256_hash(
        &drift.candidate_value_sha256,
        "runtime_proof_drift_invalid_candidate_value_hash",
    )?;
    validate_state_label(&drift.severity, "runtime_proof_drift_invalid_severity")
}
