use std::collections::{BTreeMap, BTreeSet};

use crate::error::ChioRuntimeError;
use crate::hash::canonical_sha256;
use crate::schema::{
    CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA, CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
    CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
};
use crate::types::{
    RuntimeEvidenceManifest, RuntimeProofDrift, RuntimeProofDriftReport, RuntimeProofParityReport,
    RuntimeProofRegenerationInput, RuntimeProofRegenerationReport, RuntimeProofSourceRecord,
    RuntimeStepEvidence, RuntimeWorkflowRunReport,
};
use crate::validation::common::{
    ensure_sha256_hash, validate_acceptance_failure_code, validate_non_empty, validate_state_label,
};
use crate::validation::evidence::{
    validate_relative_evidence_path, validate_runtime_evidence_manifest,
    validate_runtime_workflow_run_report,
};

pub struct RuntimeProofRegenerationArtifacts<'a> {
    pub proof_regeneration_report: &'a [u8],
    pub proof_regeneration_input: &'a [u8],
    pub evidence_manifest: &'a [u8],
    pub workflow_run_report: &'a [u8],
    pub proof_package: &'a [u8],
    pub verifier_report: &'a [u8],
    pub workflow_receipt: &'a [u8],
}

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_proof_drift_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_drift_accepted_with_drifts",
            detail: "accepted runtime proof drift report cannot carry drift rows".to_string(),
        });
    }
    Ok(())
}

fn is_runtime_proof_drift_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA)
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_proof_regeneration_input_schema(&input.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_input_missing_source_records",
            detail: "runtime proof regeneration input must carry source records".to_string(),
        });
    }
    validate_runtime_proof_source_records(&input.source_records)
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_proof_regeneration_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_source_records",
            detail: "accepted runtime proof regeneration report must carry source records"
                .to_string(),
        });
    }
    if report.accepted && report.proof_package_sha256.is_none() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_package_hash",
            detail: "accepted runtime proof regeneration report must bind proof package hash"
                .to_string(),
        });
    }
    if report.accepted && report.verifier_report_sha256.is_none() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_verifier_report_hash",
            detail: "accepted runtime proof regeneration report must bind verifier report hash"
                .to_string(),
        });
    }
    if report.accepted && report.workflow_receipt_sha256.is_none() {
        return Err(ChioRuntimeError::Rejected {
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

pub fn validate_runtime_proof_regeneration_artifacts(
    artifacts: RuntimeProofRegenerationArtifacts<'_>,
) -> Result<(), ChioRuntimeError> {
    let proof_report: RuntimeProofRegenerationReport = parse_runtime_json(
        artifacts.proof_regeneration_report,
        "runtime proof regeneration report",
    )?;
    let proof_input: RuntimeProofRegenerationInput = parse_runtime_json(
        artifacts.proof_regeneration_input,
        "runtime proof regeneration input",
    )?;
    let manifest: RuntimeEvidenceManifest =
        parse_runtime_json(artifacts.evidence_manifest, "runtime evidence manifest")?;
    let workflow_report: RuntimeWorkflowRunReport =
        parse_runtime_json(artifacts.workflow_run_report, "runtime workflow run report")?;

    validate_runtime_proof_regeneration_report(&proof_report)?;
    validate_runtime_proof_regeneration_input(&proof_input)?;
    validate_runtime_evidence_manifest(&manifest)?;
    validate_runtime_workflow_run_report(&workflow_report)?;

    if !proof_report.accepted || !workflow_report.accepted {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_evidence_not_accepted",
            detail: "runtime proof regeneration evidence must be accepted".to_string(),
        });
    }
    validate_non_empty(
        &proof_report.run_id,
        "runtime_proof_regeneration_missing_run_id",
    )?;
    ensure_runtime_regeneration_run_id(
        &proof_report.run_id,
        &proof_input.run_id,
        "proof regeneration input",
    )?;
    ensure_runtime_regeneration_run_id(
        &proof_report.run_id,
        &manifest.run_id,
        "evidence manifest",
    )?;
    ensure_runtime_regeneration_run_id(
        &proof_report.run_id,
        &workflow_report.run_id,
        "workflow run report",
    )?;

    let proof_report_sha256 = canonical_sha256(&proof_report)?;
    let proof_input_manifest_sha256 = canonical_sha256(&manifest)?;
    let workflow_report_sha256 = canonical_sha256(&workflow_report)?;
    let proof_package_sha256 =
        canonical_json_value_sha256(artifacts.proof_package, "runtime proof package")?;
    let verifier_report_sha256 =
        canonical_json_value_sha256(artifacts.verifier_report, "runtime verifier report")?;
    let workflow_receipt_sha256 =
        canonical_json_value_sha256(artifacts.workflow_receipt, "runtime workflow receipt")?;

    if workflow_report.proof_regeneration_report_sha256.as_deref()
        != Some(proof_report_sha256.as_str())
        || manifest.proof_regeneration_report_sha256 != proof_report_sha256
    {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_report_hash_mismatch",
            detail: "runtime proof regeneration report hash mismatch".to_string(),
        });
    }
    if manifest.workflow_run_report_sha256 != workflow_report_sha256
        || proof_input.workflow_run_report_sha256 != workflow_report_sha256
    {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_workflow_hash_mismatch",
            detail: "runtime proof regeneration workflow report hash mismatch".to_string(),
        });
    }
    if proof_input.evidence_manifest_sha256 != proof_input_manifest_sha256 {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_manifest_hash_mismatch",
            detail: "runtime proof regeneration evidence manifest hash mismatch".to_string(),
        });
    }
    if proof_input.source_records != proof_report.source_records {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_source_record_mismatch",
            detail: "runtime proof regeneration source records mismatch".to_string(),
        });
    }
    if !runtime_proof_source_records_match_steps(
        &workflow_report.step_evidence,
        &proof_report.source_records,
    ) {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_source_record_mismatch",
            detail: "runtime proof regeneration source records do not match workflow steps"
                .to_string(),
        });
    }
    if proof_report.proof_package_sha256.as_deref() != Some(proof_package_sha256.as_str()) {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_package_hash_mismatch",
            detail: "runtime proof regeneration proof package hash mismatch".to_string(),
        });
    }
    if proof_report.verifier_report_sha256.as_deref() != Some(verifier_report_sha256.as_str()) {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_verifier_hash_mismatch",
            detail: "runtime proof regeneration verifier report hash mismatch".to_string(),
        });
    }
    if proof_report.workflow_receipt_sha256.as_deref() != Some(workflow_receipt_sha256.as_str()) {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_workflow_receipt_hash_mismatch",
            detail: "runtime proof regeneration workflow receipt hash mismatch".to_string(),
        });
    }

    validate_manifest_entry(&manifest, "proof_package", artifacts.proof_package)?;
    validate_manifest_entry(&manifest, "verifier_report", artifacts.verifier_report)?;
    validate_manifest_entry(&manifest, "workflow_receipt", artifacts.workflow_receipt)?;
    validate_manifest_entry(
        &manifest,
        "proof_regeneration_report",
        artifacts.proof_regeneration_report,
    )?;
    validate_manifest_entry(
        &manifest,
        "runtime_run_report",
        artifacts.workflow_run_report,
    )?;
    Ok(())
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChioRuntimeError> {
    chio_runtime_proof_parity::validate_runtime_proof_parity_report(report).map_err(|error| {
        ChioRuntimeError::Rejected {
            code: error.code(),
            detail: error.detail().to_string(),
        }
    })
}

fn is_runtime_proof_regeneration_input_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA)
}

fn is_runtime_proof_regeneration_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA)
}

fn runtime_proof_source_records_match_steps(
    steps: &[RuntimeStepEvidence],
    source_records: &[RuntimeProofSourceRecord],
) -> bool {
    if steps.len() != source_records.len() {
        return false;
    }

    let mut records_by_step = BTreeMap::new();
    for record in source_records {
        if records_by_step.insert(record.step_index, record).is_some() {
            return false;
        }
    }

    steps.iter().all(|step| {
        records_by_step.get(&step.step_index).is_some_and(|record| {
            record.admission_report_sha256 == step.admission_report_sha256
                && record.tool_receipt_sha256 == step.tool_receipt_sha256
                && record.bilateral_dsse_sha256 == step.bilateral_dsse_sha256
                && record.workflow_step_sha256 == step.workflow_step_sha256
        })
    })
}

fn parse_runtime_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    label: &str,
) -> Result<T, ChioRuntimeError> {
    serde_json::from_slice(bytes)
        .map_err(|error| ChioRuntimeError::Json(format!("{label}: {error}")))
}

fn canonical_json_value_sha256(bytes: &[u8], label: &str) -> Result<String, ChioRuntimeError> {
    let value: serde_json::Value = parse_runtime_json(bytes, label)?;
    canonical_sha256(&value)
}

fn raw_sha256(bytes: &[u8]) -> String {
    chio_core_types::crypto::sha256_hex(bytes)
}

fn validate_manifest_entry(
    manifest: &RuntimeEvidenceManifest,
    role: &str,
    bytes: &[u8],
) -> Result<(), ChioRuntimeError> {
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.role == role)
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_manifest_entry_missing",
            detail: format!("runtime proof regeneration evidence manifest missing {role}"),
        })?;
    let byte_count = u64::try_from(bytes.len()).map_err(|error| ChioRuntimeError::Rejected {
        code: "runtime_proof_regeneration_artifact_too_large",
        detail: format!("runtime proof regeneration artifact byte count failed: {error}"),
    })?;
    if entry.sha256 != raw_sha256(bytes) || entry.byte_count != byte_count {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_manifest_artifact_mismatch",
            detail: format!(
                "runtime proof regeneration evidence manifest artifact mismatch for {role}"
            ),
        });
    }
    Ok(())
}

fn ensure_runtime_regeneration_run_id(
    expected: &str,
    actual: &str,
    label: &str,
) -> Result<(), ChioRuntimeError> {
    validate_non_empty(actual, "runtime_proof_regeneration_missing_run_id")?;
    if actual != expected {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_proof_regeneration_run_id_mismatch",
            detail: format!("runtime proof regeneration run ID mismatch for {label}"),
        });
    }
    Ok(())
}

fn validate_runtime_proof_source_records(
    source_records: &[RuntimeProofSourceRecord],
) -> Result<(), ChioRuntimeError> {
    let mut step_indices = BTreeSet::new();
    for record in source_records {
        if !step_indices.insert(record.step_index) {
            return Err(ChioRuntimeError::Rejected {
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

fn validate_runtime_proof_drift(drift: &RuntimeProofDrift) -> Result<(), ChioRuntimeError> {
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
