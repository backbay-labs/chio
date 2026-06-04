use std::collections::BTreeSet;

use crate::error::ChioRuntimeError;
use crate::schema::{
    CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA, CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA,
    CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA, CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
};
use crate::types::{
    RuntimeEvidenceManifest, RuntimeEvidenceSinkHealthReport, RuntimeStepEvidence,
    RuntimeWorkflowRunReport,
};
use crate::validation::common::{
    ensure_sha256_hash, is_sha256_hex, validate_acceptance_failure_code, validate_non_empty,
    validate_state_label,
};

pub fn validate_runtime_evidence_sink_health_report(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_evidence_sink_health_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_sink_health_report_schema",
            detail: format!(
                "runtime evidence sink health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_evidence_health_empty_run_id")?;
    ensure_sha256_hash(
        &report.evidence_root_sha256,
        "runtime_evidence_health_invalid_root_hash",
    )?;
    for role in &report.required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
    }
    for path in report
        .missing_artifacts
        .iter()
        .chain(report.artifact_hash_mismatches.iter())
        .chain(report.artifact_byte_count_mismatches.iter())
        .chain(report.unexpected_paths.iter())
    {
        validate_relative_evidence_path(path, "runtime_evidence_health_invalid_path")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_evidence_health_missing_failure_code",
        "runtime_evidence_health_accepted_with_failure_code",
    )?;
    Ok(())
}

fn is_runtime_evidence_sink_health_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA)
}

pub fn validate_runtime_workflow_run_report(
    report: &RuntimeWorkflowRunReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_workflow_run_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
            code: "unsupported_runtime_workflow_report_schema",
            detail: format!(
                "runtime workflow report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    if !is_sha256_hex(&report.admission_report_sha256) {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_workflow_invalid_admission_report_hash",
            detail: "runtime workflow report admission report hash is not sha256 hex".to_string(),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_workflow_missing_failure_code",
        "runtime_workflow_unexpected_failure_code",
    )?;
    for path in &report.evidence_paths {
        validate_relative_evidence_path(path, "runtime_workflow_invalid_evidence_path")?;
    }
    if report.accepted && report.step_evidence.is_empty() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_workflow_missing_step_evidence",
            detail: "accepted runtime workflow report must carry step evidence".to_string(),
        });
    }
    if report.accepted && report.proof_regeneration_report_sha256.is_none() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_workflow_missing_proof_regeneration_report",
            detail: "accepted runtime workflow report must bind proof regeneration report"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_regeneration_report_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_workflow_invalid_proof_regeneration_hash")?;
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_evidence {
        validate_runtime_step_evidence(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_workflow_duplicate_step_evidence",
                detail: format!("runtime workflow step {} is duplicated", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_evidence_manifest(
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_evidence_manifest_schema(&manifest.schema) {
        return Err(ChioRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_manifest_schema",
            detail: format!(
                "runtime evidence manifest declared unsupported schema {}",
                manifest.schema
            ),
        });
    }
    ensure_sha256_hash(
        &manifest.workflow_run_report_sha256,
        "runtime_evidence_manifest_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &manifest.proof_regeneration_report_sha256,
        "runtime_evidence_manifest_invalid_proof_report_hash",
    )?;
    if manifest.entries.is_empty() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_evidence_manifest_missing_entries",
            detail: "runtime evidence manifest must bind at least one artifact".to_string(),
        });
    }
    let mut paths = BTreeSet::new();
    for entry in &manifest.entries {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        if entry.role.trim().is_empty() {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_evidence_manifest_empty_role",
                detail: "runtime evidence manifest entry role is empty".to_string(),
            });
        }
        if !paths.insert(entry.path.clone()) {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_evidence_manifest_duplicate_path",
                detail: format!(
                    "runtime evidence manifest carries duplicate path {}",
                    entry.path
                ),
            });
        }
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
    }
    Ok(())
}

pub(crate) fn validate_relative_evidence_path(
    path: &str,
    code: &'static str,
) -> Result<(), ChioRuntimeError> {
    if !is_safe_relative_evidence_path(path) {
        return Err(ChioRuntimeError::Rejected {
            code,
            detail: format!("runtime evidence path {path:?} is not a safe relative path"),
        });
    }
    Ok(())
}

fn is_safe_relative_evidence_path(path: &str) -> bool {
    path.trim() == path
        && !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.contains("//")
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(super) fn validate_runtime_step_evidence(
    step: &RuntimeStepEvidence,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_step_evidence_schema(&step.schema) {
        return Err(ChioRuntimeError::Rejected {
            code: "unsupported_runtime_step_evidence_schema",
            detail: format!(
                "runtime step evidence declared unsupported schema {}",
                step.schema
            ),
        });
    }
    if step.admission_id.trim().is_empty() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_admission_id",
            detail: "runtime step evidence must bind admission id".to_string(),
        });
    }
    ensure_sha256_hash(
        &step.admission_report_sha256,
        "runtime_step_evidence_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &step.tool_receipt_sha256,
        "runtime_step_evidence_invalid_tool_receipt_hash",
    )?;
    ensure_sha256_hash(
        &step.output_sha256,
        "runtime_step_evidence_invalid_output_hash",
    )?;
    ensure_sha256_hash(
        &step.bilateral_dsse_sha256,
        "runtime_step_evidence_invalid_dsse_hash",
    )?;
    ensure_sha256_hash(
        &step.workflow_step_sha256,
        "runtime_step_evidence_invalid_workflow_step_hash",
    )?;
    if let Some(parent) = step.parent_receipt_sha256.as_deref() {
        ensure_sha256_hash(parent, "runtime_step_evidence_invalid_parent_hash")?;
    }
    if step.consistency_anchor.trim().is_empty() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_consistency_anchor",
            detail: "runtime step evidence must bind consistency anchor".to_string(),
        });
    }
    if step.destructive && step.governance_receipt_id.is_none() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_governance",
            detail: "destructive runtime step evidence must bind governance receipt".to_string(),
        });
    }
    Ok(())
}

fn is_runtime_workflow_run_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA)
}

fn is_runtime_evidence_manifest_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA)
}

fn is_runtime_step_evidence_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA)
}

#[cfg(test)]
mod tests {
    #[test]
    fn relative_evidence_path_helper_accepts_only_safe_paths() {
        for path in ["workflow-run-report.json", "steps/workflow-step-1.json"] {
            assert!(super::is_safe_relative_evidence_path(path), "{path}");
        }

        for path in [
            "",
            " workflow-run-report.json",
            "workflow-run-report.json ",
            "/workflow-run-report.json",
            "steps\\workflow-run-report.json",
            "C:workflow-run-report.json",
            "steps//workflow-run-report.json",
            "steps/./workflow-run-report.json",
            "steps/../workflow-run-report.json",
        ] {
            assert!(!super::is_safe_relative_evidence_path(path), "{path}");
        }
    }
}
