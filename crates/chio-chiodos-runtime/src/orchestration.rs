use std::fs;
use std::path::Path;

use chio_chiodos::VerifierReport;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::validation::validate_relative_evidence_path;
use crate::{
    validate_runtime_evidence_manifest, validate_runtime_orchestration_profile,
    validate_runtime_proof_regeneration_report, validate_runtime_workflow_run_report,
    ChiodosRuntimeError, RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry,
    RuntimeOrchestrationProfile, RuntimeProofRegenerationReport, RuntimeProofSourceRecord,
    RuntimeRunContract, RuntimeStepEvidence, RuntimeWorkflowRunReport,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeOrchestrationEvidence {
    pub workflow_run_report: RuntimeWorkflowRunReport,
    pub proof_regeneration_report: RuntimeProofRegenerationReport,
    pub manifest: RuntimeEvidenceManifest,
    pub verifier_report_accepted: bool,
    pub verifier_report_failure_code: Option<String>,
    pub proof_package_manifest_sha256: Option<String>,
    pub proof_package_file_sha256: Option<String>,
    pub proof_package_canonical_sha256: Option<String>,
    pub verifier_report_package_sha256: Option<String>,
    pub workflow_report_sha256: String,
    pub proof_report_sha256: String,
    pub manifest_sha256: String,
    pub verifier_report_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOrchestrationEvidenceFailure {
    code: String,
    detail: String,
}

impl RuntimeOrchestrationEvidenceFailure {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for RuntimeOrchestrationEvidenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RuntimeOrchestrationEvidenceFailure {}

struct RuntimeJsonArtifactHashes {
    manifest_sha256: String,
    file_sha256: String,
    canonical_sha256: String,
}

pub fn load_runtime_orchestration_evidence(
    evidence_dir: &Path,
) -> Result<RuntimeOrchestrationEvidence, ChiodosRuntimeError> {
    let workflow_report_path = evidence_dir.join("workflow-run-report.json");
    let proof_report_path = evidence_dir.join("proof-regeneration-report.json");
    let manifest_path = evidence_dir.join("runtime-evidence-manifest.json");
    let workflow_json =
        read_utf8_json_file(&workflow_report_path, "Chiodos runtime workflow report")?;
    let proof_json = read_utf8_json_file(&proof_report_path, "Chiodos runtime proof report")?;
    let manifest_json = read_utf8_json_file(&manifest_path, "Chiodos runtime evidence manifest")?;
    let workflow_run_report: RuntimeWorkflowRunReport =
        parse_json(&workflow_json, "Chiodos runtime workflow report")?;
    let proof_regeneration_report: RuntimeProofRegenerationReport =
        parse_json(&proof_json, "Chiodos runtime proof report")?;
    let manifest: RuntimeEvidenceManifest =
        parse_json(&manifest_json, "Chiodos runtime evidence manifest")?;
    validate_runtime_workflow_run_report(&workflow_run_report)?;
    validate_runtime_proof_regeneration_report(&proof_regeneration_report)?;
    validate_runtime_evidence_manifest(&manifest)?;
    let verifier_report_path = evidence_dir.join("verifier-report.json");
    let verifier_report_required = proof_regeneration_report.accepted
        || proof_regeneration_report.verifier_report_sha256.is_some();
    let verifier_json = if verifier_report_path.is_file() || verifier_report_required {
        Some(read_utf8_json_file(
            &verifier_report_path,
            "Chiodos verifier report",
        )?)
    } else {
        None
    };
    let (
        verifier_report_accepted,
        verifier_report_failure_code,
        verifier_report_package_sha256,
        verifier_report_sha256,
    ) = if let Some(verifier_json) = verifier_json {
        let verifier_report_value: serde_json::Value =
            parse_json(&verifier_json, "Chiodos verifier report")?;
        let verifier_report: VerifierReport =
            parse_json(&verifier_json, "Chiodos verifier report")?;
        (
            verifier_report.accepted,
            verifier_report
                .failure
                .as_ref()
                .map(|failure| failure.code.clone()),
            Some(verifier_report.package_sha256),
            Some(canonical_sha256(&verifier_report_value)?),
        )
    } else {
        (false, None, None, None)
    };
    let workflow_report_sha256 = canonical_sha256(&workflow_run_report)?;
    let proof_report_sha256 = canonical_sha256(&proof_regeneration_report)?;
    let manifest_sha256 = canonical_sha256(&manifest)?;
    validate_runtime_orchestration_manifest_artifacts(evidence_dir, &manifest)?;
    let proof_package_hashes = load_runtime_orchestration_role_json_artifact_hashes(
        evidence_dir,
        &manifest,
        "proof_package",
    )?;
    let proof_package_manifest_sha256 = proof_package_hashes
        .as_ref()
        .map(|hashes| hashes.manifest_sha256.clone());
    let proof_package_file_sha256 = proof_package_hashes
        .as_ref()
        .map(|hashes| hashes.file_sha256.clone());
    let proof_package_canonical_sha256 = proof_package_hashes
        .as_ref()
        .map(|hashes| hashes.canonical_sha256.clone());
    Ok(RuntimeOrchestrationEvidence {
        workflow_run_report,
        proof_regeneration_report,
        manifest,
        verifier_report_accepted,
        verifier_report_failure_code,
        proof_package_manifest_sha256,
        proof_package_file_sha256,
        proof_package_canonical_sha256,
        verifier_report_package_sha256,
        workflow_report_sha256,
        proof_report_sha256,
        manifest_sha256,
        verifier_report_sha256,
    })
}

pub fn validate_runtime_orchestration_evidence_binding(
    run_contract: &RuntimeRunContract,
    evidence: &RuntimeOrchestrationEvidence,
) -> Result<(), RuntimeOrchestrationEvidenceFailure> {
    if evidence.workflow_run_report.run_id != run_contract.run_id
        || evidence.proof_regeneration_report.run_id != run_contract.run_id
        || evidence.manifest.run_id != run_contract.run_id
    {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_evidence_run_mismatch",
            "runtime orchestration evidence run ids do not match the run contract",
        ));
    }
    if !evidence.workflow_run_report.accepted {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            evidence
                .workflow_run_report
                .failure_code
                .clone()
                .unwrap_or_else(|| "runtime_orchestration_workflow_rejected".to_string()),
            "runtime workflow run report was rejected",
        ));
    }
    let expected_step_count = usize::try_from(run_contract.expected_step_count).map_err(|_| {
        RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_step_count_mismatch",
            "runtime run contract step count does not fit this platform",
        )
    })?;
    if evidence.workflow_run_report.step_evidence.len() != expected_step_count {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_step_count_mismatch",
            "runtime workflow step evidence count does not match the run contract",
        ));
    }
    let actual_admission_ids: Vec<&str> = evidence
        .workflow_run_report
        .step_evidence
        .iter()
        .map(|step| step.admission_id.as_str())
        .collect();
    let expected_admission_ids: Vec<&str> = run_contract
        .admission_ids
        .iter()
        .map(String::as_str)
        .collect();
    if actual_admission_ids != expected_admission_ids {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_evidence_admission_mismatch",
            "runtime workflow admission ids do not match the run contract",
        ));
    }
    if !runtime_proof_source_records_match_steps(
        &evidence.workflow_run_report.step_evidence,
        &evidence.proof_regeneration_report.source_records,
    ) {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_source_records_mismatch",
            "runtime proof source records do not bind the workflow steps",
        ));
    }
    validate_runtime_orchestration_evidence_integrity(evidence)?;
    if run_contract.proof_regeneration_required
        && evidence
            .proof_regeneration_report
            .proof_package_sha256
            .is_none()
    {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_proof_package_missing",
            "runtime run contract requires a proof package",
        ));
    }
    Ok(())
}

pub fn validate_runtime_orchestration_evidence_integrity(
    evidence: &RuntimeOrchestrationEvidence,
) -> Result<(), RuntimeOrchestrationEvidenceFailure> {
    if evidence.workflow_run_report.run_id != evidence.proof_regeneration_report.run_id
        || evidence.workflow_run_report.run_id != evidence.manifest.run_id
    {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_evidence_run_mismatch",
            "runtime orchestration evidence artifacts disagree on run id",
        ));
    }
    if evidence.manifest.workflow_run_report_sha256 != evidence.workflow_report_sha256
        || evidence.manifest.proof_regeneration_report_sha256 != evidence.proof_report_sha256
        || evidence
            .workflow_run_report
            .proof_regeneration_report_sha256
            .as_deref()
            != Some(evidence.proof_report_sha256.as_str())
    {
        return Err(RuntimeOrchestrationEvidenceFailure::new(
            "runtime_orchestration_evidence_hash_mismatch",
            "runtime orchestration manifest and workflow report hashes do not match",
        ));
    }
    if let Some(expected_verifier_report_sha256) = evidence
        .proof_regeneration_report
        .verifier_report_sha256
        .as_deref()
    {
        let Some(actual_verifier_report_sha256) = evidence.verifier_report_sha256.as_deref() else {
            return Err(RuntimeOrchestrationEvidenceFailure::new(
                "runtime_orchestration_evidence_hash_mismatch",
                "runtime proof report binds a verifier report that is missing",
            ));
        };
        if expected_verifier_report_sha256 != actual_verifier_report_sha256 {
            return Err(RuntimeOrchestrationEvidenceFailure::new(
                "runtime_orchestration_evidence_hash_mismatch",
                "runtime proof report does not bind the verifier report hash",
            ));
        }
    }
    if evidence
        .proof_regeneration_report
        .proof_package_sha256
        .is_some()
    {
        let Some(expected_proof_package_sha256) = evidence
            .proof_regeneration_report
            .proof_package_sha256
            .as_deref()
        else {
            return Err(proof_package_missing_failure());
        };
        let Some(manifest_proof_package_sha256) = evidence.proof_package_manifest_sha256.as_deref()
        else {
            return Err(proof_package_missing_failure());
        };
        let Some(actual_proof_package_sha256) = evidence.proof_package_file_sha256.as_deref()
        else {
            return Err(proof_package_missing_failure());
        };
        let Some(canonical_proof_package_sha256) =
            evidence.proof_package_canonical_sha256.as_deref()
        else {
            return Err(proof_package_missing_failure());
        };
        if manifest_proof_package_sha256 != actual_proof_package_sha256
            || canonical_proof_package_sha256 != expected_proof_package_sha256
        {
            return Err(RuntimeOrchestrationEvidenceFailure::new(
                "runtime_orchestration_evidence_hash_mismatch",
                "runtime proof package hashes do not match manifest and proof bindings",
            ));
        }
        if let Some(verifier_report_package_sha256) =
            evidence.verifier_report_package_sha256.as_deref()
        {
            if verifier_report_package_sha256 != expected_proof_package_sha256 {
                return Err(RuntimeOrchestrationEvidenceFailure::new(
                    "runtime_orchestration_evidence_hash_mismatch",
                    "runtime proof package hash does not match verifier binding",
                ));
            }
        } else if evidence
            .proof_regeneration_report
            .verifier_report_sha256
            .is_some()
        {
            return Err(proof_package_missing_failure());
        }
    }
    Ok(())
}

pub fn runtime_orchestration_evidence_sink_healthy(
    profile: &RuntimeOrchestrationProfile,
    evidence_dir: &Path,
    now_unix_ms: u64,
) -> Result<bool, ChiodosRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    if !evidence_dir.is_dir() {
        return Ok(false);
    }
    let evidence = match load_runtime_orchestration_evidence(evidence_dir) {
        Ok(evidence) => evidence,
        Err(_) => return Ok(false),
    };
    if !runtime_orchestration_evidence_is_fresh(profile, &evidence, now_unix_ms) {
        return Ok(false);
    }
    if !evidence.workflow_run_report.accepted
        || !evidence.proof_regeneration_report.accepted
        || !evidence.verifier_report_accepted
    {
        return Ok(false);
    }
    Ok(validate_runtime_orchestration_evidence_integrity(&evidence).is_ok())
}

fn validate_runtime_orchestration_manifest_artifacts(
    evidence_dir: &Path,
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChiodosRuntimeError> {
    for entry in &manifest.entries {
        let hashes = load_runtime_json_artifact_hashes(evidence_dir, entry, &entry.role)?;
        if hashes.manifest_sha256 != hashes.file_sha256 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_artifact_hash_mismatch",
                detail: format!("runtime evidence manifest hash mismatch for {}", entry.path),
            });
        }
    }
    Ok(())
}

#[must_use]
pub fn runtime_orchestration_evidence_is_fresh(
    profile: &RuntimeOrchestrationProfile,
    evidence: &RuntimeOrchestrationEvidence,
    now_unix_ms: u64,
) -> bool {
    [
        evidence.workflow_run_report.generated_at_unix_ms,
        evidence.proof_regeneration_report.generated_at_unix_ms,
        evidence.manifest.generated_at_unix_ms,
    ]
    .into_iter()
    .all(|generated_at_unix_ms| {
        generated_at_unix_ms >= profile.issued_at_unix_ms
            && generated_at_unix_ms < profile.expires_at_unix_ms
            && generated_at_unix_ms <= now_unix_ms
    })
}

fn load_runtime_orchestration_role_json_artifact_hashes(
    evidence_dir: &Path,
    manifest: &RuntimeEvidenceManifest,
    role: &str,
) -> Result<Option<RuntimeJsonArtifactHashes>, ChiodosRuntimeError> {
    let mut entries = manifest
        .entries
        .iter()
        .filter(|entry| entry.role == role)
        .collect::<Vec<_>>();
    if entries.len() > 1 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_duplicate_role_artifact",
            detail: format!("runtime evidence manifest has duplicate {role} artifacts"),
        });
    }
    let Some(entry) = entries.pop() else {
        return Ok(None);
    };
    load_runtime_json_artifact_hashes(evidence_dir, entry, role).map(Some)
}

fn load_runtime_json_artifact_hashes(
    evidence_dir: &Path,
    entry: &RuntimeEvidenceManifestEntry,
    role: &str,
) -> Result<RuntimeJsonArtifactHashes, ChiodosRuntimeError> {
    validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
    let path = evidence_dir.join(&entry.path);
    let bytes = fs::read(&path).map_err(|error| {
        ChiodosRuntimeError::Io(format!(
            "failed to read Chiodos runtime {role} artifact {}: {error}",
            path.display()
        ))
    })?;
    let byte_count = u64::try_from(bytes.len()).map_err(|error| {
        ChiodosRuntimeError::Store(format!(
            "Chiodos runtime {role} artifact byte count: {error}"
        ))
    })?;
    if byte_count != entry.byte_count {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_artifact_byte_count_mismatch",
            detail: format!("runtime evidence manifest byte count mismatch for {role}"),
        });
    }
    let file_sha256 = sha256_hex(&bytes);
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        ChiodosRuntimeError::Json(format!("Chiodos runtime {role} artifact JSON: {error}"))
    })?;
    let canonical_sha256 = canonical_sha256(&value)?;
    Ok(RuntimeJsonArtifactHashes {
        manifest_sha256: entry.sha256.clone(),
        file_sha256,
        canonical_sha256,
    })
}

fn runtime_proof_source_records_match_steps(
    steps: &[RuntimeStepEvidence],
    source_records: &[RuntimeProofSourceRecord],
) -> bool {
    if steps.len() != source_records.len() {
        return false;
    }
    let mut records_by_step = std::collections::BTreeMap::new();
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

fn proof_package_missing_failure() -> RuntimeOrchestrationEvidenceFailure {
    RuntimeOrchestrationEvidenceFailure::new(
        "runtime_orchestration_proof_package_missing",
        "runtime proof package hash binding is incomplete",
    )
}

fn read_utf8_json_file(path: &Path, label: &str) -> Result<String, ChiodosRuntimeError> {
    fs::read_to_string(path).map_err(|error| {
        ChiodosRuntimeError::Io(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(
    json: &str,
    label: &str,
) -> Result<T, ChiodosRuntimeError> {
    serde_json::from_str(json)
        .map_err(|error| ChiodosRuntimeError::Json(format!("{label}: {error}")))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
