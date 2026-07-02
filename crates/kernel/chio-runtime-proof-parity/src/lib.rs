#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA: &str = "chio.runtime.evidence-manifest.v1";
pub const CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA: &str = "chio.runtime.proof-parity-report.v1";
pub const CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA: &str =
    "chio.runtime.proof-regeneration-input.v1";
pub const CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA: &str =
    "chio.runtime.proof-regeneration-report.v1";
pub const CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA: &str = "chio.runtime.workflow-run-report.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofParityMismatch {
    pub field: String,
    pub static_value_sha256: String,
    pub runtime_value_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofParityReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub static_proof_package_sha256: String,
    pub runtime_proof_package_sha256: String,
    pub static_verifier_report_sha256: String,
    pub runtime_verifier_report_sha256: String,
    pub compared_fields: Vec<String>,
    pub mismatches: Vec<RuntimeProofParityMismatch>,
}

pub struct RuntimeProofRegenerationArtifacts<'a> {
    pub proof_regeneration_report: &'a [u8],
    pub proof_regeneration_input: &'a [u8],
    pub evidence_manifest: &'a [u8],
    pub workflow_run_report: &'a [u8],
    pub proof_package: &'a [u8],
    pub verifier_report: &'a [u8],
    pub workflow_receipt: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeProofParityError {
    #[error("{code}: {detail}")]
    Rejected { code: &'static str, detail: String },
}

impl RuntimeProofParityError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RuntimeProofParityError::Rejected { code, .. } => code,
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            RuntimeProofParityError::Rejected { detail, .. } => detail,
        }
    }
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), RuntimeProofParityError> {
    if report.schema != CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return rejected(
            "unsupported_runtime_proof_parity_report_schema",
            format!(
                "runtime proof parity report declared unsupported schema {}",
                report.schema
            ),
        );
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
        return rejected(
            "runtime_proof_parity_missing_compared_fields",
            "runtime proof parity report must name compared fields",
        );
    }
    if report.accepted && !report.mismatches.is_empty() {
        return rejected(
            "runtime_proof_parity_accepted_with_mismatches",
            "accepted runtime proof parity report cannot carry mismatches",
        );
    }
    if report.accepted {
        ensure_equal_hashes(
            &report.static_proof_package_sha256,
            &report.runtime_proof_package_sha256,
            "runtime_proof_parity_accepted_package_hash_drift",
            "accepted runtime proof parity report cannot carry proof package hash drift",
        )?;
        ensure_equal_hashes(
            &report.static_verifier_report_sha256,
            &report.runtime_verifier_report_sha256,
            "runtime_proof_parity_accepted_report_hash_drift",
            "accepted runtime proof parity report cannot carry verifier report hash drift",
        )?;
    }
    for mismatch in &report.mismatches {
        if mismatch.field.trim().is_empty() {
            return rejected(
                "runtime_proof_parity_empty_mismatch_field",
                "runtime proof parity mismatch field is empty",
            );
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

pub fn validate_runtime_proof_regeneration_artifacts(
    artifacts: RuntimeProofRegenerationArtifacts<'_>,
) -> Result<(), RuntimeProofParityError> {
    let proof_report = parse_json_value(
        artifacts.proof_regeneration_report,
        "runtime proof regeneration report",
    )?;
    let proof_input = parse_json_value(
        artifacts.proof_regeneration_input,
        "runtime proof regeneration input",
    )?;
    let manifest = parse_json_value(artifacts.evidence_manifest, "runtime evidence manifest")?;
    let workflow_report =
        parse_json_value(artifacts.workflow_run_report, "runtime workflow run report")?;

    require_schema(
        &proof_report,
        CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
        "unsupported_runtime_proof_regeneration_report_schema",
        "runtime proof regeneration report",
    )?;
    require_schema(
        &proof_input,
        CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
        "unsupported_runtime_proof_regeneration_input_schema",
        "runtime proof regeneration input",
    )?;
    require_schema(
        &manifest,
        CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
        "unsupported_runtime_evidence_manifest_schema",
        "runtime evidence manifest",
    )?;
    require_schema(
        &workflow_report,
        CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
        "unsupported_runtime_workflow_report_schema",
        "runtime workflow report",
    )?;
    let proof_report_run_id = required_non_empty_str(
        &proof_report,
        "runId",
        "runtime_proof_regeneration_missing_run_id",
    )?;
    let proof_input_run_id = required_non_empty_str(
        &proof_input,
        "runId",
        "runtime_proof_regeneration_missing_run_id",
    )?;
    let manifest_run_id = required_non_empty_str(
        &manifest,
        "runId",
        "runtime_proof_regeneration_missing_run_id",
    )?;
    let workflow_report_run_id = required_non_empty_str(
        &workflow_report,
        "runId",
        "runtime_proof_regeneration_missing_run_id",
    )?;
    ensure_matching_run_id(
        proof_report_run_id,
        proof_input_run_id,
        "proof regeneration input",
    )?;
    ensure_matching_run_id(
        proof_report_run_id,
        manifest_run_id,
        "runtime evidence manifest",
    )?;
    ensure_matching_run_id(
        proof_report_run_id,
        workflow_report_run_id,
        "runtime workflow report",
    )?;

    let proof_report_accepted = required_bool(
        &proof_report,
        "accepted",
        "runtime_proof_regeneration_missing_accepted",
    )?;
    let workflow_report_accepted = required_bool(
        &workflow_report,
        "accepted",
        "runtime_workflow_missing_accepted",
    )?;
    if proof_report_accepted {
        ensure_no_failure_code(
            &proof_report,
            "runtime_proof_regeneration_unexpected_failure_code",
            "accepted runtime proof regeneration report cannot carry a failure code",
        )?;
    }
    if workflow_report_accepted {
        ensure_no_failure_code(
            &workflow_report,
            "runtime_workflow_unexpected_failure_code",
            "accepted runtime workflow report cannot carry a failure code",
        )?;
    }
    if !proof_report_accepted || !workflow_report_accepted {
        return rejected(
            "runtime_proof_regeneration_evidence_not_accepted",
            "runtime proof regeneration evidence must be accepted",
        );
    }

    let proof_report_sha256 = canonical_value_sha256(&proof_report)?;
    let manifest_sha256 = canonical_value_sha256(&manifest)?;
    let workflow_report_sha256 = canonical_value_sha256(&workflow_report)?;
    let proof_package_sha256 =
        canonical_bytes_sha256(artifacts.proof_package, "runtime proof package")?;
    let verifier_report_sha256 =
        canonical_bytes_sha256(artifacts.verifier_report, "runtime verifier report")?;
    let workflow_receipt_sha256 =
        canonical_bytes_sha256(artifacts.workflow_receipt, "runtime workflow receipt")?;

    ensure_hash_field(
        &workflow_report,
        "proofRegenerationReportSha256",
        "runtime_workflow_invalid_proof_regeneration_hash",
    )?;
    ensure_hash_field(
        &manifest,
        "proofRegenerationReportSha256",
        "runtime_evidence_manifest_invalid_proof_report_hash",
    )?;
    if required_str(
        &workflow_report,
        "proofRegenerationReportSha256",
        "runtime_workflow_missing_proof_regeneration_hash",
    )? != proof_report_sha256
        || required_str(
            &manifest,
            "proofRegenerationReportSha256",
            "runtime_evidence_manifest_missing_proof_report_hash",
        )? != proof_report_sha256
    {
        return rejected(
            "runtime_proof_regeneration_report_hash_mismatch",
            "runtime proof regeneration report hash mismatch",
        );
    }

    ensure_hash_field(
        &manifest,
        "workflowRunReportSha256",
        "runtime_evidence_manifest_invalid_workflow_report_hash",
    )?;
    ensure_hash_field(
        &proof_input,
        "workflowRunReportSha256",
        "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    )?;
    if required_str(
        &manifest,
        "workflowRunReportSha256",
        "runtime_evidence_manifest_missing_workflow_hash",
    )? != workflow_report_sha256
        || required_str(
            &proof_input,
            "workflowRunReportSha256",
            "runtime_proof_regeneration_input_missing_workflow_hash",
        )? != workflow_report_sha256
    {
        return rejected(
            "runtime_proof_regeneration_workflow_hash_mismatch",
            "runtime proof regeneration workflow report hash mismatch",
        );
    }

    ensure_hash_field(
        &proof_input,
        "evidenceManifestSha256",
        "runtime_proof_regeneration_input_invalid_manifest_hash",
    )?;
    if required_str(
        &proof_input,
        "evidenceManifestSha256",
        "runtime_proof_regeneration_input_missing_manifest_hash",
    )? != manifest_sha256
    {
        return rejected(
            "runtime_proof_regeneration_manifest_hash_mismatch",
            "runtime proof regeneration evidence manifest hash mismatch",
        );
    }

    if required_array(
        &proof_input,
        "sourceRecords",
        "runtime_proof_regeneration_input_missing_source_records",
    )? != required_array(
        &proof_report,
        "sourceRecords",
        "runtime_proof_regeneration_missing_source_records",
    )? {
        return rejected(
            "runtime_proof_regeneration_source_record_mismatch",
            "runtime proof regeneration source records mismatch",
        );
    }
    ensure_source_records_bind_workflow_step_evidence(&proof_report, &workflow_report)?;

    ensure_hash_field(
        &proof_report,
        "proofPackageSha256",
        "runtime_proof_regeneration_invalid_package_hash",
    )?;
    ensure_hash_field(
        &proof_report,
        "verifierReportSha256",
        "runtime_proof_regeneration_invalid_verifier_report_hash",
    )?;
    ensure_hash_field(
        &proof_report,
        "workflowReceiptSha256",
        "runtime_proof_regeneration_invalid_workflow_receipt_hash",
    )?;
    if required_str(
        &proof_report,
        "proofPackageSha256",
        "runtime_proof_regeneration_missing_package_hash",
    )? != proof_package_sha256
    {
        return rejected(
            "runtime_proof_regeneration_package_hash_mismatch",
            "runtime proof regeneration proof package hash mismatch",
        );
    }
    if required_str(
        &proof_report,
        "verifierReportSha256",
        "runtime_proof_regeneration_missing_verifier_hash",
    )? != verifier_report_sha256
    {
        return rejected(
            "runtime_proof_regeneration_verifier_hash_mismatch",
            "runtime proof regeneration verifier report hash mismatch",
        );
    }
    if required_str(
        &proof_report,
        "workflowReceiptSha256",
        "runtime_proof_regeneration_missing_workflow_receipt_hash",
    )? != workflow_receipt_sha256
    {
        return rejected(
            "runtime_proof_regeneration_workflow_receipt_hash_mismatch",
            "runtime proof regeneration workflow receipt hash mismatch",
        );
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

fn ensure_source_records_bind_workflow_step_evidence(
    proof_report: &Value,
    workflow_report: &Value,
) -> Result<(), RuntimeProofParityError> {
    let source_records = required_array(
        proof_report,
        "sourceRecords",
        "runtime_proof_regeneration_missing_source_records",
    )?;
    let workflow_steps = required_array(
        workflow_report,
        "stepEvidence",
        "runtime_proof_regeneration_workflow_steps_missing",
    )?;
    for source_record in source_records {
        let step_index = required_u64(
            source_record,
            "stepIndex",
            "runtime_proof_regeneration_source_record_step_missing",
        )?;
        let Some(workflow_step) = workflow_steps
            .iter()
            .find(|step| step.get("stepIndex").and_then(Value::as_u64) == Some(step_index))
        else {
            return rejected(
                "runtime_proof_regeneration_workflow_step_evidence_mismatch",
                format!("runtime proof regeneration source record step {step_index} is not bound"),
            );
        };
        for field in [
            "admissionReportSha256",
            "toolReceiptSha256",
            "bilateralDsseSha256",
            "workflowStepSha256",
        ] {
            // Fail closed: a source record (or workflow step) that omits or
            // blanks a binding hash must be denied, not skipped. This matches
            // the strict proof-room re-implementation
            // (source_runtime_required_str), which denies missing/empty fields.
            let source_value = required_non_empty_str(
                source_record,
                field,
                "runtime_proof_regeneration_source_record_hash_missing",
            )?;
            let workflow_value = required_non_empty_str(
                workflow_step,
                field,
                "runtime_proof_regeneration_workflow_step_hash_missing",
            )?;
            if source_value != workflow_value {
                return rejected(
                    "runtime_proof_regeneration_workflow_step_evidence_mismatch",
                    format!(
                        "runtime proof regeneration source record step {step_index} field {field} is not bound"
                    ),
                );
            }
        }
    }
    Ok(())
}

fn parse_json_value(bytes: &[u8], label: &str) -> Result<Value, RuntimeProofParityError> {
    serde_json::from_slice(bytes).map_err(|error| RuntimeProofParityError::Rejected {
        code: "runtime_proof_regeneration_invalid_json",
        detail: format!("{label}: {error}"),
    })
}

fn require_schema(
    value: &Value,
    expected: &str,
    code: &'static str,
    label: &str,
) -> Result<(), RuntimeProofParityError> {
    let schema = required_str(value, "schema", code)?;
    if schema == expected {
        return Ok(());
    }
    rejected(
        code,
        format!("{label} declared unsupported schema {schema}"),
    )
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
    code: &'static str,
) -> Result<&'a str, RuntimeProofParityError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RuntimeProofParityError::Rejected {
            code,
            detail: format!("runtime proof regeneration missing string field {field}"),
        })
}

fn required_non_empty_str<'a>(
    value: &'a Value,
    field: &str,
    code: &'static str,
) -> Result<&'a str, RuntimeProofParityError> {
    let string = required_str(value, field, code)?;
    if string.trim().is_empty() {
        return rejected(
            code,
            format!("runtime proof regeneration string field {field} is empty"),
        );
    }
    Ok(string)
}

fn ensure_matching_run_id(
    expected: &str,
    actual: &str,
    label: &str,
) -> Result<(), RuntimeProofParityError> {
    if expected == actual {
        return Ok(());
    }
    rejected(
        "runtime_proof_regeneration_run_id_mismatch",
        format!("runtime proof regeneration runId mismatch for {label}"),
    )
}

fn ensure_no_failure_code(
    value: &Value,
    code: &'static str,
    detail: &'static str,
) -> Result<(), RuntimeProofParityError> {
    if value.get("failureCode").is_some() {
        return rejected(code, detail);
    }
    Ok(())
}

fn required_bool(
    value: &Value,
    field: &str,
    code: &'static str,
) -> Result<bool, RuntimeProofParityError> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| RuntimeProofParityError::Rejected {
            code,
            detail: format!("runtime proof regeneration missing boolean field {field}"),
        })
}

fn required_u64(
    value: &Value,
    field: &str,
    code: &'static str,
) -> Result<u64, RuntimeProofParityError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| RuntimeProofParityError::Rejected {
            code,
            detail: format!("runtime proof regeneration missing integer field {field}"),
        })
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
    code: &'static str,
) -> Result<&'a Vec<Value>, RuntimeProofParityError> {
    let array = value.get(field).and_then(Value::as_array).ok_or_else(|| {
        RuntimeProofParityError::Rejected {
            code,
            detail: format!("runtime proof regeneration missing array field {field}"),
        }
    })?;
    if array.is_empty() {
        return rejected(
            code,
            format!("runtime proof regeneration array field {field} is empty"),
        );
    }
    Ok(array)
}

fn ensure_hash_field(
    value: &Value,
    field: &str,
    code: &'static str,
) -> Result<(), RuntimeProofParityError> {
    let hash = required_str(value, field, code)?;
    ensure_sha256_hash(hash, code)
}

fn canonical_bytes_sha256(bytes: &[u8], label: &str) -> Result<String, RuntimeProofParityError> {
    let value = parse_json_value(bytes, label)?;
    canonical_value_sha256(&value)
}

fn canonical_value_sha256(value: &Value) -> Result<String, RuntimeProofParityError> {
    let bytes = chio_core_types::crypto::canonical_json_bytes(value).map_err(|error| {
        RuntimeProofParityError::Rejected {
            code: "runtime_proof_regeneration_canonical_json_failed",
            detail: error.to_string(),
        }
    })?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

fn validate_manifest_entry(
    manifest: &Value,
    role: &str,
    bytes: &[u8],
) -> Result<(), RuntimeProofParityError> {
    let entries = required_array(
        manifest,
        "entries",
        "runtime_evidence_manifest_missing_entries",
    )?;
    let entry = entries
        .iter()
        .find(|entry| entry.get("role").and_then(Value::as_str) == Some(role))
        .ok_or_else(|| RuntimeProofParityError::Rejected {
            code: "runtime_proof_regeneration_manifest_entry_missing",
            detail: format!("runtime proof regeneration evidence manifest missing {role}"),
        })?;
    let expected_sha256 = chio_core_types::crypto::sha256_hex(bytes);
    let expected_byte_count =
        u64::try_from(bytes.len()).map_err(|error| RuntimeProofParityError::Rejected {
            code: "runtime_proof_regeneration_artifact_too_large",
            detail: format!("runtime proof regeneration artifact byte count failed: {error}"),
        })?;
    if required_str(
        entry,
        "sha256",
        "runtime_evidence_manifest_invalid_artifact_hash",
    )? != expected_sha256
        || entry.get("byteCount").and_then(Value::as_u64) != Some(expected_byte_count)
    {
        return rejected(
            "runtime_proof_regeneration_manifest_artifact_mismatch",
            format!("runtime proof regeneration evidence manifest artifact mismatch for {role}"),
        );
    }
    Ok(())
}

fn validate_acceptance_failure_code(
    accepted: bool,
    failure_code: Option<&str>,
    missing_code: &'static str,
    unexpected_code: &'static str,
) -> Result<(), RuntimeProofParityError> {
    if accepted && failure_code.is_some() {
        return rejected(
            unexpected_code,
            "accepted runtime report cannot carry a failure code",
        );
    }
    if !accepted && failure_code.is_none() {
        return rejected(
            missing_code,
            "rejected runtime report must carry a failure code",
        );
    }
    Ok(())
}

fn ensure_sha256_hash(hash: &str, code: &'static str) -> Result<(), RuntimeProofParityError> {
    if hash.len() == 64
        && hash
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Ok(());
    }
    rejected(
        code,
        format!("runtime evidence hash {hash} is not sha256 hex"),
    )
}

fn ensure_equal_hashes(
    static_hash: &str,
    runtime_hash: &str,
    code: &'static str,
    detail: &'static str,
) -> Result<(), RuntimeProofParityError> {
    if static_hash == runtime_hash {
        return Ok(());
    }
    rejected(code, detail)
}

fn rejected<T>(
    code: &'static str,
    detail: impl Into<String>,
) -> Result<T, RuntimeProofParityError> {
    Err(RuntimeProofParityError::Rejected {
        code,
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_uppercase_sha256_digest() {
        let mut report = valid_report();
        report.static_proof_package_sha256 = "A".repeat(64);

        let error = match validate_runtime_proof_parity_report(&report) {
            Ok(()) => panic!("uppercase sha256 digest unexpectedly verified"),
            Err(error) => error,
        };

        assert_eq!(
            error.code(),
            "runtime_proof_parity_invalid_static_package_hash"
        );
    }

    #[test]
    fn rejects_accepted_package_hash_drift() {
        let mut report = valid_report();
        report.runtime_proof_package_sha256 = "c".repeat(64);

        let error = match validate_runtime_proof_parity_report(&report) {
            Ok(()) => panic!("accepted package hash drift unexpectedly verified"),
            Err(error) => error,
        };

        assert_eq!(
            error.code(),
            "runtime_proof_parity_accepted_package_hash_drift"
        );
    }

    #[test]
    fn accepts_valid_runtime_proof_regeneration_artifacts() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions::default());

        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => {}
            Err(error) => panic!("valid runtime proof regeneration artifacts failed: {error}"),
        }
    }

    #[test]
    fn rejects_workflow_step_evidence_source_record_mismatch() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
            workflow_step_record_index: Some(1),
            ..RegenerationArtifactOptions::default()
        });

        let error =
            match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
                Ok(()) => panic!("workflow step evidence source record mismatch verified"),
                Err(error) => error,
            };

        assert_eq!(
            error.code(),
            "runtime_proof_regeneration_workflow_step_evidence_mismatch"
        );
    }

    #[test]
    fn rejects_source_record_missing_binding_hash_field() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
            omit_source_record_hash_field: Some("toolReceiptSha256"),
            ..RegenerationArtifactOptions::default()
        });

        let error =
            match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
                Ok(()) => {
                    panic!("source record missing a binding hash field unexpectedly verified")
                }
                Err(error) => error,
            };

        // The shared crate must DENY a missing/empty binding hash rather than
        // silently skip it (fail closed), matching the strict proof-room path.
        assert_eq!(
            error.code(),
            "runtime_proof_regeneration_source_record_hash_missing"
        );
    }

    #[test]
    fn rejects_accepted_regeneration_report_failure_code() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
            proof_report_failure_code: Some("runtime_regeneration_failed"),
            ..RegenerationArtifactOptions::default()
        });

        let error =
            match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
                Ok(()) => {
                    panic!("accepted regeneration report with failure code unexpectedly verified")
                }
                Err(error) => error,
            };

        assert_eq!(
            error.code(),
            "runtime_proof_regeneration_unexpected_failure_code"
        );
    }

    #[test]
    fn rejects_accepted_workflow_report_failure_code() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
            workflow_report_failure_code: Some("runtime_workflow_failed"),
            ..RegenerationArtifactOptions::default()
        });

        let error =
            match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
                Ok(()) => {
                    panic!("accepted workflow report with failure code unexpectedly verified")
                }
                Err(error) => error,
            };

        assert_eq!(error.code(), "runtime_workflow_unexpected_failure_code");
    }

    #[test]
    fn rejects_regeneration_artifacts_with_mismatched_run_id() {
        let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
            proof_input_run_id: "runtime-loopback-other",
            ..RegenerationArtifactOptions::default()
        });

        let error =
            match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
                Ok(()) => panic!("mismatched regeneration run ids unexpectedly verified"),
                Err(error) => error,
            };

        assert_eq!(error.code(), "runtime_proof_regeneration_run_id_mismatch");
    }

    fn valid_report() -> RuntimeProofParityReport {
        RuntimeProofParityReport {
            schema: CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
            run_id: "runtime-proof-parity-valid".to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms: 1_800_000_000_000,
            static_proof_package_sha256: "a".repeat(64),
            runtime_proof_package_sha256: "a".repeat(64),
            static_verifier_report_sha256: "b".repeat(64),
            runtime_verifier_report_sha256: "b".repeat(64),
            compared_fields: vec!["verified_claims".to_string()],
            mismatches: Vec::new(),
        }
    }

    #[derive(Clone, Copy)]
    struct RegenerationArtifactOptions<'a> {
        proof_report_run_id: &'a str,
        proof_input_run_id: &'a str,
        manifest_run_id: &'a str,
        workflow_report_run_id: &'a str,
        proof_report_failure_code: Option<&'a str>,
        workflow_report_failure_code: Option<&'a str>,
        workflow_step_record_index: Option<u64>,
        omit_source_record_hash_field: Option<&'a str>,
    }

    impl Default for RegenerationArtifactOptions<'_> {
        fn default() -> Self {
            Self {
                proof_report_run_id: "runtime-loopback-1",
                proof_input_run_id: "runtime-loopback-1",
                manifest_run_id: "runtime-loopback-1",
                workflow_report_run_id: "runtime-loopback-1",
                proof_report_failure_code: None,
                workflow_report_failure_code: None,
                workflow_step_record_index: Some(0),
                omit_source_record_hash_field: None,
            }
        }
    }

    struct TestRegenerationArtifacts {
        proof_regeneration_report: Vec<u8>,
        proof_regeneration_input: Vec<u8>,
        evidence_manifest: Vec<u8>,
        workflow_run_report: Vec<u8>,
        proof_package: Vec<u8>,
        verifier_report: Vec<u8>,
        workflow_receipt: Vec<u8>,
    }

    impl TestRegenerationArtifacts {
        fn as_runtime_artifacts(&self) -> RuntimeProofRegenerationArtifacts<'_> {
            RuntimeProofRegenerationArtifacts {
                proof_regeneration_report: &self.proof_regeneration_report,
                proof_regeneration_input: &self.proof_regeneration_input,
                evidence_manifest: &self.evidence_manifest,
                workflow_run_report: &self.workflow_run_report,
                proof_package: &self.proof_package,
                verifier_report: &self.verifier_report,
                workflow_receipt: &self.workflow_receipt,
            }
        }
    }

    fn runtime_regeneration_artifacts(
        options: RegenerationArtifactOptions<'_>,
    ) -> TestRegenerationArtifacts {
        let proof_package = serde_json::json!({
            "schema": "test.runtime-proof-package.v1",
            "id": "runtime-proof-package-1"
        });
        let verifier_report = serde_json::json!({
            "schema": "test.runtime-verifier-report.v1",
            "verdict": "verified"
        });
        let workflow_receipt = serde_json::json!({
            "schema": "test.runtime-workflow-receipt.v1",
            "receiptId": "runtime-workflow-receipt-1"
        });
        let proof_package_bytes = json_bytes(&proof_package);
        let verifier_report_bytes = json_bytes(&verifier_report);
        let workflow_receipt_bytes = json_bytes(&workflow_receipt);
        let proof_package_sha256 = test_canonical_value_sha256(&proof_package);
        let verifier_report_sha256 = test_canonical_value_sha256(&verifier_report);
        let workflow_receipt_sha256 = test_canonical_value_sha256(&workflow_receipt);
        let mut source_record = serde_json::json!({
            "stepIndex": 0,
            "admissionReportSha256": "1".repeat(64),
            "toolReceiptSha256": "2".repeat(64),
            "bilateralDsseSha256": "3".repeat(64),
            "workflowStepSha256": "4".repeat(64)
        });
        if let Some(field) = options.omit_source_record_hash_field {
            if let Some(object) = source_record.as_object_mut() {
                object.remove(field);
            }
        }
        let mut proof_report = serde_json::json!({
            "schema": CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
            "runId": options.proof_report_run_id,
            "accepted": true,
            "proofPackageSha256": proof_package_sha256,
            "verifierReportSha256": verifier_report_sha256,
            "workflowReceiptSha256": workflow_receipt_sha256,
            "sourceRecords": [source_record.clone()]
        });
        if let Some(failure_code) = options.proof_report_failure_code {
            proof_report["failureCode"] = Value::String(failure_code.to_string());
        }
        let proof_report_bytes = json_bytes(&proof_report);
        let proof_report_sha256 = test_canonical_value_sha256(&proof_report);
        let mut workflow_report = serde_json::json!({
            "schema": CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
            "runId": options.workflow_report_run_id,
            "accepted": true,
            "proofRegenerationReportSha256": proof_report_sha256
        });
        if let Some(step_index) = options.workflow_step_record_index {
            workflow_report["stepEvidence"] = serde_json::json!([{
                "stepIndex": step_index,
                "admissionReportSha256": "1".repeat(64),
                "toolReceiptSha256": "2".repeat(64),
                "bilateralDsseSha256": "3".repeat(64),
                "workflowStepSha256": "4".repeat(64)
            }]);
        }
        if let Some(failure_code) = options.workflow_report_failure_code {
            workflow_report["failureCode"] = Value::String(failure_code.to_string());
        }
        let workflow_report_bytes = json_bytes(&workflow_report);
        let workflow_report_sha256 = test_canonical_value_sha256(&workflow_report);
        let manifest = serde_json::json!({
            "schema": CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
            "runId": options.manifest_run_id,
            "workflowRunReportSha256": workflow_report_sha256,
            "proofRegenerationReportSha256": proof_report_sha256,
            "entries": [
                manifest_entry("proof_package", "runtime-proof-package.json", &proof_package_bytes),
                manifest_entry("verifier_report", "runtime-verifier-report.json", &verifier_report_bytes),
                manifest_entry("workflow_receipt", "runtime-workflow-receipt.json", &workflow_receipt_bytes),
                manifest_entry("proof_regeneration_report", "proof-regeneration-report.json", &proof_report_bytes),
                manifest_entry("runtime_run_report", "runtime-workflow-run-report.json", &workflow_report_bytes)
            ]
        });
        let evidence_manifest = json_bytes(&manifest);
        let manifest_sha256 = test_canonical_value_sha256(&manifest);
        let proof_input = serde_json::json!({
            "schema": CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
            "runId": options.proof_input_run_id,
            "evidenceManifestSha256": manifest_sha256,
            "workflowRunReportSha256": workflow_report_sha256,
            "sourceRecords": [source_record]
        });

        TestRegenerationArtifacts {
            proof_regeneration_report: proof_report_bytes,
            proof_regeneration_input: json_bytes(&proof_input),
            evidence_manifest,
            workflow_run_report: workflow_report_bytes,
            proof_package: proof_package_bytes,
            verifier_report: verifier_report_bytes,
            workflow_receipt: workflow_receipt_bytes,
        }
    }

    fn manifest_entry(role: &str, path: &str, bytes: &[u8]) -> Value {
        serde_json::json!({
            "role": role,
            "path": path,
            "sha256": chio_core_types::crypto::sha256_hex(bytes),
            "byteCount": bytes.len()
        })
    }

    fn json_bytes(value: &Value) -> Vec<u8> {
        match serde_json::to_vec(value) {
            Ok(bytes) => bytes,
            Err(error) => panic!("test JSON serialization failed: {error}"),
        }
    }

    fn test_canonical_value_sha256(value: &Value) -> String {
        match canonical_value_sha256(value) {
            Ok(hash) => hash,
            Err(error) => panic!("test canonical hash failed: {error}"),
        }
    }
}
