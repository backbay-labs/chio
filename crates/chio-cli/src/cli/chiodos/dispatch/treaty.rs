use crate::CliError;
use std::path::Path;
use std::path::PathBuf;
use super::{
    read_utf8_json_file,
    write_json_string,
};


pub(crate) fn cmd_chiodos_treaty_intersect(
    treaty_scope_path: &Path,
    manifest_paths: &[PathBuf],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    if manifest_paths.is_empty() {
        return Err(CliError::cli_other_error(
            "Chiodos treaty intersect requires at least one --manifest",
        ));
    }
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chiodos treaty scope")?;
    let treaty_scope = chio_chiodos_runtime::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty scope: {error}")))?;
    let mut manifests = Vec::new();
    for manifest_path in manifest_paths {
        let manifest_json =
            read_utf8_json_file(manifest_path, "Chiodos governance ladder manifest")?;
        manifests.push(
            chio_chiodos_runtime::governance_ladder_manifest_from_json(&manifest_json).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos governance ladder manifest: {error}"
                    ))
                },
            )?,
        );
    }
    let intersection =
        chio_chiodos_runtime::compute_ladder_intersection(&treaty_scope, &manifests, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos treaty intersection: {error}"))
            })?;
    let json = chio_chiodos_runtime::ladder_intersection_json(&intersection)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty intersection: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_treaty_admit(
    treaty_scope_path: &Path,
    ladder_intersection_path: &Path,
    expected_ladder_intersection_sha256: &str,
    action_class_id: &str,
    evidence: &[String],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chiodos treaty scope")?;
    let treaty_scope = chio_chiodos_runtime::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty scope: {error}")))?;
    let intersection_json =
        read_utf8_json_file(ladder_intersection_path, "Chiodos ladder intersection")?;
    let ladder_intersection =
        chio_chiodos_runtime::ladder_intersection_from_json(&intersection_json).map_err(
            |error| CliError::cli_other_error(format!("Chiodos ladder intersection: {error}")),
        )?;
    let verified_evidence = evidence
        .iter()
        .map(|item| {
            let Some((evidence_class, artifact_sha256)) = item.split_once('=') else {
                return Err(CliError::cli_other_error(
                    "Chiodos treaty evidence must use evidence_class=artifact_sha256",
                ));
            };
            Ok(chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                evidence_class: evidence_class.to_string(),
                artifact_sha256: artifact_sha256.to_string(),
                verified: true,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let admission = chio_chiodos_runtime::evaluate_cross_boundary_admission(
        chio_chiodos_runtime::CrossBoundaryAdmissionInput {
            treaty_scope: &treaty_scope,
            ladder_intersection: &ladder_intersection,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256.to_string()),
            action_class_id,
            present_evidence: verified_evidence
                .iter()
                .map(|item| item.evidence_class.clone())
                .collect(),
            verified_evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty admission: {error}")))?;
    let json = chio_chiodos_runtime::cross_boundary_admission_report_json(&admission)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty admission: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_treaty_verify_packet(
    packet_path: &Path,
    lineage_statement_path: &Path,
    continuation_path: &Path,
    admission_report_path: &Path,
    bilateral_invocation_path: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let packet_json = read_utf8_json_file(packet_path, "Chiodos buyer attestation packet")?;
    let packet = chio_chiodos_runtime::buyer_attestation_packet_from_json(&packet_json).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer attestation packet: {error}")),
    )?;
    let lineage_json =
        read_utf8_json_file(lineage_statement_path, "Chiodos receipt lineage statement")?;
    let lineage =
        chio_chiodos_runtime::receipt_lineage_statement_from_json(&lineage_json).map_err(
            |error| {
                CliError::cli_other_error(format!("Chiodos receipt lineage statement: {error}"))
            },
        )?;
    let continuation_json =
        read_utf8_json_file(continuation_path, "Chiodos cross-kernel continuation")?;
    let continuation: chio_chiodos_runtime::CrossKernelContinuation =
        serde_json::from_str(&continuation_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos cross-kernel continuation: {error}"))
        })?;
    let admission_json =
        read_utf8_json_file(admission_report_path, "Chiodos cross-boundary admission report")?;
    let admission: chio_chiodos_runtime::CrossBoundaryAdmissionReport =
        serde_json::from_str(&admission_json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos cross-boundary admission report: {error}"
            ))
        })?;
    let bilateral_json =
        read_utf8_json_file(bilateral_invocation_path, "Chiodos bilateral invocation")?;
    let bilateral: chio_chiodos_runtime::BilateralInvocation =
        serde_json::from_str(&bilateral_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos bilateral invocation: {error}"))
        })?;
    let verification = chio_chiodos_runtime::verify_buyer_attestation_packet(
        &packet,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos buyer attestation verification: {error}"))
    })?;
    let json = chio_chiodos_runtime::buyer_attestation_verification_report_json(&verification)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer attestation verification: {error}"))
        })?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) const BUYER_REVIEW_ARTIFACT_FILES: &[(&str, &str)] = &[
    ("buyer_attestation_packet", "buyer-attestation-packet.json"),
    ("receipt_lineage_statement", "receipt-lineage-statement.json"),
    ("receipt_lineage_bundle", "receipt-lineage-bundle.json"),
    ("cross_kernel_continuation", "cross-kernel-continuation.json"),
    (
        "cross_boundary_admission_report",
        "cross-boundary-admission-report.json",
    ),
    ("bilateral_invocation", "bilateral-invocation.json"),
    ("bilateral_dsse_envelope", "bilateral-dsse-envelope.json"),
    ("workflow_receipt", "workflow-receipt.json"),
    ("proof_package", "proof-package.json"),
    ("verifier_report", "verifier-report.json"),
    (
        "proof_regeneration_report",
        "proof-regeneration-report.json",
    ),
    ("runtime_run_report", "runtime-run-report.json"),
    (
        "runtime_evidence_manifest",
        "runtime-evidence-manifest.json",
    ),
    (
        "proof_regeneration_input",
        "runtime-proof-regeneration-input.json",
    ),
];

