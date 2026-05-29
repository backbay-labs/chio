use super::{read_utf8_json_file, write_json_string};
use crate::CliError;
use std::path::Path;
use std::path::PathBuf;

pub(crate) fn cmd_chio_federation_treaty_intersect(
    treaty_scope_path: &Path,
    manifest_paths: &[PathBuf],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    if manifest_paths.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio federation treaty intersect requires at least one --manifest",
        ));
    }
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chio treaty scope")?;
    let treaty_scope = chio_federation::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chio treaty scope: {error}")))?;
    let mut manifests = Vec::new();
    for manifest_path in manifest_paths {
        let manifest_json = read_utf8_json_file(manifest_path, "Chio governance ladder manifest")?;
        manifests.push(
            chio_federation::governance_ladder_manifest_from_json(&manifest_json).map_err(
                |error| {
                    CliError::cli_other_error(format!("Chio governance ladder manifest: {error}"))
                },
            )?,
        );
    }
    let intersection =
        chio_federation::compute_ladder_intersection(&treaty_scope, &manifests, now_unix_ms)
            .map_err(|error| {
            CliError::cli_other_error(format!("Chio treaty intersection: {error}"))
        })?;
    let json = chio_federation::ladder_intersection_json(&intersection).map_err(|error| {
        CliError::cli_other_error(format!("Chio treaty intersection: {error}"))
    })?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chio_federation_treaty_admit(
    treaty_scope_path: &Path,
    ladder_intersection_path: &Path,
    expected_ladder_intersection_sha256: &str,
    action_class_id: &str,
    evidence: &[String],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chio treaty scope")?;
    let treaty_scope = chio_federation::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chio treaty scope: {error}")))?;
    let intersection_json =
        read_utf8_json_file(ladder_intersection_path, "Chio ladder intersection")?;
    let ladder_intersection = chio_federation::ladder_intersection_from_json(&intersection_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio ladder intersection: {error}"))
        })?;
    let verified_evidence = evidence
        .iter()
        .map(|item| {
            let Some((evidence_class, artifact_sha256)) = item.split_once('=') else {
                return Err(CliError::cli_other_error(
                    "Chio treaty evidence must use evidence_class=artifact_sha256",
                ));
            };
            Ok(chio_federation::CrossBoundaryEvidenceRef {
                evidence_class: evidence_class.to_string(),
                artifact_sha256: artifact_sha256.to_string(),
                verified: true,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let admission = chio_federation::evaluate_cross_boundary_admission(
        chio_federation::CrossBoundaryAdmissionInput {
            treaty_scope: &treaty_scope,
            ladder_intersection: &ladder_intersection,
            expected_ladder_intersection_sha256: Some(
                expected_ladder_intersection_sha256.to_string(),
            ),
            action_class_id,
            present_evidence: verified_evidence
                .iter()
                .map(|item| item.evidence_class.clone())
                .collect(),
            verified_evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio treaty admission: {error}")))?;
    let json = chio_federation::cross_boundary_admission_report_json(&admission)
        .map_err(|error| CliError::cli_other_error(format!("Chio treaty admission: {error}")))?;
    write_json_string(report, &format!("{json}\n"))?;
    if admission.accepted {
        return Ok(());
    }
    Err(CliError::policy_error(format!(
        "Chio treaty admission rejected request: {}",
        admission
            .failure_code
            .as_deref()
            .unwrap_or("unknown_treaty_admission_failure")
    )))
}

pub(crate) fn cmd_chio_federation_treaty_verify_packet(
    packet_path: &Path,
    lineage_statement_path: &Path,
    continuation_path: &Path,
    admission_report_path: &Path,
    bilateral_invocation_path: &Path,
    report: &Path,
) -> Result<(), CliError> {
    cmd_chio_attest_buyer_verify_packet(
        packet_path,
        lineage_statement_path,
        continuation_path,
        admission_report_path,
        bilateral_invocation_path,
        report,
    )
}

pub(crate) fn cmd_chio_attest_buyer_verify_packet(
    packet_path: &Path,
    lineage_statement_path: &Path,
    continuation_path: &Path,
    admission_report_path: &Path,
    bilateral_invocation_path: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let packet_json = read_utf8_json_file(packet_path, "Chio buyer attestation packet")?;
    let packet = chio_attest_buyer::buyer_attestation_packet_from_json(&packet_json).map_err(
        |error| CliError::cli_other_error(format!("Chio buyer attestation packet: {error}")),
    )?;
    let lineage_json =
        read_utf8_json_file(lineage_statement_path, "Chio receipt lineage statement")?;
    let lineage: chio_attest_buyer::ReceiptLineageStatement =
        serde_json::from_str(&lineage_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio receipt lineage statement: {error}"))
        })?;
    let continuation_json =
        read_utf8_json_file(continuation_path, "Chio cross-kernel continuation")?;
    let continuation: chio_attest_buyer::CrossKernelContinuation =
        serde_json::from_str(&continuation_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio cross-kernel continuation: {error}"))
        })?;
    let admission_json = read_utf8_json_file(
        admission_report_path,
        "Chio cross-boundary admission report",
    )?;
    let admission: chio_attest_buyer::CrossBoundaryAdmissionReport =
        serde_json::from_str(&admission_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio cross-boundary admission report: {error}"))
        })?;
    let bilateral_json =
        read_utf8_json_file(bilateral_invocation_path, "Chio bilateral invocation")?;
    let bilateral: chio_attest_buyer::BilateralInvocation =
        serde_json::from_str(&bilateral_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio bilateral invocation: {error}"))
        })?;
    let verification = chio_attest_buyer::verify_buyer_attestation_packet(
        &packet,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio buyer attestation verification: {error}"))
    })?;
    let json = chio_attest_buyer::buyer_attestation_verification_report_json(&verification)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio buyer attestation verification: {error}"))
        })?;
    write_json_string(report, &format!("{json}\n"))?;
    if verification.accepted {
        return Ok(());
    }
    Err(CliError::cli_other_error(format!(
        "Chio buyer attestation verification rejected proof package: {}",
        verification
            .failure_code
            .as_deref()
            .unwrap_or("unknown_buyer_attestation_failure")
    )))
}

pub(crate) const BUYER_REVIEW_ARTIFACT_FILES: &[(&str, &str)] = &[
    ("buyer_attestation_packet", "buyer-attestation-packet.json"),
    (
        "receipt_lineage_statement",
        "receipt-lineage-statement.json",
    ),
    ("receipt_lineage_bundle", "receipt-lineage-bundle.json"),
    (
        "cross_kernel_continuation",
        "cross-kernel-continuation.json",
    ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_federation::{
        governance_ladder_manifest_sha256, ladder_intersection_sha256,
        GovernanceLadderActionClass, GovernanceLadderManifest, TreatyScope,
        CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
        CHIO_FEDERATION_TREATY_SCOPE_SCHEMA,
    };
    use std::io;

    #[test]
    fn treaty_admit_returns_error_when_report_denies() -> Result<(), Box<dyn std::error::Error>> {
        let manifest_a = treaty_manifest("kernel.buyer");
        let manifest_b = treaty_manifest("kernel.vendor");
        let scope = treaty_scope(&manifest_a, &manifest_b)?;
        let intersection = chio_federation::compute_ladder_intersection(
            &scope,
            &[manifest_a.clone(), manifest_b.clone()],
            1_800_000_001_000,
        )?;
        let expected_ladder_intersection_sha256 = ladder_intersection_sha256(&intersection)?;
        let tempdir = tempfile::tempdir()?;
        let scope_path = tempdir.path().join("treaty-scope.json");
        let intersection_path = tempdir.path().join("intersection.json");
        let report_path = tempdir.path().join("admission-report.json");
        std::fs::write(&scope_path, serde_json::to_string(&scope)?)?;
        std::fs::write(&intersection_path, serde_json::to_string(&intersection)?)?;

        let result = cmd_chio_federation_treaty_admit(
            &scope_path,
            &intersection_path,
            &expected_ladder_intersection_sha256,
            "workflow.destructive.vendor_call",
            &[],
            1_800_000_002_000,
            &report_path,
        );
        let Err(error) = result else {
            return Err(io::Error::other("denied treaty admission must return an error").into());
        };
        let error_text = error.to_string();
        assert!(
            error_text.contains("chio_federation_treaty_missing_required_evidence"),
            "error should include denial reason: {error_text}"
        );
        let report_json = std::fs::read_to_string(&report_path)?;
        let report: chio_federation::CrossBoundaryAdmissionReport =
            serde_json::from_str(&report_json)?;
        assert!(!report.accepted);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("chio_federation_treaty_missing_required_evidence")
        );

        Ok(())
    }

    fn treaty_manifest(kernel_id: &str) -> GovernanceLadderManifest {
        GovernanceLadderManifest {
            schema: CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
            manifest_id: format!("ladder-{kernel_id}"),
            kernel_id: kernel_id.to_string(),
            issuer: format!("did:chio:{kernel_id}"),
            key_id: "ladder-key-1".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
            destructive_floor: "receipt_backed".to_string(),
            default_unknown_mode: "deny".to_string(),
            action_classes: vec![GovernanceLadderActionClass {
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                mode: "receipt_backed".to_string(),
                destructive: false,
                consistency_model: "totally_ordered".to_string(),
                co_sign: "bilateral_required".to_string(),
                evidence_required: vec!["receipt_lineage".to_string()],
                aliases: Vec::new(),
            }],
        }
    }

    fn treaty_scope(
        manifest_a: &GovernanceLadderManifest,
        manifest_b: &GovernanceLadderManifest,
    ) -> Result<TreatyScope, Box<dyn std::error::Error>> {
        let buyer_key = Keypair::generate();
        let vendor_key = Keypair::generate();
        Ok(TreatyScope {
            schema: CHIO_FEDERATION_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: "treaty-buyer-vendor".to_string(),
            participant_kernel_ids: vec![manifest_a.kernel_id.clone(), manifest_b.kernel_id.clone()],
            participant_public_keys: vec![buyer_key.public_key(), vendor_key.public_key()],
            ladder_manifest_sha256s: vec![
                governance_ladder_manifest_sha256(manifest_a)?,
                governance_ladder_manifest_sha256(manifest_b)?,
            ],
            allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
            revocation_epoch_sha256: "c".repeat(64),
            trust_bundle_sha256: "b".repeat(64),
        })
    }
}
