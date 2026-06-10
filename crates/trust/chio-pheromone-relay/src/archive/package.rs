//! Relay alert assurance archive package signing, verification, and validation.

use super::*;
use crate::{
    canonical_sha256, contains_secret_marker, is_bounded_route_token, is_sha256_hex,
    validate_export_path, verify_relay_alert_assurance_export_bundle, PheromoneRelayError,
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceExportFile,
    RelayAlertAssuranceExportManifest, RelayAlertAssuranceExportReport, RelayAlertCheck,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_EXTRACTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use serde::Serialize;
use std::collections::BTreeSet;

pub fn sign_relay_alert_assurance_archive_package(
    input: RelayAlertAssuranceArchivePackageBuildInput<'_>,
) -> Result<RelayAlertAssuranceArchivePackage, PheromoneRelayError> {
    validate_archive_package_identity(input.package_id, "package id")?;
    validate_archive_package_identity(input.packager_id, "packager id")?;
    validate_archive_package_identity(input.packager_key_id, "packager key id")?;
    let previous_package_manifest_sha256 = validate_archive_package_generation(
        input.package_generation,
        input.previous_package_report,
    )?;
    validate_archive_candidates(input.bundles)?;
    validate_archive_package_source_reports(input.archive_report, input.closeout_report)?;

    let local_kernel_id = input.archive_report.local_kernel_id.clone();
    if input.closeout_report.local_kernel_id != local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive and closeout reports use different local kernels".to_string(),
        ));
    }
    if !input.archive_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source archive report is not accepted".to_string(),
        ));
    }
    if !input.closeout_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source closeout report is not accepted".to_string(),
        ));
    }

    let mut bundles = Vec::new();
    let mut members = Vec::new();
    let mut files = Vec::new();
    let mut seen_bundle_ids = BTreeSet::new();
    for candidate in input.bundles {
        let bundle = candidate.bundle.as_ref().ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid(format!(
                "bundle {} is unreadable",
                candidate.bundle_path
            ))
        })?;
        verify_relay_alert_assurance_export_bundle(
            bundle,
            input.trusted_exporters,
            input.created_at_unix_ms,
        )?;
        if bundle.manifest.body.local_kernel_id != local_kernel_id {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "bundle local kernel id does not match archive report".to_string(),
            ));
        }
        let bundle_id = bundle.manifest.body.bundle_id.clone();
        if !seen_bundle_ids.insert(bundle_id.clone()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate bundle id {bundle_id}"
            )));
        }
        push_archive_package_json_member(
            &mut members,
            &mut files,
            &candidate.bundle_path,
            &bundle_id,
            "export_manifest",
            PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
            "manifest.json",
            "incident_evidence",
            &bundle.manifest,
        )?;
        push_archive_package_json_member(
            &mut members,
            &mut files,
            &candidate.bundle_path,
            &bundle_id,
            "export_report",
            PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
            "relay-alert-assurance-export-report.json",
            "incident_evidence",
            &bundle.report,
        )?;
        for artifact in &bundle.manifest.body.artifacts {
            let file = bundle
                .files
                .iter()
                .find(|file| file.path == artifact.path)
                .ok_or_else(|| {
                    PheromoneRelayError::ArchivePackageInvalid(format!(
                        "artifact {} is missing from export bundle",
                        artifact.path
                    ))
                })?;
            push_archive_package_bytes_member(
                &mut members,
                &mut files,
                &candidate.bundle_path,
                &bundle_id,
                &artifact.role,
                &artifact.schema,
                &artifact.path,
                &artifact.retention_class,
                &file.bytes,
            )?;
        }
        bundles.push(RelayAlertAssuranceArchivePackageBundle {
            bundle_id,
            bundle_path: candidate.bundle_path.clone(),
            export_manifest_sha256: canonical_sha256(&bundle.manifest)?,
            export_report_sha256: canonical_sha256(&bundle.report)?,
            source_package_sha256: bundle.manifest.body.source_package_sha256.clone(),
            artifact_count: bundle.manifest.body.artifacts.len() as u64,
        });
    }
    validate_archive_package_member_set(&members, &files)?;
    let total_byte_count = archive_package_total_bytes(&files)?;
    let bundle_count = u64::try_from(bundles.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("bundle count overflow".to_string())
    })?;
    let member_count = u64::try_from(members.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("member count overflow".to_string())
    })?;
    let body = RelayAlertAssuranceArchivePackageManifestBody {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA.to_string(),
        package_id: input.package_id.to_string(),
        local_kernel_id,
        packager_id: input.packager_id.to_string(),
        packager_key_id: input.packager_key_id.to_string(),
        created_at_unix_ms: input.created_at_unix_ms,
        package_generation: input.package_generation,
        previous_package_manifest_sha256,
        compression_format: "tar.gz".to_string(),
        source_archive_report_sha256: canonical_sha256(input.archive_report)?,
        source_closeout_report_sha256: canonical_sha256(input.closeout_report)?,
        bundle_count,
        member_count,
        total_byte_count,
        bundles,
        members,
        safety_claims: vec![
            "local_archive_package_only".to_string(),
            "manifest_hash_trusted".to_string(),
            "no_upload_delete_move".to_string(),
            "no_live_notification_delivery".to_string(),
            "no_policy_mutation".to_string(),
            "no_dynamic_trust".to_string(),
        ],
    };
    validate_archive_package_manifest_body(&body)?;
    validate_archive_package_source_bundle_reviews(
        &body.bundles,
        input.archive_report,
        input.closeout_report,
    )?;
    let (signature, _) = input
        .signing_key
        .sign_canonical(&body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(RelayAlertAssuranceArchivePackage {
        manifest: RelayAlertAssuranceArchivePackageManifest {
            schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA.to_string(),
            body,
            signer_public_key: input.signing_key.public_key(),
            signature,
        },
        files,
    })
}
pub fn verify_relay_alert_assurance_archive_package(
    input: RelayAlertAssuranceArchivePackageVerifyInput<'_>,
) -> Result<RelayAlertAssuranceArchivePackageReport, PheromoneRelayError> {
    validate_archive_package_manifest(input.package)?;
    validate_trusted_archive_packagers(
        input.trusted_packagers,
        &input.package.manifest,
        input.now_unix_ms,
    )?;
    validate_archive_package_member_set(
        &input.package.manifest.body.members,
        &input.package.files,
    )?;
    validate_archive_package_source_reports(input.archive_report, input.closeout_report)?;
    let body = &input.package.manifest.body;
    if body.source_archive_report_sha256 != canonical_sha256(input.archive_report)? {
        return Err(PheromoneRelayError::BodyHashMismatch(
            "archive report hash does not match package manifest".to_string(),
        ));
    }
    if body.source_closeout_report_sha256 != canonical_sha256(input.closeout_report)? {
        return Err(PheromoneRelayError::BodyHashMismatch(
            "closeout report hash does not match package manifest".to_string(),
        ));
    }
    if input.archive_report.local_kernel_id != body.local_kernel_id
        || input.closeout_report.local_kernel_id != body.local_kernel_id
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source reports local kernel id mismatch".to_string(),
        ));
    }
    if !input.archive_report.accepted || !input.closeout_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source reports are not accepted".to_string(),
        ));
    }
    validate_archive_package_source_bundle_reviews(
        &body.bundles,
        input.archive_report,
        input.closeout_report,
    )?;

    for bundle in &body.bundles {
        let nested = export_bundle_from_archive_package(input.package, bundle)?;
        verify_relay_alert_assurance_export_bundle(
            &nested,
            input.trusted_exporters,
            input.now_unix_ms,
        )?;
        if canonical_sha256(&nested.manifest)? != bundle.export_manifest_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(
                "nested export manifest hash mismatch".to_string(),
            ));
        }
        if canonical_sha256(&nested.report)? != bundle.export_report_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(
                "nested export report hash mismatch".to_string(),
            ));
        }
    }
    let recomputed_total_byte_count = archive_package_total_bytes(&input.package.files)?;
    Ok(RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: body.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        package_id: body.package_id.clone(),
        package_generation: body.package_generation,
        previous_package_manifest_sha256: body.previous_package_manifest_sha256.clone(),
        package_manifest_sha256: canonical_sha256(&input.package.manifest)?,
        source_archive_report_sha256: body.source_archive_report_sha256.clone(),
        source_closeout_report_sha256: body.source_closeout_report_sha256.clone(),
        package_member_count: input.package.files.len(),
        package_total_byte_count: recomputed_total_byte_count,
        bundle_count: body.bundle_count,
        trusted_packager_verified: true,
        nested_exporter_verified: true,
        source_reports_matched: true,
        closeout_ready_verified: true,
        total_byte_count_matched: true,
        extractable: true,
        checks: vec![
            RelayAlertCheck {
                code: "trusted_archive_packager".to_string(),
                accepted: true,
                detail: "archive package signer is trusted by caller-supplied packager roots"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "exact_member_set".to_string(),
                accepted: true,
                detail: "package members match manifest paths, byte counts, hashes, and bundles"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "nested_exporters".to_string(),
                accepted: true,
                detail: "nested export bundles verify against caller-supplied exporter roots"
                    .to_string(),
            },
        ],
    })
}
pub fn build_relay_alert_assurance_archive_extraction_report(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    extracted_member_count: u64,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceArchiveExtractionReport, PheromoneRelayError> {
    let planned_member_count =
        u64::try_from(package_report.package_member_count).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("package member count overflow".to_string())
        })?;
    let accepted = package_report.accepted && extracted_member_count == planned_member_count;
    Ok(RelayAlertAssuranceArchiveExtractionReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_EXTRACTION_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "extraction_incomplete".to_string()
        },
        local_kernel_id: package_report.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        package_id: package_report.package_id.clone(),
        package_manifest_sha256: package_report.package_manifest_sha256.clone(),
        planned_member_count,
        extracted_member_count,
        checks: vec![RelayAlertCheck {
            code: "verified_extraction_plan".to_string(),
            accepted,
            detail: "extraction report is derived from a verified package report".to_string(),
        }],
    })
}
pub fn validate_relay_alert_assurance_archive_package_report(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> Result<(), PheromoneRelayError> {
    if let Some(failure) = archive_package_report_integrity_failure(report) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            failure.to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_archive_package_identity(
    value: &str,
    name: &str,
) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive package {name} is not bounded"
        )));
    }
    if contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive package {name} contains secret material or a dynamic URL"
        )));
    }
    Ok(())
}
fn validate_archive_package_path(path: &str) -> Result<(), PheromoneRelayError> {
    validate_export_path(path).map_err(|error| {
        PheromoneRelayError::ArchivePackageInvalid(format!("unsafe archive path: {error}"))
    })?;
    if !path.is_ascii()
        || path.contains("//")
        || path.chars().any(char::is_whitespace)
        || path.chars().any(char::is_control)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive path must be ASCII, normalized, and non-whitespace".to_string(),
        ));
    }
    Ok(())
}
fn join_archive_package_path(base: &str, child: &str) -> Result<String, PheromoneRelayError> {
    validate_archive_package_path(base)?;
    validate_archive_package_path(child)?;
    let path = format!("{base}/{child}");
    validate_archive_package_path(&path)?;
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn push_archive_package_json_member<T: Serialize>(
    members: &mut Vec<RelayAlertAssuranceArchivePackageMember>,
    files: &mut Vec<RelayAlertAssuranceArchivePackageFile>,
    bundle_path: &str,
    bundle_id: &str,
    artifact_role: &str,
    schema: &str,
    relative_path: &str,
    retention_class: &str,
    value: &T,
) -> Result<(), PheromoneRelayError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    push_archive_package_bytes_member(
        members,
        files,
        bundle_path,
        bundle_id,
        artifact_role,
        schema,
        relative_path,
        retention_class,
        &bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn push_archive_package_bytes_member(
    members: &mut Vec<RelayAlertAssuranceArchivePackageMember>,
    files: &mut Vec<RelayAlertAssuranceArchivePackageFile>,
    bundle_path: &str,
    bundle_id: &str,
    artifact_role: &str,
    schema: &str,
    relative_path: &str,
    retention_class: &str,
    bytes: &[u8],
) -> Result<(), PheromoneRelayError> {
    validate_archive_package_identity(bundle_id, "bundle id")?;
    validate_archive_package_identity(artifact_role, "artifact role")?;
    validate_archive_package_identity(retention_class, "retention class")?;
    if schema.trim().is_empty() || schema.contains("..") {
        return Err(PheromoneRelayError::UnsupportedSchema(schema.to_string()));
    }
    let path = join_archive_package_path(bundle_path, relative_path)?;
    let byte_count = u64::try_from(bytes.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
    })?;
    members.push(RelayAlertAssuranceArchivePackageMember {
        path: path.clone(),
        kind: "regular_file".to_string(),
        bundle_id: bundle_id.to_string(),
        artifact_role: artifact_role.to_string(),
        schema: schema.to_string(),
        sha256: sha256_hex(bytes),
        byte_count,
        retention_class: retention_class.to_string(),
    });
    files.push(RelayAlertAssuranceArchivePackageFile {
        path,
        bytes: bytes.to_vec(),
    });
    Ok(())
}
fn archive_package_total_bytes(
    files: &[RelayAlertAssuranceArchivePackageFile],
) -> Result<u64, PheromoneRelayError> {
    files.iter().try_fold(0_u64, |total, file| {
        let len = u64::try_from(file.bytes.len()).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })?;
        total.checked_add(len).ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid("package byte count overflow".to_string())
        })
    })
}
fn validate_archive_package_source_reports(
    archive_report: &RelayAlertAssuranceArchiveReport,
    closeout_report: &RelayAlertAssuranceCloseoutReport,
) -> Result<(), PheromoneRelayError> {
    if archive_report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            archive_report.schema.clone(),
        ));
    }
    if closeout_report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            closeout_report.schema.clone(),
        ));
    }
    Ok(())
}
fn validate_archive_package_source_bundle_reviews(
    bundles: &[RelayAlertAssuranceArchivePackageBundle],
    archive_report: &RelayAlertAssuranceArchiveReport,
    closeout_report: &RelayAlertAssuranceCloseoutReport,
) -> Result<(), PheromoneRelayError> {
    if archive_report.reviews.len() != bundles.len()
        || closeout_report.reviews.len() != bundles.len()
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package bundle count does not match source reports".to_string(),
        ));
    }
    for bundle in bundles {
        let archive_review = archive_report
            .reviews
            .iter()
            .find(|review| review.bundle_id == bundle.bundle_id)
            .ok_or_else(|| {
                PheromoneRelayError::ArchivePackageInvalid(format!(
                    "archive report missing package bundle {}",
                    bundle.bundle_id
                ))
            })?;
        let closeout_review = closeout_report
            .reviews
            .iter()
            .find(|review| review.bundle_id == bundle.bundle_id)
            .ok_or_else(|| {
                PheromoneRelayError::ArchivePackageInvalid(format!(
                    "closeout report missing package bundle {}",
                    bundle.bundle_id
                ))
            })?;
        if archive_review.bundle_path != bundle.bundle_path
            || archive_review.manifest_sha256.as_deref()
                != Some(bundle.export_manifest_sha256.as_str())
            || archive_review.source_package_sha256.as_deref()
                != Some(bundle.source_package_sha256.as_str())
            || archive_review.artifact_count != bundle.artifact_count
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive report review does not match package bundle {}",
                bundle.bundle_id
            )));
        }
        if closeout_review.bundle_path != bundle.bundle_path
            || closeout_review.manifest_sha256.as_deref()
                != Some(bundle.export_manifest_sha256.as_str())
            || closeout_review.artifact_count != bundle.artifact_count
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "closeout report review does not match package bundle {}",
                bundle.bundle_id
            )));
        }
        if archive_review.state != "archive_ready" || !archive_review.trusted_exporter_verified {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive report review is not archive-ready for bundle {}",
                bundle.bundle_id
            )));
        }
        if closeout_review.state != "closeout_ready" || !closeout_review.verified_bundle {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "closeout report review is not closeout-ready for bundle {}",
                bundle.bundle_id
            )));
        }
    }
    Ok(())
}
fn validate_archive_package_generation(
    generation: u64,
    previous_package_report: Option<&RelayAlertAssuranceArchivePackageReport>,
) -> Result<Option<String>, PheromoneRelayError> {
    if generation == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package generation must be at least 1".to_string(),
        ));
    }
    match (generation, previous_package_report) {
        (1, None) => Ok(None),
        (1, Some(_)) => Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation 1 package must not carry a previous package report".to_string(),
        )),
        (_, Some(previous)) => {
            if !previous.accepted {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package report is not accepted".to_string(),
                ));
            }
            if previous.package_generation.saturating_add(1) != generation {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package generation is not contiguous".to_string(),
                ));
            }
            if !is_sha256_hex(&previous.package_manifest_sha256) {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package manifest hash is invalid".to_string(),
                ));
            }
            Ok(Some(previous.package_manifest_sha256.clone()))
        }
        (_, None) => Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation greater than 1 requires a previous package report".to_string(),
        )),
    }
}
pub(crate) fn archive_package_report_integrity_failure(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> Option<&'static str> {
    if report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA {
        return Some("package_report_schema_invalid");
    }
    if validate_archive_package_identity(&report.package_id, "package id").is_err() {
        return Some("package_report_id_invalid");
    }
    if report.package_generation == 0 {
        return Some("package_report_generation_invalid");
    }
    if report.package_generation == 1 && report.previous_package_manifest_sha256.is_some() {
        return Some("package_report_previous_hash_unexpected");
    }
    if report.package_generation > 1 && report.previous_package_manifest_sha256.is_none() {
        return Some("package_report_previous_hash_missing");
    }
    if !is_sha256_hex(&report.package_manifest_sha256)
        || !is_sha256_hex(&report.source_archive_report_sha256)
        || !is_sha256_hex(&report.source_closeout_report_sha256)
        || matches!(
            report.previous_package_manifest_sha256.as_deref(),
            Some(hash) if !is_sha256_hex(hash)
        )
    {
        return Some("package_report_hash_invalid");
    }
    if report.package_member_count == 0 || report.package_total_byte_count == 0 {
        return Some("package_report_size_invalid");
    }
    if report.bundle_count == 0 {
        return Some("package_report_bundle_count_invalid");
    }
    if report.accepted && report.code != "accepted" {
        return Some("package_report_code_invalid");
    }
    if report.accepted
        && (!report.trusted_packager_verified
            || !report.nested_exporter_verified
            || !report.source_reports_matched
            || !report.closeout_ready_verified
            || !report.total_byte_count_matched
            || !report.extractable)
    {
        return Some("package_report_verification_incomplete");
    }
    if report.checks.is_empty() {
        return Some("package_report_checks_empty");
    }
    if report.checks.iter().any(|check| !check.accepted) {
        return Some("package_report_check_failed");
    }
    None
}
fn validate_archive_package_manifest_body(
    body: &RelayAlertAssuranceArchivePackageManifestBody,
) -> Result<(), PheromoneRelayError> {
    if body.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(body.schema.clone()));
    }
    validate_archive_package_identity(&body.package_id, "package id")?;
    validate_archive_package_identity(&body.packager_id, "packager id")?;
    validate_archive_package_identity(&body.packager_key_id, "packager key id")?;
    if body.compression_format != "tar.gz" {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package compression format must be tar.gz".to_string(),
        ));
    }
    if body.package_generation == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package generation must be at least 1".to_string(),
        ));
    }
    if body.package_generation == 1 && body.previous_package_manifest_sha256.is_some() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation 1 package must not carry a previous package hash".to_string(),
        ));
    }
    if body.package_generation > 1 {
        let Some(previous) = &body.previous_package_manifest_sha256 else {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "generation greater than 1 requires a previous package hash".to_string(),
            ));
        };
        if !is_sha256_hex(previous) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "previous package manifest hash is invalid".to_string(),
            ));
        }
    }
    if !is_sha256_hex(&body.source_archive_report_sha256)
        || !is_sha256_hex(&body.source_closeout_report_sha256)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package source report hash is invalid".to_string(),
        ));
    }
    if body.bundles.is_empty() || body.members.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package must contain bundles and members".to_string(),
        ));
    }
    if body.bundle_count != body.bundles.len() as u64
        || body.member_count != body.members.len() as u64
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package counts do not match manifest arrays".to_string(),
        ));
    }
    let member_total = body.members.iter().try_fold(0_u64, |total, member| {
        total.checked_add(member.byte_count).ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })
    })?;
    if body.total_byte_count != member_total {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package total byte count does not match members".to_string(),
        ));
    }
    for claim in &body.safety_claims {
        validate_archive_safety_claim(claim)?;
    }
    let mut bundle_ids = BTreeSet::new();
    let mut bundle_paths = BTreeSet::new();
    for bundle in &body.bundles {
        validate_archive_package_identity(&bundle.bundle_id, "bundle id")?;
        validate_archive_package_path(&bundle.bundle_path)?;
        if !bundle_ids.insert(bundle.bundle_id.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate package bundle id {}",
                bundle.bundle_id
            )));
        }
        if !bundle_paths.insert(bundle.bundle_path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate package bundle path {}",
                bundle.bundle_path
            )));
        }
        if !is_sha256_hex(&bundle.export_manifest_sha256)
            || !is_sha256_hex(&bundle.export_report_sha256)
            || !is_sha256_hex(&bundle.source_package_sha256)
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "package bundle hash is invalid".to_string(),
            ));
        }
    }
    for member in &body.members {
        let Some(bundle) = body
            .bundles
            .iter()
            .find(|bundle| bundle.bundle_id == member.bundle_id)
        else {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive member {} references unknown bundle {}",
                member.path, member.bundle_id
            )));
        };
        let prefix = format!("{}/", bundle.bundle_path);
        if !member.path.starts_with(&prefix) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive member {} is outside verified bundle {}",
                member.path, bundle.bundle_id
            )));
        }
    }
    Ok(())
}
fn validate_archive_package_manifest(
    package: &RelayAlertAssuranceArchivePackage,
) -> Result<(), PheromoneRelayError> {
    if package.manifest.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            package.manifest.schema.clone(),
        ));
    }
    validate_archive_package_manifest_body(&package.manifest.body)
}
fn validate_trusted_archive_packagers(
    trusted_packagers: &RelayAlertAssuranceTrustedArchivePackagersDocument,
    manifest: &RelayAlertAssuranceArchivePackageManifest,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if trusted_packagers.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA
    {
        return Err(PheromoneRelayError::UnsupportedSchema(
            trusted_packagers.schema.clone(),
        ));
    }
    if trusted_packagers.local_kernel_id != manifest.body.local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted packagers local kernel id mismatch".to_string(),
        ));
    }
    if manifest.body.created_at_unix_ms < trusted_packagers.min_created_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package is older than trusted packager floor".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut packager = None;
    for candidate in &trusted_packagers.packagers {
        validate_archive_package_identity(&candidate.packager_id, "packager id")?;
        validate_archive_package_identity(&candidate.key_id, "packager key id")?;
        if !seen.insert((candidate.packager_id.as_str(), candidate.key_id.as_str())) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate trusted archive packager".to_string(),
            ));
        }
        if candidate.packager_id == manifest.body.packager_id
            && candidate.key_id == manifest.body.packager_key_id
        {
            packager = Some(candidate);
        }
    }
    let packager = packager.ok_or(PheromoneRelayError::SignatureInvalid)?;
    if packager.status != "active" {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted archive packager is not active".to_string(),
        ));
    }
    if manifest.signer_public_key != packager.public_key {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    if now_unix_ms < packager.valid_from_unix_ms
        || now_unix_ms >= packager.valid_until_unix_ms
        || manifest.body.created_at_unix_ms < packager.valid_from_unix_ms
        || manifest.body.created_at_unix_ms >= packager.valid_until_unix_ms
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted archive packager key is outside its validity window".to_string(),
        ));
    }
    if !packager
        .public_key
        .verify_canonical(&manifest.body, &manifest.signature)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
    {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    Ok(())
}
fn validate_archive_package_member_set(
    members: &[RelayAlertAssuranceArchivePackageMember],
    files: &[RelayAlertAssuranceArchivePackageFile],
) -> Result<(), PheromoneRelayError> {
    if members.is_empty() || files.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package member set is empty".to_string(),
        ));
    }
    let mut member_paths = BTreeSet::new();
    let mut casefold_paths = BTreeSet::new();
    for member in members {
        validate_archive_package_path(&member.path)?;
        validate_archive_package_identity(&member.bundle_id, "bundle id")?;
        validate_archive_package_identity(&member.artifact_role, "artifact role")?;
        validate_archive_package_identity(&member.retention_class, "retention class")?;
        if member.kind != "regular_file" {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "archive package supports regular file members only".to_string(),
            ));
        }
        if !is_sha256_hex(&member.sha256) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "member {} has invalid hash",
                member.path
            )));
        }
        if !member_paths.insert(member.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate archive member path {}",
                member.path
            )));
        }
        let folded = member.path.to_ascii_lowercase();
        if !casefold_paths.insert(folded) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "archive member path has a casefold collision".to_string(),
            ));
        }
    }
    let mut file_paths = BTreeSet::new();
    for file in files {
        validate_archive_package_path(&file.path)?;
        if !file_paths.insert(file.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate archive package file {}",
                file.path
            )));
        }
    }
    for member in members {
        let file = files
            .iter()
            .find(|file| file.path == member.path)
            .ok_or_else(|| {
                PheromoneRelayError::BodyHashMismatch(format!(
                    "archive member {} file is missing",
                    member.path
                ))
            })?;
        let len = u64::try_from(file.bytes.len()).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })?;
        if member.byte_count != len || member.sha256 != sha256_hex(&file.bytes) {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "archive member {} hash or byte count mismatch",
                member.path
            )));
        }
    }
    for file in files {
        if !member_paths.contains(file.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive package file {} is not listed in manifest",
                file.path
            )));
        }
    }
    Ok(())
}
fn export_bundle_from_archive_package(
    package: &RelayAlertAssuranceArchivePackage,
    bundle: &RelayAlertAssuranceArchivePackageBundle,
) -> Result<RelayAlertAssuranceExportBundle, PheromoneRelayError> {
    let manifest_path = join_archive_package_path(&bundle.bundle_path, "manifest.json")?;
    let report_path = join_archive_package_path(
        &bundle.bundle_path,
        "relay-alert-assurance-export-report.json",
    )?;
    let manifest_bytes = archive_package_file_bytes(package, &manifest_path)?;
    let report_bytes = archive_package_file_bytes(package, &report_path)?;
    let manifest: RelayAlertAssuranceExportManifest = serde_json::from_slice(manifest_bytes)?;
    let report: RelayAlertAssuranceExportReport = serde_json::from_slice(report_bytes)?;
    if manifest.body.bundle_id != bundle.bundle_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "nested export manifest bundle id mismatch".to_string(),
        ));
    }
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = join_archive_package_path(&bundle.bundle_path, &artifact.path)?;
        files.push(RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes: archive_package_file_bytes(package, &path)?.to_vec(),
        });
    }
    Ok(RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}
fn archive_package_file_bytes<'a>(
    package: &'a RelayAlertAssuranceArchivePackage,
    path: &str,
) -> Result<&'a [u8], PheromoneRelayError> {
    package
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.bytes.as_slice())
        .ok_or_else(|| {
            PheromoneRelayError::BodyHashMismatch(format!("archive package file {path} is missing"))
        })
}
pub(crate) fn validate_archive_safety_claim(claim: &str) -> Result<(), PheromoneRelayError> {
    validate_archive_package_identity(claim, "safety claim")?;
    let forbidden = [
        "handoff_completed",
        "retained_externally",
        "upload",
        "uploaded",
        "delete",
        "deleted",
        "move",
        "moved",
        "live_notification",
        "dispatch",
        "policy_mutation",
        "dynamic_trust",
        "peer_discovery",
        "new_transport",
        "settlement",
        "hidden_predicate",
        "vc_di_bbs",
        "zkvm",
        "frost",
    ];
    if !claim.starts_with("no_") && forbidden.iter().any(|needle| claim.contains(needle)) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive safety claim {claim} is forbidden"
        )));
    }
    Ok(())
}
