use super::super::{
    load_relay_signing_key, read_json_file, read_utf8_json_file, write_pretty_json,
};
use super::reports::{read_archive_restore_package_reports, read_relay_report_documents};
use super::support::{
    archive_package_limits, read_relay_alert_assurance_archive_candidates,
    trusted_archive_packagers_from_signing_key, ARCHIVE_PACKAGE_MANIFEST_PATH,
};
use crate::CliError;
use std::path::Path;

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_archive_plan(
    bundle_root: &Path,
    trusted_exporters: &Path,
    archive_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let archive_profile: chio_pheromone_relay::RelayAlertAssuranceArchiveProfileDocument =
        read_json_file(
            archive_profile,
            "Chio relay alert assurance archive profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(
            retention_profile,
            "Chio relay alert assurance retention profile",
        )?;
    let archive_report = chio_pheromone_relay::generate_relay_alert_assurance_archive_report(
        chio_pheromone_relay::RelayAlertAssuranceArchiveInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            archive_profile: &archive_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert assurance archive plan: {error}"))
    })?;
    write_pretty_json(
        report,
        &archive_report,
        "Chio relay alert assurance archive report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_closeout_review(
    bundle_root: &Path,
    trusted_exporters: &Path,
    closeout_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let closeout_profile: chio_pheromone_relay::RelayAlertAssuranceCloseoutProfileDocument =
        read_json_file(
            closeout_profile,
            "Chio relay alert assurance closeout profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(
            retention_profile,
            "Chio relay alert assurance retention profile",
        )?;
    let closeout_report = chio_pheromone_relay::generate_relay_alert_assurance_closeout_report(
        chio_pheromone_relay::RelayAlertAssuranceCloseoutInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            closeout_profile: &closeout_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance closeout review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &closeout_report,
        "Chio relay alert assurance closeout report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_archive_package_create(
    bundle_root: &Path,
    trusted_exporters: &Path,
    archive_report: &Path,
    closeout_report: &Path,
    signing_key: &Path,
    package_id: &str,
    packager_key_id: &str,
    package_generation: u64,
    previous_package_report: Option<&Path>,
    now_unix_ms: u64,
    out: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let archive_report: chio_pheromone_relay::RelayAlertAssuranceArchiveReport =
        read_json_file(archive_report, "Chio relay alert assurance archive report")?;
    let closeout_report: chio_pheromone_relay::RelayAlertAssuranceCloseoutReport = read_json_file(
        closeout_report,
        "Chio relay alert assurance closeout report",
    )?;
    let previous_package_report: Option<
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
    > = previous_package_report
        .map(|path| {
            read_json_file(
                path,
                "Chio relay alert assurance previous archive package report",
            )
        })
        .transpose()?;
    let (packager_id, signing_key) = load_relay_signing_key(signing_key)?;
    let package = chio_pheromone_relay::sign_relay_alert_assurance_archive_package(
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageBuildInput {
            package_id,
            packager_id: &packager_id,
            packager_key_id,
            package_generation,
            previous_package_report: previous_package_report.as_ref(),
            signing_key: &signing_key,
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            archive_report: &archive_report,
            closeout_report: &closeout_report,
            created_at_unix_ms: now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance archive package create: {error}"
        ))
    })?;
    write_relay_alert_assurance_archive_package(out, &package)?;
    let trusted_packagers = trusted_archive_packagers_from_signing_key(
        &packager_id,
        packager_key_id,
        signing_key.public_key(),
        package.manifest.body.local_kernel_id.clone(),
        now_unix_ms,
    );
    let package_report = chio_pheromone_relay::verify_relay_alert_assurance_archive_package(
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageVerifyInput {
            package: &package,
            trusted_packagers: &trusted_packagers,
            trusted_exporters: &trusted_exporters,
            archive_report: &archive_report,
            closeout_report: &closeout_report,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance archive package create report: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &package_report,
        "Chio relay alert assurance archive package report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_archive_package_verify(
    package: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    archive_report: &Path,
    closeout_report: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let package = read_relay_alert_assurance_archive_package(package)?;
    let package_report = verify_relay_alert_assurance_archive_package_from_inputs(
        &package,
        trusted_packagers,
        trusted_exporters,
        archive_report,
        closeout_report,
        now_unix_ms,
    )?;
    write_pretty_json(
        report,
        &package_report,
        "Chio relay alert assurance archive package report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_archive_package_extract(
    package: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    archive_report: &Path,
    closeout_report: &Path,
    out_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let package = read_relay_alert_assurance_archive_package(package)?;
    let package_report = verify_relay_alert_assurance_archive_package_from_inputs(
        &package,
        trusted_packagers,
        trusted_exporters,
        archive_report,
        closeout_report,
        now_unix_ms,
    )?;
    let extracted_member_count =
        write_verified_relay_alert_assurance_archive_package(out_dir, &package)?;
    let extraction_report =
        chio_pheromone_relay::build_relay_alert_assurance_archive_extraction_report(
            &package_report,
            extracted_member_count,
            now_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance archive package extract: {error}"
            ))
        })?;
    write_pretty_json(
        report,
        &extraction_report,
        "Chio relay alert assurance archive extraction report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_physical_drill_review(
    evidence: &Path,
    package_report: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let evidence: chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveEvidence =
        read_json_file(
            evidence,
            "Chio relay alert assurance physical archive evidence",
        )?;
    let package_report: chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport =
        read_json_file(
            package_report,
            "Chio relay alert assurance archive package report",
        )?;
    let drill = chio_pheromone_relay::generate_relay_alert_assurance_physical_archive_drill_report(
        chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillInput {
            evidence: &evidence,
            expected_package_id: &package_report.package_id,
            expected_package_report_sha256: &chio_core::crypto::sha256_hex(
                &chio_core::canonical::canonical_json_bytes(&package_report).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio relay alert assurance archive package report: {error}"
                    ))
                })?,
            ),
            expected_package_manifest_sha256: &package_report.package_manifest_sha256,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance physical drill review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &drill,
        "Chio relay alert assurance physical archive drill report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_archive_restore_drill_review(
    package_dir: &Path,
    source_report_dir: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    restore_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let package_reports = read_archive_restore_package_reports(
        package_dir,
        source_report_dir,
        trusted_packagers,
        trusted_exporters,
        now_unix_ms,
    )?;
    let physical_drill_reports: Vec<
        chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillReport,
    > = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
        "Chio relay alert assurance physical archive drill report",
    )?;
    let retention_handoff_reports: Vec<
        chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffReport,
    > = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
        "Chio relay alert assurance retention handoff report",
    )?;
    let restore_profile: chio_pheromone_relay::RelayAlertAssuranceArchiveRestoreProfileDocument =
        read_json_file(
            restore_profile,
            "Chio relay alert assurance archive restore profile",
        )?;
    let restore_report =
        chio_pheromone_relay::generate_relay_alert_assurance_archive_restore_drill_report(
            chio_pheromone_relay::RelayAlertAssuranceArchiveRestoreDrillInput {
                package_reports: &package_reports,
                physical_drill_reports: &physical_drill_reports,
                retention_handoff_reports: &retention_handoff_reports,
                restore_profile: &restore_profile,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance archive restore drill: {error}"
            ))
        })?;
    write_pretty_json(
        report,
        &restore_report,
        "Chio relay alert assurance archive restore drill report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_retention_handoff_review(
    evidence: &Path,
    profile: &Path,
    package_report: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let evidence: chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffEvidence =
        read_json_file(
            evidence,
            "Chio relay alert assurance retention handoff evidence",
        )?;
    let profile: chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffProfileDocument =
        read_json_file(
            profile,
            "Chio relay alert assurance retention handoff profile",
        )?;
    let package_report: chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport =
        read_json_file(
            package_report,
            "Chio relay alert assurance archive package report",
        )?;
    let package_report_sha256 = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&package_report).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance archive package report: {error}"
            ))
        })?,
    );
    let handoff = chio_pheromone_relay::generate_relay_alert_assurance_retention_handoff_report(
        chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffInput {
            evidence: &evidence,
            profile: &profile,
            expected_package_id: &package_report.package_id,
            expected_package_report_sha256: &package_report_sha256,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance retention handoff review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &handoff,
        "Chio relay alert assurance retention handoff report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_retention_external_review(
    package_dir: &Path,
    source_report_dir: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let package_reports = read_archive_restore_package_reports(
        package_dir,
        source_report_dir,
        trusted_packagers,
        trusted_exporters,
        now_unix_ms,
    )?;
    let restore_drill_reports: Vec<
        chio_pheromone_relay::RelayAlertAssuranceArchiveRestoreDrillReport,
    > = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
        "Chio relay alert assurance archive restore drill report",
    )?;
    let physical_drill_reports: Vec<
        chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillReport,
    > = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
        "Chio relay alert assurance physical archive drill report",
    )?;
    let retention_handoff_reports: Vec<
        chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffReport,
    > = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
        "Chio relay alert assurance retention handoff report",
    )?;
    let profile_json = read_utf8_json_file(
        profile,
        "Chio relay alert assurance external retention profile",
    )?;
    let profile = chio_pheromone_relay::relay_alert_assurance_external_retention_profile_from_json(
        &profile_json,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance external retention profile: {error}"
        ))
    })?;
    let review =
        chio_pheromone_relay::generate_relay_alert_assurance_external_retention_review_report(
            chio_pheromone_relay::RelayAlertAssuranceExternalRetentionReviewInput {
                package_reports: &package_reports,
                restore_drill_reports: &restore_drill_reports,
                physical_drill_reports: &physical_drill_reports,
                retention_handoff_reports: &retention_handoff_reports,
                profile: &profile,
                since_unix_ms,
                until_unix_ms,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance external retention review: {error}"
            ))
        })?;
    write_pretty_json(
        report,
        &review,
        "Chio relay alert assurance external retention review report",
    )
}

fn verify_relay_alert_assurance_archive_package_from_inputs(
    package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    archive_report: &Path,
    closeout_report: &Path,
    now_unix_ms: u64,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport, CliError> {
    let trusted_packagers: chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument =
        read_json_file(
            trusted_packagers,
            "Chio relay alert assurance trusted archive packagers",
        )?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let archive_report: chio_pheromone_relay::RelayAlertAssuranceArchiveReport =
        read_json_file(archive_report, "Chio relay alert assurance archive report")?;
    let closeout_report: chio_pheromone_relay::RelayAlertAssuranceCloseoutReport = read_json_file(
        closeout_report,
        "Chio relay alert assurance closeout report",
    )?;
    chio_pheromone_relay::verify_relay_alert_assurance_archive_package(
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageVerifyInput {
            package,
            trusted_packagers: &trusted_packagers,
            trusted_exporters: &trusted_exporters,
            archive_report: &archive_report,
            closeout_report: &closeout_report,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance archive package verify: {error}"
        ))
    })
}

fn write_relay_alert_assurance_archive_package(
    out: &Path,
    package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
) -> Result<(), CliError> {
    let manifest_bytes =
        chio_core::canonical::canonical_json_bytes(&package.manifest).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance archive package manifest: {error}"
            ))
        })?;
    let mut entries = Vec::with_capacity(package.files.len().saturating_add(1));
    entries.push(crate::archive::SafeArchiveWriteEntry {
        path: ARCHIVE_PACKAGE_MANIFEST_PATH,
        bytes: &manifest_bytes,
    });
    for file in &package.files {
        entries.push(crate::archive::SafeArchiveWriteEntry {
            path: &file.path,
            bytes: &file.bytes,
        });
    }
    crate::archive::write_tar_gz_file(
        out,
        "Chio archive package",
        &entries,
        archive_package_limits(),
    )
}

pub(super) fn read_relay_alert_assurance_archive_package(
    package_path: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceArchivePackage, CliError> {
    let entries = crate::archive::read_tar_gz_file(
        package_path,
        "Chio archive package",
        archive_package_limits(),
    )?;
    let mut manifest = None;
    let mut files = Vec::new();
    for entry in entries {
        if entry.path == ARCHIVE_PACKAGE_MANIFEST_PATH {
            let parsed: chio_pheromone_relay::RelayAlertAssuranceArchivePackageManifest =
                serde_json::from_slice(&entry.bytes).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio archive package manifest JSON: {error}"
                    ))
                })?;
            manifest = Some(parsed);
        } else {
            files.push(
                chio_pheromone_relay::RelayAlertAssuranceArchivePackageFile {
                    path: entry.path,
                    bytes: entry.bytes,
                },
            );
        }
    }
    let manifest = manifest.ok_or_else(|| {
        CliError::cli_other_error("Chio archive package manifest is missing".to_string())
    })?;
    Ok(chio_pheromone_relay::RelayAlertAssuranceArchivePackage { manifest, files })
}

fn write_verified_relay_alert_assurance_archive_package(
    out_dir: &Path,
    package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
) -> Result<u64, CliError> {
    let entries = archive_package_entries(package)?;
    crate::archive::write_entries_to_fresh_dir(out_dir, "Chio archive extraction", &entries)?;
    u64::try_from(package.files.len()).map_err(|_| {
        CliError::cli_other_error("Chio archive package member count overflow".to_string())
    })
}

fn archive_package_entries(
    package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
) -> Result<Vec<crate::archive::SafeArchiveEntry>, CliError> {
    let manifest_bytes =
        chio_core::canonical::canonical_json_bytes(&package.manifest).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert assurance archive package manifest: {error}"
            ))
        })?;
    let mut entries = Vec::with_capacity(package.files.len().saturating_add(1));
    entries.push(crate::archive::SafeArchiveEntry {
        path: ARCHIVE_PACKAGE_MANIFEST_PATH.to_string(),
        bytes: manifest_bytes,
        mode: 0o600,
    });
    for file in &package.files {
        entries.push(crate::archive::SafeArchiveEntry {
            path: file.path.clone(),
            bytes: file.bytes.clone(),
            mode: 0o600,
        });
    }
    Ok(entries)
}
