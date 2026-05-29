use super::{load_relay_signing_key, read_json_file, read_utf8_json_file, write_pretty_json};
use crate::CliError;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_package(
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let alert_report: chio_pheromone_relay::RelayAlertReport = serde_json::from_str(
        &read_utf8_json_file(alert_report, "Chio relay alert report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio relay alert report: {error}")))?;
    let trend_report: chio_pheromone_relay::RelayTrendReport = serde_json::from_str(
        &read_utf8_json_file(trend_report, "Chio relay trend report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio relay trend report: {error}")))?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chio relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert handoff report: {error}"))
    })?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        serde_json::from_str(&read_utf8_json_file(
            normalization_report,
            "Chio relay alert normalization report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio relay alert normalization report: {error}"))
        })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chio relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery report: {error}"))
    })?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chio relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReport = serde_json::from_str(
        &read_utf8_json_file(drift_report, "Chio relay alert delivery drift report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert delivery drift report: {error}"
        ))
    })?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket = serde_json::from_str(
        &read_utf8_json_file(review_packet, "Chio relay alert route review packet")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert route review packet: {error}"))
    })?;
    let package = chio_pheromone_relay::generate_relay_alert_assurance_package(
        chio_pheromone_relay::RelayAlertAssuranceInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert assurance package: {error}"))
    })?;
    write_pretty_json(report, &package, "Chio relay alert assurance package")
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_export(
    package: &Path,
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
    retention_profile: &Path,
    signing_key: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let assurance_package: chio_pheromone_relay::RelayAlertAssurancePackage =
        read_json_file(package, "Chio relay alert assurance package")?;
    let alert_report: chio_pheromone_relay::RelayAlertReport =
        read_json_file(alert_report, "Chio relay alert report")?;
    let trend_report: chio_pheromone_relay::RelayTrendReport =
        read_json_file(trend_report, "Chio relay trend report")?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport =
        read_json_file(handoff_report, "Chio relay alert handoff report")?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport = read_json_file(
        normalization_report,
        "Chio relay alert normalization report",
    )?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport =
        read_json_file(delivery_report, "Chio relay alert delivery report")?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        read_json_file(
            acknowledgement_report,
            "Chio relay alert acknowledgement report",
        )?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReport =
        read_json_file(drift_report, "Chio relay alert delivery drift report")?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket =
        read_json_file(review_packet, "Chio relay alert route review packet")?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(
            retention_profile,
            "Chio relay alert assurance retention profile",
        )?;
    let (exporter_id, signing_key) = load_relay_signing_key(signing_key)?;
    let bundle = chio_pheromone_relay::sign_relay_alert_assurance_export_bundle(
        chio_pheromone_relay::RelayAlertAssuranceExportBuildInput {
            bundle_id: "relay-alert-assurance-export",
            exporter_id: &exporter_id,
            exporter_key_id: "default",
            signing_key: &signing_key,
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            assurance_package: &assurance_package,
            normalized_delivery_evidence: &normalization_report.evidence,
            retention_profile: &retention_profile,
            exported_at_unix_ms: now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert assurance export: {error}"))
    })?;
    write_relay_alert_assurance_bundle(out_dir, &bundle)?;
    write_pretty_json(
        report,
        &bundle.report,
        "Chio relay alert assurance export report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_verify(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let verify_report = chio_pheromone_relay::verify_relay_alert_assurance_export_bundle(
        &bundle,
        &trusted_exporters,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert assurance verify: {error}"))
    })?;
    write_pretty_json(
        report,
        &verify_report,
        "Chio relay alert assurance export report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_replay(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let replay_report = chio_pheromone_relay::generate_relay_alert_assurance_replay_report(
        chio_pheromone_relay::RelayAlertAssuranceReplayInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert assurance replay: {error}"))
    })?;
    write_pretty_json(
        report,
        &replay_report,
        "Chio relay alert assurance replay report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_retention_plan(
    bundle_root: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_bundle_root(bundle_root)?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(
            retention_profile,
            "Chio relay alert assurance retention profile",
        )?;
    let retention_report = chio_pheromone_relay::generate_relay_alert_assurance_retention_report(
        chio_pheromone_relay::RelayAlertAssuranceRetentionInput {
            bundles: &bundles,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance retention plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &retention_report,
        "Chio relay alert assurance retention report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_assurance_recovery_drill(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    case_id: &str,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let drill_report = chio_pheromone_relay::generate_relay_alert_assurance_recovery_drill_report(
        chio_pheromone_relay::RelayAlertAssuranceRecoveryDrillInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            case_id,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert assurance recovery drill: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &drill_report,
        "Chio relay alert assurance recovery drill report",
    )
}

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
        CliError::cli_other_error(format!(
            "Chio relay alert assurance archive plan: {error}"
        ))
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
    let closeout_report: chio_pheromone_relay::RelayAlertAssuranceCloseoutReport =
        read_json_file(
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
        read_json_file(evidence, "Chio relay alert assurance physical archive evidence")?;
    let package_report: chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport =
        read_json_file(
            package_report,
            "Chio relay alert assurance archive package report",
        )?;
    let drill =
        chio_pheromone_relay::generate_relay_alert_assurance_physical_archive_drill_report(
            chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillInput {
                evidence: &evidence,
                expected_package_id: &package_report.package_id,
                expected_package_report_sha256: &chio_core::crypto::sha256_hex(
                    &chio_core::canonical::canonical_json_bytes(&package_report).map_err(
                        |error| {
                            CliError::cli_other_error(format!(
                                "Chio relay alert assurance archive package report: {error}"
                            ))
                        },
                    )?,
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
        read_json_file(evidence, "Chio relay alert assurance retention handoff evidence")?;
    let profile: chio_pheromone_relay::RelayAlertAssuranceRetentionHandoffProfileDocument =
        read_json_file(profile, "Chio relay alert assurance retention handoff profile")?;
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

fn read_archive_restore_package_reports(
    package_dir: &Path,
    source_report_dir: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport>, CliError> {
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
    let mut reports = Vec::new();
    let mut package_paths = sorted_files(package_dir)?;
    retain_archive_restore_package_inputs(&mut package_paths);
    let mut source_reports = None;
    for path in package_paths {
        if file_name_ends_with(&path, ".tar.gz") || file_name_ends_with(&path, ".tgz") {
            let package = read_relay_alert_assurance_archive_package(&path)?;
            if source_reports.is_none() {
                source_reports = Some(read_archive_restore_source_reports(source_report_dir)?);
            }
            let source_reports = source_reports.as_ref().ok_or_else(|| {
                CliError::cli_other_error("Chio restore source reports missing".to_string())
            })?;
            let (archive_report, closeout_report) = source_reports.for_package(&package)?;
            let verified_report = chio_pheromone_relay::verify_relay_alert_assurance_archive_package(
                chio_pheromone_relay::RelayAlertAssuranceArchivePackageVerifyInput {
                    package: &package,
                    trusted_packagers: &trusted_packagers,
                    trusted_exporters: &trusted_exporters,
                    archive_report,
                    closeout_report,
                    now_unix_ms,
                },
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio relay alert assurance archive package restore verify: {error}"
                ))
            })?;
            let report =
                read_archive_restore_package_report_sidecar(&path, &verified_report)?
                    .unwrap_or(verified_report);
            reports.push(report);
        }
    }
    if reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no archive package tarballs found in {}",
            package_dir.display()
        )));
    }
    Ok(reports)
}

fn retain_archive_restore_package_inputs(package_paths: &mut Vec<PathBuf>) {
    package_paths.retain(|path| {
        file_name_ends_with(path, ".tar.gz") || file_name_ends_with(path, ".tgz")
    });
}

fn archive_restore_package_sidecar_report_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    let package_name = file_name
        .strip_suffix(".tar.gz")
        .or_else(|| file_name.strip_suffix(".tgz"))?;
    Some(format!("{package_name}-report.json"))
}

fn read_archive_restore_package_report_sidecar(
    package_path: &Path,
    verified_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
) -> Result<Option<chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport>, CliError> {
    let Some(sidecar_name) = archive_restore_package_sidecar_report_name(package_path) else {
        return Ok(None);
    };
    let sidecar_path = package_path.with_file_name(sidecar_name);
    if !sidecar_path.is_file() {
        return Ok(None);
    }
    let sidecar_report: chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport =
        read_json_file(
            &sidecar_path,
            "Chio relay alert assurance archive package sidecar report",
        )?;
    if !archive_restore_package_sidecar_matches_verified_report(&sidecar_report, verified_report) {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance archive package sidecar report {} does not match verified package",
            sidecar_path.display()
        )));
    }
    Ok(Some(sidecar_report))
}

fn archive_restore_package_sidecar_matches_verified_report(
    sidecar_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
    verified_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
) -> bool {
    let mut normalized_sidecar = sidecar_report.clone();
    normalized_sidecar.generated_at_unix_ms = verified_report.generated_at_unix_ms;
    normalized_sidecar == *verified_report
}

struct ArchiveRestoreSourceReports {
    archive_reports: Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveReport>,
    closeout_reports: Vec<chio_pheromone_relay::RelayAlertAssuranceCloseoutReport>,
}

impl ArchiveRestoreSourceReports {
    fn for_package(
        &self,
        package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
    ) -> Result<
        (
            &chio_pheromone_relay::RelayAlertAssuranceArchiveReport,
            &chio_pheromone_relay::RelayAlertAssuranceCloseoutReport,
        ),
        CliError,
    > {
        let body = &package.manifest.body;
        let archive_report = find_report_by_canonical_hash(
            &self.archive_reports,
            &body.source_archive_report_sha256,
            "Chio relay alert assurance archive report",
        )?;
        let closeout_report = find_report_by_canonical_hash(
            &self.closeout_reports,
            &body.source_closeout_report_sha256,
            "Chio relay alert assurance closeout report",
        )?;
        Ok((archive_report, closeout_report))
    }
}

fn read_archive_restore_source_reports(
    source_report_dir: &Path,
) -> Result<ArchiveRestoreSourceReports, CliError> {
    let archive_reports = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
        "Chio relay alert assurance archive report",
    )?;
    if archive_reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no Chio relay alert assurance archive reports found in {}",
            source_report_dir.display()
        )));
    }
    let closeout_reports = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
        "Chio relay alert assurance closeout report",
    )?;
    if closeout_reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no Chio relay alert assurance closeout reports found in {}",
            source_report_dir.display()
        )));
    }
    Ok(ArchiveRestoreSourceReports {
        archive_reports,
        closeout_reports,
    })
}

fn find_report_by_canonical_hash<'a, T: serde::Serialize>(
    reports: &'a [T],
    expected_sha256: &str,
    label: &str,
) -> Result<&'a T, CliError> {
    let mut matched_report = None;
    for report in reports {
        let report_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(report).map_err(|error| {
                CliError::cli_other_error(format!("{label} canonical hash: {error}"))
            })?,
        );
        if report_sha256 == expected_sha256 {
            if matched_report.is_some() {
                return Err(CliError::cli_other_error(format!(
                    "multiple {label} documents match package manifest hash {expected_sha256}"
                )));
            }
            matched_report = Some(report);
        }
    }
    matched_report.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "no {label} document matches package manifest hash {expected_sha256}"
        ))
    })
}

fn read_relay_report_documents<T: DeserializeOwned>(
    dir: &Path,
    schema: &str,
    label: &str,
) -> Result<Vec<T>, CliError> {
    let mut reports = Vec::new();
    for path in sorted_files(dir)? {
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value = read_json_file(&path, label)?;
        if value.get("schema").and_then(serde_json::Value::as_str) == Some(schema) {
            reports.push(serde_json::from_value(value).map_err(|error| {
                CliError::cli_json_error(format!("{label}: {error}"))
            })?);
        }
    }
    Ok(reports)
}

fn sorted_files(dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!("failed to read directory {}: {error}", dir.display()))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!("failed to read directory entry: {error}"))
        })?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn file_name_ends_with(path: &Path, suffix: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(suffix))
}

const ARCHIVE_PACKAGE_MANIFEST_PATH: &str = "archive-package-manifest.json";
const ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_COUNT: usize = 512;
const ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT: usize = ARCHIVE_PACKAGE_MAX_MEMBER_COUNT + 1;
const ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO: u64 = 200;

fn archive_package_limits() -> crate::archive::SafeArchiveLimits {
    crate::archive::SafeArchiveLimits {
        max_compressed_bytes: ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES,
        max_member_bytes: ARCHIVE_PACKAGE_MAX_MEMBER_BYTES,
        max_total_bytes: ARCHIVE_PACKAGE_MAX_TOTAL_BYTES,
        max_member_count: ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT,
        max_decompression_ratio: ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO,
    }
}

fn trusted_archive_packagers_from_signing_key(
    packager_id: &str,
    packager_key_id: &str,
    public_key: chio_core::crypto::PublicKey,
    local_kernel_id: String,
    now_unix_ms: u64,
) -> chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
    chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA
            .to_string(),
        local_kernel_id,
        min_created_at_unix_ms: now_unix_ms,
        packagers: vec![chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackager {
            packager_id: packager_id.to_string(),
            key_id: packager_key_id.to_string(),
            public_key,
            valid_from_unix_ms: now_unix_ms.saturating_sub(1),
            valid_until_unix_ms: now_unix_ms.saturating_add(24 * 60 * 60 * 1000),
            status: "active".to_string(),
        }],
    }
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
    let closeout_report: chio_pheromone_relay::RelayAlertAssuranceCloseoutReport =
        read_json_file(
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

fn read_relay_alert_assurance_archive_package(
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
            files.push(chio_pheromone_relay::RelayAlertAssuranceArchivePackageFile {
                path: entry.path,
                bytes: entry.bytes,
            });
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
    crate::archive::write_entries_to_fresh_dir(
        out_dir,
        "Chio archive extraction",
        &entries,
    )?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod archive_restore_input_tests {
    use super::*;

    #[test]
    fn archive_restore_inputs_keep_only_tarballs_when_json_reports_are_present() {
        let mut paths = vec![
            PathBuf::from("relay-archive-package.tar.gz"),
            PathBuf::from("relay-archive-package-report.json"),
            PathBuf::from("generation-2-package-report.json"),
            PathBuf::from("notes.txt"),
        ];

        retain_archive_restore_package_inputs(&mut paths);

        assert_eq!(
            paths,
            vec![PathBuf::from("relay-archive-package.tar.gz")]
        );
    }

    #[test]
    fn archive_restore_inputs_drop_report_json_when_no_tarballs_are_present() {
        let mut paths = vec![
            PathBuf::from("relay-archive-package-report.json"),
            PathBuf::from("notes.txt"),
        ];

        retain_archive_restore_package_inputs(&mut paths);

        assert!(paths.is_empty());
    }

    #[test]
    fn archive_restore_rejects_unverified_standalone_package_report_json() {
        let temp = tempfile::tempdir().unwrap();
        let package_dir = temp.path().join("packages");
        let source_report_dir = temp.path().join("source-reports");
        fs::create_dir_all(&package_dir).unwrap();
        fs::create_dir_all(&source_report_dir).unwrap();
        fs::write(
            package_dir.join("generation-1-package-report.json"),
            serde_json::to_vec(&archive_restore_package_report_for_test(10_000)).unwrap(),
        )
        .unwrap();
        let trusted_packagers_path = temp.path().join("trusted-packagers.json");
        fs::write(
            &trusted_packagers_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
                "localKernelId": "did:chio:buyer-kernel",
                "minCreatedAtUnixMs": 0,
                "packagers": []
            }))
            .unwrap(),
        )
        .unwrap();
        let trusted_exporters_path = temp.path().join("trusted-exporters.json");
        fs::write(
            &trusted_exporters_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA,
                "localKernelId": "did:chio:buyer-kernel",
                "minExportedAtUnixMs": 0,
                "exporters": []
            }))
            .unwrap(),
        )
        .unwrap();

        let err = read_archive_restore_package_reports(
            &package_dir,
            &source_report_dir,
            &trusted_packagers_path,
            &trusted_exporters_path,
            20_000,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("no archive package tarballs found"),
            "{err}"
        );
    }

    #[test]
    fn archive_restore_source_reports_match_by_canonical_hash() {
        let reports = vec![
            serde_json::json!({"id": "one", "schema": "test.schema.v1"}),
            serde_json::json!({"id": "two", "schema": "test.schema.v1"}),
        ];
        let expected_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(&reports[1]).unwrap(),
        );

        let report =
            find_report_by_canonical_hash(&reports, &expected_sha256, "test report").unwrap();

        assert_eq!(report, &reports[1]);
    }

    #[test]
    fn archive_restore_tarball_prefers_hash_stable_sidecar_report() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("relay-archive-package.tar.gz");
        std::fs::write(&package_path, b"package bytes").unwrap();
        let verified_report = archive_restore_package_report_for_test(20_000);
        let sidecar_report = archive_restore_package_report_for_test(10_000);
        let sidecar_path = temp.path().join("relay-archive-package-report.json");
        std::fs::write(
            &sidecar_path,
            serde_json::to_vec(&sidecar_report).unwrap(),
        )
        .unwrap();

        let report =
            read_archive_restore_package_report_sidecar(&package_path, &verified_report).unwrap();

        assert_eq!(report, Some(sidecar_report));
    }

    #[test]
    fn archive_restore_tarball_rejects_mismatched_sidecar_report() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("relay-archive-package.tar.gz");
        std::fs::write(&package_path, b"package bytes").unwrap();
        let verified_report = archive_restore_package_report_for_test(20_000);
        let mut sidecar_report = archive_restore_package_report_for_test(10_000);
        sidecar_report.package_manifest_sha256 = "f".repeat(64);
        let sidecar_path = temp.path().join("relay-archive-package-report.json");
        std::fs::write(
            &sidecar_path,
            serde_json::to_vec(&sidecar_report).unwrap(),
        )
        .unwrap();

        let err =
            read_archive_restore_package_report_sidecar(&package_path, &verified_report)
                .unwrap_err();

        assert!(err.to_string().contains("sidecar report"));
    }

    fn archive_restore_package_report_for_test(
        generated_at_unix_ms: u64,
    ) -> chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport {
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA
                .to_string(),
            accepted: true,
            code: "accepted".to_string(),
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            generated_at_unix_ms,
            package_id: "relay-archive-package-1".to_string(),
            package_generation: 1,
            previous_package_manifest_sha256: None,
            package_manifest_sha256: "1".repeat(64),
            source_archive_report_sha256: "2".repeat(64),
            source_closeout_report_sha256: "3".repeat(64),
            package_member_count: 1,
            package_total_byte_count: 128,
            bundle_count: 1,
            trusted_packager_verified: true,
            nested_exporter_verified: true,
            source_reports_matched: true,
            closeout_ready_verified: true,
            total_byte_count_matched: true,
            extractable: true,
            checks: vec![chio_pheromone_relay::RelayAlertCheck {
                code: "accepted".to_string(),
                accepted: true,
                detail: "test package report".to_string(),
            }],
        }
    }
}

pub(crate) fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    ensure_clean_output_dir(out_dir)?;
    write_pretty_json(
        &out_dir.join("manifest.json"),
        &bundle.manifest,
        "Chio relay alert assurance export manifest",
    )?;
    write_pretty_json(
        &out_dir.join("relay-alert-assurance-export-report.json"),
        &bundle.report,
        "Chio relay alert assurance export report",
    )?;
    for file in &bundle.files {
        let path = safe_bundle_path(out_dir, &file.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chio relay alert assurance export dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &file.bytes).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write Chio relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn read_relay_alert_assurance_bundle(
    bundle_dir: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    let manifest: chio_pheromone_relay::RelayAlertAssuranceExportManifest = read_json_file(
        &bundle_dir.join("manifest.json"),
        "Chio relay alert assurance export manifest",
    )?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport = read_json_file(
        &bundle_dir.join("relay-alert-assurance-export-report.json"),
        "Chio relay alert assurance export report",
    )?;
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = safe_bundle_path(bundle_dir, &artifact.path)?;
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
        files.push(chio_pheromone_relay::RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes,
        });
    }
    Ok(chio_pheromone_relay::RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

pub(crate) fn read_relay_alert_assurance_bundle_root(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceExportBundle>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_bundle(bundle_root)?]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut bundles = Vec::new();
    for dir in dirs {
        bundles.push(read_relay_alert_assurance_bundle(&dir)?);
    }
    if bundles.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(bundles)
}

pub(crate) fn read_relay_alert_assurance_archive_candidates(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_archive_candidate(
            bundle_root,
        )]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut candidates = Vec::new();
    for dir in dirs {
        candidates.push(read_relay_alert_assurance_archive_candidate(&dir));
    }
    if candidates.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(candidates)
}

pub(crate) fn read_relay_alert_assurance_archive_candidate(
    bundle_dir: &Path,
) -> chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
    let bundle_path = relay_alert_assurance_bundle_label(bundle_dir);
    match read_relay_alert_assurance_bundle(bundle_dir) {
        Ok(bundle) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: Some(bundle),
            error_code: None,
            error_detail: None,
        },
        Err(error) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: None,
            error_code: Some("bundle_read_failed".to_string()),
            error_detail: Some(error.to_string()),
        },
    }
}

pub(crate) fn relay_alert_assurance_bundle_label(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("export-bundle")
        .to_string()
}

pub(crate) fn ensure_clean_output_dir(out_dir: &Path) -> Result<(), CliError> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to inspect Chio output directory {}: {error}",
                    out_dir.display()
                ))
            })?
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chio output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn safe_bundle_path(root: &Path, relative: &str) -> Result<PathBuf, CliError> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || Path::new(relative).is_absolute()
    {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance export path {relative} is not relative"
        )));
    }
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "Chio relay alert assurance export path {relative} is unsafe"
            )));
        }
        path.push(segment);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::ensure_clean_output_dir;

    #[test]
    fn output_directory_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        std::fs::write(tempdir.path().join("existing.json"), "{}").expect("write fixture");

        let error = ensure_clean_output_dir(tempdir.path())
            .expect_err("non-empty output dir should fail")
            .to_string();

        let retired_label = ["Chio", "dos"].concat();
        assert!(error.contains("Chio output directory"));
        assert!(!error.contains(&retired_label));
    }
}
