use super::super::{
    load_relay_signing_key, read_json_file, read_utf8_json_file, write_pretty_json,
};
use super::support::{
    read_relay_alert_assurance_bundle, read_relay_alert_assurance_bundle_root,
    write_relay_alert_assurance_bundle,
};
use crate::CliError;
use std::path::Path;

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
            CliError::cli_other_error(format!("Chio relay alert acknowledgement report: {error}"))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReport = serde_json::from_str(
        &read_utf8_json_file(drift_report, "Chio relay alert delivery drift report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery drift report: {error}"))
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
