use super::{
    read_json_documents_from_dir, read_relay_alert_handoff_reports, read_utf8_json_file,
    write_pretty_json,
};
use crate::CliError;
use std::fs;
use std::path::Path;

pub(crate) fn cmd_chio_pheromone_relay_alert_delivery_import(
    handoff_report: &Path,
    delivery_profile: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chio relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert handoff report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chio relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery profile: {error}"))
    })?;
    let evidence = read_relay_alert_delivery_evidence(evidence_dir)?;
    let delivery_report = chio_pheromone_relay::evaluate_relay_alert_delivery(
        chio_pheromone_relay::RelayAlertDeliveryInput {
            handoff_report: &handoff_report,
            delivery_profile: &delivery_profile,
            evidence: &evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery import: {error}"))
    })?;
    write_pretty_json(report, &delivery_report, "Chio relay alert delivery report")
}

pub(crate) fn cmd_chio_pheromone_relay_alert_delivery_acknowledge(
    handoff_report: &Path,
    delivery_report: &Path,
    delivery_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chio relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert handoff report: {error}"))
    })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chio relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chio relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery profile: {error}"))
    })?;
    let acknowledgement_report = chio_pheromone_relay::evaluate_relay_alert_acknowledgement(
        chio_pheromone_relay::RelayAlertAcknowledgementInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            delivery_profile: &delivery_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay alert delivery acknowledgement: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &acknowledgement_report,
        "Chio relay alert acknowledgement report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_delivery_drift(
    handoff_reports_dir: &Path,
    delivery_reports_dir: &Path,
    delivery_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chio relay alert delivery profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery profile: {error}"))
    })?;
    let handoff_reports = read_relay_alert_handoff_reports(handoff_reports_dir)?;
    let delivery_reports = read_relay_alert_delivery_reports(delivery_reports_dir)?;
    let drift_report = chio_pheromone_relay::generate_relay_alert_handoff_drift_report(
        chio_pheromone_relay::RelayAlertHandoffDriftInput {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery drift: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chio relay alert handoff drift report",
    )
}

pub(crate) fn cmd_chio_pheromone_relay_alert_delivery_drift_window(
    handoff_reports_dir: &Path,
    delivery_reports_dir: &Path,
    delivery_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chio relay alert delivery profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery profile: {error}"))
    })?;
    let handoff_reports = read_relay_alert_handoff_reports(handoff_reports_dir)?;
    let delivery_reports = read_relay_alert_delivery_reports(delivery_reports_dir)?;
    let drift_report = chio_pheromone_relay::generate_relay_alert_delivery_drift_report(
        chio_pheromone_relay::RelayAlertDeliveryDriftInput {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert delivery drift-window: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chio relay alert delivery drift report",
    )
}

pub(crate) fn read_relay_alert_delivery_evidence(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryEvidence>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio relay alert delivery evidence dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert delivery evidence dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut evidence = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert delivery evidence")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio relay alert delivery evidence {}: {error}",
                path.display()
            ))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str())
            != Some(chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
        {
            continue;
        }
        evidence.push(
            chio_pheromone_relay::relay_alert_delivery_evidence_from_json(&json).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chio relay alert delivery evidence {}: {error}",
                        path.display()
                    ))
                },
            )?,
        );
    }
    Ok(evidence)
}

pub(crate) fn read_relay_alert_delivery_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert delivery report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    )
}
