use super::*;

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_package(
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
        &read_utf8_json_file(alert_report, "Chiodos relay alert report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert report: {error}")))?;
    let trend_report: chio_pheromone_relay::RelayTrendReport = serde_json::from_str(
        &read_utf8_json_file(trend_report, "Chiodos relay trend report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend report: {error}")))?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        serde_json::from_str(&read_utf8_json_file(
            normalization_report,
            "Chiodos relay alert normalization report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization report: {error}"
            ))
        })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        serde_json::from_str(&read_utf8_json_file(
            drift_report,
            "Chiodos relay alert delivery drift report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery drift report: {error}"
            ))
        })?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket = serde_json::from_str(
        &read_utf8_json_file(review_packet, "Chiodos relay alert route review packet")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert route review packet: {error}"))
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
        CliError::cli_other_error(format!("Chiodos relay alert assurance package: {error}"))
    })?;
    write_pretty_json(
        report,
        &package,
        "Chiodos relay alert assurance package",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_export(
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
        read_json_file(package, "Chiodos relay alert assurance package")?;
    let alert_report: chio_pheromone_relay::RelayAlertReport =
        read_json_file(alert_report, "Chiodos relay alert report")?;
    let trend_report: chio_pheromone_relay::RelayTrendReport =
        read_json_file(trend_report, "Chiodos relay trend report")?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport =
        read_json_file(handoff_report, "Chiodos relay alert handoff report")?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        read_json_file(normalization_report, "Chiodos relay alert normalization report")?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport =
        read_json_file(delivery_report, "Chiodos relay alert delivery report")?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        read_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        read_json_file(drift_report, "Chiodos relay alert delivery drift report")?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket =
        read_json_file(review_packet, "Chiodos relay alert route review packet")?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
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
        CliError::cli_other_error(format!("Chiodos relay alert assurance export: {error}"))
    })?;
    write_relay_alert_assurance_bundle(out_dir, &bundle)?;
    write_pretty_json(report, &bundle.report, "Chiodos relay alert assurance export report")
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_verify(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let verify_report = chio_pheromone_relay::verify_relay_alert_assurance_export_bundle(
        &bundle,
        &trusted_exporters,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance verify: {error}"))
    })?;
    write_pretty_json(
        report,
        &verify_report,
        "Chiodos relay alert assurance export report",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_replay(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let replay_report = chio_pheromone_relay::generate_relay_alert_assurance_replay_report(
        chio_pheromone_relay::RelayAlertAssuranceReplayInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance replay: {error}"))
    })?;
    write_pretty_json(
        report,
        &replay_report,
        "Chiodos relay alert assurance replay report",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_retention_plan(
    bundle_root: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_bundle_root(bundle_root)?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let retention_report = chio_pheromone_relay::generate_relay_alert_assurance_retention_report(
        chio_pheromone_relay::RelayAlertAssuranceRetentionInput {
            bundles: &bundles,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance retention plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &retention_report,
        "Chiodos relay alert assurance retention report",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_recovery_drill(
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
            "Chiodos relay alert assurance trusted exporters",
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
            "Chiodos relay alert assurance recovery drill: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &drill_report,
        "Chiodos relay alert assurance recovery drill report",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_archive_plan(
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
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let archive_profile: chio_pheromone_relay::RelayAlertAssuranceArchiveProfileDocument =
        read_json_file(
            archive_profile,
            "Chiodos relay alert assurance archive profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
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
            "Chiodos relay alert assurance archive plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &archive_report,
        "Chiodos relay alert assurance archive report",
    )
}

pub(crate) fn cmd_chiodos_pheromone_relay_alert_assurance_closeout_review(
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
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let closeout_profile: chio_pheromone_relay::RelayAlertAssuranceCloseoutProfileDocument =
        read_json_file(
            closeout_profile,
            "Chiodos relay alert assurance closeout profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
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
            "Chiodos relay alert assurance closeout review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &closeout_report,
        "Chiodos relay alert assurance closeout report",
    )
}



pub(crate) fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    ensure_clean_output_dir(out_dir)?;
    write_pretty_json(
        &out_dir.join("manifest.json"),
        &bundle.manifest,
        "Chiodos relay alert assurance export manifest",
    )?;
    write_pretty_json(
        &out_dir.join("relay-alert-assurance-export-report.json"),
        &bundle.report,
        "Chiodos relay alert assurance export report",
    )?;
    for file in &bundle.files {
        let path = safe_bundle_path(out_dir, &file.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chiodos relay alert assurance export dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &file.bytes).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write Chiodos relay alert assurance export file {}: {error}",
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
        "Chiodos relay alert assurance export manifest",
    )?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport = read_json_file(
        &bundle_dir.join("relay-alert-assurance-export-report.json"),
        "Chiodos relay alert assurance export report",
    )?;
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = safe_bundle_path(bundle_dir, &artifact.path)?;
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance export file {}: {error}",
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
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
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
            "Chiodos relay alert assurance bundle root {} contains no bundles",
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
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
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
            "Chiodos relay alert assurance bundle root {} contains no bundles",
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
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries.next().transpose().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?.is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chiodos output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chiodos output directory {}: {error}",
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
            "Chiodos relay alert assurance export path {relative} is not relative"
        )));
    }
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "Chiodos relay alert assurance export path {relative} is unsafe"
            )));
        }
        path.push(segment);
    }
    Ok(path)
}
