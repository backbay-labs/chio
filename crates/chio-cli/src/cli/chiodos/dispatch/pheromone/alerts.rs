fn cmd_chiodos_pheromone_relay_alert_evaluate(
    observability_report: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    suppression_state: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let observability: chio_pheromone_relay::RelayObservabilityReport = serde_json::from_str(
        &read_utf8_json_file(observability_report, "Chiodos relay observability report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay observability report: {error}"))
    })?;
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let suppression = chio_pheromone_relay::relay_alert_suppression_state_from_json(
        &read_utf8_json_file(suppression_state, "Chiodos relay alert suppression state")?,
        &profile,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert suppression state: {error}"))
    })?;
    let events = read_relay_event_reports(event_dir)?;
    let alert_report =
        chio_pheromone_relay::evaluate_relay_alerts(chio_pheromone_relay::RelayAlertEvaluationInput {
            observability: &observability,
            routing_profile: &profile,
            suppression_state: Some(&suppression),
            event_reports: &events,
            now_unix_ms,
            expected_source_report_sha256: None,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert evaluate: {error}")))?;
    write_pretty_json(report, &alert_report, "Chiodos relay alert report")
}

fn cmd_chiodos_pheromone_relay_alert_handoff(
    alert_report: &Path,
    trend_report: &Path,
    routing_profile: &Path,
    handoff_profile: &Path,
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
    let routing_profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let handoff_profile = chio_pheromone_relay::relay_alert_handoff_profile_from_json(
        &read_utf8_json_file(handoff_profile, "Chiodos relay alert handoff profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff profile: {error}"))
    })?;
    let handoff_report = chio_pheromone_relay::evaluate_relay_alert_handoff(
        chio_pheromone_relay::RelayAlertHandoffInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            routing_profile: &routing_profile,
            handoff_profile: &handoff_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert handoff: {error}")))?;
    write_pretty_json(
        report,
        &handoff_report,
        "Chiodos relay alert handoff report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_normalize(
    profile: &Path,
    input_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile: chio_pheromone_relay::RelayAlertNormalizationProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            profile,
            "Chiodos relay alert normalization profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization profile: {error}"
            ))
        })?;
    let sources = read_relay_alert_normalization_sources(input_dir)?;
    let normalization =
        chio_pheromone_relay::normalize_relay_alert_delivery_evidence(
            chio_pheromone_relay::RelayAlertNormalizationInput {
                profile: &profile,
                sources: &sources,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos relay alert normalize: {error}"))
        })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos relay alert normalized evidence dir {}: {error}",
            out_dir.display()
        ))
    })?;
    for (index, evidence) in normalization.evidence.iter().enumerate() {
        let path = out_dir.join(format!("relay-alert-delivery-evidence-{index:03}.json"));
        write_pretty_json(&path, evidence, "Chiodos relay alert delivery evidence")?;
    }
    write_pretty_json(
        report,
        &normalization,
        "Chiodos relay alert normalization report",
    )
}



fn cmd_chiodos_pheromone_relay_alert_review(
    handoff_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    route_owner_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
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
    let route_owner_profile: chio_pheromone_relay::RelayAlertRouteOwnerProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            route_owner_profile,
            "Chiodos relay alert route-owner profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert route-owner profile: {error}"
            ))
        })?;
    let review_packet = chio_pheromone_relay::generate_relay_alert_route_review_packet(
        chio_pheromone_relay::RelayAlertRouteReviewInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            route_owner_profile: &route_owner_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert review: {error}")))?;
    write_pretty_json(
        report,
        &review_packet,
        "Chiodos relay alert route review packet",
    )
}



fn read_relay_alert_normalization_sources(
    dir: &Path,
) -> Result<Vec<serde_json::Value>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert normalization input dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert normalization input dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut sources = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert normalization input")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization input {}: {error}",
                path.display()
            ))
        })?;
        sources.push(value);
    }
    Ok(sources)
}

fn read_relay_alert_handoff_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertHandoffReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert handoff report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    )
}
