// Alert routing/handoff/delivery and the end-to-end assurance pipeline CLI
// orchestration, mirroring the
// `scripts/check-chio-pheromone-relay-alert-{routing,handoff,delivery}.sh` and
// `check-chio-pheromone-relay-alert-assurance.sh` gates. Included as a focused facet module. included into `fixtures.rs` via `include!` so it shares that module's
// private helpers (ScratchDir, require_cli, reject_cli, validate_document, the
// JSON helpers).

/// The alert routing/handoff/delivery facets: the alert CLI orchestration each
/// script drove (evaluate/trend, plus handoff for handoff, plus import/
/// acknowledge/drift for delivery), cargo tests, optional sre-metrics, npm
/// test/build, then recurse. The orchestration runs in both `all` and
/// `negative-only` (it precedes the scripts' negative-only exit); npm + recursion
/// only in `all`. The dashboard `npm test` arguments differ per facet.
fn handle_alert_with_npm(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    alert_cli_orchestration(root, facet)?;
    run_cargo_tests(root, facet)?;
    if facet.sre_metrics_registry {
        run_sre_metrics(root)?;
    }
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    if facet.needs_dashboard_npm {
        run_dashboard_test_and_build(root, dashboard_test_args(&facet.name))?;
    }
    run_recursion(root, manifest, facet)
}

/// Alert-evaluation time anchors shared by the routing/handoff/delivery scripts.
const ALERT_NOW_UNIX_MS: &str = "1766000060000";
const ALERT_SINCE_UNIX_MS: &str = "1765999900000";

/// Run the alert CLI orchestration a routing/handoff/delivery facet drives. Each
/// facet builds on the previous one's generated reports, so the routing chain
/// (evaluate + trend) is always produced; handoff adds the handoff step;
/// delivery adds import/acknowledge/drift against the committed fixtures.
fn alert_cli_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("alert")?;
    let fixture_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let generated = scratch.path.clone();

    let alert_report = generated.join("relay-alert-report.json");
    let trend_report = generated.join("relay-trend-report.json");
    alert_run_evaluate_and_trend(root, &fixture_dir, &schema_dir, &alert_report, &trend_report)?;

    match facet.name.as_str() {
        "relay-alert-routing" => alert_assert_routing(&alert_report, &trend_report),
        "relay-alert-handoff" => {
            let handoff_report = generated.join("relay-alert-handoff-report.json");
            alert_run_handoff(
                root,
                &fixture_dir,
                &schema_dir,
                &alert_report,
                &trend_report,
                &handoff_report,
            )?;
            alert_assert_handoff(&handoff_report)
        }
        "relay-alert-delivery" => alert_run_delivery(root, &fixture_dir, &schema_dir, &generated),
        other => Err(invalid(&format!(
            "alert orchestration has no flow for facet {other}"
        ))),
    }
}

/// `pheromone relay alert evaluate` + `pheromone relay trend` against the
/// committed degraded observability fixture, validating both reports.
fn alert_run_evaluate_and_trend(
    root: &Path,
    fixture_dir: &Path,
    schema_dir: &Path,
    alert_report: &Path,
    trend_report: &Path,
) -> Result<(), XtaskError> {
    let degraded = fixture_dir.join("relay-observability-degraded-report.json");
    let routing_profile = fixture_dir.join("relay-alert-routing-profile.json");
    let suppression_state = fixture_dir.join("relay-alert-suppression-state.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "evaluate",
            "--observability-report", &display(&degraded),
            "--event-dir", &display(fixture_dir),
            "--routing-profile", &display(&routing_profile),
            "--suppression-state", &display(&suppression_state),
            "--now-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(alert_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-alert-report.schema.json"), alert_report)?;

    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "trend",
            "--reports-dir", &display(fixture_dir),
            "--event-dir", &display(fixture_dir),
            "--routing-profile", &display(&routing_profile),
            "--since-unix-ms", ALERT_SINCE_UNIX_MS,
            "--until-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(trend_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-trend-report.schema.json"), trend_report)
}

/// The routing script's generated-report assertions: alert report preserves
/// firing relay alerts with a dead-letter alert; trend aggregated >=1 source.
fn alert_assert_routing(alert_report: &Path, trend_report: &Path) -> Result<(), XtaskError> {
    let alert = load_json(alert_report)?;
    if str_field(&alert, "code") != Some("alerts_firing") {
        return Err(invalid("generated alert report must preserve firing relay alerts"));
    }
    let has_dead_letter = alert
        .get("alerts")
        .and_then(Value::as_array)
        .map(|alerts| {
            alerts
                .iter()
                .any(|a| a.get("code").and_then(Value::as_str) == Some("dead_letters_present"))
        })
        .unwrap_or(false);
    if !has_dead_letter {
        return Err(invalid("generated alert report omitted dead-letter alert"));
    }
    let trend = load_json(trend_report)?;
    if trend.get("sourceReportCount").and_then(Value::as_i64).unwrap_or(0) < 1 {
        return Err(invalid("generated trend report did not aggregate report evidence"));
    }
    Ok(())
}

/// `pheromone relay alert handoff` over the generated alert + trend reports.
fn alert_run_handoff(
    root: &Path,
    fixture_dir: &Path,
    schema_dir: &Path,
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
) -> Result<(), XtaskError> {
    let routing_profile = fixture_dir.join("relay-alert-routing-profile.json");
    let handoff_profile = fixture_dir.join("relay-alert-handoff-profile.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "handoff",
            "--alert-report", &display(alert_report),
            "--trend-report", &display(trend_report),
            "--routing-profile", &display(&routing_profile),
            "--handoff-profile", &display(&handoff_profile),
            "--now-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(handoff_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-handoff-report.schema.json"),
        handoff_report,
    )
}

/// The handoff script's generated-report assertions: accepted, at least one
/// critical firing alert preserved, and the primary downstream route present.
fn alert_assert_handoff(handoff_report: &Path) -> Result<(), XtaskError> {
    let handoff = load_json(handoff_report)?;
    if handoff.get("accepted") != Some(&Value::Bool(true))
        || str_field(&handoff, "code") != Some("accepted")
    {
        return Err(invalid("generated handoff report must be accepted"));
    }
    if handoff.get("criticalFiringCount").and_then(Value::as_i64).unwrap_or(0) < 1 {
        return Err(invalid("generated handoff report hid critical firing alerts"));
    }
    if !alert_routes_contain(&handoff, "alertmanager:pagerduty-primary") {
        return Err(invalid("generated handoff report missing primary downstream route"));
    }
    Ok(())
}

/// Whether a report's `routes[].targetRef` set contains a given target.
fn alert_routes_contain(report: &Value, target: &str) -> bool {
    report
        .get("routes")
        .and_then(Value::as_array)
        .map(|routes| {
            routes
                .iter()
                .any(|route| route.get("targetRef").and_then(Value::as_str) == Some(target))
        })
        .unwrap_or(false)
}

/// The delivery script's import/acknowledge/drift chain over the committed
/// handoff report, with the generated-report assertions.
fn alert_run_delivery(
    root: &Path,
    fixture_dir: &Path,
    schema_dir: &Path,
    generated: &Path,
) -> Result<(), XtaskError> {
    let handoff_report = fixture_dir.join("relay-alert-handoff-report.json");
    let delivery_profile = fixture_dir.join("relay-alert-delivery-profile.json");

    let delivery_report = generated.join("relay-alert-delivery-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "import",
            "--handoff-report", &display(&handoff_report),
            "--delivery-profile", &display(&delivery_profile),
            "--evidence-dir", &display(fixture_dir),
            "--now-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(&delivery_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-delivery-report.schema.json"),
        &delivery_report,
    )?;

    let ack_report = generated.join("relay-alert-acknowledgement-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "acknowledge",
            "--handoff-report", &display(&handoff_report),
            "--delivery-report", &display(&delivery_report),
            "--delivery-profile", &display(&delivery_profile),
            "--now-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(&ack_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-acknowledgement-report.schema.json"),
        &ack_report,
    )?;

    let drift_report = generated.join("relay-alert-handoff-drift-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "drift",
            "--handoff-reports-dir", &display(fixture_dir),
            "--delivery-reports-dir", &display(generated),
            "--delivery-profile", &display(&delivery_profile),
            "--since-unix-ms", ALERT_SINCE_UNIX_MS,
            "--until-unix-ms", ALERT_NOW_UNIX_MS,
            "--report", &display(&drift_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-handoff-drift-report.schema.json"),
        &drift_report,
    )?;

    let delivery = load_json(&delivery_report)?;
    if delivery.get("accepted") != Some(&Value::Bool(true))
        || delivery.get("deliveredCount").and_then(Value::as_i64).unwrap_or(0) < 1
    {
        return Err(invalid(
            "generated delivery report must be accepted with delivery evidence",
        ));
    }
    let ack = load_json(&ack_report)?;
    if ack.get("accepted") != Some(&Value::Bool(true))
        || ack.get("acknowledgedCount").and_then(Value::as_i64).unwrap_or(0) < 1
    {
        return Err(invalid("generated acknowledgement report must be accepted"));
    }
    let drift = load_json(&drift_report)?;
    if drift.get("accepted") != Some(&Value::Bool(true))
        || drift.get("driftCount").and_then(Value::as_i64) != Some(0)
    {
        return Err(invalid("generated drift report must be accepted"));
    }
    Ok(())
}

fn dashboard_test_args(facet_name: &str) -> &'static [&'static str] {
    match facet_name {
        "relay-alert-delivery" => &["--", "RelayAlertDeliverySummary", "RelayAlertRoutingSummary"],
        "relay-alert-handoff" => &["--", "RelayAlertRoutingSummary"],
        _ => &[],
    }
}

/// The assurance facet runs the full end-to-end assurance CLI pipeline and its
/// inline-token normalize negative, the cargo tests, then (in `all`) recursion
/// and its dashboard build (the script order). The pipeline + negative run in
/// both `all` and `negative-only`; npm + recursion only in `all`.
fn handle_alert_assurance(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    assurance_cli_orchestration(root, facet)?;
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)?;
    if facet.needs_dashboard_npm {
        run_dashboard_test_and_build(root, &["--", "RelayAlertAssuranceSummary", "api", "App"])?;
    }
    Ok(())
}

/// Assurance pipeline time anchors (the script's NOW/NORMALIZE/ACK/SINCE).
const ASSURANCE_NOW_UNIX_MS: &str = "1766000090000";
const ASSURANCE_NORMALIZE_UNIX_MS: &str = "1766000070000";
const ASSURANCE_ACK_UNIX_MS: &str = "1766000080000";
const ASSURANCE_EVAL_UNIX_MS: &str = "1766000060000";

/// Port of `check-chio-pheromone-relay-alert-assurance.sh`: the full
/// evaluate -> trend -> handoff -> normalize -> delivery import -> acknowledge
/// -> drift-window -> review -> assurance package flow with its generated-report
/// assertions, followed by the inline-token normalization negative.
fn assurance_cli_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("alert-assurance")?;
    let assurance_dir = root.join(&facet.fixture_dir);
    let relay_dir = assurance_dir
        .parent()
        .ok_or_else(|| invalid("assurance fixture dir has no parent relay dir"))?
        .to_path_buf();
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let generated = scratch.path.clone();
    let normalized = scratch.join("normalized");
    fs::create_dir_all(&normalized).map_err(|err| XtaskError::Io(display(&normalized), err))?;

    let routing_profile = relay_dir.join("relay-alert-routing-profile.json");
    let handoff_profile = relay_dir.join("relay-alert-handoff-profile.json");
    let degraded = relay_dir.join("relay-observability-degraded-report.json");
    let suppression_state = relay_dir.join("relay-alert-suppression-state.json");
    let delivery_profile = assurance_dir.join("relay-alert-delivery-profile.json");
    let normalization_profile = assurance_dir.join("relay-alert-normalization-profile.json");
    let owner_profile = assurance_dir.join("relay-alert-route-owner-profile.json");

    let alert_report = generated.join("relay-alert-report.json");
    let trend_report = generated.join("relay-trend-report.json");
    let handoff_report = generated.join("relay-alert-handoff-report.json");
    let normalization_report = generated.join("relay-alert-normalization-report.json");
    let delivery_report = generated.join("relay-alert-delivery-report.json");
    let ack_report = generated.join("relay-alert-acknowledgement-report.json");
    let drift_report = generated.join("relay-alert-delivery-drift-report.json");
    let review_packet = generated.join("relay-alert-route-review-packet.json");
    let assurance_package = generated.join("relay-alert-assurance-package.json");

    // evaluate (at the script's eval anchor, not the assurance NOW anchor).
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "evaluate",
            "--observability-report", &display(&degraded),
            "--event-dir", &display(&relay_dir),
            "--routing-profile", &display(&routing_profile),
            "--suppression-state", &display(&suppression_state),
            "--now-unix-ms", ASSURANCE_EVAL_UNIX_MS,
            "--report", &display(&alert_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-alert-report.schema.json"), &alert_report)?;

    // trend
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "trend",
            "--reports-dir", &display(&relay_dir),
            "--event-dir", &display(&relay_dir),
            "--routing-profile", &display(&routing_profile),
            "--since-unix-ms", ALERT_SINCE_UNIX_MS,
            "--until-unix-ms", ASSURANCE_EVAL_UNIX_MS,
            "--report", &display(&trend_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-trend-report.schema.json"), &trend_report)?;

    // handoff
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "handoff",
            "--alert-report", &display(&alert_report),
            "--trend-report", &display(&trend_report),
            "--routing-profile", &display(&routing_profile),
            "--handoff-profile", &display(&handoff_profile),
            "--now-unix-ms", ASSURANCE_EVAL_UNIX_MS,
            "--report", &display(&handoff_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-handoff-report.schema.json"),
        &handoff_report,
    )?;

    // normalize the downstream drops into canonical delivery evidence.
    let downstream = assurance_dir.join("downstream");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "normalize",
            "--profile", &display(&normalization_profile),
            "--input-dir", &display(&downstream),
            "--now-unix-ms", ASSURANCE_NORMALIZE_UNIX_MS,
            "--out-dir", &display(&normalized),
            "--report", &display(&normalization_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-normalization-report.schema.json"),
        &normalization_report,
    )?;
    for evidence in glob_documents(&normalized, None)? {
        validate_document(
            &schema_dir.join("relay-alert-delivery-evidence.schema.json"),
            &evidence,
        )?;
    }

    // delivery import (from the normalized evidence).
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "import",
            "--handoff-report", &display(&handoff_report),
            "--delivery-profile", &display(&delivery_profile),
            "--evidence-dir", &display(&normalized),
            "--now-unix-ms", ASSURANCE_NORMALIZE_UNIX_MS,
            "--report", &display(&delivery_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-delivery-report.schema.json"),
        &delivery_report,
    )?;

    // acknowledge
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "acknowledge",
            "--handoff-report", &display(&handoff_report),
            "--delivery-report", &display(&delivery_report),
            "--delivery-profile", &display(&delivery_profile),
            "--now-unix-ms", ASSURANCE_ACK_UNIX_MS,
            "--report", &display(&ack_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-acknowledgement-report.schema.json"),
        &ack_report,
    )?;

    // delivery drift-window (source-bound)
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "delivery", "drift-window",
            "--handoff-reports-dir", &display(&generated),
            "--delivery-reports-dir", &display(&generated),
            "--delivery-profile", &display(&delivery_profile),
            "--since-unix-ms", ALERT_SINCE_UNIX_MS,
            "--until-unix-ms", ASSURANCE_NOW_UNIX_MS,
            "--report", &display(&drift_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-delivery-drift-report.schema.json"),
        &drift_report,
    )?;

    // review
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "review",
            "--handoff-report", &display(&handoff_report),
            "--delivery-report", &display(&delivery_report),
            "--acknowledgement-report", &display(&ack_report),
            "--drift-report", &display(&drift_report),
            "--route-owner-profile", &display(&owner_profile),
            "--now-unix-ms", ASSURANCE_NOW_UNIX_MS,
            "--report", &display(&review_packet),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-route-review-packet.schema.json"),
        &review_packet,
    )?;

    // assurance package (binds the whole chain).
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "package",
            "--alert-report", &display(&alert_report),
            "--trend-report", &display(&trend_report),
            "--handoff-report", &display(&handoff_report),
            "--normalization-report", &display(&normalization_report),
            "--delivery-report", &display(&delivery_report),
            "--acknowledgement-report", &display(&ack_report),
            "--drift-report", &display(&drift_report),
            "--review-packet", &display(&review_packet),
            "--now-unix-ms", ASSURANCE_NOW_UNIX_MS,
            "--report", &display(&assurance_package),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-package.schema.json"),
        &assurance_package,
    )?;

    assurance_assert_generated(&normalization_report, &drift_report, &assurance_package)?;

    // Negative: an inline-token downstream drop must fail normalization.
    assurance_inline_token_negative(root, &scratch, &normalization_profile)
}

/// The assurance script's generated-report assertions: normalization covered all
/// three downstream drops, the source-bound drift is clean, and the package
/// preserves the unhealthy active-alert state.
fn assurance_assert_generated(
    normalization_report: &Path,
    drift_report: &Path,
    assurance_package: &Path,
) -> Result<(), XtaskError> {
    let normalization = load_json(normalization_report)?;
    if normalization.get("accepted") != Some(&Value::Bool(true))
        || normalization.get("normalizedCount").and_then(Value::as_i64) != Some(3)
    {
        return Err(invalid(
            "generated normalization report must normalize all downstream drops",
        ));
    }
    let drift = load_json(drift_report)?;
    if drift.get("accepted") != Some(&Value::Bool(true))
        || drift.get("driftCount").and_then(Value::as_i64) != Some(0)
    {
        return Err(invalid(
            "generated source-bound delivery drift report must be accepted",
        ));
    }
    let assurance = load_json(assurance_package)?;
    if assurance.get("accepted") != Some(&Value::Bool(false)) {
        return Err(invalid("generated assurance package must preserve unhealthy state"));
    }
    let has_active = assurance
        .get("operatorActionCodes")
        .and_then(Value::as_array)
        .map(|codes| {
            codes
                .iter()
                .any(|c| c.as_str() == Some("active_alerts_present"))
        })
        .unwrap_or(false);
    if !has_active {
        return Err(invalid("generated assurance package missing active-alert action"));
    }
    Ok(())
}

/// Materialize an inline-token downstream drop and confirm `alert normalize`
/// rejects it (the script's normalization negative).
fn assurance_inline_token_negative(
    root: &Path,
    scratch: &ScratchDir,
    normalization_profile: &Path,
) -> Result<(), XtaskError> {
    let input_dir = scratch.join("negative-input");
    let out_dir = scratch.join("negative-normalized");
    fs::create_dir_all(&input_dir).map_err(|err| XtaskError::Io(display(&input_dir), err))?;
    fs::create_dir_all(&out_dir).map_err(|err| XtaskError::Io(display(&out_dir), err))?;
    let drop = serde_json::json!({
        "receiverId": "alertmanager-pagerduty-primary",
        "alertCode": "dead_letters_present",
        "severity": "critical",
        "status": "delivered",
        "observedAtUnixMs": 1_766_000_065_000_i64,
        "sourceHandoffReportSha256":
            "7c1d1ed0df1b7557e17c0c849313e14801382cf8d183f22e95d1139392b9f0e9",
        "apiToken": "not-allowed",
    });
    write_json(&input_dir.join("inline-token.json"), &drop)?;
    let report = scratch.join("negative-report.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "normalize",
            "--profile", &display(normalization_profile),
            "--input-dir", &display(&input_dir),
            "--now-unix-ms", ASSURANCE_NORMALIZE_UNIX_MS,
            "--out-dir", &display(&out_dir),
            "--report", &display(&report),
        ],
        "expected inline-token normalization negative to fail",
    )
}
