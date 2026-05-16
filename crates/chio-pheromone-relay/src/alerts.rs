use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayEventReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub event_kind: String,
    pub stable_failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayAlertRouteKind {
    PagerDuty,
    OpsGenie,
    Slack,
    Email,
    Webhook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayAlertSeverity {
    Info,
    Warning,
    Critical,
}

impl RelayAlertSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRoute {
    pub route_id: String,
    pub kind: RelayAlertRouteKind,
    pub notification_route: String,
    pub opsgenie: String,
    pub target_ref: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRule {
    pub alert_code: String,
    pub route_id: String,
    pub severity: RelayAlertSeverity,
    pub min_window_ms: u64,
    pub unsuppressible: bool,
    pub require_event_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRoutingProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_source_age_ms: u64,
    pub max_suppression_ms: u64,
    pub allowed_label_names: Vec<String>,
    pub routes: Vec<RelayAlertRoute>,
    pub rules: Vec<RelayAlertRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertSuppressionEntry {
    pub alert_code: String,
    pub route_id: String,
    pub reason: String,
    pub starts_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertSuppressionStateDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub entries: Vec<RelayAlertSuppressionEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlert {
    pub code: String,
    pub state: String,
    pub severity: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub dedupe_key: String,
    pub runbook: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub window_ms: u64,
    pub suppressed_until_unix_ms: Option<u64>,
    pub source_report_sha256: String,
    pub event_evidence_sha256: Vec<String>,
    pub recommendation_codes: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_report_sha256: String,
    pub alerts: Vec<RelayAlert>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertEvaluationInput<'a> {
    pub observability: &'a RelayObservabilityReport,
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub suppression_state: Option<&'a RelayAlertSuppressionStateDocument>,
    pub event_reports: &'a [RelayEventReport],
    pub now_unix_ms: u64,
    pub expected_source_report_sha256: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrendPoint {
    pub code: String,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrendReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub source_report_count: u64,
    pub event_report_count: u64,
    pub points: Vec<RelayTrendPoint>,
}

pub struct RelayTrendInput<'a> {
    pub local_kernel_id: &'a str,
    pub observability_reports: &'a [RelayObservabilityReport],
    pub event_reports: &'a [RelayEventReport],
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayAlertHandoffSinkKind {
    #[serde(rename = "alertmanager")]
    Alertmanager,
    #[serde(rename = "pagerduty")]
    PagerDuty,
    #[serde(rename = "opsgenie")]
    OpsGenie,
    #[serde(rename = "slack")]
    Slack,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "webhook")]
    Webhook,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffReceiver {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub severity_floor: RelayAlertSeverity,
    pub escalation_ref: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffEscalation {
    pub escalation_ref: String,
    pub severity: RelayAlertSeverity,
    pub max_delay_ms: u64,
    pub recommendation_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_alert_report_age_ms: u64,
    pub max_trend_report_age_ms: u64,
    pub receivers: Vec<RelayAlertHandoffReceiver>,
    pub escalations: Vec<RelayAlertHandoffEscalation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffRouteReadiness {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub highest_severity: RelayAlertSeverity,
    pub alert_codes: Vec<String>,
    pub escalation_ref: String,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub firing_alert_count: u64,
    pub suppressed_alert_count: u64,
    pub critical_firing_count: u64,
    pub routes: Vec<RelayAlertHandoffRouteReadiness>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDrill {
    pub drill_id: String,
    pub scenario: String,
    pub expected_code: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub drills: Vec<RelayAlertDrill>,
}

pub struct RelayAlertHandoffInput<'a> {
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub handoff_profile: &'a RelayAlertHandoffProfileDocument,
    pub now_unix_ms: u64,
}

pub fn evaluate_relay_alerts(
    input: RelayAlertEvaluationInput<'_>,
) -> Result<RelayAlertReport, PheromoneRelayError> {
    validate_alert_profile(input.routing_profile, input.now_unix_ms)?;
    if let Some(state) = input.suppression_state {
        validate_suppression_state(state, input.routing_profile)?;
    }
    validate_observability_source(
        input.observability,
        input.routing_profile,
        input.now_unix_ms,
    )?;
    let source_report_sha256 = canonical_sha256(input.observability)?;
    if let Some(expected) = input.expected_source_report_sha256 {
        if expected != source_report_sha256 {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "observability report hash does not match caller expectation".to_string(),
            ));
        }
    }

    let routes = alert_route_map(input.routing_profile)?;
    let rules = alert_rule_map(input.routing_profile)?;
    let mut checks = vec![RelayAlertCheck {
        code: "source_report".to_string(),
        accepted: true,
        detail: "observability report is current and hash-bound".to_string(),
    }];
    let mut alerts = Vec::new();
    let recommendation_codes = input
        .observability
        .recommendations
        .iter()
        .map(|recommendation| recommendation.code.clone())
        .collect::<Vec<_>>();

    for recommendation in &input.observability.recommendations {
        let rule = rules.get(&recommendation.code).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "recommendation code {} has no alert rule",
                recommendation.code
            ))
        })?;
        let route = routes.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert route {} is not defined",
                rule.route_id
            ))
        })?;
        let event_evidence_sha256 = matching_event_evidence(&recommendation.code, &input)?;
        if rule.require_event_evidence && event_evidence_sha256.is_empty() {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} requires bounded event evidence",
                recommendation.code
            )));
        }
        let suppressed_until_unix_ms = if rule.unsuppressible {
            None
        } else {
            active_suppression_until(
                input.suppression_state,
                &rule.alert_code,
                &rule.route_id,
                input.now_unix_ms,
            )
        };
        let state = if suppressed_until_unix_ms.is_some() {
            "suppressed"
        } else {
            "firing"
        };
        let labels = alert_labels(route, rule)?;
        alerts.push(RelayAlert {
            code: rule.alert_code.clone(),
            state: state.to_string(),
            severity: rule.severity.as_str().to_string(),
            notification_route: route.notification_route.clone(),
            opsgenie: route.opsgenie.clone(),
            dedupe_key: format!(
                "chiodos-relay:{}:{}:{}",
                input.observability.local_kernel_id, rule.alert_code, route.route_id
            ),
            runbook: route.runbook.clone(),
            first_seen_unix_ms: input.observability.generated_at_unix_ms,
            last_seen_unix_ms: input.now_unix_ms,
            window_ms: rule.min_window_ms,
            suppressed_until_unix_ms,
            source_report_sha256: source_report_sha256.clone(),
            event_evidence_sha256,
            recommendation_codes: recommendation_codes.clone(),
            labels,
        });
    }
    let accepted = alerts.iter().all(|alert| alert.state == "suppressed");
    checks.push(RelayAlertCheck {
        code: "routing_profile".to_string(),
        accepted: true,
        detail: "alert routing profile uses bounded routes and labels".to_string(),
    });
    Ok(RelayAlertReport {
        schema: PHEROMONE_RELAY_ALERT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "alerts_firing"
        }
        .to_string(),
        local_kernel_id: input.observability.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_report_sha256,
        alerts,
        checks,
    })
}

pub fn evaluate_relay_alert_handoff(
    input: RelayAlertHandoffInput<'_>,
) -> Result<RelayAlertHandoffReport, PheromoneRelayError> {
    validate_alert_profile(input.routing_profile, input.now_unix_ms)?;
    validate_handoff_profile(input.handoff_profile, input.now_unix_ms)?;
    validate_handoff_sources(&input)?;
    let source_alert_report_sha256 = canonical_sha256(input.alert_report)?;
    let source_trend_report_sha256 = canonical_sha256(input.trend_report)?;
    let route_map = alert_route_map(input.routing_profile)?;
    let rule_map = alert_rule_map(input.routing_profile)?;
    let receiver_by_route = handoff_receiver_route_map(input.handoff_profile)?;
    let escalation_by_ref = handoff_escalation_map(input.handoff_profile)?;
    for route in route_map.values() {
        let receiver = receiver_by_route
            .get(&(route.notification_route.clone(), route.opsgenie.clone()))
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "route {} has no downstream handoff receiver",
                    route.route_id
                ))
            })?;
        if receiver.target_ref != route.target_ref || receiver.runbook != route.runbook {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "route {} handoff target does not match routing profile",
                route.route_id
            )));
        }
    }

    let mut checks = vec![
        RelayAlertCheck {
            code: "alert_report".to_string(),
            accepted: true,
            detail: "alert report is fresh and schema-bound".to_string(),
        },
        RelayAlertCheck {
            code: "trend_report".to_string(),
            accepted: true,
            detail: "trend report is fresh and schema-bound".to_string(),
        },
        RelayAlertCheck {
            code: "route_coverage".to_string(),
            accepted: true,
            detail: "every routing profile route has a downstream handoff receiver".to_string(),
        },
    ];
    let mut route_readiness = BTreeMap::<String, RelayAlertHandoffRouteReadiness>::new();
    let mut firing_alert_count = 0u64;
    let mut suppressed_alert_count = 0u64;
    let mut critical_firing_count = 0u64;

    for alert in &input.alert_report.alerts {
        if alert.state == "suppressed" {
            suppressed_alert_count = suppressed_alert_count.saturating_add(1);
            continue;
        }
        if alert.state != "firing" {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has unsupported state {}",
                alert.code, alert.state
            )));
        }
        firing_alert_count = firing_alert_count.saturating_add(1);
        let severity = relay_alert_severity_from_str(&alert.severity)?;
        if severity == RelayAlertSeverity::Critical {
            critical_firing_count = critical_firing_count.saturating_add(1);
        }
        let rule = rule_map.get(&alert.code).ok_or_else(|| {
            PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has no routing profile rule",
                alert.code
            ))
        })?;
        let route = route_map.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} does not resolve to a routing profile route",
                alert.code
            ))
        })?;
        let receiver = receiver_by_route
            .get(&(route.notification_route.clone(), route.opsgenie.clone()))
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "alert {} has no downstream handoff receiver",
                    alert.code
                ))
            })?;
        if severity < receiver.severity_floor {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} severity is below receiver floor",
                alert.code
            )));
        }
        let escalation = escalation_by_ref
            .get(receiver.escalation_ref.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "alert {} has no downstream escalation mapping",
                    alert.code
                ))
            })?;
        if severity > escalation.severity {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} severity exceeds downstream escalation mapping",
                alert.code
            )));
        }
        let readiness = route_readiness
            .entry(receiver.target_ref.clone())
            .or_insert_with(|| RelayAlertHandoffRouteReadiness {
                receiver_id: receiver.receiver_id.clone(),
                kind: receiver.kind,
                target_ref: receiver.target_ref.clone(),
                notification_route: receiver.notification_route.clone(),
                opsgenie: receiver.opsgenie.clone(),
                highest_severity: severity,
                alert_codes: Vec::new(),
                escalation_ref: receiver.escalation_ref.clone(),
                ready: true,
            });
        if severity > readiness.highest_severity {
            readiness.highest_severity = severity;
        }
        if !readiness.alert_codes.contains(&alert.code) {
            readiness.alert_codes.push(alert.code.clone());
        }
    }

    checks.push(RelayAlertCheck {
        code: "handoff_dry_run".to_string(),
        accepted: true,
        detail: "all firing alerts are routeable without sending notifications".to_string(),
    });
    Ok(RelayAlertHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.alert_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_alert_report_sha256,
        source_trend_report_sha256,
        firing_alert_count,
        suppressed_alert_count,
        critical_firing_count,
        routes: route_readiness.into_values().collect(),
        checks,
    })
}

pub fn generate_relay_trend_report(
    input: RelayTrendInput<'_>,
) -> Result<RelayTrendReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend lower bound is after upper bound".to_string(),
        ));
    }
    validate_alert_profile(input.routing_profile, input.until_unix_ms)?;
    let rule_map = alert_rule_map(input.routing_profile)?;
    let mut points: BTreeMap<String, RelayTrendPoint> = BTreeMap::new();
    let mut source_report_count = 0u64;
    for report in input.observability_reports {
        if report.local_kernel_id != input.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "observability report local kernel id mismatch".to_string(),
            ));
        }
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        source_report_count = source_report_count.saturating_add(1);
        for recommendation in &report.recommendations {
            let rule = rule_map.get(&recommendation.code).ok_or_else(|| {
                PheromoneRelayError::AlertRoutingInvalid(format!(
                    "recommendation code {} has no trend rule",
                    recommendation.code
                ))
            })?;
            bump_trend_point(
                &mut points,
                &recommendation.code,
                rule.severity.as_str(),
                report.generated_at_unix_ms,
            )?;
        }
    }
    let mut event_report_count = 0u64;
    for event in input.event_reports {
        if event.local_kernel_id != input.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report local kernel id mismatch".to_string(),
            ));
        }
        if event.generated_at_unix_ms < input.since_unix_ms
            || event.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        event_report_count = event_report_count.saturating_add(1);
        let code = event
            .stable_failure_code
            .as_deref()
            .unwrap_or(event.code.as_str());
        if !is_bounded_code(code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "event code {code} is not bounded"
            )));
        }
        bump_trend_point(&mut points, code, "warning", event.generated_at_unix_ms)?;
    }
    Ok(RelayTrendReport {
        schema: PHEROMONE_RELAY_TREND_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.local_kernel_id.to_string(),
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        source_report_count,
        event_report_count,
        points: points.into_values().collect(),
    })
}

pub(crate) fn validate_alert_profile(
    profile: &RelayAlertRoutingProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_source_age_ms == 0 || profile.max_suppression_ms == 0 {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile time bounds must be positive".to_string(),
        ));
    }
    let allowed_labels = profile
        .allowed_label_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in ["notification_route", "opsgenie", "service", "severity"] {
        if !allowed_labels.contains(required) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "routing profile is missing bounded label {required}"
            )));
        }
    }
    let mut route_ids = BTreeSet::new();
    let mut route_targets = BTreeSet::new();
    for route in &profile.routes {
        validate_alert_route(route)?;
        if !route_ids.insert(route.route_id.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert route {}",
                route.route_id
            )));
        }
        let target = (
            route.notification_route.as_str(),
            route.opsgenie.as_str(),
            route.target_ref.as_str(),
        );
        if !route_targets.insert(target) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "duplicate alert route target".to_string(),
            ));
        }
    }
    if route_ids.is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile has no routes".to_string(),
        ));
    }
    let mut alert_codes = BTreeSet::new();
    for rule in &profile.rules {
        if !is_bounded_code(&rule.alert_code) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert code {} is not bounded",
                rule.alert_code
            )));
        }
        if !route_ids.contains(rule.route_id.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "rule {} references unknown route {}",
                rule.alert_code, rule.route_id
            )));
        }
        if !alert_codes.insert(rule.alert_code.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert rule {}",
                rule.alert_code
            )));
        }
    }
    if alert_codes.is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile has no rules".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_alert_route(route: &RelayAlertRoute) -> Result<(), PheromoneRelayError> {
    for (field, value) in [
        ("route_id", route.route_id.as_str()),
        ("notification_route", route.notification_route.as_str()),
        ("opsgenie", route.opsgenie.as_str()),
        ("target_ref", route.target_ref.as_str()),
    ] {
        if !is_bounded_route_token(value) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert route field {field} is not bounded"
            )));
        }
        reject_secret_marker(field, value)?;
    }
    if route.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "alert route target ref must not be a dynamic URL".to_string(),
        ));
    }
    if route.runbook.trim().is_empty()
        || route.runbook.contains("://")
        || route.runbook.to_ascii_lowercase().contains("token")
    {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "alert route runbook must be a local non-secret reference".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_handoff_profile(
    profile: &RelayAlertHandoffProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_alert_report_age_ms == 0 || profile.max_trend_report_age_ms == 0 {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile age limits must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile has no downstream receivers".to_string(),
        ));
    }
    if profile.escalations.is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile has no escalation mappings".to_string(),
        ));
    }
    let mut escalation_refs = BTreeMap::new();
    for escalation in &profile.escalations {
        validate_handoff_token("escalation_ref", &escalation.escalation_ref)?;
        if escalation_refs
            .insert(escalation.escalation_ref.as_str(), escalation.severity)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate escalation {}",
                escalation.escalation_ref
            )));
        }
        if escalation.max_delay_ms == 0 || !is_bounded_code(&escalation.recommendation_code) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "handoff escalation has invalid bounds".to_string(),
            ));
        }
    }
    let mut receiver_ids = BTreeSet::new();
    let mut target_refs = BTreeSet::new();
    let mut route_keys = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_handoff_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate receiver {}",
                receiver.receiver_id
            )));
        }
        if !target_refs.insert(receiver.target_ref.as_str()) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate receiver target {}",
                receiver.target_ref
            )));
        }
        let route_key = (
            receiver.notification_route.as_str(),
            receiver.opsgenie.as_str(),
        );
        if !route_keys.insert(route_key) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "duplicate handoff route coverage".to_string(),
            ));
        }
        let escalation_severity = escalation_refs
            .get(receiver.escalation_ref.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "receiver {} references unknown escalation {}",
                    receiver.receiver_id, receiver.escalation_ref
                ))
            })?;
        if receiver.severity_floor > *escalation_severity {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "receiver {} severity floor exceeds escalation {}",
                receiver.receiver_id, receiver.escalation_ref
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_handoff_receiver(
    receiver: &RelayAlertHandoffReceiver,
) -> Result<(), PheromoneRelayError> {
    if receiver.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff receiver sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("receiver_id", receiver.receiver_id.as_str()),
        ("target_ref", receiver.target_ref.as_str()),
        ("notification_route", receiver.notification_route.as_str()),
        ("opsgenie", receiver.opsgenie.as_str()),
        ("escalation_ref", receiver.escalation_ref.as_str()),
    ] {
        validate_handoff_token(field, value)?;
    }
    if receiver.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff target ref must not be a dynamic URL".to_string(),
        ));
    }
    if receiver.runbook.trim().is_empty()
        || receiver.runbook.contains("://")
        || receiver.runbook.to_ascii_lowercase().contains("token")
    {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff runbook must be a local non-secret reference".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn delivery_receiver_map(
    profile: &RelayAlertDeliveryProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertDeliveryReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        if receivers
            .insert(receiver.receiver_id.as_str(), receiver)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(receivers)
}

pub(crate) fn handoff_route_map(
    report: &RelayAlertHandoffReport,
) -> Result<BTreeMap<&str, &RelayAlertHandoffRouteReadiness>, PheromoneRelayError> {
    let mut routes = BTreeMap::new();
    for route in &report.routes {
        if routes.insert(route.receiver_id.as_str(), route).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate handoff route {}",
                route.receiver_id
            )));
        }
    }
    Ok(routes)
}

pub(crate) fn validate_handoff_token(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
            "handoff field {field} is not bounded"
        )));
    }
    reject_handoff_secret_marker(field, value)
}

pub(crate) fn reject_handoff_secret_marker(
    field: &str,
    value: &str,
) -> Result<(), PheromoneRelayError> {
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
            "handoff field {field} appears to contain secret material"
        )));
    }
    Ok(())
}

pub(crate) fn reject_secret_marker(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
            "alert route field {field} appears to contain secret material"
        )));
    }
    Ok(())
}

pub(crate) fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "secret", "token", "password", "apikey", "api_key", "api-key", "bearer",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub(crate) fn validate_suppression_state(
    state: &RelayAlertSuppressionStateDocument,
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<(), PheromoneRelayError> {
    if state.schema != PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(state.schema.clone()));
    }
    if state.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "suppression state local kernel id mismatch".to_string(),
        ));
    }
    let rules = alert_rule_map(profile)?;
    let routes = alert_route_map(profile)?;
    let mut seen = BTreeSet::new();
    for entry in &state.entries {
        let rule = rules.get(&entry.alert_code).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "suppression references unknown alert {}",
                entry.alert_code
            ))
        })?;
        if !routes.contains_key(&entry.route_id) || rule.route_id != entry.route_id {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "suppression route {} does not match alert {}",
                entry.route_id, entry.alert_code
            )));
        }
        if entry.starts_at_unix_ms >= entry.expires_at_unix_ms {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression window is empty".to_string(),
            ));
        }
        let window = entry
            .expires_at_unix_ms
            .saturating_sub(entry.starts_at_unix_ms);
        if window > profile.max_suppression_ms {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression window exceeds routing profile maximum".to_string(),
            ));
        }
        if !is_bounded_code(&entry.reason) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression reason is not bounded".to_string(),
            ));
        }
        let key = (&entry.alert_code, &entry.route_id);
        if !seen.insert(key) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate suppression for alert {}",
                entry.alert_code
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_observability_source(
    report: &RelayObservabilityReport,
    profile: &RelayAlertRoutingProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(report.generated_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report is stale".to_string(),
        ));
    }
    for recommendation in &report.recommendations {
        if !is_bounded_code(&recommendation.code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "recommendation code {} is not bounded",
                recommendation.code
            )));
        }
    }
    let recommendation_codes = report
        .recommendations
        .iter()
        .map(|recommendation| recommendation.code.as_str())
        .collect::<BTreeSet<_>>();
    require_alert_recommendation(
        report.queue.dead_letter > 0,
        &recommendation_codes,
        "dead_letters_present",
    )?;
    require_alert_recommendation(
        report.queue.stale_lease_count > 0,
        &recommendation_codes,
        "stale_leases_present",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "relay_nonce_replay" && failure.count > 0),
        &recommendation_codes,
        "relay_nonce_replay",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "endpoint_denied" && failure.count > 0),
        &recommendation_codes,
        "endpoint_denied",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "catchup_denied" && failure.count > 0),
        &recommendation_codes,
        "catchup_denied",
    )?;
    Ok(())
}

pub(crate) fn validate_handoff_sources(
    input: &RelayAlertHandoffInput<'_>,
) -> Result<(), PheromoneRelayError> {
    if input.alert_report.schema != PHEROMONE_RELAY_ALERT_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.alert_report.schema.clone(),
        ));
    }
    if input.trend_report.schema != PHEROMONE_RELAY_TREND_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.trend_report.schema.clone(),
        ));
    }
    let local_kernel_id = input.routing_profile.local_kernel_id.as_str();
    if input.handoff_profile.local_kernel_id != local_kernel_id
        || input.alert_report.local_kernel_id != local_kernel_id
        || input.trend_report.local_kernel_id != local_kernel_id
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "handoff input local kernel id mismatch".to_string(),
        ));
    }
    if input.alert_report.generated_at_unix_ms > input.now_unix_ms
        || input.trend_report.until_unix_ms > input.now_unix_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "handoff source timestamp is in the future".to_string(),
        ));
    }
    if input
        .now_unix_ms
        .saturating_sub(input.alert_report.generated_at_unix_ms)
        > input.handoff_profile.max_alert_report_age_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "alert report is stale for handoff".to_string(),
        ));
    }
    if input
        .now_unix_ms
        .saturating_sub(input.trend_report.until_unix_ms)
        > input.handoff_profile.max_trend_report_age_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend report is stale for handoff".to_string(),
        ));
    }
    if input.trend_report.since_unix_ms > input.trend_report.until_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend report window is invalid".to_string(),
        ));
    }
    if !is_sha256_hex(&input.alert_report.source_report_sha256) {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "alert report source hash is invalid".to_string(),
        ));
    }
    let routes = alert_route_map(input.routing_profile)?;
    let rules = alert_rule_map(input.routing_profile)?;
    let trend_codes = input
        .trend_report
        .points
        .iter()
        .map(|point| point.code.as_str())
        .collect::<BTreeSet<_>>();
    for alert in &input.alert_report.alerts {
        if !is_bounded_code(&alert.code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert code {} is not bounded",
                alert.code
            )));
        }
        let rule = rules.get(&alert.code).ok_or_else(|| {
            PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has no routing profile rule",
                alert.code
            ))
        })?;
        let route = routes.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} route {} is not defined",
                alert.code, rule.route_id
            ))
        })?;
        let severity = relay_alert_severity_from_str(&alert.severity)?;
        if severity != rule.severity {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} severity does not match routing rule",
                alert.code
            )));
        }
        if !matches!(alert.state.as_str(), "firing" | "suppressed") {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has unsupported state {}",
                alert.code, alert.state
            )));
        }
        if alert.state == "suppressed"
            && (rule.unsuppressible || severity == RelayAlertSeverity::Critical)
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} hides an unsuppressible or critical alert",
                alert.code
            )));
        }
        if alert.notification_route != route.notification_route
            || alert.opsgenie != route.opsgenie
            || alert.runbook != route.runbook
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} does not match routing profile route",
                alert.code
            )));
        }
        if rule.require_event_evidence && alert.event_evidence_sha256.is_empty() {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} is missing required event evidence",
                alert.code
            )));
        }
        for evidence_hash in &alert.event_evidence_sha256 {
            if !is_sha256_hex(evidence_hash) {
                return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                    "alert {} event evidence hash is invalid",
                    alert.code
                )));
            }
        }
        if alert.state == "firing" && !trend_codes.contains(alert.code.as_str()) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "trend report omits firing alert {}",
                alert.code
            )));
        }
        if !is_sha256_hex(&alert.source_report_sha256) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} source hash is invalid",
                alert.code
            )));
        }
        if alert.source_report_sha256 != input.alert_report.source_report_sha256 {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} source hash does not match alert report",
                alert.code
            )));
        }
        for (name, value) in &alert.labels {
            if !matches!(
                name.as_str(),
                "notification_route" | "opsgenie" | "service" | "severity"
            ) || !is_bounded_route_token(value)
            {
                return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                    "alert {} contains an unbounded label",
                    alert.code
                )));
            }
        }
        if alert.labels.get("notification_route") != Some(&alert.notification_route)
            || alert.labels.get("opsgenie") != Some(&alert.opsgenie)
            || alert.labels.get("severity") != Some(&alert.severity)
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} labels do not match alert routing fields",
                alert.code
            )));
        }
    }
    for point in &input.trend_report.points {
        if !is_bounded_code(&point.code) || relay_alert_severity_from_str(&point.severity).is_err()
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "trend report contains unbounded point data".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn handoff_escalation_map(
    profile: &RelayAlertHandoffProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertHandoffEscalation>, PheromoneRelayError> {
    let mut escalations = BTreeMap::new();
    for escalation in &profile.escalations {
        if escalations
            .insert(escalation.escalation_ref.as_str(), escalation)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate escalation {}",
                escalation.escalation_ref
            )));
        }
    }
    Ok(escalations)
}

pub(crate) fn require_alert_recommendation(
    required: bool,
    recommendation_codes: &BTreeSet<&str>,
    code: &str,
) -> Result<(), PheromoneRelayError> {
    if required && !recommendation_codes.contains(code) {
        return Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "observability report omitted required {code} recommendation"
        )));
    }
    Ok(())
}

pub(crate) fn handoff_receiver_route_map(
    profile: &RelayAlertHandoffProfileDocument,
) -> Result<BTreeMap<(String, String), RelayAlertHandoffReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        let key = (
            receiver.notification_route.clone(),
            receiver.opsgenie.clone(),
        );
        if receivers.insert(key, receiver.clone()).is_some() {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "duplicate handoff route coverage".to_string(),
            ));
        }
    }
    Ok(receivers)
}

pub(crate) fn alert_route_map(
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<BTreeMap<String, RelayAlertRoute>, PheromoneRelayError> {
    let mut routes = BTreeMap::new();
    for route in &profile.routes {
        if routes
            .insert(route.route_id.clone(), route.clone())
            .is_some()
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert route {}",
                route.route_id
            )));
        }
    }
    Ok(routes)
}

pub(crate) fn alert_rule_map(
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<BTreeMap<String, RelayAlertRule>, PheromoneRelayError> {
    let mut rules = BTreeMap::new();
    for rule in &profile.rules {
        if rules
            .insert(rule.alert_code.clone(), rule.clone())
            .is_some()
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert rule {}",
                rule.alert_code
            )));
        }
    }
    Ok(rules)
}

pub(crate) fn matching_event_evidence(
    alert_code: &str,
    input: &RelayAlertEvaluationInput<'_>,
) -> Result<Vec<String>, PheromoneRelayError> {
    let mut evidence = Vec::new();
    for event in input.event_reports {
        if event.schema != PHEROMONE_RELAY_EVENT_REPORT_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(event.schema.clone()));
        }
        if event.local_kernel_id != input.observability.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report local kernel id mismatch".to_string(),
            ));
        }
        if event.generated_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report timestamp is in the future".to_string(),
            ));
        }
        let stable = event.stable_failure_code.as_deref();
        if event.code == alert_code || stable == Some(alert_code) {
            evidence.push(canonical_sha256(event)?);
        }
    }
    Ok(evidence)
}

pub(crate) fn active_suppression_until(
    state: Option<&RelayAlertSuppressionStateDocument>,
    alert_code: &str,
    route_id: &str,
    now_unix_ms: u64,
) -> Option<u64> {
    let state = state?;
    state
        .entries
        .iter()
        .find(|entry| {
            entry.alert_code == alert_code
                && entry.route_id == route_id
                && entry.starts_at_unix_ms <= now_unix_ms
                && entry.expires_at_unix_ms > now_unix_ms
        })
        .map(|entry| entry.expires_at_unix_ms)
}

pub(crate) fn alert_labels(
    route: &RelayAlertRoute,
    rule: &RelayAlertRule,
) -> Result<BTreeMap<String, String>, PheromoneRelayError> {
    let mut labels = BTreeMap::new();
    labels.insert(
        "notification_route".to_string(),
        route.notification_route.clone(),
    );
    labels.insert("opsgenie".to_string(), route.opsgenie.clone());
    labels.insert("service".to_string(), "chiodos-pheromone-relay".to_string());
    labels.insert("severity".to_string(), rule.severity.as_str().to_string());
    for (name, value) in &labels {
        if !matches!(
            name.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity"
        ) || !is_bounded_route_token(value)
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert label {name} is not bounded"
            )));
        }
    }
    Ok(labels)
}

pub(crate) fn bump_trend_point(
    points: &mut BTreeMap<String, RelayTrendPoint>,
    code: &str,
    severity: &str,
    observed_at_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if !is_bounded_code(code) {
        return Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "trend code {code} is not bounded"
        )));
    }
    points
        .entry(code.to_string())
        .and_modify(|point| {
            point.count = point.count.saturating_add(1);
            point.first_seen_unix_ms = point.first_seen_unix_ms.min(observed_at_unix_ms);
            point.last_seen_unix_ms = point.last_seen_unix_ms.max(observed_at_unix_ms);
        })
        .or_insert_with(|| RelayTrendPoint {
            code: code.to_string(),
            count: 1,
            first_seen_unix_ms: observed_at_unix_ms,
            last_seen_unix_ms: observed_at_unix_ms,
            severity: severity.to_string(),
        });
    Ok(())
}

pub(crate) fn relay_alert_severity_from_str(
    value: &str,
) -> Result<RelayAlertSeverity, PheromoneRelayError> {
    match value {
        "info" => Ok(RelayAlertSeverity::Info),
        "warning" => Ok(RelayAlertSeverity::Warning),
        "critical" => Ok(RelayAlertSeverity::Critical),
        _ => Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "alert severity {value} is not supported"
        ))),
    }
}

pub(crate) fn is_bounded_code(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 96
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-' | '.')
        })
}

pub(crate) fn is_bounded_route_token(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '_' | '-' | '.' | ':' | '/')
        })
}
