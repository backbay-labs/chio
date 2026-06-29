use crate::{
    canonical_sha256, PheromoneRelayError, PHEROMONE_RELAY_ALERT_DEDUPE_PREFIX,
    PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
    PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};
use std::collections::BTreeMap;

use super::{
    active_suppression_until, alert_labels, alert_route_map, alert_rule_map, bump_trend_point,
    handoff_escalation_map, handoff_receiver_route_map, is_bounded_code, matching_event_evidence,
    relay_alert_severity_from_str, validate_alert_profile, validate_handoff_profile,
    validate_handoff_sources, validate_observability_source, validate_suppression_state,
    RelayAlert, RelayAlertCheck, RelayAlertEvaluationInput, RelayAlertHandoffInput,
    RelayAlertHandoffReport, RelayAlertHandoffRouteReadiness, RelayAlertReport, RelayAlertSeverity,
    RelayTrendInput, RelayTrendPoint, RelayTrendReport,
};

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
                "{}:{}:{}:{}",
                PHEROMONE_RELAY_ALERT_DEDUPE_PREFIX,
                input.observability.local_kernel_id,
                rule.alert_code,
                route.route_id
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
