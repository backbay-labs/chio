use crate::{
    canonical_sha256, PheromoneRelayError, RelayAlertDeliveryProfileDocument,
    RelayAlertDeliveryReceiver, PHEROMONE_RELAY_EVENT_REPORT_SCHEMA, PHEROMONE_RELAY_SERVICE_LABEL,
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::{
    RelayAlertEvaluationInput, RelayAlertHandoffEscalation, RelayAlertHandoffProfileDocument,
    RelayAlertHandoffReceiver, RelayAlertHandoffReport, RelayAlertHandoffRouteReadiness,
    RelayAlertRoute, RelayAlertRoutingProfileDocument, RelayAlertRule, RelayAlertSeverity,
    RelayAlertSuppressionStateDocument, RelayTrendPoint,
};

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
    labels.insert(
        "service".to_string(),
        PHEROMONE_RELAY_SERVICE_LABEL.to_string(),
    );
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
