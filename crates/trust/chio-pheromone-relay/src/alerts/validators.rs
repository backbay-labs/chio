use crate::RelayObservabilityReport;
use crate::{
    is_sha256_hex, PheromoneRelayError, PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA,
    PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA, PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA,
    PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::{
    alert_route_map, alert_rule_map, is_bounded_code, is_bounded_route_token, reject_secret_marker,
    relay_alert_severity_from_str, require_alert_recommendation, validate_handoff_token,
    RelayAlertHandoffInput, RelayAlertHandoffProfileDocument, RelayAlertHandoffReceiver,
    RelayAlertHandoffSinkKind, RelayAlertRoute, RelayAlertRoutingProfileDocument,
    RelayAlertSeverity, RelayAlertSuppressionStateDocument,
};

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
