use super::*;

pub(crate) fn validate_delivery_profile(
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_handoff_report_age_ms == 0
        || profile.max_evidence_age_ms == 0
        || profile.max_acknowledgement_age_ms == 0
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile age limits must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile has no downstream receivers".to_string(),
        ));
    }
    let mut receiver_ids = BTreeSet::new();
    let mut target_refs = BTreeSet::new();
    let mut route_keys = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_delivery_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery receiver {}",
                receiver.receiver_id
            )));
        }
        if !target_refs.insert(receiver.target_ref.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery target {}",
                receiver.target_ref
            )));
        }
        let route_key = (
            receiver.notification_route.as_str(),
            receiver.opsgenie.as_str(),
        );
        if !route_keys.insert(route_key) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate delivery route coverage".to_string(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_normalization_profile(
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_source_age_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile source age must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile has no downstream receivers".to_string(),
        ));
    }
    let mut receiver_ids = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_delivery_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate normalization receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(())
}
pub(crate) fn validate_delivery_receiver(
    receiver: &RelayAlertDeliveryReceiver,
) -> Result<(), PheromoneRelayError> {
    if receiver.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery receiver sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("receiver_id", receiver.receiver_id.as_str()),
        ("target_ref", receiver.target_ref.as_str()),
        ("notification_route", receiver.notification_route.as_str()),
        ("opsgenie", receiver.opsgenie.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if receiver.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery target ref must not be a dynamic URL".to_string(),
        ));
    }
    if receiver.runbook.trim().is_empty()
        || receiver.runbook.contains("://")
        || contains_secret_marker(&receiver.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery runbook must be a local non-secret reference".to_string(),
        ));
    }
    if receiver.max_delay_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery receiver delay bound must be positive".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_delivery_token(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery field {field} is not bounded"
        )));
    }
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery field {field} appears to contain secret material"
        )));
    }
    Ok(())
}
pub(crate) fn validate_delivery_evidence_shape(
    evidence: &RelayAlertDeliveryEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    if evidence.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("result_id", evidence.result_id.as_str()),
        ("receiver_id", evidence.receiver_id.as_str()),
        ("target_ref", evidence.target_ref.as_str()),
        ("notification_route", evidence.notification_route.as_str()),
        ("opsgenie", evidence.opsgenie.as_str()),
        ("dedupe_key", evidence.dedupe_key.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if !is_bounded_code(&evidence.alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery alert code is not bounded".to_string(),
        ));
    }
    if evidence.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence target ref must not be a dynamic URL".to_string(),
        ));
    }
    if evidence.runbook.trim().is_empty()
        || evidence.runbook.contains("://")
        || contains_secret_marker(&evidence.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence runbook must be a local non-secret reference".to_string(),
        ));
    }
    if !is_sha256_hex(&evidence.source_handoff_report_sha256)
        || !is_sha256_hex(&evidence.downstream_evidence_sha256)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence hash is invalid".to_string(),
        ));
    }
    validate_delivery_labels(&evidence.labels, evidence)?;
    Ok(())
}
pub(crate) fn validate_delivery_labels(
    labels: &BTreeMap<String, String>,
    evidence: &RelayAlertDeliveryEvidence,
) -> Result<(), PheromoneRelayError> {
    for (name, value) in labels {
        if !matches!(
            name.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity" | "status" | "receiver"
        ) || !is_bounded_route_token(value)
            || contains_secret_marker(value)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence contains an unbounded label".to_string(),
            ));
        }
    }
    if labels.get("notification_route") != Some(&evidence.notification_route)
        || labels.get("opsgenie") != Some(&evidence.opsgenie)
        || labels.get("severity").map(String::as_str) != Some(evidence.severity.as_str())
        || labels.get("status").map(String::as_str) != Some(evidence.status.as_str())
        || labels.get("receiver") != Some(&evidence.receiver_id)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence labels do not match delivery fields".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_delivery_handoff_report(
    report: &RelayAlertHandoffReport,
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if !report.accepted || report.code != "accepted" {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report is not accepted".to_string(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(report.generated_at_unix_ms) > profile.max_handoff_report_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report is stale for delivery import".to_string(),
        ));
    }
    if !is_sha256_hex(&report.source_alert_report_sha256)
        || !is_sha256_hex(&report.source_trend_report_sha256)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report source hash is invalid".to_string(),
        ));
    }
    if report.firing_alert_count > 0 && report.routes.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report has firing alerts without route readiness".to_string(),
        ));
    }
    for route in &report.routes {
        if !route.ready {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "handoff route {} is not ready",
                route.receiver_id
            )));
        }
        validate_delivery_token("receiver_id", &route.receiver_id)?;
        validate_delivery_token("target_ref", &route.target_ref)?;
        validate_delivery_token("notification_route", &route.notification_route)?;
        validate_delivery_token("opsgenie", &route.opsgenie)?;
        validate_delivery_token("escalation_ref", &route.escalation_ref)?;
        if route.kind == RelayAlertHandoffSinkKind::Unknown {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route sink kind is unknown".to_string(),
            ));
        }
        if route.target_ref.contains("://") {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route target ref must not be a dynamic URL".to_string(),
            ));
        }
        if route.alert_codes.is_empty() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route has no alert codes".to_string(),
            ));
        }
        for alert_code in &route.alert_codes {
            if !is_bounded_code(alert_code) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "handoff route alert code is not bounded".to_string(),
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn validate_delivery_report(
    report: &RelayAlertDeliveryReport,
    handoff: &RelayAlertHandoffReport,
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report timestamp is in the future".to_string(),
        ));
    }
    if report.source_handoff_report_sha256 != canonical_sha256(handoff)? {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report source handoff hash mismatch".to_string(),
        ));
    }
    if report.source_alert_report_sha256 != handoff.source_alert_report_sha256
        || report.source_trend_report_sha256 != handoff.source_trend_report_sha256
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report source alert or trend hash mismatch".to_string(),
        ));
    }
    let receiver_map = delivery_receiver_map(profile)?;
    let route_map = handoff_route_map(handoff)?;
    let mut seen = BTreeSet::new();
    for result in &report.results {
        validate_delivery_result(result)?;
        if !seen.insert((result.receiver_id.as_str(), result.alert_code.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate delivery report result".to_string(),
            ));
        }
        let receiver = receiver_map
            .get(result.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "delivery report references unknown receiver {}",
                    result.receiver_id
                ))
            })?;
        let route = route_map.get(result.receiver_id.as_str()).ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery report receiver {} is absent from handoff",
                result.receiver_id
            ))
        })?;
        if result.target_ref != receiver.target_ref
            || result.target_ref != route.target_ref
            || result.notification_route != receiver.notification_route
            || result.notification_route != route.notification_route
            || result.opsgenie != receiver.opsgenie
            || result.opsgenie != route.opsgenie
            || result.runbook != receiver.runbook
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report result does not match trusted delivery profile".to_string(),
            ));
        }
        if !route.alert_codes.contains(&result.alert_code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report result alert is not in handoff".to_string(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_delivery_result(
    result: &RelayAlertDeliveryResult,
) -> Result<(), PheromoneRelayError> {
    for (field, value) in [
        ("result_id", result.result_id.as_str()),
        ("receiver_id", result.receiver_id.as_str()),
        ("target_ref", result.target_ref.as_str()),
        ("notification_route", result.notification_route.as_str()),
        ("opsgenie", result.opsgenie.as_str()),
        ("dedupe_key", result.dedupe_key.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if !is_bounded_code(&result.alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report alert code is not bounded".to_string(),
        ));
    }
    if result.runbook.trim().is_empty()
        || result.runbook.contains("://")
        || contains_secret_marker(&result.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report runbook must be a local non-secret reference".to_string(),
        ));
    }
    if !is_sha256_hex(&result.downstream_evidence_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report evidence hash is invalid".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_route_owner_profile(
    profile: &RelayAlertRouteOwnerProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_report_age_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile report age must be positive".to_string(),
        ));
    }
    if profile.owners.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile has no owners".to_string(),
        ));
    }
    let mut owner_aliases = BTreeSet::new();
    let mut receiver_ids = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for owner in &profile.owners {
        validate_delivery_token("owner_alias", &owner.owner_alias)?;
        if !owner_aliases.insert(owner.owner_alias.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate route owner {}",
                owner.owner_alias
            )));
        }
        if owner.receiver_ids.is_empty() || owner.notification_routes.is_empty() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "route owner must cover receivers and notification routes".to_string(),
            ));
        }
        for receiver_id in &owner.receiver_ids {
            validate_delivery_token("receiver_id", receiver_id)?;
            if !receiver_ids.insert(receiver_id.as_str()) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner receiver {receiver_id}"
                )));
            }
        }
        for route in &owner.notification_routes {
            validate_delivery_token("notification_route", route)?;
            if !routes.insert(route.as_str()) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner notification route {route}"
                )));
            }
        }
        if owner.runbook.trim().is_empty()
            || owner.runbook.contains("://")
            || contains_secret_marker(&owner.runbook)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "route owner runbook must be a local non-secret reference".to_string(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_review_source_chain(
    input: &RelayAlertRouteReviewInput<'_>,
) -> Result<(), PheromoneRelayError> {
    let local_kernel_id = input.handoff_report.local_kernel_id.as_str();
    for (name, candidate) in [
        ("delivery", input.delivery_report.local_kernel_id.as_str()),
        (
            "acknowledgement",
            input.acknowledgement_report.local_kernel_id.as_str(),
        ),
        ("drift", input.drift_report.local_kernel_id.as_str()),
        (
            "route owner profile",
            input.route_owner_profile.local_kernel_id.as_str(),
        ),
    ] {
        if candidate != local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} local kernel id mismatch"
            )));
        }
    }
    for (name, generated_at) in [
        ("handoff report", input.handoff_report.generated_at_unix_ms),
        (
            "delivery report",
            input.delivery_report.generated_at_unix_ms,
        ),
        (
            "acknowledgement report",
            input.acknowledgement_report.generated_at_unix_ms,
        ),
        ("drift report", input.drift_report.generated_at_unix_ms),
    ] {
        if generated_at > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} timestamp is in the future"
            )));
        }
        if input.now_unix_ms.saturating_sub(generated_at)
            > input.route_owner_profile.max_report_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} is stale for route review"
            )));
        }
    }
    if input.delivery_report.source_handoff_report_sha256 != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route review source hash mismatch".to_string(),
        ));
    }
    Ok(())
}
