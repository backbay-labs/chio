use crate::{
    canonical_sha256, contains_secret_marker, delivery_receiver_map, handoff_route_map,
    is_bounded_code, is_bounded_route_token, is_sha256_hex, relay_alert_severity_from_str,
    validate_alert_profile, validate_handoff_profile, validate_suppression_state,
    PheromoneRelayError, RelayAlertCheck, RelayAlertHandoffProfileDocument,
    RelayAlertHandoffReport, RelayAlertHandoffSinkKind, RelayAlertRoutingProfileDocument,
    RelayAlertSeverity, RelayAlertSuppressionStateDocument,
    PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_V2_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAlertDeliveryStatus {
    Delivered,
    Accepted,
    Failed,
    Delayed,
    Duplicate,
    Unknown,
    OperatorAcknowledged,
}

impl RelayAlertDeliveryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Accepted => "accepted",
            Self::Failed => "failed",
            Self::Delayed => "delayed",
            Self::Duplicate => "duplicate",
            Self::Unknown => "unknown",
            Self::OperatorAcknowledged => "operator_acknowledged",
        }
    }

    #[must_use]
    pub const fn requires_attention(self) -> bool {
        matches!(self, Self::Failed | Self::Delayed | Self::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryReceiver {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub severity_floor: RelayAlertSeverity,
    pub max_delay_ms: u64,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_handoff_report_age_ms: u64,
    pub max_evidence_age_ms: u64,
    pub max_acknowledgement_age_ms: u64,
    pub receivers: Vec<RelayAlertDeliveryReceiver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryEvidence {
    pub schema: String,
    pub local_kernel_id: String,
    pub observed_at_unix_ms: u64,
    pub result_id: String,
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub severity: RelayAlertSeverity,
    pub runbook: String,
    pub status: RelayAlertDeliveryStatus,
    pub source_handoff_report_sha256: String,
    pub downstream_evidence_sha256: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryResult {
    pub result_id: String,
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub severity: RelayAlertSeverity,
    pub runbook: String,
    pub status: RelayAlertDeliveryStatus,
    pub observed_at_unix_ms: u64,
    pub downstream_evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub critical_firing_count: u64,
    pub delivered_count: u64,
    pub delayed_count: u64,
    pub failed_count: u64,
    pub unknown_count: u64,
    pub results: Vec<RelayAlertDeliveryResult>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAcknowledgement {
    pub result_id: String,
    pub receiver_id: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub status: RelayAlertDeliveryStatus,
    pub acknowledged_at_unix_ms: u64,
    pub downstream_evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAcknowledgementReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub acknowledged_count: u64,
    pub pending_count: u64,
    pub failed_count: u64,
    pub acknowledgements: Vec<RelayAlertAcknowledgement>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffDrift {
    pub code: String,
    pub receiver_id: String,
    pub alert_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffDriftReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub handoff_report_count: u64,
    pub delivery_report_count: u64,
    pub drift_count: u64,
    pub drifts: Vec<RelayAlertHandoffDrift>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertNormalizationProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_source_age_ms: u64,
    pub receivers: Vec<RelayAlertDeliveryReceiver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertNormalizationReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_count: u64,
    pub normalized_count: u64,
    pub evidence_hashes: Vec<String>,
    pub evidence: Vec<RelayAlertDeliveryEvidence>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryDriftV2 {
    pub code: String,
    pub source_handoff_report_sha256: String,
    pub matched_delivery_report_sha256: Option<String>,
    pub receiver_id: String,
    pub alert_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryDriftReportV2 {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub handoff_report_count: u64,
    pub delivery_report_count: u64,
    pub drift_count: u64,
    pub drifts: Vec<RelayAlertDeliveryDriftV2>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteOwner {
    pub owner_alias: String,
    pub receiver_ids: Vec<String>,
    pub notification_routes: Vec<String>,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteOwnerProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_report_age_ms: u64,
    pub owners: Vec<RelayAlertRouteOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteReview {
    pub owner_alias: String,
    pub receiver_id: String,
    pub notification_route: String,
    pub alert_codes: Vec<String>,
    pub status: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteReviewPacket {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub source_acknowledgement_report_sha256: String,
    pub source_drift_report_sha256: String,
    pub ready_route_count: u64,
    pub owner_review_count: u64,
    pub reviews: Vec<RelayAlertRouteReview>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertDeliveryInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub evidence: &'a [RelayAlertDeliveryEvidence],
    pub now_unix_ms: u64,
}

pub struct RelayAlertAcknowledgementInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertHandoffDriftInput<'a> {
    pub handoff_reports: &'a [RelayAlertHandoffReport],
    pub delivery_reports: &'a [RelayAlertDeliveryReport],
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

pub struct RelayAlertNormalizationInput<'a> {
    pub profile: &'a RelayAlertNormalizationProfileDocument,
    pub sources: &'a [Value],
    pub now_unix_ms: u64,
}

pub struct RelayAlertDeliveryDriftInputV2<'a> {
    pub handoff_reports: &'a [RelayAlertHandoffReport],
    pub delivery_reports: &'a [RelayAlertDeliveryReport],
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

pub struct RelayAlertRouteReviewInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReportV2,
    pub route_owner_profile: &'a RelayAlertRouteOwnerProfileDocument,
    pub now_unix_ms: u64,
}

pub fn relay_alert_routing_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertRoutingProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertRoutingProfileDocument = serde_json::from_str(json)?;
    validate_alert_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_suppression_state_from_json(
    json: &str,
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<RelayAlertSuppressionStateDocument, PheromoneRelayError> {
    let state: RelayAlertSuppressionStateDocument = serde_json::from_str(json)?;
    validate_suppression_state(&state, profile)?;
    Ok(state)
}

pub fn relay_alert_handoff_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertHandoffProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertHandoffProfileDocument = serde_json::from_str(json)?;
    validate_handoff_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertDeliveryProfileDocument = serde_json::from_str(json)?;
    validate_delivery_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_evidence_from_json(
    json: &str,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    let evidence: RelayAlertDeliveryEvidence = serde_json::from_str(json)?;
    validate_delivery_evidence_shape(&evidence)?;
    Ok(evidence)
}

pub fn evaluate_relay_alert_delivery(
    input: RelayAlertDeliveryInput<'_>,
) -> Result<RelayAlertDeliveryReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let receiver_map = delivery_receiver_map(input.delivery_profile)?;
    let route_map = handoff_route_map(input.handoff_report)?;
    let mut seen_results = BTreeSet::new();
    let mut seen_alerts = BTreeSet::new();
    let mut results = Vec::new();
    let mut delayed_count = 0u64;
    let mut failed_count = 0u64;
    let mut unknown_count = 0u64;

    for evidence in input.evidence {
        validate_delivery_evidence_shape(evidence)?;
        if evidence.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence local kernel id mismatch".to_string(),
            ));
        }
        if evidence.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence timestamp is in the future".to_string(),
            ));
        }
        if input
            .now_unix_ms
            .saturating_sub(evidence.observed_at_unix_ms)
            > input.delivery_profile.max_evidence_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is stale".to_string(),
            ));
        }
        if evidence.source_handoff_report_sha256 != source_handoff_report_sha256 {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is not bound to the handoff report".to_string(),
            ));
        }
        if !seen_results.insert(evidence.result_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery result {}",
                evidence.result_id
            )));
        }
        let receiver = receiver_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "delivery evidence references unknown receiver {}",
                    evidence.receiver_id
                ))
            })?;
        let route = route_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "handoff report has no route for receiver {}",
                    evidence.receiver_id
                ))
            })?;
        if evidence.kind != receiver.kind
            || evidence.kind != route.kind
            || evidence.target_ref != receiver.target_ref
            || evidence.target_ref != route.target_ref
            || evidence.notification_route != receiver.notification_route
            || evidence.notification_route != route.notification_route
            || evidence.opsgenie != receiver.opsgenie
            || evidence.opsgenie != route.opsgenie
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence route does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.runbook != receiver.runbook {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence runbook does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.severity < receiver.severity_floor || evidence.severity < route.highest_severity
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence weakens alert severity for {}",
                evidence.alert_code
            )));
        }
        if !route.alert_codes.contains(&evidence.alert_code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence alert {} is not in handoff route",
                evidence.alert_code
            )));
        }
        if !seen_alerts.insert((evidence.receiver_id.as_str(), evidence.alert_code.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery evidence for alert {}",
                evidence.alert_code
            )));
        }
        if evidence.status == RelayAlertDeliveryStatus::Delayed {
            delayed_count = delayed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Unknown {
            unknown_count = unknown_count.saturating_add(1);
        }
        results.push(RelayAlertDeliveryResult {
            result_id: evidence.result_id.clone(),
            receiver_id: evidence.receiver_id.clone(),
            kind: evidence.kind,
            target_ref: evidence.target_ref.clone(),
            notification_route: evidence.notification_route.clone(),
            opsgenie: evidence.opsgenie.clone(),
            alert_code: evidence.alert_code.clone(),
            dedupe_key: evidence.dedupe_key.clone(),
            severity: evidence.severity,
            runbook: evidence.runbook.clone(),
            status: evidence.status,
            observed_at_unix_ms: evidence.observed_at_unix_ms,
            downstream_evidence_sha256: evidence.downstream_evidence_sha256.clone(),
        });
    }

    let mut missing = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        for alert_code in &route.alert_codes {
            if !seen_alerts.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                missing.push((route.receiver_id.clone(), alert_code.clone()));
            }
        }
    }
    if !missing.is_empty() {
        let rendered = missing
            .iter()
            .map(|(receiver, alert)| format!("{receiver}:{alert}"))
            .collect::<Vec<_>>()
            .join(",");
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "missing delivery evidence for {rendered}"
        )));
    }

    results.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let delivered_count = results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                RelayAlertDeliveryStatus::Delivered
                    | RelayAlertDeliveryStatus::Accepted
                    | RelayAlertDeliveryStatus::Duplicate
                    | RelayAlertDeliveryStatus::OperatorAcknowledged
            )
        })
        .count() as u64;
    let accepted = delayed_count == 0 && failed_count == 0 && unknown_count == 0;
    Ok(RelayAlertDeliveryReport {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_alert_report_sha256: input.handoff_report.source_alert_report_sha256.clone(),
        source_trend_report_sha256: input.handoff_report.source_trend_report_sha256.clone(),
        critical_firing_count: input.handoff_report.critical_firing_count,
        delivered_count,
        delayed_count,
        failed_count,
        unknown_count,
        results,
        checks: vec![
            RelayAlertCheck {
                code: "handoff_report".to_string(),
                accepted: true,
                detail: "handoff report is fresh and hash-bound".to_string(),
            },
            RelayAlertCheck {
                code: "delivery_evidence".to_string(),
                accepted,
                detail: "downstream delivery evidence covers every handoff alert".to_string(),
            },
        ],
    })
}

pub fn evaluate_relay_alert_acknowledgement(
    input: RelayAlertAcknowledgementInput<'_>,
) -> Result<RelayAlertAcknowledgementReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    validate_delivery_report(
        input.delivery_report,
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let mut acknowledgements = Vec::new();
    let mut acknowledged_count = 0u64;
    let mut pending_count = 0u64;
    let mut failed_count = 0u64;
    for result in &input.delivery_report.results {
        if result.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result timestamp is in the future".to_string(),
            ));
        }
        if input.now_unix_ms.saturating_sub(result.observed_at_unix_ms)
            > input.delivery_profile.max_acknowledgement_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result is stale for acknowledgement".to_string(),
            ));
        }
        if result.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if result.status.requires_attention() {
            pending_count = pending_count.saturating_add(1);
        } else {
            acknowledged_count = acknowledged_count.saturating_add(1);
        }
        acknowledgements.push(RelayAlertAcknowledgement {
            result_id: result.result_id.clone(),
            receiver_id: result.receiver_id.clone(),
            alert_code: result.alert_code.clone(),
            dedupe_key: result.dedupe_key.clone(),
            status: result.status,
            acknowledged_at_unix_ms: input.now_unix_ms,
            downstream_evidence_sha256: result.downstream_evidence_sha256.clone(),
        });
    }
    let accepted = pending_count == 0 && failed_count == 0;
    Ok(RelayAlertAcknowledgementReport {
        schema: PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "acknowledgement_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256: input.delivery_report.source_handoff_report_sha256.clone(),
        source_delivery_report_sha256,
        acknowledged_count,
        pending_count,
        failed_count,
        acknowledgements,
        checks: vec![RelayAlertCheck {
            code: "delivery_report".to_string(),
            accepted,
            detail: "delivery outcomes are summarized without notifying downstream systems"
                .to_string(),
        }],
    })
}

pub fn generate_relay_alert_handoff_drift_report(
    input: RelayAlertHandoffDriftInput<'_>,
) -> Result<RelayAlertHandoffDriftReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;
    let mut drifts = Vec::new();
    let mut delivery_index = BTreeMap::<(String, String), &RelayAlertDeliveryResult>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        delivery_report_count = delivery_report_count.saturating_add(1);
        for result in &report.results {
            delivery_index.insert(
                (result.receiver_id.clone(), result.alert_code.clone()),
                result,
            );
        }
    }

    let mut handoff_report_count = 0u64;
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(handoff, input.delivery_profile, input.until_unix_ms)?;
        handoff_report_count = handoff_report_count.saturating_add(1);
        for route in &handoff.routes {
            for alert_code in &route.alert_codes {
                let key = (route.receiver_id.clone(), alert_code.clone());
                match delivery_index.get(&key) {
                    Some(result) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "severity_weakening".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "route_alias_drift".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "delivery_attention_required".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertHandoffDrift {
                        code: "missing_delivery_result".to_string(),
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no downstream delivery evidence".to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertHandoffDriftReport {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "handoff_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "handoff_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and downstream delivery reports intersect by bounded route aliases"
                .to_string(),
        }],
    })
}

pub fn normalize_relay_alert_delivery_evidence(
    input: RelayAlertNormalizationInput<'_>,
) -> Result<RelayAlertNormalizationReport, PheromoneRelayError> {
    validate_normalization_profile(input.profile, input.now_unix_ms)?;
    if input.sources.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization input has no downstream sources".to_string(),
        ));
    }
    let receivers = normalization_receiver_map(input.profile)?;
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for source in input.sources {
        reject_downstream_source_secrets(source)?;
        let normalized =
            normalize_downstream_source(source, &receivers, input.profile, input.now_unix_ms)?;
        let key = (
            normalized.source_handoff_report_sha256.clone(),
            normalized.receiver_id.clone(),
            normalized.alert_code.clone(),
        );
        if !seen.insert(key) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "normalization source mapping is ambiguous".to_string(),
            ));
        }
        evidence.push(normalized);
    }
    evidence.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let evidence_hashes = evidence
        .iter()
        .map(canonical_sha256)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RelayAlertNormalizationReport {
        schema: PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_count: input.sources.len() as u64,
        normalized_count: evidence.len() as u64,
        evidence_hashes,
        evidence,
        checks: vec![RelayAlertCheck {
            code: "normalization".to_string(),
            accepted: true,
            detail: "local downstream exports normalized into Chio delivery evidence".to_string(),
        }],
    })
}

pub fn generate_relay_alert_delivery_drift_report_v2(
    input: RelayAlertDeliveryDriftInputV2<'_>,
) -> Result<RelayAlertDeliveryDriftReportV2, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;

    let mut handoffs_by_hash = BTreeMap::new();
    let mut ordered_handoffs = Vec::new();
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(
            handoff,
            input.delivery_profile,
            handoff.generated_at_unix_ms,
        )?;
        let hash = canonical_sha256(handoff)?;
        if handoffs_by_hash.insert(hash.clone(), handoff).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate handoff report hash in drift window".to_string(),
            ));
        }
        ordered_handoffs.push((hash, handoff));
    }

    let mut drifts = Vec::new();
    let mut delivery_index =
        BTreeMap::<(String, String, String), (&RelayAlertDeliveryResult, String)>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.schema != PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(
                report.schema.clone(),
            ));
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        let report_hash = canonical_sha256(report)?;
        delivery_report_count = delivery_report_count.saturating_add(1);
        if !handoffs_by_hash.contains_key(&report.source_handoff_report_sha256) {
            drifts.push(RelayAlertDeliveryDriftV2 {
                code: "unbound_delivery_report".to_string(),
                source_handoff_report_sha256: report.source_handoff_report_sha256.clone(),
                matched_delivery_report_sha256: Some(report_hash.clone()),
                receiver_id: "unknown".to_string(),
                alert_code: "unknown".to_string(),
                detail: "delivery report source handoff hash is outside the review window"
                    .to_string(),
            });
        }
        for result in &report.results {
            validate_delivery_result(result)?;
            let key = (
                report.source_handoff_report_sha256.clone(),
                result.receiver_id.clone(),
                result.alert_code.clone(),
            );
            if delivery_index
                .insert(key, (result, report_hash.clone()))
                .is_some()
            {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "duplicate delivery result across drift reports".to_string(),
                ));
            }
        }
    }

    if ordered_handoffs.is_empty() && delivery_report_count == 0 {
        drifts.push(RelayAlertDeliveryDriftV2 {
            code: "no_window_evidence".to_string(),
            source_handoff_report_sha256: "0".repeat(64),
            matched_delivery_report_sha256: None,
            receiver_id: "unknown".to_string(),
            alert_code: "unknown".to_string(),
            detail: "no handoff or delivery reports were present in the requested window"
                .to_string(),
        });
    }

    for (handoff_hash, handoff) in &ordered_handoffs {
        for route in handoff.routes.iter().filter(|route| route.ready) {
            for alert_code in &route.alert_codes {
                let key = (
                    handoff_hash.clone(),
                    route.receiver_id.clone(),
                    alert_code.clone(),
                );
                match delivery_index.get(&key) {
                    Some((result, report_hash)) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "severity_weakening".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "route_alias_drift".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "delivery_attention_required".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertDeliveryDriftV2 {
                        code: "missing_delivery_result".to_string(),
                        source_handoff_report_sha256: handoff_hash.clone(),
                        matched_delivery_report_sha256: None,
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no source-bound downstream delivery evidence"
                            .to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertDeliveryDriftReportV2 {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_V2_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count: ordered_handoffs.len() as u64,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "source_bound_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and delivery reports intersect by source handoff hash".to_string(),
        }],
    })
}

pub fn generate_relay_alert_route_review_packet(
    input: RelayAlertRouteReviewInput<'_>,
) -> Result<RelayAlertRouteReviewPacket, PheromoneRelayError> {
    validate_route_owner_profile(input.route_owner_profile, input.now_unix_ms)?;
    validate_review_source_chain(&input)?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let source_acknowledgement_report_sha256 = canonical_sha256(input.acknowledgement_report)?;
    let source_drift_report_sha256 = canonical_sha256(input.drift_report)?;
    let owner_map = route_owner_map(input.route_owner_profile)?;
    let drift_keys = input
        .drift_report
        .drifts
        .iter()
        .map(|drift| (drift.receiver_id.as_str(), drift.alert_code.as_str()))
        .collect::<BTreeSet<_>>();
    let delivery_status = input
        .delivery_report
        .results
        .iter()
        .map(|result| {
            (
                (result.receiver_id.as_str(), result.alert_code.as_str()),
                result.status,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reviews = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        let owner = owner_map.get(route.receiver_id.as_str()).ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "route owner missing for receiver {}",
                route.receiver_id
            ))
        })?;
        let mut status = "ready";
        for alert_code in &route.alert_codes {
            if drift_keys.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                status = "attention_required";
            }
            if delivery_status
                .get(&(route.receiver_id.as_str(), alert_code.as_str()))
                .is_some_and(|delivery_status| delivery_status.requires_attention())
            {
                status = "attention_required";
            }
        }
        reviews.push(RelayAlertRouteReview {
            owner_alias: owner.owner_alias.clone(),
            receiver_id: route.receiver_id.clone(),
            notification_route: route.notification_route.clone(),
            alert_codes: route.alert_codes.clone(),
            status: status.to_string(),
            runbook: owner.runbook.clone(),
        });
    }
    reviews.sort_by(|left, right| {
        left.owner_alias
            .cmp(&right.owner_alias)
            .then_with(|| left.receiver_id.cmp(&right.receiver_id))
    });
    let accepted = input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && reviews.iter().all(|review| review.status == "ready");
    Ok(RelayAlertRouteReviewPacket {
        schema: PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "route_review_attention_required"
        }
        .to_string(),
        local_kernel_id: input.handoff_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_delivery_report_sha256,
        source_acknowledgement_report_sha256,
        source_drift_report_sha256,
        ready_route_count: input
            .handoff_report
            .routes
            .iter()
            .filter(|route| route.ready)
            .count() as u64,
        owner_review_count: reviews.len() as u64,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "route_owner_review".to_string(),
            accepted,
            detail: "route owners are bound to handoff and delivery evidence".to_string(),
        }],
    })
}

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

pub(crate) fn normalization_receiver_map(
    profile: &RelayAlertNormalizationProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertDeliveryReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        if receivers
            .insert(receiver.receiver_id.as_str(), receiver)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate normalization receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(receivers)
}

pub(crate) fn normalize_downstream_source(
    source: &Value,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    if source
        .get("schema")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
    {
        let evidence: RelayAlertDeliveryEvidence = serde_json::from_value(source.clone())?;
        validate_delivery_evidence_shape(&evidence)?;
        validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
        return Ok(evidence);
    }

    let receiver_id = json_string(source, &["receiverId", "receiver_id", "receiver"])?;
    let receiver = receivers.get(receiver_id.as_str()).ok_or_else(|| {
        PheromoneRelayError::AlertDeliveryInvalid(format!(
            "normalization receiver {receiver_id} is unknown"
        ))
    })?;
    let alert_code = json_string(source, &["alertCode", "alert_code", "alertname"])?;
    if !is_bounded_code(&alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized alert code is not bounded".to_string(),
        ));
    }
    let observed_at_unix_ms = json_u64(source, &["observedAtUnixMs", "observed_at_unix_ms"])?;
    if observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source is stale".to_string(),
        ));
    }
    let status = relay_alert_delivery_status_from_str(
        json_string(source, &["status", "outcome"])?.as_str(),
    )?;
    let severity = relay_alert_severity_from_str(json_string(source, &["severity"])?.as_str())
        .map_err(|error| PheromoneRelayError::AlertDeliveryInvalid(error.to_string()))?;
    let source_handoff_report_sha256 = json_string(
        source,
        &["sourceHandoffReportSha256", "source_handoff_report_sha256"],
    )?;
    if !is_sha256_hex(&source_handoff_report_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source handoff hash is invalid".to_string(),
        ));
    }
    let dedupe_key = json_string(source, &["dedupeKey", "dedupe_key", "fingerprint"])?;
    if !is_bounded_route_token(&dedupe_key) || contains_secret_marker(&dedupe_key) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization dedupe key is not bounded".to_string(),
        ));
    }
    let runbook = json_string(source, &["runbook", "runbook_ref"])
        .unwrap_or_else(|_| receiver.runbook.clone());
    if runbook.trim().is_empty() || runbook.contains("://") || contains_secret_marker(&runbook) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization runbook must be a local non-secret reference".to_string(),
        ));
    }
    let downstream_evidence_sha256 = json_string(
        source,
        &["downstreamEvidenceSha256", "downstream_evidence_sha256"],
    )
    .unwrap_or(canonical_sha256(source)?);
    if !is_sha256_hex(&downstream_evidence_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization downstream evidence hash is invalid".to_string(),
        ));
    }
    let result_id = json_string(source, &["resultId", "result_id"])
        .unwrap_or_else(|_| format!("normalized:{receiver_id}:{alert_code}"));
    validate_delivery_token("result_id", &result_id)?;
    let mut labels = json_labels(source)?;
    labels
        .entry("notification_route".to_string())
        .or_insert_with(|| receiver.notification_route.clone());
    labels
        .entry("opsgenie".to_string())
        .or_insert_with(|| receiver.opsgenie.clone());
    labels
        .entry("service".to_string())
        .or_insert_with(|| "chiodos-pheromone-relay".to_string());
    labels
        .entry("severity".to_string())
        .or_insert_with(|| severity.as_str().to_string());
    labels
        .entry("status".to_string())
        .or_insert_with(|| status.as_str().to_string());
    labels
        .entry("receiver".to_string())
        .or_insert_with(|| receiver.receiver_id.clone());

    let evidence = RelayAlertDeliveryEvidence {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: profile.local_kernel_id.clone(),
        observed_at_unix_ms,
        result_id,
        receiver_id: receiver.receiver_id.clone(),
        kind: receiver.kind,
        target_ref: receiver.target_ref.clone(),
        notification_route: receiver.notification_route.clone(),
        opsgenie: receiver.opsgenie.clone(),
        alert_code,
        dedupe_key,
        severity,
        runbook,
        status,
        source_handoff_report_sha256,
        downstream_evidence_sha256,
        labels,
    };
    validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
    Ok(evidence)
}

pub(crate) fn validate_normalized_evidence(
    evidence: &RelayAlertDeliveryEvidence,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    validate_delivery_evidence_shape(evidence)?;
    if evidence.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence local kernel id mismatch".to_string(),
        ));
    }
    if evidence.observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(evidence.observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence is stale".to_string(),
        ));
    }
    let receiver = receivers
        .get(evidence.receiver_id.as_str())
        .ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "normalization receiver {} is unknown",
                evidence.receiver_id
            ))
        })?;
    validate_evidence_matches_receiver(evidence, receiver)
}

pub(crate) fn validate_evidence_matches_receiver(
    evidence: &RelayAlertDeliveryEvidence,
    receiver: &RelayAlertDeliveryReceiver,
) -> Result<(), PheromoneRelayError> {
    if evidence.kind != receiver.kind
        || evidence.target_ref != receiver.target_ref
        || evidence.notification_route != receiver.notification_route
        || evidence.opsgenie != receiver.opsgenie
        || evidence.severity < receiver.severity_floor
        || evidence.runbook != receiver.runbook
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence does not match receiver contract".to_string(),
        ));
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

pub(crate) fn relay_alert_delivery_status_from_str(
    value: &str,
) -> Result<RelayAlertDeliveryStatus, PheromoneRelayError> {
    match value {
        "delivered" => Ok(RelayAlertDeliveryStatus::Delivered),
        "accepted" => Ok(RelayAlertDeliveryStatus::Accepted),
        "failed" => Ok(RelayAlertDeliveryStatus::Failed),
        "delayed" => Ok(RelayAlertDeliveryStatus::Delayed),
        "duplicate" => Ok(RelayAlertDeliveryStatus::Duplicate),
        "unknown" => Ok(RelayAlertDeliveryStatus::Unknown),
        "operator_acknowledged" => Ok(RelayAlertDeliveryStatus::OperatorAcknowledged),
        _ => Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery status {value} is not supported"
        ))),
    }
}

pub(crate) fn json_string(value: &Value, names: &[&str]) -> Result<String, PheromoneRelayError> {
    for name in names {
        if let Some(text) = value.get(*name).and_then(Value::as_str) {
            if text.trim().is_empty() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "field {name} is empty"
                )));
            }
            return Ok(text.to_string());
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing field {}",
        names.join("/")
    )))
}

pub(crate) fn json_u64(value: &Value, names: &[&str]) -> Result<u64, PheromoneRelayError> {
    for name in names {
        if let Some(number) = value.get(*name).and_then(Value::as_u64) {
            return Ok(number);
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing numeric field {}",
        names.join("/")
    )))
}

pub(crate) fn json_labels(value: &Value) -> Result<BTreeMap<String, String>, PheromoneRelayError> {
    let mut labels = BTreeMap::new();
    if let Some(raw_labels) = value.get("labels") {
        let object = raw_labels.as_object().ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(
                "normalization labels must be an object".to_string(),
            )
        })?;
        for (name, value) in object {
            let text = value.as_str().ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(
                    "normalization label value must be a string".to_string(),
                )
            })?;
            labels.insert(name.clone(), text.to_string());
        }
    }
    Ok(labels)
}

pub(crate) fn reject_downstream_source_secrets(value: &Value) -> Result<(), PheromoneRelayError> {
    match value {
        Value::String(text) => {
            if text.contains("://") || contains_secret_marker(text) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "downstream source contains secret material or a dynamic URL".to_string(),
                ));
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Object(object) => {
            for (name, item) in object {
                if contains_secret_marker(name) || name.to_ascii_lowercase().contains("url") {
                    return Err(PheromoneRelayError::AlertDeliveryInvalid(
                        "downstream source contains secret material or a dynamic URL".to_string(),
                    ));
                }
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
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

pub(crate) fn route_owner_map(
    profile: &RelayAlertRouteOwnerProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertRouteOwner>, PheromoneRelayError> {
    let mut owners = BTreeMap::new();
    for owner in &profile.owners {
        for receiver_id in &owner.receiver_ids {
            if owners.insert(receiver_id.as_str(), owner).is_some() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner receiver {receiver_id}"
                )));
            }
        }
    }
    Ok(owners)
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
