use super::*;

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
pub struct RelayAlertDeliveryDrift {
    pub code: String,
    pub source_handoff_report_sha256: String,
    pub matched_delivery_report_sha256: Option<String>,
    pub receiver_id: String,
    pub alert_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryDriftReport {
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
    pub drifts: Vec<RelayAlertDeliveryDrift>,
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

pub struct RelayAlertDeliveryDriftInput<'a> {
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
    pub drift_report: &'a RelayAlertDeliveryDriftReport,
    pub route_owner_profile: &'a RelayAlertRouteOwnerProfileDocument,
    pub now_unix_ms: u64,
}
