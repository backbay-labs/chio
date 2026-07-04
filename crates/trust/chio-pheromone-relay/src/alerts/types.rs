use crate::RelayObservabilityReport;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

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
