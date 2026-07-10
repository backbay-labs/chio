use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssurancePackage {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub source_handoff_report_sha256: String,
    pub source_normalization_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub source_acknowledgement_report_sha256: String,
    pub source_drift_report_sha256: String,
    pub source_review_packet_sha256: String,
    pub firing_alert_count: u64,
    pub critical_firing_alert_count: u64,
    pub normalized_count: u64,
    pub ready_route_count: u64,
    pub delivery_attention_count: u64,
    pub acknowledgement_pending_count: u64,
    pub drift_count: u64,
    pub operator_action_codes: Vec<String>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportArtifact {
    pub role: String,
    pub schema: String,
    pub path: String,
    pub sha256: String,
    pub byte_count: u64,
    pub retention_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportManifestBody {
    pub schema: String,
    pub bundle_id: String,
    pub local_kernel_id: String,
    pub exporter_id: String,
    pub exporter_key_id: String,
    pub exported_at_unix_ms: u64,
    pub source_package_sha256: String,
    pub artifacts: Vec<RelayAlertAssuranceExportArtifact>,
    pub safety_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportManifest {
    pub schema: String,
    pub body: RelayAlertAssuranceExportManifestBody,
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub source_package_sha256: String,
    pub artifact_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportBundle {
    pub manifest: RelayAlertAssuranceExportManifest,
    pub report: RelayAlertAssuranceExportReport,
    pub files: Vec<RelayAlertAssuranceExportFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedExporter {
    pub exporter_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedExportersDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub min_exported_at_unix_ms: u64,
    pub exporters: Vec<RelayAlertAssuranceTrustedExporter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionRule {
    pub artifact_role: String,
    pub retain_for_ms: u64,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub warning_window_ms: u64,
    pub rules: Vec<RelayAlertAssuranceRetentionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceReplayReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_id: String,
    pub source_package_sha256: String,
    pub replayed_package_sha256: String,
    pub mismatch_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAlertAssuranceRetentionState {
    Retain,
    ExpiringSoon,
    EligibleForDelete,
    Blocked,
    Missing,
    Quarantine,
}

impl RelayAlertAssuranceRetentionState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Retain => "retain",
            Self::ExpiringSoon => "expiring_soon",
            Self::EligibleForDelete => "eligible_for_delete",
            Self::Blocked => "blocked",
            Self::Missing => "missing",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionEntry {
    pub bundle_id: String,
    pub artifact_role: String,
    pub path: String,
    pub state: String,
    pub retain_until_unix_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub retained_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_delete_count: u64,
    pub blocked_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub entries: Vec<RelayAlertAssuranceRetentionEntry>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRecoveryDrill {
    pub case_id: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRecoveryDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub drill_count: u64,
    pub drills: Vec<RelayAlertAssuranceRecoveryDrill>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertAssuranceInput<'a> {
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub normalization_report: &'a RelayAlertNormalizationReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReport,
    pub review_packet: &'a RelayAlertRouteReviewPacket,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceExportBuildInput<'a> {
    pub bundle_id: &'a str,
    pub exporter_id: &'a str,
    pub exporter_key_id: &'a str,
    pub signing_key: &'a Keypair,
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub normalization_report: &'a RelayAlertNormalizationReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReport,
    pub review_packet: &'a RelayAlertRouteReviewPacket,
    pub assurance_package: &'a RelayAlertAssurancePackage,
    pub normalized_delivery_evidence: &'a [RelayAlertDeliveryEvidence],
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub exported_at_unix_ms: u64,
}

pub struct RelayAlertAssuranceReplayInput<'a> {
    pub bundle: &'a RelayAlertAssuranceExportBundle,
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceRetentionInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceExportBundle],
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceRecoveryDrillInput<'a> {
    pub bundle: &'a RelayAlertAssuranceExportBundle,
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub case_id: &'a str,
    pub now_unix_ms: u64,
}
