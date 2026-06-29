use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use chio_conformance::ResultStatus;
use chio_core::{PublicKey, Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationVerdict {
    Pass,
    Fail,
}

impl CertificationVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CriterionStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationCriterion {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) status: CriterionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationFinding {
    pub(crate) kind: String,
    pub(crate) message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scenario_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) deployment_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<ResultStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationSummary {
    pub(crate) scenario_count: usize,
    pub(crate) result_count: usize,
    pub(crate) evaluated_peer_count: usize,
    pub(crate) pass_count: usize,
    pub(crate) fail_count: usize,
    pub(crate) unsupported_count: usize,
    pub(crate) skipped_count: usize,
    pub(crate) xfail_count: usize,
    pub(crate) missing_scenarios_count: usize,
    pub(crate) unknown_results_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationEvidence {
    pub(crate) evidence_profile: String,
    pub(crate) scenarios_dir: String,
    pub(crate) results_dir: String,
    pub(crate) normalized_scenarios_sha256: String,
    pub(crate) normalized_results_sha256: String,
    pub(crate) generated_report_sha256: String,
    pub(crate) generated_report_bytes: usize,
    pub(crate) generated_report_media_type: String,
    pub(crate) provenance_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) report_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationTarget {
    pub(crate) tool_server_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tool_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationCheckBody {
    pub(crate) schema: String,
    pub(crate) criteria_profile: String,
    pub(crate) checked_at: u64,
    pub(crate) target: CertificationTarget,
    pub(crate) verdict: CertificationVerdict,
    pub(crate) summary: CertificationSummary,
    pub(crate) criteria: Vec<CertificationCriterion>,
    pub(crate) evidence: CertificationEvidence,
    pub(crate) findings: Vec<CertificationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCertificationCheck {
    pub body: CertificationCheckBody,
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationRegistryState {
    Active,
    Superseded,
    Revoked,
}

impl CertificationRegistryState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationResolutionState {
    Active,
    Superseded,
    Revoked,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationDisputeState {
    Open,
    UnderReview,
    ResolvedNoChange,
    ResolvedRevoked,
}

impl CertificationDisputeState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::UnderReview => "under-review",
            Self::ResolvedNoChange => "resolved-no-change",
            Self::ResolvedRevoked => "resolved-revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDisputeRecord {
    pub state: CertificationDisputeState,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDisputeRequest {
    pub state: CertificationDisputeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationRegistryEntry {
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub tool_server_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server_name: Option<String>,
    pub verdict: CertificationVerdict,
    pub checked_at: u64,
    pub published_at: u64,
    pub status: CertificationRegistryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute: Option<CertificationDisputeRecord>,
    pub artifact: SignedCertificationCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationRegistry {
    pub version: String,
    #[serde(default)]
    pub artifacts: BTreeMap<String, CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationRegistryListResponse {
    pub configured: bool,
    pub count: usize,
    pub artifacts: Vec<CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationResolutionResponse {
    pub tool_server_id: String,
    pub state: CertificationResolutionState,
    pub total_entries: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationRevocationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryPeerResult {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CertificationPublicMetadata>,
    #[serde(default)]
    pub metadata_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<CertificationResolutionResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryResponse {
    pub tool_server_id: String,
    pub peer_count: usize,
    pub reachable_count: usize,
    pub active_count: usize,
    pub revoked_count: usize,
    pub superseded_count: usize,
    pub not_found_count: usize,
    pub peers: Vec<CertificationDiscoveryPeerResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationNetworkPublishPeerResult {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationNetworkPublishResponse {
    pub artifact_id: String,
    pub tool_server_id: String,
    pub peer_count: usize,
    pub success_count: usize,
    pub results: Vec<CertificationNetworkPublishPeerResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationNetworkPublishRequest {
    pub artifact: SignedCertificationCheck,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operator_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPublicPublisher {
    pub publisher_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_name: Option<String>,
    pub registry_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationSupportedProfile {
    pub criteria_profile: String,
    pub evidence_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPublicMetadata {
    pub schema: String,
    pub generated_at: u64,
    pub expires_at: u64,
    pub publisher: CertificationPublicPublisher,
    pub public_resolve_path_template: String,
    pub public_search_path: String,
    pub public_transparency_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_profiles: Vec<CertificationSupportedProfile>,
    pub discovery_informational_only: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPublicSearchQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criteria_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CertificationRegistryState>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationMarketplaceSearchQuery {
    #[serde(flatten)]
    pub filters: CertificationPublicSearchQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_ids: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPublicSearchResult {
    pub publisher: CertificationPublicPublisher,
    pub metadata_expires_at: u64,
    pub entry: CertificationRegistryEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryError {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPublicSearchResponse {
    pub schema: String,
    pub generated_at: u64,
    pub peer_count: usize,
    pub reachable_count: usize,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<CertificationPublicSearchResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<CertificationDiscoveryError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationTransparencyEventKind {
    Published,
    Superseded,
    Revoked,
    DisputeOpened,
    DisputeUnderReview,
    DisputeResolvedNoChange,
    DisputeResolvedRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationTransparencyEvent {
    pub observed_at: u64,
    pub kind: CertificationTransparencyEventKind,
    pub publisher: CertificationPublicPublisher,
    pub tool_server_id: String,
    pub artifact_id: String,
    pub verdict: CertificationVerdict,
    pub status: CertificationRegistryState,
    pub criteria_profile: String,
    pub evidence_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute: Option<CertificationDisputeRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationTransparencyQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationMarketplaceTransparencyQuery {
    #[serde(flatten)]
    pub filters: CertificationTransparencyQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_ids: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationTransparencyResponse {
    pub schema: String,
    pub generated_at: u64,
    pub peer_count: usize,
    pub reachable_count: usize,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<CertificationTransparencyEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<CertificationDiscoveryError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationConsumptionRequest {
    pub tool_server_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_criteria_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_evidence_profiles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationConsumptionPeerDecision {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    pub accepted: bool,
    pub metadata_valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<CertificationResolutionResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationConsumptionResponse {
    pub policy_profile: String,
    pub tool_server_id: String,
    pub admitted_count: usize,
    pub rejected_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admitted_artifact_ids: Vec<String>,
    pub decisions: Vec<CertificationConsumptionPeerDecision>,
}

pub(crate) struct EvaluationArtifacts {
    pub(crate) verdict: CertificationVerdict,
    pub(crate) criteria: Vec<CertificationCriterion>,
    pub(crate) findings: Vec<CertificationFinding>,
    pub(crate) summary: CertificationSummary,
}
