use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use chio_conformance::{
    generate_markdown_report, load_results_from_dir, load_scenarios_from_dir, CompatibilityReport,
    ResultStatus, ScenarioDescriptor, ScenarioResult,
};
use chio_core::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};

use crate::enterprise_federation::CertificationDiscoveryNetwork;
use crate::{load_or_create_authority_keypair, CliError};

const CERTIFICATION_SCHEMA: &str = "chio.certify.check.v1";
const CERTIFICATION_REGISTRY_VERSION: &str = "chio.certify.registry.v1";
const CRITERIA_PROFILE_ALL_PASS_V1: &str = "conformance-all-pass-v1";
const EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1: &str = "conformance-report-bundle-v1";
const CERTIFICATION_PUBLIC_METADATA_SCHEMA: &str = "chio.certify.discovery-metadata.v1";
const CERTIFICATION_PUBLIC_SEARCH_SCHEMA: &str = "chio.certify.search.v1";
const CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA: &str = "chio.certify.transparency.v1";
const CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1: &str = "chio.certify.consume.v1";
const CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER: &str = "artifact-signer-key";
const GENERATED_REPORT_MEDIA_TYPE_MARKDOWN: &str = "text/markdown";

fn is_supported_certification_schema(schema: &str) -> bool {
    schema == CERTIFICATION_SCHEMA
}

fn is_supported_certification_registry_version(version: &str) -> bool {
    version == CERTIFICATION_REGISTRY_VERSION
}

fn is_supported_evidence_profile(profile: &str) -> bool {
    profile == EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1
}

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
enum CriterionStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationCriterion {
    id: String,
    description: String,
    status: CriterionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationFinding {
    kind: String,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scenario_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deployment_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<ResultStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationSummary {
    scenario_count: usize,
    result_count: usize,
    evaluated_peer_count: usize,
    pass_count: usize,
    fail_count: usize,
    unsupported_count: usize,
    skipped_count: usize,
    xfail_count: usize,
    missing_scenarios_count: usize,
    unknown_results_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationEvidence {
    evidence_profile: String,
    scenarios_dir: String,
    results_dir: String,
    normalized_scenarios_sha256: String,
    normalized_results_sha256: String,
    generated_report_sha256: String,
    generated_report_bytes: usize,
    generated_report_media_type: String,
    provenance_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationTarget {
    tool_server_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationCheckBody {
    schema: String,
    criteria_profile: String,
    checked_at: u64,
    target: CertificationTarget,
    verdict: CertificationVerdict,
    summary: CertificationSummary,
    criteria: Vec<CertificationCriterion>,
    evidence: CertificationEvidence,
    findings: Vec<CertificationFinding>,
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

struct EvaluationArtifacts {
    verdict: CertificationVerdict,
    criteria: Vec<CertificationCriterion>,
    findings: Vec<CertificationFinding>,
    summary: CertificationSummary,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn normalize_registry_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn require_non_empty_field(value: &str, field: &str) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::attest_error(format!(
            "certification field `{field}` must not be empty"
        )));
    }
    Ok(())
}

fn validate_certification_evidence(evidence: &CertificationEvidence) -> Result<(), CliError> {
    if !is_supported_evidence_profile(&evidence.evidence_profile) {
        return Err(CliError::attest_error(format!(
            "unsupported certification evidence profile: {}",
            evidence.evidence_profile
        )));
    }
    require_non_empty_field(&evidence.scenarios_dir, "evidence.scenariosDir")?;
    require_non_empty_field(&evidence.results_dir, "evidence.resultsDir")?;
    require_non_empty_field(
        &evidence.normalized_scenarios_sha256,
        "evidence.normalizedScenariosSha256",
    )?;
    require_non_empty_field(
        &evidence.normalized_results_sha256,
        "evidence.normalizedResultsSha256",
    )?;
    require_non_empty_field(
        &evidence.generated_report_sha256,
        "evidence.generatedReportSha256",
    )?;
    if evidence.generated_report_bytes == 0 {
        return Err(CliError::attest_error(
            "certification evidence must include a non-empty generated report".to_string(),
        ));
    }
    if evidence.generated_report_media_type != GENERATED_REPORT_MEDIA_TYPE_MARKDOWN {
        return Err(CliError::attest_error(format!(
            "unsupported generated report media type: {}",
            evidence.generated_report_media_type
        )));
    }
    if evidence.provenance_mode != CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER {
        return Err(CliError::attest_error(format!(
            "unsupported certification provenance mode: {}",
            evidence.provenance_mode
        )));
    }
    Ok(())
}

pub(crate) fn validate_public_certification_metadata(
    metadata: &CertificationPublicMetadata,
    expected_registry_url: Option<&str>,
    now: u64,
) -> Result<(), CliError> {
    if metadata.schema != CERTIFICATION_PUBLIC_METADATA_SCHEMA {
        return Err(CliError::attest_error(format!(
            "unsupported certification public metadata schema: {}",
            metadata.schema
        )));
    }
    let publisher_id = normalize_registry_url(&metadata.publisher.publisher_id);
    let registry_url = normalize_registry_url(&metadata.publisher.registry_url);
    if publisher_id.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata is missing publisher.publisherId".to_string(),
        ));
    }
    if registry_url.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata is missing publisher.registryUrl".to_string(),
        ));
    }
    if publisher_id != registry_url {
        return Err(CliError::attest_error(format!(
            "certification public metadata publisher id `{publisher_id}` does not match registry url `{registry_url}`"
        )));
    }
    if let Some(expected_registry_url) = expected_registry_url {
        let expected = normalize_registry_url(expected_registry_url);
        if registry_url != expected {
            return Err(CliError::attest_error(format!(
                "certification public metadata registry url `{registry_url}` does not match expected `{expected}`"
            )));
        }
    }
    if metadata.generated_at == 0 {
        return Err(CliError::attest_error(
            "certification public metadata must include generatedAt".to_string(),
        ));
    }
    if metadata.expires_at <= metadata.generated_at {
        return Err(CliError::attest_error(
            "certification public metadata has expired or invalid expiry".to_string(),
        ));
    }
    if now >= metadata.expires_at {
        return Err(CliError::attest_error(
            "certification public metadata is stale".to_string(),
        ));
    }
    if !metadata.discovery_informational_only {
        return Err(CliError::attest_error(
            "certification public metadata must declare discovery as informational-only"
                .to_string(),
        ));
    }
    if metadata.supported_profiles.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata must advertise at least one supported profile"
                .to_string(),
        ));
    }
    for profile in &metadata.supported_profiles {
        if profile.criteria_profile.trim().is_empty() {
            return Err(CliError::attest_error(
                "certification public metadata contains an empty criteria profile".to_string(),
            ));
        }
        if !is_supported_evidence_profile(&profile.evidence_profile) {
            return Err(CliError::attest_error(format!(
                "certification public metadata contains unsupported evidence profile `{}`",
                profile.evidence_profile
            )));
        }
    }
    for path in [
        metadata.public_resolve_path_template.as_str(),
        metadata.public_search_path.as_str(),
        metadata.public_transparency_path.as_str(),
    ] {
        if !normalize_registry_url(path).starts_with(&registry_url) {
            return Err(CliError::attest_error(format!(
                "certification public metadata path `{path}` falls outside publisher registry url `{registry_url}`"
            )));
        }
    }
    Ok(())
}

fn validate_certification_artifact_body(body: &CertificationCheckBody) -> Result<(), CliError> {
    if !is_supported_certification_schema(&body.schema) {
        return Err(CliError::attest_error(format!(
            "unsupported certification schema: expected {}, got {}",
            CERTIFICATION_SCHEMA, body.schema
        )));
    }
    if body.criteria_profile != CRITERIA_PROFILE_ALL_PASS_V1 {
        return Err(CliError::attest_error(format!(
            "unsupported certification criteria profile: {}",
            body.criteria_profile
        )));
    }
    require_non_empty_field(&body.target.tool_server_id, "target.toolServerId")?;
    validate_certification_evidence(&body.evidence)?;
    Ok(())
}

fn require_certification_discovery_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::attest_error(
            "certification discovery requires --certification-discovery-file when not using --control-url"
                .to_string(),
        )
    })
}

impl Default for CertificationRegistry {
    fn default() -> Self {
        Self {
            version: CERTIFICATION_REGISTRY_VERSION.to_string(),
            artifacts: BTreeMap::new(),
        }
    }
}

fn require_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::attest_error(format!(
            "{label} directory does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::attest_error(format!(
            "{label} path must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn build_certification_body(
    criteria_profile: &str,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    scenarios_dir: &Path,
    results_dir: &Path,
    report_output: Option<&Path>,
    scenarios: Vec<ScenarioDescriptor>,
    results: Vec<ScenarioResult>,
) -> Result<(CertificationCheckBody, Vec<u8>), CliError> {
    if criteria_profile != CRITERIA_PROFILE_ALL_PASS_V1 {
        return Err(CliError::attest_error(format!(
            "unsupported certification criteria profile: {criteria_profile}"
        )));
    }

    let report = CompatibilityReport {
        scenarios: scenarios.clone(),
        results: results.clone(),
    };
    let report_markdown = generate_markdown_report(&report);
    let report_bytes = report_markdown.as_bytes().to_vec();

    let evaluation = evaluate_all_pass_profile(&scenarios, &results);
    let evidence = CertificationEvidence {
        evidence_profile: EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1.to_string(),
        scenarios_dir: scenarios_dir.display().to_string(),
        results_dir: results_dir.display().to_string(),
        normalized_scenarios_sha256: sha256_hex(&canonical_json_bytes(&scenarios)?),
        normalized_results_sha256: sha256_hex(&canonical_json_bytes(&results)?),
        generated_report_sha256: sha256_hex(&report_bytes),
        generated_report_bytes: report_bytes.len(),
        generated_report_media_type: GENERATED_REPORT_MEDIA_TYPE_MARKDOWN.to_string(),
        provenance_mode: CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER.to_string(),
        report_output: report_output.map(|path| path.display().to_string()),
    };

    let body = CertificationCheckBody {
        schema: CERTIFICATION_SCHEMA.to_string(),
        criteria_profile: criteria_profile.to_string(),
        checked_at: unix_now(),
        target: CertificationTarget {
            tool_server_id: tool_server_id.to_string(),
            tool_server_name: tool_server_name.map(ToOwned::to_owned),
        },
        verdict: evaluation.verdict,
        summary: evaluation.summary,
        criteria: evaluation.criteria,
        evidence,
        findings: evaluation.findings,
    };
    Ok((body, report_bytes))
}

fn evaluate_all_pass_profile(
    scenarios: &[ScenarioDescriptor],
    results: &[ScenarioResult],
) -> EvaluationArtifacts {
    let scenario_ids = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut results_by_scenario = BTreeMap::<String, usize>::new();
    let mut findings = Vec::new();

    for result in results {
        if scenario_ids.contains(result.scenario_id.as_str()) {
            *results_by_scenario
                .entry(result.scenario_id.clone())
                .or_insert(0) += 1;
        } else {
            findings.push(CertificationFinding {
                kind: "unknown-scenario-result".to_string(),
                message: format!(
                    "result references unknown scenario `{}`",
                    result.scenario_id
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    for scenario in scenarios {
        if scenario.expected != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "scenario-expectation-not-certifiable".to_string(),
                message: format!(
                    "scenario `{}` has non-pass expected status `{}`",
                    scenario.id,
                    scenario.expected.label()
                ),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: Some(scenario.expected),
            });
        }
        if !results_by_scenario.contains_key(&scenario.id) {
            findings.push(CertificationFinding {
                kind: "missing-scenario-result".to_string(),
                message: format!("scenario `{}` has no result coverage", scenario.id),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: None,
            });
        }
    }

    for result in results {
        if result.status != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "non-pass-result".to_string(),
                message: format!(
                    "scenario `{}` returned `{}`",
                    result.scenario_id,
                    result.status.label()
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    let pass_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Pass)
        .count();
    let fail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Fail)
        .count();
    let unsupported_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Unsupported)
        .count();
    let skipped_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Skipped)
        .count();
    let xfail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Xfail)
        .count();
    let unknown_results_count = findings
        .iter()
        .filter(|finding| finding.kind == "unknown-scenario-result")
        .count();
    let missing_scenarios_count = findings
        .iter()
        .filter(|finding| finding.kind == "missing-scenario-result")
        .count();
    let unsupported_expectation_count = findings
        .iter()
        .filter(|finding| finding.kind == "scenario-expectation-not-certifiable")
        .count();
    let unique_peers = results
        .iter()
        .map(|result| result.peer.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    let criteria = vec![
        CertificationCriterion {
            id: "non-empty-scenario-corpus".to_string(),
            description: "Certification requires at least one declared scenario.".to_string(),
            status: if scenarios.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "non-empty-result-corpus".to_string(),
            description: "Certification requires at least one observed result.".to_string(),
            status: if results.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "scenario-coverage-complete".to_string(),
            description:
                "Every declared scenario must have at least one result and every result must map to a declared scenario."
                    .to_string(),
            status: if missing_scenarios_count == 0 && unknown_results_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "certification-profile-supported".to_string(),
            description:
                "The alpha certification profile only supports scenario sets whose declared expectation is pass."
                    .to_string(),
            status: if unsupported_expectation_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "all-results-pass".to_string(),
            description:
                "Every observed conformance result must be pass; fail, unsupported, skipped, and xfail block certification."
                    .to_string(),
            status: if fail_count == 0
                && unsupported_count == 0
                && skipped_count == 0
                && xfail_count == 0
                && !results.is_empty()
            {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
    ];

    let verdict = if criteria
        .iter()
        .all(|criterion| criterion.status == CriterionStatus::Pass)
    {
        CertificationVerdict::Pass
    } else {
        CertificationVerdict::Fail
    };

    EvaluationArtifacts {
        verdict,
        criteria,
        findings,
        summary: CertificationSummary {
            scenario_count: scenarios.len(),
            result_count: results.len(),
            evaluated_peer_count: unique_peers,
            pass_count,
            fail_count,
            unsupported_count,
            skipped_count,
            xfail_count,
            missing_scenarios_count,
            unknown_results_count,
        },
    }
}

fn sign_artifact(
    body: CertificationCheckBody,
    keypair: &Keypair,
) -> Result<SignedCertificationCheck, CliError> {
    let (signature, _) = keypair.sign_canonical(&body)?;
    Ok(SignedCertificationCheck {
        body,
        signer_public_key: keypair.public_key(),
        signature,
    })
}

pub(crate) fn verify_signed_certification_check(
    artifact: &SignedCertificationCheck,
) -> Result<(), CliError> {
    validate_certification_artifact_body(&artifact.body)?;
    let body_bytes = canonical_json_bytes(&artifact.body)?;
    if !artifact
        .signer_public_key
        .verify(&body_bytes, &artifact.signature)
    {
        return Err(CliError::attest_error(
            "certification artifact signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn certification_artifact_id(
    artifact: &SignedCertificationCheck,
) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(artifact)?))
}

fn load_signed_certification_check(path: &Path) -> Result<SignedCertificationCheck, CliError> {
    let artifact: SignedCertificationCheck = serde_json::from_slice(&fs::read(path)?)?;
    verify_signed_certification_check(&artifact)?;
    Ok(artifact)
}

impl CertificationRegistry {
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if !is_supported_certification_registry_version(&registry.version) {
                    return Err(CliError::attest_error(format!(
                        "unsupported certification registry version: {}",
                        registry.version
                    )));
                }
                registry.version = CERTIFICATION_REGISTRY_VERSION.to_string();
                for entry in registry.artifacts.values() {
                    verify_certification_registry_entry(entry)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), CliError> {
        ensure_parent_dir(path)?;
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub(crate) fn get(&self, artifact_id: &str) -> Option<&CertificationRegistryEntry> {
        self.artifacts.get(artifact_id)
    }

    pub(crate) fn publish(
        &mut self,
        artifact: SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        verify_signed_certification_check(&artifact)?;
        self.version = CERTIFICATION_REGISTRY_VERSION.to_string();
        let artifact_id = certification_artifact_id(&artifact)?;
        if let Some(existing) = self.artifacts.get(&artifact_id) {
            return Ok(existing.clone());
        }

        let published_at = unix_now();
        for existing in self.artifacts.values_mut() {
            if existing.tool_server_id == artifact.body.target.tool_server_id
                && existing.status == CertificationRegistryState::Active
            {
                existing.status = CertificationRegistryState::Superseded;
                existing.superseded_at = Some(published_at);
                existing.superseded_by = Some(artifact_id.clone());
            }
        }

        let entry = CertificationRegistryEntry {
            artifact_sha256: artifact_id.clone(),
            artifact_id: artifact_id.clone(),
            tool_server_id: artifact.body.target.tool_server_id.clone(),
            tool_server_name: artifact.body.target.tool_server_name.clone(),
            verdict: artifact.body.verdict,
            checked_at: artifact.body.checked_at,
            published_at,
            status: CertificationRegistryState::Active,
            superseded_at: None,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            dispute: None,
            artifact,
        };
        self.artifacts.insert(artifact_id, entry.clone());
        Ok(entry)
    }

    pub(crate) fn resolve(&self, tool_server_id: &str) -> CertificationResolutionResponse {
        let mut matches = self
            .artifacts
            .values()
            .filter(|entry| entry.tool_server_id == tool_server_id)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.published_at
                .cmp(&right.published_at)
                .then(left.checked_at.cmp(&right.checked_at))
                .then(left.artifact_id.cmp(&right.artifact_id))
        });
        let total_entries = matches.len();
        let current = matches
            .iter()
            .rev()
            .find(|entry| entry.status == CertificationRegistryState::Active)
            .cloned()
            .or_else(|| {
                matches
                    .iter()
                    .rev()
                    .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                    .max_by(|left, right| {
                        left.revoked_at
                            .cmp(&right.revoked_at)
                            .then(left.published_at.cmp(&right.published_at))
                            .then(left.checked_at.cmp(&right.checked_at))
                    })
                    .cloned()
            })
            .or_else(|| matches.last().cloned());
        let state = match current.as_ref().map(|entry| entry.status) {
            Some(CertificationRegistryState::Active) => CertificationResolutionState::Active,
            Some(CertificationRegistryState::Superseded) => {
                CertificationResolutionState::Superseded
            }
            Some(CertificationRegistryState::Revoked) => CertificationResolutionState::Revoked,
            None => CertificationResolutionState::NotFound,
        };
        CertificationResolutionResponse {
            tool_server_id: tool_server_id.to_string(),
            state,
            total_entries,
            current,
        }
    }

    pub(crate) fn revoke(
        &mut self,
        artifact_id: &str,
        reason: Option<&str>,
        revoked_at: Option<u64>,
    ) -> Result<CertificationRegistryEntry, CliError> {
        let Some(entry) = self.artifacts.get_mut(artifact_id) else {
            return Err(CliError::attest_error(format!(
                "certification artifact `{artifact_id}` was not found"
            )));
        };
        entry.status = CertificationRegistryState::Revoked;
        entry.revoked_at = Some(revoked_at.unwrap_or_else(unix_now));
        entry.revoked_reason = reason.map(str::to_string);
        Ok(entry.clone())
    }

    pub(crate) fn dispute(
        &mut self,
        artifact_id: &str,
        request: &CertificationDisputeRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        let Some(entry) = self.artifacts.get_mut(artifact_id) else {
            return Err(CliError::attest_error(format!(
                "certification artifact `{artifact_id}` was not found"
            )));
        };
        let updated_at = request.updated_at.unwrap_or_else(unix_now);
        let dispute = CertificationDisputeRecord {
            state: request.state,
            updated_at,
            note: request.note.clone(),
        };
        if request.state == CertificationDisputeState::ResolvedRevoked {
            entry.status = CertificationRegistryState::Revoked;
            entry.revoked_at = Some(updated_at);
            if entry.revoked_reason.is_none() {
                entry.revoked_reason = Some(
                    request
                        .note
                        .clone()
                        .unwrap_or_else(|| "dispute resolved as revoked".to_string()),
                );
            }
        }
        entry.dispute = Some(dispute);
        Ok(entry.clone())
    }

    pub(crate) fn search_public(
        &self,
        publisher: &CertificationPublicPublisher,
        metadata_expires_at: u64,
        query: &CertificationPublicSearchQuery,
    ) -> CertificationPublicSearchResponse {
        let mut results = self
            .artifacts
            .values()
            .filter(|entry| {
                query
                    .tool_server_id
                    .as_deref()
                    .is_none_or(|tool_server_id| entry.tool_server_id == tool_server_id)
            })
            .filter(|entry| {
                query
                    .criteria_profile
                    .as_deref()
                    .is_none_or(|criteria_profile| {
                        entry.artifact.body.criteria_profile == criteria_profile
                    })
            })
            .filter(|entry| {
                query
                    .evidence_profile
                    .as_deref()
                    .is_none_or(|evidence_profile| {
                        entry.artifact.body.evidence.evidence_profile == evidence_profile
                    })
            })
            .filter(|entry| query.status.is_none_or(|status| entry.status == status))
            .cloned()
            .map(|entry| CertificationPublicSearchResult {
                publisher: publisher.clone(),
                metadata_expires_at,
                entry,
            })
            .collect::<Vec<_>>();
        results.sort_by(|left, right| {
            left.entry
                .tool_server_id
                .cmp(&right.entry.tool_server_id)
                .then(right.entry.published_at.cmp(&left.entry.published_at))
                .then(right.entry.checked_at.cmp(&left.entry.checked_at))
                .then(left.entry.artifact_id.cmp(&right.entry.artifact_id))
        });
        CertificationPublicSearchResponse {
            schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
            generated_at: unix_now(),
            peer_count: 1,
            reachable_count: 1,
            count: results.len(),
            results,
            errors: Vec::new(),
        }
    }

    pub(crate) fn transparency(
        &self,
        publisher: &CertificationPublicPublisher,
        query: &CertificationTransparencyQuery,
    ) -> CertificationTransparencyResponse {
        let mut events = Vec::new();
        for entry in self.artifacts.values() {
            if query
                .tool_server_id
                .as_deref()
                .is_some_and(|tool_server_id| entry.tool_server_id != tool_server_id)
            {
                continue;
            }
            events.push(CertificationTransparencyEvent {
                observed_at: entry.published_at,
                kind: CertificationTransparencyEventKind::Published,
                publisher: publisher.clone(),
                tool_server_id: entry.tool_server_id.clone(),
                artifact_id: entry.artifact_id.clone(),
                verdict: entry.verdict,
                status: entry.status,
                criteria_profile: entry.artifact.body.criteria_profile.clone(),
                evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                superseded_by: entry.superseded_by.clone(),
                revoked_reason: entry.revoked_reason.clone(),
                dispute: entry.dispute.clone(),
            });
            if let Some(superseded_at) = entry.superseded_at {
                events.push(CertificationTransparencyEvent {
                    observed_at: superseded_at,
                    kind: CertificationTransparencyEventKind::Superseded,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: entry.dispute.clone(),
                });
            }
            if let Some(revoked_at) = entry.revoked_at {
                events.push(CertificationTransparencyEvent {
                    observed_at: revoked_at,
                    kind: CertificationTransparencyEventKind::Revoked,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: entry.dispute.clone(),
                });
            }
            if let Some(dispute) = entry.dispute.clone() {
                let kind = match dispute.state {
                    CertificationDisputeState::Open => {
                        CertificationTransparencyEventKind::DisputeOpened
                    }
                    CertificationDisputeState::UnderReview => {
                        CertificationTransparencyEventKind::DisputeUnderReview
                    }
                    CertificationDisputeState::ResolvedNoChange => {
                        CertificationTransparencyEventKind::DisputeResolvedNoChange
                    }
                    CertificationDisputeState::ResolvedRevoked => {
                        CertificationTransparencyEventKind::DisputeResolvedRevoked
                    }
                };
                events.push(CertificationTransparencyEvent {
                    observed_at: dispute.updated_at,
                    kind,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: Some(dispute),
                });
            }
        }
        events.sort_by(|left, right| {
            left.observed_at
                .cmp(&right.observed_at)
                .then(left.artifact_id.cmp(&right.artifact_id))
        });
        CertificationTransparencyResponse {
            schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
            generated_at: unix_now(),
            peer_count: 1,
            reachable_count: 1,
            count: events.len(),
            events,
            errors: Vec::new(),
        }
    }
}

fn verify_certification_registry_entry(entry: &CertificationRegistryEntry) -> Result<(), CliError> {
    verify_signed_certification_check(&entry.artifact)?;
    let expected_artifact_id = certification_artifact_id(&entry.artifact)?;
    if entry.artifact_id != expected_artifact_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched artifact_id",
            entry.artifact_id
        )));
    }
    if entry.artifact_sha256 != expected_artifact_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched artifact digest",
            entry.artifact_id
        )));
    }
    if entry.tool_server_id != entry.artifact.body.target.tool_server_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched tool_server_id",
            entry.artifact_id
        )));
    }
    if entry.tool_server_name != entry.artifact.body.target.tool_server_name {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched tool_server_name",
            entry.artifact_id
        )));
    }
    if entry.checked_at != entry.artifact.body.checked_at {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched checked_at",
            entry.artifact_id
        )));
    }
    if entry.verdict != entry.artifact.body.verdict {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched verdict",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Superseded && entry.superseded_by.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is superseded without superseded_by",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Superseded && entry.superseded_at.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is superseded without superseded_at",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Revoked && entry.revoked_at.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is revoked without revoked_at",
            entry.artifact_id
        )));
    }
    if let Some(dispute) = entry.dispute.as_ref() {
        if dispute.updated_at == 0 {
            return Err(CliError::attest_error(format!(
                "certification registry entry `{}` has invalid dispute timestamp",
                entry.artifact_id
            )));
        }
    }
    Ok(())
}

pub fn cmd_certify_verify(input: &Path, json_output: bool) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let artifact_id = certification_artifact_id(&artifact)?;
    if json_output {
        let message = serde_json::json!({
            "input": input.display().to_string(),
            "artifactId": artifact_id,
            "toolServerId": artifact.body.target.tool_server_id,
            "toolServerName": artifact.body.target.tool_server_name,
            "verdict": artifact.body.verdict.label(),
            "checkedAt": artifact.body.checked_at,
            "signerPublicKey": artifact.signer_public_key,
            "verified": true,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!("certification verified");
        println!("artifact_id:      {artifact_id}");
        println!("tool_server_id:   {}", artifact.body.target.tool_server_id);
        println!("verdict:          {}", artifact.body.verdict.label());
        println!("checked_at:       {}", artifact.body.checked_at);
    }
    Ok(())
}

pub fn cmd_certify_check(
    scenarios_dir: &Path,
    results_dir: &Path,
    output: &Path,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    report_output: Option<&Path>,
    criteria_profile: &str,
    signing_seed_file: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    require_existing_dir(scenarios_dir, "scenarios")?;
    require_existing_dir(results_dir, "results")?;

    let scenarios = load_scenarios_from_dir(scenarios_dir)?;
    let results = load_results_from_dir(results_dir)?;
    let (body, report_bytes) = build_certification_body(
        criteria_profile,
        tool_server_id,
        tool_server_name,
        scenarios_dir,
        results_dir,
        report_output,
        scenarios,
        results,
    )?;

    if let Some(report_output) = report_output {
        ensure_parent_dir(report_output)?;
        fs::write(report_output, &report_bytes)?;
    }

    let signing_key = load_or_create_authority_keypair(signing_seed_file)?;
    let artifact = sign_artifact(body, &signing_key)?;
    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&artifact)?)?;

    if json_output {
        let message = serde_json::json!({
            "output": output.display().to_string(),
            "verdict": artifact.body.verdict.label(),
            "criteriaProfile": artifact.body.criteria_profile,
            "summary": artifact.body.summary,
            "signerPublicKey": artifact.signer_public_key,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!(
            "wrote certification artifact to {} ({}, {} result(s))",
            output.display(),
            artifact.body.verdict.label(),
            artifact.body.summary.result_count
        );
        if let Some(report_output) = report_output {
            println!("wrote certification report to {}", report_output.display());
        }
    }

    Ok(())
}

pub fn cmd_certify_registry_publish_local(
    input: &Path,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.publish(artifact)?;
    registry.save(registry_path)?;
    emit_registry_entry("published certification artifact", &entry, json_output)
}

pub fn cmd_certify_registry_list_local(
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = CertificationRegistryListResponse {
        configured: true,
        count: registry.artifacts.len(),
        artifacts: registry.artifacts.into_values().collect(),
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("certifications: {}", response.count);
        for artifact in response.artifacts {
            println!(
                "- {} server={} verdict={} status={}",
                artifact.artifact_id,
                artifact.tool_server_id,
                artifact.verdict.label(),
                artifact.status.label()
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_get_local(
    artifact_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.get(artifact_id).cloned().ok_or_else(|| {
        CliError::attest_error(format!(
            "certification artifact `{artifact_id}` was not found"
        ))
    })?;
    emit_registry_entry("certification artifact", &entry, json_output)
}

pub fn cmd_certify_registry_resolve_local(
    tool_server_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = registry.resolve(tool_server_id);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("tool_server_id: {}", response.tool_server_id);
        println!(
            "state:          {}",
            match response.state {
                CertificationResolutionState::Active => "active",
                CertificationResolutionState::Superseded => "superseded",
                CertificationResolutionState::Revoked => "revoked",
                CertificationResolutionState::NotFound => "not-found",
            }
        );
        println!("total_entries:  {}", response.total_entries);
        if let Some(current) = response.current {
            println!("artifact_id:    {}", current.artifact_id);
            println!("verdict:        {}", current.verdict.label());
            println!("status:         {}", current.status.label());
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_revoke_local(
    artifact_id: &str,
    registry_path: &Path,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.revoke(artifact_id, reason, revoked_at)?;
    registry.save(registry_path)?;
    emit_registry_entry("revoked certification artifact", &entry, json_output)
}

pub fn discover_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    tool_server_id: &str,
) -> CertificationDiscoveryResponse {
    let mut peers = Vec::new();
    let mut reachable_count = 0;
    let mut active_count = 0;
    let mut revoked_count = 0;
    let mut superseded_count = 0;
    let mut not_found_count = 0;

    for operator in network.validated_operators() {
        match crate::trust_control::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => {
                    reachable_count += 1;
                    match crate::trust_control::resolve_public_certification(
                        &operator.registry_url,
                        tool_server_id,
                    ) {
                        Ok(resolution) => {
                            match resolution.state {
                                CertificationResolutionState::Active => active_count += 1,
                                CertificationResolutionState::Revoked => revoked_count += 1,
                                CertificationResolutionState::Superseded => superseded_count += 1,
                                CertificationResolutionState::NotFound => not_found_count += 1,
                            }
                            peers.push(CertificationDiscoveryPeerResult {
                                operator_id: operator.operator_id.clone(),
                                operator_name: operator.operator_name.clone(),
                                registry_url: operator.registry_url.clone(),
                                reachable: true,
                                metadata: Some(metadata),
                                metadata_valid: true,
                                error: None,
                                resolution: Some(resolution),
                            });
                        }
                        Err(error) => peers.push(CertificationDiscoveryPeerResult {
                            operator_id: operator.operator_id.clone(),
                            operator_name: operator.operator_name.clone(),
                            registry_url: operator.registry_url.clone(),
                            reachable: true,
                            metadata: Some(metadata),
                            metadata_valid: true,
                            error: Some(error.to_string()),
                            resolution: None,
                        }),
                    }
                }
                Err(error) => peers.push(CertificationDiscoveryPeerResult {
                    operator_id: operator.operator_id.clone(),
                    operator_name: operator.operator_name.clone(),
                    registry_url: operator.registry_url.clone(),
                    reachable: true,
                    metadata: Some(metadata),
                    metadata_valid: false,
                    error: Some(error.to_string()),
                    resolution: None,
                }),
            },
            Err(error) => peers.push(CertificationDiscoveryPeerResult {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                reachable: false,
                metadata: None,
                metadata_valid: false,
                error: Some(error.to_string()),
                resolution: None,
            }),
        }
    }

    CertificationDiscoveryResponse {
        tool_server_id: tool_server_id.to_string(),
        peer_count: peers.len(),
        reachable_count,
        active_count,
        revoked_count,
        superseded_count,
        not_found_count,
        peers,
    }
}

fn selected_network_operators<'a>(
    network: &'a CertificationDiscoveryNetwork,
    operator_ids: &[String],
) -> Result<Vec<&'a crate::enterprise_federation::CertificationDiscoveryOperator>, CliError> {
    if operator_ids.is_empty() {
        return Ok(network.validated_operators().collect());
    }
    let mut operators = Vec::new();
    for operator_id in operator_ids {
        let operator = network.validated_operator(operator_id).ok_or_else(|| {
            CliError::attest_error(format!(
                "certification discovery operator `{operator_id}` was not found or is invalid"
            ))
        })?;
        operators.push(operator);
    }
    Ok(operators)
}

fn parse_operator_ids_csv(operator_ids: Option<&str>) -> Vec<String> {
    operator_ids
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn search_public_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    query: &CertificationMarketplaceSearchQuery,
) -> CertificationPublicSearchResponse {
    let mut results = Vec::new();
    let mut errors = Vec::new();
    let mut reachable_count = 0;
    let operator_ids = parse_operator_ids_csv(query.operator_ids.as_deref());
    let operators = match selected_network_operators(network, &operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationPublicSearchResponse {
                schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
                generated_at: unix_now(),
                peer_count: 0,
                reachable_count: 0,
                count: 0,
                results: Vec::new(),
                errors: vec![CertificationDiscoveryError {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: error.to_string(),
                }],
            };
        }
    };
    let peer_count = operators.len();
    for operator in operators {
        match crate::trust_control::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => match crate::trust_control::search_public_certifications(
                    &operator.registry_url,
                    &query.filters,
                ) {
                    Ok(response) => {
                        reachable_count += 1;
                        results.extend(response.results);
                    }
                    Err(error) => errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    }),
                },
                Err(error) => {
                    reachable_count += 1;
                    errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    });
                }
            },
            Err(error) => errors.push(CertificationDiscoveryError {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                error: error.to_string(),
            }),
        }
    }
    results.sort_by(|left, right| {
        left.publisher
            .publisher_id
            .cmp(&right.publisher.publisher_id)
            .then(left.entry.tool_server_id.cmp(&right.entry.tool_server_id))
            .then(right.entry.published_at.cmp(&left.entry.published_at))
            .then(left.entry.artifact_id.cmp(&right.entry.artifact_id))
    });
    CertificationPublicSearchResponse {
        schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
        generated_at: unix_now(),
        peer_count,
        reachable_count,
        count: results.len(),
        results,
        errors,
    }
}

pub fn transparency_public_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    query: &CertificationMarketplaceTransparencyQuery,
) -> CertificationTransparencyResponse {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut reachable_count = 0;
    let operator_ids = parse_operator_ids_csv(query.operator_ids.as_deref());
    let operators = match selected_network_operators(network, &operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationTransparencyResponse {
                schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
                generated_at: unix_now(),
                peer_count: 0,
                reachable_count: 0,
                count: 0,
                events: Vec::new(),
                errors: vec![CertificationDiscoveryError {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: error.to_string(),
                }],
            };
        }
    };
    let peer_count = operators.len();
    for operator in operators {
        match crate::trust_control::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => match crate::trust_control::resolve_public_certification_transparency(
                    &operator.registry_url,
                    &query.filters,
                ) {
                    Ok(response) => {
                        reachable_count += 1;
                        events.extend(response.events);
                    }
                    Err(error) => errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    }),
                },
                Err(error) => {
                    reachable_count += 1;
                    errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    });
                }
            },
            Err(error) => errors.push(CertificationDiscoveryError {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                error: error.to_string(),
            }),
        }
    }
    events.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then(
                left.publisher
                    .publisher_id
                    .cmp(&right.publisher.publisher_id),
            )
            .then(left.artifact_id.cmp(&right.artifact_id))
    });
    CertificationTransparencyResponse {
        schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
        generated_at: unix_now(),
        peer_count,
        reachable_count,
        count: events.len(),
        events,
        errors,
    }
}

pub fn consume_public_certification_across_network(
    network: &CertificationDiscoveryNetwork,
    request: &CertificationConsumptionRequest,
) -> CertificationConsumptionResponse {
    let mut decisions = Vec::new();
    let mut admitted_artifact_ids = Vec::new();
    let operators = match selected_network_operators(network, &request.operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationConsumptionResponse {
                policy_profile: CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1.to_string(),
                tool_server_id: request.tool_server_id.clone(),
                admitted_count: 0,
                rejected_count: 1,
                admitted_artifact_ids: Vec::new(),
                decisions: vec![CertificationConsumptionPeerDecision {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    accepted: false,
                    metadata_valid: false,
                    reasons: vec![error.to_string()],
                    resolution: None,
                }],
            };
        }
    };
    for operator in operators {
        let mut decision = CertificationConsumptionPeerDecision {
            operator_id: operator.operator_id.clone(),
            operator_name: operator.operator_name.clone(),
            registry_url: operator.registry_url.clone(),
            accepted: false,
            metadata_valid: false,
            reasons: Vec::new(),
            resolution: None,
        };
        match crate::trust_control::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => {
                    decision.metadata_valid = true;
                    match crate::trust_control::resolve_public_certification(
                        &operator.registry_url,
                        &request.tool_server_id,
                    ) {
                        Ok(resolution) => {
                            decision.resolution = Some(resolution.clone());
                            let mut accepted = true;
                            if resolution.state != CertificationResolutionState::Active {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "current listing state is {}",
                                    match resolution.state {
                                        CertificationResolutionState::Active => "active",
                                        CertificationResolutionState::Superseded => "superseded",
                                        CertificationResolutionState::Revoked => "revoked",
                                        CertificationResolutionState::NotFound => "not-found",
                                    }
                                ));
                            }
                            let Some(current) = resolution.current else {
                                decision.reasons.push(
                                    "no current certification artifact is available".to_string(),
                                );
                                decisions.push(decision);
                                continue;
                            };
                            if current.verdict != CertificationVerdict::Pass {
                                accepted = false;
                                decision
                                    .reasons
                                    .push("current certification verdict is not pass".to_string());
                            }
                            if let Some(dispute) = current.dispute.as_ref() {
                                if matches!(
                                    dispute.state,
                                    CertificationDisputeState::Open
                                        | CertificationDisputeState::UnderReview
                                ) {
                                    accepted = false;
                                    decision.reasons.push(format!(
                                        "current certification is disputed ({})",
                                        dispute.state.label()
                                    ));
                                }
                            }
                            if !request.allowed_criteria_profiles.is_empty()
                                && !request.allowed_criteria_profiles.iter().any(|profile| {
                                    profile == &current.artifact.body.criteria_profile
                                })
                            {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "criteria profile `{}` is not allowed by consumption policy",
                                    current.artifact.body.criteria_profile
                                ));
                            }
                            if !request.allowed_evidence_profiles.is_empty()
                                && !request.allowed_evidence_profiles.iter().any(|profile| {
                                    profile == &current.artifact.body.evidence.evidence_profile
                                })
                            {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "evidence profile `{}` is not allowed by consumption policy",
                                    current.artifact.body.evidence.evidence_profile
                                ));
                            }
                            if accepted {
                                admitted_artifact_ids.push(current.artifact_id.clone());
                                decision.accepted = true;
                            }
                        }
                        Err(error) => decision.reasons.push(error.to_string()),
                    }
                }
                Err(error) => decision.reasons.push(error.to_string()),
            },
            Err(error) => decision.reasons.push(error.to_string()),
        }
        decisions.push(decision);
    }
    let admitted_count = decisions
        .iter()
        .filter(|decision| decision.accepted)
        .count();
    let rejected_count = decisions.len().saturating_sub(admitted_count);
    CertificationConsumptionResponse {
        policy_profile: CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1.to_string(),
        tool_server_id: request.tool_server_id.clone(),
        admitted_count,
        rejected_count,
        admitted_artifact_ids,
        decisions,
    }
}

pub fn publish_certification_across_network(
    network: &CertificationDiscoveryNetwork,
    artifact: &SignedCertificationCheck,
    operator_ids: &[String],
) -> Result<CertificationNetworkPublishResponse, CliError> {
    verify_signed_certification_check(artifact)?;
    let artifact_id = certification_artifact_id(artifact)?;
    let mut operators = Vec::new();
    if operator_ids.is_empty() {
        operators.extend(network.validated_operators().cloned());
    } else {
        for operator_id in operator_ids {
            let operator = network.validated_operator(operator_id).ok_or_else(|| {
                CliError::attest_error(format!(
                    "certification discovery operator `{operator_id}` was not found or is invalid"
                ))
            })?;
            operators.push(operator.clone());
        }
    }

    let mut results = Vec::new();
    let mut success_count = 0;
    for operator in operators {
        let mut result = CertificationNetworkPublishPeerResult {
            operator_id: operator.operator_id.clone(),
            operator_name: operator.operator_name.clone(),
            registry_url: operator.registry_url.clone(),
            published: false,
            error: None,
            entry: None,
        };

        if !operator.allow_publish {
            result.error = Some("operator is not configured for publish fan-out".to_string());
            results.push(result);
            continue;
        }
        let Some(token) = operator.control_token.as_deref() else {
            result.error = Some("operator is missing control_token".to_string());
            results.push(result);
            continue;
        };

        match crate::trust_control::build_client(&operator.registry_url, token)
            .and_then(|client| client.publish_certification(artifact))
        {
            Ok(entry) => {
                success_count += 1;
                result.published = true;
                result.entry = Some(entry);
            }
            Err(error) => result.error = Some(error.to_string()),
        }
        results.push(result);
    }

    Ok(CertificationNetworkPublishResponse {
        artifact_id,
        tool_server_id: artifact.body.target.tool_server_id.clone(),
        peer_count: results.len(),
        success_count,
        results,
    })
}

pub fn cmd_certify_registry_discover(
    tool_server_id: &str,
    discovery_path: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.discover_certification(tool_server_id)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        discover_certifications_across_network(&network, tool_server_id)
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("tool_server_id: {}", response.tool_server_id);
        println!("peer_count:     {}", response.peer_count);
        println!("reachable:      {}", response.reachable_count);
        println!("active:         {}", response.active_count);
        println!("revoked:        {}", response.revoked_count);
        println!("superseded:     {}", response.superseded_count);
        println!("not_found:      {}", response.not_found_count);
        for peer in response.peers {
            match peer.resolution {
                Some(resolution) => println!(
                    "- {} state={} registry={}",
                    peer.operator_id,
                    certification_resolution_label(resolution.state),
                    peer.registry_url
                ),
                None => println!(
                    "- {} error={} registry={}",
                    peer.operator_id,
                    peer.error.unwrap_or_else(|| "unknown".to_string()),
                    peer.registry_url
                ),
            }
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_publish_network(
    input: &Path,
    discovery_path: Option<&Path>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.publish_certification_network(
            &CertificationNetworkPublishRequest {
                artifact,
                operator_ids: operator_ids.to_vec(),
            },
        )?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        publish_certification_across_network(&network, &artifact, operator_ids)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("artifact_id:   {}", response.artifact_id);
        println!("tool_server:   {}", response.tool_server_id);
        println!("peer_count:    {}", response.peer_count);
        println!("success_count: {}", response.success_count);
        for result in response.results {
            if result.published {
                println!(
                    "- {} published registry={}",
                    result.operator_id, result.registry_url
                );
            } else {
                println!(
                    "- {} error={} registry={}",
                    result.operator_id,
                    result.error.unwrap_or_else(|| "unknown".to_string()),
                    result.registry_url
                );
            }
        }
    }
    Ok(())
}

fn parse_registry_state_filter(
    status: Option<&str>,
) -> Result<Option<CertificationRegistryState>, CliError> {
    match status {
        None => Ok(None),
        Some("active") => Ok(Some(CertificationRegistryState::Active)),
        Some("superseded") => Ok(Some(CertificationRegistryState::Superseded)),
        Some("revoked") => Ok(Some(CertificationRegistryState::Revoked)),
        Some(other) => Err(CliError::attest_error(format!(
            "unsupported certification status filter `{other}`"
        ))),
    }
}

fn parse_dispute_state(state: &str) -> Result<CertificationDisputeState, CliError> {
    match state {
        "open" => Ok(CertificationDisputeState::Open),
        "under-review" => Ok(CertificationDisputeState::UnderReview),
        "resolved-no-change" => Ok(CertificationDisputeState::ResolvedNoChange),
        "resolved-revoked" => Ok(CertificationDisputeState::ResolvedRevoked),
        other => Err(CliError::attest_error(format!(
            "unsupported certification dispute state `{other}`"
        ))),
    }
}

pub fn cmd_certify_registry_search(
    discovery_path: Option<&Path>,
    tool_server_id: Option<&str>,
    criteria_profile: Option<&str>,
    evidence_profile: Option<&str>,
    status: Option<&str>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = CertificationMarketplaceSearchQuery {
        filters: CertificationPublicSearchQuery {
            tool_server_id: tool_server_id.map(str::to_string),
            criteria_profile: criteria_profile.map(str::to_string),
            evidence_profile: evidence_profile.map(str::to_string),
            status: parse_registry_state_filter(status)?,
        },
        operator_ids: (!operator_ids.is_empty()).then(|| operator_ids.join(",")),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?.search_certification_marketplace(&query)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        search_public_certifications_across_network(&network, &query)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("search_results: {}", response.count);
        println!("reachable:      {}", response.reachable_count);
        for result in response.results {
            println!(
                "- publisher={} server={} status={} verdict={} artifact={}",
                result.publisher.publisher_id,
                result.entry.tool_server_id,
                result.entry.status.label(),
                result.entry.verdict.label(),
                result.entry.artifact_id
            );
        }
        for error in response.errors {
            println!(
                "- operator={} error={} registry={}",
                error.operator_id, error.error, error.registry_url
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_transparency(
    discovery_path: Option<&Path>,
    tool_server_id: Option<&str>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = CertificationMarketplaceTransparencyQuery {
        filters: CertificationTransparencyQuery {
            tool_server_id: tool_server_id.map(str::to_string),
        },
        operator_ids: (!operator_ids.is_empty()).then(|| operator_ids.join(",")),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?
            .certification_marketplace_transparency(&query)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        transparency_public_certifications_across_network(&network, &query)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("events:    {}", response.count);
        println!("reachable: {}", response.reachable_count);
        for event in response.events {
            println!(
                "- publisher={} kind={:?} server={} artifact={} at={}",
                event.publisher.publisher_id,
                event.kind,
                event.tool_server_id,
                event.artifact_id,
                event.observed_at
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_consume(
    discovery_path: Option<&Path>,
    tool_server_id: &str,
    operator_ids: &[String],
    allowed_criteria_profiles: &[String],
    allowed_evidence_profiles: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = CertificationConsumptionRequest {
        tool_server_id: tool_server_id.to_string(),
        operator_ids: operator_ids.to_vec(),
        allowed_criteria_profiles: allowed_criteria_profiles.to_vec(),
        allowed_evidence_profiles: allowed_evidence_profiles.to_vec(),
    };
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?
            .consume_certification_marketplace(&request)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        consume_public_certification_across_network(&network, &request)
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("admitted: {}", response.admitted_count);
        println!("rejected: {}", response.rejected_count);
        for decision in response.decisions {
            println!(
                "- operator={} accepted={} reasons={}",
                decision.operator_id,
                decision.accepted,
                decision.reasons.join("; ")
            );
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_dispute(
    artifact_id: &str,
    state: &str,
    note: Option<&str>,
    updated_at: Option<u64>,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = CertificationDisputeRequest {
        state: parse_dispute_state(state)?,
        note: note.map(str::to_string),
        updated_at,
    };
    let entry = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::build_client(url, token)?
            .dispute_certification(artifact_id, &request)?
    } else {
        let path = certification_registry_file.ok_or_else(|| {
            CliError::attest_error(
                "certification dispute requires --certification-registry-file when not using --control-url"
                    .to_string(),
            )
        })?;
        let mut registry = CertificationRegistry::load(path)?;
        let entry = registry.dispute(artifact_id, &request)?;
        registry.save(path)?;
        entry
    };
    emit_registry_entry("updated certification dispute state", &entry, json_output)
}

fn emit_registry_entry(
    headline: &str,
    entry: &CertificationRegistryEntry,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(entry)?);
    } else {
        println!("{headline}");
        println!("artifact_id:     {}", entry.artifact_id);
        println!("tool_server_id:  {}", entry.tool_server_id);
        println!("verdict:         {}", entry.verdict.label());
        println!("status:          {}", entry.status.label());
        println!("published_at:    {}", entry.published_at);
        if let Some(revoked_at) = entry.revoked_at {
            println!("revoked_at:      {revoked_at}");
        }
        if let Some(reason) = entry.revoked_reason.as_deref() {
            println!("revoked_reason:  {reason}");
        }
        if let Some(dispute) = entry.dispute.as_ref() {
            println!("dispute_state:   {}", dispute.state.label());
            println!("dispute_at:      {}", dispute.updated_at);
            if let Some(note) = dispute.note.as_deref() {
                println!("dispute_note:    {note}");
            }
        }
        if let Some(superseded_by) = entry.superseded_by.as_deref() {
            println!("superseded_by:   {superseded_by}");
        }
    }
    Ok(())
}

fn certification_resolution_label(state: CertificationResolutionState) -> &'static str {
    match state {
        CertificationResolutionState::Active => "active",
        CertificationResolutionState::Superseded => "superseded",
        CertificationResolutionState::Revoked => "revoked",
        CertificationResolutionState::NotFound => "not-found",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    use chio_conformance::{
        DeploymentMode, PeerRole, RequiredCapabilities, ScenarioCategory, Transport,
    };

    fn scenario(id: &str) -> ScenarioDescriptor {
        ScenarioDescriptor {
            id: id.to_string(),
            title: format!("Scenario {id}"),
            area: "core".to_string(),
            category: ScenarioCategory::McpCore,
            spec_versions: vec!["2025-11-25".to_string()],
            transport: vec![Transport::Stdio],
            peer_roles: vec![PeerRole::ClientToChioServer],
            deployment_modes: vec![DeploymentMode::WrappedStdio],
            required_capabilities: RequiredCapabilities::default(),
            tags: vec!["core".to_string()],
            expected: ResultStatus::Pass,
            timeout_ms: None,
            notes: None,
        }
    }

    fn result(id: &str, status: ResultStatus) -> ScenarioResult {
        ScenarioResult {
            scenario_id: id.to_string(),
            peer: "js".to_string(),
            peer_role: PeerRole::ClientToChioServer,
            deployment_mode: DeploymentMode::WrappedStdio,
            transport: Transport::Stdio,
            spec_version: "2025-11-25".to_string(),
            category: ScenarioCategory::McpCore,
            status,
            duration_ms: 25,
            assertions: Vec::new(),
            notes: None,
            artifacts: BTreeMap::new(),
            failure_kind: None,
            failure_message: None,
            expected_failure: None,
        }
    }

    #[test]
    fn all_pass_profile_produces_pass_verdict() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize")],
            &[result("initialize", ResultStatus::Pass)],
        );
        assert_eq!(evaluation.verdict, CertificationVerdict::Pass);
        assert!(evaluation.findings.is_empty());
        assert_eq!(evaluation.summary.pass_count, 1);
    }

    #[test]
    fn all_pass_profile_fails_on_missing_unknown_and_non_pass_results() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize"), scenario("list-tools")],
            &[
                result("initialize", ResultStatus::Pass),
                result("unknown", ResultStatus::Fail),
                result("initialize", ResultStatus::Unsupported),
            ],
        );

        assert_eq!(evaluation.verdict, CertificationVerdict::Fail);
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "missing-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "unknown-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "non-pass-result"));
    }

    #[test]
    fn signed_artifact_verifies_against_body() {
        let (body, _) = build_certification_body(
            CRITERIA_PROFILE_ALL_PASS_V1,
            "demo-server",
            Some("Demo"),
            Path::new("/tmp/scenarios"),
            Path::new("/tmp/results"),
            None,
            vec![scenario("initialize")],
            vec![result("initialize", ResultStatus::Pass)],
        )
        .test_expect("build body");
        let keypair = Keypair::generate();
        let artifact = sign_artifact(body, &keypair).test_expect("sign artifact");

        assert!(artifact
            .signer_public_key
            .verify_canonical(&artifact.body, &artifact.signature)
            .test_expect("verify canonical"));
    }
}
