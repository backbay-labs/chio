use crate::{
    canonical_sha256, contains_secret_marker, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    is_bounded_route_token, is_sha256_hex, validate_export_path, validate_retention_profile,
    verify_relay_alert_assurance_export_bundle, PheromoneRelayError,
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceExportFile,
    RelayAlertAssuranceExportManifest, RelayAlertAssuranceExportReport,
    RelayAlertAssuranceRecoveryDrillInput, RelayAlertAssuranceRecoveryDrillReport,
    RelayAlertAssuranceReplayInput, RelayAlertAssuranceRetentionInput,
    RelayAlertAssuranceRetentionProfileDocument, RelayAlertAssuranceTrustedExportersDocument,
    RelayAlertCheck, RelayOperatorRecommendation,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_EXTRACTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub require_replay_match: bool,
    pub require_recovery_drill: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub require_replay_match: bool,
    pub require_recovery_drill: bool,
    pub block_legal_hold: bool,
    pub block_eligible_for_delete: bool,
}

#[derive(Debug, Clone)]
pub struct RelayAlertAssuranceArchiveBundleCandidate {
    pub bundle_path: String,
    pub bundle: Option<RelayAlertAssuranceExportBundle>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveBundleReview {
    pub bundle_id: String,
    pub bundle_path: String,
    pub manifest_sha256: Option<String>,
    pub source_package_sha256: Option<String>,
    pub artifact_count: u64,
    pub state: String,
    pub code: String,
    pub detail: String,
    pub trusted_exporter_verified: bool,
    pub replay_matched: bool,
    pub recovery_drill_accepted: bool,
    pub route_review_present: bool,
    pub retained_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_delete_count: u64,
    pub legal_hold_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_count: u64,
    pub archive_ready_count: u64,
    pub archive_blocked_count: u64,
    pub quarantine_count: u64,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub reviews: Vec<RelayAlertAssuranceArchiveBundleReview>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutBundleReview {
    pub bundle_id: String,
    pub bundle_path: String,
    pub manifest_sha256: Option<String>,
    pub artifact_count: u64,
    pub state: String,
    pub code: String,
    pub detail: String,
    pub verified_bundle: bool,
    pub replay_matched: bool,
    pub retention_safe: bool,
    pub recovery_drill_accepted: bool,
    pub route_review_present: bool,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_count: u64,
    pub closeout_ready_count: u64,
    pub closeout_blocked_count: u64,
    pub quarantine_count: u64,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub reviews: Vec<RelayAlertAssuranceCloseoutBundleReview>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageMember {
    pub path: String,
    pub kind: String,
    pub bundle_id: String,
    pub artifact_role: String,
    pub schema: String,
    pub sha256: String,
    pub byte_count: u64,
    pub retention_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageBundle {
    pub bundle_id: String,
    pub bundle_path: String,
    pub export_manifest_sha256: String,
    pub export_report_sha256: String,
    pub source_package_sha256: String,
    pub artifact_count: u64,
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageManifestBody {
    pub schema: String,
    pub package_id: String,
    pub local_kernel_id: String,
    pub packager_id: String,
    pub packager_key_id: String,
    pub created_at_unix_ms: u64,
    pub package_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_package_manifest_sha256: Option<String>,
    pub compression_format: String,
    pub source_archive_report_sha256: String,
    pub source_closeout_report_sha256: String,
    pub bundle_count: u64,
    pub member_count: u64,
    pub total_byte_count: u64,
    pub bundles: Vec<RelayAlertAssuranceArchivePackageBundle>,
    pub members: Vec<RelayAlertAssuranceArchivePackageMember>,
    pub safety_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageManifest {
    pub schema: String,
    pub body: RelayAlertAssuranceArchivePackageManifestBody,
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackage {
    pub manifest: RelayAlertAssuranceArchivePackageManifest,
    pub files: Vec<RelayAlertAssuranceArchivePackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedArchivePackager {
    pub packager_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedArchivePackagersDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub min_created_at_unix_ms: u64,
    pub packagers: Vec<RelayAlertAssuranceTrustedArchivePackager>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchivePackageReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub package_id: String,
    pub package_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_package_manifest_sha256: Option<String>,
    pub package_manifest_sha256: String,
    pub source_archive_report_sha256: String,
    pub source_closeout_report_sha256: String,
    pub package_member_count: usize,
    pub package_total_byte_count: u64,
    pub bundle_count: u64,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub trusted_packager_verified: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub nested_exporter_verified: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub source_reports_matched: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub closeout_ready_verified: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub total_byte_count_matched: bool,
    pub extractable: bool,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveExtractionReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub package_id: String,
    pub package_manifest_sha256: String,
    pub planned_member_count: u64,
    pub extracted_member_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveRestoreProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub profile_id: String,
    pub max_package_count: u64,
    pub require_generation_continuity: bool,
    pub require_physical_readback: bool,
    pub require_retention_handoff_ready: bool,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveRestorePackageReview {
    pub package_id: String,
    pub package_generation: u64,
    pub package_manifest_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_package_manifest_sha256: Option<String>,
    pub accepted: bool,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveRestoreDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub package_count: u64,
    pub verified_generation_count: u64,
    pub latest_package_generation: u64,
    pub quarantine_count: u64,
    pub blocked_count: u64,
    pub packages: Vec<RelayAlertAssuranceArchiveRestorePackageReview>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssurancePhysicalArchiveEvidence {
    pub schema: String,
    pub local_kernel_id: String,
    pub evidence_id: String,
    pub package_id: String,
    pub package_report_sha256: String,
    pub package_manifest_sha256: String,
    pub observed_at_unix_ms: u64,
    pub sampled_member_count: u64,
    pub media_alias: String,
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssurancePhysicalArchiveDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub evidence_id: String,
    pub package_id: String,
    pub package_report_sha256: String,
    pub sampled_member_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionHandoffProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub allowed_system_aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionHandoffEvidence {
    pub schema: String,
    pub local_kernel_id: String,
    pub evidence_id: String,
    pub package_id: String,
    pub package_report_sha256: String,
    pub target_system_alias: String,
    pub observed_at_unix_ms: u64,
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionHandoffReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub evidence_id: String,
    pub package_id: String,
    pub package_report_sha256: String,
    pub target_system_alias: String,
    pub ready_for_operator_handoff: bool,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExternalRetentionProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub allowed_retention_system_aliases: Vec<String>,
    pub max_package_count: u64,
    pub max_evidence_age_ms: u64,
    pub require_generation_continuity: bool,
    pub require_restore_accepted: bool,
    pub require_physical_readback: bool,
    pub require_retention_handoff_ready: bool,
    pub min_sampled_members: u64,
    pub min_sample_coverage_basis_points: u64,
    pub recommendation_codes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExternalRetentionPackageReview {
    pub package_id: String,
    pub package_generation: u64,
    pub package_manifest_sha256: String,
    pub package_report_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_system_alias: Option<String>,
    pub sample_coverage_basis_points: u64,
    pub restore_status: String,
    pub physical_readback_status: String,
    pub retention_handoff_status: String,
    pub accepted: bool,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExternalRetentionReviewReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub package_count: u64,
    pub ready_count: u64,
    pub latest_package_generation: u64,
    pub quarantine_count: u64,
    pub drift_count: u64,
    pub insufficient_sample_count: u64,
    pub reviews: Vec<RelayAlertAssuranceExternalRetentionPackageReview>,
    pub recommendations: Vec<RelayOperatorRecommendation>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertAssuranceArchiveInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceArchiveBundleCandidate],
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub archive_profile: &'a RelayAlertAssuranceArchiveProfileDocument,
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceCloseoutInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceArchiveBundleCandidate],
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub closeout_profile: &'a RelayAlertAssuranceCloseoutProfileDocument,
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceArchivePackageBuildInput<'a> {
    pub package_id: &'a str,
    pub packager_id: &'a str,
    pub packager_key_id: &'a str,
    pub package_generation: u64,
    pub previous_package_report: Option<&'a RelayAlertAssuranceArchivePackageReport>,
    pub signing_key: &'a Keypair,
    pub bundles: &'a [RelayAlertAssuranceArchiveBundleCandidate],
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub archive_report: &'a RelayAlertAssuranceArchiveReport,
    pub closeout_report: &'a RelayAlertAssuranceCloseoutReport,
    pub created_at_unix_ms: u64,
}

pub struct RelayAlertAssuranceArchivePackageVerifyInput<'a> {
    pub package: &'a RelayAlertAssuranceArchivePackage,
    pub trusted_packagers: &'a RelayAlertAssuranceTrustedArchivePackagersDocument,
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub archive_report: &'a RelayAlertAssuranceArchiveReport,
    pub closeout_report: &'a RelayAlertAssuranceCloseoutReport,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceArchiveRestoreDrillInput<'a> {
    pub package_reports: &'a [RelayAlertAssuranceArchivePackageReport],
    pub physical_drill_reports: &'a [RelayAlertAssurancePhysicalArchiveDrillReport],
    pub retention_handoff_reports: &'a [RelayAlertAssuranceRetentionHandoffReport],
    pub restore_profile: &'a RelayAlertAssuranceArchiveRestoreProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssurancePhysicalArchiveDrillInput<'a> {
    pub evidence: &'a RelayAlertAssurancePhysicalArchiveEvidence,
    pub expected_package_id: &'a str,
    pub expected_package_report_sha256: &'a str,
    pub expected_package_manifest_sha256: &'a str,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceRetentionHandoffInput<'a> {
    pub evidence: &'a RelayAlertAssuranceRetentionHandoffEvidence,
    pub profile: &'a RelayAlertAssuranceRetentionHandoffProfileDocument,
    pub expected_package_id: &'a str,
    pub expected_package_report_sha256: &'a str,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceExternalRetentionReviewInput<'a> {
    pub package_reports: &'a [RelayAlertAssuranceArchivePackageReport],
    pub restore_drill_reports: &'a [RelayAlertAssuranceArchiveRestoreDrillReport],
    pub physical_drill_reports: &'a [RelayAlertAssurancePhysicalArchiveDrillReport],
    pub retention_handoff_reports: &'a [RelayAlertAssuranceRetentionHandoffReport],
    pub profile: &'a RelayAlertAssuranceExternalRetentionProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub now_unix_ms: u64,
}

pub fn generate_relay_alert_assurance_archive_report(
    input: RelayAlertAssuranceArchiveInput<'_>,
) -> Result<RelayAlertAssuranceArchiveReport, PheromoneRelayError> {
    validate_archive_profile(input.archive_profile, input.now_unix_ms)?;
    validate_retention_profile(input.retention_profile, input.now_unix_ms)?;
    validate_archive_input_roots(
        input.archive_profile.local_kernel_id.as_str(),
        input.trusted_exporters.local_kernel_id.as_str(),
        input.retention_profile.local_kernel_id.as_str(),
    )?;
    validate_archive_candidates(input.bundles)?;

    let mut reviews = Vec::new();
    for candidate in input.bundles {
        reviews.push(review_archive_candidate(
            candidate,
            input.trusted_exporters,
            input.retention_profile,
            input.archive_profile.require_replay_match,
            input.archive_profile.require_recovery_drill,
            input.now_unix_ms,
        )?);
    }
    let archive_ready_count = reviews
        .iter()
        .filter(|review| review.state == "archive_ready")
        .count() as u64;
    let archive_blocked_count = reviews
        .iter()
        .filter(|review| review.state == "archive_blocked")
        .count() as u64;
    let quarantine_count = reviews
        .iter()
        .filter(|review| review.state == "quarantine")
        .count() as u64;
    let legal_hold_count = reviews.iter().map(|review| review.legal_hold_count).sum();
    let eligible_for_delete_count = reviews
        .iter()
        .map(|review| review.eligible_for_delete_count)
        .sum();
    let accepted = archive_blocked_count == 0 && quarantine_count == 0;
    Ok(RelayAlertAssuranceArchiveReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "archive_attention_required"
        }
        .to_string(),
        local_kernel_id: input.archive_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        bundle_count: reviews.len() as u64,
        archive_ready_count,
        archive_blocked_count,
        quarantine_count,
        legal_hold_count,
        eligible_for_delete_count,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "archive_report_only".to_string(),
            accepted: true,
            detail: "archive lifecycle evaluation is report-only and does not move, delete, or upload evidence"
                .to_string(),
        }],
    })
}

pub fn generate_relay_alert_assurance_closeout_report(
    input: RelayAlertAssuranceCloseoutInput<'_>,
) -> Result<RelayAlertAssuranceCloseoutReport, PheromoneRelayError> {
    validate_closeout_profile(input.closeout_profile, input.now_unix_ms)?;
    validate_retention_profile(input.retention_profile, input.now_unix_ms)?;
    validate_archive_input_roots(
        input.closeout_profile.local_kernel_id.as_str(),
        input.trusted_exporters.local_kernel_id.as_str(),
        input.retention_profile.local_kernel_id.as_str(),
    )?;
    let archive_profile = RelayAlertAssuranceArchiveProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA.to_string(),
        local_kernel_id: input.closeout_profile.local_kernel_id.clone(),
        issued_at_unix_ms: input.closeout_profile.issued_at_unix_ms,
        expires_at_unix_ms: input.closeout_profile.expires_at_unix_ms,
        require_replay_match: input.closeout_profile.require_replay_match,
        require_recovery_drill: input.closeout_profile.require_recovery_drill,
    };
    let archive_report =
        generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
            bundles: input.bundles,
            trusted_exporters: input.trusted_exporters,
            archive_profile: &archive_profile,
            retention_profile: input.retention_profile,
            now_unix_ms: input.now_unix_ms,
        })?;

    let mut reviews = Vec::new();
    for archive_review in archive_report.reviews {
        reviews.push(closeout_review_from_archive(
            archive_review,
            input.closeout_profile,
        ));
    }
    let closeout_ready_count = reviews
        .iter()
        .filter(|review| review.state == "closeout_ready")
        .count() as u64;
    let closeout_blocked_count = reviews
        .iter()
        .filter(|review| review.state == "closeout_blocked")
        .count() as u64;
    let quarantine_count = reviews
        .iter()
        .filter(|review| review.state == "quarantine")
        .count() as u64;
    let legal_hold_count = reviews.iter().map(|review| review.legal_hold_count).sum();
    let eligible_for_delete_count = reviews
        .iter()
        .map(|review| review.eligible_for_delete_count)
        .sum();
    let accepted = closeout_blocked_count == 0 && quarantine_count == 0;
    Ok(RelayAlertAssuranceCloseoutReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "closeout_blocked"
        }
        .to_string(),
        local_kernel_id: input.closeout_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        bundle_count: reviews.len() as u64,
        closeout_ready_count,
        closeout_blocked_count,
        quarantine_count,
        legal_hold_count,
        eligible_for_delete_count,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "closeout_report_only".to_string(),
            accepted: true,
            detail: "closeout review is report-only and makes no human notification claim"
                .to_string(),
        }],
    })
}

pub fn sign_relay_alert_assurance_archive_package(
    input: RelayAlertAssuranceArchivePackageBuildInput<'_>,
) -> Result<RelayAlertAssuranceArchivePackage, PheromoneRelayError> {
    validate_archive_package_identity(input.package_id, "package id")?;
    validate_archive_package_identity(input.packager_id, "packager id")?;
    validate_archive_package_identity(input.packager_key_id, "packager key id")?;
    let previous_package_manifest_sha256 = validate_archive_package_generation(
        input.package_generation,
        input.previous_package_report,
    )?;
    validate_archive_candidates(input.bundles)?;
    validate_archive_package_source_reports(input.archive_report, input.closeout_report)?;

    let local_kernel_id = input.archive_report.local_kernel_id.clone();
    if input.closeout_report.local_kernel_id != local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive and closeout reports use different local kernels".to_string(),
        ));
    }
    if !input.archive_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source archive report is not accepted".to_string(),
        ));
    }
    if !input.closeout_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source closeout report is not accepted".to_string(),
        ));
    }

    let mut bundles = Vec::new();
    let mut members = Vec::new();
    let mut files = Vec::new();
    let mut seen_bundle_ids = BTreeSet::new();
    for candidate in input.bundles {
        let bundle = candidate.bundle.as_ref().ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid(format!(
                "bundle {} is unreadable",
                candidate.bundle_path
            ))
        })?;
        verify_relay_alert_assurance_export_bundle(
            bundle,
            input.trusted_exporters,
            input.created_at_unix_ms,
        )?;
        if bundle.manifest.body.local_kernel_id != local_kernel_id {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "bundle local kernel id does not match archive report".to_string(),
            ));
        }
        let bundle_id = bundle.manifest.body.bundle_id.clone();
        if !seen_bundle_ids.insert(bundle_id.clone()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate bundle id {bundle_id}"
            )));
        }
        push_archive_package_json_member(
            &mut members,
            &mut files,
            &candidate.bundle_path,
            &bundle_id,
            "export_manifest",
            PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
            "manifest.json",
            "incident_evidence",
            &bundle.manifest,
        )?;
        push_archive_package_json_member(
            &mut members,
            &mut files,
            &candidate.bundle_path,
            &bundle_id,
            "export_report",
            PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
            "relay-alert-assurance-export-report.json",
            "incident_evidence",
            &bundle.report,
        )?;
        for artifact in &bundle.manifest.body.artifacts {
            let file = bundle
                .files
                .iter()
                .find(|file| file.path == artifact.path)
                .ok_or_else(|| {
                    PheromoneRelayError::ArchivePackageInvalid(format!(
                        "artifact {} is missing from export bundle",
                        artifact.path
                    ))
                })?;
            push_archive_package_bytes_member(
                &mut members,
                &mut files,
                &candidate.bundle_path,
                &bundle_id,
                &artifact.role,
                &artifact.schema,
                &artifact.path,
                &artifact.retention_class,
                &file.bytes,
            )?;
        }
        bundles.push(RelayAlertAssuranceArchivePackageBundle {
            bundle_id,
            bundle_path: candidate.bundle_path.clone(),
            export_manifest_sha256: canonical_sha256(&bundle.manifest)?,
            export_report_sha256: canonical_sha256(&bundle.report)?,
            source_package_sha256: bundle.manifest.body.source_package_sha256.clone(),
            artifact_count: bundle.manifest.body.artifacts.len() as u64,
        });
    }
    validate_archive_package_member_set(&members, &files)?;
    let total_byte_count = archive_package_total_bytes(&files)?;
    let bundle_count = u64::try_from(bundles.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("bundle count overflow".to_string())
    })?;
    let member_count = u64::try_from(members.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("member count overflow".to_string())
    })?;
    let body = RelayAlertAssuranceArchivePackageManifestBody {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA.to_string(),
        package_id: input.package_id.to_string(),
        local_kernel_id,
        packager_id: input.packager_id.to_string(),
        packager_key_id: input.packager_key_id.to_string(),
        created_at_unix_ms: input.created_at_unix_ms,
        package_generation: input.package_generation,
        previous_package_manifest_sha256,
        compression_format: "tar.gz".to_string(),
        source_archive_report_sha256: canonical_sha256(input.archive_report)?,
        source_closeout_report_sha256: canonical_sha256(input.closeout_report)?,
        bundle_count,
        member_count,
        total_byte_count,
        bundles,
        members,
        safety_claims: vec![
            "local_archive_package_only".to_string(),
            "manifest_hash_trusted".to_string(),
            "no_upload_delete_move".to_string(),
            "no_live_notification_delivery".to_string(),
            "no_policy_mutation".to_string(),
            "no_dynamic_trust".to_string(),
        ],
    };
    validate_archive_package_manifest_body(&body)?;
    validate_archive_package_source_bundle_reviews(
        &body.bundles,
        input.archive_report,
        input.closeout_report,
    )?;
    let (signature, _) = input
        .signing_key
        .sign_canonical(&body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(RelayAlertAssuranceArchivePackage {
        manifest: RelayAlertAssuranceArchivePackageManifest {
            schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA.to_string(),
            body,
            signer_public_key: input.signing_key.public_key(),
            signature,
        },
        files,
    })
}

pub fn verify_relay_alert_assurance_archive_package(
    input: RelayAlertAssuranceArchivePackageVerifyInput<'_>,
) -> Result<RelayAlertAssuranceArchivePackageReport, PheromoneRelayError> {
    validate_archive_package_manifest(input.package)?;
    validate_trusted_archive_packagers(
        input.trusted_packagers,
        &input.package.manifest,
        input.now_unix_ms,
    )?;
    validate_archive_package_member_set(
        &input.package.manifest.body.members,
        &input.package.files,
    )?;
    validate_archive_package_source_reports(input.archive_report, input.closeout_report)?;
    let body = &input.package.manifest.body;
    if body.source_archive_report_sha256 != canonical_sha256(input.archive_report)? {
        return Err(PheromoneRelayError::BodyHashMismatch(
            "archive report hash does not match package manifest".to_string(),
        ));
    }
    if body.source_closeout_report_sha256 != canonical_sha256(input.closeout_report)? {
        return Err(PheromoneRelayError::BodyHashMismatch(
            "closeout report hash does not match package manifest".to_string(),
        ));
    }
    if input.archive_report.local_kernel_id != body.local_kernel_id
        || input.closeout_report.local_kernel_id != body.local_kernel_id
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source reports local kernel id mismatch".to_string(),
        ));
    }
    if !input.archive_report.accepted || !input.closeout_report.accepted {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "source reports are not accepted".to_string(),
        ));
    }
    validate_archive_package_source_bundle_reviews(
        &body.bundles,
        input.archive_report,
        input.closeout_report,
    )?;

    for bundle in &body.bundles {
        let nested = export_bundle_from_archive_package(input.package, bundle)?;
        verify_relay_alert_assurance_export_bundle(
            &nested,
            input.trusted_exporters,
            input.now_unix_ms,
        )?;
        if canonical_sha256(&nested.manifest)? != bundle.export_manifest_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(
                "nested export manifest hash mismatch".to_string(),
            ));
        }
        if canonical_sha256(&nested.report)? != bundle.export_report_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(
                "nested export report hash mismatch".to_string(),
            ));
        }
    }
    let recomputed_total_byte_count = archive_package_total_bytes(&input.package.files)?;
    Ok(RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: body.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        package_id: body.package_id.clone(),
        package_generation: body.package_generation,
        previous_package_manifest_sha256: body.previous_package_manifest_sha256.clone(),
        package_manifest_sha256: canonical_sha256(&input.package.manifest)?,
        source_archive_report_sha256: body.source_archive_report_sha256.clone(),
        source_closeout_report_sha256: body.source_closeout_report_sha256.clone(),
        package_member_count: input.package.files.len(),
        package_total_byte_count: recomputed_total_byte_count,
        bundle_count: body.bundle_count,
        trusted_packager_verified: true,
        nested_exporter_verified: true,
        source_reports_matched: true,
        closeout_ready_verified: true,
        total_byte_count_matched: true,
        extractable: true,
        checks: vec![
            RelayAlertCheck {
                code: "trusted_archive_packager".to_string(),
                accepted: true,
                detail: "archive package signer is trusted by caller-supplied packager roots"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "exact_member_set".to_string(),
                accepted: true,
                detail: "package members match manifest paths, byte counts, hashes, and bundles"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "nested_exporters".to_string(),
                accepted: true,
                detail: "nested export bundles verify against caller-supplied exporter roots"
                    .to_string(),
            },
        ],
    })
}

pub fn build_relay_alert_assurance_archive_extraction_report(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    extracted_member_count: u64,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceArchiveExtractionReport, PheromoneRelayError> {
    let planned_member_count =
        u64::try_from(package_report.package_member_count).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("package member count overflow".to_string())
        })?;
    let accepted = package_report.accepted && extracted_member_count == planned_member_count;
    Ok(RelayAlertAssuranceArchiveExtractionReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_EXTRACTION_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "extraction_incomplete".to_string()
        },
        local_kernel_id: package_report.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        package_id: package_report.package_id.clone(),
        package_manifest_sha256: package_report.package_manifest_sha256.clone(),
        planned_member_count,
        extracted_member_count,
        checks: vec![RelayAlertCheck {
            code: "verified_extraction_plan".to_string(),
            accepted,
            detail: "extraction report is derived from a verified package report".to_string(),
        }],
    })
}

pub fn validate_relay_alert_assurance_archive_package_report(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> Result<(), PheromoneRelayError> {
    if let Some(failure) = archive_package_report_integrity_failure(report) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            failure.to_string(),
        ));
    }
    Ok(())
}

pub fn generate_relay_alert_assurance_archive_restore_drill_report(
    input: RelayAlertAssuranceArchiveRestoreDrillInput<'_>,
) -> Result<RelayAlertAssuranceArchiveRestoreDrillReport, PheromoneRelayError> {
    validate_archive_restore_profile(input.restore_profile, input.now_unix_ms)?;
    if input.package_reports.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore drill requires at least one package report".to_string(),
        ));
    }
    let max_package_count =
        usize::try_from(input.restore_profile.max_package_count).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("restore package count overflow".to_string())
        })?;
    if input.package_reports.len() > max_package_count {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore drill package count exceeds profile limit".to_string(),
        ));
    }

    let mut package_reports: Vec<&RelayAlertAssuranceArchivePackageReport> =
        input.package_reports.iter().collect();
    package_reports.sort_by_key(|report| report.package_generation);
    let mut seen_generations = BTreeSet::new();
    let mut reviews = Vec::new();
    let mut checks = Vec::new();
    let mut previous_manifest_hash: Option<String> = None;
    let mut latest_generation = 0_u64;
    let mut quarantine_count = 0_u64;

    for report in package_reports {
        let package_report_failure = archive_package_report_integrity_failure(report);
        let mut accepted = report.accepted;
        let mut code = if report.accepted {
            "accepted".to_string()
        } else {
            "package_report_rejected".to_string()
        };
        if let Some(failure) = package_report_failure {
            accepted = false;
            code = failure.to_string();
        }
        if accepted && report.local_kernel_id != input.restore_profile.local_kernel_id {
            accepted = false;
            code = "local_kernel_mismatch".to_string();
        }
        if accepted && seen_generations.contains(&report.package_generation) {
            accepted = false;
            code = "duplicate_generation".to_string();
        }
        if accepted && input.restore_profile.require_generation_continuity {
            let expected_generation = latest_generation.saturating_add(1);
            if report.package_generation != expected_generation {
                accepted = false;
                code = "generation_gap".to_string();
            } else if report.package_generation > 1
                && report.previous_package_manifest_sha256 != previous_manifest_hash
            {
                accepted = false;
                code = "previous_manifest_hash_mismatch".to_string();
            }
        }
        if accepted
            && input.restore_profile.require_physical_readback
            && !has_matching_physical_readback(report, input.physical_drill_reports)?
        {
            accepted = false;
            code = "missing_physical_readback".to_string();
        }
        if accepted
            && input.restore_profile.require_retention_handoff_ready
            && !has_matching_retention_handoff(report, input.retention_handoff_reports)?
        {
            accepted = false;
            code = "retention_handoff_not_ready".to_string();
        }
        if !accepted {
            quarantine_count = quarantine_count.saturating_add(1);
        }
        checks.push(RelayAlertCheck {
            code: format!("package_generation_{}", report.package_generation),
            accepted,
            detail: code.clone(),
        });
        reviews.push(RelayAlertAssuranceArchiveRestorePackageReview {
            package_id: report.package_id.clone(),
            package_generation: report.package_generation,
            package_manifest_sha256: report.package_manifest_sha256.clone(),
            previous_package_manifest_sha256: report.previous_package_manifest_sha256.clone(),
            accepted,
            code,
        });
        if accepted {
            seen_generations.insert(report.package_generation);
            latest_generation = latest_generation.max(report.package_generation);
            previous_manifest_hash = Some(report.package_manifest_sha256.clone());
        }
    }

    let accepted = checks.iter().all(|check| check.accepted);
    let package_count = u64::try_from(input.package_reports.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("restore package count overflow".to_string())
    })?;
    Ok(RelayAlertAssuranceArchiveRestoreDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "restore_blocked".to_string()
        },
        local_kernel_id: input.restore_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        package_count,
        verified_generation_count: package_count.saturating_sub(quarantine_count),
        latest_package_generation: latest_generation,
        quarantine_count,
        blocked_count: quarantine_count,
        packages: reviews,
        checks,
    })
}

pub fn generate_relay_alert_assurance_physical_archive_drill_report(
    input: RelayAlertAssurancePhysicalArchiveDrillInput<'_>,
) -> Result<RelayAlertAssurancePhysicalArchiveDrillReport, PheromoneRelayError> {
    validate_physical_archive_evidence(input.evidence)?;
    if input.evidence.package_id != input.expected_package_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package id mismatch".to_string(),
        ));
    }
    if input.evidence.package_report_sha256 != input.expected_package_report_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package report hash mismatch".to_string(),
        ));
    }
    if input.evidence.package_manifest_sha256 != input.expected_package_manifest_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package manifest hash mismatch".to_string(),
        ));
    }
    if input.now_unix_ms < input.evidence.observed_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence is from the future".to_string(),
        ));
    }
    Ok(RelayAlertAssurancePhysicalArchiveDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.evidence.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        evidence_id: input.evidence.evidence_id.clone(),
        package_id: input.evidence.package_id.clone(),
        package_report_sha256: input.evidence.package_report_sha256.clone(),
        sampled_member_count: input.evidence.sampled_member_count,
        checks: vec![
            RelayAlertCheck {
                code: "local_readback_evidence".to_string(),
                accepted: true,
                detail: "operator-provided local readback evidence is hash-bound to package report"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "physical_media_not_controlled".to_string(),
                accepted: true,
                detail: "report does not claim Chio wrote to or controls physical media"
                    .to_string(),
            },
        ],
    })
}

pub fn generate_relay_alert_assurance_retention_handoff_report(
    input: RelayAlertAssuranceRetentionHandoffInput<'_>,
) -> Result<RelayAlertAssuranceRetentionHandoffReport, PheromoneRelayError> {
    validate_retention_handoff_profile(input.profile, input.now_unix_ms)?;
    validate_retention_handoff_evidence(input.evidence)?;
    if input.evidence.package_id != input.expected_package_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff package id mismatch".to_string(),
        ));
    }
    if input.evidence.package_report_sha256 != input.expected_package_report_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff package report hash mismatch".to_string(),
        ));
    }
    if input.evidence.local_kernel_id != input.profile.local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff local kernel id mismatch".to_string(),
        ));
    }
    if !input
        .profile
        .allowed_system_aliases
        .iter()
        .any(|alias| alias == &input.evidence.target_system_alias)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff target alias is not allowed".to_string(),
        ));
    }
    if input.now_unix_ms < input.evidence.observed_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff evidence is from the future".to_string(),
        ));
    }
    Ok(RelayAlertAssuranceRetentionHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.evidence.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        evidence_id: input.evidence.evidence_id.clone(),
        package_id: input.evidence.package_id.clone(),
        package_report_sha256: input.evidence.package_report_sha256.clone(),
        target_system_alias: input.evidence.target_system_alias.clone(),
        ready_for_operator_handoff: true,
        checks: vec![
            RelayAlertCheck {
                code: "local_evidence_only".to_string(),
                accepted: true,
                detail: "retention handoff uses bounded aliases and local hashes only".to_string(),
            },
            RelayAlertCheck {
                code: "operator_managed_handoff".to_string(),
                accepted: true,
                detail: "report claims readiness for operator-managed handoff only".to_string(),
            },
        ],
    })
}

pub fn relay_alert_assurance_external_retention_profile_from_json(
    input: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceExternalRetentionProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertAssuranceExternalRetentionProfileDocument = serde_json::from_str(input)?;
    validate_external_retention_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn generate_relay_alert_assurance_external_retention_review_report(
    input: RelayAlertAssuranceExternalRetentionReviewInput<'_>,
) -> Result<RelayAlertAssuranceExternalRetentionReviewReport, PheromoneRelayError> {
    validate_external_retention_profile(input.profile, input.now_unix_ms)?;
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention review window is invalid".to_string(),
        ));
    }
    if input.package_reports.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention review requires at least one package report".to_string(),
        ));
    }
    let max_package_count = usize::try_from(input.profile.max_package_count).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count overflow".to_string(),
        )
    })?;
    if input.package_reports.len() > max_package_count {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count exceeds profile limit".to_string(),
        ));
    }

    let mut package_reports: Vec<&RelayAlertAssuranceArchivePackageReport> =
        input.package_reports.iter().collect();
    package_reports.sort_by_key(|report| report.package_generation);

    let mut seen_generations = BTreeSet::new();
    let mut previous_manifest_hash: Option<String> = None;
    let mut latest_generation = 0_u64;
    let mut expected_alias: Option<String> = None;
    let mut reviews = Vec::new();
    let mut checks = Vec::new();
    let mut quarantine_count = 0_u64;
    let mut drift_count = 0_u64;
    let mut insufficient_sample_count = 0_u64;

    for report in package_reports {
        if let Some(failure) = archive_package_report_integrity_failure(report) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "external retention package report rejected: {failure}"
            )));
        }
        let package_report_sha256 = canonical_sha256(report)?;
        let mut accepted = true;
        let mut code = "accepted".to_string();
        let mut restore_status = "not_required".to_string();
        let mut physical_readback_status = "not_required".to_string();
        let mut retention_handoff_status = "not_required".to_string();
        let mut target_system_alias = None;
        let mut accepted_alias_candidate = None;
        let mut sample_coverage_basis_points = 0_u64;

        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.local_kernel_id == input.profile.local_kernel_id,
            "local_kernel",
            "local_kernel_mismatch",
            "package report local kernel matches external retention profile",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.accepted,
            "package_report",
            "package_report_rejected",
            "archive package report is accepted",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.source_reports_matched,
            "source_reports_matched",
            "source_report_mismatch",
            "archive package report is bound to matching archive and closeout reports",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.closeout_ready_verified,
            "closeout_ready",
            "closeout_not_ready",
            "archive package report verified closeout readiness",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.total_byte_count_matched,
            "total_byte_count",
            "total_byte_mismatch",
            "archive package report verified package byte totals",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.extractable,
            "package_extractable",
            "package_not_extractable",
            "archive package report is extractable by the safe archive path",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.trusted_packager_verified,
            "trusted_packager",
            "untrusted_packager",
            "archive package report verified the trusted packager",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.nested_exporter_verified,
            "trusted_exporter",
            "untrusted_exporter",
            "archive package report verified nested exporters",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            external_retention_fresh(
                report.generated_at_unix_ms,
                input.since_unix_ms,
                input.until_unix_ms,
                input.now_unix_ms,
                input.profile.max_evidence_age_ms,
            ),
            "package_report_freshness",
            "stale_evidence",
            "archive package report is inside the review window and freshness bound",
        );

        if !seen_generations.insert(report.package_generation) {
            external_retention_fail(
                &mut checks,
                &mut accepted,
                &mut code,
                "duplicate_generation",
                "duplicate package generation in external retention review",
            );
        }
        if input.profile.require_generation_continuity {
            let expected_generation = latest_generation.saturating_add(1);
            if report.package_generation != expected_generation {
                external_retention_fail(
                    &mut checks,
                    &mut accepted,
                    &mut code,
                    "generation_gap",
                    "package generations are not contiguous",
                );
            }
            if report.package_generation > 1
                && report.previous_package_manifest_sha256 != previous_manifest_hash
            {
                external_retention_fail(
                    &mut checks,
                    &mut accepted,
                    &mut code,
                    "previous_manifest_mismatch",
                    "previous package manifest hash does not bind to prior generation",
                );
            }
        }

        let package_level_accepted = accepted;
        let package_level_code = code.clone();

        if input.profile.require_restore_accepted {
            match external_retention_restore_status(input.restore_drill_reports, report) {
                ExternalRetentionEvidence::Missing => {
                    restore_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_restore_drill",
                        "no restore drill report covers this package generation",
                    );
                }
                ExternalRetentionEvidence::Single(restore) => {
                    let (status, status_valid) = external_retention_report_status(
                        &restore.code,
                        "restore drill report status",
                    );
                    restore_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "restore drill report status is not schema-safe",
                        );
                    }
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        restore.local_kernel_id == input.profile.local_kernel_id,
                        "restore_drill_local_kernel",
                        "local_kernel_mismatch",
                        "restore drill report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        restore.accepted,
                        "restore_drill",
                        "rejected_restore_drill",
                        "restore drill accepts this package generation",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            restore.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "restore_drill_freshness",
                        "stale_evidence",
                        "restore drill report is inside the review window and freshness bound",
                    );
                }
                ExternalRetentionEvidence::Duplicate => {
                    restore_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_restore_drill_evidence",
                        "multiple restore drill reports match this package report",
                    );
                }
            }
        }

        if input.profile.require_physical_readback {
            match external_retention_physical_reports(
                input.physical_drill_reports,
                &package_report_sha256,
                &report.package_id,
            )
            .as_slice()
            {
                [] => {
                    physical_readback_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_physical_readback",
                        "no physical readback report matches this package report",
                    );
                }
                [physical] => {
                    let (status, status_valid) = external_retention_report_status(
                        &physical.code,
                        "physical readback report status",
                    );
                    physical_readback_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "physical readback report status is not schema-safe",
                        );
                    }
                    let package_member_count =
                        u64::try_from(report.package_member_count).map_err(|_| {
                            PheromoneRelayError::ArchivePackageInvalid(
                                "external retention member count overflow".to_string(),
                            )
                        })?;
                    let sample_within_package =
                        physical.sampled_member_count <= package_member_count;
                    sample_coverage_basis_points = external_retention_sample_coverage(
                        physical.sampled_member_count,
                        package_member_count,
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        physical.local_kernel_id == input.profile.local_kernel_id,
                        "physical_readback_local_kernel",
                        "local_kernel_mismatch",
                        "physical readback report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        physical.accepted,
                        "physical_readback",
                        "rejected_physical_readback",
                        "physical readback report is accepted",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            physical.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "physical_readback_freshness",
                        "stale_evidence",
                        "physical readback report is inside the review window and freshness bound",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        sample_within_package,
                        "physical_readback_sample_bound",
                        "sample_exceeds_package_size",
                        "physical readback sample count does not exceed package member count",
                    );
                    let sample_ok = sample_within_package
                        && physical.sampled_member_count >= input.profile.min_sampled_members
                        && sample_coverage_basis_points
                            >= input.profile.min_sample_coverage_basis_points;
                    if sample_within_package && !sample_ok {
                        insufficient_sample_count = insufficient_sample_count.saturating_add(1);
                    }
                    if sample_within_package {
                        external_retention_check(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            sample_ok,
                            "physical_readback_sample",
                            "insufficient_sample",
                            "physical readback sample satisfies external retention profile",
                        );
                    }
                }
                _ => {
                    physical_readback_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_physical_readback_evidence",
                        "multiple physical readback reports match this package report",
                    );
                }
            }
        }

        if input.profile.require_retention_handoff_ready {
            let matching_handoffs = external_retention_handoffs(
                input.retention_handoff_reports,
                &package_report_sha256,
                &report.package_id,
            );
            match matching_handoffs.as_slice() {
                [] => {
                    retention_handoff_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_retention_handoff",
                        "no retention handoff report matches this package report",
                    );
                }
                [handoff] => {
                    let (status, status_valid) = external_retention_report_status(
                        &handoff.code,
                        "retention handoff report status",
                    );
                    retention_handoff_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "retention handoff report status is not schema-safe",
                        );
                    }
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        handoff.local_kernel_id == input.profile.local_kernel_id,
                        "retention_handoff_local_kernel",
                        "local_kernel_mismatch",
                        "retention handoff report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        handoff.accepted && handoff.ready_for_operator_handoff,
                        "retention_handoff",
                        "retention_handoff_not_ready",
                        "retention handoff report is ready for operator review",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            handoff.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "retention_handoff_freshness",
                        "stale_evidence",
                        "retention handoff report is inside the review window and freshness bound",
                    );
                    let alias_schema_valid = validate_external_retention_schema_token(
                        &handoff.target_system_alias,
                        "retention handoff target alias",
                    )
                    .is_ok();
                    let alias_allowed = alias_schema_valid
                        && input
                            .profile
                            .allowed_retention_system_aliases
                            .iter()
                            .any(|alias| alias == &handoff.target_system_alias);
                    if alias_schema_valid {
                        target_system_alias = Some(handoff.target_system_alias.clone());
                    }
                    if !alias_allowed {
                        drift_count = drift_count.saturating_add(1);
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "unknown_retention_alias",
                            "retention handoff target alias is not allowed by profile",
                        );
                    }
                    match (&expected_alias, alias_allowed) {
                        (Some(alias), true) if alias != &handoff.target_system_alias => {
                            drift_count = drift_count.saturating_add(1);
                            external_retention_fail(
                                &mut checks,
                                &mut accepted,
                                &mut code,
                                "alias_drift",
                                "retention handoff target alias drifted across generations",
                            );
                        }
                        (None, true) => {
                            accepted_alias_candidate = Some(handoff.target_system_alias.clone());
                        }
                        _ => {}
                    }
                }
                _ => {
                    retention_handoff_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_handoff_evidence",
                        "multiple retention handoff reports match this package report",
                    );
                }
            }
        }

        if !accepted {
            quarantine_count = quarantine_count.saturating_add(1);
        }
        if !package_level_accepted {
            code = package_level_code;
        }
        if accepted {
            if let Some(alias) = accepted_alias_candidate {
                expected_alias = Some(alias);
            }
            latest_generation = latest_generation.max(report.package_generation);
            previous_manifest_hash = Some(report.package_manifest_sha256.clone());
        }
        reviews.push(RelayAlertAssuranceExternalRetentionPackageReview {
            package_id: report.package_id.clone(),
            package_generation: report.package_generation,
            package_manifest_sha256: report.package_manifest_sha256.clone(),
            package_report_sha256,
            target_system_alias,
            sample_coverage_basis_points,
            restore_status,
            physical_readback_status,
            retention_handoff_status,
            accepted,
            code,
        });
    }

    let package_count = u64::try_from(input.package_reports.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count overflow".to_string(),
        )
    })?;
    let ready_count = package_count.saturating_sub(quarantine_count);
    let accepted = quarantine_count == 0;
    Ok(RelayAlertAssuranceExternalRetentionReviewReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "external_retention_blocked".to_string()
        },
        local_kernel_id: input.profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        package_count,
        ready_count,
        latest_package_generation: latest_generation,
        quarantine_count,
        drift_count,
        insufficient_sample_count,
        reviews,
        recommendations: input
            .profile
            .recommendation_codes
            .iter()
            .map(|code| RelayOperatorRecommendation {
                code: code.clone(),
                severity: if accepted { "info" } else { "warning" }.to_string(),
            })
            .collect(),
        checks,
    })
}

fn validate_archive_package_identity(value: &str, name: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive package {name} is not bounded"
        )));
    }
    if contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive package {name} contains secret material or a dynamic URL"
        )));
    }
    Ok(())
}

fn validate_archive_package_path(path: &str) -> Result<(), PheromoneRelayError> {
    validate_export_path(path).map_err(|error| {
        PheromoneRelayError::ArchivePackageInvalid(format!("unsafe archive path: {error}"))
    })?;
    if !path.is_ascii()
        || path.contains("//")
        || path.chars().any(char::is_whitespace)
        || path.chars().any(char::is_control)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive path must be ASCII, normalized, and non-whitespace".to_string(),
        ));
    }
    Ok(())
}

fn join_archive_package_path(base: &str, child: &str) -> Result<String, PheromoneRelayError> {
    validate_archive_package_path(base)?;
    validate_archive_package_path(child)?;
    let path = format!("{base}/{child}");
    validate_archive_package_path(&path)?;
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn push_archive_package_json_member<T: Serialize>(
    members: &mut Vec<RelayAlertAssuranceArchivePackageMember>,
    files: &mut Vec<RelayAlertAssuranceArchivePackageFile>,
    bundle_path: &str,
    bundle_id: &str,
    artifact_role: &str,
    schema: &str,
    relative_path: &str,
    retention_class: &str,
    value: &T,
) -> Result<(), PheromoneRelayError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    push_archive_package_bytes_member(
        members,
        files,
        bundle_path,
        bundle_id,
        artifact_role,
        schema,
        relative_path,
        retention_class,
        &bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn push_archive_package_bytes_member(
    members: &mut Vec<RelayAlertAssuranceArchivePackageMember>,
    files: &mut Vec<RelayAlertAssuranceArchivePackageFile>,
    bundle_path: &str,
    bundle_id: &str,
    artifact_role: &str,
    schema: &str,
    relative_path: &str,
    retention_class: &str,
    bytes: &[u8],
) -> Result<(), PheromoneRelayError> {
    validate_archive_package_identity(bundle_id, "bundle id")?;
    validate_archive_package_identity(artifact_role, "artifact role")?;
    validate_archive_package_identity(retention_class, "retention class")?;
    if schema.trim().is_empty() || schema.contains("..") {
        return Err(PheromoneRelayError::UnsupportedSchema(schema.to_string()));
    }
    let path = join_archive_package_path(bundle_path, relative_path)?;
    let byte_count = u64::try_from(bytes.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
    })?;
    members.push(RelayAlertAssuranceArchivePackageMember {
        path: path.clone(),
        kind: "regular_file".to_string(),
        bundle_id: bundle_id.to_string(),
        artifact_role: artifact_role.to_string(),
        schema: schema.to_string(),
        sha256: sha256_hex(bytes),
        byte_count,
        retention_class: retention_class.to_string(),
    });
    files.push(RelayAlertAssuranceArchivePackageFile {
        path,
        bytes: bytes.to_vec(),
    });
    Ok(())
}

fn archive_package_total_bytes(
    files: &[RelayAlertAssuranceArchivePackageFile],
) -> Result<u64, PheromoneRelayError> {
    files.iter().try_fold(0_u64, |total, file| {
        let len = u64::try_from(file.bytes.len()).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })?;
        total.checked_add(len).ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid("package byte count overflow".to_string())
        })
    })
}

fn validate_archive_package_source_reports(
    archive_report: &RelayAlertAssuranceArchiveReport,
    closeout_report: &RelayAlertAssuranceCloseoutReport,
) -> Result<(), PheromoneRelayError> {
    if archive_report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            archive_report.schema.clone(),
        ));
    }
    if closeout_report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            closeout_report.schema.clone(),
        ));
    }
    Ok(())
}

fn validate_archive_package_source_bundle_reviews(
    bundles: &[RelayAlertAssuranceArchivePackageBundle],
    archive_report: &RelayAlertAssuranceArchiveReport,
    closeout_report: &RelayAlertAssuranceCloseoutReport,
) -> Result<(), PheromoneRelayError> {
    if archive_report.reviews.len() != bundles.len()
        || closeout_report.reviews.len() != bundles.len()
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package bundle count does not match source reports".to_string(),
        ));
    }
    for bundle in bundles {
        let archive_review = archive_report
            .reviews
            .iter()
            .find(|review| review.bundle_id == bundle.bundle_id)
            .ok_or_else(|| {
                PheromoneRelayError::ArchivePackageInvalid(format!(
                    "archive report missing package bundle {}",
                    bundle.bundle_id
                ))
            })?;
        let closeout_review = closeout_report
            .reviews
            .iter()
            .find(|review| review.bundle_id == bundle.bundle_id)
            .ok_or_else(|| {
                PheromoneRelayError::ArchivePackageInvalid(format!(
                    "closeout report missing package bundle {}",
                    bundle.bundle_id
                ))
            })?;
        if archive_review.bundle_path != bundle.bundle_path
            || archive_review.manifest_sha256.as_deref()
                != Some(bundle.export_manifest_sha256.as_str())
            || archive_review.source_package_sha256.as_deref()
                != Some(bundle.source_package_sha256.as_str())
            || archive_review.artifact_count != bundle.artifact_count
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive report review does not match package bundle {}",
                bundle.bundle_id
            )));
        }
        if closeout_review.bundle_path != bundle.bundle_path
            || closeout_review.manifest_sha256.as_deref()
                != Some(bundle.export_manifest_sha256.as_str())
            || closeout_review.artifact_count != bundle.artifact_count
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "closeout report review does not match package bundle {}",
                bundle.bundle_id
            )));
        }
        if archive_review.state != "archive_ready" || !archive_review.trusted_exporter_verified {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive report review is not archive-ready for bundle {}",
                bundle.bundle_id
            )));
        }
        if closeout_review.state != "closeout_ready" || !closeout_review.verified_bundle {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "closeout report review is not closeout-ready for bundle {}",
                bundle.bundle_id
            )));
        }
    }
    Ok(())
}

fn validate_archive_package_generation(
    generation: u64,
    previous_package_report: Option<&RelayAlertAssuranceArchivePackageReport>,
) -> Result<Option<String>, PheromoneRelayError> {
    if generation == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package generation must be at least 1".to_string(),
        ));
    }
    match (generation, previous_package_report) {
        (1, None) => Ok(None),
        (1, Some(_)) => Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation 1 package must not carry a previous package report".to_string(),
        )),
        (_, Some(previous)) => {
            if !previous.accepted {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package report is not accepted".to_string(),
                ));
            }
            if previous.package_generation.saturating_add(1) != generation {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package generation is not contiguous".to_string(),
                ));
            }
            if !is_sha256_hex(&previous.package_manifest_sha256) {
                return Err(PheromoneRelayError::ArchivePackageInvalid(
                    "previous package manifest hash is invalid".to_string(),
                ));
            }
            Ok(Some(previous.package_manifest_sha256.clone()))
        }
        (_, None) => Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation greater than 1 requires a previous package report".to_string(),
        )),
    }
}

fn archive_package_report_integrity_failure(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> Option<&'static str> {
    if report.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA {
        return Some("package_report_schema_invalid");
    }
    if validate_archive_package_identity(&report.package_id, "package id").is_err() {
        return Some("package_report_id_invalid");
    }
    if report.package_generation == 0 {
        return Some("package_report_generation_invalid");
    }
    if report.package_generation == 1 && report.previous_package_manifest_sha256.is_some() {
        return Some("package_report_previous_hash_unexpected");
    }
    if report.package_generation > 1 && report.previous_package_manifest_sha256.is_none() {
        return Some("package_report_previous_hash_missing");
    }
    if !is_sha256_hex(&report.package_manifest_sha256)
        || !is_sha256_hex(&report.source_archive_report_sha256)
        || !is_sha256_hex(&report.source_closeout_report_sha256)
        || matches!(
            report.previous_package_manifest_sha256.as_deref(),
            Some(hash) if !is_sha256_hex(hash)
        )
    {
        return Some("package_report_hash_invalid");
    }
    if report.package_member_count == 0 || report.package_total_byte_count == 0 {
        return Some("package_report_size_invalid");
    }
    if report.bundle_count == 0 {
        return Some("package_report_bundle_count_invalid");
    }
    if report.accepted && report.code != "accepted" {
        return Some("package_report_code_invalid");
    }
    if report.accepted
        && (!report.trusted_packager_verified
            || !report.nested_exporter_verified
            || !report.source_reports_matched
            || !report.closeout_ready_verified
            || !report.total_byte_count_matched
            || !report.extractable)
    {
        return Some("package_report_verification_incomplete");
    }
    if report.checks.is_empty() {
        return Some("package_report_checks_empty");
    }
    if report.checks.iter().any(|check| !check.accepted) {
        return Some("package_report_check_failed");
    }
    None
}

fn validate_archive_restore_profile(
    profile: &RelayAlertAssuranceArchiveRestoreProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_archive_package_identity(&profile.profile_id, "restore profile id")?;
    if profile.max_package_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile max package count must be positive".to_string(),
        ));
    }
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile validity window is invalid".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

fn has_matching_physical_readback(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    physical_reports: &[RelayAlertAssurancePhysicalArchiveDrillReport],
) -> Result<bool, PheromoneRelayError> {
    let report_hash = canonical_sha256(package_report)?;
    Ok(physical_reports.iter().any(|report| {
        report.accepted
            && report.schema == PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA
            && report.local_kernel_id == package_report.local_kernel_id
            && report.package_id == package_report.package_id
            && report.package_report_sha256 == report_hash
            && report.sampled_member_count > 0
            && !report.checks.is_empty()
    }))
}

fn has_matching_retention_handoff(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    handoff_reports: &[RelayAlertAssuranceRetentionHandoffReport],
) -> Result<bool, PheromoneRelayError> {
    let report_hash = canonical_sha256(package_report)?;
    Ok(handoff_reports.iter().any(|report| {
        report.accepted
            && report.schema == PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA
            && report.ready_for_operator_handoff
            && report.local_kernel_id == package_report.local_kernel_id
            && report.package_id == package_report.package_id
            && report.package_report_sha256 == report_hash
            && validate_archive_package_identity(&report.target_system_alias, "target system alias")
                .is_ok()
            && !report.checks.is_empty()
    }))
}

fn validate_archive_package_manifest_body(
    body: &RelayAlertAssuranceArchivePackageManifestBody,
) -> Result<(), PheromoneRelayError> {
    if body.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(body.schema.clone()));
    }
    validate_archive_package_identity(&body.package_id, "package id")?;
    validate_archive_package_identity(&body.packager_id, "packager id")?;
    validate_archive_package_identity(&body.packager_key_id, "packager key id")?;
    if body.compression_format != "tar.gz" {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package compression format must be tar.gz".to_string(),
        ));
    }
    if body.package_generation == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package generation must be at least 1".to_string(),
        ));
    }
    if body.package_generation == 1 && body.previous_package_manifest_sha256.is_some() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "generation 1 package must not carry a previous package hash".to_string(),
        ));
    }
    if body.package_generation > 1 {
        let Some(previous) = &body.previous_package_manifest_sha256 else {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "generation greater than 1 requires a previous package hash".to_string(),
            ));
        };
        if !is_sha256_hex(previous) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "previous package manifest hash is invalid".to_string(),
            ));
        }
    }
    if !is_sha256_hex(&body.source_archive_report_sha256)
        || !is_sha256_hex(&body.source_closeout_report_sha256)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package source report hash is invalid".to_string(),
        ));
    }
    if body.bundles.is_empty() || body.members.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package must contain bundles and members".to_string(),
        ));
    }
    if body.bundle_count != body.bundles.len() as u64
        || body.member_count != body.members.len() as u64
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package counts do not match manifest arrays".to_string(),
        ));
    }
    let member_total = body.members.iter().try_fold(0_u64, |total, member| {
        total.checked_add(member.byte_count).ok_or_else(|| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })
    })?;
    if body.total_byte_count != member_total {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package total byte count does not match members".to_string(),
        ));
    }
    for claim in &body.safety_claims {
        validate_archive_safety_claim(claim)?;
    }
    let mut bundle_ids = BTreeSet::new();
    let mut bundle_paths = BTreeSet::new();
    for bundle in &body.bundles {
        validate_archive_package_identity(&bundle.bundle_id, "bundle id")?;
        validate_archive_package_path(&bundle.bundle_path)?;
        if !bundle_ids.insert(bundle.bundle_id.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate package bundle id {}",
                bundle.bundle_id
            )));
        }
        if !bundle_paths.insert(bundle.bundle_path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate package bundle path {}",
                bundle.bundle_path
            )));
        }
        if !is_sha256_hex(&bundle.export_manifest_sha256)
            || !is_sha256_hex(&bundle.export_report_sha256)
            || !is_sha256_hex(&bundle.source_package_sha256)
        {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "package bundle hash is invalid".to_string(),
            ));
        }
    }
    for member in &body.members {
        let Some(bundle) = body
            .bundles
            .iter()
            .find(|bundle| bundle.bundle_id == member.bundle_id)
        else {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive member {} references unknown bundle {}",
                member.path, member.bundle_id
            )));
        };
        let prefix = format!("{}/", bundle.bundle_path);
        if !member.path.starts_with(&prefix) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive member {} is outside verified bundle {}",
                member.path, bundle.bundle_id
            )));
        }
    }
    Ok(())
}

fn validate_archive_package_manifest(
    package: &RelayAlertAssuranceArchivePackage,
) -> Result<(), PheromoneRelayError> {
    if package.manifest.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            package.manifest.schema.clone(),
        ));
    }
    validate_archive_package_manifest_body(&package.manifest.body)
}

fn validate_trusted_archive_packagers(
    trusted_packagers: &RelayAlertAssuranceTrustedArchivePackagersDocument,
    manifest: &RelayAlertAssuranceArchivePackageManifest,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if trusted_packagers.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA
    {
        return Err(PheromoneRelayError::UnsupportedSchema(
            trusted_packagers.schema.clone(),
        ));
    }
    if trusted_packagers.local_kernel_id != manifest.body.local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted packagers local kernel id mismatch".to_string(),
        ));
    }
    if manifest.body.created_at_unix_ms < trusted_packagers.min_created_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package is older than trusted packager floor".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut packager = None;
    for candidate in &trusted_packagers.packagers {
        validate_archive_package_identity(&candidate.packager_id, "packager id")?;
        validate_archive_package_identity(&candidate.key_id, "packager key id")?;
        if !seen.insert((candidate.packager_id.as_str(), candidate.key_id.as_str())) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate trusted archive packager".to_string(),
            ));
        }
        if candidate.packager_id == manifest.body.packager_id
            && candidate.key_id == manifest.body.packager_key_id
        {
            packager = Some(candidate);
        }
    }
    let packager = packager.ok_or(PheromoneRelayError::SignatureInvalid)?;
    if packager.status != "active" {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted archive packager is not active".to_string(),
        ));
    }
    if manifest.signer_public_key != packager.public_key {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    if now_unix_ms < packager.valid_from_unix_ms
        || now_unix_ms >= packager.valid_until_unix_ms
        || manifest.body.created_at_unix_ms < packager.valid_from_unix_ms
        || manifest.body.created_at_unix_ms >= packager.valid_until_unix_ms
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "trusted archive packager key is outside its validity window".to_string(),
        ));
    }
    if !packager
        .public_key
        .verify_canonical(&manifest.body, &manifest.signature)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
    {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    Ok(())
}

fn validate_archive_package_member_set(
    members: &[RelayAlertAssuranceArchivePackageMember],
    files: &[RelayAlertAssuranceArchivePackageFile],
) -> Result<(), PheromoneRelayError> {
    if members.is_empty() || files.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "archive package member set is empty".to_string(),
        ));
    }
    let mut member_paths = BTreeSet::new();
    let mut casefold_paths = BTreeSet::new();
    for member in members {
        validate_archive_package_path(&member.path)?;
        validate_archive_package_identity(&member.bundle_id, "bundle id")?;
        validate_archive_package_identity(&member.artifact_role, "artifact role")?;
        validate_archive_package_identity(&member.retention_class, "retention class")?;
        if member.kind != "regular_file" {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "archive package supports regular file members only".to_string(),
            ));
        }
        if !is_sha256_hex(&member.sha256) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "member {} has invalid hash",
                member.path
            )));
        }
        if !member_paths.insert(member.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate archive member path {}",
                member.path
            )));
        }
        let folded = member.path.to_ascii_lowercase();
        if !casefold_paths.insert(folded) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "archive member path has a casefold collision".to_string(),
            ));
        }
    }
    let mut file_paths = BTreeSet::new();
    for file in files {
        validate_archive_package_path(&file.path)?;
        if !file_paths.insert(file.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "duplicate archive package file {}",
                file.path
            )));
        }
    }
    for member in members {
        let file = files
            .iter()
            .find(|file| file.path == member.path)
            .ok_or_else(|| {
                PheromoneRelayError::BodyHashMismatch(format!(
                    "archive member {} file is missing",
                    member.path
                ))
            })?;
        let len = u64::try_from(file.bytes.len()).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("member byte count overflow".to_string())
        })?;
        if member.byte_count != len || member.sha256 != sha256_hex(&file.bytes) {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "archive member {} hash or byte count mismatch",
                member.path
            )));
        }
    }
    for file in files {
        if !member_paths.contains(file.path.as_str()) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "archive package file {} is not listed in manifest",
                file.path
            )));
        }
    }
    Ok(())
}

fn export_bundle_from_archive_package(
    package: &RelayAlertAssuranceArchivePackage,
    bundle: &RelayAlertAssuranceArchivePackageBundle,
) -> Result<RelayAlertAssuranceExportBundle, PheromoneRelayError> {
    let manifest_path = join_archive_package_path(&bundle.bundle_path, "manifest.json")?;
    let report_path = join_archive_package_path(
        &bundle.bundle_path,
        "relay-alert-assurance-export-report.json",
    )?;
    let manifest_bytes = archive_package_file_bytes(package, &manifest_path)?;
    let report_bytes = archive_package_file_bytes(package, &report_path)?;
    let manifest: RelayAlertAssuranceExportManifest = serde_json::from_slice(manifest_bytes)?;
    let report: RelayAlertAssuranceExportReport = serde_json::from_slice(report_bytes)?;
    if manifest.body.bundle_id != bundle.bundle_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "nested export manifest bundle id mismatch".to_string(),
        ));
    }
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = join_archive_package_path(&bundle.bundle_path, &artifact.path)?;
        files.push(RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes: archive_package_file_bytes(package, &path)?.to_vec(),
        });
    }
    Ok(RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

fn archive_package_file_bytes<'a>(
    package: &'a RelayAlertAssuranceArchivePackage,
    path: &str,
) -> Result<&'a [u8], PheromoneRelayError> {
    package
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.bytes.as_slice())
        .ok_or_else(|| {
            PheromoneRelayError::BodyHashMismatch(format!("archive package file {path} is missing"))
        })
}

fn validate_archive_safety_claim(claim: &str) -> Result<(), PheromoneRelayError> {
    validate_archive_package_identity(claim, "safety claim")?;
    let forbidden = [
        "handoff_completed",
        "retained_externally",
        "upload",
        "uploaded",
        "delete",
        "deleted",
        "move",
        "moved",
        "live_notification",
        "dispatch",
        "policy_mutation",
        "dynamic_trust",
        "peer_discovery",
        "new_transport",
        "settlement",
        "hidden_predicate",
        "vc_di_bbs",
        "zkvm",
        "frost",
    ];
    if !claim.starts_with("no_") && forbidden.iter().any(|needle| claim.contains(needle)) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "archive safety claim {claim} is forbidden"
        )));
    }
    Ok(())
}

fn validate_physical_archive_evidence(
    evidence: &RelayAlertAssurancePhysicalArchiveEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.media_alias, "media alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256)
        || !is_sha256_hex(&evidence.package_manifest_sha256)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence hashes are invalid".to_string(),
        ));
    }
    if evidence.sampled_member_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence must sample at least one member".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}

fn validate_retention_handoff_profile(
    profile: &RelayAlertAssuranceRetentionHandoffProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile is not fresh".to_string(),
        ));
    }
    if profile.allowed_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for alias in &profile.allowed_system_aliases {
        validate_archive_package_identity(alias, "retention system alias")?;
        if !seen.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate retention system alias".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_retention_handoff_evidence(
    evidence: &RelayAlertAssuranceRetentionHandoffEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.target_system_alias, "target system alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff evidence package report hash is invalid".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}

fn validate_external_retention_profile(
    profile: &RelayAlertAssuranceExternalRetentionProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile is not fresh".to_string(),
        ));
    }
    if profile.max_package_count == 0 || profile.max_evidence_age_ms == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile limits must be positive".to_string(),
        ));
    }
    if profile.min_sampled_members == 0 || profile.min_sample_coverage_basis_points == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample requirements must be positive".to_string(),
        ));
    }
    if profile.min_sample_coverage_basis_points > 10_000 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample coverage exceeds 100 percent".to_string(),
        ));
    }
    if profile.allowed_retention_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen_aliases = BTreeSet::new();
    for alias in &profile.allowed_retention_system_aliases {
        validate_external_retention_schema_token(alias, "external retention alias")?;
        if !seen_aliases.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention alias".to_string(),
            ));
        }
    }
    let mut seen_recommendations = BTreeSet::new();
    for code in &profile.recommendation_codes {
        validate_external_retention_schema_token(code, "external retention recommendation")?;
        if !seen_recommendations.insert(code) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention recommendation".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_external_retention_schema_token(
    value: &str,
    field: &str,
) -> Result<(), PheromoneRelayError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "{field} is invalid"
        )));
    }
    Ok(())
}

enum ExternalRetentionEvidence<T> {
    Missing,
    Single(T),
    Duplicate,
}

struct ExternalRetentionRestoreStatus {
    code: String,
    accepted: bool,
    generated_at_unix_ms: u64,
    local_kernel_id: String,
}

fn external_retention_report_status(value: &str, field: &str) -> (String, bool) {
    if validate_external_retention_schema_token(value, field).is_ok() {
        return (value.to_string(), true);
    }
    ("invalid".to_string(), false)
}

fn external_retention_restore_status(
    restore_reports: &[RelayAlertAssuranceArchiveRestoreDrillReport],
    package_report: &RelayAlertAssuranceArchivePackageReport,
) -> ExternalRetentionEvidence<ExternalRetentionRestoreStatus> {
    let mut matches = restore_reports.iter().filter_map(|restore| {
        restore.packages.iter().find_map(|package| {
            if package.package_id == package_report.package_id
                && package.package_generation == package_report.package_generation
                && package.package_manifest_sha256 == package_report.package_manifest_sha256
            {
                Some(ExternalRetentionRestoreStatus {
                    code: package.code.clone(),
                    accepted: restore.accepted && package.accepted,
                    generated_at_unix_ms: restore.generated_at_unix_ms,
                    local_kernel_id: restore.local_kernel_id.clone(),
                })
            } else {
                None
            }
        })
    });
    let Some(first) = matches.next() else {
        return ExternalRetentionEvidence::Missing;
    };
    if matches.next().is_some() {
        return ExternalRetentionEvidence::Duplicate;
    }
    ExternalRetentionEvidence::Single(first)
}

fn external_retention_physical_reports<'a>(
    physical_reports: &'a [RelayAlertAssurancePhysicalArchiveDrillReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssurancePhysicalArchiveDrillReport> {
    physical_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}

fn external_retention_handoffs<'a>(
    handoff_reports: &'a [RelayAlertAssuranceRetentionHandoffReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssuranceRetentionHandoffReport> {
    handoff_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}

fn external_retention_sample_coverage(sampled: u64, member_count: u64) -> u64 {
    if member_count == 0 {
        return 0;
    }
    sampled.min(member_count).saturating_mul(10_000) / member_count
}

fn external_retention_fresh(
    generated_at_unix_ms: u64,
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> bool {
    generated_at_unix_ms >= since_unix_ms
        && generated_at_unix_ms <= until_unix_ms
        && generated_at_unix_ms <= now_unix_ms
        && now_unix_ms.saturating_sub(generated_at_unix_ms) <= max_age_ms
}

fn external_retention_check(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    condition: bool,
    check_code: &str,
    failure_code: &str,
    detail: &str,
) {
    checks.push(RelayAlertCheck {
        code: if condition {
            check_code.to_string()
        } else {
            failure_code.to_string()
        },
        accepted: condition,
        detail: detail.to_string(),
    });
    if !condition {
        *accepted = false;
        *code = failure_code.to_string();
    }
}

fn external_retention_fail(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    failure_code: &str,
    detail: &str,
) {
    external_retention_check(
        checks,
        accepted,
        code,
        false,
        failure_code,
        failure_code,
        detail,
    );
}

pub(crate) fn validate_archive_profile(
    profile: &RelayAlertAssuranceArchiveProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_closeout_profile(
    profile: &RelayAlertAssuranceCloseoutProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "closeout profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_archive_input_roots(
    profile_kernel_id: &str,
    trusted_kernel_id: &str,
    retention_kernel_id: &str,
) -> Result<(), PheromoneRelayError> {
    if profile_kernel_id != trusted_kernel_id || profile_kernel_id != retention_kernel_id {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive closeout inputs use mixed local kernel ids".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_local_kernel_id(value: &str) -> Result<(), PheromoneRelayError> {
    if value.trim().is_empty() || contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "local kernel id is empty or unsafe".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_archive_candidates(
    candidates: &[RelayAlertAssuranceArchiveBundleCandidate],
) -> Result<(), PheromoneRelayError> {
    if candidates.is_empty() {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive review requires at least one bundle candidate".to_string(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    for candidate in candidates {
        validate_export_path(&candidate.bundle_path)?;
        if !paths.insert(candidate.bundle_path.as_str()) {
            return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                "duplicate bundle path {}",
                candidate.bundle_path
            )));
        }
        if let Some(bundle) = &candidate.bundle {
            let bundle_id = bundle.manifest.body.bundle_id.as_str();
            if !bundle_ids.insert(bundle_id) {
                return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                    "duplicate bundle id {bundle_id}"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn review_archive_candidate(
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    trusted_exporters: &RelayAlertAssuranceTrustedExportersDocument,
    retention_profile: &RelayAlertAssuranceRetentionProfileDocument,
    require_replay_match: bool,
    require_recovery_drill: bool,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceArchiveBundleReview, PheromoneRelayError> {
    let Some(bundle) = &candidate.bundle else {
        return Ok(archive_quarantine_review(
            candidate,
            candidate
                .error_code
                .as_deref()
                .unwrap_or("bundle_unreadable"),
            candidate
                .error_detail
                .as_deref()
                .unwrap_or("bundle could not be loaded"),
        ));
    };
    let manifest_sha256 = Some(canonical_sha256(&bundle.manifest)?);
    let source_package_sha256 = Some(bundle.manifest.body.source_package_sha256.clone());
    let artifact_count = bundle.manifest.body.artifacts.len() as u64;
    let route_review_present = bundle
        .manifest
        .body
        .artifacts
        .iter()
        .any(|artifact| artifact.role == "route_review_packet");
    let mut checks = Vec::new();

    if let Err(error) =
        verify_relay_alert_assurance_export_bundle(bundle, trusted_exporters, now_unix_ms)
    {
        let code = error.code().to_string();
        checks.push(RelayAlertCheck {
            code: "trusted_exporter".to_string(),
            accepted: false,
            detail: error.to_string(),
        });
        return Ok(RelayAlertAssuranceArchiveBundleReview {
            bundle_id: bundle.manifest.body.bundle_id.clone(),
            bundle_path: candidate.bundle_path.clone(),
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            state: "quarantine".to_string(),
            code,
            detail: "bundle failed trusted-exporter verification".to_string(),
            trusted_exporter_verified: false,
            replay_matched: false,
            recovery_drill_accepted: false,
            route_review_present,
            retained_count: 0,
            expiring_soon_count: 0,
            eligible_for_delete_count: 0,
            legal_hold_count: 0,
            missing_count: 0,
            quarantine_count: 1,
            checks,
        });
    }
    checks.push(RelayAlertCheck {
        code: "trusted_exporter".to_string(),
        accepted: true,
        detail: "bundle manifest verifies against caller-supplied trusted exporters".to_string(),
    });

    let replay = generate_relay_alert_assurance_replay_report(RelayAlertAssuranceReplayInput {
        bundle,
        trusted_exporters,
        now_unix_ms,
    });
    let replay_matched = replay.as_ref().is_ok_and(|report| report.accepted);
    checks.push(RelayAlertCheck {
        code: "assurance_replay".to_string(),
        accepted: replay_matched,
        detail: match &replay {
            Ok(report) => report.code.clone(),
            Err(error) => error.to_string(),
        },
    });
    if require_replay_match && !replay_matched {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "replay_mismatch",
            "bundle did not replay to the exported assurance package",
            false,
            false,
        ));
    }

    let retention =
        generate_relay_alert_assurance_retention_report(RelayAlertAssuranceRetentionInput {
            bundles: std::slice::from_ref(bundle),
            retention_profile,
            now_unix_ms,
        })?;
    let recovery = if require_recovery_drill {
        generate_relay_alert_assurance_recovery_drill_report(
            RelayAlertAssuranceRecoveryDrillInput {
                bundle,
                trusted_exporters,
                case_id: "all",
                now_unix_ms,
            },
        )
    } else {
        Ok(RelayAlertAssuranceRecoveryDrillReport {
            schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
            accepted: true,
            code: "accepted".to_string(),
            local_kernel_id: bundle.manifest.body.local_kernel_id.clone(),
            generated_at_unix_ms: now_unix_ms,
            drill_count: 0,
            drills: Vec::new(),
            checks: Vec::new(),
        })
    };
    let recovery_drill_accepted = recovery.as_ref().is_ok_and(|report| report.accepted);
    checks.push(RelayAlertCheck {
        code: "recovery_drill".to_string(),
        accepted: recovery_drill_accepted,
        detail: match &recovery {
            Ok(report) => report.code.clone(),
            Err(error) => error.to_string(),
        },
    });
    if require_recovery_drill && !recovery_drill_accepted {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "recovery_drill_failed",
            "bundle recovery drill did not complete",
            replay_matched,
            false,
        ));
    }
    if !route_review_present {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "missing_route_review",
            "bundle is missing route-owner review evidence",
            replay_matched,
            recovery_drill_accepted,
        ));
    }

    Ok(RelayAlertAssuranceArchiveBundleReview {
        bundle_id: bundle.manifest.body.bundle_id.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256,
        source_package_sha256,
        artifact_count,
        state: "archive_ready".to_string(),
        code: "accepted".to_string(),
        detail: "bundle verified, replayed, retained, and recovery-drilled for archive closeout"
            .to_string(),
        trusted_exporter_verified: true,
        replay_matched,
        recovery_drill_accepted,
        route_review_present,
        retained_count: retention.retained_count,
        expiring_soon_count: retention.expiring_soon_count,
        eligible_for_delete_count: retention.eligible_for_delete_count,
        legal_hold_count: retention.blocked_count,
        missing_count: retention.missing_count,
        quarantine_count: retention.quarantine_count,
        checks,
    })
}

pub(crate) fn archive_quarantine_review(
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    code: &str,
    detail: &str,
) -> RelayAlertAssuranceArchiveBundleReview {
    RelayAlertAssuranceArchiveBundleReview {
        bundle_id: candidate.bundle_path.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256: None,
        source_package_sha256: None,
        artifact_count: 0,
        state: "quarantine".to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        trusted_exporter_verified: false,
        replay_matched: false,
        recovery_drill_accepted: false,
        route_review_present: false,
        retained_count: 0,
        expiring_soon_count: 0,
        eligible_for_delete_count: 0,
        legal_hold_count: 0,
        missing_count: 0,
        quarantine_count: 1,
        checks: vec![RelayAlertCheck {
            code: code.to_string(),
            accepted: false,
            detail: detail.to_string(),
        }],
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn archive_blocked_review(
    bundle: &RelayAlertAssuranceExportBundle,
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    manifest_sha256: Option<String>,
    source_package_sha256: Option<String>,
    artifact_count: u64,
    route_review_present: bool,
    checks: Vec<RelayAlertCheck>,
    code: &str,
    detail: &str,
    replay_matched: bool,
    recovery_drill_accepted: bool,
) -> RelayAlertAssuranceArchiveBundleReview {
    RelayAlertAssuranceArchiveBundleReview {
        bundle_id: bundle.manifest.body.bundle_id.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256,
        source_package_sha256,
        artifact_count,
        state: "archive_blocked".to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        trusted_exporter_verified: true,
        replay_matched,
        recovery_drill_accepted,
        route_review_present,
        retained_count: 0,
        expiring_soon_count: 0,
        eligible_for_delete_count: 0,
        legal_hold_count: 0,
        missing_count: 0,
        quarantine_count: 0,
        checks,
    }
}

pub(crate) fn closeout_review_from_archive(
    archive: RelayAlertAssuranceArchiveBundleReview,
    profile: &RelayAlertAssuranceCloseoutProfileDocument,
) -> RelayAlertAssuranceCloseoutBundleReview {
    let retention_safe = archive.missing_count == 0
        && archive.quarantine_count == 0
        && (!profile.block_legal_hold || archive.legal_hold_count == 0)
        && (!profile.block_eligible_for_delete || archive.eligible_for_delete_count == 0);
    let (state, code, detail) = if archive.state == "quarantine" {
        (
            "quarantine",
            archive.code.as_str(),
            "bundle is quarantined before closeout review",
        )
    } else if archive.state != "archive_ready" {
        (
            "closeout_blocked",
            archive.code.as_str(),
            "bundle is not archive-ready",
        )
    } else if !archive.route_review_present {
        (
            "closeout_blocked",
            "missing_route_review",
            "bundle is missing route-owner review evidence",
        )
    } else if profile.block_legal_hold && archive.legal_hold_count > 0 {
        (
            "closeout_blocked",
            "legal_hold_blocked",
            "bundle has legal-hold retention rows",
        )
    } else if profile.block_eligible_for_delete && archive.eligible_for_delete_count > 0 {
        (
            "closeout_blocked",
            "eligible_for_delete_present",
            "bundle has dry-run delete eligibility rows",
        )
    } else {
        (
            "closeout_ready",
            "accepted",
            "bundle is ready for operator-managed closeout",
        )
    };
    RelayAlertAssuranceCloseoutBundleReview {
        bundle_id: archive.bundle_id,
        bundle_path: archive.bundle_path,
        manifest_sha256: archive.manifest_sha256,
        artifact_count: archive.artifact_count,
        state: state.to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        verified_bundle: archive.trusted_exporter_verified,
        replay_matched: archive.replay_matched,
        retention_safe,
        recovery_drill_accepted: archive.recovery_drill_accepted,
        route_review_present: archive.route_review_present,
        legal_hold_count: archive.legal_hold_count,
        eligible_for_delete_count: archive.eligible_for_delete_count,
        missing_count: archive.missing_count,
        quarantine_count: archive.quarantine_count,
        checks: archive.checks,
    }
}
