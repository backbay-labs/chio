//! Archive and retention wire types for relay alert assurance.

use crate::{
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceRetentionProfileDocument,
    RelayAlertAssuranceTrustedExportersDocument, RelayAlertCheck, RelayOperatorRecommendation,
};
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use serde::Deserialize;
use serde::Serialize;

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
