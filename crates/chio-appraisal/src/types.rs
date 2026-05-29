//! Wire and data types for runtime attestation appraisal artifacts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::{
    AttestationTrustError, RuntimeAssuranceTier, RuntimeAttestationEvidence, WorkloadIdentity,
    WorkloadIdentityError,
};
use crate::receipt::SignedExportEnvelope;
use chio_core_types::runtime_attestation::AttestationVerifierFamily;

pub const AZURE_MAA_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.azure-maa.jwt.v1";
pub const AWS_NITRO_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.aws-nitro-attestation.v1";
pub const GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA: &str =
    "chio.runtime-attestation.google-confidential-vm.jwt.v1";
pub const ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA: &str =
    "chio.runtime-attestation.enterprise-verifier.json.v1";
pub const AZURE_MAA_VERIFIER_ADAPTER: &str = "azure_maa";
pub const AWS_NITRO_VERIFIER_ADAPTER: &str = "aws_nitro";
pub const GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER: &str = "google_confidential_vm";
pub const ENTERPRISE_VERIFIER_ADAPTER: &str = "enterprise_verifier";

pub const RUNTIME_ATTESTATION_APPRAISAL_SCHEMA: &str = "chio.runtime-attestation.appraisal.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA: &str =
    "chio.runtime-attestation.appraisal-artifact.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA: &str =
    "chio.runtime-attestation.appraisal-report.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_INVENTORY_SCHEMA: &str =
    "chio.runtime-attestation.appraisal-artifact-inventory.v1";
pub const RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA: &str =
    "chio.runtime-attestation.normalized-claim-vocabulary.v1";
pub const RUNTIME_ATTESTATION_REASON_TAXONOMY_SCHEMA: &str =
    "chio.runtime-attestation.reason-taxonomy.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA: &str =
    "chio.runtime-attestation.appraisal-result.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_IMPORT_REPORT_SCHEMA: &str =
    "chio.runtime-attestation.appraisal-import-report.v1";
pub const RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA: &str =
    "chio.runtime-attestation.verifier-descriptor.v1";
pub const RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA: &str =
    "chio.runtime-attestation.reference-values.v1";
pub const RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA: &str =
    "chio.runtime-attestation.trust-bundle.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalVerdict {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalReasonCode {
    EvidenceVerified,
    UnsupportedEvidence,
    UnsupportedClaimMapping,
    AmbiguousClaimMapping,
    PolicyRejected,
    InvalidClaims,
    EvidenceStale,
    MeasurementMismatch,
    DebugStateUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationNormalizedClaimCode {
    AttestationType,
    RuntimeIdentity,
    WorkloadIdentityScheme,
    WorkloadIdentityUri,
    ModuleId,
    MeasurementDigest,
    MeasurementRegisters,
    HardwareModel,
    SecureBootState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationNormalizedClaimCategory {
    Identity,
    Measurement,
    Platform,
    Configuration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationNormalizedClaimConfidence {
    Verified,
    Derived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationNormalizedClaimFreshness {
    EvidenceWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationClaimProvenance {
    EvidenceEnvelope,
    VendorClaims,
    WorkloadProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalReasonGroup {
    Verification,
    Compatibility,
    Freshness,
    Measurement,
    DebugPosture,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalReasonDisposition {
    Pass,
    Warn,
    Deny,
    Degrade,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationNormalizedClaim {
    pub code: RuntimeAttestationNormalizedClaimCode,
    pub legacy_assertion_key: String,
    pub category: RuntimeAttestationNormalizedClaimCategory,
    pub confidence: RuntimeAttestationNormalizedClaimConfidence,
    pub freshness: RuntimeAttestationNormalizedClaimFreshness,
    pub provenance: RuntimeAttestationClaimProvenance,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationNormalizedClaimVocabularyEntry {
    pub code: RuntimeAttestationNormalizedClaimCode,
    pub legacy_assertion_key: String,
    pub category: RuntimeAttestationNormalizedClaimCategory,
    pub confidence: RuntimeAttestationNormalizedClaimConfidence,
    pub freshness: RuntimeAttestationNormalizedClaimFreshness,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_verifier_families: Vec<AttestationVerifierFamily>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationNormalizedClaimVocabulary {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<RuntimeAttestationNormalizedClaimVocabularyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalReason {
    pub code: RuntimeAttestationAppraisalReasonCode,
    pub group: RuntimeAttestationAppraisalReasonGroup,
    pub disposition: RuntimeAttestationAppraisalReasonDisposition,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationReasonTaxonomy {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<RuntimeAttestationAppraisalReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalResultSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalResult {
    pub schema: String,
    pub result_id: String,
    pub exported_at: u64,
    pub issuer: String,
    pub appraisal: RuntimeAttestationAppraisalArtifact,
    pub exporter_policy_outcome: RuntimeAttestationPolicyOutcome,
    pub subject: RuntimeAttestationAppraisalResultSubject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationImportDisposition {
    Allow,
    Attenuate,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationImportReasonCode {
    NoLocalPolicy,
    InvalidSignature,
    UnsupportedAppraisalSchema,
    ResultStale,
    EvidenceStale,
    ExporterPolicyRejected,
    UntrustedIssuer,
    UntrustedSigner,
    UnsupportedVerifierFamily,
    MissingRequiredClaim,
    ClaimMismatch,
    TierAttenuated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationImportReason {
    pub code: RuntimeAttestationImportReasonCode,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationImportedAppraisalPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_signer_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_verifier_families: Vec<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_result_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_effective_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_claims: BTreeMap<RuntimeAttestationNormalizedClaimCode, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalImportOutcome {
    pub disposition: RuntimeAttestationImportDisposition,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<RuntimeAttestationImportReasonCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<RuntimeAttestationImportReason>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalImportRequest {
    pub signed_result: SignedRuntimeAttestationAppraisalResult,
    pub local_policy: RuntimeAttestationImportedAppraisalPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalImportReport {
    pub schema: String,
    pub evaluated_at: u64,
    pub signer_key_hex: String,
    pub result: RuntimeAttestationAppraisalResult,
    pub local_policy_outcome: RuntimeAttestationAppraisalImportOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationVerifierDescriptorDocument {
    pub schema: String,
    pub descriptor_id: String,
    pub verifier: String,
    pub verifier_family: AttestationVerifierFamily,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestation_schemas: Vec<String>,
    pub appraisal_artifact_schema: String,
    pub appraisal_result_schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing_key_fingerprints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_values_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub type SignedRuntimeAttestationVerifierDescriptor =
    SignedExportEnvelope<RuntimeAttestationVerifierDescriptorDocument>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationReferenceValueState {
    Active,
    Superseded,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationReferenceValueSet {
    pub schema: String,
    pub reference_value_id: String,
    pub descriptor_id: String,
    pub verifier_family: AttestationVerifierFamily,
    pub attestation_schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: RuntimeAttestationReferenceValueState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub measurements: BTreeMap<String, Value>,
}

pub type SignedRuntimeAttestationReferenceValueSet =
    SignedExportEnvelope<RuntimeAttestationReferenceValueSet>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationTrustBundleDocument {
    pub schema: String,
    pub bundle_id: String,
    pub publisher: String,
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptors: Vec<SignedRuntimeAttestationVerifierDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_values: Vec<SignedRuntimeAttestationReferenceValueSet>,
}

pub type SignedRuntimeAttestationTrustBundle =
    SignedExportEnvelope<RuntimeAttestationTrustBundleDocument>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationTrustBundleVerification {
    pub schema: String,
    pub bundle_id: String,
    pub publisher: String,
    pub version: u64,
    pub descriptor_count: usize,
    pub reference_value_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_families: Vec<AttestationVerifierFamily>,
    pub verified_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeAttestationAppraisalError {
    #[error("runtime attestation schema `{schema}` is not recognized by the canonical appraisal boundary")]
    UnsupportedSchema { schema: String },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RuntimeAttestationVerificationError {
    #[error("runtime attestation workload identity is invalid: {0}")]
    InvalidWorkloadIdentity(#[from] WorkloadIdentityError),
    #[error("runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})")]
    StaleEvidence {
        now: u64,
        issued_at: u64,
        expires_at: u64,
    },
    #[error(transparent)]
    Appraisal(#[from] RuntimeAttestationAppraisalError),
    #[error("runtime attestation evidence rejected by local trust policy: {0}")]
    TrustPolicy(#[from] AttestationTrustError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationVerifierDescriptor {
    pub adapter: String,
    pub verifier_family: AttestationVerifierFamily,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationClaimSets {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub normalized_assertions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalized_claims: Vec<RuntimeAttestationNormalizedClaim>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vendor_claims: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationPolicyProjection {
    pub verdict: RuntimeAttestationAppraisalVerdict,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<RuntimeAttestationAppraisalReason>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalArtifact {
    pub schema: String,
    pub evidence: RuntimeAttestationEvidenceDescriptor,
    pub verifier: RuntimeAttestationVerifierDescriptor,
    pub claims: RuntimeAttestationClaimSets,
    pub policy: RuntimeAttestationPolicyProjection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalArtifactInventoryEntry {
    pub attestation_schema: String,
    pub artifact_schema: String,
    pub verifier_family: AttestationVerifierFamily,
    pub adapter: String,
    pub vendor_claim_namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalized_assertion_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalized_claim_codes: Vec<RuntimeAttestationNormalizedClaimCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalArtifactInventory {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<RuntimeAttestationAppraisalArtifactInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationEvidenceDescriptor {
    pub schema: String,
    pub verifier: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence_sha256: String,
}

impl From<&RuntimeAttestationEvidence> for RuntimeAttestationEvidenceDescriptor {
    fn from(value: &RuntimeAttestationEvidence) -> Self {
        Self {
            schema: value.schema.clone(),
            verifier: value.verifier.clone(),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            evidence_sha256: value.evidence_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisal {
    pub schema: String,
    pub adapter: String,
    pub verifier_family: AttestationVerifierFamily,
    pub evidence: RuntimeAttestationEvidenceDescriptor,
    pub verdict: RuntimeAttestationAppraisalVerdict,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub normalized_assertions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalized_claims: Vec<RuntimeAttestationNormalizedClaim>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vendor_claims: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<RuntimeAttestationAppraisalReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<RuntimeAttestationAppraisalArtifact>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalRequest {
    pub runtime_attestation: RuntimeAttestationEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalResultExportRequest {
    pub issuer: String,
    pub runtime_attestation: RuntimeAttestationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationPolicyOutcome {
    pub trust_policy_configured: bool,
    pub accepted: bool,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedRuntimeAttestationProvenance {
    pub verifier_family: AttestationVerifierFamily,
    pub verifier_adapter: String,
    pub canonical_verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_trust_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedRuntimeAttestationRecord {
    pub evidence: RuntimeAttestationEvidence,
    pub appraisal: RuntimeAttestationAppraisal,
    pub policy_outcome: RuntimeAttestationPolicyOutcome,
    pub subject: RuntimeAttestationAppraisalResultSubject,
    pub provenance: VerifiedRuntimeAttestationProvenance,
    pub verified_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalReport {
    pub schema: String,
    pub generated_at: u64,
    pub appraisal: RuntimeAttestationAppraisal,
    pub policy_outcome: RuntimeAttestationPolicyOutcome,
}

pub type SignedRuntimeAttestationAppraisalReport =
    SignedExportEnvelope<RuntimeAttestationAppraisalReport>;
pub type SignedRuntimeAttestationAppraisalResult =
    SignedExportEnvelope<RuntimeAttestationAppraisalResult>;
