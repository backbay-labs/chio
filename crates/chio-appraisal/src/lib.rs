pub use chio_core_types::{canonical, capability, crypto, error, receipt, Error};

use std::collections::{BTreeMap, BTreeSet};

pub mod marketplace_pricing;

pub use marketplace_pricing::{
    compute_marketplace_invocation_price, MarketplaceBasePrice, MarketplaceInvocationPrice,
    MarketplacePricingContext, MarketplaceReputationTier, TIER_DISCOUNT_PER_HUNDRED,
};

pub use chio_core_types::runtime_attestation::AttestationVerifierFamily;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::capability::{
    canonicalize_attestation_verifier, AttestationTrustError, AttestationTrustPolicy,
    RuntimeAssuranceTier, RuntimeAttestationEvidence, WorkloadIdentity, WorkloadIdentityError,
};
use crate::crypto::sha256_hex;
use crate::error::Result as ChioResult;
use crate::receipt::SignedExportEnvelope;

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

pub struct RuntimeAttestationVerifierDescriptorArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub descriptor_id: String,
    pub verifier: String,
    pub verifier_family: AttestationVerifierFamily,
    pub adapter: String,
    pub attestation_schemas: Vec<String>,
    pub signing_key_fingerprints: Vec<String>,
    pub reference_values_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn create_signed_runtime_attestation_verifier_descriptor(
    args: RuntimeAttestationVerifierDescriptorArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationVerifierDescriptor> {
    let descriptor = RuntimeAttestationVerifierDescriptorDocument {
        schema: RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA.to_string(),
        descriptor_id: args.descriptor_id,
        verifier: args.verifier,
        verifier_family: args.verifier_family,
        adapter: args.adapter,
        attestation_schemas: args.attestation_schemas,
        appraisal_artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
        appraisal_result_schema: RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string(),
        signing_key_fingerprints: args.signing_key_fingerprints,
        reference_values_uri: args.reference_values_uri,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
    };
    validate_runtime_attestation_verifier_descriptor(&descriptor)?;
    SignedExportEnvelope::sign(descriptor, args.signer)
}

pub fn verify_signed_runtime_attestation_verifier_descriptor(
    descriptor: &SignedRuntimeAttestationVerifierDescriptor,
    now: u64,
) -> ChioResult<()> {
    validate_runtime_attestation_verifier_descriptor(&descriptor.body)?;
    if now < descriptor.body.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` is not yet valid",
            descriptor.body.descriptor_id
        )));
    }
    if now > descriptor.body.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` has expired",
            descriptor.body.descriptor_id
        )));
    }
    if !descriptor.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` signature verification failed",
            descriptor.body.descriptor_id
        )));
    }
    Ok(())
}

pub struct RuntimeAttestationReferenceValueSetArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub reference_value_id: String,
    pub descriptor_id: String,
    pub verifier_family: AttestationVerifierFamily,
    pub attestation_schema: String,
    pub source_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: RuntimeAttestationReferenceValueState,
    pub superseded_by: Option<String>,
    pub revoked_reason: Option<String>,
    pub measurements: BTreeMap<String, Value>,
}

pub fn create_signed_runtime_attestation_reference_value_set(
    args: RuntimeAttestationReferenceValueSetArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationReferenceValueSet> {
    let reference_value_set = RuntimeAttestationReferenceValueSet {
        schema: RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA.to_string(),
        reference_value_id: args.reference_value_id,
        descriptor_id: args.descriptor_id,
        verifier_family: args.verifier_family,
        attestation_schema: args.attestation_schema,
        source_uri: args.source_uri,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
        state: args.state,
        superseded_by: args.superseded_by,
        revoked_reason: args.revoked_reason,
        measurements: args.measurements,
    };
    validate_runtime_attestation_reference_value_set(&reference_value_set)?;
    SignedExportEnvelope::sign(reference_value_set, args.signer)
}

pub fn verify_signed_runtime_attestation_reference_value_set(
    reference_value_set: &SignedRuntimeAttestationReferenceValueSet,
    now: u64,
) -> ChioResult<()> {
    validate_runtime_attestation_reference_value_set(&reference_value_set.body)?;
    if now < reference_value_set.body.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` is not yet valid",
            reference_value_set.body.reference_value_id
        )));
    }
    if now > reference_value_set.body.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` has expired",
            reference_value_set.body.reference_value_id
        )));
    }
    if !reference_value_set.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` signature verification failed",
            reference_value_set.body.reference_value_id
        )));
    }
    Ok(())
}

pub struct RuntimeAttestationTrustBundleArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub bundle_id: String,
    pub publisher: String,
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub descriptors: Vec<SignedRuntimeAttestationVerifierDescriptor>,
    pub reference_values: Vec<SignedRuntimeAttestationReferenceValueSet>,
}

pub fn create_signed_runtime_attestation_trust_bundle(
    args: RuntimeAttestationTrustBundleArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationTrustBundle> {
    let bundle = RuntimeAttestationTrustBundleDocument {
        schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
        bundle_id: args.bundle_id,
        publisher: args.publisher,
        version: args.version,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
        descriptors: args.descriptors,
        reference_values: args.reference_values,
    };
    validate_runtime_attestation_trust_bundle(&bundle, args.issued_at)?;
    SignedExportEnvelope::sign(bundle, args.signer)
}

pub fn verify_signed_runtime_attestation_trust_bundle(
    bundle: &SignedRuntimeAttestationTrustBundle,
    now: u64,
) -> ChioResult<RuntimeAttestationTrustBundleVerification> {
    validate_runtime_attestation_trust_bundle(&bundle.body, now)?;
    if !bundle.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` signature verification failed",
            bundle.body.bundle_id
        )));
    }
    let verifier_families = bundle
        .body
        .descriptors
        .iter()
        .map(|descriptor| descriptor.body.verifier_family)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(RuntimeAttestationTrustBundleVerification {
        schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
        bundle_id: bundle.body.bundle_id.clone(),
        publisher: bundle.body.publisher.clone(),
        version: bundle.body.version,
        descriptor_count: bundle.body.descriptors.len(),
        reference_value_count: bundle.body.reference_values.len(),
        verifier_families,
        verified_at: now,
    })
}

fn validate_runtime_attestation_verifier_descriptor(
    descriptor: &RuntimeAttestationVerifierDescriptorDocument,
) -> ChioResult<()> {
    if descriptor.schema != RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor schema must be {RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA}"
        )));
    }
    if descriptor.descriptor_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation verifier descriptor must include a non-empty descriptor_id"
                .to_string(),
        ));
    }
    if descriptor.verifier.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include a non-empty verifier",
            descriptor.descriptor_id
        )));
    }
    if descriptor.adapter.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include a non-empty adapter",
            descriptor.descriptor_id
        )));
    }
    if descriptor.issued_at > descriptor.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must not expire before it is issued",
            descriptor.descriptor_id
        )));
    }
    if descriptor.attestation_schemas.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include at least one attestation schema",
            descriptor.descriptor_id
        )));
    }
    validate_sorted_unique_strings(
        &descriptor.attestation_schemas,
        "attestation_schemas",
        &descriptor.descriptor_id,
    )?;
    if descriptor.appraisal_artifact_schema != RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must reference the canonical appraisal artifact schema",
            descriptor.descriptor_id
        )));
    }
    if descriptor.appraisal_result_schema != RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must reference the canonical appraisal result schema",
            descriptor.descriptor_id
        )));
    }
    if descriptor.signing_key_fingerprints.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include at least one signing-key fingerprint",
            descriptor.descriptor_id
        )));
    }
    validate_sorted_unique_strings(
        &descriptor.signing_key_fingerprints,
        "signing_key_fingerprints",
        &descriptor.descriptor_id,
    )?;
    if let Some(reference_values_uri) = &descriptor.reference_values_uri {
        if reference_values_uri.trim().is_empty() {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation verifier descriptor `{}` cannot include an empty reference_values_uri",
                descriptor.descriptor_id
            )));
        }
    }
    Ok(())
}

fn validate_runtime_attestation_reference_value_set(
    reference_value_set: &RuntimeAttestationReferenceValueSet,
) -> ChioResult<()> {
    if reference_value_set.schema != RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value schema must be {RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA}"
        )));
    }
    if reference_value_set.reference_value_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation reference-value set must include a non-empty reference_value_id"
                .to_string(),
        ));
    }
    if reference_value_set.descriptor_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include a non-empty descriptor_id",
            reference_value_set.reference_value_id
        )));
    }
    if reference_value_set.attestation_schema.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include a non-empty attestation_schema",
            reference_value_set.reference_value_id
        )));
    }
    if reference_value_set.issued_at > reference_value_set.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must not expire before it is issued",
            reference_value_set.reference_value_id
        )));
    }
    if let Some(source_uri) = &reference_value_set.source_uri {
        if source_uri.trim().is_empty() {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` cannot include an empty source_uri",
                reference_value_set.reference_value_id
            )));
        }
    }
    if reference_value_set.measurements.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include at least one measurement",
            reference_value_set.reference_value_id
        )));
    }
    match reference_value_set.state {
        RuntimeAttestationReferenceValueState::Active => {
            if reference_value_set.superseded_by.is_some()
                || reference_value_set.revoked_reason.is_some()
            {
                return Err(crate::Error::CanonicalJson(format!(
                    "active runtime attestation reference-value set `{}` cannot include supersession or revocation fields",
                    reference_value_set.reference_value_id
                )));
            }
        }
        RuntimeAttestationReferenceValueState::Superseded => {
            let superseded_by = reference_value_set.superseded_by.as_deref().ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{}` must include superseded_by",
                    reference_value_set.reference_value_id
                ))
            })?;
            if superseded_by == reference_value_set.reference_value_id {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation reference-value set `{}` cannot supersede itself",
                    reference_value_set.reference_value_id
                )));
            }
            if reference_value_set.revoked_reason.is_some() {
                return Err(crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{}` cannot include revoked_reason",
                    reference_value_set.reference_value_id
                )));
            }
        }
        RuntimeAttestationReferenceValueState::Revoked => {
            if reference_value_set.superseded_by.is_some() {
                return Err(crate::Error::CanonicalJson(format!(
                    "revoked runtime attestation reference-value set `{}` cannot include superseded_by",
                    reference_value_set.reference_value_id
                )));
            }
            if reference_value_set
                .revoked_reason
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            {
                return Err(crate::Error::CanonicalJson(format!(
                    "revoked runtime attestation reference-value set `{}` must include revoked_reason",
                    reference_value_set.reference_value_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_runtime_attestation_trust_bundle(
    bundle: &RuntimeAttestationTrustBundleDocument,
    now: u64,
) -> ChioResult<()> {
    if bundle.schema != RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust-bundle schema must be {RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA}"
        )));
    }
    if bundle.bundle_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation trust bundle must include a non-empty bundle_id".to_string(),
        ));
    }
    if bundle.publisher.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include a non-empty publisher",
            bundle.bundle_id
        )));
    }
    if bundle.version == 0 {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include a non-zero version",
            bundle.bundle_id
        )));
    }
    if bundle.issued_at > bundle.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must not expire before it is issued",
            bundle.bundle_id
        )));
    }
    if now < bundle.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` is not yet valid",
            bundle.bundle_id
        )));
    }
    if now > bundle.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` has expired",
            bundle.bundle_id
        )));
    }
    if bundle.descriptors.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include at least one verifier descriptor",
            bundle.bundle_id
        )));
    }

    let mut descriptor_ids = BTreeSet::new();
    let mut descriptors = BTreeMap::new();
    for descriptor in &bundle.descriptors {
        verify_signed_runtime_attestation_verifier_descriptor(descriptor, now)?;
        let descriptor_id = descriptor.body.descriptor_id.clone();
        if !descriptor_ids.insert(descriptor_id.clone()) {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` contains duplicate verifier descriptor `{descriptor_id}`",
                bundle.bundle_id
            )));
        }
        descriptors.insert(descriptor_id, &descriptor.body);
    }

    let mut reference_value_ids = BTreeSet::new();
    let mut active_slots = BTreeSet::new();
    let mut reference_value_states = BTreeMap::new();
    for reference_value in &bundle.reference_values {
        verify_signed_runtime_attestation_reference_value_set(reference_value, now)?;
        let reference_value_id = reference_value.body.reference_value_id.clone();
        if !reference_value_ids.insert(reference_value_id.clone()) {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` contains duplicate reference-value set `{reference_value_id}`",
                bundle.bundle_id
            )));
        }
        let descriptor = descriptors
            .get(&reference_value.body.descriptor_id)
            .ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` references unknown verifier descriptor `{}`",
                bundle.bundle_id, reference_value.body.descriptor_id
            ))
            })?;
        if descriptor.verifier_family != reference_value.body.verifier_family {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` does not match verifier-family {:?} of descriptor `{}`",
                reference_value_id, descriptor.verifier_family, descriptor.descriptor_id
            )));
        }
        if !descriptor
            .attestation_schemas
            .contains(&reference_value.body.attestation_schema)
        {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` uses attestation schema `{}` outside descriptor `{}`",
                reference_value_id, reference_value.body.attestation_schema, descriptor.descriptor_id
            )));
        }
        if reference_value.body.state == RuntimeAttestationReferenceValueState::Active {
            let slot = (
                reference_value.body.descriptor_id.clone(),
                reference_value.body.attestation_schema.clone(),
            );
            if !active_slots.insert(slot) {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation trust bundle `{}` contains ambiguous active reference values for descriptor `{}` and schema `{}`",
                    bundle.bundle_id,
                    reference_value.body.descriptor_id,
                    reference_value.body.attestation_schema
                )));
            }
        }
        reference_value_states.insert(
            reference_value_id,
            (
                reference_value.body.state,
                reference_value.body.superseded_by.clone(),
            ),
        );
    }

    for (reference_value_id, (state, superseded_by)) in &reference_value_states {
        if *state == RuntimeAttestationReferenceValueState::Superseded {
            let successor = superseded_by.as_ref().ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{reference_value_id}` must include superseded_by"
                ))
            })?;
            if !reference_value_states.contains_key(successor) {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation trust bundle `{}` references unknown successor `{successor}` for superseded set `{reference_value_id}`",
                    bundle.bundle_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_sorted_unique_strings(values: &[String], field: &str, id: &str) -> ChioResult<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(crate::Error::CanonicalJson(format!(
            "{field} for `{id}` cannot contain empty values"
        )));
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != values {
        return Err(crate::Error::CanonicalJson(format!(
            "{field} for `{id}` must be stored in sorted unique order"
        )));
    }
    Ok(())
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

impl VerifiedRuntimeAttestationRecord {
    #[must_use]
    pub fn is_locally_accepted(&self) -> bool {
        self.policy_outcome.accepted
    }

    #[must_use]
    pub fn evidence_schema(&self) -> &str {
        self.evidence.schema.as_str()
    }

    #[must_use]
    pub fn evidence_sha256(&self) -> &str {
        self.evidence.evidence_sha256.as_str()
    }

    #[must_use]
    pub fn canonical_verifier(&self) -> &str {
        self.provenance.canonical_verifier.as_str()
    }

    #[must_use]
    pub fn verifier_family(&self) -> AttestationVerifierFamily {
        self.provenance.verifier_family
    }

    #[must_use]
    pub fn effective_tier(&self) -> RuntimeAssuranceTier {
        self.policy_outcome.effective_tier
    }

    #[must_use]
    pub fn workload_identity(&self) -> Option<&WorkloadIdentity> {
        self.subject.workload_identity.as_ref()
    }

    #[must_use]
    pub fn matched_trust_rule(&self) -> Option<&str> {
        self.provenance.matched_trust_rule.as_deref()
    }

    #[must_use]
    pub fn matches_evidence(&self, evidence: &RuntimeAttestationEvidence) -> bool {
        self.evidence_schema() == evidence.schema
            && self.evidence_sha256() == evidence.evidence_sha256
            && self.canonical_verifier() == canonicalize_attestation_verifier(&evidence.verifier)
            && verifier_family_for_attestation_schema(evidence.schema.as_str())
                == Some(self.verifier_family())
    }
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

impl RuntimeAttestationNormalizedClaimCode {
    #[must_use]
    pub fn legacy_assertion_key(self) -> &'static str {
        match self {
            Self::AttestationType => "attestationType",
            Self::RuntimeIdentity => "runtimeIdentity",
            Self::WorkloadIdentityScheme => "workloadIdentityScheme",
            Self::WorkloadIdentityUri => "workloadIdentityUri",
            Self::ModuleId => "moduleId",
            Self::MeasurementDigest => "digest",
            Self::MeasurementRegisters => "pcrs",
            Self::HardwareModel => "hardwareModel",
            Self::SecureBootState => "secureBoot",
        }
    }

    #[must_use]
    pub fn category(self) -> RuntimeAttestationNormalizedClaimCategory {
        match self {
            Self::RuntimeIdentity | Self::WorkloadIdentityScheme | Self::WorkloadIdentityUri => {
                RuntimeAttestationNormalizedClaimCategory::Identity
            }
            Self::ModuleId | Self::MeasurementDigest | Self::MeasurementRegisters => {
                RuntimeAttestationNormalizedClaimCategory::Measurement
            }
            Self::AttestationType | Self::HardwareModel => {
                RuntimeAttestationNormalizedClaimCategory::Platform
            }
            Self::SecureBootState => RuntimeAttestationNormalizedClaimCategory::Configuration,
        }
    }

    #[must_use]
    pub fn confidence(self) -> RuntimeAttestationNormalizedClaimConfidence {
        match self {
            Self::WorkloadIdentityScheme | Self::WorkloadIdentityUri => {
                RuntimeAttestationNormalizedClaimConfidence::Derived
            }
            _ => RuntimeAttestationNormalizedClaimConfidence::Verified,
        }
    }

    #[must_use]
    pub fn freshness(self) -> RuntimeAttestationNormalizedClaimFreshness {
        RuntimeAttestationNormalizedClaimFreshness::EvidenceWindow
    }

    #[must_use]
    pub fn default_provenance(self) -> RuntimeAttestationClaimProvenance {
        match self {
            Self::RuntimeIdentity => RuntimeAttestationClaimProvenance::EvidenceEnvelope,
            Self::WorkloadIdentityScheme | Self::WorkloadIdentityUri => {
                RuntimeAttestationClaimProvenance::WorkloadProjection
            }
            _ => RuntimeAttestationClaimProvenance::VendorClaims,
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::AttestationType => {
                "Portable platform attestation profile or technology class."
            }
            Self::RuntimeIdentity => {
                "Opaque runtime identity string carried by the verified evidence."
            }
            Self::WorkloadIdentityScheme => {
                "Normalized scheme for projected workload identity material."
            }
            Self::WorkloadIdentityUri => {
                "Normalized workload identity URI when Chio has an explicit mapping."
            }
            Self::ModuleId => "Vendor-scoped enclave or module identifier.",
            Self::MeasurementDigest => {
                "Primary verified digest or measurement identifier from the vendor evidence."
            }
            Self::MeasurementRegisters => {
                "Verified measurement-register set preserved without claiming cross-vendor equivalence."
            }
            Self::HardwareModel => {
                "Verified hardware model identifier for the attested platform."
            }
            Self::SecureBootState => {
                "Normalized secure-boot state derived from the verified evidence."
            }
        }
    }

    #[must_use]
    pub fn supported_verifier_families(self) -> Vec<AttestationVerifierFamily> {
        match self {
            Self::AttestationType => vec![
                AttestationVerifierFamily::AzureMaa,
                AttestationVerifierFamily::GoogleAttestation,
                AttestationVerifierFamily::EnterpriseVerifier,
            ],
            Self::RuntimeIdentity => vec![
                AttestationVerifierFamily::AzureMaa,
                AttestationVerifierFamily::GoogleAttestation,
                AttestationVerifierFamily::EnterpriseVerifier,
            ],
            Self::WorkloadIdentityScheme | Self::WorkloadIdentityUri => {
                vec![
                    AttestationVerifierFamily::AzureMaa,
                    AttestationVerifierFamily::GoogleAttestation,
                    AttestationVerifierFamily::EnterpriseVerifier,
                ]
            }
            Self::ModuleId | Self::MeasurementDigest | Self::MeasurementRegisters => {
                vec![
                    AttestationVerifierFamily::AwsNitro,
                    AttestationVerifierFamily::EnterpriseVerifier,
                ]
            }
            Self::HardwareModel | Self::SecureBootState => {
                vec![
                    AttestationVerifierFamily::GoogleAttestation,
                    AttestationVerifierFamily::EnterpriseVerifier,
                ]
            }
        }
    }
}

impl RuntimeAttestationNormalizedClaim {
    #[must_use]
    pub fn new(code: RuntimeAttestationNormalizedClaimCode, value: Value) -> Self {
        Self {
            code,
            legacy_assertion_key: code.legacy_assertion_key().to_string(),
            category: code.category(),
            confidence: code.confidence(),
            freshness: code.freshness(),
            provenance: code.default_provenance(),
            value,
        }
    }
}

impl RuntimeAttestationAppraisalReasonCode {
    #[must_use]
    pub fn group(self) -> RuntimeAttestationAppraisalReasonGroup {
        match self {
            Self::EvidenceVerified => RuntimeAttestationAppraisalReasonGroup::Verification,
            Self::UnsupportedEvidence
            | Self::UnsupportedClaimMapping
            | Self::AmbiguousClaimMapping => RuntimeAttestationAppraisalReasonGroup::Compatibility,
            Self::PolicyRejected => RuntimeAttestationAppraisalReasonGroup::Policy,
            Self::InvalidClaims | Self::MeasurementMismatch => {
                RuntimeAttestationAppraisalReasonGroup::Measurement
            }
            Self::EvidenceStale => RuntimeAttestationAppraisalReasonGroup::Freshness,
            Self::DebugStateUnknown => RuntimeAttestationAppraisalReasonGroup::DebugPosture,
        }
    }

    #[must_use]
    pub fn disposition(self) -> RuntimeAttestationAppraisalReasonDisposition {
        match self {
            Self::EvidenceVerified => RuntimeAttestationAppraisalReasonDisposition::Pass,
            Self::UnsupportedEvidence => RuntimeAttestationAppraisalReasonDisposition::Unknown,
            Self::UnsupportedClaimMapping => RuntimeAttestationAppraisalReasonDisposition::Degrade,
            Self::AmbiguousClaimMapping
            | Self::PolicyRejected
            | Self::InvalidClaims
            | Self::MeasurementMismatch => RuntimeAttestationAppraisalReasonDisposition::Deny,
            Self::EvidenceStale => RuntimeAttestationAppraisalReasonDisposition::Degrade,
            Self::DebugStateUnknown => RuntimeAttestationAppraisalReasonDisposition::Warn,
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::EvidenceVerified => {
                "The verifier accepted the evidence and Chio derived a portable appraisal."
            }
            Self::UnsupportedEvidence => {
                "The evidence schema is outside the current portable appraisal boundary."
            }
            Self::UnsupportedClaimMapping => {
                "Some provider output could not be represented in Chio's portable claim vocabulary."
            }
            Self::AmbiguousClaimMapping => {
                "Provider output could map to more than one portable meaning, so Chio fails closed."
            }
            Self::PolicyRejected => {
                "Local Chio policy rejected the appraisal outcome or prevented trust widening."
            }
            Self::InvalidClaims => {
                "The verified evidence carried claims that were structurally invalid for the expected verifier family."
            }
            Self::EvidenceStale => {
                "The evidence was accepted cryptographically but is too old for the requested policy posture."
            }
            Self::MeasurementMismatch => {
                "The verified measurement material does not satisfy the required portable policy semantics."
            }
            Self::DebugStateUnknown => {
                "The verifier family does not provide one portable debug-posture signal, so Chio preserves uncertainty explicitly."
            }
        }
    }
}

impl RuntimeAttestationAppraisalReason {
    #[must_use]
    pub fn from_code(code: RuntimeAttestationAppraisalReasonCode) -> Self {
        Self {
            code,
            group: code.group(),
            disposition: code.disposition(),
            description: code.description().to_string(),
        }
    }
}

impl RuntimeAttestationImportReasonCode {
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::NoLocalPolicy => {
                "No explicit local import policy was provided, so Chio rejects the foreign result fail closed."
            }
            Self::InvalidSignature => {
                "The signed appraisal result failed signature verification."
            }
            Self::UnsupportedAppraisalSchema => {
                "The imported result or nested appraisal artifact is outside Chio's supported portable appraisal boundary."
            }
            Self::ResultStale => {
                "The imported signed result is older than the allowed local freshness window."
            }
            Self::EvidenceStale => {
                "The evidence carried by the imported result is older than the allowed local freshness window."
            }
            Self::ExporterPolicyRejected => {
                "The exporting operator did not accept the appraisal as trust-widening evidence."
            }
            Self::UntrustedIssuer => {
                "The imported result issuer is not explicitly trusted by local policy."
            }
            Self::UntrustedSigner => {
                "The imported result signer key is not explicitly trusted by local policy."
            }
            Self::UnsupportedVerifierFamily => {
                "The imported verifier family is not allowed by local policy."
            }
            Self::MissingRequiredClaim => {
                "A required portable normalized claim is missing from the imported result."
            }
            Self::ClaimMismatch => {
                "A required portable normalized claim value does not match local policy."
            }
            Self::TierAttenuated => {
                "Chio accepted the imported result only after capping its effective runtime-assurance tier locally."
            }
        }
    }
}

impl RuntimeAttestationImportReason {
    #[must_use]
    pub fn from_code(code: RuntimeAttestationImportReasonCode) -> Self {
        Self {
            code,
            description: code.description().to_string(),
        }
    }
}

impl RuntimeAttestationImportedAppraisalPolicy {
    #[must_use]
    pub fn is_explicit(&self) -> bool {
        !self.trusted_issuers.is_empty()
            || !self.trusted_signer_keys.is_empty()
            || !self.allowed_verifier_families.is_empty()
            || self.max_result_age_seconds.is_some()
            || self.max_evidence_age_seconds.is_some()
            || self.maximum_effective_tier.is_some()
            || !self.required_claims.is_empty()
    }
}

impl RuntimeAttestationAppraisalResult {
    pub fn from_report(
        issuer: impl Into<String>,
        report: &RuntimeAttestationAppraisalReport,
    ) -> ChioResult<Self> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(crate::Error::CanonicalJson(
                "runtime attestation appraisal result issuer must not be empty".to_string(),
            ));
        }
        let appraisal = report.appraisal.artifact.clone().ok_or_else(|| {
            crate::Error::CanonicalJson(
                "runtime attestation appraisal report is missing the nested artifact".to_string(),
            )
        })?;
        let subject = RuntimeAttestationAppraisalResultSubject {
            runtime_identity: report
                .appraisal
                .normalized_assertions
                .get("runtimeIdentity")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            workload_identity: report.appraisal.workload_identity.clone(),
        };
        let descriptor = serde_json::json!({
            "schema": RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA,
            "exportedAt": report.generated_at,
            "issuer": issuer,
            "appraisal": appraisal,
            "exporterPolicyOutcome": report.policy_outcome,
            "subject": subject,
        });
        let result_id = format!(
            "appraisal-result-{}",
            sha256_hex(&canonical_json_bytes(&descriptor)?)
        );

        Ok(Self {
            schema: RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string(),
            result_id,
            exported_at: report.generated_at,
            issuer,
            appraisal,
            exporter_policy_outcome: report.policy_outcome.clone(),
            subject,
        })
    }
}

struct RuntimeAttestationArtifactArgs<'a> {
    adapter: String,
    verifier_family: AttestationVerifierFamily,
    evidence: &'a RuntimeAttestationEvidence,
    normalized_assertions: BTreeMap<String, Value>,
    vendor_claims: BTreeMap<String, Value>,
    verdict: RuntimeAttestationAppraisalVerdict,
    effective_tier: RuntimeAssuranceTier,
    reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
}

impl RuntimeAttestationAppraisal {
    fn artifact(args: RuntimeAttestationArtifactArgs<'_>) -> RuntimeAttestationAppraisalArtifact {
        let normalized_claims = normalized_claims_from_assertions(&args.normalized_assertions);
        let reasons = reasons_from_codes(&args.reason_codes);
        RuntimeAttestationAppraisalArtifact {
            schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
            evidence: RuntimeAttestationEvidenceDescriptor::from(args.evidence),
            verifier: RuntimeAttestationVerifierDescriptor {
                adapter: args.adapter,
                verifier_family: args.verifier_family,
            },
            claims: RuntimeAttestationClaimSets {
                normalized_assertions: args.normalized_assertions,
                normalized_claims,
                vendor_claims: args.vendor_claims,
            },
            policy: RuntimeAttestationPolicyProjection {
                verdict: args.verdict,
                effective_tier: args.effective_tier,
                reason_codes: args.reason_codes,
                reasons,
            },
            workload_identity: args.evidence.workload_identity.clone(),
        }
    }

    #[must_use]
    pub fn accepted(
        adapter: impl Into<String>,
        verifier_family: AttestationVerifierFamily,
        evidence: &RuntimeAttestationEvidence,
        normalized_assertions: BTreeMap<String, Value>,
        vendor_claims: BTreeMap<String, Value>,
        reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    ) -> Self {
        let adapter = adapter.into();
        let normalized_claims = normalized_claims_from_assertions(&normalized_assertions);
        let reasons = reasons_from_codes(&reason_codes);
        let artifact = Self::artifact(RuntimeAttestationArtifactArgs {
            adapter: adapter.clone(),
            verifier_family,
            evidence,
            normalized_assertions: normalized_assertions.clone(),
            vendor_claims: vendor_claims.clone(),
            verdict: RuntimeAttestationAppraisalVerdict::Accepted,
            effective_tier: evidence.tier,
            reason_codes: reason_codes.clone(),
        });
        Self {
            schema: RUNTIME_ATTESTATION_APPRAISAL_SCHEMA.to_string(),
            adapter,
            verifier_family,
            evidence: RuntimeAttestationEvidenceDescriptor::from(evidence),
            verdict: RuntimeAttestationAppraisalVerdict::Accepted,
            effective_tier: evidence.tier,
            normalized_assertions,
            normalized_claims,
            vendor_claims,
            reason_codes,
            reasons,
            workload_identity: evidence.workload_identity.clone(),
            artifact: Some(artifact),
        }
    }

    #[must_use]
    pub fn rejected(
        adapter: impl Into<String>,
        verifier_family: AttestationVerifierFamily,
        evidence: &RuntimeAttestationEvidence,
        normalized_assertions: BTreeMap<String, Value>,
        vendor_claims: BTreeMap<String, Value>,
        reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    ) -> Self {
        let adapter = adapter.into();
        let normalized_claims = normalized_claims_from_assertions(&normalized_assertions);
        let reasons = reasons_from_codes(&reason_codes);
        let artifact = Self::artifact(RuntimeAttestationArtifactArgs {
            adapter: adapter.clone(),
            verifier_family,
            evidence,
            normalized_assertions: normalized_assertions.clone(),
            vendor_claims: vendor_claims.clone(),
            verdict: RuntimeAttestationAppraisalVerdict::Rejected,
            effective_tier: RuntimeAssuranceTier::None,
            reason_codes: reason_codes.clone(),
        });
        Self {
            schema: RUNTIME_ATTESTATION_APPRAISAL_SCHEMA.to_string(),
            adapter,
            verifier_family,
            evidence: RuntimeAttestationEvidenceDescriptor::from(evidence),
            verdict: RuntimeAttestationAppraisalVerdict::Rejected,
            effective_tier: RuntimeAssuranceTier::None,
            normalized_assertions,
            normalized_claims,
            vendor_claims,
            reason_codes,
            reasons,
            workload_identity: evidence.workload_identity.clone(),
            artifact: Some(artifact),
        }
    }
}

#[must_use]
pub fn runtime_attestation_appraisal_artifact_inventory(
) -> RuntimeAttestationAppraisalArtifactInventory {
    RuntimeAttestationAppraisalArtifactInventory {
        schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_INVENTORY_SCHEMA.to_string(),
        entries: vec![
            RuntimeAttestationAppraisalArtifactInventoryEntry {
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                vendor_claim_namespace: "azureMaa".to_string(),
                normalized_assertion_keys: vec![
                    "attestationType".to_string(),
                    "runtimeIdentity".to_string(),
                    "workloadIdentityScheme".to_string(),
                    "workloadIdentityUri".to_string(),
                ],
                normalized_claim_codes: vec![
                    RuntimeAttestationNormalizedClaimCode::AttestationType,
                    RuntimeAttestationNormalizedClaimCode::RuntimeIdentity,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityScheme,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityUri,
                ],
                default_reason_codes: vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
            },
            RuntimeAttestationAppraisalArtifactInventoryEntry {
                attestation_schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
                artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
                verifier_family: AttestationVerifierFamily::AwsNitro,
                adapter: AWS_NITRO_VERIFIER_ADAPTER.to_string(),
                vendor_claim_namespace: "awsNitro".to_string(),
                normalized_assertion_keys: vec![
                    "moduleId".to_string(),
                    "digest".to_string(),
                    "pcrs".to_string(),
                ],
                normalized_claim_codes: vec![
                    RuntimeAttestationNormalizedClaimCode::ModuleId,
                    RuntimeAttestationNormalizedClaimCode::MeasurementDigest,
                    RuntimeAttestationNormalizedClaimCode::MeasurementRegisters,
                ],
                default_reason_codes: vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
            },
            RuntimeAttestationAppraisalArtifactInventoryEntry {
                attestation_schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
                artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
                verifier_family: AttestationVerifierFamily::GoogleAttestation,
                adapter: GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER.to_string(),
                vendor_claim_namespace: "googleAttestation".to_string(),
                normalized_assertion_keys: vec![
                    "attestationType".to_string(),
                    "hardwareModel".to_string(),
                    "secureBoot".to_string(),
                    "runtimeIdentity".to_string(),
                    "workloadIdentityScheme".to_string(),
                    "workloadIdentityUri".to_string(),
                ],
                normalized_claim_codes: vec![
                    RuntimeAttestationNormalizedClaimCode::AttestationType,
                    RuntimeAttestationNormalizedClaimCode::HardwareModel,
                    RuntimeAttestationNormalizedClaimCode::SecureBootState,
                    RuntimeAttestationNormalizedClaimCode::RuntimeIdentity,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityScheme,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityUri,
                ],
                default_reason_codes: vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
            },
            RuntimeAttestationAppraisalArtifactInventoryEntry {
                attestation_schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
                artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
                verifier_family: AttestationVerifierFamily::EnterpriseVerifier,
                adapter: ENTERPRISE_VERIFIER_ADAPTER.to_string(),
                vendor_claim_namespace: "enterpriseVerifier".to_string(),
                normalized_assertion_keys: vec![
                    "attestationType".to_string(),
                    "runtimeIdentity".to_string(),
                    "workloadIdentityScheme".to_string(),
                    "workloadIdentityUri".to_string(),
                    "moduleId".to_string(),
                    "digest".to_string(),
                    "pcrs".to_string(),
                    "hardwareModel".to_string(),
                    "secureBoot".to_string(),
                ],
                normalized_claim_codes: vec![
                    RuntimeAttestationNormalizedClaimCode::AttestationType,
                    RuntimeAttestationNormalizedClaimCode::RuntimeIdentity,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityScheme,
                    RuntimeAttestationNormalizedClaimCode::WorkloadIdentityUri,
                    RuntimeAttestationNormalizedClaimCode::ModuleId,
                    RuntimeAttestationNormalizedClaimCode::MeasurementDigest,
                    RuntimeAttestationNormalizedClaimCode::MeasurementRegisters,
                    RuntimeAttestationNormalizedClaimCode::HardwareModel,
                    RuntimeAttestationNormalizedClaimCode::SecureBootState,
                ],
                default_reason_codes: vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
            },
        ],
    }
}

#[must_use]
pub fn runtime_attestation_normalized_claim_vocabulary(
) -> RuntimeAttestationNormalizedClaimVocabulary {
    let entries = vec![
        RuntimeAttestationNormalizedClaimCode::AttestationType,
        RuntimeAttestationNormalizedClaimCode::RuntimeIdentity,
        RuntimeAttestationNormalizedClaimCode::WorkloadIdentityScheme,
        RuntimeAttestationNormalizedClaimCode::WorkloadIdentityUri,
        RuntimeAttestationNormalizedClaimCode::ModuleId,
        RuntimeAttestationNormalizedClaimCode::MeasurementDigest,
        RuntimeAttestationNormalizedClaimCode::MeasurementRegisters,
        RuntimeAttestationNormalizedClaimCode::HardwareModel,
        RuntimeAttestationNormalizedClaimCode::SecureBootState,
    ]
    .into_iter()
    .map(|code| RuntimeAttestationNormalizedClaimVocabularyEntry {
        code,
        legacy_assertion_key: code.legacy_assertion_key().to_string(),
        category: code.category(),
        confidence: code.confidence(),
        freshness: code.freshness(),
        description: code.description().to_string(),
        supported_verifier_families: code.supported_verifier_families(),
    })
    .collect();

    RuntimeAttestationNormalizedClaimVocabulary {
        schema: RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA.to_string(),
        entries,
    }
}

#[must_use]
pub fn runtime_attestation_reason_taxonomy() -> RuntimeAttestationReasonTaxonomy {
    let entries = vec![
        RuntimeAttestationAppraisalReasonCode::EvidenceVerified,
        RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence,
        RuntimeAttestationAppraisalReasonCode::UnsupportedClaimMapping,
        RuntimeAttestationAppraisalReasonCode::AmbiguousClaimMapping,
        RuntimeAttestationAppraisalReasonCode::PolicyRejected,
        RuntimeAttestationAppraisalReasonCode::InvalidClaims,
        RuntimeAttestationAppraisalReasonCode::EvidenceStale,
        RuntimeAttestationAppraisalReasonCode::MeasurementMismatch,
        RuntimeAttestationAppraisalReasonCode::DebugStateUnknown,
    ]
    .into_iter()
    .map(RuntimeAttestationAppraisalReason::from_code)
    .collect();

    RuntimeAttestationReasonTaxonomy {
        schema: RUNTIME_ATTESTATION_REASON_TAXONOMY_SCHEMA.to_string(),
        entries,
    }
}

#[must_use]
pub fn verifier_family_for_attestation_schema(schema: &str) -> Option<AttestationVerifierFamily> {
    match schema {
        AZURE_MAA_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AzureMaa),
        AWS_NITRO_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AwsNitro),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => {
            Some(AttestationVerifierFamily::GoogleAttestation)
        }
        ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA => {
            Some(AttestationVerifierFamily::EnterpriseVerifier)
        }
        _ => None,
    }
}

fn normalized_claim_code_for_assertion_key(
    key: &str,
) -> Option<RuntimeAttestationNormalizedClaimCode> {
    match key {
        "attestationType" => Some(RuntimeAttestationNormalizedClaimCode::AttestationType),
        "runtimeIdentity" => Some(RuntimeAttestationNormalizedClaimCode::RuntimeIdentity),
        "workloadIdentityScheme" => {
            Some(RuntimeAttestationNormalizedClaimCode::WorkloadIdentityScheme)
        }
        "workloadIdentityUri" => Some(RuntimeAttestationNormalizedClaimCode::WorkloadIdentityUri),
        "moduleId" => Some(RuntimeAttestationNormalizedClaimCode::ModuleId),
        "digest" => Some(RuntimeAttestationNormalizedClaimCode::MeasurementDigest),
        "pcrs" => Some(RuntimeAttestationNormalizedClaimCode::MeasurementRegisters),
        "hardwareModel" => Some(RuntimeAttestationNormalizedClaimCode::HardwareModel),
        "secureBoot" => Some(RuntimeAttestationNormalizedClaimCode::SecureBootState),
        _ => None,
    }
}

fn normalized_claims_from_assertions(
    normalized_assertions: &BTreeMap<String, Value>,
) -> Vec<RuntimeAttestationNormalizedClaim> {
    normalized_assertions
        .iter()
        .filter_map(|(key, value)| {
            normalized_claim_code_for_assertion_key(key)
                .map(|code| RuntimeAttestationNormalizedClaim::new(code, value.clone()))
        })
        .collect()
}

fn reasons_from_codes(
    reason_codes: &[RuntimeAttestationAppraisalReasonCode],
) -> Vec<RuntimeAttestationAppraisalReason> {
    reason_codes
        .iter()
        .copied()
        .map(RuntimeAttestationAppraisalReason::from_code)
        .collect()
}

fn import_reasons_from_codes(
    reason_codes: &[RuntimeAttestationImportReasonCode],
) -> Vec<RuntimeAttestationImportReason> {
    reason_codes
        .iter()
        .copied()
        .map(RuntimeAttestationImportReason::from_code)
        .collect()
}

fn normalized_claim_value_string(claim: &RuntimeAttestationNormalizedClaim) -> Option<String> {
    match &claim.value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        other => serde_json::to_string(other).ok(),
    }
}

#[must_use]
pub fn evaluate_imported_runtime_attestation_appraisal(
    request: &RuntimeAttestationAppraisalImportRequest,
    now: u64,
) -> RuntimeAttestationAppraisalImportReport {
    let result = request.signed_result.body.clone();
    let signer_key_hex = request.signed_result.signer_key.to_hex();
    let mut reason_codes = Vec::new();

    if !request.local_policy.is_explicit() {
        reason_codes.push(RuntimeAttestationImportReasonCode::NoLocalPolicy);
    }
    if !request.signed_result.verify_signature().unwrap_or(false) {
        reason_codes.push(RuntimeAttestationImportReasonCode::InvalidSignature);
    }
    if result.schema != RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA
        || result.appraisal.schema != RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA
    {
        reason_codes.push(RuntimeAttestationImportReasonCode::UnsupportedAppraisalSchema);
    }
    match verifier_family_for_attestation_schema(&result.appraisal.evidence.schema) {
        Some(expected_family) if expected_family == result.appraisal.verifier.verifier_family => {}
        _ => reason_codes.push(RuntimeAttestationImportReasonCode::UnsupportedAppraisalSchema),
    }
    if let Some(max_result_age_seconds) = request.local_policy.max_result_age_seconds {
        let age = now.saturating_sub(result.exported_at);
        if age > max_result_age_seconds {
            reason_codes.push(RuntimeAttestationImportReasonCode::ResultStale);
        }
    }
    if let Some(max_evidence_age_seconds) = request.local_policy.max_evidence_age_seconds {
        let age = now.saturating_sub(result.appraisal.evidence.issued_at);
        if age > max_evidence_age_seconds {
            reason_codes.push(RuntimeAttestationImportReasonCode::EvidenceStale);
        }
    }
    if !result.exporter_policy_outcome.accepted
        || result.appraisal.policy.verdict != RuntimeAttestationAppraisalVerdict::Accepted
    {
        reason_codes.push(RuntimeAttestationImportReasonCode::ExporterPolicyRejected);
    }
    if !request.local_policy.trusted_issuers.is_empty()
        && !request
            .local_policy
            .trusted_issuers
            .iter()
            .any(|trusted| trusted == &result.issuer)
    {
        reason_codes.push(RuntimeAttestationImportReasonCode::UntrustedIssuer);
    }
    if !request.local_policy.trusted_signer_keys.is_empty()
        && !request
            .local_policy
            .trusted_signer_keys
            .iter()
            .any(|trusted| trusted == &signer_key_hex)
    {
        reason_codes.push(RuntimeAttestationImportReasonCode::UntrustedSigner);
    }
    if !request.local_policy.allowed_verifier_families.is_empty()
        && !request
            .local_policy
            .allowed_verifier_families
            .contains(&result.appraisal.verifier.verifier_family)
    {
        reason_codes.push(RuntimeAttestationImportReasonCode::UnsupportedVerifierFamily);
    }

    for (required_code, expected_value) in &request.local_policy.required_claims {
        let actual = result
            .appraisal
            .claims
            .normalized_claims
            .iter()
            .find(|claim| &claim.code == required_code);
        match actual {
            Some(claim) => {
                let actual =
                    normalized_claim_value_string(claim).unwrap_or_else(|| "null".to_string());
                if &actual != expected_value {
                    reason_codes.push(RuntimeAttestationImportReasonCode::ClaimMismatch);
                }
            }
            None => reason_codes.push(RuntimeAttestationImportReasonCode::MissingRequiredClaim),
        }
    }

    let imported_tier = result
        .appraisal
        .policy
        .effective_tier
        .min(result.exporter_policy_outcome.effective_tier);
    let mut disposition = RuntimeAttestationImportDisposition::Allow;
    let mut effective_tier = imported_tier;

    if !reason_codes.is_empty() {
        disposition = RuntimeAttestationImportDisposition::Reject;
        effective_tier = RuntimeAssuranceTier::None;
    } else if let Some(maximum_effective_tier) = request.local_policy.maximum_effective_tier {
        if imported_tier > maximum_effective_tier {
            disposition = RuntimeAttestationImportDisposition::Attenuate;
            effective_tier = maximum_effective_tier;
            reason_codes.push(RuntimeAttestationImportReasonCode::TierAttenuated);
        }
    }

    RuntimeAttestationAppraisalImportReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_IMPORT_REPORT_SCHEMA.to_string(),
        evaluated_at: now,
        signer_key_hex,
        result,
        local_policy_outcome: RuntimeAttestationAppraisalImportOutcome {
            disposition,
            effective_tier,
            reasons: import_reasons_from_codes(&reason_codes),
            reason_codes,
        },
    }
}

pub fn derive_runtime_attestation_appraisal(
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisal, RuntimeAttestationAppraisalError> {
    match evidence.schema.as_str() {
        AZURE_MAA_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            azure_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "azureMaa"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        AWS_NITRO_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            aws_nitro_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "awsNitro"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
            AttestationVerifierFamily::GoogleAttestation,
            evidence,
            google_confidential_vm_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "googleAttestation"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            ENTERPRISE_VERIFIER_ADAPTER,
            AttestationVerifierFamily::EnterpriseVerifier,
            evidence,
            enterprise_verifier_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "enterpriseVerifier"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        _ => Err(RuntimeAttestationAppraisalError::UnsupportedSchema {
            schema: evidence.schema.clone(),
        }),
    }
}

pub fn verify_runtime_attestation_record(
    evidence: &RuntimeAttestationEvidence,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, RuntimeAttestationVerificationError> {
    let appraisal = derive_runtime_attestation_appraisal(evidence)?;
    let subject = verified_runtime_attestation_subject(evidence)?;
    let policy_outcome = verify_runtime_attestation_policy_outcome(evidence, trust_policy, now)?;
    Ok(VerifiedRuntimeAttestationRecord {
        evidence: evidence.clone(),
        provenance: VerifiedRuntimeAttestationProvenance {
            verifier_family: appraisal.verifier_family,
            verifier_adapter: appraisal.adapter.clone(),
            canonical_verifier: canonicalize_attestation_verifier(&evidence.verifier),
            matched_trust_rule: policy_outcome.matched_trust_rule.clone(),
        },
        appraisal,
        policy_outcome: policy_outcome.outcome,
        subject,
        verified_at: now,
    })
}

fn verified_runtime_attestation_subject(
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisalResultSubject, RuntimeAttestationVerificationError> {
    Ok(RuntimeAttestationAppraisalResultSubject {
        runtime_identity: evidence.runtime_identity.clone(),
        workload_identity: evidence.normalized_workload_identity()?,
    })
}

#[derive(Debug, Clone)]
struct VerifiedRuntimeAttestationPolicyVerification {
    outcome: RuntimeAttestationPolicyOutcome,
    matched_trust_rule: Option<String>,
}

fn verify_runtime_attestation_policy_outcome(
    evidence: &RuntimeAttestationEvidence,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationPolicyVerification, RuntimeAttestationVerificationError> {
    let trust_policy_configured = trust_policy.is_some_and(|policy| !policy.rules.is_empty());
    if trust_policy_configured {
        let resolved = evidence
            .resolve_effective_runtime_assurance(trust_policy, now)
            .map_err(RuntimeAttestationVerificationError::TrustPolicy)?;
        let matched_trust_rule = resolved.matched_rule.clone();
        return Ok(VerifiedRuntimeAttestationPolicyVerification {
            outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: true,
                accepted: true,
                effective_tier: resolved.effective_tier,
                reason: matched_trust_rule
                    .as_ref()
                    .map(|rule| format!("matched attestation trust rule `{rule}`")),
            },
            matched_trust_rule,
        });
    }

    evidence.validate_workload_identity_binding()?;
    if !evidence.is_valid_at(now) {
        return Err(RuntimeAttestationVerificationError::StaleEvidence {
            now,
            issued_at: evidence.issued_at,
            expires_at: evidence.expires_at,
        });
    }

    Ok(VerifiedRuntimeAttestationPolicyVerification {
        outcome: RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: false,
            effective_tier: RuntimeAssuranceTier::None,
            reason: Some(
                "runtime attestation evidence did not cross a local verified trust boundary"
                    .to_string(),
            ),
        },
        matched_trust_rule: None,
    })
}

fn extract_vendor_claims(
    evidence: &RuntimeAttestationEvidence,
    vendor_key: &str,
) -> BTreeMap<String, Value> {
    evidence
        .claims
        .as_ref()
        .and_then(|claims| claims.get(vendor_key))
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn azure_normalized_assertions(evidence: &RuntimeAttestationEvidence) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "azureMaa");
    let mut normalized = BTreeMap::new();
    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn aws_nitro_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "awsNitro");
    let mut normalized = BTreeMap::new();
    if let Some(module_id) = vendor_claims.get("moduleId") {
        normalized.insert("moduleId".to_string(), module_id.clone());
    }
    if let Some(digest) = vendor_claims.get("digest") {
        normalized.insert("digest".to_string(), digest.clone());
    }
    if let Some(pcrs) = vendor_claims.get("pcrs") {
        normalized.insert("pcrs".to_string(), pcrs.clone());
    }
    normalized
}

fn google_confidential_vm_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "googleAttestation");
    let mut normalized = BTreeMap::new();
    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(hardware_model) = vendor_claims.get("hardwareModel") {
        normalized.insert("hardwareModel".to_string(), hardware_model.clone());
    }
    if let Some(secure_boot) = vendor_claims.get("secureBoot") {
        normalized.insert("secureBoot".to_string(), secure_boot.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn enterprise_verifier_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "enterpriseVerifier");
    let mut normalized = BTreeMap::new();
    for key in [
        "attestationType",
        "moduleId",
        "digest",
        "pcrs",
        "hardwareModel",
        "secureBoot",
    ] {
        if let Some(value) = vendor_claims.get(key) {
            normalized.insert(key.to_string(), value.clone());
        }
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn push_workload_identity_assertions(
    normalized: &mut BTreeMap<String, Value>,
    workload_identity: Option<&WorkloadIdentity>,
) {
    if let Some(workload_identity) = workload_identity {
        normalized.insert(
            "workloadIdentityScheme".to_string(),
            Value::String(format!("{:?}", workload_identity.scheme).to_lowercase()),
        );
        normalized.insert(
            "workloadIdentityUri".to_string(),
            Value::String(workload_identity.uri.clone()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AttestationTrustPolicy, AttestationTrustRule, RuntimeAssuranceTier,
        RuntimeAttestationEvidence, WorkloadCredentialKind, WorkloadIdentity,
        WorkloadIdentityScheme,
    };
    use serde_json::json;

    fn sample_evidence() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "abc123".to_string(),
            runtime_identity: Some("spiffe://contoso.test/runtime/worker".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://contoso.test/runtime/worker".to_string(),
                trust_domain: "contoso.test".to_string(),
                path: "/runtime/worker".to_string(),
            }),
            claims: Some(json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn sample_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        }
    }

    fn sample_nitro_evidence() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://nitro.aws.example/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "nitro-digest-1".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:nitro-measurement",
                    "pcrs": {"0": "0123"}
                }
            })),
        }
    }

    fn sample_nitro_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "aws-nitro-contoso".to_string(),
                schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::from([
                    ("moduleId".to_string(), "nitro-enclave-1".to_string()),
                    ("digest".to_string(), "sha384:nitro-measurement".to_string()),
                ]),
            }],
        }
    }

    fn sample_descriptor_document() -> RuntimeAttestationVerifierDescriptorDocument {
        RuntimeAttestationVerifierDescriptorDocument {
            schema: RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA.to_string(),
            descriptor_id: "azure-prod".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            verifier_family: AttestationVerifierFamily::AzureMaa,
            adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
            attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
            appraisal_artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
            appraisal_result_schema: RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string(),
            signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
            reference_values_uri: Some("https://maa.contoso.test/reference-values".to_string()),
            issued_at: 100,
            expires_at: 300,
        }
    }

    fn sample_reference_value_set() -> RuntimeAttestationReferenceValueSet {
        RuntimeAttestationReferenceValueSet {
            schema: RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA.to_string(),
            reference_value_id: "azure-rv-1".to_string(),
            descriptor_id: "azure-prod".to_string(),
            verifier_family: AttestationVerifierFamily::AzureMaa,
            attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
            source_uri: Some("https://maa.contoso.test/reference-values/1".to_string()),
            issued_at: 100,
            expires_at: 300,
            state: RuntimeAttestationReferenceValueState::Active,
            superseded_by: None,
            revoked_reason: None,
            measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
        }
    }

    fn sample_signed_descriptor(
        signer: &crate::crypto::Keypair,
    ) -> SignedRuntimeAttestationVerifierDescriptor {
        SignedExportEnvelope::sign(sample_descriptor_document(), signer).expect("sign descriptor")
    }

    fn sample_signed_reference_value_set(
        signer: &crate::crypto::Keypair,
    ) -> SignedRuntimeAttestationReferenceValueSet {
        SignedExportEnvelope::sign(sample_reference_value_set(), signer)
            .expect("sign reference values")
    }

    fn sample_trust_bundle_document(
        signer: &crate::crypto::Keypair,
    ) -> RuntimeAttestationTrustBundleDocument {
        RuntimeAttestationTrustBundleDocument {
            schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
            bundle_id: "bundle-1".to_string(),
            publisher: "https://trust.contoso.test".to_string(),
            version: 1,
            issued_at: 100,
            expires_at: 300,
            descriptors: vec![sample_signed_descriptor(signer)],
            reference_values: vec![sample_signed_reference_value_set(signer)],
        }
    }

    fn empty_import_policy() -> RuntimeAttestationImportedAppraisalPolicy {
        RuntimeAttestationImportedAppraisalPolicy {
            trusted_issuers: Vec::new(),
            trusted_signer_keys: Vec::new(),
            allowed_verifier_families: Vec::new(),
            max_result_age_seconds: None,
            max_evidence_age_seconds: None,
            maximum_effective_tier: None,
            required_claims: BTreeMap::new(),
        }
    }

    fn sample_appraisal_result() -> RuntimeAttestationAppraisalResult {
        let appraisal = derive_runtime_attestation_appraisal(&sample_evidence())
            .expect("derive sample appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
            .expect("result from sample report")
    }

    #[test]
    fn verified_runtime_attestation_record_requires_local_trust_boundary_for_tier_promotion() {
        let verified =
            verify_runtime_attestation_record(&sample_evidence(), None, 150).expect("record");

        assert_eq!(verified.verified_at, 150);
        assert_eq!(
            verified.subject.runtime_identity.as_deref(),
            Some("spiffe://contoso.test/runtime/worker")
        );
        assert_eq!(
            verified
                .workload_identity()
                .expect("verified record should carry canonical workload identity")
                .trust_domain,
            "contoso.test"
        );
        assert_eq!(
            verified.appraisal.effective_tier,
            RuntimeAssuranceTier::Attested
        );
        assert!(!verified.policy_outcome.trust_policy_configured);
        assert!(!verified.policy_outcome.accepted);
        assert!(!verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::None);
        assert_eq!(
            verified.provenance.verifier_adapter,
            AZURE_MAA_VERIFIER_ADAPTER
        );
        assert_eq!(
            verified.provenance.canonical_verifier,
            "https://maa.contoso.test"
        );
        assert_eq!(verified.matched_trust_rule(), None);
        assert_eq!(
            verified.policy_outcome.effective_tier,
            RuntimeAssuranceTier::None
        );
        assert_eq!(
            verified.policy_outcome.reason.as_deref(),
            Some("runtime attestation evidence did not cross a local verified trust boundary")
        );
    }

    #[test]
    fn verified_runtime_attestation_record_promotes_tier_only_after_local_policy_verification() {
        let verified = verify_runtime_attestation_record(
            &sample_evidence(),
            Some(&sample_trust_policy()),
            150,
        )
        .expect("trusted record");

        assert!(verified.policy_outcome.trust_policy_configured);
        assert!(verified.policy_outcome.accepted);
        assert!(verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
        assert_eq!(
            verified.provenance.verifier_family,
            AttestationVerifierFamily::AzureMaa
        );
        assert_eq!(verified.matched_trust_rule(), Some("azure-contoso"));
        assert_eq!(
            verified.policy_outcome.effective_tier,
            RuntimeAssuranceTier::Verified
        );
        assert_eq!(
            verified.policy_outcome.reason.as_deref(),
            Some("matched attestation trust rule `azure-contoso`")
        );
    }

    #[test]
    fn verified_runtime_attestation_record_accepts_nitro_evidence_across_trust_boundary() {
        let evidence = sample_nitro_evidence();
        let verified =
            verify_runtime_attestation_record(&evidence, Some(&sample_nitro_trust_policy()), 150)
                .expect("nitro record should verify across the trust boundary");

        assert!(verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
        assert_eq!(verified.evidence_schema(), AWS_NITRO_ATTESTATION_SCHEMA);
        assert_eq!(verified.evidence_sha256(), "nitro-digest-1");
        assert_eq!(verified.canonical_verifier(), "https://nitro.aws.example");
        assert_eq!(
            verified.verifier_family(),
            AttestationVerifierFamily::AwsNitro
        );
        assert!(verified.matches_evidence(&evidence));

        let mut modified = evidence.clone();
        modified.evidence_sha256 = "nitro-digest-2".to_string();
        assert!(!verified.matches_evidence(&modified));
    }

    #[test]
    fn verifier_descriptor_validation_and_verification_reject_invalid_variants() {
        let mut descriptor = sample_descriptor_document();
        descriptor.schema = "chio.runtime-attestation.verifier-descriptor.v0".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("invalid descriptor schema")
                .to_string()
                .contains("schema must be")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.descriptor_id = "  ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty descriptor id")
                .to_string()
                .contains("descriptor_id")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.verifier = " ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty verifier")
                .to_string()
                .contains("non-empty verifier")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.adapter = " ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty adapter")
                .to_string()
                .contains("non-empty adapter")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.issued_at = 301;
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("inverted descriptor window")
                .to_string()
                .contains("must not expire before it is issued")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas.clear();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("missing schemas")
                .to_string()
                .contains("at least one attestation schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas = vec![
            GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
            AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        ];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("unsorted schemas")
                .to_string()
                .contains("sorted unique order")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas = vec![String::new()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty schema entry")
                .to_string()
                .contains("cannot contain empty values")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.appraisal_artifact_schema = "chio.runtime-attestation.other.v1".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("wrong artifact schema")
                .to_string()
                .contains("canonical appraisal artifact schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.appraisal_result_schema = "chio.runtime-attestation.other-result.v1".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("wrong result schema")
                .to_string()
                .contains("canonical appraisal result schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints.clear();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("missing signing keys")
                .to_string()
                .contains("at least one signing-key fingerprint")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints =
            vec!["sha256:key-b".to_string(), "sha256:key-a".to_string()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("unsorted signing keys")
                .to_string()
                .contains("sorted unique order")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints = vec![" ".to_string()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty signing key")
                .to_string()
                .contains("cannot contain empty values")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.reference_values_uri = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .expect_err("empty reference_values_uri")
                .to_string()
                .contains("reference_values_uri")
        );

        let signer = crate::crypto::Keypair::generate();
        let signed = sample_signed_descriptor(&signer);
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&signed, 50)
                .expect_err("descriptor not yet valid")
                .to_string()
                .contains("not yet valid")
        );
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&signed, 400)
                .expect_err("descriptor expired")
                .to_string()
                .contains("has expired")
        );

        let mut tampered = signed.clone();
        tampered.body.verifier = "https://maa.other.example".to_string();
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&tampered, 150)
                .expect_err("descriptor signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn reference_value_validation_and_verification_reject_invalid_variants() {
        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.schema = "chio.runtime-attestation.reference-values.v0".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("invalid reference-value schema")
                .to_string()
                .contains("schema must be")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.reference_value_id = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("empty reference_value_id")
                .to_string()
                .contains("reference_value_id")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.descriptor_id = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("empty descriptor_id")
                .to_string()
                .contains("descriptor_id")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.attestation_schema = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("empty attestation schema")
                .to_string()
                .contains("attestation_schema")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.issued_at = 301;
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("inverted reference-value window")
                .to_string()
                .contains("must not expire before it is issued")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.source_uri = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("empty source uri")
                .to_string()
                .contains("source_uri")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.measurements.clear();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("missing measurements")
                .to_string()
                .contains("at least one measurement")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("active state with supersession")
                .to_string()
                .contains("cannot include supersession or revocation fields")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("superseded without successor")
                .to_string()
                .contains("must include superseded_by")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        reference_value_set.superseded_by = Some("azure-rv-1".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("self supersession")
                .to_string()
                .contains("cannot supersede itself")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        reference_value_set.revoked_reason = Some("compromised".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("superseded with revoked_reason")
                .to_string()
                .contains("cannot include revoked_reason")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Revoked;
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        reference_value_set.revoked_reason = Some("compromised".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("revoked with superseded_by")
                .to_string()
                .contains("cannot include superseded_by")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Revoked;
        reference_value_set.revoked_reason = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .expect_err("revoked without reason")
                .to_string()
                .contains("must include revoked_reason")
        );

        let signer = crate::crypto::Keypair::generate();
        let signed = sample_signed_reference_value_set(&signer);
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&signed, 50)
                .expect_err("reference values not yet valid")
                .to_string()
                .contains("not yet valid")
        );
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&signed, 400)
                .expect_err("reference values expired")
                .to_string()
                .contains("has expired")
        );

        let mut tampered = signed.clone();
        tampered.body.source_uri = Some("https://maa.other.example/reference-values".to_string());
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&tampered, 150)
                .expect_err("reference-value signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn trust_bundle_validation_and_verification_reject_remaining_invalid_states() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = sample_signed_descriptor(&signer);
        let reference_value = sample_signed_reference_value_set(&signer);

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.schema = "chio.runtime-attestation.trust-bundle.v0".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("invalid bundle schema")
            .to_string()
            .contains("schema must be"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.bundle_id = " ".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("empty bundle id")
            .to_string()
            .contains("bundle_id"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.publisher = " ".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("empty bundle publisher")
            .to_string()
            .contains("non-empty publisher"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.version = 0;
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("bundle version zero")
            .to_string()
            .contains("non-zero version"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.issued_at = 301;
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("inverted bundle window")
            .to_string()
            .contains("must not expire before it is issued"));

        let bundle = sample_trust_bundle_document(&signer);
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 50)
            .expect_err("bundle not yet valid")
            .to_string()
            .contains("not yet valid"));
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 400)
            .expect_err("bundle expired")
            .to_string()
            .contains("has expired"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.descriptors.clear();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("bundle without descriptors")
            .to_string()
            .contains("at least one verifier descriptor"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.descriptors = vec![descriptor.clone(), descriptor.clone()];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("duplicate descriptor ids")
            .to_string()
            .contains("duplicate verifier descriptor"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values = vec![reference_value.clone(), reference_value.clone()];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("duplicate reference-value ids")
            .to_string()
            .contains("duplicate reference-value set"));

        let mut unknown_reference = sample_reference_value_set();
        unknown_reference.descriptor_id = "azure-other".to_string();
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values =
            vec![SignedExportEnvelope::sign(unknown_reference, &signer)
                .expect("sign unknown reference")];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("unknown descriptor")
            .to_string()
            .contains("unknown verifier descriptor"));

        let mut schema_mismatch_reference = sample_reference_value_set();
        schema_mismatch_reference.attestation_schema =
            GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string();
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values =
            vec![
                SignedExportEnvelope::sign(schema_mismatch_reference, &signer)
                    .expect("sign schema mismatch reference"),
            ];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("schema outside descriptor")
            .to_string()
            .contains("outside descriptor"));

        let mut superseded_reference = sample_reference_value_set();
        superseded_reference.reference_value_id = "azure-rv-old".to_string();
        superseded_reference.state = RuntimeAttestationReferenceValueState::Superseded;
        superseded_reference.superseded_by = Some("azure-rv-next".to_string());
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values = vec![SignedExportEnvelope::sign(superseded_reference, &signer)
            .expect("sign superseded reference")];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("missing superseded successor")
            .to_string()
            .contains("unknown successor"));

        let signed_bundle =
            SignedExportEnvelope::sign(sample_trust_bundle_document(&signer), &signer)
                .expect("sign trust bundle");
        let mut tampered = signed_bundle.clone();
        tampered.body.publisher = "https://trust.other.example".to_string();
        assert!(
            verify_signed_runtime_attestation_trust_bundle(&tampered, 150)
                .expect_err("bundle signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn runtime_attestation_import_reasons_cover_remaining_policy_fail_closed_paths() {
        let signed_result = SignedRuntimeAttestationAppraisalResult::sign(
            sample_appraisal_result(),
            &crate::crypto::Keypair::generate(),
        )
        .expect("sign result");

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result,
                local_policy: empty_import_policy(),
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::NoLocalPolicy]
        );
        assert_eq!(
            import.local_policy_outcome.reasons[0].description,
            RuntimeAttestationImportReasonCode::NoLocalPolicy.description()
        );
    }

    #[test]
    fn imported_runtime_attestation_rejects_untrusted_exporters_and_claim_policy_failures() {
        let mut result = sample_appraisal_result();
        result.exporter_policy_outcome.accepted = false;
        let signer = crate::crypto::Keypair::generate();
        let signed_result =
            SignedRuntimeAttestationAppraisalResult::sign(result, &signer).expect("sign result");

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:trusted".to_string()],
                    trusted_signer_keys: vec!["sha256:not-the-real-signer".to_string()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::GoogleAttestation],
                    max_result_age_seconds: None,
                    max_evidence_age_seconds: None,
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::from([
                        (
                            RuntimeAttestationNormalizedClaimCode::ModuleId,
                            "module-1".to_string(),
                        ),
                        (
                            RuntimeAttestationNormalizedClaimCode::AttestationType,
                            "sev".to_string(),
                        ),
                    ]),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        for code in [
            RuntimeAttestationImportReasonCode::ExporterPolicyRejected,
            RuntimeAttestationImportReasonCode::UntrustedIssuer,
            RuntimeAttestationImportReasonCode::UntrustedSigner,
            RuntimeAttestationImportReasonCode::UnsupportedVerifierFamily,
            RuntimeAttestationImportReasonCode::MissingRequiredClaim,
            RuntimeAttestationImportReasonCode::ClaimMismatch,
        ] {
            assert!(import.local_policy_outcome.reason_codes.contains(&code));
            assert!(import
                .local_policy_outcome
                .reasons
                .iter()
                .any(|reason| reason.code == code && reason.description == code.description()));
        }
    }

    #[test]
    fn normalized_claim_values_and_result_guards_cover_remaining_branch_paths() {
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::SecureBootState,
                Value::Bool(true),
            )),
            Some("true".to_string())
        );
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                Value::Number(serde_json::Number::from(7)),
            )),
            Some("7".to_string())
        );
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::MeasurementRegisters,
                json!({"0": "abcd"}),
            )),
            Some("{\"0\":\"abcd\"}".to_string())
        );

        let appraisal = derive_runtime_attestation_appraisal(&sample_evidence())
            .expect("derive appraisal for result guard test");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };

        assert!(
            RuntimeAttestationAppraisalResult::from_report("  ", &report)
                .expect_err("empty issuer")
                .to_string()
                .contains("issuer must not be empty")
        );

        let mut missing_artifact_report = report.clone();
        missing_artifact_report.appraisal.artifact = None;
        assert!(RuntimeAttestationAppraisalResult::from_report(
            "did:chio:test:issuer",
            &missing_artifact_report,
        )
        .expect_err("missing artifact")
        .to_string()
        .contains("missing the nested artifact"));

        assert_eq!(
            verifier_family_for_attestation_schema(ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA),
            Some(AttestationVerifierFamily::EnterpriseVerifier)
        );
        assert_eq!(
            verifier_family_for_attestation_schema("urn:chio:unknown"),
            None
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_aws_nitro_and_rejects_unknown_schema() {
        let evidence = RuntimeAttestationEvidence {
            schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://nitro.aws.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "aws-digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:aws-measurement",
                    "pcrs": {"0": "0123"}
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .expect("aws nitro evidence should derive");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::AwsNitro
        );
        assert_eq!(
            appraisal.normalized_assertions["moduleId"],
            "nitro-enclave-1"
        );
        assert_eq!(
            appraisal.normalized_assertions["digest"],
            "sha384:aws-measurement"
        );
        assert_eq!(
            appraisal.normalized_assertions["pcrs"],
            json!({"0": "0123"})
        );
        let artifact = appraisal.artifact.expect("aws appraisal artifact");
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::MeasurementRegisters
                && claim.value == json!({"0": "0123"})
        }));

        let mut unsupported = sample_evidence();
        unsupported.schema = "chio.runtime-attestation.unknown.v1".to_string();
        let error = derive_runtime_attestation_appraisal(&unsupported)
            .expect_err("unsupported schema should fail");
        assert!(matches!(
            error,
            RuntimeAttestationAppraisalError::UnsupportedSchema { schema }
            if schema == "chio.runtime-attestation.unknown.v1"
        ));
    }

    #[test]
    fn runtime_attestation_appraisal_copies_evidence_descriptor_fields() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::accepted(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        );

        assert_eq!(appraisal.schema, RUNTIME_ATTESTATION_APPRAISAL_SCHEMA);
        assert_eq!(appraisal.evidence.schema, evidence.schema);
        assert_eq!(appraisal.evidence.verifier, evidence.verifier);
        assert_eq!(appraisal.evidence.evidence_sha256, evidence.evidence_sha256);
        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Accepted
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::Attested);
        let artifact = appraisal
            .artifact
            .expect("accepted appraisal should carry artifact");
        assert_eq!(
            artifact.schema,
            RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA
        );
        assert_eq!(artifact.verifier.adapter, "azure_maa");
        assert_eq!(
            artifact.verifier.verifier_family,
            AttestationVerifierFamily::AzureMaa
        );
        assert_eq!(
            artifact.policy.verdict,
            RuntimeAttestationAppraisalVerdict::Accepted
        );
        assert_eq!(
            artifact.policy.effective_tier,
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(
            appraisal.reasons,
            vec![RuntimeAttestationAppraisalReason::from_code(
                RuntimeAttestationAppraisalReasonCode::EvidenceVerified
            )]
        );
    }

    #[test]
    fn rejected_runtime_attestation_appraisal_drops_effective_tier() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::rejected(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected],
        );

        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::None);
        assert_eq!(
            appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected]
        );
        let artifact = appraisal
            .artifact
            .expect("rejected appraisal should carry artifact");
        assert_eq!(
            artifact.policy.verdict,
            RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(artifact.policy.effective_tier, RuntimeAssuranceTier::None);
        assert_eq!(
            artifact.policy.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected]
        );
        assert_eq!(
            artifact.policy.reasons,
            vec![RuntimeAttestationAppraisalReason::from_code(
                RuntimeAttestationAppraisalReasonCode::PolicyRejected
            )]
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_google_confidential_vm() {
        let evidence = RuntimeAttestationEvidence {
            schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "google-digest".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .expect("google evidence should derive a canonical appraisal");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::GoogleAttestation
        );
        assert_eq!(
            appraisal.normalized_assertions["attestationType"],
            "confidential_vm"
        );
        assert_eq!(
            appraisal.normalized_assertions["hardwareModel"],
            "GCP_AMD_SEV"
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
        let artifact = appraisal
            .artifact
            .expect("derived appraisal should carry artifact");
        assert_eq!(
            artifact.claims.normalized_assertions["secureBoot"],
            "enabled"
        );
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::SecureBootState
                && claim.category == RuntimeAttestationNormalizedClaimCategory::Configuration
                && claim.provenance == RuntimeAttestationClaimProvenance::VendorClaims
                && claim.value == Value::String("enabled".to_string())
        }));
        assert_eq!(
            artifact.verifier.adapter,
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_enterprise_verifier() {
        let evidence = RuntimeAttestationEvidence {
            schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://attest.contoso.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "enterprise-digest".to_string(),
            runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
            workload_identity: Some(
                WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                    .expect("parse enterprise workload identity"),
            ),
            claims: Some(json!({
                "enterpriseVerifier": {
                    "attestationType": "enterprise_confidential_vm",
                    "hardwareModel": "AMD_SEV_SNP",
                    "secureBoot": "enabled",
                    "digest": "sha384:enterprise-measurement",
                    "pcrs": {
                        "0": "8f7f1be8"
                    }
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .expect("enterprise evidence should derive a canonical appraisal");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::EnterpriseVerifier
        );
        assert_eq!(
            appraisal.normalized_assertions["attestationType"],
            "enterprise_confidential_vm"
        );
        assert_eq!(
            appraisal.normalized_assertions["hardwareModel"],
            "AMD_SEV_SNP"
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
        assert_eq!(
            appraisal.normalized_assertions["digest"],
            "sha384:enterprise-measurement"
        );
        let artifact = appraisal
            .artifact
            .expect("derived appraisal should carry artifact");
        assert_eq!(artifact.verifier.adapter, ENTERPRISE_VERIFIER_ADAPTER);
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::MeasurementDigest
                && claim.value == Value::String("sha384:enterprise-measurement".to_string())
        }));
    }

    #[test]
    fn runtime_attestation_appraisal_inventory_lists_supported_bridges() {
        let inventory = runtime_attestation_appraisal_artifact_inventory();

        assert_eq!(
            inventory.schema,
            RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_INVENTORY_SCHEMA
        );
        assert_eq!(inventory.entries.len(), 4);
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == AZURE_MAA_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "azureMaa"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == AWS_NITRO_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "awsNitro"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "googleAttestation"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "enterpriseVerifier"
            ));
        assert!(inventory.entries.iter().any(|entry| {
            entry.attestation_schema == AWS_NITRO_ATTESTATION_SCHEMA
                && entry
                    .normalized_claim_codes
                    .contains(&RuntimeAttestationNormalizedClaimCode::MeasurementDigest)
        }));
    }

    #[test]
    fn runtime_attestation_claim_vocabulary_lists_portable_codes() {
        let vocabulary = runtime_attestation_normalized_claim_vocabulary();

        assert_eq!(
            vocabulary.schema,
            RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA
        );
        assert!(vocabulary.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationNormalizedClaimCode::SecureBootState
                && entry.legacy_assertion_key == "secureBoot"
                && entry.category == RuntimeAttestationNormalizedClaimCategory::Configuration
                && entry
                    .supported_verifier_families
                    .contains(&AttestationVerifierFamily::GoogleAttestation)
        }));
        assert!(vocabulary.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationNormalizedClaimCode::MeasurementDigest
                && entry
                    .supported_verifier_families
                    .contains(&AttestationVerifierFamily::EnterpriseVerifier)
        }));
    }

    #[test]
    fn runtime_attestation_reason_taxonomy_lists_structured_reasons() {
        let taxonomy = runtime_attestation_reason_taxonomy();

        assert_eq!(taxonomy.schema, RUNTIME_ATTESTATION_REASON_TAXONOMY_SCHEMA);
        assert!(taxonomy.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationAppraisalReasonCode::EvidenceVerified
                && entry.group == RuntimeAttestationAppraisalReasonGroup::Verification
                && entry.disposition == RuntimeAttestationAppraisalReasonDisposition::Pass
        }));
        assert!(taxonomy.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationAppraisalReasonCode::UnsupportedClaimMapping
                && entry.group == RuntimeAttestationAppraisalReasonGroup::Compatibility
                && entry.disposition == RuntimeAttestationAppraisalReasonDisposition::Degrade
        }));
    }

    #[test]
    fn runtime_attestation_trust_bundle_verifies_signed_descriptor_and_reference_values() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: Some("https://maa.contoso.test/reference-values".to_string()),
                issued_at: 100,
                expires_at: 300,
            },
        )
        .expect("descriptor");
        let reference_values = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: Some("https://maa.contoso.test/reference-values/1".to_string()),
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
            },
        )
        .expect("reference values");
        let bundle =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-1".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_values],
            })
            .expect("bundle");

        let verification =
            verify_signed_runtime_attestation_trust_bundle(&bundle, 150).expect("verify");

        assert_eq!(verification.schema, RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA);
        assert_eq!(verification.descriptor_count, 1);
        assert_eq!(verification.reference_value_count, 1);
        assert_eq!(
            verification.verifier_families,
            vec![AttestationVerifierFamily::AzureMaa]
        );
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_expired_descriptor() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 120,
            },
        )
        .expect("descriptor");
        let bundle =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-2".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: Vec::new(),
            })
            .expect("bundle");

        let error = verify_signed_runtime_attestation_trust_bundle(&bundle, 150)
            .expect_err("expired descriptor");
        assert!(error
            .to_string()
            .contains("verifier descriptor `azure-prod` has expired"));
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_ambiguous_active_reference_values() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 300,
            },
        )
        .expect("descriptor");
        let reference_a = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
            },
        )
        .expect("reference values");
        let reference_b = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-2".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("def456"))]),
            },
        )
        .expect("reference values");
        let error =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-3".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_a, reference_b],
            })
            .expect_err("ambiguous reference values");
        assert!(error
            .to_string()
            .contains("ambiguous active reference values"));
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_reference_values_outside_descriptor_contract() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 300,
            },
        )
        .expect("descriptor");
        let reference_values = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "google-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::GoogleAttestation,
                attestation_schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("hwModel".to_string(), json!("GCP_AMD_SEV"))]),
            },
        )
        .expect("reference values");
        let error =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-4".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_values],
            })
            .expect_err("mismatched reference values");
        assert!(error.to_string().contains("does not match verifier-family"));
    }

    #[test]
    fn runtime_attestation_appraisal_result_ids_are_deterministic() {
        let evidence = sample_evidence();
        let appraisal = derive_runtime_attestation_appraisal(&evidence).expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: true,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Verified,
                reason: None,
            },
        };

        let first = RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
            .unwrap();
        let second =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .unwrap();

        assert_eq!(
            first.schema,
            RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string()
        );
        assert_eq!(first.result_id, second.result_id);
        assert!(first.result_id.starts_with("appraisal-result-"));
    }

    #[test]
    fn imported_runtime_attestation_rejects_invalid_signature() {
        let evidence = sample_evidence();
        let appraisal = derive_runtime_attestation_appraisal(&evidence).expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).unwrap();
        let mut tampered = signed.clone();
        tampered.body.issuer = "did:chio:test:other".to_string();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: tampered,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    max_result_age_seconds: Some(120),
                    ..RuntimeAttestationImportedAppraisalPolicy {
                        trusted_issuers: Vec::new(),
                        trusted_signer_keys: Vec::new(),
                        allowed_verifier_families: Vec::new(),
                        max_result_age_seconds: None,
                        max_evidence_age_seconds: None,
                        maximum_effective_tier: None,
                        required_claims: BTreeMap::new(),
                    }
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::InvalidSignature]
        );
    }

    #[test]
    fn imported_runtime_attestation_can_be_attenuated_locally() {
        let evidence = sample_evidence();
        let appraisal = derive_runtime_attestation_appraisal(&evidence).expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    max_result_age_seconds: Some(300),
                    max_evidence_age_seconds: Some(300),
                    maximum_effective_tier: Some(RuntimeAssuranceTier::Basic),
                    required_claims: BTreeMap::new(),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Attenuate
        );
        assert_eq!(
            import.local_policy_outcome.effective_tier,
            RuntimeAssuranceTier::Basic
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::TierAttenuated]
        );
    }

    #[test]
    fn imported_runtime_attestation_rejects_stale_result_and_evidence() {
        let evidence = sample_evidence();
        let appraisal = derive_runtime_attestation_appraisal(&evidence).expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    max_result_age_seconds: Some(20),
                    max_evidence_age_seconds: Some(20),
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::new(),
                },
            },
            200,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert!(import
            .local_policy_outcome
            .reason_codes
            .contains(&RuntimeAttestationImportReasonCode::ResultStale));
        assert!(import
            .local_policy_outcome
            .reason_codes
            .contains(&RuntimeAttestationImportReasonCode::EvidenceStale));
    }

    #[test]
    fn imported_runtime_attestation_rejects_schema_family_mismatch() {
        let evidence = sample_evidence();
        let appraisal = derive_runtime_attestation_appraisal(&evidence).expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let mut result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .unwrap();
        result.appraisal.verifier.verifier_family = AttestationVerifierFamily::GoogleAttestation;
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::GoogleAttestation],
                    max_result_age_seconds: Some(300),
                    max_evidence_age_seconds: Some(300),
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::new(),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::UnsupportedAppraisalSchema]
        );
    }
}
