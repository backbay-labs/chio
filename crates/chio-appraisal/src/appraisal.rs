//! Appraisal derivation, record verification, and foreign-result import evaluation.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::capability::{
    canonicalize_attestation_verifier, AttestationTrustPolicy, RuntimeAssuranceTier,
    RuntimeAttestationEvidence, WorkloadIdentity,
};
use crate::crypto::sha256_hex;
use crate::error::Result as ChioResult;
use chio_core_types::runtime_attestation::AttestationVerifierFamily;

use crate::artifact_inventory::verifier_family_for_attestation_schema;
use crate::types::*;

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

pub(crate) fn normalized_claim_value_string(
    claim: &RuntimeAttestationNormalizedClaim,
) -> Option<String> {
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
