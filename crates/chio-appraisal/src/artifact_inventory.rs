//! Static catalogs: appraisal artifact inventory, normalized-claim vocabulary, and reason taxonomy.

use crate::types::*;
use chio_core_types::runtime_attestation::AttestationVerifierFamily;

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
