use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chio_core::appraisal::{
    derive_runtime_attestation_appraisal, AttestationVerifierFamily, RuntimeAttestationAppraisal,
    RuntimeAttestationAppraisalReasonCode, ENTERPRISE_VERIFIER_ADAPTER,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
};
use chio_core::capability::{
    RuntimeAssuranceTier, RuntimeAttestationEvidence, WorkloadCredentialKind, WorkloadIdentity,
};
use chio_core::crypto::PublicKey;
use chio_core::receipt::SignedExportEnvelope;
use ciborium::de::from_reader as cbor_from_reader;
use ciborium::ser::into_writer as cbor_into_writer;
use ciborium::value::{Integer as CborInteger, Value as CborValue};
use p384::ecdsa::{
    signature::Verifier as _, Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use rsa::{pkcs1v15::Signature as RsaPkcs1v15Signature, pss::Signature as RsaPssSignature};
use rsa::{BigUint, RsaPublicKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};
use x509_cert::Certificate;

pub const AZURE_MAA_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.azure-maa.jwt.v1";
pub const AZURE_MAA_VERIFIER_ADAPTER: &str = "azure_maa";
pub const AWS_NITRO_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.aws-nitro-attestation.v1";
pub const AWS_NITRO_VERIFIER_ADAPTER: &str = "aws_nitro";
const COSE_HEADER_ALGORITHM_KEY: i64 = 1;
const COSE_ES384_ALGORITHM: i64 = -35;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRuntimeAttestation {
    pub evidence: RuntimeAttestationEvidence,
    pub appraisal: RuntimeAttestationAppraisal,
}

pub trait RuntimeAttestationVerifierAdapter {
    type Error;

    fn adapter_name(&self) -> &'static str;

    fn verifier_family(&self) -> AttestationVerifierFamily;

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureMaaVerifierAdapter {
    pub policy: AzureMaaVerificationPolicy,
    pub jwks: AzureMaaJwks,
}

impl AzureMaaVerifierAdapter {
    pub fn new(
        policy: AzureMaaVerificationPolicy,
        jwks: AzureMaaJwks,
    ) -> Result<Self, AzureMaaVerificationError> {
        policy.validate()?;
        Ok(Self { policy, jwks })
    }
}

impl RuntimeAttestationVerifierAdapter for AzureMaaVerifierAdapter {
    type Error = AzureMaaVerificationError;

    fn adapter_name(&self) -> &'static str {
        AZURE_MAA_VERIFIER_ADAPTER
    }

    fn verifier_family(&self) -> AttestationVerifierFamily {
        AttestationVerifierFamily::AzureMaa
    }

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error> {
        let verified_evidence =
            verify_azure_maa_attestation_jwt(evidence, &self.policy, &self.jwks, now)?;
        let appraisal = appraise_azure_maa_evidence(&verified_evidence);
        Ok(VerifiedRuntimeAttestation {
            evidence: verified_evidence,
            appraisal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNitroVerificationPolicy {
    pub trusted_root_certificates_pem: Vec<String>,
    #[serde(default)]
    pub expected_pcrs: BTreeMap<u8, String>,
    pub max_document_age_seconds: u64,
    #[serde(default = "default_aws_nitro_runtime_tier")]
    pub tier: RuntimeAssuranceTier,
    #[serde(default)]
    pub allow_debug_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_nonce_hex: Option<String>,
}

impl AwsNitroVerificationPolicy {
    pub fn validate(&self) -> Result<(), AwsNitroVerificationError> {
        if self.trusted_root_certificates_pem.is_empty() {
            return Err(AwsNitroVerificationError::InvalidPolicy(
                "trusted_root_certificates_pem must not be empty".to_string(),
            ));
        }
        if self.max_document_age_seconds == 0 {
            return Err(AwsNitroVerificationError::InvalidPolicy(
                "max_document_age_seconds must be >= 1".to_string(),
            ));
        }
        if self.tier > RuntimeAssuranceTier::Attested {
            return Err(AwsNitroVerificationError::InvalidPolicy(
                "phase-70 verifier adapters must not widen runtime assurance above `attested` before policy v2 rebinding".to_string(),
            ));
        }
        for (index, pem) in self.trusted_root_certificates_pem.iter().enumerate() {
            if pem.trim().is_empty() {
                return Err(AwsNitroVerificationError::InvalidPolicy(format!(
                    "trusted_root_certificates_pem[{index}] must not be empty"
                )));
            }
        }
        for (pcr_index, hex_digest) in &self.expected_pcrs {
            let decoded = hex::decode(hex_digest).map_err(|error| {
                AwsNitroVerificationError::InvalidPolicy(format!(
                    "expected_pcrs[{pcr_index}] must be valid hex: {error}"
                ))
            })?;
            if decoded.len() != 48 {
                return Err(AwsNitroVerificationError::InvalidPolicy(format!(
                    "expected_pcrs[{pcr_index}] must be 48 bytes for SHA384"
                )));
            }
        }
        if let Some(nonce_hex) = self.expected_nonce_hex.as_deref() {
            let decoded = hex::decode(nonce_hex).map_err(|error| {
                AwsNitroVerificationError::InvalidPolicy(format!(
                    "expected_nonce_hex must be valid hex: {error}"
                ))
            })?;
            if decoded.is_empty() {
                return Err(AwsNitroVerificationError::InvalidPolicy(
                    "expected_nonce_hex must not be empty".to_string(),
                ));
            }
        }
        Ok(())
    }
}

fn default_aws_nitro_runtime_tier() -> RuntimeAssuranceTier {
    RuntimeAssuranceTier::Attested
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNitroVerifierAdapter {
    pub policy: AwsNitroVerificationPolicy,
}

impl AwsNitroVerifierAdapter {
    pub fn new(policy: AwsNitroVerificationPolicy) -> Result<Self, AwsNitroVerificationError> {
        policy.validate()?;
        Ok(Self { policy })
    }
}

impl RuntimeAttestationVerifierAdapter for AwsNitroVerifierAdapter {
    type Error = AwsNitroVerificationError;

    fn adapter_name(&self) -> &'static str {
        AWS_NITRO_VERIFIER_ADAPTER
    }

    fn verifier_family(&self) -> AttestationVerifierFamily {
        AttestationVerifierFamily::AwsNitro
    }

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error> {
        let verified_evidence =
            verify_aws_nitro_attestation_document(evidence.as_bytes(), &self.policy, now)?;
        let appraisal = appraise_aws_nitro_evidence(&verified_evidence);
        Ok(VerifiedRuntimeAttestation {
            evidence: verified_evidence,
            appraisal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleConfidentialVmVerifierAdapter {
    pub policy: GoogleConfidentialVmVerificationPolicy,
    pub jwks: GoogleConfidentialVmJwks,
}

impl GoogleConfidentialVmVerifierAdapter {
    pub fn new(
        policy: GoogleConfidentialVmVerificationPolicy,
        jwks: GoogleConfidentialVmJwks,
    ) -> Result<Self, GoogleConfidentialVmVerificationError> {
        policy.validate()?;
        Ok(Self { policy, jwks })
    }
}

impl RuntimeAttestationVerifierAdapter for GoogleConfidentialVmVerifierAdapter {
    type Error = GoogleConfidentialVmVerificationError;

    fn adapter_name(&self) -> &'static str {
        GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER
    }

    fn verifier_family(&self) -> AttestationVerifierFamily {
        AttestationVerifierFamily::GoogleAttestation
    }

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error> {
        let verified_evidence =
            verify_google_confidential_vm_attestation_jwt(evidence, &self.policy, &self.jwks, now)?;
        let appraisal = appraise_google_confidential_vm_evidence(&verified_evidence);
        Ok(VerifiedRuntimeAttestation {
            evidence: verified_evidence,
            appraisal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseVerifierVerificationPolicy {
    pub verifier: String,
    #[serde(default)]
    pub trusted_signer_keys: Vec<String>,
    pub max_evidence_age_seconds: u64,
    #[serde(default = "default_enterprise_verifier_runtime_tier")]
    pub tier: RuntimeAssuranceTier,
}

impl EnterpriseVerifierVerificationPolicy {
    pub fn validate(&self) -> Result<(), EnterpriseVerifierVerificationError> {
        if self.verifier.trim().is_empty() {
            return Err(EnterpriseVerifierVerificationError::InvalidPolicy(
                "verifier must not be empty".to_string(),
            ));
        }
        if self.trusted_signer_keys.is_empty() {
            return Err(EnterpriseVerifierVerificationError::InvalidPolicy(
                "trusted_signer_keys must not be empty".to_string(),
            ));
        }
        if self.max_evidence_age_seconds == 0 {
            return Err(EnterpriseVerifierVerificationError::InvalidPolicy(
                "max_evidence_age_seconds must be >= 1".to_string(),
            ));
        }
        if self.tier > RuntimeAssuranceTier::Attested {
            return Err(EnterpriseVerifierVerificationError::InvalidPolicy(
                "phase-108 verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
            ));
        }
        for (index, signer_key) in self.trusted_signer_keys.iter().enumerate() {
            if signer_key.trim().is_empty() {
                return Err(EnterpriseVerifierVerificationError::InvalidPolicy(format!(
                    "trusted_signer_keys[{index}] must not be empty"
                )));
            }
            PublicKey::from_hex(signer_key).map_err(|error| {
                EnterpriseVerifierVerificationError::InvalidPolicy(format!(
                    "trusted_signer_keys[{index}] must be valid ed25519 public keys: {error}"
                ))
            })?;
        }
        Ok(())
    }
}

fn default_enterprise_verifier_runtime_tier() -> RuntimeAssuranceTier {
    RuntimeAssuranceTier::Attested
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseVerifierAdapter {
    pub policy: EnterpriseVerifierVerificationPolicy,
}

impl EnterpriseVerifierAdapter {
    pub fn new(
        policy: EnterpriseVerifierVerificationPolicy,
    ) -> Result<Self, EnterpriseVerifierVerificationError> {
        policy.validate()?;
        Ok(Self { policy })
    }
}

impl RuntimeAttestationVerifierAdapter for EnterpriseVerifierAdapter {
    type Error = EnterpriseVerifierVerificationError;

    fn adapter_name(&self) -> &'static str {
        ENTERPRISE_VERIFIER_ADAPTER
    }

    fn verifier_family(&self) -> AttestationVerifierFamily {
        AttestationVerifierFamily::EnterpriseVerifier
    }

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error> {
        let signed_evidence: SignedExportEnvelope<RuntimeAttestationEvidence> =
            serde_json::from_str(evidence).map_err(|error| {
                EnterpriseVerifierVerificationError::InvalidEnvelope(error.to_string())
            })?;
        if !signed_evidence.verify_signature().map_err(|error| {
            EnterpriseVerifierVerificationError::InvalidEnvelope(error.to_string())
        })? {
            return Err(EnterpriseVerifierVerificationError::InvalidSignature);
        }
        let signer_key_hex = signed_evidence.signer_key.to_hex();
        if !self
            .policy
            .trusted_signer_keys
            .iter()
            .any(|allowed| allowed == &signer_key_hex)
        {
            return Err(EnterpriseVerifierVerificationError::UntrustedSigner {
                signer_key: signer_key_hex,
            });
        }

        let verified_evidence = signed_evidence.body;
        if verified_evidence.schema != ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA {
            return Err(EnterpriseVerifierVerificationError::UnsupportedSchema {
                actual: verified_evidence.schema.clone(),
            });
        }
        if verified_evidence.verifier != self.policy.verifier {
            return Err(EnterpriseVerifierVerificationError::VerifierMismatch {
                expected: self.policy.verifier.clone(),
                actual: verified_evidence.verifier.clone(),
            });
        }
        if !verified_evidence.is_valid_at(now) {
            return Err(EnterpriseVerifierVerificationError::EvidenceNotValid { now });
        }
        let age = now.saturating_sub(verified_evidence.issued_at);
        if age > self.policy.max_evidence_age_seconds {
            return Err(EnterpriseVerifierVerificationError::EvidenceTooOld {
                max_evidence_age_seconds: self.policy.max_evidence_age_seconds,
                actual_age_seconds: age,
            });
        }
        if verified_evidence.tier > self.policy.tier {
            return Err(EnterpriseVerifierVerificationError::TierTooHigh {
                actual: verified_evidence.tier,
                maximum: self.policy.tier,
            });
        }

        let appraisal =
            derive_runtime_attestation_appraisal(&verified_evidence).map_err(|error| {
                EnterpriseVerifierVerificationError::InvalidEvidence(error.to_string())
            })?;
        Ok(VerifiedRuntimeAttestation {
            evidence: verified_evidence,
            appraisal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureMaaVerificationPolicy {
    pub issuer: String,
    #[serde(default)]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default = "default_azure_maa_runtime_tier")]
    pub tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_claim_path: Option<String>,
}

impl AzureMaaVerificationPolicy {
    pub fn validate(&self) -> Result<(), AzureMaaVerificationError> {
        if self.issuer.trim().is_empty() {
            return Err(AzureMaaVerificationError::InvalidPolicy(
                "issuer must not be empty".to_string(),
            ));
        }
        if self.tier > RuntimeAssuranceTier::Attested {
            return Err(AzureMaaVerificationError::InvalidPolicy(
                "phase-58 verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
            ));
        }
        if let Some(path) = self.workload_claim_path.as_deref() {
            if path.trim().is_empty() {
                return Err(AzureMaaVerificationError::InvalidPolicy(
                    "workload_claim_path must not be empty when provided".to_string(),
                ));
            }
        }
        Ok(())
    }
}

fn default_azure_maa_runtime_tier() -> RuntimeAssuranceTier {
    RuntimeAssuranceTier::Attested
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureMaaJwks {
    #[serde(default)]
    pub keys: Vec<AzureMaaJwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureMaaJwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x5c: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureMaaOpenIdMetadata {
    pub issuer: String,
    pub jwks_uri: String,
}

pub type GoogleConfidentialVmJwks = AzureMaaJwks;
pub type GoogleConfidentialVmJwk = AzureMaaJwk;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleConfidentialVmOpenIdMetadata {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleConfidentialVmVerificationPolicy {
    pub issuer: String,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    #[serde(default)]
    pub allowed_service_accounts: Vec<String>,
    #[serde(default)]
    pub allowed_hardware_models: Vec<String>,
    #[serde(default = "default_google_confidential_vm_runtime_tier")]
    pub tier: RuntimeAssuranceTier,
    #[serde(default)]
    pub require_secure_boot: bool,
}

impl GoogleConfidentialVmVerificationPolicy {
    pub fn validate(&self) -> Result<(), GoogleConfidentialVmVerificationError> {
        if self.issuer.trim().is_empty() {
            return Err(GoogleConfidentialVmVerificationError::InvalidPolicy(
                "issuer must not be empty".to_string(),
            ));
        }
        if self.tier > RuntimeAssuranceTier::Attested {
            return Err(GoogleConfidentialVmVerificationError::InvalidPolicy(
                "phase-71 verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
            ));
        }
        for (index, audience) in self.allowed_audiences.iter().enumerate() {
            if audience.trim().is_empty() {
                return Err(GoogleConfidentialVmVerificationError::InvalidPolicy(
                    format!("allowed_audiences[{index}] must not be empty"),
                ));
            }
        }
        for (index, account) in self.allowed_service_accounts.iter().enumerate() {
            if account.trim().is_empty() {
                return Err(GoogleConfidentialVmVerificationError::InvalidPolicy(
                    format!("allowed_service_accounts[{index}] must not be empty"),
                ));
            }
        }
        for (index, model) in self.allowed_hardware_models.iter().enumerate() {
            if model.trim().is_empty() {
                return Err(GoogleConfidentialVmVerificationError::InvalidPolicy(
                    format!("allowed_hardware_models[{index}] must not be empty"),
                ));
            }
        }
        Ok(())
    }
}

fn default_google_confidential_vm_runtime_tier() -> RuntimeAssuranceTier {
    RuntimeAssuranceTier::Attested
}

#[derive(Debug, thiserror::Error)]
pub enum AzureMaaVerificationError {
    #[error("Azure MAA verification policy is invalid: {0}")]
    InvalidPolicy(String),

    #[error("invalid Azure MAA JWT: {0}")]
    InvalidJwt(&'static str),

    #[error("unsupported Azure MAA JWT algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("Azure MAA signing key is not trusted")]
    UntrustedSigningKey,

    #[error("Azure MAA JWT signing key does not support algorithm `{0}`")]
    KeyAlgorithmMismatch(String),

    #[error("failed to decode Azure MAA JWK component `{component}`: {error}")]
    InvalidJwkComponent {
        component: &'static str,
        error: String,
    },

    #[error("failed to parse Azure MAA RSA key: {0}")]
    InvalidRsaKey(String),

    #[error("failed to parse Azure MAA certificate chain: {0}")]
    InvalidCertificate(String),

    #[error("Azure MAA JWT signature verification failed")]
    InvalidSignature,

    #[error("Azure MAA issuer `{actual}` did not match expected `{expected}`")]
    IssuerMismatch { expected: String, actual: String },

    #[error("Azure MAA token is not valid at {now}")]
    TokenNotValid { now: u64 },

    #[error("Azure MAA token missing required claim `{0}`")]
    MissingClaim(&'static str),

    #[error("Azure MAA attestation type `{actual}` is not allowed")]
    DisallowedAttestationType { actual: String },

    #[error("Azure MAA workload claim path `{0}` did not resolve to a string")]
    InvalidWorkloadClaim(String),

    #[error("Azure MAA workload identity is invalid: {0}")]
    InvalidWorkloadIdentity(String),

    #[error("failed to fetch Azure MAA metadata `{url}`: {error}")]
    MetadataFetch { url: String, error: String },

    #[error("failed to parse Azure MAA metadata `{url}`: {error}")]
    MetadataParse { url: String, error: String },
}

#[derive(Debug, thiserror::Error)]
pub enum EnterpriseVerifierVerificationError {
    #[error("enterprise verifier policy is invalid: {0}")]
    InvalidPolicy(String),

    #[error("enterprise verifier evidence envelope is invalid: {0}")]
    InvalidEnvelope(String),

    #[error("enterprise verifier evidence signature is invalid")]
    InvalidSignature,

    #[error("enterprise verifier signer `{signer_key}` is not trusted")]
    UntrustedSigner { signer_key: String },

    #[error("enterprise verifier evidence schema `{actual}` is unsupported")]
    UnsupportedSchema { actual: String },

    #[error("enterprise verifier mismatch: expected `{expected}`, got `{actual}`")]
    VerifierMismatch { expected: String, actual: String },

    #[error("enterprise verifier evidence is not valid at {now}")]
    EvidenceNotValid { now: u64 },

    #[error("enterprise verifier evidence age {actual_age_seconds}s exceeds {max_evidence_age_seconds}s")]
    EvidenceTooOld {
        max_evidence_age_seconds: u64,
        actual_age_seconds: u64,
    },

    #[error("enterprise verifier evidence tier {actual:?} exceeds configured maximum {maximum:?}")]
    TierTooHigh {
        actual: RuntimeAssuranceTier,
        maximum: RuntimeAssuranceTier,
    },

    #[error(
        "enterprise verifier evidence could not be appraised on the shared Chio substrate: {0}"
    )]
    InvalidEvidence(String),
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleConfidentialVmVerificationError {
    #[error("Google Confidential VM verification policy is invalid: {0}")]
    InvalidPolicy(String),

    #[error("invalid Google Confidential VM JWT: {0}")]
    InvalidJwt(&'static str),

    #[error("unsupported Google Confidential VM JWT algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("Google Confidential VM signing key is not trusted")]
    UntrustedSigningKey,

    #[error("Google Confidential VM JWT signing key does not support algorithm `{0}`")]
    KeyAlgorithmMismatch(String),

    #[error("failed to decode Google Confidential VM JWK component `{component}`: {error}")]
    InvalidJwkComponent {
        component: &'static str,
        error: String,
    },

    #[error("failed to parse Google Confidential VM RSA key: {0}")]
    InvalidRsaKey(String),

    #[error("failed to parse Google Confidential VM certificate chain: {0}")]
    InvalidCertificate(String),

    #[error("Google Confidential VM JWT signature verification failed")]
    InvalidSignature,

    #[error("Google Confidential VM issuer `{actual}` did not match expected `{expected}`")]
    IssuerMismatch { expected: String, actual: String },

    #[error("Google Confidential VM token audience did not match the configured audiences")]
    AudienceMismatch,

    #[error("Google Confidential VM token is not valid at {now}")]
    TokenNotValid { now: u64 },

    #[error("Google Confidential VM token missing required claim `{0}`")]
    MissingClaim(&'static str),

    #[error("Google Confidential VM hardware model `{actual}` is not allowed")]
    DisallowedHardwareModel { actual: String },

    #[error("Google Confidential VM secure boot is required")]
    InsecureBoot,

    #[error("Google Confidential VM service account `{actual}` is not allowed")]
    DisallowedServiceAccount { actual: String },

    #[error("failed to fetch Google Confidential VM metadata `{url}`: {error}")]
    MetadataFetch { url: String, error: String },

    #[error("failed to parse Google Confidential VM metadata `{url}`: {error}")]
    MetadataParse { url: String, error: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AwsNitroVerificationError {
    #[error("AWS Nitro verification policy is invalid: {0}")]
    InvalidPolicy(String),

    #[error("invalid AWS Nitro COSE document: {0}")]
    InvalidCose(&'static str),

    #[error("unsupported AWS Nitro COSE algorithm `{0}`")]
    UnsupportedAlgorithm(i64),

    #[error("AWS Nitro attestation document missing field `{0}`")]
    MissingField(&'static str),

    #[error("AWS Nitro attestation field `{0}` is invalid")]
    InvalidField(&'static str),

    #[error("AWS Nitro digest `{0}` is not supported")]
    UnsupportedDigest(String),

    #[error("AWS Nitro attestation signature verification failed")]
    InvalidSignature,

    #[error("failed to parse AWS Nitro certificate: {0}")]
    InvalidCertificate(String),

    #[error("AWS Nitro certificate chain is invalid: {0}")]
    InvalidCertificateChain(String),

    #[error("AWS Nitro certificate is not valid at {now}")]
    CertificateNotValid { now: u64 },

    #[error("AWS Nitro attestation document is stale at {now} (timestamp={timestamp}, max_age_seconds={max_age_seconds})")]
    StaleDocument {
        now: u64,
        timestamp: u64,
        max_age_seconds: u64,
    },

    #[error(
        "AWS Nitro attestation document timestamp {timestamp} is in the future relative to {now}"
    )]
    FutureDocument { now: u64, timestamp: u64 },

    #[error("AWS Nitro attestation document nonce did not match the expected nonce")]
    NonceMismatch,

    #[error("AWS Nitro attestation document is missing PCR {index}")]
    MissingPcr { index: u8 },

    #[error("AWS Nitro attestation document PCR {index} did not match the expected measurement")]
    PcrMismatch { index: u8 },

    #[error(
        "AWS Nitro attestation document appears to be debug-mode evidence and policy forbids it"
    )]
    DebugModeEvidence,

    #[error("AWS Nitro public key could not be parsed: {0}")]
    InvalidPublicKey(String),
}

#[derive(Debug, Deserialize)]
struct AwsNitroCoseSign1(Vec<u8>, BTreeMap<i64, CborValue>, Vec<u8>, Vec<u8>);

#[derive(Debug, Deserialize)]
struct AwsNitroAttestationDocument {
    module_id: String,
    timestamp: u64,
    digest: String,
    pcrs: BTreeMap<u8, Vec<u8>>,
    certificate: Vec<u8>,
    #[serde(default)]
    cabundle: Vec<Vec<u8>>,
    #[serde(default)]
    public_key: Option<Vec<u8>>,
    #[serde(default)]
    user_data: Option<Vec<u8>>,
    #[serde(default)]
    nonce: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct OidcJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum OidcJwtDecodeError {
    #[error("invalid JWT: {0}")]
    InvalidJwt(&'static str),
}

#[derive(Debug, thiserror::Error)]
enum OidcRsaKeyResolveError {
    #[error("signing key is not trusted")]
    UntrustedSigningKey,

    #[error("JWT signing key does not support algorithm `{0}`")]
    KeyAlgorithmMismatch(String),

    #[error("failed to decode JWK component `{component}`: {error}")]
    InvalidJwkComponent {
        component: &'static str,
        error: String,
    },

    #[error("failed to parse RSA key: {0}")]
    InvalidRsaKey(String),

    #[error("failed to parse certificate chain: {0}")]
    InvalidCertificate(String),
}

#[derive(Debug, Deserialize)]
struct AzureMaaJwtClaims {
    iss: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(default)]
    jti: Option<String>,
    #[serde(rename = "x-ms-ver")]
    version: String,
    #[serde(rename = "x-ms-attestation-type")]
    attestation_type: String,
    #[serde(default, rename = "x-ms-policy-hash")]
    policy_hash: Option<String>,
    #[serde(default, rename = "x-ms-runtime")]
    runtime: Option<Value>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct GoogleConfidentialVmJwtClaims {
    iss: String,
    sub: String,
    aud: Value,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(default, rename = "secboot")]
    secure_boot: Option<bool>,
    #[serde(default, rename = "hwmodel")]
    hardware_model: Option<String>,
    #[serde(default, rename = "swname")]
    software_name: Option<String>,
    #[serde(default, rename = "eat_nonce")]
    nonce: Option<String>,
    #[serde(default)]
    google_service_accounts: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AzureMaaJwtAlgorithm {
    Rs256,
    Ps256,
}

impl AzureMaaJwtAlgorithm {
    fn parse(value: &str) -> Result<Self, AzureMaaVerificationError> {
        match value {
            "RS256" => Ok(Self::Rs256),
            "PS256" => Ok(Self::Ps256),
            other => Err(AzureMaaVerificationError::UnsupportedAlgorithm(
                other.to_string(),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
        }
    }
}

#[derive(Debug, Clone)]
struct AzureMaaResolvedJwk {
    key: RsaPublicKey,
    alg_hint: Option<String>,
}

impl AzureMaaResolvedJwk {
    fn supports_alg(&self, alg: AzureMaaJwtAlgorithm) -> bool {
        self.alg_hint
            .as_deref()
            .is_none_or(|hint| hint == alg.as_str())
    }

    fn verify(&self, alg: AzureMaaJwtAlgorithm, signed_input: &[u8], signature: &[u8]) -> bool {
        match alg {
            AzureMaaJwtAlgorithm::Rs256 => RsaPkcs1v15Signature::try_from(signature)
                .ok()
                .and_then(|signature| {
                    RsaPkcs1v15VerifyingKey::<Sha256>::new(self.key.clone())
                        .verify(signed_input, &signature)
                        .ok()
                })
                .is_some(),
            AzureMaaJwtAlgorithm::Ps256 => RsaPssSignature::try_from(signature)
                .ok()
                .and_then(|signature| {
                    RsaPssVerifyingKey::<Sha256>::new(self.key.clone())
                        .verify(signed_input, &signature)
                        .ok()
                })
                .is_some(),
        }
    }
}

impl From<OidcJwtDecodeError> for AzureMaaVerificationError {
    fn from(value: OidcJwtDecodeError) -> Self {
        match value {
            OidcJwtDecodeError::InvalidJwt(message) => Self::InvalidJwt(message),
        }
    }
}

impl From<OidcRsaKeyResolveError> for AzureMaaVerificationError {
    fn from(value: OidcRsaKeyResolveError) -> Self {
        match value {
            OidcRsaKeyResolveError::UntrustedSigningKey => Self::UntrustedSigningKey,
            OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg) => Self::KeyAlgorithmMismatch(alg),
            OidcRsaKeyResolveError::InvalidJwkComponent { component, error } => {
                Self::InvalidJwkComponent { component, error }
            }
            OidcRsaKeyResolveError::InvalidRsaKey(error) => Self::InvalidRsaKey(error),
            OidcRsaKeyResolveError::InvalidCertificate(error) => Self::InvalidCertificate(error),
        }
    }
}

impl From<OidcJwtDecodeError> for GoogleConfidentialVmVerificationError {
    fn from(value: OidcJwtDecodeError) -> Self {
        match value {
            OidcJwtDecodeError::InvalidJwt(message) => Self::InvalidJwt(message),
        }
    }
}

impl From<OidcRsaKeyResolveError> for GoogleConfidentialVmVerificationError {
    fn from(value: OidcRsaKeyResolveError) -> Self {
        match value {
            OidcRsaKeyResolveError::UntrustedSigningKey => Self::UntrustedSigningKey,
            OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg) => Self::KeyAlgorithmMismatch(alg),
            OidcRsaKeyResolveError::InvalidJwkComponent { component, error } => {
                Self::InvalidJwkComponent { component, error }
            }
            OidcRsaKeyResolveError::InvalidRsaKey(error) => Self::InvalidRsaKey(error),
            OidcRsaKeyResolveError::InvalidCertificate(error) => Self::InvalidCertificate(error),
        }
    }
}

pub fn fetch_azure_maa_openid_metadata(
    metadata_url: &str,
) -> Result<AzureMaaOpenIdMetadata, AzureMaaVerificationError> {
    let response = ureq::get(metadata_url).call().map_err(|error| {
        AzureMaaVerificationError::MetadataFetch {
            url: metadata_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<AzureMaaOpenIdMetadata>()
        .map_err(|error| AzureMaaVerificationError::MetadataParse {
            url: metadata_url.to_string(),
            error: error.to_string(),
        })
}

pub fn fetch_azure_maa_jwks(jwks_url: &str) -> Result<AzureMaaJwks, AzureMaaVerificationError> {
    let response =
        ureq::get(jwks_url)
            .call()
            .map_err(|error| AzureMaaVerificationError::MetadataFetch {
                url: jwks_url.to_string(),
                error: error.to_string(),
            })?;
    response
        .into_json::<AzureMaaJwks>()
        .map_err(|error| AzureMaaVerificationError::MetadataParse {
            url: jwks_url.to_string(),
            error: error.to_string(),
        })
}

pub fn fetch_google_confidential_vm_openid_metadata(
    metadata_url: &str,
) -> Result<GoogleConfidentialVmOpenIdMetadata, GoogleConfidentialVmVerificationError> {
    let response = ureq::get(metadata_url).call().map_err(|error| {
        GoogleConfidentialVmVerificationError::MetadataFetch {
            url: metadata_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<GoogleConfidentialVmOpenIdMetadata>()
        .map_err(
            |error| GoogleConfidentialVmVerificationError::MetadataParse {
                url: metadata_url.to_string(),
                error: error.to_string(),
            },
        )
}

pub fn fetch_google_confidential_vm_jwks(
    jwks_url: &str,
) -> Result<GoogleConfidentialVmJwks, GoogleConfidentialVmVerificationError> {
    let response = ureq::get(jwks_url).call().map_err(|error| {
        GoogleConfidentialVmVerificationError::MetadataFetch {
            url: jwks_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<GoogleConfidentialVmJwks>()
        .map_err(
            |error| GoogleConfidentialVmVerificationError::MetadataParse {
                url: jwks_url.to_string(),
                error: error.to_string(),
            },
        )
}

pub fn verify_azure_maa_attestation_jwt(
    token: &str,
    policy: &AzureMaaVerificationPolicy,
    jwks: &AzureMaaJwks,
    now: u64,
) -> Result<RuntimeAttestationEvidence, AzureMaaVerificationError> {
    policy.validate()?;
    let (header, claims, signed_input, signature): (
        OidcJwtHeader,
        AzureMaaJwtClaims,
        String,
        Vec<u8>,
    ) = decode_jwt_parts(token)?;
    let algorithm = AzureMaaJwtAlgorithm::parse(&header.alg)?;
    let key = resolve_signing_key(jwks, header.kid.as_deref(), algorithm)?;
    if !key.verify(algorithm, signed_input.as_bytes(), &signature) {
        return Err(AzureMaaVerificationError::InvalidSignature);
    }

    let expected_issuer = canonicalize_issuer(&policy.issuer);
    let actual_issuer = canonicalize_issuer(&claims.iss);
    if actual_issuer != expected_issuer {
        return Err(AzureMaaVerificationError::IssuerMismatch {
            expected: expected_issuer,
            actual: actual_issuer,
        });
    }

    if now < claims.nbf || now >= claims.exp {
        return Err(AzureMaaVerificationError::TokenNotValid { now });
    }
    if claims.version.trim().is_empty() {
        return Err(AzureMaaVerificationError::MissingClaim("x-ms-ver"));
    }
    if claims.attestation_type.trim().is_empty() {
        return Err(AzureMaaVerificationError::MissingClaim(
            "x-ms-attestation-type",
        ));
    }
    if !policy.allowed_attestation_types.is_empty()
        && !policy
            .allowed_attestation_types
            .iter()
            .any(|allowed| allowed == &claims.attestation_type)
    {
        return Err(AzureMaaVerificationError::DisallowedAttestationType {
            actual: claims.attestation_type.clone(),
        });
    }

    let (runtime_identity, workload_identity) = resolve_workload_identity(
        claims.runtime.as_ref(),
        policy.workload_claim_path.as_deref(),
    )?;

    Ok(RuntimeAttestationEvidence {
        schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        verifier: expected_issuer,
        tier: policy.tier,
        issued_at: claims.iat,
        expires_at: claims.exp,
        evidence_sha256: sha256_hex(token.as_bytes()),
        runtime_identity,
        workload_identity,
        claims: Some(json!({
            "azureMaa": build_vendor_claims(&header, &claims)
        })),
    })
}

#[must_use]
pub fn appraise_azure_maa_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    let mut normalized_assertions = BTreeMap::new();
    let vendor_claims = extract_vendor_claims(evidence, "azureMaa");

    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized_assertions.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized_assertions.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    if let Some(workload_identity) = evidence.workload_identity.as_ref() {
        normalized_assertions.insert(
            "workloadIdentityScheme".to_string(),
            Value::String(format!("{:?}", workload_identity.scheme).to_lowercase()),
        );
        normalized_assertions.insert(
            "workloadIdentityUri".to_string(),
            Value::String(workload_identity.uri.clone()),
        );
    }

    let reason_codes = if evidence.schema == AZURE_MAA_ATTESTATION_SCHEMA {
        vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
    } else {
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    };

    if evidence.schema == AZURE_MAA_ATTESTATION_SCHEMA {
        RuntimeAttestationAppraisal::accepted(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    } else {
        RuntimeAttestationAppraisal::rejected(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    }
}

pub fn verify_google_confidential_vm_attestation_jwt(
    token: &str,
    policy: &GoogleConfidentialVmVerificationPolicy,
    jwks: &GoogleConfidentialVmJwks,
    now: u64,
) -> Result<RuntimeAttestationEvidence, GoogleConfidentialVmVerificationError> {
    policy.validate()?;
    let (header, claims, signed_input, signature): (
        OidcJwtHeader,
        GoogleConfidentialVmJwtClaims,
        String,
        Vec<u8>,
    ) = decode_jwt_parts(token)?;
    let algorithm = match header.alg.as_str() {
        "RS256" => AzureMaaJwtAlgorithm::Rs256,
        other => {
            return Err(GoogleConfidentialVmVerificationError::UnsupportedAlgorithm(
                other.to_string(),
            ))
        }
    };
    let key = resolve_signing_key(jwks, header.kid.as_deref(), algorithm)?;
    if !key.verify(algorithm, signed_input.as_bytes(), &signature) {
        return Err(GoogleConfidentialVmVerificationError::InvalidSignature);
    }

    let expected_issuer = canonicalize_issuer(&policy.issuer);
    let actual_issuer = canonicalize_issuer(&claims.iss);
    if actual_issuer != expected_issuer {
        return Err(GoogleConfidentialVmVerificationError::IssuerMismatch {
            expected: expected_issuer,
            actual: actual_issuer,
        });
    }
    if now < claims.nbf || now >= claims.exp {
        return Err(GoogleConfidentialVmVerificationError::TokenNotValid { now });
    }
    if claims.sub.trim().is_empty() {
        return Err(GoogleConfidentialVmVerificationError::MissingClaim("sub"));
    }
    let audiences = google_token_audiences(&claims.aud)?;
    if !policy.allowed_audiences.is_empty()
        && !audiences.iter().any(|audience| {
            policy
                .allowed_audiences
                .iter()
                .any(|allowed| allowed == audience)
        })
    {
        return Err(GoogleConfidentialVmVerificationError::AudienceMismatch);
    }
    let hardware_model = claims
        .hardware_model
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(GoogleConfidentialVmVerificationError::MissingClaim(
            "hwmodel",
        ))?;
    if !policy.allowed_hardware_models.is_empty()
        && !policy
            .allowed_hardware_models
            .iter()
            .any(|allowed| allowed == hardware_model)
    {
        return Err(
            GoogleConfidentialVmVerificationError::DisallowedHardwareModel {
                actual: hardware_model.to_string(),
            },
        );
    }
    if policy.require_secure_boot && claims.secure_boot != Some(true) {
        return Err(GoogleConfidentialVmVerificationError::InsecureBoot);
    }
    if !policy.allowed_service_accounts.is_empty() {
        let actual = claims
            .google_service_accounts
            .iter()
            .find(|account| {
                policy
                    .allowed_service_accounts
                    .iter()
                    .any(|allowed| allowed == *account)
            })
            .cloned();
        if actual.is_none() {
            return Err(
                GoogleConfidentialVmVerificationError::DisallowedServiceAccount {
                    actual: claims
                        .google_service_accounts
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "<none>".to_string()),
                },
            );
        }
    }

    Ok(RuntimeAttestationEvidence {
        schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
        verifier: expected_issuer,
        tier: policy.tier,
        issued_at: claims.iat,
        expires_at: claims.exp,
        evidence_sha256: sha256_hex(token.as_bytes()),
        runtime_identity: Some(claims.sub.clone()),
        workload_identity: None,
        claims: Some(json!({
            "googleAttestation": build_google_confidential_vm_vendor_claims(&header, &claims, audiences)
        })),
    })
}

#[must_use]
pub fn appraise_google_confidential_vm_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    derive_runtime_attestation_appraisal(evidence).unwrap_or_else(|_| {
        RuntimeAttestationAppraisal::rejected(
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
            AttestationVerifierFamily::GoogleAttestation,
            evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence],
        )
    })
}

pub fn verify_aws_nitro_attestation_document(
    document: &[u8],
    policy: &AwsNitroVerificationPolicy,
    now: u64,
) -> Result<RuntimeAttestationEvidence, AwsNitroVerificationError> {
    policy.validate()?;

    let AwsNitroCoseSign1(protected, _unprotected, payload, signature) =
        cbor_from_reader(Cursor::new(document))
            .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid COSE_Sign1 encoding"))?;
    let protected_headers = decode_cose_protected_headers(&protected)?;
    let algorithm = protected_headers
        .get(&COSE_HEADER_ALGORITHM_KEY)
        .and_then(cbor_integer_to_i64)
        .ok_or(AwsNitroVerificationError::MissingField("protected.alg"))?;
    if algorithm != COSE_ES384_ALGORITHM {
        return Err(AwsNitroVerificationError::UnsupportedAlgorithm(algorithm));
    }

    let payload_doc: AwsNitroAttestationDocument = cbor_from_reader(Cursor::new(&payload))
        .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid attestation payload"))?;
    validate_aws_nitro_document(&payload_doc, policy, now)?;

    let signing_cert = decode_certificate_der(&payload_doc.certificate)?;
    validate_certificate_chain(
        &signing_cert,
        &payload_doc.cabundle,
        &policy.trusted_root_certificates_pem,
        now,
    )?;

    let sig_structure = build_cose_sign1_sig_structure(&protected, &payload)?;
    verify_p384_cose_signature(&signing_cert, &signature, &sig_structure)?;

    Ok(RuntimeAttestationEvidence {
        schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
        verifier: "aws-nitro".to_string(),
        tier: policy.tier,
        issued_at: payload_doc.timestamp / 1000,
        expires_at: payload_doc.timestamp / 1000 + policy.max_document_age_seconds,
        evidence_sha256: sha256_hex(document),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(json!({
            "awsNitro": build_aws_nitro_vendor_claims(&payload_doc, &signing_cert)
        })),
    })
}

#[must_use]
pub fn appraise_aws_nitro_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    let vendor_claims = extract_vendor_claims(evidence, "awsNitro");
    let mut normalized_assertions = BTreeMap::new();
    if let Some(module_id) = vendor_claims.get("moduleId") {
        normalized_assertions.insert("moduleId".to_string(), module_id.clone());
    }
    if let Some(digest) = vendor_claims.get("digest") {
        normalized_assertions.insert("digest".to_string(), digest.clone());
    }
    if let Some(pcrs) = vendor_claims.get("pcrs") {
        normalized_assertions.insert("pcrs".to_string(), pcrs.clone());
    }

    let reason_codes = if evidence.schema == AWS_NITRO_ATTESTATION_SCHEMA {
        vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
    } else {
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    };

    if evidence.schema == AWS_NITRO_ATTESTATION_SCHEMA {
        RuntimeAttestationAppraisal::accepted(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    } else {
        RuntimeAttestationAppraisal::rejected(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    }
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

fn decode_cose_protected_headers(
    protected: &[u8],
) -> Result<BTreeMap<i64, CborValue>, AwsNitroVerificationError> {
    if protected.is_empty() {
        return Ok(BTreeMap::new());
    }
    cbor_from_reader(Cursor::new(protected))
        .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid protected header map"))
}

fn cbor_integer_to_i64(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Integer(value) => cbor_integer_to_i64_inner(*value),
        _ => None,
    }
}

fn cbor_integer_to_i64_inner(value: CborInteger) -> Option<i64> {
    i128::from(value).try_into().ok()
}

fn validate_aws_nitro_document(
    document: &AwsNitroAttestationDocument,
    policy: &AwsNitroVerificationPolicy,
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    if document.module_id.trim().is_empty() {
        return Err(AwsNitroVerificationError::MissingField("module_id"));
    }
    if document.certificate.is_empty() {
        return Err(AwsNitroVerificationError::MissingField("certificate"));
    }
    match document.digest.as_str() {
        "SHA384" => {}
        other => {
            return Err(AwsNitroVerificationError::UnsupportedDigest(
                other.to_string(),
            ))
        }
    }

    let issued_at = document.timestamp / 1000;
    if now < issued_at {
        return Err(AwsNitroVerificationError::FutureDocument {
            now,
            timestamp: document.timestamp,
        });
    }
    if now - issued_at > policy.max_document_age_seconds {
        return Err(AwsNitroVerificationError::StaleDocument {
            now,
            timestamp: document.timestamp,
            max_age_seconds: policy.max_document_age_seconds,
        });
    }

    if document.pcrs.is_empty() {
        return Err(AwsNitroVerificationError::MissingField("pcrs"));
    }
    let mut all_zero = true;
    for pcr in document.pcrs.values() {
        if pcr.len() != 48 {
            return Err(AwsNitroVerificationError::InvalidField("pcrs"));
        }
        if pcr.iter().any(|byte| *byte != 0) {
            all_zero = false;
        }
    }
    if all_zero && !policy.allow_debug_mode {
        return Err(AwsNitroVerificationError::DebugModeEvidence);
    }

    for (index, expected_hex) in &policy.expected_pcrs {
        let actual = document
            .pcrs
            .get(index)
            .ok_or(AwsNitroVerificationError::MissingPcr { index: *index })?;
        let expected = hex::decode(expected_hex)
            .map_err(|_| AwsNitroVerificationError::InvalidField("expected_pcrs"))?;
        if *actual != expected {
            return Err(AwsNitroVerificationError::PcrMismatch { index: *index });
        }
    }

    if let Some(expected_nonce_hex) = policy.expected_nonce_hex.as_deref() {
        let actual = document
            .nonce
            .as_ref()
            .ok_or(AwsNitroVerificationError::MissingField("nonce"))?;
        let expected = hex::decode(expected_nonce_hex)
            .map_err(|_| AwsNitroVerificationError::InvalidField("expected_nonce_hex"))?;
        if *actual != expected {
            return Err(AwsNitroVerificationError::NonceMismatch);
        }
    }

    Ok(())
}

fn build_cose_sign1_sig_structure(
    protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, AwsNitroVerificationError> {
    let structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut bytes = Vec::new();
    cbor_into_writer(&structure, &mut bytes)
        .map_err(|_| AwsNitroVerificationError::InvalidCose("failed to encode Sig_structure"))?;
    Ok(bytes)
}

fn verify_p384_cose_signature(
    signing_cert: &Certificate,
    signature: &[u8],
    sig_structure: &[u8],
) -> Result<(), AwsNitroVerificationError> {
    let verifying_key = p384_verifying_key_from_cert(signing_cert)?;
    let parsed = parse_p384_signature(signature)?;
    verifying_key
        .verify(sig_structure, &parsed)
        .map_err(|_| AwsNitroVerificationError::InvalidSignature)
}

fn validate_certificate_chain(
    signing_cert: &Certificate,
    cabundle: &[Vec<u8>],
    trusted_roots_pem: &[String],
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    ensure_certificate_valid_at(signing_cert, now)?;
    let chain = cabundle
        .iter()
        .map(|cert| decode_certificate_der(cert))
        .collect::<Result<Vec<_>, _>>()?;

    let mut current = signing_cert;
    for issuer in chain.iter().rev() {
        ensure_certificate_valid_at(issuer, now)?;
        verify_certificate_issued_by(current, issuer)?;
        current = issuer;
    }

    let trusted_roots = trusted_roots_pem
        .iter()
        .map(|pem| {
            Certificate::from_pem(pem)
                .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let anchored = trusted_roots.iter().any(|root| {
        certificates_match(current, root) || verify_certificate_issued_by(current, root).is_ok()
    });
    if !anchored {
        return Err(AwsNitroVerificationError::InvalidCertificateChain(
            "certificate chain did not anchor in a trusted Nitro root".to_string(),
        ));
    }
    Ok(())
}

fn decode_certificate_der(bytes: &[u8]) -> Result<Certificate, AwsNitroVerificationError> {
    Certificate::from_der(bytes)
        .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))
}

fn ensure_certificate_valid_at(
    certificate: &Certificate,
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    let now_duration = Duration::from_secs(now);
    let validity = certificate.tbs_certificate.validity;
    if validity.not_before.to_unix_duration() > now_duration
        || validity.not_after.to_unix_duration() < now_duration
    {
        return Err(AwsNitroVerificationError::CertificateNotValid { now });
    }
    Ok(())
}

fn verify_certificate_issued_by(
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<(), AwsNitroVerificationError> {
    if certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(AwsNitroVerificationError::InvalidCertificateChain(
            "certificate issuer did not match issuer subject".to_string(),
        ));
    }
    let issuer_key = p384_verifying_key_from_cert(issuer)?;
    let signature = parse_p384_signature(certificate.signature.raw_bytes())?;
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))?;
    issuer_key.verify(&tbs, &signature).map_err(|_| {
        AwsNitroVerificationError::InvalidCertificateChain(
            "certificate signature did not verify".to_string(),
        )
    })
}

fn certificates_match(left: &Certificate, right: &Certificate) -> bool {
    left.tbs_certificate.subject == right.tbs_certificate.subject
        && left
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            == right
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
}

fn p384_verifying_key_from_cert(
    certificate: &Certificate,
) -> Result<P384VerifyingKey, AwsNitroVerificationError> {
    P384VerifyingKey::from_sec1_bytes(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .map_err(|error| AwsNitroVerificationError::InvalidPublicKey(error.to_string()))
}

fn parse_p384_signature(signature: &[u8]) -> Result<P384Signature, AwsNitroVerificationError> {
    P384Signature::from_slice(signature)
        .or_else(|_| P384Signature::from_der(signature))
        .map_err(|_| AwsNitroVerificationError::InvalidSignature)
}

fn build_aws_nitro_vendor_claims(
    document: &AwsNitroAttestationDocument,
    signing_cert: &Certificate,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert(
        "moduleId".to_string(),
        Value::String(document.module_id.clone()),
    );
    vendor.insert("timestampMs".to_string(), Value::from(document.timestamp));
    vendor.insert("digest".to_string(), Value::String(document.digest.clone()));
    vendor.insert(
        "pcrs".to_string(),
        Value::Object(
            document
                .pcrs
                .iter()
                .map(|(index, value)| (index.to_string(), Value::String(hex::encode(value))))
                .collect(),
        ),
    );
    vendor.insert(
        "certificateSha256".to_string(),
        Value::String(sha256_hex(
            &signing_cert
                .to_der()
                .unwrap_or_else(|_| document.certificate.clone()),
        )),
    );
    if let Some(public_key) = document.public_key.as_ref() {
        vendor.insert(
            "publicKeySha256".to_string(),
            Value::String(sha256_hex(public_key)),
        );
    }
    if let Some(user_data) = document.user_data.as_ref() {
        vendor.insert(
            "userDataSha256".to_string(),
            Value::String(sha256_hex(user_data)),
        );
    }
    if let Some(nonce) = document.nonce.as_ref() {
        vendor.insert("nonce".to_string(), Value::String(hex::encode(nonce)));
    }
    vendor
}

fn build_vendor_claims(
    header: &OidcJwtHeader,
    claims: &AzureMaaJwtClaims,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert("version".to_string(), Value::String(claims.version.clone()));
    vendor.insert(
        "attestationType".to_string(),
        Value::String(claims.attestation_type.clone()),
    );
    vendor.insert("issuedAt".to_string(), Value::from(claims.iat));
    vendor.insert("notBefore".to_string(), Value::from(claims.nbf));
    vendor.insert("expiresAt".to_string(), Value::from(claims.exp));
    if let Some(policy_hash) = claims.policy_hash.as_ref() {
        vendor.insert("policyHash".to_string(), Value::String(policy_hash.clone()));
    }
    if let Some(token_id) = claims.jti.as_ref() {
        vendor.insert("tokenId".to_string(), Value::String(token_id.clone()));
    }
    if let Some(kid) = header.kid.as_ref() {
        vendor.insert("signingKeyId".to_string(), Value::String(kid.clone()));
    }
    if let Some(runtime) = claims.runtime.as_ref() {
        vendor.insert("runtime".to_string(), runtime.clone());
    }
    for (key, value) in &claims.extra {
        vendor.insert(key.clone(), value.clone());
    }
    vendor
}

fn build_google_confidential_vm_vendor_claims(
    header: &OidcJwtHeader,
    claims: &GoogleConfidentialVmJwtClaims,
    audiences: Vec<String>,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert(
        "attestationType".to_string(),
        Value::String("confidential_vm".to_string()),
    );
    vendor.insert("issuedAt".to_string(), Value::from(claims.iat));
    vendor.insert("notBefore".to_string(), Value::from(claims.nbf));
    vendor.insert("expiresAt".to_string(), Value::from(claims.exp));
    vendor.insert("subject".to_string(), Value::String(claims.sub.clone()));
    vendor.insert(
        "audiences".to_string(),
        Value::Array(audiences.into_iter().map(Value::String).collect()),
    );
    if let Some(hardware_model) = claims.hardware_model.as_ref() {
        vendor.insert(
            "hardwareModel".to_string(),
            Value::String(hardware_model.clone()),
        );
    }
    if let Some(software_name) = claims.software_name.as_ref() {
        vendor.insert(
            "softwareName".to_string(),
            Value::String(software_name.clone()),
        );
    }
    if let Some(secure_boot) = claims.secure_boot {
        vendor.insert(
            "secureBoot".to_string(),
            Value::String(if secure_boot {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            }),
        );
    }
    if let Some(nonce) = claims.nonce.as_ref() {
        vendor.insert("nonce".to_string(), Value::String(nonce.clone()));
    }
    if !claims.google_service_accounts.is_empty() {
        vendor.insert(
            "serviceAccounts".to_string(),
            Value::Array(
                claims
                    .google_service_accounts
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(kid) = header.kid.as_ref() {
        vendor.insert("signingKeyId".to_string(), Value::String(kid.clone()));
    }
    for (key, value) in &claims.extra {
        vendor.insert(key.clone(), value.clone());
    }
    vendor
}

fn resolve_workload_identity(
    runtime: Option<&Value>,
    workload_claim_path: Option<&str>,
) -> Result<(Option<String>, Option<WorkloadIdentity>), AzureMaaVerificationError> {
    let Some(path) = workload_claim_path else {
        return Ok((None, None));
    };
    let Some(runtime) = runtime else {
        return Err(AzureMaaVerificationError::InvalidWorkloadClaim(
            path.to_string(),
        ));
    };
    let mut current = runtime
        .get("claims")
        .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    for segment in path.split('.') {
        current = current
            .get(segment)
            .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    }
    let workload_uri = current
        .as_str()
        .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    let workload_identity =
        WorkloadIdentity::parse_spiffe_uri_with_kind(workload_uri, WorkloadCredentialKind::Uri)
            .map_err(|error| {
                AzureMaaVerificationError::InvalidWorkloadIdentity(error.to_string())
            })?;
    Ok((Some(workload_uri.to_string()), Some(workload_identity)))
}

fn google_token_audiences(
    aud: &Value,
) -> Result<Vec<String>, GoogleConfidentialVmVerificationError> {
    match aud {
        Value::String(value) if !value.trim().is_empty() => Ok(vec![value.clone()]),
        Value::Array(values) => {
            let audiences = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if audiences.is_empty() {
                Err(GoogleConfidentialVmVerificationError::MissingClaim("aud"))
            } else {
                Ok(audiences)
            }
        }
        _ => Err(GoogleConfidentialVmVerificationError::MissingClaim("aud")),
    }
}

fn canonicalize_issuer(value: &str) -> String {
    let trimmed = value.trim();
    match url::Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

fn decode_jwt_parts<T: DeserializeOwned>(
    token: &str,
) -> Result<(OidcJwtHeader, T, String, Vec<u8>), OidcJwtDecodeError> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing header"))?;
    let payload_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing payload"))?;
    let signature_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing signature"))?;
    if parts.next().is_some() {
        return Err(OidcJwtDecodeError::InvalidJwt("too many segments"));
    }

    let header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid header encoding"))?,
    )
    .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid header json"))?;
    let claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid payload encoding"))?,
    )
    .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid payload json"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid signature encoding"))?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{payload_b64}"),
        signature,
    ))
}

fn resolve_signing_key(
    jwks: &AzureMaaJwks,
    kid: Option<&str>,
    alg: AzureMaaJwtAlgorithm,
) -> Result<AzureMaaResolvedJwk, OidcRsaKeyResolveError> {
    let mut keys_by_kid = HashMap::new();
    let mut anonymous = Vec::new();
    for jwk in &jwks.keys {
        if jwk.key_use.as_deref().is_some_and(|value| value != "sig") {
            continue;
        }
        let resolved = resolve_jwk_public_key(jwk)?;
        if let Some(kid) = jwk.kid.as_ref() {
            keys_by_kid.insert(kid.clone(), resolved);
        } else {
            anonymous.push(resolved);
        }
    }

    if let Some(kid) = kid {
        let key = keys_by_kid
            .get(kid)
            .ok_or(OidcRsaKeyResolveError::UntrustedSigningKey)?;
        if !key.supports_alg(alg) {
            return Err(OidcRsaKeyResolveError::KeyAlgorithmMismatch(
                alg.as_str().to_string(),
            ));
        }
        return Ok(key.clone());
    }

    let mut compatible = keys_by_kid
        .values()
        .chain(anonymous.iter())
        .filter(|key| key.supports_alg(alg));
    let Some(first) = compatible.next() else {
        return Err(OidcRsaKeyResolveError::UntrustedSigningKey);
    };
    if compatible.next().is_some() {
        return Err(OidcRsaKeyResolveError::UntrustedSigningKey);
    }
    Ok(first.clone())
}

fn resolve_jwk_public_key(
    jwk: &AzureMaaJwk,
) -> Result<AzureMaaResolvedJwk, OidcRsaKeyResolveError> {
    if jwk.kty != "RSA" {
        return Err(OidcRsaKeyResolveError::InvalidRsaKey(format!(
            "unsupported kty `{}`",
            jwk.kty
        )));
    }
    let key = if let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) {
        let modulus = BigUint::from_bytes_be(&decode_urlsafe_component(n, "n")?);
        let exponent = BigUint::from_bytes_be(&decode_urlsafe_component(e, "e")?);
        RsaPublicKey::new(modulus, exponent)
            .map_err(|error| OidcRsaKeyResolveError::InvalidRsaKey(error.to_string()))?
    } else {
        let first_cert = jwk.x5c.first().ok_or_else(|| {
            OidcRsaKeyResolveError::InvalidRsaKey("RSA JWK must include n/e or x5c".to_string())
        })?;
        let cert_der = STANDARD
            .decode(first_cert)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        let cert = Certificate::from_der(&cert_der)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?
    };

    Ok(AzureMaaResolvedJwk {
        key,
        alg_hint: jwk.alg.clone(),
    })
}

fn decode_urlsafe_component(
    value: &str,
    component: &'static str,
) -> Result<Vec<u8>, OidcRsaKeyResolveError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| OidcRsaKeyResolveError::InvalidJwkComponent {
            component,
            error: error.to_string(),
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use p384::ecdsa::signature::Signer as _;
    use p384::ecdsa::SigningKey as P384SigningKey;
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa,
        KeyPair as RcgenKeyPair, PKCS_ECDSA_P384_SHA384,
    };
    use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
    use rsa::traits::PublicKeyParts;
    use serde_json::json;

    use chio_test_support::prelude::*;

    fn sign_rs256_jwt(private_key: &rsa::RsaPrivateKey, header: Value, claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).test_unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).test_unwrap());
        let signed_input = format!("{header}.{payload}");
        let signature = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone())
            .sign_with_rng(&mut OsRng, signed_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_vec());
        format!("{signed_input}.{signature}")
    }

    fn rsa_jwk_set(private_key: &rsa::RsaPrivateKey, kid: &str) -> AzureMaaJwks {
        let public_key = private_key.to_public_key();
        AzureMaaJwks {
            keys: vec![AzureMaaJwk {
                kty: "RSA".to_string(),
                kid: Some(kid.to_string()),
                alg: Some("RS256".to_string()),
                key_use: Some("sig".to_string()),
                n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
                e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
                x5c: Vec::new(),
            }],
        }
    }

    struct AwsNitroTestMaterials {
        root_pem: String,
        leaf_der: Vec<u8>,
        leaf_signing_key: P384SigningKey,
    }

    fn generate_aws_nitro_test_materials() -> AwsNitroTestMaterials {
        let mut root_params = CertificateParams::new(Vec::<String>::new()).test_unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.distinguished_name = DistinguishedName::new();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Chio Nitro Root");
        let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).test_unwrap();
        let root_cert = root_params.self_signed(&root_key).test_unwrap();

        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).test_unwrap();
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Chio Nitro Leaf");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).test_unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .test_unwrap();

        AwsNitroTestMaterials {
            root_pem: root_cert.pem(),
            leaf_der: leaf_cert.der().to_vec(),
            leaf_signing_key: P384SigningKey::from_pkcs8_der(&leaf_key.serialize_der())
                .test_unwrap(),
        }
    }

    fn build_aws_nitro_attestation_document(
        materials: &AwsNitroTestMaterials,
        timestamp_ms: u64,
        pcrs: BTreeMap<u8, Vec<u8>>,
        nonce: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let payload = CborValue::Map(vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text("i-arcnitro123".to_string()),
            ),
            (
                CborValue::Text("timestamp".to_string()),
                CborValue::Integer(timestamp_ms.into()),
            ),
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(
                    pcrs.iter()
                        .map(|(index, value)| {
                            (
                                CborValue::Integer((*index).into()),
                                CborValue::Bytes(value.clone()),
                            )
                        })
                        .collect(),
                ),
            ),
            (
                CborValue::Text("certificate".to_string()),
                CborValue::Bytes(materials.leaf_der.clone()),
            ),
            (
                CborValue::Text("cabundle".to_string()),
                CborValue::Array(Vec::new()),
            ),
            (
                CborValue::Text("public_key".to_string()),
                CborValue::Bytes(vec![1, 2, 3, 4]),
            ),
            (
                CborValue::Text("user_data".to_string()),
                CborValue::Bytes(vec![9, 9, 9]),
            ),
            (
                CborValue::Text("nonce".to_string()),
                CborValue::Bytes(nonce.unwrap_or_else(|| vec![0xAA, 0xBB])),
            ),
        ]);
        let mut payload_bytes = Vec::new();
        cbor_into_writer(&payload, &mut payload_bytes).test_unwrap();

        let protected = CborValue::Map(vec![(
            CborValue::Integer(COSE_HEADER_ALGORITHM_KEY.into()),
            CborValue::Integer(COSE_ES384_ALGORITHM.into()),
        )]);
        let mut protected_bytes = Vec::new();
        cbor_into_writer(&protected, &mut protected_bytes).test_unwrap();

        let sig_structure =
            build_cose_sign1_sig_structure(&protected_bytes, &payload_bytes).test_unwrap();
        let signature: P384Signature = materials.leaf_signing_key.sign(&sig_structure);
        let signature = signature.to_bytes().to_vec();

        let sign1 = CborValue::Array(vec![
            CborValue::Bytes(protected_bytes),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload_bytes),
            CborValue::Bytes(signature),
        ]);
        let mut bytes = Vec::new();
        cbor_into_writer(&sign1, &mut bytes).test_unwrap();
        bytes
    }

    fn current_unix_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_secs()
    }

    fn serve_json_once(body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let address = listener.local_addr().test_unwrap();
        let body = body.to_string();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().test_unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).test_unwrap();
        });
        format!("http://{address}")
    }

    fn closed_local_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let address = listener.local_addr().test_unwrap();
        drop(listener);
        format!("http://{address}")
    }

    fn sample_enterprise_evidence(now: u64) -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://attest.contoso.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(30),
            expires_at: now.saturating_add(300),
            evidence_sha256: "sha256-enterprise-attestation".to_string(),
            runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
            workload_identity: Some(
                WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                    .test_unwrap(),
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
        }
    }

    fn sample_aws_document(
        materials: &AwsNitroTestMaterials,
        now: u64,
    ) -> AwsNitroAttestationDocument {
        AwsNitroAttestationDocument {
            module_id: "i-arcnitro123".to_string(),
            timestamp: now.saturating_sub(10) * 1000,
            digest: "SHA384".to_string(),
            pcrs: BTreeMap::from([(0, vec![0x11; 48])]),
            certificate: materials.leaf_der.clone(),
            cabundle: Vec::new(),
            public_key: Some(vec![1, 2, 3, 4]),
            user_data: Some(vec![9, 9, 9]),
            nonce: Some(vec![0xCA, 0xFE]),
        }
    }

    #[test]
    fn attestation_policy_validation_and_adapter_identity_helpers_cover_branch_guards() {
        let aws_policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec!["root-pem".to_string()],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 60,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: None,
        };
        let aws_adapter = AwsNitroVerifierAdapter::new(aws_policy.clone()).test_unwrap();
        assert_eq!(
            default_aws_nitro_runtime_tier(),
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(aws_adapter.adapter_name(), AWS_NITRO_VERIFIER_ADAPTER);
        assert_eq!(
            aws_adapter.verifier_family(),
            AttestationVerifierFamily::AwsNitro
        );
        assert!(matches!(
            AwsNitroVerificationPolicy {
                trusted_root_certificates_pem: Vec::new(),
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                max_document_age_seconds: 0,
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                tier: RuntimeAssuranceTier::Verified,
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                trusted_root_certificates_pem: vec![" ".to_string()],
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                expected_pcrs: BTreeMap::from([(0, "zz".to_string())]),
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                expected_pcrs: BTreeMap::from([(0, "11".repeat(47))]),
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                expected_nonce_hex: Some("zz".to_string()),
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AwsNitroVerificationPolicy {
                expected_nonce_hex: Some(String::new()),
                ..aws_policy.clone()
            }
            .validate(),
            Err(AwsNitroVerificationError::InvalidPolicy(_))
        ));

        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let azure_policy = AzureMaaVerificationPolicy {
            issuer: "https://maa.contoso.test".to_string(),
            allowed_attestation_types: vec!["sgx".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            workload_claim_path: None,
        };
        let azure_adapter = AzureMaaVerifierAdapter::new(
            azure_policy.clone(),
            rsa_jwk_set(&private_key, "maa-key"),
        )
        .test_unwrap();
        assert_eq!(
            default_azure_maa_runtime_tier(),
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(azure_adapter.adapter_name(), AZURE_MAA_VERIFIER_ADAPTER);
        assert_eq!(
            azure_adapter.verifier_family(),
            AttestationVerifierFamily::AzureMaa
        );
        assert!(matches!(
            AzureMaaVerificationPolicy {
                issuer: " ".to_string(),
                ..azure_policy.clone()
            }
            .validate(),
            Err(AzureMaaVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            AzureMaaVerificationPolicy {
                workload_claim_path: Some(" ".to_string()),
                ..azure_policy.clone()
            }
            .validate(),
            Err(AzureMaaVerificationError::InvalidPolicy(_))
        ));

        let google_policy = GoogleConfidentialVmVerificationPolicy {
            issuer: "https://confidentialcomputing.googleapis.com".to_string(),
            allowed_audiences: vec!["chio-runtime".to_string()],
            allowed_service_accounts: vec!["svc@example.test".to_string()],
            allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            require_secure_boot: true,
        };
        let google_adapter = GoogleConfidentialVmVerifierAdapter::new(
            google_policy.clone(),
            GoogleConfidentialVmJwks { keys: Vec::new() },
        )
        .test_unwrap();
        assert_eq!(
            default_google_confidential_vm_runtime_tier(),
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(
            google_adapter.adapter_name(),
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER
        );
        assert_eq!(
            google_adapter.verifier_family(),
            AttestationVerifierFamily::GoogleAttestation
        );
        assert!(matches!(
            GoogleConfidentialVmVerificationPolicy {
                issuer: " ".to_string(),
                ..google_policy.clone()
            }
            .validate(),
            Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationPolicy {
                tier: RuntimeAssuranceTier::Verified,
                ..google_policy.clone()
            }
            .validate(),
            Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationPolicy {
                allowed_audiences: vec![" ".to_string()],
                ..google_policy.clone()
            }
            .validate(),
            Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationPolicy {
                allowed_service_accounts: vec![" ".to_string()],
                ..google_policy.clone()
            }
            .validate(),
            Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationPolicy {
                allowed_hardware_models: vec![" ".to_string()],
                ..google_policy.clone()
            }
            .validate(),
            Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
        ));

        let trusted_signer = chio_core::crypto::Keypair::generate();
        let enterprise_policy = EnterpriseVerifierVerificationPolicy {
            verifier: "https://attest.contoso.example".to_string(),
            trusted_signer_keys: vec![trusted_signer.public_key().to_hex()],
            max_evidence_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
        };
        let enterprise_adapter =
            EnterpriseVerifierAdapter::new(enterprise_policy.clone()).test_unwrap();
        assert_eq!(
            default_enterprise_verifier_runtime_tier(),
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(
            enterprise_adapter.adapter_name(),
            ENTERPRISE_VERIFIER_ADAPTER
        );
        assert_eq!(
            enterprise_adapter.verifier_family(),
            AttestationVerifierFamily::EnterpriseVerifier
        );
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                verifier: " ".to_string(),
                ..enterprise_policy.clone()
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                trusted_signer_keys: Vec::new(),
                ..enterprise_policy.clone()
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                max_evidence_age_seconds: 0,
                ..enterprise_policy.clone()
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                tier: RuntimeAssuranceTier::Verified,
                ..enterprise_policy.clone()
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                trusted_signer_keys: vec![" ".to_string()],
                ..enterprise_policy.clone()
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
        assert!(matches!(
            EnterpriseVerifierVerificationPolicy {
                trusted_signer_keys: vec!["deadbeef".to_string()],
                ..enterprise_policy
            }
            .validate(),
            Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn attestation_oidc_and_metadata_helpers_cover_parse_and_resolution_edges() {
        assert_eq!(
            AzureMaaJwtAlgorithm::parse("RS256").test_unwrap().as_str(),
            "RS256"
        );
        assert_eq!(
            AzureMaaJwtAlgorithm::parse("PS256").test_unwrap().as_str(),
            "PS256"
        );
        assert!(matches!(
            AzureMaaJwtAlgorithm::parse("HS256"),
            Err(AzureMaaVerificationError::UnsupportedAlgorithm(_))
        ));
        assert!(AzureMaaResolvedJwk {
            key: rsa::RsaPrivateKey::new(&mut OsRng, 2048)
                .test_unwrap()
                .to_public_key(),
            alg_hint: None,
        }
        .supports_alg(AzureMaaJwtAlgorithm::Rs256));
        assert!(!AzureMaaResolvedJwk {
            key: rsa::RsaPrivateKey::new(&mut OsRng, 2048)
                .test_unwrap()
                .to_public_key(),
            alg_hint: Some("PS256".to_string()),
        }
        .supports_alg(AzureMaaJwtAlgorithm::Rs256));
        assert!(matches!(
            AzureMaaVerificationError::from(OidcJwtDecodeError::InvalidJwt("bad")),
            AzureMaaVerificationError::InvalidJwt("bad")
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationError::from(OidcJwtDecodeError::InvalidJwt("bad")),
            GoogleConfidentialVmVerificationError::InvalidJwt("bad")
        ));
        assert!(matches!(
            AzureMaaVerificationError::from(OidcRsaKeyResolveError::UntrustedSigningKey),
            AzureMaaVerificationError::UntrustedSigningKey
        ));
        assert!(matches!(
            GoogleConfidentialVmVerificationError::from(
                OidcRsaKeyResolveError::KeyAlgorithmMismatch("RS256".to_string())
            ),
            GoogleConfidentialVmVerificationError::KeyAlgorithmMismatch(alg) if alg == "RS256"
        ));

        assert!(decode_cose_protected_headers(&[]).test_unwrap().is_empty());
        assert!(matches!(
            decode_cose_protected_headers(b"not-cbor"),
            Err(AwsNitroVerificationError::InvalidCose(_))
        ));
        assert_eq!(cbor_integer_to_i64(&CborValue::Integer(7.into())), Some(7));
        assert_eq!(
            cbor_integer_to_i64(&CborValue::Text("nope".to_string())),
            None
        );

        assert!(matches!(
            decode_jwt_parts::<Value>("header-only"),
            Err(OidcJwtDecodeError::InvalidJwt("missing payload"))
        ));
        assert!(matches!(
            decode_jwt_parts::<Value>("a.b"),
            Err(OidcJwtDecodeError::InvalidJwt("missing signature"))
        ));
        assert!(matches!(
            decode_jwt_parts::<Value>("a.b.c.d"),
            Err(OidcJwtDecodeError::InvalidJwt("too many segments"))
        ));
        assert!(matches!(
            decode_jwt_parts::<Value>("***.b.c"),
            Err(OidcJwtDecodeError::InvalidJwt("invalid header encoding"))
        ));
        let bad_json = URL_SAFE_NO_PAD.encode(b"not-json");
        assert!(matches!(
            decode_jwt_parts::<Value>(&format!("{bad_json}.b.c")),
            Err(OidcJwtDecodeError::InvalidJwt("invalid header json"))
        ));
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        assert!(matches!(
            decode_jwt_parts::<Value>(&format!("{header}.***.c")),
            Err(OidcJwtDecodeError::InvalidJwt("invalid payload encoding"))
        ));
        let bad_payload = URL_SAFE_NO_PAD.encode(b"not-json");
        assert!(matches!(
            decode_jwt_parts::<Value>(&format!("{header}.{bad_payload}.c")),
            Err(OidcJwtDecodeError::InvalidJwt("invalid payload json"))
        ));
        let valid_payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"demo"}"#);
        assert!(matches!(
            decode_jwt_parts::<Value>(&format!("{header}.{valid_payload}.***")),
            Err(OidcJwtDecodeError::InvalidJwt("invalid signature encoding"))
        ));

        assert!(matches!(
            decode_urlsafe_component("***", "n"),
            Err(OidcRsaKeyResolveError::InvalidJwkComponent { component: "n", .. })
        ));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            google_token_audiences(&Value::String("chio-runtime".to_string())).test_unwrap(),
            vec!["chio-runtime".to_string()]
        );
        assert_eq!(
            google_token_audiences(&json!(["chio-runtime", "", 7, "fallback"])).test_unwrap(),
            vec!["chio-runtime".to_string(), "fallback".to_string()]
        );
        assert!(matches!(
            google_token_audiences(&json!(["", 7])),
            Err(GoogleConfidentialVmVerificationError::MissingClaim("aud"))
        ));
        assert_eq!(
            canonicalize_issuer(" https://issuer.example/path/ "),
            "https://issuer.example/path"
        );
        assert_eq!(canonicalize_issuer("issuer.example/"), "issuer.example");

        assert_eq!(
            resolve_workload_identity(None, None).test_unwrap(),
            (None, None)
        );
        let runtime = json!({
            "claims": {
                "nested": {
                    "spiffe": "spiffe://contoso.test/runtime/worker"
                }
            }
        });
        let (runtime_identity, workload_identity) =
            resolve_workload_identity(Some(&runtime), Some("nested.spiffe")).test_unwrap();
        assert_eq!(
            runtime_identity.as_deref(),
            Some("spiffe://contoso.test/runtime/worker")
        );
        assert_eq!(workload_identity.test_unwrap().trust_domain, "contoso.test");
        assert!(matches!(
            resolve_workload_identity(None, Some("nested.spiffe")),
            Err(AzureMaaVerificationError::InvalidWorkloadClaim(path))
            if path == "nested.spiffe"
        ));
        assert!(matches!(
            resolve_workload_identity(Some(&json!({"claims": {"nested": {"spiffe": 7}}})), Some("nested.spiffe")),
            Err(AzureMaaVerificationError::InvalidWorkloadClaim(path))
            if path == "nested.spiffe"
        ));
        assert!(matches!(
            resolve_workload_identity(
                Some(&json!({"claims": {"nested": {"spiffe": "not-a-spiffe"}}})),
                Some("nested.spiffe")
            ),
            Err(AzureMaaVerificationError::InvalidWorkloadIdentity(_))
        ));

        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let jwks_json =
            serde_json::to_string(&rsa_jwk_set(&private_key, "maa-key-1")).test_unwrap();

        let azure_metadata_url = serve_json_once(
            r#"{"issuer":"https://maa.contoso.test","jwksUri":"https://maa.contoso.test/keys"}"#,
        );
        assert_eq!(
            fetch_azure_maa_openid_metadata(&azure_metadata_url)
                .test_unwrap()
                .jwks_uri,
            "https://maa.contoso.test/keys"
        );
        let azure_jwks_url = serve_json_once(&jwks_json);
        assert_eq!(
            fetch_azure_maa_jwks(&azure_jwks_url)
                .test_unwrap()
                .keys
                .len(),
            1
        );
        let azure_parse_url = serve_json_once("{bad json");
        assert!(matches!(
            fetch_azure_maa_openid_metadata(&azure_parse_url),
            Err(AzureMaaVerificationError::MetadataParse { .. })
        ));
        let azure_fetch_url = closed_local_url();
        assert!(matches!(
            fetch_azure_maa_jwks(&azure_fetch_url),
            Err(AzureMaaVerificationError::MetadataFetch { .. })
        ));

        let google_metadata_url = serve_json_once(
            r#"{"issuer":"https://confidentialcomputing.googleapis.com","jwksUri":"https://confidentialcomputing.googleapis.com/keys"}"#,
        );
        assert_eq!(
            fetch_google_confidential_vm_openid_metadata(&google_metadata_url)
                .test_unwrap()
                .issuer,
            "https://confidentialcomputing.googleapis.com"
        );
        let google_jwks_url = serve_json_once(&jwks_json);
        assert_eq!(
            fetch_google_confidential_vm_jwks(&google_jwks_url)
                .test_unwrap()
                .keys
                .len(),
            1
        );
        let google_parse_url = serve_json_once("{bad json");
        assert!(matches!(
            fetch_google_confidential_vm_jwks(&google_parse_url),
            Err(GoogleConfidentialVmVerificationError::MetadataParse { .. })
        ));
        let google_fetch_url = closed_local_url();
        assert!(matches!(
            fetch_google_confidential_vm_openid_metadata(&google_fetch_url),
            Err(GoogleConfidentialVmVerificationError::MetadataFetch { .. })
        ));
    }

    #[test]
    fn attestation_jwk_resolution_and_aws_helpers_cover_remaining_error_branches() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let compatible = rsa_jwk_set(&private_key, "maa-key-1");
        let resolved =
            resolve_signing_key(&compatible, Some("maa-key-1"), AzureMaaJwtAlgorithm::Rs256)
                .test_unwrap();
        assert!(resolved.supports_alg(AzureMaaJwtAlgorithm::Rs256));

        let mismatched_alg = AzureMaaJwks {
            keys: vec![AzureMaaJwk {
                alg: Some("PS256".to_string()),
                ..compatible.keys[0].clone()
            }],
        };
        assert!(matches!(
            resolve_signing_key(
                &mismatched_alg,
                Some("maa-key-1"),
                AzureMaaJwtAlgorithm::Rs256
            ),
            Err(OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg)) if alg == "RS256"
        ));

        let anonymous = AzureMaaJwks {
            keys: vec![AzureMaaJwk {
                kid: None,
                ..compatible.keys[0].clone()
            }],
        };
        assert!(resolve_signing_key(&anonymous, None, AzureMaaJwtAlgorithm::Rs256).is_ok());

        let ambiguous = AzureMaaJwks {
            keys: vec![
                AzureMaaJwk {
                    kid: None,
                    ..compatible.keys[0].clone()
                },
                AzureMaaJwk {
                    kid: None,
                    ..compatible.keys[0].clone()
                },
            ],
        };
        assert!(matches!(
            resolve_signing_key(&ambiguous, None, AzureMaaJwtAlgorithm::Rs256),
            Err(OidcRsaKeyResolveError::UntrustedSigningKey)
        ));

        let encryption_only = AzureMaaJwks {
            keys: vec![AzureMaaJwk {
                key_use: Some("enc".to_string()),
                ..compatible.keys[0].clone()
            }],
        };
        assert!(matches!(
            resolve_signing_key(
                &encryption_only,
                Some("maa-key-1"),
                AzureMaaJwtAlgorithm::Rs256
            ),
            Err(OidcRsaKeyResolveError::UntrustedSigningKey)
        ));

        assert!(matches!(
            resolve_jwk_public_key(&AzureMaaJwk {
                kty: "EC".to_string(),
                kid: None,
                alg: None,
                key_use: None,
                n: None,
                e: None,
                x5c: Vec::new(),
            }),
            Err(OidcRsaKeyResolveError::InvalidRsaKey(_))
        ));
        assert!(matches!(
            resolve_jwk_public_key(&AzureMaaJwk {
                kty: "RSA".to_string(),
                kid: None,
                alg: None,
                key_use: None,
                n: None,
                e: None,
                x5c: Vec::new(),
            }),
            Err(OidcRsaKeyResolveError::InvalidRsaKey(_))
        ));
        assert!(matches!(
            resolve_jwk_public_key(&AzureMaaJwk {
                kty: "RSA".to_string(),
                kid: None,
                alg: None,
                key_use: None,
                n: Some("***".to_string()),
                e: Some("AQAB".to_string()),
                x5c: Vec::new(),
            }),
            Err(OidcRsaKeyResolveError::InvalidJwkComponent { component: "n", .. })
        ));

        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: Some("cafe".to_string()),
        };
        let valid_document = sample_aws_document(&materials, now);
        assert!(validate_aws_nitro_document(&valid_document, &policy, now).is_ok());
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    module_id: " ".to_string(),
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::MissingField("module_id"))
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    certificate: Vec::new(),
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::MissingField("certificate"))
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    digest: "SHA256".to_string(),
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::UnsupportedDigest(_))
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    timestamp: now.saturating_add(10) * 1000,
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::FutureDocument { .. })
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    pcrs: BTreeMap::new(),
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::MissingField("pcrs"))
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    pcrs: BTreeMap::from([(0, vec![0x11; 47])]),
                    ..sample_aws_document(&materials, now)
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::InvalidField("pcrs"))
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &valid_document,
                &AwsNitroVerificationPolicy {
                    expected_pcrs: BTreeMap::from([(1, "11".repeat(48))]),
                    ..policy.clone()
                },
                now
            ),
            Err(AwsNitroVerificationError::MissingPcr { index: 1 })
        ));
        assert!(matches!(
            validate_aws_nitro_document(
                &AwsNitroAttestationDocument {
                    nonce: None,
                    ..valid_document
                },
                &policy,
                now
            ),
            Err(AwsNitroVerificationError::MissingField("nonce"))
        ));
    }

    #[test]
    fn enterprise_and_appraisal_negative_paths_cover_remaining_branch_states() {
        let now = current_unix_time();
        let signer = chio_core::crypto::Keypair::generate();
        let policy = EnterpriseVerifierVerificationPolicy {
            verifier: "https://attest.contoso.example".to_string(),
            trusted_signer_keys: vec![signer.public_key().to_hex()],
            max_evidence_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
        };
        let adapter = EnterpriseVerifierAdapter::new(policy.clone()).test_unwrap();

        assert!(matches!(
            adapter.verify_and_appraise("{", now),
            Err(EnterpriseVerifierVerificationError::InvalidEnvelope(_))
        ));

        let signed =
            SignedExportEnvelope::sign(sample_enterprise_evidence(now), &signer).test_unwrap();
        let mut tampered = signed.clone();
        tampered.body.verifier = "https://attest.other.example".to_string();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&tampered).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::InvalidSignature)
        ));

        let unsupported = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.other.v1".to_string(),
            ..sample_enterprise_evidence(now)
        };
        let unsupported = SignedExportEnvelope::sign(unsupported, &signer).test_unwrap();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&unsupported).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::UnsupportedSchema { .. })
        ));

        let mismatch = RuntimeAttestationEvidence {
            verifier: "https://attest.other.example".to_string(),
            ..sample_enterprise_evidence(now)
        };
        let mismatch = SignedExportEnvelope::sign(mismatch, &signer).test_unwrap();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&mismatch).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::VerifierMismatch { .. })
        ));

        let future = RuntimeAttestationEvidence {
            issued_at: now.saturating_add(30),
            expires_at: now.saturating_add(300),
            ..sample_enterprise_evidence(now)
        };
        let future = SignedExportEnvelope::sign(future, &signer).test_unwrap();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&future).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::EvidenceNotValid { .. })
        ));

        let stale = RuntimeAttestationEvidence {
            issued_at: now.saturating_sub(500),
            expires_at: now.saturating_add(300),
            ..sample_enterprise_evidence(now)
        };
        let stale = SignedExportEnvelope::sign(stale, &signer).test_unwrap();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&stale).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::EvidenceTooOld { .. })
        ));

        let too_high = RuntimeAttestationEvidence {
            tier: RuntimeAssuranceTier::Verified,
            ..sample_enterprise_evidence(now)
        };
        let too_high = SignedExportEnvelope::sign(too_high, &signer).test_unwrap();
        assert!(matches!(
            adapter.verify_and_appraise(&serde_json::to_string(&too_high).test_unwrap(), now),
            Err(EnterpriseVerifierVerificationError::TierTooHigh { .. })
        ));

        let foreign_google = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.other.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let google_appraisal = appraise_google_confidential_vm_evidence(&foreign_google);
        assert_eq!(
            google_appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
        );
        assert_eq!(
            google_appraisal.verdict,
            chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
        );

        let foreign_aws = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.other.v1".to_string(),
            verifier: "aws-nitro".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let aws_appraisal = appraise_aws_nitro_evidence(&foreign_aws);
        assert_eq!(
            aws_appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
        );
        assert_eq!(
            aws_appraisal.verdict,
            chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert!(extract_vendor_claims(&foreign_aws, "awsNitro").is_empty());
    }

    #[test]
    fn azure_maa_jwt_normalizes_runtime_attestation_and_workload_identity() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://maa.contoso.test",
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "jti": "maa-token-1",
                "x-ms-ver": "1.0",
                "x-ms-attestation-type": "sgx",
                "x-ms-policy-hash": "policy-hash-1",
                "x-ms-runtime": {
                    "claims": {
                        "spiffe_uri": "spiffe://contoso.test/runtime/worker"
                    }
                }
            }),
        );
        let policy = AzureMaaVerificationPolicy {
            issuer: "https://maa.contoso.test".to_string(),
            allowed_attestation_types: vec!["sgx".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            workload_claim_path: Some("spiffe_uri".to_string()),
        };

        let evidence = verify_azure_maa_attestation_jwt(
            &token,
            &policy,
            &rsa_jwk_set(&private_key, "maa-key-1"),
            150,
        )
        .test_unwrap();

        assert_eq!(evidence.schema, AZURE_MAA_ATTESTATION_SCHEMA);
        assert_eq!(evidence.verifier, "https://maa.contoso.test");
        assert_eq!(evidence.tier, RuntimeAssuranceTier::Attested);
        assert_eq!(
            evidence.runtime_identity.as_deref(),
            Some("spiffe://contoso.test/runtime/worker")
        );
        assert_eq!(
            evidence
                .workload_identity
                .as_ref()
                .test_unwrap()
                .trust_domain,
            "contoso.test"
        );
        assert_eq!(
            evidence.claims.test_unwrap()["azureMaa"]["attestationType"],
            "sgx"
        );
    }

    #[test]
    fn azure_maa_jwt_rejects_disallowed_attestation_type() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://maa.contoso.test",
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "x-ms-ver": "1.0",
                "x-ms-attestation-type": "sev_snp"
            }),
        );
        let policy = AzureMaaVerificationPolicy {
            issuer: "https://maa.contoso.test".to_string(),
            allowed_attestation_types: vec!["sgx".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            workload_claim_path: None,
        };

        let error = verify_azure_maa_attestation_jwt(
            &token,
            &policy,
            &rsa_jwk_set(&private_key, "maa-key-1"),
            150,
        )
        .test_unwrap_err();
        assert!(matches!(
            error,
            AzureMaaVerificationError::DisallowedAttestationType { .. }
        ));
    }

    #[test]
    fn azure_maa_policy_rejects_assurance_tier_above_attested() {
        let policy = AzureMaaVerificationPolicy {
            issuer: "https://maa.contoso.test".to_string(),
            allowed_attestation_types: Vec::new(),
            tier: RuntimeAssuranceTier::Verified,
            workload_claim_path: None,
        };

        let error = policy.validate().test_unwrap_err();
        assert!(matches!(error, AzureMaaVerificationError::InvalidPolicy(_)));
    }

    #[test]
    fn azure_maa_adapter_emits_canonical_appraisal_contract() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://maa.contoso.test",
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "jti": "maa-token-1",
                "x-ms-ver": "1.0",
                "x-ms-attestation-type": "sgx",
                "x-ms-runtime": {
                    "claims": {
                        "spiffe_uri": "spiffe://contoso.test/runtime/worker"
                    }
                }
            }),
        );
        let adapter = AzureMaaVerifierAdapter::new(
            AzureMaaVerificationPolicy {
                issuer: "https://maa.contoso.test".to_string(),
                allowed_attestation_types: vec!["sgx".to_string()],
                tier: RuntimeAssuranceTier::Attested,
                workload_claim_path: Some("spiffe_uri".to_string()),
            },
            rsa_jwk_set(&private_key, "maa-key-1"),
        )
        .test_unwrap();

        let verified = adapter.verify_and_appraise(&token, 150).test_unwrap();

        assert_eq!(verified.appraisal.adapter, AZURE_MAA_VERIFIER_ADAPTER);
        assert_eq!(
            verified.appraisal.verifier_family,
            AttestationVerifierFamily::AzureMaa
        );
        assert_eq!(
            verified.appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
        );
        assert_eq!(
            verified.appraisal.normalized_assertions["attestationType"],
            "sgx"
        );
        assert_eq!(
            verified.appraisal.normalized_assertions["workloadIdentityUri"],
            "spiffe://contoso.test/runtime/worker"
        );
        assert_eq!(verified.appraisal.vendor_claims["attestationType"], "sgx");
    }

    #[test]
    fn azure_maa_appraisal_rejects_non_azure_schema() {
        let evidence = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.other.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };

        let appraisal = appraise_azure_maa_evidence(&evidence);
        assert_eq!(
            appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
        );
        assert_eq!(
            appraisal.verdict,
            chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::None);
    }

    #[test]
    fn google_confidential_vm_jwt_verifies_and_appraises() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://confidentialcomputing.googleapis.com",
                "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
                "aud": ["chio-runtime"],
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "secboot": true,
                "hwmodel": "GCP_AMD_SEV",
                "swname": "GCE",
                "google_service_accounts": ["svc-demo@project.iam.gserviceaccount.com"]
            }),
        );
        let policy = GoogleConfidentialVmVerificationPolicy {
            issuer: "https://confidentialcomputing.googleapis.com".to_string(),
            allowed_audiences: vec!["chio-runtime".to_string()],
            allowed_service_accounts: vec!["svc-demo@project.iam.gserviceaccount.com".to_string()],
            allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            require_secure_boot: true,
        };

        let evidence = verify_google_confidential_vm_attestation_jwt(
            &token,
            &policy,
            &rsa_jwk_set(&private_key, "google-key-1"),
            150,
        )
        .test_unwrap();

        assert_eq!(evidence.schema, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA);
        assert_eq!(
            evidence.runtime_identity.as_deref(),
            Some("//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1")
        );
        assert_eq!(
            evidence.claims.as_ref().test_unwrap()["googleAttestation"]["hardwareModel"],
            "GCP_AMD_SEV"
        );

        let appraisal = appraise_google_confidential_vm_evidence(&evidence);
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::GoogleAttestation
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
    }

    #[test]
    fn google_confidential_vm_jwt_rejects_audience_mismatch() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://confidentialcomputing.googleapis.com",
                "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
                "aud": ["unexpected-audience"],
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "secboot": true,
                "hwmodel": "GCP_AMD_SEV"
            }),
        );
        let policy = GoogleConfidentialVmVerificationPolicy {
            issuer: "https://confidentialcomputing.googleapis.com".to_string(),
            allowed_audiences: vec!["chio-runtime".to_string()],
            allowed_service_accounts: Vec::new(),
            allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            require_secure_boot: false,
        };

        let error = verify_google_confidential_vm_attestation_jwt(
            &token,
            &policy,
            &rsa_jwk_set(&private_key, "google-key-1"),
            150,
        )
        .test_unwrap_err();
        assert!(matches!(
            error,
            GoogleConfidentialVmVerificationError::AudienceMismatch
        ));
    }

    #[test]
    fn google_confidential_vm_jwt_rejects_insecure_boot() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
        let token = sign_rs256_jwt(
            &private_key,
            json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
            json!({
                "iss": "https://confidentialcomputing.googleapis.com",
                "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
                "aud": ["chio-runtime"],
                "iat": 100,
                "nbf": 100,
                "exp": 200,
                "secboot": false,
                "hwmodel": "GCP_AMD_SEV"
            }),
        );
        let policy = GoogleConfidentialVmVerificationPolicy {
            issuer: "https://confidentialcomputing.googleapis.com".to_string(),
            allowed_audiences: vec!["chio-runtime".to_string()],
            allowed_service_accounts: Vec::new(),
            allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            require_secure_boot: true,
        };

        let error = verify_google_confidential_vm_attestation_jwt(
            &token,
            &policy,
            &rsa_jwk_set(&private_key, "google-key-1"),
            150,
        )
        .test_unwrap_err();
        assert!(matches!(
            error,
            GoogleConfidentialVmVerificationError::InsecureBoot
        ));
    }

    #[test]
    fn aws_nitro_attestation_document_verifies_and_appraises() {
        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let pcr0 = vec![0x11; 48];
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, pcr0.clone());
        let document = build_aws_nitro_attestation_document(
            &materials,
            (now - 50) * 1000,
            pcrs,
            Some(vec![0xCA, 0xFE]),
        );
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::from([(0, hex::encode(&pcr0))]),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: Some("cafe".to_string()),
        };

        let evidence = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap();
        assert_eq!(evidence.schema, AWS_NITRO_ATTESTATION_SCHEMA);
        assert_eq!(evidence.verifier, "aws-nitro");
        assert_eq!(
            evidence.claims.as_ref().test_unwrap()["awsNitro"]["moduleId"],
            "i-arcnitro123"
        );

        let appraisal = appraise_aws_nitro_evidence(&evidence);
        assert_eq!(appraisal.adapter, AWS_NITRO_VERIFIER_ADAPTER);
        assert_eq!(appraisal.normalized_assertions["digest"], "SHA384");
    }

    #[test]
    fn aws_nitro_attestation_document_rejects_pcr_mismatch() {
        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0x11; 48]);
        let document =
            build_aws_nitro_attestation_document(&materials, (now - 50) * 1000, pcrs, None);
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::from([(0, hex::encode(vec![0x22; 48]))]),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: None,
        };

        let error =
            verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
        assert!(matches!(
            error,
            AwsNitroVerificationError::PcrMismatch { index: 0 }
        ));
    }

    #[test]
    fn aws_nitro_attestation_document_rejects_stale_document() {
        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0x11; 48]);
        let document =
            build_aws_nitro_attestation_document(&materials, (now - 10) * 1000, pcrs, None);
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 5,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: None,
        };

        let error =
            verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
        assert!(matches!(
            error,
            AwsNitroVerificationError::StaleDocument { .. }
        ));
    }

    #[test]
    fn aws_nitro_attestation_document_rejects_debug_mode_by_default() {
        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0x00; 48]);
        let document =
            build_aws_nitro_attestation_document(&materials, (now - 50) * 1000, pcrs, None);
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: None,
        };

        let error =
            verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
        assert!(matches!(
            error,
            AwsNitroVerificationError::DebugModeEvidence
        ));
    }

    #[test]
    fn aws_nitro_attestation_document_rejects_nonce_mismatch() {
        let materials = generate_aws_nitro_test_materials();
        let now = current_unix_time();
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0x11; 48]);
        let document = build_aws_nitro_attestation_document(
            &materials,
            (now - 50) * 1000,
            pcrs,
            Some(vec![0xCA, 0xFE]),
        );
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![materials.root_pem.clone()],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: Some("beef".to_string()),
        };

        let error =
            verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
        assert!(matches!(error, AwsNitroVerificationError::NonceMismatch));
    }

    #[test]
    fn aws_nitro_attestation_document_rejects_malformed_cose() {
        let policy = AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_string(),
            ],
            expected_pcrs: BTreeMap::new(),
            max_document_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
            allow_debug_mode: false,
            expected_nonce_hex: None,
        };

        let error =
            verify_aws_nitro_attestation_document(b"not-cbor", &policy, current_unix_time())
                .test_unwrap_err();
        assert!(matches!(error, AwsNitroVerificationError::InvalidCose(_)));
    }

    #[test]
    fn enterprise_verifier_adapter_verifies_signed_envelope_and_derives_portable_appraisal() {
        let signer = chio_core::crypto::Keypair::generate();
        let now = current_unix_time();
        let evidence = RuntimeAttestationEvidence {
            schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://attest.contoso.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(30),
            expires_at: now.saturating_add(300),
            evidence_sha256: "sha256-enterprise-attestation".to_string(),
            runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
            workload_identity: Some(
                WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                    .test_unwrap(),
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
        let signed = SignedExportEnvelope::sign(evidence.clone(), &signer).test_unwrap();
        let adapter = EnterpriseVerifierAdapter::new(EnterpriseVerifierVerificationPolicy {
            verifier: "https://attest.contoso.example".to_string(),
            trusted_signer_keys: vec![signer.public_key().to_hex()],
            max_evidence_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
        })
        .test_unwrap();

        let verified = adapter
            .verify_and_appraise(&serde_json::to_string(&signed).test_unwrap(), now)
            .test_unwrap();
        assert_eq!(verified.evidence, evidence);
        assert_eq!(
            verified.appraisal.verifier_family,
            AttestationVerifierFamily::EnterpriseVerifier
        );
        assert_eq!(
            verified.appraisal.normalized_assertions["secureBoot"],
            json!("enabled")
        );
        assert_eq!(
            verified.appraisal.normalized_assertions["digest"],
            json!("sha384:enterprise-measurement")
        );
    }

    #[test]
    fn enterprise_verifier_adapter_rejects_untrusted_signer() {
        let trusted_signer = chio_core::crypto::Keypair::generate();
        let actual_signer = chio_core::crypto::Keypair::generate();
        let now = current_unix_time();
        let signed = SignedExportEnvelope::sign(
            RuntimeAttestationEvidence {
                schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
                verifier: "https://attest.contoso.example".to_string(),
                tier: RuntimeAssuranceTier::Attested,
                issued_at: now.saturating_sub(30),
                expires_at: now.saturating_add(300),
                evidence_sha256: "sha256-enterprise-attestation".to_string(),
                runtime_identity: None,
                workload_identity: None,
                claims: Some(json!({
                    "enterpriseVerifier": {
                        "attestationType": "enterprise_confidential_vm"
                    }
                })),
            },
            &actual_signer,
        )
        .test_unwrap();
        let adapter = EnterpriseVerifierAdapter::new(EnterpriseVerifierVerificationPolicy {
            verifier: "https://attest.contoso.example".to_string(),
            trusted_signer_keys: vec![trusted_signer.public_key().to_hex()],
            max_evidence_age_seconds: 120,
            tier: RuntimeAssuranceTier::Attested,
        })
        .test_unwrap();

        let error = adapter
            .verify_and_appraise(&serde_json::to_string(&signed).test_unwrap(), now)
            .test_unwrap_err();
        assert!(matches!(
            error,
            EnterpriseVerifierVerificationError::UntrustedSigner { .. }
        ));
    }
}
