use super::*;

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
                "verifier adapters must not widen runtime assurance above `attested` before policy v2 rebinding".to_string(),
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

pub(super) fn default_aws_nitro_runtime_tier() -> RuntimeAssuranceTier {
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
                "verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
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

pub(super) fn default_enterprise_verifier_runtime_tier() -> RuntimeAssuranceTier {
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
                "verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
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

pub(super) fn default_azure_maa_runtime_tier() -> RuntimeAssuranceTier {
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
                "verifier adapters must not widen runtime assurance above `attested` before trust-policy rebinding".to_string(),
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

pub(super) fn default_google_confidential_vm_runtime_tier() -> RuntimeAssuranceTier {
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
