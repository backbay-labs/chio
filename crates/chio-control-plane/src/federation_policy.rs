use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chio_core::federation::{
    validate_federated_open_admission_policy, FederatedOpenAdmissionPolicyArtifact,
    SignedFederatedOpenAdmissionPolicy,
};
use chio_core::listing::GenericTrustAdmissionClass;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::CliError;

pub const FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA: &str =
    "chio.permissionless-federation-policy.v1";
pub const FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION: &str =
    "chio.permissionless-federation-policy-registry.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionRateLimit {
    pub max_requests: u32,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionAntiSybilControls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<FederationAdmissionRateLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_of_work_bits: Option<u8>,
    #[serde(default)]
    pub bond_backed_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionPolicyRecord {
    pub schema: String,
    pub published_at: u64,
    pub policy: SignedFederatedOpenAdmissionPolicy,
    #[serde(default)]
    pub anti_sybil: FederationAdmissionAntiSybilControls,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_reputation_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionPolicyRegistry {
    pub version: String,
    #[serde(default)]
    pub policies: BTreeMap<String, FederationAdmissionPolicyRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionPolicyListResponse {
    pub configured: bool,
    pub count: usize,
    pub policies: Vec<FederationAdmissionPolicyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionPolicyDeleteResponse {
    pub policy_id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionEvaluationRequest {
    pub policy_id: String,
    pub subject_key: String,
    pub requested_admission_class: GenericTrustAdmissionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_of_work_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionRateLimitStatus {
    pub limit: u32,
    pub window_seconds: u64,
    pub remaining: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAdmissionEvaluationResponse {
    pub policy_id: String,
    pub subject_key: String,
    pub requested_admission_class: GenericTrustAdmissionClass,
    pub accepted: bool,
    pub decision_reason: String,
    pub proof_of_work_required: bool,
    pub proof_of_work_verified: bool,
    pub bond_backed_required: bool,
    pub bond_backed_satisfied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_reputation_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_reputation_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<FederationAdmissionRateLimitStatus>,
}

impl Default for FederationAdmissionPolicyRegistry {
    fn default() -> Self {
        Self {
            version: FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION.to_string(),
            policies: BTreeMap::new(),
        }
    }
}

impl FederationAdmissionPolicyRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION {
                    return Err(CliError::cli_other_error(format!(
                        "unsupported federation admission policy registry version: {}",
                        registry.version
                    )));
                }
                registry.version = FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION.to_string();
                for (policy_id, record) in &registry.policies {
                    if policy_id != &record.policy.body.policy_id {
                        return Err(CliError::cli_other_error(
                            "federation policy map key must match signed policy body policy_id"
                                .to_string(),
                        ));
                    }
                    verify_federation_admission_policy_record(record)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, policy_id: &str) -> Option<&FederationAdmissionPolicyRecord> {
        self.policies.get(policy_id)
    }

    pub fn upsert(&mut self, record: FederationAdmissionPolicyRecord) -> Result<(), CliError> {
        verify_federation_admission_policy_record(&record)?;
        self.policies
            .insert(record.policy.body.policy_id.clone(), record);
        Ok(())
    }

    pub fn remove(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }
}

pub fn verify_federation_admission_policy_record(
    record: &FederationAdmissionPolicyRecord,
) -> Result<(), CliError> {
    if record.schema != FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "unsupported federation admission policy schema: {}",
            record.schema
        )));
    }
    if !record.policy.verify_signature()? {
        return Err(CliError::cli_other_error(
            "federation admission policy signature verification failed".to_string(),
        ));
    }
    validate_federated_open_admission_policy(&record.policy.body)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    validate_anti_sybil_controls(&record.anti_sybil, &record.policy.body)?;
    if let Some(score) = record.minimum_reputation_score {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(CliError::cli_other_error(
                "minimum_reputation_score must be between 0.0 and 1.0".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn verify_admission_proof_of_work(
    policy_id: &str,
    subject_key: &str,
    nonce: &str,
    difficulty_bits: u8,
) -> bool {
    if difficulty_bits == 0 || nonce.trim().is_empty() {
        return false;
    }
    let digest = sha256_hex(format!("{policy_id}:{subject_key}:{nonce}").as_bytes());
    leading_zero_bits(&digest) >= u32::from(difficulty_bits)
}

fn validate_anti_sybil_controls(
    controls: &FederationAdmissionAntiSybilControls,
    policy: &FederatedOpenAdmissionPolicyArtifact,
) -> Result<(), CliError> {
    if let Some(limit) = controls.rate_limit.as_ref() {
        if limit.max_requests == 0 {
            return Err(CliError::cli_other_error(
                "anti_sybil.rate_limit.max_requests must be non-zero".to_string(),
            ));
        }
        if limit.window_seconds == 0 {
            return Err(CliError::cli_other_error(
                "anti_sybil.rate_limit.window_seconds must be non-zero".to_string(),
            ));
        }
    }
    if let Some(bits) = controls.proof_of_work_bits {
        if bits == 0 || bits > 24 {
            return Err(CliError::cli_other_error(
                "anti_sybil.proof_of_work_bits must be between 1 and 24".to_string(),
            ));
        }
    }
    if controls.bond_backed_only
        && !policy
            .allowed_admission_classes
            .contains(&GenericTrustAdmissionClass::BondBacked)
    {
        return Err(CliError::cli_other_error(
            "bond_backed_only requires the signed policy to allow bond_backed admission"
                .to_string(),
        ));
    }
    Ok(())
}

fn leading_zero_bits(hex_digest: &str) -> u32 {
    let mut bits = 0_u32;
    for ch in hex_digest.chars() {
        let Some(value) = ch.to_digit(16) else {
            break;
        };
        if value == 0 {
            bits += 4;
            continue;
        }
        bits += value.leading_zeros().saturating_sub(28);
        break;
    }
    bits
}

#[cfg(test)]
mod federation_policy_error_tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::federation::{
        FederatedOpenAdmissionPolicyArtifact, FederationArtifactKind, FederationArtifactReference,
        CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA,
    };
    use chio_test_support::prelude::*;

    fn assert_cli_other_error(error: CliError, expected_message: &str) {
        match error {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), "urn:chio:error:cli:other");
                assert_eq!(chio.domain().as_str(), "cli");
                assert!(
                    chio.to_string().contains(expected_message),
                    "message: {chio}",
                );
            }
            other => panic!("expected registry-backed CLI error, got {other:?}"),
        }
    }

    fn reference(
        kind: FederationArtifactKind,
        schema: &str,
        artifact_id: &str,
    ) -> FederationArtifactReference {
        FederationArtifactReference {
            kind,
            schema: schema.to_string(),
            artifact_id: artifact_id.to_string(),
            operator_id: "operator-alpha".to_string(),
            sha256: "ab".repeat(32),
            uri: Some(format!("https://operator.example/{artifact_id}")),
        }
    }

    fn signed_record() -> FederationAdmissionPolicyRecord {
        let artifact = FederatedOpenAdmissionPolicyArtifact {
            schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
            policy_id: "open-admission-alpha".to_string(),
            issued_at: 1_700_000_000,
            namespace: "chio://federation/open".to_string(),
            governing_operator_id: "operator-alpha".to_string(),
            allowed_admission_classes: vec![GenericTrustAdmissionClass::PublicUntrusted],
            stake_requirements: Vec::new(),
            governing_charter_ref: reference(
                FederationArtifactKind::GovernanceCharter,
                "chio.governance-charter.v1",
                "charter-alpha",
            ),
            fee_schedule_ref: reference(
                FederationArtifactKind::OpenMarketFeeSchedule,
                "chio.open-market-fee-schedule.v1",
                "fees-alpha",
            ),
            explicit_local_review_required: true,
            visibility_only_without_activation: true,
            note: None,
        };
        let keypair = Keypair::generate();
        let policy = SignedFederatedOpenAdmissionPolicy::sign(artifact, &keypair).test_unwrap();
        FederationAdmissionPolicyRecord {
            schema: FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA.to_string(),
            published_at: 1_700_000_100,
            policy,
            anti_sybil: FederationAdmissionAntiSybilControls::default(),
            minimum_reputation_score: None,
            note: None,
        }
    }

    fn temp_registry_path() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "chio-federation-admission-policy-registry-{nonce}.json"
        ))
    }

    #[test]
    fn invalid_record_schema_uses_cli_registry_domain() {
        let mut record = signed_record();
        record.schema = "unsupported".to_string();

        let error = verify_federation_admission_policy_record(&record).test_unwrap_err();

        assert_cli_other_error(error, "unsupported federation admission policy schema");
    }

    #[test]
    fn invalid_reputation_score_uses_cli_registry_domain() {
        let mut record = signed_record();
        record.minimum_reputation_score = Some(1.1);

        let error = verify_federation_admission_policy_record(&record).test_unwrap_err();

        assert_cli_other_error(error, "minimum_reputation_score");
    }

    #[test]
    fn invalid_anti_sybil_controls_use_cli_registry_domain() {
        let mut record = signed_record();
        record.anti_sybil.proof_of_work_bits = Some(25);

        let error = verify_federation_admission_policy_record(&record).test_unwrap_err();

        assert_cli_other_error(error, "anti_sybil.proof_of_work_bits");
    }

    #[test]
    fn load_rejects_policy_map_key_that_differs_from_signed_policy_id() {
        let path = temp_registry_path();
        let mut registry = FederationAdmissionPolicyRegistry::default();
        registry
            .policies
            .insert("open-admission-alias".to_string(), signed_record());
        fs::write(&path, serde_json::to_vec_pretty(&registry).test_unwrap()).test_unwrap();

        let result = FederationAdmissionPolicyRegistry::load(&path);
        let _ = fs::remove_file(&path);
        let error = result.test_unwrap_err();

        assert_cli_other_error(
            error,
            "federation policy map key must match signed policy body policy_id",
        );
    }
}
