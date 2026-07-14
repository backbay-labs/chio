//! Local Chio pheromone substrate and observation-cost evidence types.

#![forbid(unsafe_code)]

use std::sync::PoisonError;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::hashing::Hash;
use chio_core_types::merkle::MerkleProof;
use chio_core_types::{Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod substrate;
mod validation;

pub use substrate::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
pub use validation::validate_scarcity_policy_material;
use validation::{
    accepted_deposit_treaties, canonical_sha256, deposit_signature_body,
    newcomer_horizon_for_subject, resolve_passport, scarcity_policy_is_active,
    scarcity_windows_overlap, subject_policy, validate_deposit_static, verify_deposit_signature,
    verify_observation_cost_commitment,
};

pub const PHEROMONE_DEPOSIT_SCHEMA: &str = "chio.pheromone-deposit.v1";
pub const PHEROMONE_COST_COMMITMENT_SCHEMA: &str = "chio.pheromone-cost-commitment.v1";
pub const PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA: &str =
    "chio.pheromone-observation-cost-statement.v1";
pub const PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA: &str =
    "chio.pheromone-observation-cost-telemetry-root.v1";
pub const PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA: &str = "chio.pheromone-observation-cost-leaf.v1";
pub const PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA: &str =
    "chio.pheromone-observation-cost-verifier-root.v1";
pub const PHEROMONE_WORKFLOW_CONTEXT_SCHEMA: &str = "chio.pheromone-workflow-context.v1";
pub const PHEROMONE_CONCENTRATION_SCHEMA: &str = "chio.pheromone-concentration.v1";
pub const PHEROMONE_SCARCITY_POLICY_SCHEMA: &str = "chio.pheromone-scarcity-policy.v1";
pub const PHEROMONE_SCARCITY_WINDOW_ID_SCHEMA: &str = "chio.pheromone-scarcity-window-id.v1";
pub const OBSERVATION_COST_UNIT: &str = "chio.observation.microunit.v1";
pub const OBSERVATION_COST_TELEMETRY_ALGORITHM: &str = "rfc6962-sha256-v1";
pub const RUNTIME_TRUST_FLOOR_STATE_SCHEMA: &str = "chio.runtime.trust-floor-state.v1";
pub const DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS: u64 = 8;

#[derive(Debug, thiserror::Error)]
pub enum PheromoneError {
    #[error("unsupported_schema: {0}")]
    UnsupportedSchema(String),
    #[error("signature_invalid: deposit signature does not verify")]
    SignatureInvalid,
    #[error("signature_key_mismatch: {0}")]
    SignatureKeyMismatch(String),
    #[error("kernel_key_used_for_deposit: deposit was signed by a kernel key")]
    KernelKeyUsedForDeposit,
    #[error("unknown_origin_agent: {0}")]
    UnknownOriginAgent(String),
    #[error("replay_window_exceeded: {0}")]
    ReplayWindowExceeded(String),
    #[error("deposit_from_future: {0}")]
    DepositFromFuture(String),
    #[error("treaty_scope_violation: {0}")]
    TreatyScopeViolation(String),
    #[error("subject_class_unknown: {0}")]
    SubjectClassUnknown(String),
    #[error("observation_cost_commitment_missing: {0}")]
    ObservationCostCommitmentMissing(String),
    #[error("observation_cost_commitment_required: {0}")]
    ObservationCostCommitmentRequired(String),
    #[error("observation_cost_commitment_unverified: {0}")]
    ObservationCostCommitmentUnverified(String),
    #[error("observation_cost_commitment_schema_invalid: {0}")]
    ObservationCostCommitmentSchemaInvalid(String),
    #[error("observation_cost_policy_mismatch: {0}")]
    ObservationCostPolicyMismatch(String),
    #[error("observation_cost_verifier_untrusted: {0}")]
    ObservationCostVerifierUntrusted(String),
    #[error("observation_cost_signature_invalid: {0}")]
    ObservationCostSignatureInvalid(String),
    #[error("observation_cost_telemetry_root_mismatch: {0}")]
    ObservationCostTelemetryRootMismatch(String),
    #[error("observation_cost_inclusion_invalid: {0}")]
    ObservationCostInclusionInvalid(String),
    #[error("observation_cost_window_mismatch: {0}")]
    ObservationCostWindowMismatch(String),
    #[error("observation_cost_revoked: {0}")]
    ObservationCostRevoked(String),
    #[error("observation_cost_unit_invalid: {0}")]
    ObservationCostUnitInvalid(String),
    #[error("observation_cost_leaf_mismatch: {0}")]
    ObservationCostLeafMismatch(String),
    #[error("observation_cost_runtime_policy_mismatch: {0}")]
    ObservationCostRuntimePolicyMismatch(String),
    #[error("scarcity_policy_missing: {0}")]
    ScarcityPolicyMissing(String),
    #[error("scarcity_policy_ambiguous: {0}")]
    ScarcityPolicyAmbiguous(String),
    #[error("scarcity_policy_invalid: {0}")]
    ScarcityPolicyInvalid(String),
    #[error("scarcity_window_stale: {0}")]
    ScarcityWindowStale(String),
    #[error("invalid_newcomer_horizon: {0}")]
    InvalidNewcomerHorizon(u64),
    #[error("rate_limit_exhausted: {0}")]
    RateLimitExhausted(String),
    #[error("diversity_cap_exceeded: {0}")]
    DiversityCapExceeded(String),
    #[error("sqrt_n_passport_cap_exceeded: {0}")]
    SqrtNPassportCapExceeded(String),
    #[error("unknown_reputation_epoch: {0}")]
    UnknownReputationEpoch(u64),
    #[error("weight_out_of_range: {0}")]
    WeightOutOfRange(String),
    #[error("confidence_out_of_range: {0}")]
    ConfidenceOutOfRange(f64),
    #[error("half_life_invalid: {0}")]
    HalfLifeInvalid(f64),
    #[error("evaporation_floor_invalid: {0}")]
    EvaporationFloorInvalid(f64),
    #[error("workflow_context_mismatch: {0}")]
    WorkflowContextMismatch(String),
    #[error("invalid_field: {0}")]
    InvalidField(String),
    #[error("store_poisoned: pheromone store lock is poisoned")]
    StorePoisoned,
    #[error("canonical_json: {0}")]
    CanonicalJson(String),
}

impl PheromoneError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignatureKeyMismatch(_) => "signature_key_mismatch",
            Self::KernelKeyUsedForDeposit => "kernel_key_used_for_deposit",
            Self::UnknownOriginAgent(_) => "unknown_origin_agent",
            Self::ReplayWindowExceeded(_) => "replay_window_exceeded",
            Self::DepositFromFuture(_) => "deposit_from_future",
            Self::TreatyScopeViolation(_) => "treaty_scope_violation",
            Self::SubjectClassUnknown(_) => "subject_class_unknown",
            Self::ObservationCostCommitmentMissing(_) => "observation_cost_commitment_missing",
            Self::ObservationCostCommitmentRequired(_) => "observation_cost_commitment_required",
            Self::ObservationCostCommitmentUnverified(_) => {
                "observation_cost_commitment_unverified"
            }
            Self::ObservationCostCommitmentSchemaInvalid(_) => {
                "observation_cost_commitment_schema_invalid"
            }
            Self::ObservationCostPolicyMismatch(_) => "observation_cost_policy_mismatch",
            Self::ObservationCostVerifierUntrusted(_) => "observation_cost_verifier_untrusted",
            Self::ObservationCostSignatureInvalid(_) => "observation_cost_signature_invalid",
            Self::ObservationCostTelemetryRootMismatch(_) => {
                "observation_cost_telemetry_root_mismatch"
            }
            Self::ObservationCostInclusionInvalid(_) => "observation_cost_inclusion_invalid",
            Self::ObservationCostWindowMismatch(_) => "observation_cost_window_mismatch",
            Self::ObservationCostRevoked(_) => "observation_cost_revoked",
            Self::ObservationCostUnitInvalid(_) => "observation_cost_unit_invalid",
            Self::ObservationCostLeafMismatch(_) => "observation_cost_leaf_mismatch",
            Self::ObservationCostRuntimePolicyMismatch(_) => {
                "observation_cost_runtime_policy_mismatch"
            }
            Self::ScarcityPolicyMissing(_) => "scarcity_policy_missing",
            Self::ScarcityPolicyAmbiguous(_) => "scarcity_policy_ambiguous",
            Self::ScarcityPolicyInvalid(_) => "scarcity_policy_invalid",
            Self::ScarcityWindowStale(_) => "scarcity_window_stale",
            Self::InvalidNewcomerHorizon(_) => "invalid_newcomer_horizon",
            Self::RateLimitExhausted(_) => "rate_limit_exhausted",
            Self::DiversityCapExceeded(_) => "diversity_cap_exceeded",
            Self::SqrtNPassportCapExceeded(_) => "sqrt_n_passport_cap_exceeded",
            Self::UnknownReputationEpoch(_) => "unknown_reputation_epoch",
            Self::WeightOutOfRange(_) => "weight_out_of_range",
            Self::ConfidenceOutOfRange(_) => "confidence_out_of_range",
            Self::HalfLifeInvalid(_) => "half_life_invalid",
            Self::EvaporationFloorInvalid(_) => "evaporation_floor_invalid",
            Self::WorkflowContextMismatch(_) => "workflow_context_mismatch",
            Self::InvalidField(_) => "invalid_field",
            Self::StorePoisoned => "store_poisoned",
            Self::CanonicalJson(_) => "canonical_json",
        }
    }
}

impl<T> From<PoisonError<T>> for PheromoneError {
    fn from(_: PoisonError<T>) -> Self {
        Self::StorePoisoned
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneCostCommitment {
    pub schema: String,
    pub statement: PheromoneObservationCostStatement,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostAmount {
    pub unit: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostTelemetryRoot {
    pub schema: String,
    pub algorithm: String,
    pub root_hash: Hash,
    pub tree_size: usize,
    pub verifier_id: String,
    pub verifier_key_id: String,
    pub closed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostStatement {
    pub schema: String,
    pub commitment_id: String,
    pub verifier_id: String,
    pub verifier_key_id: String,
    pub runtime_policy_sha256: String,
    pub scarcity_policy_sha256: String,
    pub deposit_body_sha256: String,
    pub deposit_signature_sha256: String,
    pub kernel_id: String,
    pub agent_passport_key_hash: String,
    pub treaty_id: String,
    pub subject_class_namespace: String,
    pub subject_class: String,
    pub observation_window_start_unix_ms: u64,
    pub observation_window_end_unix_ms: u64,
    pub observed_at_unix_ms: u64,
    pub event_digest_sha256: String,
    pub cost: PheromoneObservationCostAmount,
    pub telemetry: PheromoneObservationCostTelemetryRoot,
    pub inclusion_proof: MerkleProof,
    pub leaf_preimage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostLeaf {
    pub schema: String,
    pub deposit_body_sha256: String,
    pub deposit_signature_sha256: String,
    pub kernel_id: String,
    pub agent_passport_key_hash: String,
    pub treaty_id: String,
    pub subject_class_namespace: String,
    pub subject_class: String,
    pub observed_at_unix_ms: u64,
    pub event_digest_sha256: String,
    pub cost: PheromoneObservationCostAmount,
    pub scarcity_policy_sha256: String,
    pub runtime_policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostVerifierRootBody {
    pub schema: String,
    pub verifier_id: String,
    pub verifier_key_id: String,
    pub public_key: PublicKey,
    pub signature_algorithm: SigningAlgorithm,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub allowed_treaties: Vec<String>,
    pub allowed_subject_class_namespaces: Vec<String>,
    pub allowed_subject_classes: Vec<String>,
    pub runtime_policy_sha256: String,
    pub issuer_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneObservationCostVerifierRoot {
    #[serde(flatten)]
    pub body: PheromoneObservationCostVerifierRootBody,
    pub issuer_signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneRuntimeTrustFloorEntry {
    pub verifier_id: String,
    pub key_id: String,
    pub highest_version: u64,
    pub latest_bundle_sha256: String,
    pub latest_revocation_checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneRuntimeTrustFloorState {
    pub schema: String,
    pub entries: Vec<PheromoneRuntimeTrustFloorEntry>,
}

impl Default for PheromoneRuntimeTrustFloorState {
    fn default() -> Self {
        Self {
            schema: RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string(),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneWorkflowContext {
    pub schema: String,
    pub workflow_id: String,
    pub workflow_receipt_id: String,
    pub workflow_receipt_sha256: String,
    pub workflow_intersection_id: String,
    pub workflow_intersection_sha256: String,
    pub step_index: u64,
    pub tool_receipt_id: String,
    pub bilateral_dsse_sha256: String,
    pub consistency_anchor: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneDepositBody {
    pub schema: String,
    pub kernel_id: String,
    pub agent_passport_key_hash: String,
    pub agent_passport_jwk_thumbprint: String,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub indicator: Value,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp_unix_ms: u64,
    pub decay_half_life_secs: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaporation_floor: Option<f64>,
    pub nonce: String,
    pub treaty_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_commitment: Option<PheromoneCostCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_context: Option<PheromoneWorkflowContext>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneDeposit {
    #[serde(flatten)]
    pub body: PheromoneDepositBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneConcentration {
    pub schema: String,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub total_strength: f64,
    pub unweighted_total_strength: f64,
    pub distinct_origin_pairs: u64,
    pub peak_confidence: f64,
    pub reputation_epoch: u64,
    pub evaluated_at_unix_ms: u64,
    pub treaty_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostCommitmentPolicy {
    NotRequired,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCostVerificationMode {
    NotRequired,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneScarcityPolicy {
    pub schema: String,
    pub policy_id: String,
    pub reputation_epoch: u64,
    pub window_id: String,
    pub window_start_unix_ms: u64,
    pub window_end_unix_ms: u64,
    pub token_capacity: u64,
    pub newcomer_horizon_epochs: u64,
    pub treaty_scope: Vec<String>,
    pub subject_class_namespace: String,
    pub subject_class: String,
    pub observation_cost_verification: ObservationCostVerificationMode,
    pub verifier_id: String,
    pub runtime_policy_sha256: String,
    pub policy_sha256: String,
    pub active_peers_epoch: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PheromoneScarcityWindowIdPreimage<'a> {
    schema: &'a str,
    reputation_epoch: u64,
    window_start_unix_ms: u64,
    window_end_unix_ms: u64,
    treaty_id: &'a str,
    subject_class_namespace: &'a str,
    subject_class: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PheromoneScarcityAdmission {
    pub reputation_epoch: u64,
    pub window_id: String,
    pub treaty_id: String,
    pub subject_class_namespace: String,
    pub subject_class: String,
    pub token_capacity: u64,
    pub newcomer_horizon_epochs: u64,
    pub active_peers_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectClassPolicy {
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub allowed_treaties: Vec<String>,
    pub cost_commitment: CostCommitmentPolicy,
    pub destructive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportAdmission {
    pub kernel_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub first_seen_epoch: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PheromoneValidationContext {
    pub now_unix_ms: u64,
    pub replay_window_ms: u64,
    pub active_peers_in_treaty: u64,
    pub active_reputation_epoch: u64,
    pub known_reputation_epochs: Vec<u64>,
    pub passports: Vec<PassportAdmission>,
    pub kernel_public_keys: Vec<PublicKey>,
    pub subject_classes: Vec<SubjectClassPolicy>,
    pub max_deposits_per_pair: u64,
    pub scarcity_policies: Vec<PheromoneScarcityPolicy>,
    pub runtime_policy_sha256: Option<String>,
    pub runtime_policy_issuer_public_keys: Vec<PublicKey>,
    pub observation_cost_verifier_roots: Vec<PheromoneObservationCostVerifierRoot>,
    pub runtime_trust_floor_state: PheromoneRuntimeTrustFloorState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositQuery {
    pub subject_class: Option<String>,
    pub treaty_id: Option<String>,
}

pub fn sign_deposit(
    body: PheromoneDepositBody,
    keypair: &Keypair,
) -> Result<PheromoneDeposit, PheromoneError> {
    let canonical = canonical_json_bytes(&deposit_signature_body(&body))
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    Ok(PheromoneDeposit {
        body,
        signature: keypair.sign(&canonical),
    })
}

pub fn validate_deposit_for_admission(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
) -> Result<PassportAdmission, PheromoneError> {
    validate_deposit_static(deposit, context)?;
    let passport = resolve_passport(deposit, context)?;
    verify_deposit_signature(deposit, &passport.public_key)?;
    Ok(passport.clone())
}

pub fn scarcity_admissions_for_deposit(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
) -> Result<Vec<PheromoneScarcityAdmission>, PheromoneError> {
    let body = &deposit.body;
    let subject = subject_policy(body, context)?;
    let accepted_treaties = accepted_deposit_treaties(body, subject);
    if accepted_treaties.is_empty() {
        return Err(PheromoneError::TreatyScopeViolation(format!(
            "deposit has no treaty accepted for {}",
            body.subject_class
        )));
    }
    scarcity_admissions_for_treaties(deposit, context, accepted_treaties)
}

pub fn scarcity_admissions_for_deposit_treaty(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    treaty_id: &str,
) -> Result<Vec<PheromoneScarcityAdmission>, PheromoneError> {
    let body = &deposit.body;
    let subject = subject_policy(body, context)?;
    if !body.treaty_scope.iter().any(|treaty| treaty == treaty_id)
        || !subject
            .allowed_treaties
            .iter()
            .any(|allowed| allowed == treaty_id)
    {
        return Err(PheromoneError::TreatyScopeViolation(format!(
            "frame treaty {treaty_id} is not accepted for {}",
            body.subject_class
        )));
    }
    scarcity_admissions_for_treaties(deposit, context, vec![treaty_id.to_string()])
}

fn scarcity_admissions_for_treaties(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    accepted_treaties: Vec<String>,
) -> Result<Vec<PheromoneScarcityAdmission>, PheromoneError> {
    let body = &deposit.body;
    if context.scarcity_policies.is_empty() {
        return Err(PheromoneError::ScarcityPolicyMissing(format!(
            "{}:{} has no receiver-owned scarcity policy",
            body.subject_class_namespace, body.subject_class
        )));
    }

    let mut admissions = Vec::new();
    for treaty_id in accepted_treaties {
        let candidates = context
            .scarcity_policies
            .iter()
            .filter(|policy| {
                policy.subject_class == body.subject_class
                    && policy.subject_class_namespace == body.subject_class_namespace
                    && policy
                        .treaty_scope
                        .iter()
                        .any(|treaty| treaty == &treaty_id)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(PheromoneError::ScarcityPolicyMissing(format!(
                "{}:{} treaty {}",
                body.subject_class_namespace, body.subject_class, treaty_id
            )));
        }
        let mut active = Vec::new();
        for policy in candidates {
            validate_scarcity_policy_material(policy, context)?;
            if scarcity_policy_is_active(policy, context) {
                active.push(policy);
            }
        }
        let policy = match active.as_slice() {
            [] => {
                return Err(PheromoneError::ScarcityWindowStale(format!(
                    "{}:{} treaty {}",
                    body.subject_class_namespace, body.subject_class, treaty_id
                )));
            }
            [policy] => *policy,
            _ => {
                return Err(PheromoneError::ScarcityPolicyAmbiguous(format!(
                    "multiple active scarcity policies match {}:{} treaty {}",
                    body.subject_class_namespace, body.subject_class, treaty_id
                )))
            }
        };
        if !policy
            .treaty_scope
            .iter()
            .any(|treaty| treaty == &treaty_id)
        {
            return Err(PheromoneError::ScarcityPolicyMissing(format!(
                "{} does not include treaty {}",
                policy.policy_id, treaty_id
            )));
        }
        let expected_window_id = scarcity_window_id(policy, &treaty_id)?;
        if policy.window_id != expected_window_id {
            return Err(PheromoneError::ScarcityPolicyInvalid(format!(
                "{} window id {} does not match deterministic id {}",
                policy.policy_id, policy.window_id, expected_window_id
            )));
        }
        if policy.observation_cost_verification == ObservationCostVerificationMode::Required {
            verify_observation_cost_commitment(deposit, policy, context, &treaty_id)?;
        }
        admissions.push(PheromoneScarcityAdmission {
            reputation_epoch: policy.reputation_epoch,
            window_id: policy.window_id.clone(),
            treaty_id,
            subject_class_namespace: body.subject_class_namespace.clone(),
            subject_class: body.subject_class.clone(),
            token_capacity: policy.token_capacity,
            newcomer_horizon_epochs: policy.newcomer_horizon_epochs,
            active_peers_epoch: policy.active_peers_epoch,
        });
    }
    Ok(admissions)
}

pub fn reject_overlapping_scarcity_windows(
    policies: &[PheromoneScarcityPolicy],
) -> Result<(), PheromoneError> {
    for (left_index, left) in policies.iter().enumerate() {
        for right in policies.iter().skip(left_index + 1) {
            if left.reputation_epoch != right.reputation_epoch
                || left.subject_class_namespace != right.subject_class_namespace
                || left.subject_class != right.subject_class
                || !scarcity_windows_overlap(left, right)
            {
                continue;
            }
            if let Some(treaty_id) = left.treaty_scope.iter().find(|left_treaty| {
                right
                    .treaty_scope
                    .iter()
                    .any(|right_treaty| right_treaty == *left_treaty)
            }) {
                return Err(PheromoneError::ScarcityPolicyAmbiguous(format!(
                    "overlapping scarcity windows for epoch {} treaty {} {}:{}",
                    left.reputation_epoch,
                    treaty_id,
                    left.subject_class_namespace,
                    left.subject_class
                )));
            }
        }
    }
    Ok(())
}

pub fn scarcity_window_id(
    policy: &PheromoneScarcityPolicy,
    treaty_id: &str,
) -> Result<String, PheromoneError> {
    canonical_sha256(&PheromoneScarcityWindowIdPreimage {
        schema: PHEROMONE_SCARCITY_WINDOW_ID_SCHEMA,
        reputation_epoch: policy.reputation_epoch,
        window_start_unix_ms: policy.window_start_unix_ms,
        window_end_unix_ms: policy.window_end_unix_ms,
        treaty_id,
        subject_class_namespace: &policy.subject_class_namespace,
        subject_class: &policy.subject_class,
    })
}

pub fn scarcity_policy_sha256(policy: &PheromoneScarcityPolicy) -> Result<String, PheromoneError> {
    let mut value = serde_json::to_value(policy)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        PheromoneError::CanonicalJson("scarcity policy did not serialize as an object".to_string())
    })?;
    object.remove("policySha256");
    canonical_sha256(&value)
}

pub fn newcomer_discount_for_deposit(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    reputation_epoch: u64,
    subject_class_namespace: &str,
    subject_class: &str,
) -> Result<f64, PheromoneError> {
    let horizon = newcomer_horizon_for_subject(
        context,
        reputation_epoch,
        subject_class_namespace,
        subject_class,
    )?;
    let first_seen = context
        .passports
        .iter()
        .find(|passport| {
            passport.kernel_id == deposit.body.kernel_id
                && agent_passport_key_hash(&passport.public_key)
                    == deposit.body.agent_passport_key_hash
        })
        .map(|passport| passport.first_seen_epoch)
        .unwrap_or(reputation_epoch);
    let age = reputation_epoch
        .saturating_sub(first_seen)
        .saturating_add(1);
    Ok((age as f64 / horizon as f64).min(1.0))
}

#[must_use]
pub fn default_newcomer_discount_horizon_epochs() -> u64 {
    DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS
}

#[must_use]
pub fn agent_passport_key_hash(public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    match public_key.algorithm() {
        SigningAlgorithm::Ed25519 => hasher.update(public_key.as_bytes()),
        _ => hasher.update(public_key.to_hex().as_bytes()),
    }
    hex::encode(hasher.finalize())
}

#[must_use]
pub fn agent_passport_jwk_thumbprint(public_key: &PublicKey) -> String {
    let x = match public_key.algorithm() {
        SigningAlgorithm::Ed25519 => URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
        _ => URL_SAFE_NO_PAD.encode(public_key.to_hex().as_bytes()),
    };
    let jwk = serde_json::json!({
        "crv": "Ed25519",
        "kty": "OKP",
        "x": x,
    });
    let canonical = canonical_json_bytes(&jwk).unwrap_or_else(|_| b"{}".to_vec());
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
