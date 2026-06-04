//! Local Chio pheromone substrate and transit evidence types.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::hashing::Hash;
use chio_core_types::merkle::MerkleProof;
use chio_core_types::{Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

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

pub trait PheromoneSubstrate {
    fn deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneError>;

    fn query_deposits(&self, query: &DepositQuery)
        -> Result<Vec<PheromoneDeposit>, PheromoneError>;

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn Fn(&str, u64) -> f64,
    ) -> Result<PheromoneConcentration, PheromoneError>;

    fn gc_evaporated(&self, now_unix_ms: u64) -> Result<usize, PheromoneError>;
}

type ScarcityBucketKey = (u64, String, String, String, String);
type PairBucketKey = (u64, String, String, String, String, String, String);
type PassportCapKey = (u64, String, String, String, String, String);

#[derive(Debug, Default)]
pub struct InMemoryPheromoneSubstrate {
    deposits: Mutex<Vec<PheromoneDeposit>>,
    seen_nonces: Mutex<BTreeSet<(String, String, String)>>,
    scarcity_buckets: Mutex<BTreeMap<ScarcityBucketKey, u64>>,
    pair_counts: Mutex<BTreeMap<PairBucketKey, u64>>,
    passports_by_kernel_class: Mutex<BTreeMap<PassportCapKey, BTreeSet<String>>>,
}

impl InMemoryPheromoneSubstrate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PheromoneSubstrate for InMemoryPheromoneSubstrate {
    fn deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneError> {
        validate_deposit_for_admission(&deposit, context)?;
        commit_admission_state(
            &deposit,
            &self.seen_nonces,
            context,
            &self.scarcity_buckets,
            &self.pair_counts,
            &self.passports_by_kernel_class,
        )?;
        self.deposits.lock()?.push(deposit);
        Ok(())
    }

    fn query_deposits(
        &self,
        query: &DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneError> {
        let guard = self.deposits.lock()?;
        Ok(guard
            .iter()
            .filter(|deposit| {
                query
                    .subject_class
                    .as_deref()
                    .map(|value| value == deposit.body.subject_class)
                    .unwrap_or(true)
            })
            .filter(|deposit| {
                query
                    .treaty_id
                    .as_deref()
                    .map(|value| {
                        deposit
                            .body
                            .treaty_scope
                            .iter()
                            .any(|treaty| treaty == value)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect())
    }

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn Fn(&str, u64) -> f64,
    ) -> Result<PheromoneConcentration, PheromoneError> {
        if !context.known_reputation_epochs.contains(&reputation_epoch) {
            return Err(PheromoneError::UnknownReputationEpoch(reputation_epoch));
        }
        let guard = self.deposits.lock()?;
        let mut total_strength = 0.0;
        let mut unweighted_total_strength = 0.0;
        let mut peak_confidence = 0.0;
        let mut origins = BTreeSet::new();
        let mut treaties = BTreeSet::new();
        for deposit in guard.iter().filter(|deposit| {
            deposit.body.subject_class == subject_class
                && deposit.body.subject_class_namespace == subject_class_namespace
        }) {
            let strength = strength_at(deposit, now_unix_ms);
            if let Some(floor) = deposit.body.evaporation_floor {
                if strength < floor {
                    continue;
                }
            }
            let weight = peer_weight(&deposit.body.kernel_id, reputation_epoch);
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return Err(PheromoneError::WeightOutOfRange(format!(
                    "weight for {} at epoch {} was {}",
                    deposit.body.kernel_id, reputation_epoch, weight
                )));
            }
            let discount = newcomer_discount_for_deposit(
                deposit,
                context,
                reputation_epoch,
                subject_class_namespace,
                subject_class,
            )?;
            total_strength += strength * weight * discount;
            unweighted_total_strength += strength;
            if deposit.body.confidence > peak_confidence {
                peak_confidence = deposit.body.confidence;
            }
            origins.insert((
                deposit.body.kernel_id.clone(),
                deposit.body.agent_passport_key_hash.clone(),
            ));
            for treaty in &deposit.body.treaty_scope {
                treaties.insert(treaty.clone());
            }
        }
        Ok(PheromoneConcentration {
            schema: PHEROMONE_CONCENTRATION_SCHEMA.to_string(),
            subject_class: subject_class.to_string(),
            subject_class_namespace: subject_class_namespace.to_string(),
            total_strength,
            unweighted_total_strength,
            distinct_origin_pairs: origins.len() as u64,
            peak_confidence,
            reputation_epoch,
            evaluated_at_unix_ms: now_unix_ms,
            treaty_scopes: treaties.into_iter().collect(),
        })
    }

    fn gc_evaporated(&self, now_unix_ms: u64) -> Result<usize, PheromoneError> {
        let mut guard = self.deposits.lock()?;
        let before = guard.len();
        guard.retain(|deposit| {
            let floor = deposit.body.evaporation_floor.unwrap_or(0.01);
            strength_at(deposit, now_unix_ms) >= floor
        });
        Ok(before.saturating_sub(guard.len()))
    }
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

fn validate_deposit_static(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    if body.schema != PHEROMONE_DEPOSIT_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(body.schema.clone()));
    }
    validate_non_empty(&body.kernel_id, "kernel_id")?;
    validate_non_empty(&body.agent_passport_key_hash, "agent_passport_key_hash")?;
    validate_non_empty(
        &body.agent_passport_jwk_thumbprint,
        "agent_passport_jwk_thumbprint",
    )?;
    validate_non_empty(&body.subject_class, "subject_class")?;
    validate_non_empty(&body.subject_class_namespace, "subject_class_namespace")?;
    validate_non_empty(&body.nonce, "nonce")?;
    validate_unique_non_empty_strings(&body.treaty_scope, "treaty_scope")?;
    if !body.confidence.is_finite() || !(0.0..=1.0).contains(&body.confidence) {
        return Err(PheromoneError::ConfidenceOutOfRange(body.confidence));
    }
    if !body.decay_half_life_secs.is_finite() || body.decay_half_life_secs <= 0.0 {
        return Err(PheromoneError::HalfLifeInvalid(body.decay_half_life_secs));
    }
    if let Some(floor) = body.evaporation_floor {
        if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
            return Err(PheromoneError::EvaporationFloorInvalid(floor));
        }
    }
    if let Some(commitment) = &body.cost_commitment {
        if commitment.schema != PHEROMONE_COST_COMMITMENT_SCHEMA {
            return Err(PheromoneError::UnsupportedSchema(commitment.schema.clone()));
        }
        validate_cost_commitment_static(commitment)?;
    }
    if let Some(workflow) = &body.workflow_context {
        validate_workflow_context(workflow)?;
    }
    let policy = subject_policy(body, context)?;
    if policy
        .allowed_treaties
        .iter()
        .all(|treaty| !body.treaty_scope.contains(treaty))
    {
        return Err(PheromoneError::TreatyScopeViolation(format!(
            "deposit has no treaty accepted for {}",
            body.subject_class
        )));
    }
    if (policy.destructive || policy.cost_commitment == CostCommitmentPolicy::Required)
        && body.cost_commitment.is_none()
    {
        return Err(PheromoneError::ObservationCostCommitmentMissing(
            body.subject_class.clone(),
        ));
    }
    let _admissions = scarcity_admissions_for_deposit(deposit, context)?;
    if body
        .timestamp_unix_ms
        .saturating_add(context.replay_window_ms)
        < context.now_unix_ms
    {
        return Err(PheromoneError::ReplayWindowExceeded(body.nonce.clone()));
    }
    if body.timestamp_unix_ms > context.now_unix_ms {
        return Err(PheromoneError::DepositFromFuture(body.nonce.clone()));
    }
    Ok(())
}

fn validate_workflow_context(workflow: &PheromoneWorkflowContext) -> Result<(), PheromoneError> {
    if workflow.schema != PHEROMONE_WORKFLOW_CONTEXT_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(workflow.schema.clone()));
    }
    validate_non_empty(&workflow.workflow_id, "workflow_id")?;
    validate_non_empty(&workflow.workflow_receipt_id, "workflow_receipt_id")?;
    validate_hex64(&workflow.workflow_receipt_sha256, "workflow_receipt_sha256")?;
    validate_non_empty(
        &workflow.workflow_intersection_id,
        "workflow_intersection_id",
    )?;
    validate_hex64(
        &workflow.workflow_intersection_sha256,
        "workflow_intersection_sha256",
    )?;
    validate_non_empty(&workflow.tool_receipt_id, "tool_receipt_id")?;
    validate_hex64(&workflow.bilateral_dsse_sha256, "bilateral_dsse_sha256")?;
    validate_non_empty(&workflow.consistency_anchor, "consistency_anchor")?;
    Ok(())
}

fn resolve_passport<'a>(
    deposit: &PheromoneDeposit,
    context: &'a PheromoneValidationContext,
) -> Result<&'a PassportAdmission, PheromoneError> {
    for kernel_key in &context.kernel_public_keys {
        if agent_passport_key_hash(kernel_key) == deposit.body.agent_passport_key_hash
            && verify_deposit_signature(deposit, kernel_key).is_ok()
        {
            return Err(PheromoneError::KernelKeyUsedForDeposit);
        }
    }
    let passport = context
        .passports
        .iter()
        .find(|passport| {
            passport.kernel_id == deposit.body.kernel_id
                && agent_passport_key_hash(&passport.public_key)
                    == deposit.body.agent_passport_key_hash
        })
        .ok_or_else(|| PheromoneError::UnknownOriginAgent(deposit.body.kernel_id.clone()))?;
    if passport.revoked
        || passport.valid_from_unix_ms > deposit.body.timestamp_unix_ms
        || passport.valid_until_unix_ms <= deposit.body.timestamp_unix_ms
    {
        return Err(PheromoneError::UnknownOriginAgent(
            deposit.body.kernel_id.clone(),
        ));
    }
    if agent_passport_jwk_thumbprint(&passport.public_key)
        != deposit.body.agent_passport_jwk_thumbprint
    {
        return Err(PheromoneError::SignatureKeyMismatch(
            "JWK thumbprint mismatch".to_string(),
        ));
    }
    Ok(passport)
}

fn verify_deposit_signature(
    deposit: &PheromoneDeposit,
    public_key: &PublicKey,
) -> Result<(), PheromoneError> {
    let canonical = canonical_json_bytes(&deposit_signature_body(&deposit.body))
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if public_key.verify(&canonical, &deposit.signature) {
        Ok(())
    } else {
        Err(PheromoneError::SignatureInvalid)
    }
}

fn deposit_signature_body(body: &PheromoneDepositBody) -> PheromoneDepositBody {
    let mut signed = body.clone();
    signed.cost_commitment = None;
    signed
}

fn commit_admission_state(
    deposit: &PheromoneDeposit,
    seen_nonces: &Mutex<BTreeSet<(String, String, String)>>,
    context: &PheromoneValidationContext,
    scarcity_buckets: &Mutex<BTreeMap<ScarcityBucketKey, u64>>,
    pair_counts: &Mutex<BTreeMap<PairBucketKey, u64>>,
    passports_by_kernel_class: &Mutex<BTreeMap<PassportCapKey, BTreeSet<String>>>,
) -> Result<(), PheromoneError> {
    let admissions = scarcity_admissions_for_deposit(deposit, context)?;
    let nonce_key = (
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
        deposit.body.nonce.clone(),
    );

    let mut seen = seen_nonces.lock()?;
    if seen.contains(&nonce_key) {
        return Err(PheromoneError::ReplayWindowExceeded(
            deposit.body.nonce.clone(),
        ));
    }
    let mut buckets = scarcity_buckets.lock()?;
    let mut counts = pair_counts.lock()?;
    let mut by_kernel = passports_by_kernel_class.lock()?;

    for admission in &admissions {
        let scarcity_key = scarcity_bucket_key(admission);
        let bucket_count = buckets.get(&scarcity_key).copied().unwrap_or(0);
        if bucket_count >= admission.token_capacity {
            return Err(PheromoneError::RateLimitExhausted(format!(
                "{}:{}:{}:{}",
                admission.reputation_epoch,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class
            )));
        }
        let pair_key = pair_bucket_key(deposit, admission);
        let count = counts.get(&pair_key).copied().unwrap_or(0);
        if count >= context.max_deposits_per_pair {
            return Err(PheromoneError::DiversityCapExceeded(
                deposit.body.agent_passport_key_hash.clone(),
            ));
        }

        let passport_key = passport_cap_key(deposit, admission);
        let cap = sqrt_passport_cap(context.active_peers_in_treaty);
        let passport_seen = by_kernel
            .get(&passport_key)
            .map(|passports| passports.contains(&deposit.body.agent_passport_key_hash))
            .unwrap_or(false);
        let projected_passport_count = by_kernel
            .get(&passport_key)
            .map(BTreeSet::len)
            .unwrap_or(0)
            .saturating_add(usize::from(!passport_seen));
        if projected_passport_count as u64 > cap {
            return Err(PheromoneError::SqrtNPassportCapExceeded(
                deposit.body.kernel_id.clone(),
            ));
        }
    }

    seen.insert(nonce_key);
    for admission in &admissions {
        let scarcity_key = scarcity_bucket_key(admission);
        let count = buckets.get(&scarcity_key).copied().unwrap_or(0);
        buckets.insert(scarcity_key, count.saturating_add(1));
        let pair_key = pair_bucket_key(deposit, admission);
        let pair_count = counts.get(&pair_key).copied().unwrap_or(0);
        counts.insert(pair_key, pair_count.saturating_add(1));
        by_kernel
            .entry(passport_cap_key(deposit, admission))
            .or_default()
            .insert(deposit.body.agent_passport_key_hash.clone());
    }
    Ok(())
}

fn scarcity_bucket_key(admission: &PheromoneScarcityAdmission) -> ScarcityBucketKey {
    (
        admission.reputation_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
    )
}

fn pair_bucket_key(
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> PairBucketKey {
    (
        admission.reputation_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
    )
}

fn passport_cap_key(
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> PassportCapKey {
    (
        admission.active_peers_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
        deposit.body.kernel_id.clone(),
    )
}

fn subject_policy<'a>(
    body: &PheromoneDepositBody,
    context: &'a PheromoneValidationContext,
) -> Result<&'a SubjectClassPolicy, PheromoneError> {
    context
        .subject_classes
        .iter()
        .find(|policy| {
            policy.subject_class == body.subject_class
                && policy.subject_class_namespace == body.subject_class_namespace
        })
        .ok_or_else(|| PheromoneError::SubjectClassUnknown(body.subject_class.clone()))
}

fn accepted_deposit_treaties(
    body: &PheromoneDepositBody,
    policy: &SubjectClassPolicy,
) -> Vec<String> {
    body.treaty_scope
        .iter()
        .filter(|treaty| {
            policy
                .allowed_treaties
                .iter()
                .any(|allowed| allowed == *treaty)
        })
        .cloned()
        .collect()
}

pub fn validate_scarcity_policy_material(
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
) -> Result<(), PheromoneError> {
    if policy.schema != PHEROMONE_SCARCITY_POLICY_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(policy.schema.clone()));
    }
    validate_non_empty(&policy.policy_id, "scarcity policy id")?;
    validate_non_empty(&policy.window_id, "scarcity window id")?;
    validate_hex64(&policy.runtime_policy_sha256, "runtime_policy_sha256")?;
    validate_hex64(&policy.policy_sha256, "policy_sha256")?;
    validate_non_empty(
        &policy.subject_class_namespace,
        "scarcity subject class namespace",
    )?;
    validate_non_empty(&policy.subject_class, "scarcity subject class")?;
    if policy.treaty_scope.is_empty() {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} treaty scope must not be empty",
            policy.policy_id
        )));
    }
    validate_unique_non_empty_strings(&policy.treaty_scope, "scarcity treaty scope")?;
    if !context
        .known_reputation_epochs
        .contains(&policy.reputation_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            policy.reputation_epoch,
        ));
    }
    if !context
        .known_reputation_epochs
        .contains(&context.active_reputation_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            context.active_reputation_epoch,
        ));
    }
    if !context
        .known_reputation_epochs
        .contains(&policy.active_peers_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            policy.active_peers_epoch,
        ));
    }
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ScarcityPolicyInvalid(format!(
            "{} runtime policy hash is absent from receiver context",
            policy.policy_id
        ))
    })?;
    if policy.runtime_policy_sha256 != runtime_policy_sha256 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} runtime policy hash {} does not match receiver policy hash {}",
            policy.policy_id, policy.runtime_policy_sha256, runtime_policy_sha256
        )));
    }
    let expected_policy_sha256 = scarcity_policy_sha256(policy)?;
    if policy.policy_sha256 != expected_policy_sha256 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} policy hash {} does not match canonical hash {}",
            policy.policy_id, policy.policy_sha256, expected_policy_sha256
        )));
    }
    if policy.window_start_unix_ms >= policy.window_end_unix_ms {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} window start must be before end",
            policy.policy_id
        )));
    }
    if policy.token_capacity == 0 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} token capacity must be positive",
            policy.policy_id
        )));
    }
    if policy.newcomer_horizon_epochs == 0 {
        return Err(PheromoneError::InvalidNewcomerHorizon(
            policy.newcomer_horizon_epochs,
        ));
    }
    if policy.observation_cost_verification == ObservationCostVerificationMode::Required {
        validate_non_empty(&policy.verifier_id, "scarcity verifier id")?;
    }
    let Some(subject) = context.subject_classes.iter().find(|subject| {
        subject.subject_class == policy.subject_class
            && subject.subject_class_namespace == policy.subject_class_namespace
    }) else {
        return Err(PheromoneError::SubjectClassUnknown(
            policy.subject_class.clone(),
        ));
    };
    for treaty in &policy.treaty_scope {
        if !subject
            .allowed_treaties
            .iter()
            .any(|allowed| allowed == treaty)
        {
            return Err(PheromoneError::ScarcityPolicyInvalid(format!(
                "{} treaty {} is not allowed for subject class",
                policy.policy_id, treaty
            )));
        }
    }
    Ok(())
}

fn scarcity_policy_is_active(
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
) -> bool {
    policy.reputation_epoch == context.active_reputation_epoch
        && policy.window_start_unix_ms <= context.now_unix_ms
        && context.now_unix_ms < policy.window_end_unix_ms
}

fn scarcity_windows_overlap(
    left: &PheromoneScarcityPolicy,
    right: &PheromoneScarcityPolicy,
) -> bool {
    left.window_start_unix_ms < right.window_end_unix_ms
        && right.window_start_unix_ms < left.window_end_unix_ms
}

fn verify_observation_cost_commitment(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
    treaty_id: &str,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    let Some(commitment) = body.cost_commitment.as_ref() else {
        return Err(PheromoneError::ObservationCostCommitmentMissing(
            body.subject_class.clone(),
        ));
    };
    validate_cost_commitment_static(commitment)?;
    let statement = &commitment.statement;
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ObservationCostRuntimePolicyMismatch(
            "runtime policy hash is absent from receiver context".to_string(),
        )
    })?;
    let scarcity_policy_sha256 = scarcity_policy_sha256(policy)?;
    if statement.runtime_policy_sha256 != runtime_policy_sha256 {
        return Err(PheromoneError::ObservationCostRuntimePolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.scarcity_policy_sha256 != scarcity_policy_sha256 {
        return Err(PheromoneError::ObservationCostPolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    verify_observation_cost_policy_binding(deposit, policy, statement, treaty_id)?;

    let root = resolve_observation_cost_verifier_root(context, statement, treaty_id)?;
    if observation_cost_root_is_revoked(context, root) {
        return Err(PheromoneError::ObservationCostRevoked(
            root.body.verifier_key_id.clone(),
        ));
    }
    verify_observation_cost_signature(commitment, root)?;
    verify_observation_cost_leaf_and_inclusion(deposit, statement)?;
    Ok(())
}

fn validate_cost_commitment_static(
    commitment: &PheromoneCostCommitment,
) -> Result<(), PheromoneError> {
    if commitment.schema != PHEROMONE_COST_COMMITMENT_SCHEMA {
        return Err(PheromoneError::ObservationCostCommitmentSchemaInvalid(
            commitment.schema.clone(),
        ));
    }
    let statement = &commitment.statement;
    if statement.schema != PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA {
        return Err(PheromoneError::ObservationCostCommitmentSchemaInvalid(
            statement.schema.clone(),
        ));
    }
    validate_non_empty(&statement.commitment_id, "cost commitment id")?;
    validate_non_empty(&statement.verifier_id, "cost verifier id")?;
    validate_non_empty(&statement.verifier_key_id, "cost verifier key id")?;
    validate_hex64(&statement.runtime_policy_sha256, "runtime_policy_sha256")?;
    validate_hex64(&statement.scarcity_policy_sha256, "scarcity_policy_sha256")?;
    validate_hex64(&statement.deposit_body_sha256, "deposit_body_sha256")?;
    validate_hex64(
        &statement.deposit_signature_sha256,
        "deposit_signature_sha256",
    )?;
    validate_non_empty(&statement.kernel_id, "cost kernel id")?;
    validate_non_empty(
        &statement.agent_passport_key_hash,
        "cost agent passport key hash",
    )?;
    validate_non_empty(&statement.treaty_id, "cost treaty id")?;
    validate_non_empty(
        &statement.subject_class_namespace,
        "cost subject class namespace",
    )?;
    validate_non_empty(&statement.subject_class, "cost subject class")?;
    validate_hex64(&statement.event_digest_sha256, "event_digest_sha256")?;
    validate_hex64(&statement.leaf_preimage_sha256, "leaf_preimage_sha256")?;
    if statement.observation_window_start_unix_ms >= statement.observation_window_end_unix_ms {
        return Err(PheromoneError::ObservationCostWindowMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.cost.unit != OBSERVATION_COST_UNIT || statement.cost.amount == 0 {
        return Err(PheromoneError::ObservationCostUnitInvalid(
            statement.commitment_id.clone(),
        ));
    }
    let telemetry = &statement.telemetry;
    if telemetry.schema != PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA
        || telemetry.algorithm != OBSERVATION_COST_TELEMETRY_ALGORITHM
        || telemetry.tree_size == 0
        || telemetry.verifier_id != statement.verifier_id
        || telemetry.verifier_key_id != statement.verifier_key_id
    {
        return Err(PheromoneError::ObservationCostTelemetryRootMismatch(
            statement.commitment_id.clone(),
        ));
    }
    Ok(())
}

fn verify_observation_cost_policy_binding(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    statement: &PheromoneObservationCostStatement,
    treaty_id: &str,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    if statement.deposit_body_sha256 != deposit_signature_body_sha256(body)?
        || statement.deposit_signature_sha256 != deposit_signature_sha256(&deposit.signature)
        || statement.kernel_id != body.kernel_id
        || statement.agent_passport_key_hash != body.agent_passport_key_hash
        || statement.treaty_id != treaty_id
        || statement.subject_class_namespace != body.subject_class_namespace
        || statement.subject_class != body.subject_class
        || statement.verifier_id != policy.verifier_id
    {
        return Err(PheromoneError::ObservationCostPolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.observation_window_start_unix_ms < policy.window_start_unix_ms
        || statement.observation_window_end_unix_ms > policy.window_end_unix_ms
        || statement.observed_at_unix_ms < statement.observation_window_start_unix_ms
        || statement.observed_at_unix_ms >= statement.observation_window_end_unix_ms
        || statement.telemetry.closed_at_unix_ms < statement.observation_window_start_unix_ms
        || statement.telemetry.closed_at_unix_ms >= statement.observation_window_end_unix_ms
    {
        return Err(PheromoneError::ObservationCostWindowMismatch(
            statement.commitment_id.clone(),
        ));
    }
    Ok(())
}

fn resolve_observation_cost_verifier_root<'a>(
    context: &'a PheromoneValidationContext,
    statement: &PheromoneObservationCostStatement,
    treaty_id: &str,
) -> Result<&'a PheromoneObservationCostVerifierRoot, PheromoneError> {
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ObservationCostRuntimePolicyMismatch(
            "runtime policy hash is absent from receiver context".to_string(),
        )
    })?;
    let matches = context
        .observation_cost_verifier_roots
        .iter()
        .filter(|root| {
            root.body.schema == PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA
                && root.body.verifier_id == statement.verifier_id
                && root.body.verifier_key_id == statement.verifier_key_id
                && root.body.runtime_policy_sha256 == runtime_policy_sha256
                && root.body.valid_from_unix_ms <= context.now_unix_ms
                && context.now_unix_ms < root.body.valid_until_unix_ms
                && root
                    .body
                    .allowed_treaties
                    .iter()
                    .any(|allowed| allowed == treaty_id)
                && root
                    .body
                    .allowed_subject_class_namespaces
                    .iter()
                    .any(|allowed| allowed == &statement.subject_class_namespace)
                && root
                    .body
                    .allowed_subject_classes
                    .iter()
                    .any(|allowed| allowed == &statement.subject_class)
                && root.body.signature_algorithm == root.body.public_key.algorithm()
                && verifier_root_issuer_signature_is_valid(context, root)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [root] => Ok(*root),
        _ => Err(PheromoneError::ObservationCostVerifierUntrusted(
            statement.verifier_key_id.clone(),
        )),
    }
}

fn verifier_root_issuer_signature_is_valid(
    context: &PheromoneValidationContext,
    root: &PheromoneObservationCostVerifierRoot,
) -> bool {
    let Ok(canonical) = canonical_json_bytes(&root.body) else {
        return false;
    };
    context
        .runtime_policy_issuer_public_keys
        .iter()
        .any(|public_key| public_key.verify(&canonical, &root.issuer_signature))
}

fn observation_cost_root_is_revoked(
    context: &PheromoneValidationContext,
    root: &PheromoneObservationCostVerifierRoot,
) -> bool {
    context
        .runtime_trust_floor_state
        .entries
        .iter()
        .all(|entry| {
            entry.verifier_id != root.body.verifier_id
                || entry.key_id != root.body.verifier_key_id
                || entry.highest_version == 0
                || validate_hex64(&entry.latest_bundle_sha256, "latest_bundle_sha256").is_err()
                || validate_hex64(
                    &entry.latest_revocation_checkpoint_sha256,
                    "latest_revocation_checkpoint_sha256",
                )
                .is_err()
        })
}

fn verify_observation_cost_signature(
    commitment: &PheromoneCostCommitment,
    root: &PheromoneObservationCostVerifierRoot,
) -> Result<(), PheromoneError> {
    if commitment.signature.algorithm() != root.body.signature_algorithm {
        return Err(PheromoneError::ObservationCostSignatureInvalid(
            commitment.statement.commitment_id.clone(),
        ));
    }
    let canonical = canonical_json_bytes(&commitment.statement)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if root
        .body
        .public_key
        .verify(&canonical, &commitment.signature)
    {
        Ok(())
    } else {
        Err(PheromoneError::ObservationCostSignatureInvalid(
            commitment.statement.commitment_id.clone(),
        ))
    }
}

fn verify_observation_cost_leaf_and_inclusion(
    deposit: &PheromoneDeposit,
    statement: &PheromoneObservationCostStatement,
) -> Result<(), PheromoneError> {
    if statement.telemetry.tree_size != statement.inclusion_proof.tree_size {
        return Err(PheromoneError::ObservationCostTelemetryRootMismatch(
            statement.commitment_id.clone(),
        ));
    }
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256: deposit_signature_body_sha256(&deposit.body)?,
        deposit_signature_sha256: deposit_signature_sha256(&deposit.signature),
        kernel_id: statement.kernel_id.clone(),
        agent_passport_key_hash: statement.agent_passport_key_hash.clone(),
        treaty_id: statement.treaty_id.clone(),
        subject_class_namespace: statement.subject_class_namespace.clone(),
        subject_class: statement.subject_class.clone(),
        observed_at_unix_ms: statement.observed_at_unix_ms,
        event_digest_sha256: statement.event_digest_sha256.clone(),
        cost: statement.cost.clone(),
        scarcity_policy_sha256: statement.scarcity_policy_sha256.clone(),
        runtime_policy_sha256: statement.runtime_policy_sha256.clone(),
    };
    let leaf_bytes = canonical_json_bytes(&leaf)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if sha256_hex_bytes(&leaf_bytes) != statement.leaf_preimage_sha256 {
        return Err(PheromoneError::ObservationCostLeafMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement
        .inclusion_proof
        .verify(&leaf_bytes, &statement.telemetry.root_hash)
    {
        Ok(())
    } else {
        Err(PheromoneError::ObservationCostInclusionInvalid(
            statement.commitment_id.clone(),
        ))
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PheromoneError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex_bytes(&canonical))
}

fn deposit_signature_body_sha256(body: &PheromoneDepositBody) -> Result<String, PheromoneError> {
    canonical_sha256(&deposit_signature_body(body))
}

fn deposit_signature_sha256(signature: &Signature) -> String {
    sha256_hex_bytes(signature.to_hex().as_bytes())
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn newcomer_horizon_for_subject(
    context: &PheromoneValidationContext,
    reputation_epoch: u64,
    subject_class_namespace: &str,
    subject_class: &str,
) -> Result<u64, PheromoneError> {
    let mut horizon = None;
    for policy in context.scarcity_policies.iter().filter(|policy| {
        policy.reputation_epoch == reputation_epoch
            && policy.subject_class == subject_class
            && policy.subject_class_namespace == subject_class_namespace
    }) {
        validate_scarcity_policy_material(policy, context)?;
        if !scarcity_policy_is_active(policy, context) {
            continue;
        }
        match horizon {
            None => horizon = Some(policy.newcomer_horizon_epochs),
            Some(existing) if existing == policy.newcomer_horizon_epochs => {}
            Some(_) => {
                return Err(PheromoneError::ScarcityPolicyAmbiguous(format!(
                    "conflicting newcomer horizons for {subject_class_namespace}:{subject_class}"
                )))
            }
        }
    }
    Ok(horizon.unwrap_or(DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS))
}

fn strength_at(deposit: &PheromoneDeposit, now_unix_ms: u64) -> f64 {
    if now_unix_ms <= deposit.body.timestamp_unix_ms {
        return deposit.body.confidence;
    }
    let elapsed_secs = now_unix_ms.saturating_sub(deposit.body.timestamp_unix_ms) as f64 / 1000.0;
    deposit.body.confidence * 2_f64.powf(-(elapsed_secs / deposit.body.decay_half_life_secs))
}

fn sqrt_passport_cap(active_peers: u64) -> u64 {
    (active_peers.max(1) as f64).sqrt().ceil() as u64
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), PheromoneError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

fn validate_unique_non_empty_strings(values: &[String], field: &str) -> Result<(), PheromoneError> {
    if values.is_empty() {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must not be empty"
        )));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_non_empty(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(PheromoneError::InvalidField(format!(
                "{field} contains duplicate value {value}"
            )));
        }
    }
    Ok(())
}

fn validate_hex64(value: &str, field: &str) -> Result<(), PheromoneError> {
    if !is_hex64_shape(value) {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be 64 lowercase hex characters"
        )));
    }
    if value.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be lowercase hex"
        )));
    }
    Ok(())
}

fn is_hex64_shape(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex64_shape_helper_accepts_exact_ascii_hex_before_lowercase_validation() {
        assert!(super::is_hex64_shape(&"a".repeat(64)));
        assert!(super::is_hex64_shape(&"A".repeat(64)));
        assert!(!super::is_hex64_shape(&"a".repeat(63)));
        assert!(!super::is_hex64_shape(&format!("{}g", "a".repeat(63))));
    }
}
