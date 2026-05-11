//! Local Chiodos pheromone substrate and transit evidence types.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::{Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PHEROMONE_DEPOSIT_SCHEMA: &str = "chio.pheromone-deposit.v1";
pub const PHEROMONE_COST_COMMITMENT_SCHEMA: &str = "chio.pheromone-cost-commitment.v1";
pub const PHEROMONE_WORKFLOW_CONTEXT_SCHEMA: &str = "chio.pheromone-workflow-context.v1";
pub const PHEROMONE_CONCENTRATION_SCHEMA: &str = "chio.pheromone-concentration.v1";

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
    #[error("treaty_scope_violation: {0}")]
    TreatyScopeViolation(String),
    #[error("subject_class_unknown: {0}")]
    SubjectClassUnknown(String),
    #[error("observation_cost_commitment_required: {0}")]
    ObservationCostCommitmentRequired(String),
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
            Self::TreatyScopeViolation(_) => "treaty_scope_violation",
            Self::SubjectClassUnknown(_) => "subject_class_unknown",
            Self::ObservationCostCommitmentRequired(_) => "observation_cost_commitment_required",
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
    pub telemetry_chain_root: String,
    pub chain_position: u64,
    pub chain_position_proof: Value,
    pub observed_at_unix_ms: u64,
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
    pub known_reputation_epochs: Vec<u64>,
    pub passports: Vec<PassportAdmission>,
    pub kernel_public_keys: Vec<PublicKey>,
    pub subject_classes: Vec<SubjectClassPolicy>,
    pub max_deposits_per_pair: u64,
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

#[derive(Debug, Default)]
pub struct InMemoryPheromoneSubstrate {
    deposits: Mutex<Vec<PheromoneDeposit>>,
    seen_nonces: Mutex<BTreeSet<(String, String, String)>>,
    pair_counts: Mutex<BTreeMap<(String, String, String), u64>>,
    passports_by_kernel_class: Mutex<BTreeMap<(String, String), BTreeSet<String>>>,
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
        validate_deposit_static(&deposit, context)?;
        let passport = resolve_passport(&deposit, context)?;
        verify_deposit_signature(&deposit, &passport.public_key)?;
        commit_admission_state(
            &deposit,
            &self.seen_nonces,
            context,
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
            let discount = newcomer_discount(deposit, context, reputation_epoch);
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
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    Ok(PheromoneDeposit {
        body,
        signature: keypair.sign(&canonical),
    })
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
        validate_hex64(&commitment.telemetry_chain_root, "telemetry_chain_root")?;
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
        return Err(PheromoneError::ObservationCostCommitmentRequired(
            body.subject_class.clone(),
        ));
    }
    if body
        .timestamp_unix_ms
        .saturating_add(context.replay_window_ms)
        < context.now_unix_ms
    {
        return Err(PheromoneError::ReplayWindowExceeded(body.nonce.clone()));
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
    let canonical = canonical_json_bytes(&deposit.body)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if public_key.verify(&canonical, &deposit.signature) {
        Ok(())
    } else {
        Err(PheromoneError::SignatureInvalid)
    }
}

fn commit_admission_state(
    deposit: &PheromoneDeposit,
    seen_nonces: &Mutex<BTreeSet<(String, String, String)>>,
    context: &PheromoneValidationContext,
    pair_counts: &Mutex<BTreeMap<(String, String, String), u64>>,
    passports_by_kernel_class: &Mutex<BTreeMap<(String, String), BTreeSet<String>>>,
) -> Result<(), PheromoneError> {
    let nonce_key = (
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
        deposit.body.nonce.clone(),
    );
    let pair_key = (
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
        deposit.body.subject_class.clone(),
    );
    let kernel_class_key = (
        deposit.body.kernel_id.clone(),
        deposit.body.subject_class.clone(),
    );

    let mut seen = seen_nonces.lock()?;
    if seen.contains(&nonce_key) {
        return Err(PheromoneError::ReplayWindowExceeded(
            deposit.body.nonce.clone(),
        ));
    }
    let mut counts = pair_counts.lock()?;
    let count = counts.get(&pair_key).copied().unwrap_or(0);
    if count >= context.max_deposits_per_pair {
        return Err(PheromoneError::DiversityCapExceeded(
            deposit.body.agent_passport_key_hash.clone(),
        ));
    }

    let cap = sqrt_passport_cap(context.active_peers_in_treaty);
    let mut by_kernel = passports_by_kernel_class.lock()?;
    let passport_seen = by_kernel
        .get(&kernel_class_key)
        .map(|passports| passports.contains(&deposit.body.agent_passport_key_hash))
        .unwrap_or(false);
    let projected_passport_count = by_kernel
        .get(&kernel_class_key)
        .map(BTreeSet::len)
        .unwrap_or(0)
        .saturating_add(usize::from(!passport_seen));
    if projected_passport_count as u64 > cap {
        return Err(PheromoneError::SqrtNPassportCapExceeded(
            deposit.body.kernel_id.clone(),
        ));
    }

    seen.insert(nonce_key);
    counts.insert(pair_key, count.saturating_add(1));
    by_kernel
        .entry(kernel_class_key)
        .or_default()
        .insert(deposit.body.agent_passport_key_hash.clone());
    Ok(())
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

fn strength_at(deposit: &PheromoneDeposit, now_unix_ms: u64) -> f64 {
    if now_unix_ms <= deposit.body.timestamp_unix_ms {
        return deposit.body.confidence;
    }
    let elapsed_secs = now_unix_ms.saturating_sub(deposit.body.timestamp_unix_ms) as f64 / 1000.0;
    deposit.body.confidence * 2_f64.powf(-(elapsed_secs / deposit.body.decay_half_life_secs))
}

fn newcomer_discount(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    reputation_epoch: u64,
) -> f64 {
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
    (age as f64 / 8.0).min(1.0)
}

fn sqrt_passport_cap(active_peers: u64) -> u64 {
    (active_peers.max(1) as f64).sqrt().ceil() as u64
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), PheromoneError> {
    if value.trim().is_empty() {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn validate_hex64(value: &str, field: &str) -> Result<(), PheromoneError> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
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
