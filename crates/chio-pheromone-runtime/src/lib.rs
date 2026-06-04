//! Local Chio pheromone receiver runtime.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use chio_attest_buyer_core::{
    package_sha256, proof_package_from_json, verification_context_from_json,
    verification_context_sha256, verifier_trust_bundle_from_json, verify_package,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::SignedExportEnvelope;
use chio_federation::{
    verify_pheromone_gossip_batch_envelope, verify_pheromone_gossip_frame_for_batch,
    PheromoneGossipBatch, PheromoneGossipBatchVerificationContext, PheromoneGossipError,
    PheromoneTransitPolicy,
};
use chio_pheromone::{
    agent_passport_key_hash, newcomer_discount_for_deposit, reject_overlapping_scarcity_windows,
    scarcity_admissions_for_deposit, scarcity_admissions_for_deposit_treaty,
    validate_deposit_for_admission, validate_scarcity_policy_material, PassportAdmission,
    PheromoneConcentration, PheromoneDeposit, PheromoneError, PheromoneObservationCostVerifierRoot,
    PheromoneRuntimeTrustFloorState, PheromoneScarcityAdmission, PheromoneScarcityPolicy,
    PheromoneValidationContext, PheromoneWorkflowContext, SubjectClassPolicy,
    PHEROMONE_CONCENTRATION_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const PHEROMONE_RECEIVE_REPORT_SCHEMA: &str = "chio.pheromone.receive-report.v1";
pub const PHEROMONE_QUERY_REPORT_SCHEMA: &str = "chio.pheromone.query-report.v1";
pub const PHEROMONE_PEER_WEIGHTS_SCHEMA: &str = "chio.pheromone.peer-weights.v1";
const PHEROMONE_TRANSIT_POLICY_SCHEMA_JSON: &str =
    include_str!("../../../spec/schemas/chio-pheromone/v1/transit-policy.schema.json");
const PHEROMONE_PEER_WEIGHTS_SCHEMA_JSON: &str =
    include_str!("../../../spec/schemas/chio-pheromone/v1/peer-weights.schema.json");

#[derive(Debug, thiserror::Error)]
pub enum PheromoneRuntimeError {
    #[error("federation: {0}")]
    Federation(#[from] PheromoneGossipError),
    #[error("pheromone: {0}")]
    Pheromone(#[from] PheromoneError),
    #[error("workflow_context_mismatch: {0}")]
    WorkflowContextMismatch(String),
    #[error("chio_workflow_verification: {0}")]
    WorkflowVerification(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("json: {0}")]
    Json(String),
    #[error("schema_invalid: {0}")]
    SchemaInvalid(String),
    #[error("canonical_json: {0}")]
    CanonicalJson(String),
    #[error("invalid_field: {0}")]
    InvalidField(String),
    #[error("store_poisoned: pheromone runtime store lock is poisoned")]
    StorePoisoned,
}

impl PheromoneRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Federation(error) => error.code(),
            Self::Pheromone(error) => error.code(),
            Self::WorkflowContextMismatch(_) => "workflow_context_mismatch",
            Self::WorkflowVerification(_) => "chio_workflow_verification",
            Self::Sqlite(_) => "sqlite",
            Self::Json(_) => "json",
            Self::SchemaInvalid(_) => "schema_invalid",
            Self::CanonicalJson(_) => "canonical_json",
            Self::InvalidField(_) => "invalid_field",
            Self::StorePoisoned => "store_poisoned",
        }
    }
}

impl From<rusqlite::Error> for PheromoneRuntimeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.to_string())
    }
}

impl<T> From<PoisonError<T>> for PheromoneRuntimeError {
    fn from(_: PoisonError<T>) -> Self {
        Self::StorePoisoned
    }
}

impl From<serde_json::Error> for PheromoneRuntimeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<std::io::Error> for PheromoneRuntimeError {
    fn from(error: std::io::Error) -> Self {
        Self::Json(error.to_string())
    }
}

fn chio_workflow_verification_error(error: impl std::fmt::Display) -> PheromoneRuntimeError {
    PheromoneRuntimeError::WorkflowVerification(error.to_string())
}

#[derive(Debug, Clone)]
pub struct ChioWorkflowProofPackage {
    inner: chio_attest_buyer_core::ChioProofPackage,
}

impl ChioWorkflowProofPackage {
    pub fn from_json(json: &str) -> Result<Self, PheromoneRuntimeError> {
        proof_package_from_json(json)
            .map(|inner| Self { inner })
            .map_err(chio_workflow_verification_error)
    }

    fn as_attest_core(&self) -> &chio_attest_buyer_core::ChioProofPackage {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub struct ChioWorkflowVerifierTrustBundle {
    inner: chio_attest_buyer_core::ChioVerifierTrustBundle,
}

impl ChioWorkflowVerifierTrustBundle {
    pub fn from_json(json: &str) -> Result<Self, PheromoneRuntimeError> {
        verifier_trust_bundle_from_json(json)
            .map(|inner| Self { inner })
            .map_err(chio_workflow_verification_error)
    }

    #[must_use]
    pub fn runtime_policy_issuer_public_keys(&self) -> &[chio_core_types::PublicKey] {
        self.inner.runtime_policy_issuer_public_keys()
    }

    fn as_attest_core(&self) -> &chio_attest_buyer_core::ChioVerifierTrustBundle {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChioWorkflowVerificationContext {
    inner: chio_attest_buyer_core::ChioVerificationContext,
}

impl ChioWorkflowVerificationContext {
    pub fn from_json(json: &str) -> Result<Self, PheromoneRuntimeError> {
        verification_context_from_json(json)
            .map(|inner| Self { inner })
            .map_err(chio_workflow_verification_error)
    }

    fn as_attest_core(&self) -> &chio_attest_buyer_core::ChioVerificationContext {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneFrameReport {
    pub frame_index: usize,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_nonce: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PheromoneBatchOutcome {
    Accepted,
    Partial,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneReceiveReport {
    pub schema: String,
    pub accepted: bool,
    pub batch_outcome: PheromoneBatchOutcome,
    pub accepted_frame_count: u64,
    pub rejected_frame_count: u64,
    pub batch_sha256: String,
    pub recipient_kernel_id: String,
    pub authenticated_sender_kernel_id: String,
    pub received_at_unix_ms: u64,
    pub frames: Vec<PheromoneFrameReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneQueryReport {
    pub schema: String,
    pub accepted: bool,
    pub concentration: PheromoneConcentration,
}

#[derive(Debug, Clone)]
pub struct PheromoneReceiverConfig {
    pub recipient_kernel_id: String,
    pub authenticated_sender_kernel_id: String,
    pub validation_context: PheromoneValidationContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PheromoneAdmissionPolicyDocument {
    pub recipient_kernel_id: String,
    pub authenticated_sender_kernel_id: String,
    pub replay_window_ms: u64,
    pub active_peers_in_treaty: u64,
    pub active_reputation_epoch: u64,
    pub known_reputation_epochs: Vec<u64>,
    pub passports: Vec<PassportAdmission>,
    pub kernel_public_keys: Vec<chio_core_types::PublicKey>,
    pub subject_classes: Vec<SubjectClassPolicy>,
    pub max_deposits_per_pair: u64,
    pub scarcity_policies: Vec<PheromoneScarcityPolicy>,
    pub runtime_policy_issuer_public_keys: Vec<chio_core_types::PublicKey>,
    pub observation_cost_verifier_roots: Vec<PheromoneObservationCostVerifierRoot>,
    pub runtime_trust_floor_state: PheromoneRuntimeTrustFloorState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerWeightEntry {
    pub kernel_id: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerWeightsDocument {
    pub schema: String,
    pub reputation_epoch: u64,
    pub weights: Vec<PeerWeightEntry>,
}

pub fn runtime_policy_document_sha256(
    value: &serde_json::Value,
) -> Result<String, PheromoneRuntimeError> {
    let mut hash_material = value.clone();
    remove_runtime_policy_self_references(&mut hash_material);
    canonical_sha256(&hash_material)
}

fn remove_runtime_policy_self_references(value: &mut serde_json::Value) {
    let Some(admission) = value.get_mut("admission") else {
        return;
    };
    if let Some(policies) = admission
        .get_mut("scarcityPolicies")
        .and_then(serde_json::Value::as_array_mut)
    {
        for policy in policies {
            if let Some(object) = policy.as_object_mut() {
                object.remove("runtimePolicySha256");
                object.remove("policySha256");
            }
        }
    }
    if let Some(roots) = admission
        .get_mut("observationCostVerifierRoots")
        .and_then(serde_json::Value::as_array_mut)
    {
        for root in roots {
            if let Some(object) = root.as_object_mut() {
                object.remove("runtimePolicySha256");
                object.remove("issuerSignature");
            }
        }
    }
}

pub fn runtime_policy_from_json(
    json: &str,
    now_unix_ms: u64,
    trusted_runtime_policy_issuer_keys: &[chio_core_types::PublicKey],
) -> Result<(PheromoneTransitPolicy, PheromoneReceiverConfig), PheromoneRuntimeError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    validate_runtime_policy_schema(&value)?;
    let envelope: SignedExportEnvelope<serde_json::Value> = serde_json::from_value(value)?;
    if !envelope
        .verify_signature()
        .map_err(|error| PheromoneRuntimeError::CanonicalJson(error.to_string()))?
    {
        return Err(PheromoneRuntimeError::InvalidField(
            "runtime policy envelope signature is invalid".to_string(),
        ));
    }
    let mut body_value = envelope.body;
    let runtime_policy_sha256 = runtime_policy_document_sha256(&body_value)?;
    let admission_value = body_value
        .as_object_mut()
        .and_then(|object| object.remove("admission"))
        .ok_or_else(|| {
            PheromoneRuntimeError::InvalidField(
                "transit policy requires admission material for runtime receive".to_string(),
            )
        })?;
    let transit_policy: PheromoneTransitPolicy = serde_json::from_value(body_value)?;
    let admission: PheromoneAdmissionPolicyDocument = serde_json::from_value(admission_value)?;
    if !trusted_runtime_policy_issuer_keys
        .iter()
        .any(|public_key| public_key == &envelope.signer_key)
    {
        return Err(PheromoneRuntimeError::InvalidField(
            "runtime policy signer is not trusted by verifier trust bundle issuer roots"
                .to_string(),
        ));
    }
    if !admission
        .runtime_policy_issuer_public_keys
        .iter()
        .any(|public_key| public_key == &envelope.signer_key)
    {
        return Err(PheromoneRuntimeError::InvalidField(
            "runtime policy signer is not authorized by admission issuer roots".to_string(),
        ));
    }
    if admission.scarcity_policies.is_empty() {
        return Err(PheromoneRuntimeError::Pheromone(
            PheromoneError::ScarcityPolicyMissing(
                "runtime policy has no live scarcity policies".to_string(),
            ),
        ));
    }
    reject_overlapping_scarcity_windows(&admission.scarcity_policies)?;
    let validation_context = PheromoneValidationContext {
        now_unix_ms,
        replay_window_ms: admission.replay_window_ms,
        active_peers_in_treaty: admission.active_peers_in_treaty,
        active_reputation_epoch: admission.active_reputation_epoch,
        known_reputation_epochs: admission.known_reputation_epochs,
        passports: admission.passports,
        kernel_public_keys: admission.kernel_public_keys,
        subject_classes: admission.subject_classes,
        max_deposits_per_pair: admission.max_deposits_per_pair,
        scarcity_policies: admission.scarcity_policies,
        runtime_policy_sha256: Some(runtime_policy_sha256),
        runtime_policy_issuer_public_keys: admission.runtime_policy_issuer_public_keys,
        observation_cost_verifier_roots: admission.observation_cost_verifier_roots,
        runtime_trust_floor_state: admission.runtime_trust_floor_state,
    };
    for policy in &validation_context.scarcity_policies {
        validate_scarcity_policy_material(policy, &validation_context)?;
    }
    Ok((
        transit_policy,
        PheromoneReceiverConfig {
            recipient_kernel_id: admission.recipient_kernel_id,
            authenticated_sender_kernel_id: admission.authenticated_sender_kernel_id,
            validation_context,
        },
    ))
}

fn validate_runtime_policy_schema(value: &serde_json::Value) -> Result<(), PheromoneRuntimeError> {
    validate_json_schema(
        value,
        PHEROMONE_TRANSIT_POLICY_SCHEMA_JSON,
        "transit policy",
    )
}

fn validate_json_schema(
    value: &serde_json::Value,
    schema_json: &str,
    label: &str,
) -> Result<(), PheromoneRuntimeError> {
    let schema: serde_json::Value = serde_json::from_str(schema_json).map_err(|error| {
        PheromoneRuntimeError::SchemaInvalid(format!(
            "embedded {label} schema is invalid JSON: {error}"
        ))
    })?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|error| PheromoneRuntimeError::SchemaInvalid(error.to_string()))?;
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PheromoneRuntimeError::SchemaInvalid(errors.join(" | ")))
    }
}

pub fn peer_weights_from_json(
    json: &str,
) -> Result<StaticPeerWeightProvider, PheromoneRuntimeError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    validate_json_schema(&value, PHEROMONE_PEER_WEIGHTS_SCHEMA_JSON, "peer weights")?;
    let document: PeerWeightsDocument = serde_json::from_value(value)?;
    if document.schema != PHEROMONE_PEER_WEIGHTS_SCHEMA {
        return Err(PheromoneRuntimeError::InvalidField(format!(
            "peer weights schema {} is unsupported",
            document.schema
        )));
    }
    let mut kernel_ids = BTreeSet::new();
    for entry in &document.weights {
        let kernel_id = entry.kernel_id.trim();
        if kernel_id.is_empty() || kernel_id != entry.kernel_id {
            return Err(PheromoneRuntimeError::InvalidField(
                "peer weight kernel id must be non-empty and unpadded".to_string(),
            ));
        }
        if !kernel_ids.insert(entry.kernel_id.as_str()) {
            return Err(PheromoneRuntimeError::InvalidField(format!(
                "peer weight kernel id {} is duplicated",
                entry.kernel_id
            )));
        }
    }
    Ok(StaticPeerWeightProvider::new(
        document.reputation_epoch,
        document
            .weights
            .into_iter()
            .map(|entry| (entry.kernel_id, entry.weight)),
    ))
}

pub trait WorkflowContextResolver {
    fn resolve(&self, context: &PheromoneWorkflowContext) -> Result<(), PheromoneRuntimeError>;
}

pub trait PeerWeightProvider {
    fn weight(&self, kernel_id: &str, reputation_epoch: u64) -> Result<f64, PheromoneRuntimeError>;
}

#[derive(Debug, Clone)]
pub struct StaticPeerWeightProvider {
    reputation_epoch: u64,
    weights: BTreeMap<String, f64>,
}

impl StaticPeerWeightProvider {
    pub fn new<I>(reputation_epoch: u64, weights: I) -> Self
    where
        I: IntoIterator<Item = (String, f64)>,
    {
        Self {
            reputation_epoch,
            weights: weights.into_iter().collect(),
        }
    }
}

impl PeerWeightProvider for StaticPeerWeightProvider {
    fn weight(&self, kernel_id: &str, reputation_epoch: u64) -> Result<f64, PheromoneRuntimeError> {
        if reputation_epoch != self.reputation_epoch {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::UnknownReputationEpoch(reputation_epoch),
            ));
        }
        let weight = self.weights.get(kernel_id).copied().unwrap_or(1.0);
        if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::WeightOutOfRange(format!(
                    "weight for {kernel_id} at epoch {reputation_epoch} was {weight}"
                )),
            ));
        }
        Ok(weight)
    }
}

pub trait PheromoneRuntimeStore {
    fn receive_batch(
        &self,
        _batch: &PheromoneGossipBatch,
        _policy: &PheromoneTransitPolicy,
        _config: &PheromoneReceiverConfig,
        _resolver: &dyn WorkflowContextResolver,
    ) -> Result<PheromoneReceiveReport, PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::InvalidField(
            "atomic receive/report persistence is required for live receive".to_string(),
        ))
    }

    fn admit_deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError>;

    fn admit_deposit_for_treaty(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
        treaty_id: &str,
    ) -> Result<(), PheromoneRuntimeError> {
        let _ = (deposit, context, treaty_id);
        Err(PheromoneRuntimeError::InvalidField(
            "scoped treaty admission is required for live receive; unscoped store default fails closed"
                .to_string(),
        ))
    }

    fn query_deposits(
        &self,
        subject_class: Option<&str>,
        treaty_id: Option<&str>,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneRuntimeError>;

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneConcentration, PheromoneRuntimeError>;

    fn record_receive_report(
        &self,
        report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError>;

    fn receive_reports(&self) -> Result<Vec<PheromoneReceiveReport>, PheromoneRuntimeError>;
}

#[derive(Debug)]
pub struct PheromoneReceiver<S, R> {
    store: S,
    resolver: R,
    config: PheromoneReceiverConfig,
}

impl<S, R> PheromoneReceiver<S, R>
where
    S: PheromoneRuntimeStore,
    R: WorkflowContextResolver,
{
    #[must_use]
    pub fn new(store: S, resolver: R, config: PheromoneReceiverConfig) -> Self {
        Self {
            store,
            resolver,
            config,
        }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn receive_batch(
        &self,
        batch: &PheromoneGossipBatch,
        policy: &PheromoneTransitPolicy,
    ) -> Result<PheromoneReceiveReport, PheromoneRuntimeError> {
        self.store
            .receive_batch(batch, policy, &self.config, &self.resolver)
    }

    pub fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        reputation_epoch: u64,
        peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneQueryReport, PheromoneRuntimeError> {
        let concentration = self.store.query_concentration(
            subject_class,
            subject_class_namespace,
            self.config.validation_context.now_unix_ms,
            reputation_epoch,
            &self.config.validation_context,
            peer_weight,
        )?;
        Ok(PheromoneQueryReport {
            schema: PHEROMONE_QUERY_REPORT_SCHEMA.to_string(),
            accepted: true,
            concentration,
        })
    }
}

fn build_receive_report(
    config: &PheromoneReceiverConfig,
    batch_sha256: String,
    frames: Vec<PheromoneFrameReport>,
) -> PheromoneReceiveReport {
    let accepted_frame_count = frames.iter().filter(|frame| frame.accepted).count() as u64;
    let rejected_frame_count = frames.len() as u64 - accepted_frame_count;
    let batch_outcome = match (accepted_frame_count, rejected_frame_count) {
        (_, 0) => PheromoneBatchOutcome::Accepted,
        (0, _) => PheromoneBatchOutcome::Rejected,
        _ => PheromoneBatchOutcome::Partial,
    };
    PheromoneReceiveReport {
        schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
        accepted: batch_outcome == PheromoneBatchOutcome::Accepted,
        batch_outcome,
        accepted_frame_count,
        rejected_frame_count,
        batch_sha256,
        recipient_kernel_id: config.recipient_kernel_id.clone(),
        authenticated_sender_kernel_id: config.authenticated_sender_kernel_id.clone(),
        received_at_unix_ms: config.validation_context.now_unix_ms,
        frames,
    }
}

fn frame_failure_code(error: &PheromoneRuntimeError) -> &'static str {
    if is_storage_commit_error(error) {
        "storage_commit_failed"
    } else {
        error.code()
    }
}

fn is_storage_commit_error(error: &PheromoneRuntimeError) -> bool {
    matches!(
        error,
        PheromoneRuntimeError::Sqlite(_) | PheromoneRuntimeError::StorePoisoned
    )
}

#[cfg(test)]
mod tests {
    use super::PheromoneRuntimeError;

    #[test]
    fn storage_commit_error_helper_selects_only_storage_failures() {
        assert!(super::is_storage_commit_error(
            &PheromoneRuntimeError::Sqlite("disk full".to_string())
        ));
        assert!(super::is_storage_commit_error(
            &PheromoneRuntimeError::StorePoisoned
        ));
        assert!(!super::is_storage_commit_error(
            &PheromoneRuntimeError::InvalidField("bad frame".to_string())
        ));
    }
}

#[derive(Debug, Clone)]
struct WorkflowStepEvidence {
    tool_receipt_id: String,
    bilateral_dsse_sha256: String,
    consistency_anchor: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedChioWorkflowResolver {
    workflow_id: String,
    workflow_receipt_id: String,
    workflow_receipt_sha256: String,
    workflow_intersection_id: String,
    workflow_intersection_sha256: String,
    steps: BTreeMap<u64, WorkflowStepEvidence>,
    package_sha256: String,
    trust_bundle_sha256: String,
    verification_context_sha256: String,
}

impl VerifiedChioWorkflowResolver {
    pub fn from_verified_package(
        package: &ChioWorkflowProofPackage,
        trust_bundle: &ChioWorkflowVerifierTrustBundle,
        context: &ChioWorkflowVerificationContext,
    ) -> Result<Self, PheromoneRuntimeError> {
        let package = package.as_attest_core();
        let trust_bundle = trust_bundle.as_attest_core();
        let context = context.as_attest_core();
        verify_package(package, trust_bundle, context).map_err(chio_workflow_verification_error)?;
        let workflow_receipt_sha256 = canonical_sha256(&package.workflow_receipt)?;
        let workflow_intersection_sha256 = canonical_sha256(&package.workflow_intersection)?;
        let mut steps = BTreeMap::new();
        for step in &package.workflow_receipt.steps {
            let step_index = u64::try_from(step.step_index).map_err(|_| {
                PheromoneRuntimeError::InvalidField(format!(
                    "step index {} does not fit u64",
                    step.step_index
                ))
            })?;
            let tool_receipt_id = step.tool_receipt_id.clone().ok_or_else(|| {
                PheromoneRuntimeError::WorkflowContextMismatch(format!(
                    "workflow step {step_index} has no tool receipt id"
                ))
            })?;
            let bilateral_dsse_sha256 = step.bilateral_dsse_sha256.clone().ok_or_else(|| {
                PheromoneRuntimeError::WorkflowContextMismatch(format!(
                    "workflow step {step_index} has no bilateral DSSE hash"
                ))
            })?;
            let consistency_anchor = step.consistency_anchor.clone().ok_or_else(|| {
                PheromoneRuntimeError::WorkflowContextMismatch(format!(
                    "workflow step {step_index} has no consistency anchor"
                ))
            })?;
            if steps
                .insert(
                    step_index,
                    WorkflowStepEvidence {
                        tool_receipt_id,
                        bilateral_dsse_sha256,
                        consistency_anchor,
                    },
                )
                .is_some()
            {
                return Err(PheromoneRuntimeError::WorkflowContextMismatch(format!(
                    "duplicate workflow step {step_index}"
                )));
            }
        }
        Ok(Self {
            workflow_id: package.workflow_id.clone(),
            workflow_receipt_id: package.workflow_receipt.id.clone(),
            workflow_receipt_sha256,
            workflow_intersection_id: package.workflow_intersection.intersection_id.clone(),
            workflow_intersection_sha256,
            steps,
            package_sha256: package_sha256(package).map_err(chio_workflow_verification_error)?,
            trust_bundle_sha256: trust_bundle.document_sha256().to_string(),
            verification_context_sha256: verification_context_sha256(context)
                .map_err(chio_workflow_verification_error)?,
        })
    }

    #[must_use]
    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }

    #[must_use]
    pub fn trust_bundle_sha256(&self) -> &str {
        &self.trust_bundle_sha256
    }

    #[must_use]
    pub fn verification_context_sha256(&self) -> &str {
        &self.verification_context_sha256
    }
}

impl WorkflowContextResolver for VerifiedChioWorkflowResolver {
    fn resolve(&self, context: &PheromoneWorkflowContext) -> Result<(), PheromoneRuntimeError> {
        ensure_equal("workflow_id", &context.workflow_id, &self.workflow_id)?;
        ensure_equal(
            "workflow_receipt_id",
            &context.workflow_receipt_id,
            &self.workflow_receipt_id,
        )?;
        ensure_equal(
            "workflow_receipt_sha256",
            &context.workflow_receipt_sha256,
            &self.workflow_receipt_sha256,
        )?;
        ensure_equal(
            "workflow_intersection_id",
            &context.workflow_intersection_id,
            &self.workflow_intersection_id,
        )?;
        ensure_equal(
            "workflow_intersection_sha256",
            &context.workflow_intersection_sha256,
            &self.workflow_intersection_sha256,
        )?;
        let step = self.steps.get(&context.step_index).ok_or_else(|| {
            PheromoneRuntimeError::WorkflowContextMismatch(format!(
                "workflow step {} is not present",
                context.step_index
            ))
        })?;
        ensure_equal(
            "tool_receipt_id",
            &context.tool_receipt_id,
            &step.tool_receipt_id,
        )?;
        ensure_equal(
            "bilateral_dsse_sha256",
            &context.bilateral_dsse_sha256,
            &step.bilateral_dsse_sha256,
        )?;
        ensure_equal(
            "consistency_anchor",
            &context.consistency_anchor,
            &step.consistency_anchor,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqlitePheromoneRuntimeStore {
    conn: Mutex<Connection>,
}

impl SqlitePheromoneRuntimeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PheromoneRuntimeError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, PheromoneRuntimeError> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_pheromone_deposits (
                deposit_sha256 TEXT PRIMARY KEY,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                timestamp_unix_ms INTEGER NOT NULL,
                json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_replay_nonces (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash, nonce)
            );

            CREATE INDEX IF NOT EXISTS idx_chio_pheromone_replay_expiry
                ON chio_pheromone_replay_nonces(expires_at_unix_ms);

            CREATE TABLE IF NOT EXISTS chio_pheromone_pair_counts (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash, subject_class, treaty_id)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_caps (
                kernel_id TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                PRIMARY KEY (kernel_id, subject_class, passport_key_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_scarcity_buckets (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_pair_buckets (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class,
                    kernel_id,
                    passport_key_hash
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_caps_v2 (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class,
                    kernel_id,
                    passport_key_hash
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_admissions (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_receive_reports (
                report_sha256 TEXT PRIMARY KEY,
                received_at_unix_ms INTEGER NOT NULL,
                json TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    fn stored_passports(&self) -> Result<Vec<PassportAdmission>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT json FROM chio_pheromone_passport_admissions ORDER BY kernel_id, passport_key_hash")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut passports = Vec::new();
        for row in rows {
            passports.push(serde_json::from_str(&row?)?);
        }
        Ok(passports)
    }

    fn query_context_with_stored_passports(
        &self,
        context: &PheromoneValidationContext,
    ) -> Result<PheromoneValidationContext, PheromoneRuntimeError> {
        let mut query_context = context.clone();
        let mut seen = BTreeSet::new();
        for passport in &query_context.passports {
            seen.insert(passport_identity(passport));
        }
        for passport in self.stored_passports()? {
            if seen.insert(passport_identity(&passport)) {
                query_context.passports.push(passport);
            }
        }
        Ok(query_context)
    }

    fn admit_deposit_scoped(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
        treaty_id: Option<&str>,
    ) -> Result<(), PheromoneRuntimeError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        admit_deposit_scoped_tx(&tx, &deposit, context, treaty_id)?;
        tx.commit()?;
        Ok(())
    }
}

fn admit_deposit_scoped_tx(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    treaty_id: Option<&str>,
) -> Result<(), PheromoneRuntimeError> {
    let passport = validate_deposit_for_admission(deposit, context)?;
    let admissions = match treaty_id {
        Some(treaty_id) => scarcity_admissions_for_deposit_treaty(deposit, context, treaty_id)?,
        None => scarcity_admissions_for_deposit(deposit, context)?,
    };
    let now = i64_from_u64(context.now_unix_ms, "now_unix_ms")?;
    tx.execute(
        "DELETE FROM chio_pheromone_replay_nonces WHERE expires_at_unix_ms <= ?1",
        params![now],
    )?;
    let expires_at = context.now_unix_ms.saturating_add(context.replay_window_ms);
    let inserted = tx.execute(
        r#"
        INSERT INTO chio_pheromone_replay_nonces
            (kernel_id, passport_key_hash, nonce, expires_at_unix_ms)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(kernel_id, passport_key_hash, nonce) DO NOTHING
        "#,
        params![
            deposit.body.kernel_id,
            deposit.body.agent_passport_key_hash,
            deposit.body.nonce,
            i64_from_u64(expires_at, "replay_expires_at_unix_ms")?,
        ],
    )?;
    if inserted == 0 {
        return Err(PheromoneRuntimeError::Pheromone(
            PheromoneError::ReplayWindowExceeded(deposit.body.nonce.clone()),
        ));
    }

    for admission in &admissions {
        let bucket_count = scarcity_bucket_count(tx, admission)?;
        if bucket_count >= admission.token_capacity {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::RateLimitExhausted(format!(
                    "{}:{}:{}:{}",
                    admission.reputation_epoch,
                    admission.window_id,
                    admission.treaty_id,
                    admission.subject_class
                )),
            ));
        }
        let count = pair_bucket_count(tx, deposit, admission)?;
        if count >= context.max_deposits_per_pair {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::DiversityCapExceeded(deposit.body.agent_passport_key_hash.clone()),
            ));
        }
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_scarcity_buckets
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, count)
            VALUES (?1, ?2, ?3, ?4, ?5, 1)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class)
            DO UPDATE SET count = count + 1
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
            ],
        )?;
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_pair_buckets
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, kernel_id, passport_key_hash, count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class, kernel_id, passport_key_hash)
            DO UPDATE SET count = count + 1
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
        )?;
    }

    for admission in &admissions {
        let passport_seen = passport_seen(tx, deposit, admission)?;
        let passport_count = passport_count(tx, deposit, admission)?;
        let projected = passport_count.saturating_add(u64::from(!passport_seen));
        if projected > sqrt_passport_cap(context.active_peers_in_treaty) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::SqrtNPassportCapExceeded(deposit.body.kernel_id.clone()),
            ));
        }
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_passport_caps_v2
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, kernel_id, passport_key_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class, kernel_id, passport_key_hash)
            DO NOTHING
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
        )?;
    }

    let passport_json = serde_json::to_string(&passport)?;
    tx.execute(
        r#"
        INSERT INTO chio_pheromone_passport_admissions
            (kernel_id, passport_key_hash, json)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(kernel_id, passport_key_hash)
        DO UPDATE SET json = excluded.json
        "#,
        params![
            passport.kernel_id,
            agent_passport_key_hash(&passport.public_key),
            passport_json,
        ],
    )?;

    let json = serde_json::to_string(deposit)?;
    tx.execute(
        r#"
        INSERT INTO chio_pheromone_deposits
            (deposit_sha256, kernel_id, passport_key_hash, subject_class,
             subject_class_namespace, timestamp_unix_ms, json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(deposit_sha256) DO NOTHING
        "#,
        params![
            canonical_sha256(deposit)?,
            deposit.body.kernel_id,
            deposit.body.agent_passport_key_hash,
            deposit.body.subject_class,
            deposit.body.subject_class_namespace,
            i64_from_u64(deposit.body.timestamp_unix_ms, "timestamp_unix_ms")?,
            json,
        ],
    )?;
    Ok(())
}

impl PheromoneRuntimeStore for SqlitePheromoneRuntimeStore {
    fn receive_batch(
        &self,
        batch: &PheromoneGossipBatch,
        policy: &PheromoneTransitPolicy,
        config: &PheromoneReceiverConfig,
        resolver: &dyn WorkflowContextResolver,
    ) -> Result<PheromoneReceiveReport, PheromoneRuntimeError> {
        let batch_sha256 = canonical_sha256(batch)?;
        let mut frames = Vec::new();
        let verification_context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: config.validation_context.now_unix_ms,
            recipient_kernel_id: config.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: config.authenticated_sender_kernel_id.clone(),
        };
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        if let Err(error) = verify_pheromone_gossip_batch_envelope(batch, &verification_context) {
            frames.push(PheromoneFrameReport {
                frame_index: 0,
                accepted: false,
                code: error.code().to_string(),
                detail: error.to_string(),
                deposit_nonce: None,
            });
            let report = build_receive_report(config, batch_sha256, frames);
            record_receive_report_tx(&tx, &report)?;
            tx.commit()?;
            return Ok(report);
        }

        for (index, frame) in batch.frames.iter().enumerate() {
            let preflight = verify_pheromone_gossip_frame_for_batch(
                frame,
                batch,
                policy,
                &verification_context,
            )
            .map_err(PheromoneRuntimeError::from)
            .and_then(|()| {
                frame
                    .deposit
                    .body
                    .workflow_context
                    .as_ref()
                    .map_or(Ok(()), |context| resolver.resolve(context))
            });
            let result = match preflight {
                Ok(()) => {
                    let savepoint = format!("frame_{index}");
                    tx.execute_batch(&format!("SAVEPOINT {savepoint}"))?;
                    let admission = admit_deposit_scoped_tx(
                        &tx,
                        &frame.deposit,
                        &config.validation_context,
                        Some(&frame.treaty_id),
                    );
                    match admission {
                        Ok(()) => {
                            tx.execute_batch(&format!("RELEASE SAVEPOINT {savepoint}"))?;
                            Ok(())
                        }
                        Err(error) => {
                            tx.execute_batch(&format!(
                                "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint}"
                            ))?;
                            Err(error)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(()) => frames.push(PheromoneFrameReport {
                    frame_index: index,
                    accepted: true,
                    code: "accepted".to_string(),
                    detail: "accepted".to_string(),
                    deposit_nonce: Some(frame.deposit.body.nonce.clone()),
                }),
                Err(error) => frames.push(PheromoneFrameReport {
                    frame_index: index,
                    accepted: false,
                    code: frame_failure_code(&error).to_string(),
                    detail: error.to_string(),
                    deposit_nonce: Some(frame.deposit.body.nonce.clone()),
                }),
            }
        }
        let report = build_receive_report(config, batch_sha256, frames);
        record_receive_report_tx(&tx, &report)?;
        tx.commit()?;
        Ok(report)
    }

    fn admit_deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError> {
        self.admit_deposit_scoped(deposit, context, None)
    }

    fn admit_deposit_for_treaty(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
        treaty_id: &str,
    ) -> Result<(), PheromoneRuntimeError> {
        self.admit_deposit_scoped(deposit, context, Some(treaty_id))
    }

    fn query_deposits(
        &self,
        subject_class: Option<&str>,
        treaty_id: Option<&str>,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT json FROM chio_pheromone_deposits ORDER BY deposit_sha256")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut deposits = Vec::new();
        for row in rows {
            let deposit: PheromoneDeposit = serde_json::from_str(&row?)?;
            if subject_class
                .map(|value| value == deposit.body.subject_class)
                .unwrap_or(true)
                && treaty_id
                    .map(|value| {
                        deposit
                            .body
                            .treaty_scope
                            .iter()
                            .any(|treaty| treaty == value)
                    })
                    .unwrap_or(true)
            {
                deposits.push(deposit);
            }
        }
        Ok(deposits)
    }

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneConcentration, PheromoneRuntimeError> {
        if !context.known_reputation_epochs.contains(&reputation_epoch) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::UnknownReputationEpoch(reputation_epoch),
            ));
        }
        let query_context = self.query_context_with_stored_passports(context)?;
        let deposits = self.query_deposits(Some(subject_class), None)?;
        let mut total_strength = 0.0;
        let mut unweighted_total_strength = 0.0;
        let mut peak_confidence = 0.0;
        let mut origins = BTreeSet::new();
        let mut treaties = BTreeSet::new();
        for deposit in deposits
            .iter()
            .filter(|deposit| deposit.body.subject_class_namespace == subject_class_namespace)
        {
            let strength = strength_at(deposit, now_unix_ms);
            if let Some(floor) = deposit.body.evaporation_floor {
                if strength < floor {
                    continue;
                }
            }
            let weight = peer_weight.weight(&deposit.body.kernel_id, reputation_epoch)?;
            let discount = newcomer_discount_for_deposit(
                deposit,
                &query_context,
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

    fn record_receive_report(
        &self,
        report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        record_receive_report_connection(&conn, report)?;
        Ok(())
    }

    fn receive_reports(&self) -> Result<Vec<PheromoneReceiveReport>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT json FROM chio_pheromone_receive_reports ORDER BY received_at_unix_ms",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut reports = Vec::new();
        for row in rows {
            reports.push(serde_json::from_str(&row?)?);
        }
        Ok(reports)
    }
}

fn scarcity_bucket_count(
    tx: &rusqlite::Transaction<'_>,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx
        .query_row(
            r#"
            SELECT count FROM chio_pheromone_scarcity_buckets
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("scarcity count is negative".to_string()))
}

fn pair_bucket_count(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx
        .query_row(
            r#"
            SELECT count FROM chio_pheromone_pair_buckets
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
              AND kernel_id = ?6 AND passport_key_hash = ?7
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("pair bucket count is negative".to_string()))
}

fn passport_seen(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<bool, PheromoneRuntimeError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1 FROM chio_pheromone_passport_caps_v2
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
              AND kernel_id = ?6 AND passport_key_hash = ?7
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn passport_count(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx.query_row(
        r#"
        SELECT COUNT(*) FROM chio_pheromone_passport_caps_v2
        WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
          AND subject_class_namespace = ?4 AND subject_class = ?5 AND kernel_id = ?6
        "#,
        params![
            i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
            admission.window_id,
            admission.treaty_id,
            admission.subject_class_namespace,
            admission.subject_class,
            deposit.body.kernel_id,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("passport count is negative".to_string()))
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PheromoneRuntimeError> {
    i64::try_from(value).map_err(|_| {
        PheromoneRuntimeError::InvalidField(format!("{field} does not fit signed SQLite integer"))
    })
}

fn record_receive_report_tx(
    tx: &rusqlite::Transaction<'_>,
    report: &PheromoneReceiveReport,
) -> Result<(), PheromoneRuntimeError> {
    let json = serde_json::to_string(report)?;
    tx.execute(
        r#"
        INSERT OR REPLACE INTO chio_pheromone_receive_reports
            (report_sha256, received_at_unix_ms, json)
        VALUES (?1, ?2, ?3)
        "#,
        params![
            canonical_sha256(report)?,
            i64_from_u64(report.received_at_unix_ms, "received_at_unix_ms")?,
            json,
        ],
    )?;
    Ok(())
}

fn record_receive_report_connection(
    conn: &Connection,
    report: &PheromoneReceiveReport,
) -> Result<(), PheromoneRuntimeError> {
    let json = serde_json::to_string(report)?;
    conn.execute(
        r#"
        INSERT OR REPLACE INTO chio_pheromone_receive_reports
            (report_sha256, received_at_unix_ms, json)
        VALUES (?1, ?2, ?3)
        "#,
        params![
            canonical_sha256(report)?,
            i64_from_u64(report.received_at_unix_ms, "received_at_unix_ms")?,
            json,
        ],
    )?;
    Ok(())
}

fn passport_identity(passport: &PassportAdmission) -> (String, String) {
    (
        passport.kernel_id.clone(),
        agent_passport_key_hash(&passport.public_key),
    )
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PheromoneRuntimeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| PheromoneRuntimeError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn ensure_equal(field: &str, actual: &str, expected: &str) -> Result<(), PheromoneRuntimeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PheromoneRuntimeError::WorkflowContextMismatch(format!(
            "{field} {actual} does not match verified Chio workflow evidence {expected}"
        )))
    }
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
