//! Local Chio pheromone receiver runtime.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::PoisonError;

use chio_attest_buyer_core::context::{
    verification_context_from_json, verification_context_sha256,
};
use chio_attest_buyer_core::proof_package::{package_sha256, proof_package_from_json};
use chio_attest_buyer_core::report::verify_package;
use chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_from_json;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_federation::{
    pheromone_gossip::PheromoneGossipBatch, pheromone_gossip::PheromoneGossipError,
    pheromone_gossip::PheromoneTransitPolicy,
};
use chio_pheromone::{
    reject_overlapping_scarcity_windows, validate_scarcity_policy_material, PassportAdmission,
    PheromoneConcentration, PheromoneDeposit, PheromoneError, PheromoneObservationCostVerifierRoot,
    PheromoneRuntimeTrustFloorState, PheromoneScarcityPolicy, PheromoneValidationContext,
    PheromoneWorkflowContext, SubjectClassPolicy,
};
use serde::{Deserialize, Serialize};

pub mod store;

pub const PHEROMONE_RECEIVE_REPORT_SCHEMA: &str = "chio.pheromone.receive-report.v1";
pub const PHEROMONE_QUERY_REPORT_SCHEMA: &str = "chio.pheromone.query-report.v1";
pub const PHEROMONE_PEER_WEIGHTS_SCHEMA: &str = "chio.pheromone.peer-weights.v1";
const PHEROMONE_TRANSIT_POLICY_SCHEMA_JSON: &str =
    include_str!("../schemas/transit-policy.schema.json");
const PHEROMONE_PEER_WEIGHTS_SCHEMA_JSON: &str =
    include_str!("../schemas/peer-weights.schema.json");

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
    inner: chio_attest_buyer_core::proof_package::ChioProofPackage,
}

impl ChioWorkflowProofPackage {
    pub fn from_json(json: &str) -> Result<Self, PheromoneRuntimeError> {
        proof_package_from_json(json)
            .map(|inner| Self { inner })
            .map_err(chio_workflow_verification_error)
    }

    fn as_attest_core(&self) -> &chio_attest_buyer_core::proof_package::ChioProofPackage {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub struct ChioWorkflowVerifierTrustBundle {
    inner: chio_attest_buyer_core::trust_bundle::ChioVerifierTrustBundle,
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

    fn as_attest_core(&self) -> &chio_attest_buyer_core::trust_bundle::ChioVerifierTrustBundle {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChioWorkflowVerificationContext {
    inner: chio_attest_buyer_core::context::ChioVerificationContext,
}

impl ChioWorkflowVerificationContext {
    pub fn from_json(json: &str) -> Result<Self, PheromoneRuntimeError> {
        verification_context_from_json(json)
            .map(|inner| Self { inner })
            .map_err(chio_workflow_verification_error)
    }

    fn as_attest_core(&self) -> &chio_attest_buyer_core::context::ChioVerificationContext {
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
