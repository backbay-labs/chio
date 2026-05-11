//! Local Chiodos pheromone receiver runtime.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use chio_chiodos::{
    package_sha256, verification_context_sha256, verify_package, ChiodosPackageError,
    ChiodosProofPackage, ChiodosVerificationContext, ChiodosVerifierTrustBundle,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_federation::{
    verify_pheromone_gossip_batch, PheromoneGossipBatch, PheromoneGossipBatchVerificationContext,
    PheromoneGossipError, PheromoneTransitPolicy,
};
use chio_pheromone::{
    agent_passport_key_hash, InMemoryPheromoneSubstrate, PassportAdmission, PheromoneConcentration,
    PheromoneDeposit, PheromoneError, PheromoneSubstrate, PheromoneValidationContext,
    PheromoneWorkflowContext, SubjectClassPolicy, PHEROMONE_CONCENTRATION_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const PHEROMONE_RECEIVE_REPORT_SCHEMA: &str = "chio.pheromone.receive-report.v1";
pub const PHEROMONE_QUERY_REPORT_SCHEMA: &str = "chio.pheromone.query-report.v1";
pub const PHEROMONE_PEER_WEIGHTS_SCHEMA: &str = "chio.pheromone.peer-weights.v1";

#[derive(Debug, thiserror::Error)]
pub enum PheromoneRuntimeError {
    #[error("federation: {0}")]
    Federation(#[from] PheromoneGossipError),
    #[error("pheromone: {0}")]
    Pheromone(#[from] PheromoneError),
    #[error("workflow_context_mismatch: {0}")]
    WorkflowContextMismatch(String),
    #[error("chiodos_verification: {0}")]
    Chiodos(#[from] ChiodosPackageError),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("json: {0}")]
    Json(String),
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
            Self::Chiodos(_) => "chiodos_verification",
            Self::Sqlite(_) => "sqlite",
            Self::Json(_) => "json",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneReceiveReport {
    pub schema: String,
    pub accepted: bool,
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
#[serde(rename_all = "camelCase")]
pub struct PheromoneAdmissionPolicyDocument {
    pub recipient_kernel_id: String,
    pub authenticated_sender_kernel_id: String,
    pub replay_window_ms: u64,
    pub active_peers_in_treaty: u64,
    pub known_reputation_epochs: Vec<u64>,
    pub passports: Vec<PassportAdmission>,
    pub kernel_public_keys: Vec<chio_core_types::PublicKey>,
    pub subject_classes: Vec<SubjectClassPolicy>,
    pub max_deposits_per_pair: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerWeightEntry {
    pub kernel_id: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerWeightsDocument {
    pub schema: String,
    pub reputation_epoch: u64,
    pub weights: Vec<PeerWeightEntry>,
}

pub fn runtime_policy_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<(PheromoneTransitPolicy, PheromoneReceiverConfig), PheromoneRuntimeError> {
    let mut value: serde_json::Value = serde_json::from_str(json)?;
    let admission_value = value
        .as_object_mut()
        .and_then(|object| object.remove("admission"))
        .ok_or_else(|| {
            PheromoneRuntimeError::InvalidField(
                "transit policy requires admission material for runtime receive".to_string(),
            )
        })?;
    let transit_policy: PheromoneTransitPolicy = serde_json::from_value(value)?;
    let admission: PheromoneAdmissionPolicyDocument = serde_json::from_value(admission_value)?;
    let validation_context = PheromoneValidationContext {
        now_unix_ms,
        replay_window_ms: admission.replay_window_ms,
        active_peers_in_treaty: admission.active_peers_in_treaty,
        known_reputation_epochs: admission.known_reputation_epochs,
        passports: admission.passports,
        kernel_public_keys: admission.kernel_public_keys,
        subject_classes: admission.subject_classes,
        max_deposits_per_pair: admission.max_deposits_per_pair,
    };
    Ok((
        transit_policy,
        PheromoneReceiverConfig {
            recipient_kernel_id: admission.recipient_kernel_id,
            authenticated_sender_kernel_id: admission.authenticated_sender_kernel_id,
            validation_context,
        },
    ))
}

pub fn peer_weights_from_json(
    json: &str,
) -> Result<StaticPeerWeightProvider, PheromoneRuntimeError> {
    let document: PeerWeightsDocument = serde_json::from_str(json)?;
    if document.schema != PHEROMONE_PEER_WEIGHTS_SCHEMA {
        return Err(PheromoneRuntimeError::InvalidField(format!(
            "peer weights schema {} is unsupported",
            document.schema
        )));
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
    fn admit_deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError>;

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
        let batch_sha256 = canonical_sha256(batch)?;
        let mut frames = Vec::new();
        let verification_context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: self.config.validation_context.now_unix_ms,
            recipient_kernel_id: self.config.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: self.config.authenticated_sender_kernel_id.clone(),
        };
        if let Err(error) = verify_pheromone_gossip_batch(batch, policy, &verification_context) {
            frames.push(PheromoneFrameReport {
                frame_index: 0,
                accepted: false,
                code: error.code().to_string(),
                detail: error.to_string(),
                deposit_nonce: None,
            });
            let report = self.report(batch_sha256, frames);
            self.store.record_receive_report(&report)?;
            return Ok(report);
        }

        for (index, frame) in batch.frames.iter().enumerate() {
            let result = frame
                .deposit
                .body
                .workflow_context
                .as_ref()
                .map_or(Ok(()), |context| self.resolver.resolve(context))
                .and_then(|()| {
                    self.store
                        .admit_deposit(frame.deposit.clone(), &self.config.validation_context)
                });
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
                    code: error.code().to_string(),
                    detail: error.to_string(),
                    deposit_nonce: Some(frame.deposit.body.nonce.clone()),
                }),
            }
        }
        let report = self.report(batch_sha256, frames);
        self.store.record_receive_report(&report)?;
        Ok(report)
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

    fn report(
        &self,
        batch_sha256: String,
        frames: Vec<PheromoneFrameReport>,
    ) -> PheromoneReceiveReport {
        PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
            accepted: frames.iter().all(|frame| frame.accepted),
            batch_sha256,
            recipient_kernel_id: self.config.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: self.config.authenticated_sender_kernel_id.clone(),
            received_at_unix_ms: self.config.validation_context.now_unix_ms,
            frames,
        }
    }
}

#[derive(Debug, Clone)]
struct WorkflowStepEvidence {
    tool_receipt_id: String,
    bilateral_dsse_sha256: String,
    consistency_anchor: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedChiodosWorkflowResolver {
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

impl VerifiedChiodosWorkflowResolver {
    pub fn from_verified_package(
        package: &ChiodosProofPackage,
        trust_bundle: &ChiodosVerifierTrustBundle,
        context: &ChiodosVerificationContext,
    ) -> Result<Self, PheromoneRuntimeError> {
        verify_package(package, trust_bundle, context)?;
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
            package_sha256: package_sha256(package)?,
            trust_bundle_sha256: trust_bundle.document_sha256().to_string(),
            verification_context_sha256: verification_context_sha256(context)?,
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

impl WorkflowContextResolver for VerifiedChiodosWorkflowResolver {
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

            CREATE TABLE IF NOT EXISTS chio_pheromone_receive_reports (
                report_sha256 TEXT PRIMARY KEY,
                received_at_unix_ms INTEGER NOT NULL,
                json TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }
}

impl PheromoneRuntimeStore for SqlitePheromoneRuntimeStore {
    fn admit_deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError> {
        let validator = InMemoryPheromoneSubstrate::new();
        validator.deposit(deposit.clone(), context)?;
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
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

        for treaty_id in &deposit.body.treaty_scope {
            let count = pair_count(&tx, &deposit, treaty_id)?;
            if count >= context.max_deposits_per_pair {
                return Err(PheromoneRuntimeError::Pheromone(
                    PheromoneError::DiversityCapExceeded(
                        deposit.body.agent_passport_key_hash.clone(),
                    ),
                ));
            }
            tx.execute(
                r#"
                INSERT INTO chio_pheromone_pair_counts
                    (kernel_id, passport_key_hash, subject_class, treaty_id, count)
                VALUES (?1, ?2, ?3, ?4, 1)
                ON CONFLICT(kernel_id, passport_key_hash, subject_class, treaty_id)
                DO UPDATE SET count = count + 1
                "#,
                params![
                    deposit.body.kernel_id,
                    deposit.body.agent_passport_key_hash,
                    deposit.body.subject_class,
                    treaty_id,
                ],
            )?;
        }

        let passport_seen = tx
            .query_row(
                r#"
                SELECT 1 FROM chio_pheromone_passport_caps
                WHERE kernel_id = ?1 AND subject_class = ?2 AND passport_key_hash = ?3
                "#,
                params![
                    deposit.body.kernel_id,
                    deposit.body.subject_class,
                    deposit.body.agent_passport_key_hash,
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let passport_count = tx.query_row(
            r#"
            SELECT COUNT(*) FROM chio_pheromone_passport_caps
            WHERE kernel_id = ?1 AND subject_class = ?2
            "#,
            params![deposit.body.kernel_id, deposit.body.subject_class],
            |row| row.get::<_, i64>(0),
        )?;
        let projected = u64::try_from(passport_count)
            .map_err(|_| PheromoneRuntimeError::Sqlite("passport count is negative".to_string()))?
            .saturating_add(u64::from(!passport_seen));
        if projected > sqrt_passport_cap(context.active_peers_in_treaty) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::SqrtNPassportCapExceeded(deposit.body.kernel_id.clone()),
            ));
        }
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_passport_caps
                (kernel_id, subject_class, passport_key_hash)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(kernel_id, subject_class, passport_key_hash) DO NOTHING
            "#,
            params![
                deposit.body.kernel_id,
                deposit.body.subject_class,
                deposit.body.agent_passport_key_hash,
            ],
        )?;

        let json = serde_json::to_string(&deposit)?;
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_deposits
                (deposit_sha256, kernel_id, passport_key_hash, subject_class,
                 subject_class_namespace, timestamp_unix_ms, json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(deposit_sha256) DO NOTHING
            "#,
            params![
                canonical_sha256(&deposit)?,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
                deposit.body.subject_class,
                deposit.body.subject_class_namespace,
                i64_from_u64(deposit.body.timestamp_unix_ms, "timestamp_unix_ms")?,
                json,
            ],
        )?;
        tx.commit()?;
        Ok(())
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

    fn record_receive_report(
        &self,
        report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
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

fn pair_count(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    treaty_id: &str,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx
        .query_row(
            r#"
            SELECT count FROM chio_pheromone_pair_counts
            WHERE kernel_id = ?1 AND passport_key_hash = ?2
              AND subject_class = ?3 AND treaty_id = ?4
            "#,
            params![
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
                deposit.body.subject_class,
                treaty_id,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("pair count is negative".to_string()))
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PheromoneRuntimeError> {
    i64::try_from(value).map_err(|_| {
        PheromoneRuntimeError::InvalidField(format!("{field} does not fit signed SQLite integer"))
    })
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
            "{field} {actual} does not match verified Chiodos evidence {expected}"
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
