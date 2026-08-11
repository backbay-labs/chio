//! Durable finding-status feed state for the cognition market.
//!
//! This module persists storage-neutral, already-verified status epochs and
//! portable proofs. Canonical artifact parsing, signature verification, sparse
//! path verification, and operator-authorization policy remain at the caller
//! boundary. The store accepts only the exact signed epoch bytes that caller
//! verified and derives their digest itself. It then enforces the durable
//! invariants that cannot safely live in an in-memory verifier: one stable
//! operator identity per feed, an advancing epoch floor, immutable epoch and
//! proof history, and sticky pending or retracted state per finding.

use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior,
};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
#[cfg(feature = "cognition-market-experimental")]
use crate::finding_challenge_store::{
    begin_finalizing_under_sanction_tx, FindingFinalizingAuthorizationInput, FindingLiabilityState,
};
use crate::serving_owner::SqliteServingOwner;

const FINDING_STATUS_SCHEMA_KEY: &str = "finding_status";
pub(crate) const FINDING_STATUS_SUPPORTED_SCHEMA_VERSION: i32 = 3;
const FINDING_STATUS_SCHEMA_ANCHORS: &[&str] = &[
    "finding_status_feeds",
    "admission_operations",
    "chio_serving_owner",
];
const FINDING_STATUS_SCHEMA: &str = include_str!("finding_status_store.sql");

/// The single wire nonce selected for the `chio.finding.status.v1` key domain.
///
/// This is the first 53 bits of the protocol-domain digest. It is fixed rather
/// than caller-configurable and remains exactly representable by JSON number
/// implementations that use IEEE-754 doubles.
pub const FINDING_STATUS_KEY_DOMAIN_NONCE: u64 = 3_318_287_169_837_494;

/// Maximum exact signed epoch envelope retained by the store.
pub const MAX_FINDING_STATUS_EPOCH_BYTES: usize = 256 * 1024;
/// Maximum exact portable proof input retained by the store.
pub const MAX_FINDING_STATUS_PROOF_BYTES: usize = 256 * 1024;
/// Maximum exact signed retraction intent or finality evidence retained.
pub const MAX_FINDING_RETRACTION_EVIDENCE_BYTES: usize = 256 * 1024;
/// Maximum exact sparse-map leaf value retained by the store.
pub const MAX_FINDING_STATUS_VALUE_BYTES: usize = 4 * 1024;

/// Fail-closed errors from durable finding-status persistence.
#[derive(Debug, Error)]
pub enum FindingStatusStoreError {
    #[error("finding status store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding status store fence rejected the caller")]
    Fenced,
    #[error("finding status store conflict: {0}")]
    Conflict(String),
    #[error("finding status store invariant violated: {0}")]
    Invariant(String),
    #[error("finding status store commit outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("finding status feed `{feed_id}` has no durable epoch floor")]
    MissingFloor { feed_id: String },
    #[error("finding `{finding_id}` has no durable current-floor status evidence")]
    MissingState { finding_id: String },
    #[error(
        "finding status epoch rollback for feed `{feed_id}`: current {current}, proposed {proposed}"
    )]
    Rollback {
        feed_id: String,
        current: u64,
        proposed: u64,
    },
    #[error("finding status epoch {map_epoch} equivocated for feed `{feed_id}`")]
    Equivocation { feed_id: String, map_epoch: u64 },
    #[error("non-inclusion contradicts sticky status for finding `{finding_id}`")]
    ContradictoryNonInclusion { finding_id: String },
    #[error("finding status proof for `{finding_id}` is stale at {trusted_now}")]
    StaleProof {
        finding_id: String,
        trusted_now: u64,
    },
}

/// A storage-neutral boundary for an epoch artifact already verified by the
/// status-feed verifier.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedFindingStatusEpochInput<'a> {
    pub feed_id: &'a str,
    /// Stable operator authorization identity. Key rotation does not change it.
    pub operator_id: &'a str,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub epoch_id: &'a str,
    pub root_hash: &'a str,
    /// Exact canonical signed envelope bytes accepted by the verifier.
    pub signed_epoch_bytes: &'a [u8],
    pub operator_key: &'a str,
    pub operator_key_epoch: u64,
    pub operator_authorization_sha256: &'a str,
    pub generated_at: u64,
    pub valid_until: u64,
    pub recorded_at: u64,
}

/// One retained exact signed status epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusEpochRecord {
    pub feed_id: String,
    pub operator_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub epoch_id: String,
    pub root_hash: String,
    pub signed_epoch_sha256: String,
    pub signed_epoch_bytes: Vec<u8>,
    pub operator_key: String,
    pub operator_key_epoch: u64,
    pub operator_authorization_sha256: String,
    pub generated_at: u64,
    pub valid_until: u64,
    pub recorded_at: u64,
}

/// The durable rollback floor for one feed and its stable operator identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusFeedFloor {
    pub feed_id: String,
    pub operator_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub epoch_id: String,
    pub root_hash: String,
    pub signed_epoch_sha256: String,
    pub operator_key: String,
    pub operator_key_epoch: u64,
    pub operator_authorization_sha256: String,
    pub advanced_at: u64,
}

/// Origin of a locally durable retraction intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingRetractionIntentSource {
    Voluntary,
    Enforcement,
}

/// Durable outbox lifecycle for a retraction intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingRetractionIntentState {
    WaitingFinality,
    DispatchEligible,
    Published,
}

/// Exact local retraction intent to persist before any external effect.
#[derive(Debug, Clone, Copy)]
pub struct FindingRetractionIntentInput<'a> {
    pub intent_id: &'a str,
    pub feed_id: &'a str,
    pub operator_id: &'a str,
    pub finding_id: &'a str,
    pub source: FindingRetractionIntentSource,
    /// Exact canonical signed intent bytes.
    pub intent_bytes: &'a [u8],
    pub issued_at: u64,
    pub inclusion_deadline: u64,
    pub created_at: u64,
}

/// Retained retraction intent and its outbox state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRetractionIntentRecord {
    pub intent_id: String,
    pub feed_id: String,
    pub operator_id: String,
    pub finding_id: String,
    pub source: FindingRetractionIntentSource,
    pub intent_sha256: String,
    pub intent_bytes: Vec<u8>,
    pub issued_at: u64,
    pub inclusion_deadline: u64,
    pub state: FindingRetractionIntentState,
    pub finality_evidence_sha256: Option<String>,
    pub finality_evidence_bytes: Option<Vec<u8>>,
    pub dispatch_eligible_at: Option<u64>,
    pub published_map_epoch: Option<u64>,
    pub published_epoch_id: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Sticky local status. There is deliberately no `live` row: liveness needs a
/// fresh non-inclusion proof at the current durable floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStickyStatus {
    Pending,
    Retracted,
}

/// One sticky local status row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusRecord {
    pub feed_id: String,
    pub operator_id: String,
    pub finding_id: String,
    pub state: FindingStickyStatus,
    pub retraction_intent_sha256: String,
    pub first_observed_at: u64,
    pub updated_at: u64,
    pub retracted_map_epoch: Option<u64>,
    pub retracted_epoch_id: Option<String>,
    pub retracted_root_hash: Option<String>,
}

/// A sparse-map leaf already verified against the supplied signed epoch.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedFindingStatusLeafInput<'a> {
    pub finding_id: &'a str,
    pub status_value_bytes: &'a [u8],
    pub retraction_intent_sha256: &'a str,
    /// Present when this inclusion completes a local durable outbox intent.
    pub local_intent_id: Option<&'a str>,
}

/// Retained sticky sparse-map leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusLeafRecord {
    pub feed_id: String,
    pub operator_id: String,
    pub finding_id: String,
    pub key_domain_nonce: u64,
    pub status_value_sha256: String,
    pub status_value_bytes: Vec<u8>,
    pub retraction_intent_sha256: String,
    pub local_intent_id: Option<String>,
    pub first_map_epoch: u64,
    pub first_epoch_id: String,
    pub recorded_at: u64,
}

/// Closed portable proof branch persisted by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusProofKind {
    Inclusion,
    NonInclusion,
}

/// Storage-neutral boundary for a portable proof input already verified by the
/// sparse-map verifier.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedFindingStatusProofInput<'a> {
    pub feed_id: &'a str,
    pub operator_id: &'a str,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub epoch_id: &'a str,
    pub root_hash: &'a str,
    pub finding_id: &'a str,
    pub kind: FindingStatusProofKind,
    /// Exact canonical portable proof-input bytes.
    pub proof_bytes: &'a [u8],
    pub status_value_bytes: Option<&'a [u8]>,
    pub retraction_intent_sha256: Option<&'a str>,
    pub checked_at: u64,
    pub valid_until: u64,
    pub recorded_at: u64,
}

/// A retained proof joined to the exact signed epoch bytes it authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusProofRecord {
    pub feed_id: String,
    pub operator_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub epoch_id: String,
    pub root_hash: String,
    pub finding_id: String,
    pub kind: FindingStatusProofKind,
    pub proof_sha256: String,
    pub proof_bytes: Vec<u8>,
    pub status_value_sha256: Option<String>,
    pub status_value_bytes: Option<Vec<u8>>,
    pub retraction_intent_sha256: Option<String>,
    pub checked_at: u64,
    pub valid_until: u64,
    pub recorded_at: u64,
    pub signed_epoch_sha256: String,
    pub signed_epoch_bytes: Vec<u8>,
}

/// Epoch advance plus any leaf updates and portable proofs verified against it.
#[derive(Debug, Clone, Copy)]
pub struct FindingStatusEpochAdvance<'a> {
    pub epoch: VerifiedFindingStatusEpochInput<'a>,
    pub leaves: &'a [VerifiedFindingStatusLeafInput<'a>],
    pub proofs: &'a [VerifiedFindingStatusProofInput<'a>],
}

/// Whether a durable mutation inserted new state or reconciled exact state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusWriteOutcome {
    Inserted,
    ExactReplay,
}

/// Fail-closed status decision for purchase or guarded use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingStatusDecision {
    Pending(FindingStatusRecord),
    Retracted(FindingStatusRecord),
    VerifiedLive(FindingStatusProofRecord),
}

#[derive(Clone)]
pub struct SqliteFindingStatusStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFindingStatusStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FindingStatusStoreError> {
        self.connection.lock().map_err(|_| {
            FindingStatusStoreError::Unavailable(
                "sqlite finding status store lock poisoned".to_owned(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingStatusStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingStatusStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FindingStatusStoreError> {
        #[cfg(feature = "cognition-market-experimental")]
        self.serving_owner
            .append_finding_challenge_projection_if_changed(&transaction)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))?;
        #[cfg(feature = "cognition-market-experimental")]
        self.serving_owner
            .append_finding_status_projection_if_changed(&transaction)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))?;
        transaction.commit().map_err(|error| {
            FindingStatusStoreError::OutcomeUnknown(
                self.serving_owner
                    .outcome_unknown(format!(
                        "sqlite finding status commit outcome is unknown: {error}"
                    ))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FindingStatusStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))
    }

    /// Atomically persist a local retraction intent and the sticky pending row.
    /// Exact replay is a no-op; a second intent for the same finding conflicts.
    pub fn issue_retraction_intent(
        &self,
        input: &FindingRetractionIntentInput<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        validate_intent_input(input)?;
        let intent_sha256 = sha256_hex(input.intent_bytes);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        ensure_feed_tx(
            &transaction,
            input.feed_id,
            input.operator_id,
            input.created_at,
        )?;

        if let Some(existing) = load_intent_tx(&transaction, input.intent_id)? {
            verify_intent_replay(&existing, input, &intent_sha256)?;
            let status = load_status_tx(&transaction, input.feed_id, input.finding_id)?
                .ok_or_else(|| invariant("exact intent replay is missing its sticky status row"))?;
            verify_intent_status_pair(&existing, &status)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(FindingStatusWriteOutcome::ExactReplay);
        }

        if let Some(status) = load_status_tx(&transaction, input.feed_id, input.finding_id)? {
            return Err(FindingStatusStoreError::Conflict(format!(
                "finding {} is already {:?} under intent {}",
                input.finding_id, status.state, status.retraction_intent_sha256
            )));
        }

        let (initial_state, finality_sha256, finality_bytes, dispatch_eligible_at) = match input
            .source
        {
            FindingRetractionIntentSource::Voluntary => (
                "dispatch_eligible",
                Some(intent_sha256.as_str()),
                Some(input.intent_bytes),
                Some(sqlite_i64(input.created_at, "created_at")?),
            ),
            FindingRetractionIntentSource::Enforcement => ("waiting_finality", None, None, None),
        };
        transaction
            .execute(
                r#"
                INSERT INTO finding_retraction_intents (
                    intent_id, feed_id, operator_id, finding_id, source,
                    intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                    state, finality_evidence_sha256, finality_evidence_bytes,
                    dispatch_eligible_at, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                          ?10, ?11, ?12, ?13, ?14, ?14)
                "#,
                params![
                    input.intent_id,
                    input.feed_id,
                    input.operator_id,
                    input.finding_id,
                    intent_source_name(input.source),
                    intent_sha256,
                    input.intent_bytes,
                    sqlite_i64(input.issued_at, "issued_at")?,
                    sqlite_i64(input.inclusion_deadline, "inclusion_deadline")?,
                    initial_state,
                    finality_sha256,
                    finality_bytes,
                    dispatch_eligible_at,
                    sqlite_i64(input.created_at, "created_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                r#"
                INSERT INTO finding_status_states (
                    feed_id, operator_id, finding_id, state,
                    retraction_intent_sha256, first_observed_at, updated_at
                ) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5)
                "#,
                params![
                    input.feed_id,
                    input.operator_id,
                    input.finding_id,
                    intent_sha256,
                    sqlite_i64(input.created_at, "created_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingStatusWriteOutcome::Inserted)
    }

    /// Atomically enter an appeal-final liability into `finalizing`, set its
    /// publication-pending bit, and persist the exact enforcement retraction
    /// outbox item plus sticky pending status. A prior voluntary retraction
    /// for the same feed and finding is retained as the satisfying outbox
    /// item instead of being replaced.
    ///
    /// This is the M5/M6 transaction boundary. An evaluation or reversible
    /// hold cannot call it because the liability must still be in the durable
    /// `pending_appeal` state. Exact replay accepts an already-finalizing head
    /// only when the outbox and sticky row remain consistent.
    #[cfg(feature = "cognition-market-experimental")]
    pub fn begin_finalizing_with_retraction(
        &self,
        liability_key: &str,
        sanction_case_id: &str,
        authorization: &FindingFinalizingAuthorizationInput<'_>,
        input: &FindingRetractionIntentInput<'_>,
        now: u64,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_identifier(sanction_case_id, "sanction_case_id")?;
        validate_intent_input(input)?;
        require_positive(now, "now")?;
        if input.source != FindingRetractionIntentSource::Enforcement || input.created_at != now {
            return Err(invariant(
                "finalizing transition requires a current enforcement retraction intent",
            ));
        }
        let intent_sha256 = sha256_hex(input.intent_bytes);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let transition_outcome = begin_finalizing_under_sanction_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::PendingAppeal,
            sanction_case_id,
            authorization,
            now,
        )
        .map_err(|error| {
            FindingStatusStoreError::Conflict(format!(
                "appeal-final liability transition rejected: {error}"
            ))
        })?;

        ensure_feed_tx(
            &transaction,
            input.feed_id,
            input.operator_id,
            input.created_at,
        )?;
        let intent_outcome = if let Some(existing) = load_intent_tx(&transaction, input.intent_id)?
        {
            verify_intent_replay(&existing, input, &intent_sha256)?;
            let status = load_status_tx(&transaction, input.feed_id, input.finding_id)?
                .ok_or_else(|| invariant("exact intent replay is missing its sticky status row"))?;
            verify_intent_status_pair(&existing, &status)?;
            FindingStatusWriteOutcome::ExactReplay
        } else if let Some(status) = load_status_tx(&transaction, input.feed_id, input.finding_id)?
        {
            let existing =
                load_intent_by_finding_tx(&transaction, input.feed_id, input.finding_id)?
                    .ok_or_else(|| {
                        invariant("sticky status is missing its durable retraction intent")
                    })?;
            if existing.source != FindingRetractionIntentSource::Voluntary
                || existing.operator_id != input.operator_id
            {
                return Err(FindingStatusStoreError::Conflict(format!(
                    "finding {} is already governed by a different retraction intent",
                    input.finding_id
                )));
            }
            verify_intent_status_pair(&existing, &status)?;
            FindingStatusWriteOutcome::ExactReplay
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_retraction_intents (
                        intent_id, feed_id, operator_id, finding_id, source,
                        intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                        state, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 'enforcement', ?5, ?6, ?7, ?8,
                              'waiting_finality', ?9, ?9)
                    "#,
                    params![
                        input.intent_id,
                        input.feed_id,
                        input.operator_id,
                        input.finding_id,
                        intent_sha256,
                        input.intent_bytes,
                        sqlite_i64(input.issued_at, "issued_at")?,
                        sqlite_i64(input.inclusion_deadline, "inclusion_deadline")?,
                        sqlite_i64(input.created_at, "created_at")?,
                    ],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_states (
                        feed_id, operator_id, finding_id, state,
                        retraction_intent_sha256, first_observed_at, updated_at
                    ) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5)
                    "#,
                    params![
                        input.feed_id,
                        input.operator_id,
                        input.finding_id,
                        intent_sha256,
                        sqlite_i64(input.created_at, "created_at")?,
                    ],
                )
                .map_err(sqlite_error)?;
            FindingStatusWriteOutcome::Inserted
        };

        self.serving_owner
            .append_finding_challenge_projection_if_changed(&transaction)
            .map_err(|error| FindingStatusStoreError::Unavailable(error.to_string()))?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        if intent_outcome == FindingStatusWriteOutcome::Inserted
            || transition_outcome
                == crate::finding_challenge_store::FindingChallengeWriteOutcome::Inserted
        {
            Ok(FindingStatusWriteOutcome::Inserted)
        } else {
            Ok(FindingStatusWriteOutcome::ExactReplay)
        }
    }

    /// Mark a persisted intent dispatch-eligible after exact finality evidence
    /// has been verified. The evidence is retained byte-for-byte for recovery.
    pub fn mark_retraction_dispatch_eligible(
        &self,
        intent_id: &str,
        finality_evidence_bytes: &[u8],
        authorized_at: u64,
        inclusion_sla_secs: u64,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        require_hex64(intent_id, "intent_id")?;
        require_bytes(
            finality_evidence_bytes,
            MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
            "finality_evidence_bytes",
        )?;
        require_positive(authorized_at, "authorized_at")?;
        require_positive(inclusion_sla_secs, "inclusion_sla_secs")?;
        let inclusion_deadline = authorized_at
            .checked_add(inclusion_sla_secs)
            .ok_or_else(|| invariant("dispatch inclusion deadline overflowed"))?;
        let inclusion_deadline = sqlite_i64(inclusion_deadline, "inclusion_deadline")?;
        let evidence_sha256 = sha256_hex(finality_evidence_bytes);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing = load_intent_tx(&transaction, intent_id)?.ok_or_else(|| {
            FindingStatusStoreError::Conflict(format!(
                "retraction intent {intent_id} is not durable"
            ))
        })?;
        match existing.state {
            FindingRetractionIntentState::WaitingFinality => {
                if authorized_at < existing.created_at {
                    return Err(invariant("dispatch eligibility predates the intent"));
                }
                transaction
                    .execute(
                        r#"
                        UPDATE finding_retraction_intents
                        SET state = 'dispatch_eligible',
                            finality_evidence_sha256 = ?2,
                            finality_evidence_bytes = ?3,
                            issued_at = ?4,
                            inclusion_deadline = ?5,
                            dispatch_eligible_at = ?4,
                            updated_at = ?4
                        WHERE intent_id = ?1 AND state = 'waiting_finality'
                        "#,
                        params![
                            intent_id,
                            evidence_sha256,
                            finality_evidence_bytes,
                            sqlite_i64(authorized_at, "authorized_at")?,
                            inclusion_deadline,
                        ],
                    )
                    .map_err(sqlite_error)?;
                self.commit_write(transaction)?;
                self.sync_after_write(&connection)?;
                Ok(FindingStatusWriteOutcome::Inserted)
            }
            FindingRetractionIntentState::DispatchEligible
            | FindingRetractionIntentState::Published => {
                if existing.finality_evidence_sha256.as_deref() != Some(&evidence_sha256)
                    || existing.finality_evidence_bytes.as_deref() != Some(finality_evidence_bytes)
                {
                    return Err(FindingStatusStoreError::Conflict(format!(
                        "retraction intent {intent_id} has different finality evidence"
                    )));
                }
                transaction.commit().map_err(sqlite_error)?;
                Ok(FindingStatusWriteOutcome::ExactReplay)
            }
        }
    }

    /// Atomically advance the signed epoch floor and retain any verified leaf
    /// updates and proof inputs associated with that exact epoch.
    pub fn advance_epoch(
        &self,
        advance: &FindingStatusEpochAdvance<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        validate_epoch_input(&advance.epoch)?;
        for leaf in advance.leaves {
            validate_leaf_input(leaf)?;
        }
        for proof in advance.proofs {
            validate_proof_input(proof)?;
            verify_proof_epoch_binding(proof, &advance.epoch)?;
        }
        require_unique_leaf_inputs(advance.leaves)?;
        require_unique_proof_inputs(advance.proofs)?;
        require_leaf_proofs(advance.leaves, advance.proofs)?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        ensure_feed_tx(
            &transaction,
            advance.epoch.feed_id,
            advance.epoch.operator_id,
            advance.epoch.recorded_at,
        )?;
        let prior_floor = load_floor_tx(&transaction, advance.epoch.feed_id)?;
        let mut outcome = persist_epoch_tx(&transaction, &advance.epoch, prior_floor.as_ref())?;

        for leaf in advance.leaves {
            if persist_leaf_tx(&transaction, &advance.epoch, leaf)?
                == FindingStatusWriteOutcome::Inserted
            {
                outcome = FindingStatusWriteOutcome::Inserted;
            }
        }
        for proof in advance.proofs {
            if persist_proof_tx(&transaction, proof)? == FindingStatusWriteOutcome::Inserted {
                outcome = FindingStatusWriteOutcome::Inserted;
            }
        }

        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Advance only the durable signed epoch floor.
    pub fn observe_verified_epoch(
        &self,
        epoch: &VerifiedFindingStatusEpochInput<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        self.advance_epoch(&FindingStatusEpochAdvance {
            epoch: *epoch,
            leaves: &[],
            proofs: &[],
        })
    }

    /// Retain a verified portable proof only when it names the exact current
    /// floor. Inclusion makes local status sticky; non-inclusion never clears it.
    pub fn record_verified_proof(
        &self,
        proof: &VerifiedFindingStatusProofInput<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        validate_proof_input(proof)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        ensure_feed_exists_tx(&transaction, proof.feed_id, proof.operator_id)?;
        let floor = load_floor_tx(&transaction, proof.feed_id)?.ok_or_else(|| {
            FindingStatusStoreError::MissingFloor {
                feed_id: proof.feed_id.to_owned(),
            }
        })?;
        verify_proof_floor_binding(proof, &floor)?;
        let outcome = persist_proof_tx(&transaction, proof)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Type-safe inclusion wrapper over [`Self::record_verified_proof`].
    pub fn observe_verified_inclusion(
        &self,
        proof: &VerifiedFindingStatusProofInput<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        if proof.kind != FindingStatusProofKind::Inclusion {
            return Err(invariant("inclusion API received a non-inclusion proof"));
        }
        self.record_verified_proof(proof)
    }

    /// Type-safe non-inclusion wrapper over [`Self::record_verified_proof`].
    pub fn observe_verified_non_inclusion(
        &self,
        proof: &VerifiedFindingStatusProofInput<'_>,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        if proof.kind != FindingStatusProofKind::NonInclusion {
            return Err(invariant("non-inclusion API received an inclusion proof"));
        }
        self.record_verified_proof(proof)
    }

    /// Load the durable rollback floor. A registered feed without a floor is a
    /// fail-closed error, never an implicit epoch zero.
    pub fn get_feed_floor(
        &self,
        feed_id: &str,
    ) -> Result<FindingStatusFeedFloor, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let floor = load_floor_tx(&transaction, feed_id)?.ok_or_else(|| {
            FindingStatusStoreError::MissingFloor {
                feed_id: feed_id.to_owned(),
            }
        })?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(floor)
    }

    /// Return the exact signed bytes for the current epoch of a feed.
    pub fn get_current_epoch(
        &self,
        feed_id: &str,
    ) -> Result<FindingStatusEpochRecord, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let floor = load_floor_tx(&transaction, feed_id)?.ok_or_else(|| {
            FindingStatusStoreError::MissingFloor {
                feed_id: feed_id.to_owned(),
            }
        })?;
        let epoch = load_epoch_tx(&transaction, feed_id, floor.map_epoch)?
            .ok_or_else(|| invariant("durable floor points to a missing status epoch"))?;
        verify_floor_epoch_consistency(&floor, &epoch)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(epoch)
    }

    /// Return an exact historical signed epoch by map epoch.
    pub fn get_epoch(
        &self,
        feed_id: &str,
        map_epoch: u64,
    ) -> Result<Option<FindingStatusEpochRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_positive(map_epoch, "map_epoch")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let epoch = load_epoch_tx(&transaction, feed_id, map_epoch)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(epoch)
    }

    /// Return the most recent retained proof and the exact signed epoch bytes
    /// it authenticates. A registered feed with no floor fails closed.
    pub fn get_latest_proof(
        &self,
        feed_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingStatusProofRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let floor = load_floor_tx(&transaction, feed_id)?.ok_or_else(|| {
            FindingStatusStoreError::MissingFloor {
                feed_id: feed_id.to_owned(),
            }
        })?;
        let proof = load_proof_tx(&transaction, feed_id, finding_id, floor.map_epoch)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(proof)
    }

    /// Load sticky local status, if one has been observed.
    pub fn get_finding_status(
        &self,
        feed_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingStatusRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let status = load_status_tx(&transaction, feed_id, finding_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(status)
    }

    /// Resolve a purchase-time decision. Only a fresh non-inclusion proof at
    /// the exact current floor can produce `VerifiedLive`.
    pub fn status_for_purchase(
        &self,
        feed_id: &str,
        finding_id: &str,
        trusted_now: u64,
    ) -> Result<FindingStatusDecision, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_hex64(finding_id, "finding_id")?;
        require_positive(trusted_now, "trusted_now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;

        if let Some(status) = load_status_tx(&transaction, feed_id, finding_id)? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(match status.state {
                FindingStickyStatus::Pending => FindingStatusDecision::Pending(status),
                FindingStickyStatus::Retracted => FindingStatusDecision::Retracted(status),
            });
        }

        let floor = load_floor_tx(&transaction, feed_id)?.ok_or_else(|| {
            FindingStatusStoreError::MissingFloor {
                feed_id: feed_id.to_owned(),
            }
        })?;
        let proof = load_proof_tx(&transaction, feed_id, finding_id, floor.map_epoch)?.ok_or_else(
            || FindingStatusStoreError::MissingState {
                finding_id: finding_id.to_owned(),
            },
        )?;
        if proof.kind != FindingStatusProofKind::NonInclusion {
            return Err(invariant(
                "inclusion proof exists without the required sticky retracted state",
            ));
        }
        verify_proof_record_at_floor(&proof, &floor)?;
        if trusted_now < proof.checked_at || trusted_now >= proof.valid_until {
            return Err(FindingStatusStoreError::StaleProof {
                finding_id: finding_id.to_owned(),
                trusted_now,
            });
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(FindingStatusDecision::VerifiedLive(proof))
    }

    /// Load a local retraction intent by id.
    pub fn get_retraction_intent(
        &self,
        intent_id: &str,
    ) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
        require_hex64(intent_id, "intent_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let intent = load_intent_tx(&transaction, intent_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(intent)
    }

    /// Resolve the status intent satisfying one signed enforcement effect.
    ///
    /// The normal path is the exact enforcement intent id. If an authorized
    /// voluntary retraction made the finding sticky first, the unique intent
    /// for the same feed and finding satisfies the effect without replacing
    /// its signed bytes or sticky digest.
    #[cfg(feature = "cognition-market-experimental")]
    pub fn get_retraction_intent_for_effect(
        &self,
        effect_intent_id: &str,
        feed_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
        require_hex64(effect_intent_id, "effect_intent_id")?;
        require_identifier(feed_id, "feed_id")?;
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let intent = if let Some(intent) = load_intent_tx(&transaction, effect_intent_id)? {
            if intent.feed_id != feed_id || intent.finding_id != finding_id {
                return Err(FindingStatusStoreError::Conflict(
                    "retraction effect resolves to a different feed or finding".to_owned(),
                ));
            }
            Some(intent)
        } else {
            match load_intent_by_finding_tx(&transaction, feed_id, finding_id)? {
                Some(intent) if intent.source == FindingRetractionIntentSource::Voluntary => {
                    Some(intent)
                }
                Some(_) => {
                    return Err(FindingStatusStoreError::Conflict(
                        "retraction effect does not name the durable enforcement intent".to_owned(),
                    ));
                }
                None => None,
            }
        };
        if let Some(intent) = intent.as_ref() {
            let status = load_status_tx(&transaction, feed_id, finding_id)?
                .ok_or_else(|| invariant("resolved retraction intent has no sticky status"))?;
            verify_intent_status_pair(intent, &status)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(intent)
    }

    /// Return a bounded ordered batch of dispatch-eligible outbox intents.
    pub fn list_dispatch_eligible_intents(
        &self,
        feed_id: &str,
        limit: usize,
    ) -> Result<Vec<FindingRetractionIntentRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        if limit == 0 || limit > 200 {
            return Err(invariant("intent query limit must be between 1 and 200"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT intent_id, feed_id, operator_id, finding_id, source,
                       intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                       state, finality_evidence_sha256, finality_evidence_bytes,
                       dispatch_eligible_at, published_map_epoch,
                       published_epoch_id, created_at, updated_at
                FROM finding_retraction_intents
                WHERE feed_id = ?1 AND state = 'dispatch_eligible'
                ORDER BY created_at, intent_id
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![feed_id, sqlite_i64(limit as u64, "limit")?],
                raw_intent_from_row,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let intents = rows
            .into_iter()
            .map(intent_from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(intents)
    }

    /// Return work the cadence publisher must revisit. This includes newly
    /// dispatch-eligible intents and published sticky leaves whose inclusion
    /// proof is absent at the current floor or is no longer fresh.
    pub fn list_publication_candidates(
        &self,
        feed_id: &str,
        trusted_now: u64,
        limit: usize,
    ) -> Result<Vec<FindingRetractionIntentRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_positive(trusted_now, "trusted_now")?;
        if limit == 0 || limit > 200 {
            return Err(invariant("intent query limit must be between 1 and 200"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT intent_id, feed_id, operator_id, finding_id, source,
                       intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                       state, finality_evidence_sha256, finality_evidence_bytes,
                       dispatch_eligible_at, published_map_epoch,
                       published_epoch_id, created_at, updated_at
                FROM finding_retraction_intents AS intent
                WHERE intent.feed_id = ?1
                  AND (
                    intent.state = 'dispatch_eligible'
                    OR (
                      intent.state = 'published'
                      AND NOT EXISTS (
                        SELECT 1
                        FROM finding_status_feed_floors AS floor
                        JOIN finding_status_proofs AS proof
                          ON proof.feed_id = floor.feed_id
                         AND proof.map_epoch = floor.map_epoch
                         AND proof.finding_id = intent.finding_id
                         AND proof.proof_kind = 'inclusion'
                         AND proof.valid_until > ?2
                        WHERE floor.feed_id = intent.feed_id
                      )
                    )
                  )
                ORDER BY CASE intent.state
                           WHEN 'dispatch_eligible' THEN 0 ELSE 1
                         END,
                         intent.created_at, intent.intent_id
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    feed_id,
                    sqlite_i64(trusted_now, "trusted_now")?,
                    sqlite_i64(limit as u64, "limit")?,
                ],
                raw_intent_from_row,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let intents = rows
            .into_iter()
            .map(intent_from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(intents)
    }

    /// Return live findings whose retained non-inclusion proof cannot satisfy
    /// the current durable floor. This includes proofs displaced by any epoch
    /// advance and current-floor proofs whose signed validity has expired.
    pub fn list_non_inclusion_refresh_candidates(
        &self,
        feed_id: &str,
        trusted_now: u64,
        limit: usize,
    ) -> Result<Vec<FindingStatusProofRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_positive(trusted_now, "trusted_now")?;
        if limit == 0 || limit > 200 {
            return Err(invariant("proof query limit must be between 1 and 200"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let query = format!(
            r#"
            {PROOF_SELECT}
            JOIN finding_status_feed_floors AS floor
              ON floor.feed_id = p.feed_id
            WHERE p.feed_id = ?1
              AND p.proof_kind = 'non_inclusion'
              AND NOT EXISTS (
                SELECT 1
                FROM finding_status_states AS status
                WHERE status.feed_id = p.feed_id
                  AND status.finding_id = p.finding_id
              )
              AND NOT EXISTS (
                SELECT 1
                FROM finding_status_proofs AS current
                WHERE current.feed_id = p.feed_id
                  AND current.finding_id = p.finding_id
                  AND current.map_epoch = floor.map_epoch
                  AND current.proof_kind = 'non_inclusion'
                  AND current.valid_until > ?2
              )
              AND p.map_epoch = (
                SELECT MAX(latest.map_epoch)
                FROM finding_status_proofs AS latest
                WHERE latest.feed_id = p.feed_id
                  AND latest.finding_id = p.finding_id
                  AND latest.proof_kind = 'non_inclusion'
              )
            ORDER BY p.recorded_at, p.finding_id
            LIMIT ?3
            "#
        );
        let mut statement = transaction.prepare(&query).map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    feed_id,
                    sqlite_i64(trusted_now, "trusted_now")?,
                    sqlite_i64(limit as u64, "limit")?,
                ],
                raw_proof_from_row,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let proofs = rows
            .into_iter()
            .map(proof_from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(proofs)
    }

    /// Load one retained retracted leaf.
    pub fn get_leaf(
        &self,
        feed_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingStatusLeafRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let leaf = load_leaf_tx(&transaction, feed_id, finding_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(leaf)
    }

    /// List all sticky retracted leaves needed to rebuild the sparse map.
    pub fn list_leaves(
        &self,
        feed_id: &str,
    ) -> Result<Vec<FindingStatusLeafRecord>, FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT feed_id, operator_id, finding_id, key_domain_nonce,
                       status_value_sha256, status_value_bytes,
                       retraction_intent_sha256, local_intent_id,
                       first_map_epoch, first_epoch_id, recorded_at
                FROM finding_status_leaves
                WHERE feed_id = ?1
                ORDER BY finding_id
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([feed_id], raw_leaf_from_row)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let leaves = rows
            .into_iter()
            .map(leaf_from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(leaves)
    }
}

include!("finding_status_store/persistence.rs");

#[cfg(test)]
#[path = "finding_status_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
