//! Durable storage for the finding challenge and audit lane: submitted
//! challenges and the verdicts that close them, the exclusive dispute
//! bond a buyer submission locks, the liability head one defect opens,
//! the governance case index that resolves that head's authoritative
//! case, the sealed claim snapshot, and the domain-keyed effect intents
//! fenced before anything leaves this operator.
//!
//! Six tables back the lane. `challenges` is the adjudication record:
//! one authorization branch, one evidence class, one bounded retry, and a
//! lifecycle that only ever runs
//! `submitted -> evaluating -> rejected | indeterminate_retryable |
//! indeterminate_closed | upheld`, with `indeterminate_retryable` the one
//! state that may re-enter evaluation. `dispute_locks` holds the bond a
//! buyer submission puts up: exclusive per challenge, disposed exactly
//! once, and never reused for a second challenge. `liability_heads` is
//! the money-bearing head: one row per defect on one backed listing,
//! advanced only by compare-and-set from `open` through
//! `upheld_pending_claims`, `pending_appeal`, and `finalizing` to
//! `settled`, with `reversed_before_impairment` as the appeal terminal.
//! `governance_case_index` records the sanction and appeal cases that
//! target a liability and resolves the single live head among them.
//! `claim_snapshots` seals the frozen accounting the payout derives from.
//! `effect_intents` is the durable fence every external effect passes
//! through before it is dispatched.
//!
//! Writes run under `TransactionBehavior::Immediate` behind the
//! serving-owner fence; reads run `Deferred`; a commit whose outcome
//! cannot be observed surfaces as outcome-unknown and poisons the owner
//! exactly like the sibling stores.
//!
//! The store shares one connection and one serving-owner fence with the
//! purchase store, which is what makes [`SqliteFindingChallengeStore::uphold_liability`]
//! possible: the liability compare-and-set that records the upheld
//! challenge and freezes the purchase cutoff commits in the same
//! transaction as the sales block that stops the purchase store's slot
//! line growing past it. No slot can open in between, so the frozen
//! cutoff is exactly the listing's high-water mark. The appeal terminal
//! is the mirror of that transaction:
//! [`SqliteFindingChallengeStore::reverse_liability_before_impairment`]
//! lifts the block in the same commit that exonerates the head, so a
//! seller who wins an appeal is selling again the moment the reversal is
//! durable.
//!
//! The store is not an authority boundary: envelope signature
//! verification, evidence adjudication, and penalty authorization belong
//! to the surfaces that call in here. The store enforces the durable
//! invariants those surfaces rely on: closed lifecycles that cannot skip
//! or revisit a state, a challenger present exactly when the branch is a
//! buyer submission, a bond that cannot be forfeited except against a
//! rejected challenge, a liability head whose upheld challenge and
//! purchase cutoff freeze together and never move again, a case head that
//! refuses to resolve while two live cases target the same defect, and an
//! effect intent whose commitment digest can never be rewritten under a
//! key that is already durable.
//!
//! Every mutation is idempotent by its natural key following the durable
//! fee-intent fence: a replay carrying the same identity succeeds without
//! re-applying the effect, and a replay with conflicting parameters
//! rejects rather than overwriting what is already durable. Identity is
//! the semantic content of the write; the trusted times a caller supplies
//! are not part of it, so a retry issued from a later clock replays rather
//! than stranding the durable row it is retrying.

use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
use crate::finding_purchase_store::{
    block_new_slots_tx, highest_slot_ordinal_tx, lift_sales_block_tx,
    outstanding_exposure_total_tx, FindingPurchaseStoreError,
};
use crate::serving_owner::SqliteServingOwner;

const FINDING_CHALLENGE_SCHEMA_KEY: &str = "finding_challenge";
pub(crate) const FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION: i32 = 3;
const FINDING_CHALLENGE_SCHEMA_ANCHORS: &[&str] =
    &["challenges", "admission_operations", "chio_serving_owner"];
const FINDING_CHALLENGE_SCHEMA: &str = include_str!("finding_challenge_store.sql");

/// Upper bound on every opaque identifier this store persists. An
/// unbounded identifier is an amplification vector rather than a name.
const MAX_IDENTIFIER_BYTES: usize = 512;
/// Upper bound on the opaque governance case state. The governance
/// surface owns that vocabulary; the store only refuses one too long to
/// be a state name.
const MAX_CASE_STATE_BYTES: usize = 64;

const DISPUTE_BOND_FUNDING_DOMAIN: &str = "chio.finding.dispute-bond-funding.v1";
const DISPUTE_BOND_RETURN_DOMAIN: &str = "chio.finding.dispute-bond-return.v1";
/// Retries one challenge may take after an indeterminate verdict. An
/// indeterminate result is an infrastructure or authority failure rather
/// than an answer, so the challenge is entitled to exactly one further
/// evaluation inside its signed window; the next indeterminate verdict
/// closes it. Raising this bound would let an unavailable dependency hold
/// a bond indefinitely.
const MAX_CHALLENGE_RETRIES: u64 = 1;
/// Batch clamp for the list readers, keeping one transaction bounded.
const MAX_LIST_ROWS: usize = 512;

/// Errors surfaced by the finding-challenge store. Fail-closed: every
/// rejection denies the mutation and rolls the transaction back.
#[derive(Debug, Error)]
pub enum FindingChallengeStoreError {
    #[error("finding challenge store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding challenge store fence rejected the caller")]
    Fenced,
    #[error("finding challenge record not found")]
    NotFound,
    #[error("finding challenge conflict: {0}")]
    Conflict(String),
    #[error("finding challenge invariant violated: {0}")]
    Invariant(String),
    #[error(
        "liability {liability_key} has two live governance cases ({first_case_id} and {second_case_id}); no case head can be resolved"
    )]
    AmbiguousCaseHead {
        liability_key: String,
        first_case_id: String,
        second_case_id: String,
    },
    #[error("finding challenge commit outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

/// Lifecycle of one challenge. `submitted`, `evaluating`, and
/// `indeterminate_retryable` are live; `rejected`, `indeterminate_closed`,
/// and `upheld` are terminal. Only `upheld` may enter the penalty lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeState {
    Submitted,
    Evaluating,
    Rejected,
    IndeterminateRetryable,
    IndeterminateClosed,
    Upheld,
}

/// The class-independent verdict an evaluation returns.
///
/// `Indeterminate` carries the trusted deadline of the signed retry
/// window when the challenge is entitled to one. Absent a deadline, or
/// once the retry bound or the deadline itself is spent, the challenge
/// closes indeterminate: an evaluation that cannot establish its inputs
/// never becomes a rejection and never sanctions a seller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeVerdict {
    Upheld,
    Rejected,
    Indeterminate { retry_deadline: Option<u64> },
}

/// Which authorization branch a challenge was submitted under. A buyer
/// submission names a challenger and posts a dispute bond; a venue audit
/// names neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeAuthorizationBranch {
    BuyerSubmission,
    VenueAudit,
}

/// The single mechanical evidence class a challenge presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeEvidenceClass {
    DigestMismatch,
    EvidenceInvalid,
    ReplayContradiction,
}

/// What [`SqliteFindingChallengeStore::begin_evaluation`] did with the
/// challenge. `RetryWindowExpired` means the signed retry window had
/// already lapsed, so the store closed the challenge indeterminate rather
/// than admitting a late evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeEvaluationStart {
    Started,
    AlreadyEvaluating,
    RetryWindowExpired,
}

/// Lifecycle of one dispute bond lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingDisputeLockState {
    Locked,
    Returned,
    Forfeited,
}

/// The two ways a dispute bond leaves `locked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingDisputeLockDisposition {
    Returned,
    Forfeited,
}

/// Lifecycle of one liability head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingLiabilityState {
    Open,
    UpheldPendingClaims,
    PendingAppeal,
    Finalizing,
    Settled,
    ReversedBeforeImpairment,
}

/// The two governance case kinds that target a liability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingGovernanceCaseKind {
    Sanction,
    Appeal,
}

/// The domain a semantic effect intent belongs to. Each kind is keyed by
/// its own domain-separated preimage, so intents in different domains can
/// never collide on one coarse key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingEffectIntentKind {
    SellerImpair,
    ChallengeBond,
    Fee,
    RootIntent,
    Retraction,
}

/// Lifecycle of one effect intent. `confirmed` and `quarantined` are
/// terminal; a quarantined intent is never dispatched again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingEffectIntentState {
    Pending,
    Dispatched,
    Confirmed,
    Failed,
    Quarantined,
}

/// Whether a write created durable state or replayed identical prior
/// state as a no-op. A lifecycle transition reports `Inserted` when it
/// applied the change and `ExistingSame` when the durable row already
/// carried it, so a resumed caller can tell the two apart without
/// re-reading the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeWriteOutcome {
    Inserted,
    ExistingSame,
}

/// Everything one submitted challenge is. `challenger_hex` is required
/// for a buyer submission and refused for a venue audit.
#[derive(Debug, Clone, Copy)]
pub struct FindingChallengeSubmission<'a> {
    pub challenge_id: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub challenge_envelope_sha256: &'a str,
    pub authorization_branch: FindingChallengeAuthorizationBranch,
    pub evidence_class: FindingChallengeEvidenceClass,
    pub challenger_hex: Option<&'a str>,
    pub submitted_at: u64,
}

/// One challenge row, including its live lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingChallengeRecord {
    pub challenge_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub challenge_envelope_sha256: String,
    pub authorization_branch: FindingChallengeAuthorizationBranch,
    pub evidence_class: FindingChallengeEvidenceClass,
    pub challenger_hex: Option<String>,
    pub state: FindingChallengeState,
    pub retry_count: u64,
    pub retry_deadline: Option<u64>,
    pub outcome_envelope_sha256: Option<String>,
    pub submitted_at: u64,
    pub updated_at: u64,
}

/// The dispute bond one buyer submission locks. `bond_class` is not a
/// parameter: the store pins it to the dispute class so a caller cannot
/// present a listing bond as a challenge bond.
#[derive(Debug, Clone, Copy)]
pub struct FindingDisputeLockInput<'a> {
    pub lock_id: &'a str,
    pub challenge_id: &'a str,
    pub owner_hex: &'a str,
    pub schedule_envelope_sha256: &'a str,
    pub amount_units: u64,
    pub currency: &'a str,
    pub expires_at: u64,
    pub locked_at: u64,
}

/// Durable key for the independently confirmed funding behind one dispute
/// lock. The challenge and lock identities are both present so one funded
/// lock cannot be claimed by another filing.
#[must_use]
pub fn derive_dispute_bond_funding_intent_key(challenge_id: &str, lock_id: &str) -> String {
    sha256_hex(format!("{DISPUTE_BOND_FUNDING_DOMAIN}\0{challenge_id}\0{lock_id}").as_bytes())
}

/// Commitment a confirmed funding intent must carry before the store will
/// turn it into an evaluable dispute lock.
#[must_use]
pub fn dispute_bond_funding_intent_digest(input: &FindingDisputeLockInput<'_>) -> String {
    sha256_hex(
        format!(
            "{DISPUTE_BOND_FUNDING_DOMAIN}\0{challenge}\0{lock}\0{owner}\0{schedule}\0{units}\0{currency}\0{expiry}",
            challenge = input.challenge_id,
            lock = input.lock_id,
            owner = input.owner_hex,
            schedule = input.schedule_envelope_sha256,
            units = input.amount_units,
            currency = input.currency,
            expiry = input.expires_at,
        )
        .as_bytes(),
    )
}

/// Durable key for the independently confirmed return of one dispute lock.
/// Funding and return use different domains so confirming the debit can
/// never satisfy the credit fence.
#[must_use]
pub fn derive_dispute_bond_return_intent_key(challenge_id: &str, lock_id: &str) -> String {
    sha256_hex(format!("{DISPUTE_BOND_RETURN_DOMAIN}\0{challenge_id}\0{lock_id}").as_bytes())
}

/// Commitment a confirmed return intent must carry before the store will
/// report a dispute lock as returned.
#[must_use]
pub fn dispute_bond_return_intent_digest(input: &FindingDisputeLockInput<'_>) -> String {
    sha256_hex(
        format!(
            "{DISPUTE_BOND_RETURN_DOMAIN}\0{challenge}\0{lock}\0{owner}\0{schedule}\0{units}\0{currency}\0{expiry}",
            challenge = input.challenge_id,
            lock = input.lock_id,
            owner = input.owner_hex,
            schedule = input.schedule_envelope_sha256,
            units = input.amount_units,
            currency = input.currency,
            expiry = input.expires_at,
        )
        .as_bytes(),
    )
}

/// One dispute bond lock row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDisputeLockRecord {
    pub lock_id: String,
    pub challenge_id: String,
    pub owner_hex: String,
    pub bond_class: String,
    pub schedule_envelope_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub expires_at: u64,
    pub state: FindingDisputeLockState,
    pub locked_at: u64,
    pub updated_at: u64,
}

/// The identity of one liability head: the defect it carries and the
/// exact backed listing and vault it is charged against.
#[derive(Debug, Clone, Copy)]
pub struct FindingLiabilityInput<'a> {
    pub liability_key: &'a str,
    pub defect_key: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub allocation_id: &'a str,
    pub venue_id: &'a str,
    pub chain_id: &'a str,
    pub vault_contract: &'a str,
    pub vault_id: &'a str,
    pub opened_at: u64,
}

/// One liability head row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingLiabilityRecord {
    pub liability_key: String,
    pub defect_key: String,
    pub finding_id: String,
    pub listing_id: String,
    pub allocation_id: String,
    pub venue_id: String,
    pub chain_id: String,
    pub vault_contract: String,
    pub vault_id: String,
    pub state: FindingLiabilityState,
    pub upheld_challenge_id: Option<String>,
    pub purchase_cutoff_slot: Option<u64>,
    /// Trusted time the seller-signed claim window closes. Frozen with
    /// the cutoff; no snapshot seals before it.
    pub claim_deadline: Option<u64>,
    /// Trusted time the seller-signed appeal window opened. Frozen with
    /// the absolute deadline when the head enters `pending_appeal`.
    pub appeal_window_opened_at: Option<u64>,
    /// Absolute trusted deadline derived from the signed appeal duration.
    pub appeal_deadline: Option<u64>,
    /// Envelope digest of the exact seller-signed terms that supplied the
    /// frozen appeal duration.
    pub appeal_terms_envelope_sha256: Option<String>,
    pub snapshot_digest: Option<String>,
    pub allocation_digest: Option<String>,
    pub publication_pending: bool,
    pub quarantined: bool,
    pub opened_at: u64,
    pub updated_at: u64,
}

/// One governance case targeting a liability.
#[derive(Debug, Clone, Copy)]
pub struct FindingGovernanceCaseInput<'a> {
    pub case_id: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub liability_key: &'a str,
    pub case_kind: FindingGovernanceCaseKind,
    /// Opaque to this store: the governance surface owns the vocabulary.
    pub case_state: &'a str,
    pub appeal_of_case_id: Option<&'a str>,
    pub supersedes_case_id: Option<&'a str>,
    pub recorded_at: u64,
}

/// One governance case row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingGovernanceCaseRecord {
    pub case_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub liability_key: String,
    pub case_kind: FindingGovernanceCaseKind,
    pub case_state: String,
    pub appeal_of_case_id: Option<String>,
    pub supersedes_case_id: Option<String>,
    pub superseded_by_case_id: Option<String>,
    pub recorded_at: u64,
}

/// The frozen accounting a payout derives from, sealed once per
/// liability.
#[derive(Debug, Clone, Copy)]
pub struct FindingClaimSnapshotInput<'a> {
    pub liability_key: &'a str,
    pub cutoff_slot: u64,
    pub snapshot_digest: &'a str,
    pub allocation_digest: &'a str,
    pub total_realized_spend_units: u64,
    pub currency: &'a str,
    pub buyer_pool_units: u64,
    pub community_fund_units: u64,
    pub sealed_at: u64,
}

/// One sealed claim snapshot row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingClaimSnapshotRecord {
    pub liability_key: String,
    pub cutoff_slot: u64,
    pub snapshot_digest: String,
    pub allocation_digest: String,
    pub total_realized_spend_units: u64,
    pub currency: String,
    pub buyer_pool_units: u64,
    pub community_fund_units: u64,
    pub sealed_at: u64,
}

/// One effect intent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEffectIntentRecord {
    pub intent_key: String,
    pub liability_key: Option<String>,
    pub kind: FindingEffectIntentKind,
    pub intent_digest: String,
    /// Whether this effect must reach `confirmed` before its liability may
    /// leave `finalizing`.
    pub settlement_required: bool,
    pub state: FindingEffectIntentState,
    pub attempt_count: u64,
    pub recorded_at: u64,
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct SqliteFindingChallengeStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFindingChallengeStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    /// Serving identity shared by every store opened alongside this one.
    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FindingChallengeStoreError> {
        self.connection.lock().map_err(|_| {
            FindingChallengeStoreError::Unavailable(
                "sqlite finding challenge lock poisoned".to_owned(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingChallengeStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingChallengeStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingChallengeStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingChallengeStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FindingChallengeStoreError> {
        transaction.commit().map_err(|error| {
            FindingChallengeStoreError::OutcomeUnknown(
                self.serving_owner
                    .outcome_unknown(format!(
                        "sqlite finding challenge commit outcome is unknown: {error}"
                    ))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FindingChallengeStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FindingChallengeStoreError::Unavailable(error.to_string()))
    }

    /// Record one submitted challenge. Idempotent on the challenge id: a
    /// replay carrying the same challenge identity returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without disturbing
    /// the adjudication already in progress, and conflicting parameters
    /// under an existing challenge id reject. The signed challenge
    /// envelope digest is a dedup key in its own right, so a second
    /// challenge id presenting one envelope rejects rather than opening a
    /// second adjudication of the same submission.
    pub fn submit_challenge(
        &self,
        input: &FindingChallengeSubmission<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_submission(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_challenge_tx(&transaction, input.challenge_id)? {
            if challenge_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "challenge id is already bound to different challenge parameters".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT challenge_id FROM challenges WHERE challenge_envelope_sha256 = ?1",
            input.challenge_envelope_sha256,
            "challenge envelope digest",
        )?;
        let submitted_at = sqlite_i64(input.submitted_at, "submitted_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO challenges (
                    challenge_id, finding_id, listing_id,
                    challenge_envelope_sha256, authorization_branch,
                    evidence_class, challenger_hex, state, retry_count,
                    retry_deadline, outcome_envelope_sha256, submitted_at,
                    updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'submitted', 0, NULL, NULL, ?8, ?8
                )
                "#,
                params![
                    input.challenge_id,
                    input.finding_id,
                    input.listing_id,
                    input.challenge_envelope_sha256,
                    authorization_branch_name(input.authorization_branch),
                    evidence_class_name(input.evidence_class),
                    input.challenger_hex,
                    submitted_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("challenge insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Move one challenge into evaluation. A submitted challenge starts
    /// its first evaluation; a retryable one starts its retry, but only
    /// inside the signed window it was granted. Past that deadline the
    /// challenge closes indeterminate here rather than admitting a late
    /// evaluation, so a lapsed window can never produce a verdict.
    /// Idempotent: a challenge already evaluating is left alone.
    pub fn begin_evaluation(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<FindingChallengeEvaluationStart, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let (from, to, outcome) = match challenge.state {
            FindingChallengeState::Evaluating => {
                return Ok(FindingChallengeEvaluationStart::AlreadyEvaluating);
            }
            FindingChallengeState::Submitted => (
                "submitted",
                "evaluating",
                FindingChallengeEvaluationStart::Started,
            ),
            FindingChallengeState::IndeterminateRetryable => {
                let deadline = challenge
                    .retry_deadline
                    .ok_or_else(|| invariant("retryable challenge holds no retry deadline"))?;
                if now < deadline {
                    (
                        "indeterminate_retryable",
                        "evaluating",
                        FindingChallengeEvaluationStart::Started,
                    )
                } else {
                    (
                        "indeterminate_retryable",
                        "indeterminate_closed",
                        FindingChallengeEvaluationStart::RetryWindowExpired,
                    )
                }
            }
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "challenge cannot enter evaluation from state {}",
                    challenge_state_name(other)
                )));
            }
        };
        advance_challenge_state_tx(&transaction, challenge_id, from, to, now)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Close one evaluation against its signed outcome, returning the
    /// state the challenge landed in.
    ///
    /// `Upheld` and `Rejected` are terminal immediately. `Indeterminate`
    /// grants at most one retry, and only when the caller carries a signed
    /// retry deadline still in the future and the challenge has not spent
    /// its retry already; every other indeterminate result closes the
    /// challenge. An indeterminate verdict never becomes a rejection, so
    /// it can neither forfeit a bond nor reach the penalty lane.
    ///
    /// Idempotent: replaying one verdict under the same outcome digest
    /// returns the state that verdict produced; a different verdict or a
    /// different outcome digest against a closed challenge rejects.
    pub fn record_verdict(
        &self,
        challenge_id: &str,
        verdict: FindingChallengeVerdict,
        outcome_envelope_sha256: &str,
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_hex64(outcome_envelope_sha256, "outcome_envelope_sha256")?;
        require_trusted_time(now, "now")?;
        if let FindingChallengeVerdict::Indeterminate {
            retry_deadline: Some(deadline),
        } = verdict
        {
            require_trusted_time(deadline, "retry_deadline")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        match challenge.state {
            FindingChallengeState::Evaluating => {}
            FindingChallengeState::Submitted => {
                return Err(FindingChallengeStoreError::Conflict(
                    "a verdict requires an evaluation already in progress".to_owned(),
                ));
            }
            recorded => {
                if challenge.outcome_envelope_sha256.as_deref() == Some(outcome_envelope_sha256)
                    && verdict_admits_state(verdict, recorded)
                {
                    return Ok(recorded);
                }
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "challenge already carries a verdict in state {}",
                    challenge_state_name(recorded)
                )));
            }
        }
        let (target, retry_count, retry_deadline) = match verdict {
            FindingChallengeVerdict::Upheld => (
                FindingChallengeState::Upheld,
                challenge.retry_count,
                challenge.retry_deadline,
            ),
            FindingChallengeVerdict::Rejected => (
                FindingChallengeState::Rejected,
                challenge.retry_count,
                challenge.retry_deadline,
            ),
            FindingChallengeVerdict::Indeterminate { retry_deadline } => {
                match retry_deadline.filter(|deadline| *deadline > now) {
                    Some(deadline) if challenge.retry_count < MAX_CHALLENGE_RETRIES => {
                        let spent = challenge
                            .retry_count
                            .checked_add(1)
                            .ok_or_else(|| invariant("challenge retry count overflowed u64"))?;
                        (
                            FindingChallengeState::IndeterminateRetryable,
                            spent,
                            Some(deadline),
                        )
                    }
                    _ => (
                        FindingChallengeState::IndeterminateClosed,
                        challenge.retry_count,
                        challenge.retry_deadline,
                    ),
                }
            }
        };
        let changed = transaction
            .execute(
                r#"
                UPDATE challenges
                SET state = ?2, retry_count = ?3, retry_deadline = ?4,
                    outcome_envelope_sha256 = ?5, updated_at = ?6
                WHERE challenge_id = ?1 AND state = 'evaluating'
                "#,
                params![
                    challenge_id,
                    challenge_state_name(target),
                    sqlite_i64(retry_count, "retry_count")?,
                    retry_deadline
                        .map(|deadline| sqlite_i64(deadline, "retry_deadline"))
                        .transpose()?,
                    outcome_envelope_sha256,
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("challenge verdict did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(target)
    }

    /// One challenge by its id.
    pub fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<FindingChallengeRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_challenge_tx(&transaction, challenge_id)
    }

    /// Every challenge against one finding on one listing, oldest first.
    pub fn list_challenges(
        &self,
        finding_id: &str,
        listing_id: &str,
    ) -> Result<Vec<FindingChallengeRecord>, FindingChallengeStoreError> {
        require_hex64(finding_id, "finding_id")?;
        require_identifier(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {CHALLENGE_COLUMNS} FROM challenges
                WHERE finding_id = ?1 AND listing_id = ?2
                ORDER BY submitted_at ASC, challenge_id ASC
                LIMIT ?3
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![finding_id, listing_id, list_limit()?],
                map_challenge,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(challenge_from_raw).collect()
    }

    /// Lock one buyer submission's dispute bond. The bond is exclusive
    /// per challenge, is pinned to the dispute class, and must be owned by
    /// the challenger the challenge names, so a third party cannot post a
    /// bond for someone else's submission. A venue audit posts no bond and
    /// is refused here.
    ///
    /// Idempotent on the challenge: an identical replay returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without locking
    /// again, and conflicting parameters reject.
    pub fn lock_dispute_bond(
        &self,
        input: &FindingDisputeLockInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_dispute_lock(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let funding_key = derive_dispute_bond_funding_intent_key(input.challenge_id, input.lock_id);
        let funding = load_effect_intent_tx(&transaction, &funding_key)?.ok_or_else(|| {
            FindingChallengeStoreError::Conflict(
                "dispute bond has no independently confirmed funding intent".to_owned(),
            )
        })?;
        if funding.kind != FindingEffectIntentKind::ChallengeBond
            || funding.liability_key.is_some()
            || funding.settlement_required
            || funding.intent_digest != dispute_bond_funding_intent_digest(input)
            || funding.state != FindingEffectIntentState::Confirmed
        {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond funding intent is not confirmed for this lock".to_owned(),
            ));
        }
        if let Some(existing) = load_dispute_lock_tx(&transaction, input.challenge_id)? {
            if dispute_lock_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "challenge is already bound to a different dispute bond".to_owned(),
            ));
        }
        let challenge = load_challenge_tx(&transaction, input.challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Err(FindingChallengeStoreError::Conflict(
                "a venue audit posts no dispute bond".to_owned(),
            ));
        }
        if challenge.challenger_hex.as_deref() != Some(input.owner_hex) {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond owner is not the challenger the challenge names".to_owned(),
            ));
        }
        if is_terminal_challenge_state(challenge.state) {
            return Err(FindingChallengeStoreError::Conflict(
                "a closed challenge cannot take a fresh dispute bond".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT challenge_id FROM dispute_locks WHERE lock_id = ?1",
            input.lock_id,
            "dispute lock id",
        )?;
        let locked_at = sqlite_i64(input.locked_at, "locked_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO dispute_locks (
                    lock_id, challenge_id, owner_hex, bond_class,
                    schedule_envelope_sha256, amount_units, currency,
                    expires_at, state, locked_at, updated_at
                ) VALUES (?1, ?2, ?3, 'dispute', ?4, ?5, ?6, ?7, 'locked', ?8, ?8)
                "#,
                params![
                    input.lock_id,
                    input.challenge_id,
                    input.owner_hex,
                    input.schedule_envelope_sha256,
                    sqlite_i64(input.amount_units, "amount_units")?,
                    input.currency,
                    sqlite_i64(input.expires_at, "expires_at")?,
                    locked_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("dispute lock insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Dispose one dispute bond exactly once.
    ///
    /// A bond is only disposed once its challenge is closed, and
    /// forfeiture is only available against a rejected challenge: an
    /// upheld challenge gets its bond back, and an indeterminate one never
    /// forfeits for an infrastructure or availability failure. Idempotent
    /// on the disposition already recorded; a second, different
    /// disposition rejects.
    pub fn release_dispute_bond(
        &self,
        challenge_id: &str,
        disposition: FindingDisputeLockDisposition,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let lock = load_dispute_lock_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        match lock.state {
            FindingDisputeLockState::Locked => {}
            settled => {
                if settled == disposed_lock_state(disposition) {
                    return Ok(FindingChallengeWriteOutcome::ExistingSame);
                }
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "dispute bond was already {}",
                    dispute_lock_state_name(settled)
                )));
            }
        }
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or_else(|| invariant("dispute lock outlived its challenge"))?;
        if !is_terminal_challenge_state(challenge.state) {
            return Err(FindingChallengeStoreError::Conflict(
                "a dispute bond is disposed only once its challenge closes".to_owned(),
            ));
        }
        if disposition == FindingDisputeLockDisposition::Forfeited
            && challenge.state != FindingChallengeState::Rejected
        {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "a dispute bond cannot be forfeited against a challenge in state {}",
                challenge_state_name(challenge.state)
            )));
        }
        if disposition == FindingDisputeLockDisposition::Returned {
            let input = FindingDisputeLockInput {
                lock_id: &lock.lock_id,
                challenge_id: &lock.challenge_id,
                owner_hex: &lock.owner_hex,
                schedule_envelope_sha256: &lock.schedule_envelope_sha256,
                amount_units: lock.amount_units,
                currency: &lock.currency,
                expires_at: lock.expires_at,
                locked_at: lock.locked_at,
            };
            let return_key =
                derive_dispute_bond_return_intent_key(input.challenge_id, input.lock_id);
            let returned = load_effect_intent_tx(&transaction, &return_key)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict(
                    "dispute bond has no independently confirmed return intent".to_owned(),
                )
            })?;
            if returned.kind != FindingEffectIntentKind::ChallengeBond
                || returned.liability_key.is_some()
                || returned.settlement_required
                || returned.intent_digest != dispute_bond_return_intent_digest(&input)
                || returned.state != FindingEffectIntentState::Confirmed
            {
                return Err(FindingChallengeStoreError::Conflict(
                    "dispute bond return intent is not confirmed for this lock".to_owned(),
                ));
            }
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE dispute_locks SET state = ?2, updated_at = ?3
                WHERE challenge_id = ?1 AND state = 'locked'
                "#,
                params![
                    challenge_id,
                    dispute_lock_state_name(disposed_lock_state(disposition)),
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("dispute bond disposition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The dispute bond locked for one challenge, if it posted one.
    pub fn get_dispute_lock(
        &self,
        challenge_id: &str,
    ) -> Result<Option<FindingDisputeLockRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_dispute_lock_tx(&transaction, challenge_id)
    }

    /// Open one liability head. Idempotent on the liability key: a replay
    /// carrying the same defect, listing, allocation, and vault returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without disturbing
    /// the state the head has already reached, and conflicting parameters
    /// reject. One defect on one backed listing has exactly one head, so
    /// a second corroborating challenge joins it rather than opening a
    /// second slashable liability.
    pub fn open_liability(
        &self,
        input: &FindingLiabilityInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_liability(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_liability_tx(&transaction, input.liability_key)? {
            if liability_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "liability key is already bound to a different defect or vault".to_owned(),
            ));
        }
        let opened_at = sqlite_i64(input.opened_at, "opened_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO liability_heads (
                    liability_key, defect_key, finding_id, listing_id,
                    allocation_id, venue_id, chain_id, vault_contract, vault_id,
                    state, upheld_challenge_id, purchase_cutoff_slot,
                    claim_deadline, appeal_window_opened_at, appeal_deadline,
                    appeal_terms_envelope_sha256, snapshot_digest,
                    allocation_digest, publication_pending, quarantined,
                    opened_at, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, ?10, ?10
                )
                "#,
                params![
                    input.liability_key,
                    input.defect_key,
                    input.finding_id,
                    input.listing_id,
                    input.allocation_id,
                    input.venue_id,
                    input.chain_id,
                    input.vault_contract,
                    input.vault_id,
                    opened_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("liability head insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The first upheld transaction: compare-and-set the liability head
    /// from `open` to `upheld_pending_claims`, record the challenge that
    /// carried it there, freeze the purchase cutoff, and block new
    /// pending-purchase slots on the listing, all in one immediate
    /// transaction on the connection the purchase store shares.
    ///
    /// The block and the frozen cutoff commit together or not at all,
    /// which is what makes the cutoff meaningful: a reserve racing this
    /// transaction either takes its slot before the block lands, and so
    /// sits at or below the cutoff the caller froze, or sees the block and
    /// is refused. No slot can appear above the cutoff and below the
    /// block.
    ///
    /// Only an upheld challenge on this liability's own finding and
    /// listing may carry it, and the cutoff must cover every slot the
    /// listing has already handed out, so no buyer who paid before the
    /// block can fall above the claim line. Idempotent on the exact
    /// challenge and cutoff already frozen; a different challenge or a
    /// different cutoff rejects.
    ///
    /// `claim_deadline` freezes with the cutoff and is never rewritten,
    /// so the window harmed buyers were promised is fixed by the first
    /// call. A replay derives its own deadline from its own clock and
    /// that value is ignored, which is what stops a retry shortening the
    /// window it is resuming.
    pub fn uphold_liability(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.uphold_liability_inner(
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            None,
            now,
        )
    }

    /// Freeze and block exactly like [`Self::uphold_liability`], while
    /// atomically requiring the authoritative allocation exposure to
    /// equal the evaluator-signed calculation. A reservation racing the
    /// coordinator's earlier read therefore lands wholly before this
    /// check and rejects the transition, or wholly after the sales block
    /// and is refused by the purchase store.
    pub fn uphold_liability_with_exposure_fence(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        expected_open_exposure_units: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.uphold_liability_inner(
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            Some(expected_open_exposure_units),
            now,
        )
    }

    fn uphold_liability_inner(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        expected_open_exposure_units: Option<u64>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        require_trusted_time(claim_deadline, "claim_deadline")?;
        if claim_deadline <= now {
            return Err(FindingChallengeStoreError::Conflict(
                "claim deadline has already lapsed at the upheld transaction".to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(expected) = expected_open_exposure_units {
            let liability = load_liability_tx(&transaction, liability_key)?
                .ok_or(FindingChallengeStoreError::NotFound)?;
            if liability.state == FindingLiabilityState::Open {
                let authoritative =
                    outstanding_exposure_total_tx(&transaction, &liability.allocation_id, now)
                        .map_err(purchase_error)?;
                if authoritative != expected {
                    return Err(FindingChallengeStoreError::Conflict(
                        "allocation exposure changed before the upheld transaction".to_owned(),
                    ));
                }
            }
        }
        let outcome = uphold_liability_tx(
            &transaction,
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Compare-and-set `upheld_pending_claims -> pending_appeal`, freezing
    /// the seller-signed appeal window in the same transaction.
    ///
    /// The caller supplies the already verified signed duration and the
    /// digest of the terms envelope that carried it. The store derives the
    /// absolute deadline from the trusted transition clock. A replay must
    /// present the same duration and envelope digest, and never recomputes
    /// the absolute deadline from its later clock.
    pub fn begin_appeal_window(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        appeal_terms_envelope_sha256: &str,
        appeal_window_secs: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_hex64(appeal_terms_envelope_sha256, "appeal_terms_envelope_sha256")?;
        require_trusted_time(now, "now")?;
        if appeal_window_secs == 0 {
            return Err(invariant("appeal_window_secs must be nonzero"));
        }
        require_transition_source(
            expected_state,
            FindingLiabilityState::UpheldPendingClaims,
            FindingLiabilityState::PendingAppeal,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state == FindingLiabilityState::PendingAppeal {
            let same_window = liability
                .appeal_window_opened_at
                .and_then(|opened_at| opened_at.checked_add(appeal_window_secs))
                == liability.appeal_deadline;
            if same_window
                && liability.appeal_terms_envelope_sha256.as_deref()
                    == Some(appeal_terms_envelope_sha256)
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "appeal window is already bound to different signed terms".to_owned(),
            ));
        }
        if liability.state != FindingLiabilityState::UpheldPendingClaims {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected upheld_pending_claims",
                liability_state_name(liability.state)
            )));
        }
        let appeal_deadline = now
            .checked_add(appeal_window_secs)
            .ok_or_else(|| invariant("appeal deadline overflowed u64"))?;
        let changed = transaction
            .execute(
                r#"
                UPDATE liability_heads
                SET state = 'pending_appeal', appeal_window_opened_at = ?2,
                    appeal_deadline = ?3, appeal_terms_envelope_sha256 = ?4,
                    updated_at = ?2
                WHERE liability_key = ?1 AND state = 'upheld_pending_claims'
                "#,
                params![
                    liability_key,
                    sqlite_i64(now, "now")?,
                    sqlite_i64(appeal_deadline, "appeal_deadline")?,
                    appeal_terms_envelope_sha256,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("appeal-window transition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Test-only raw lifecycle edge. Production finalization must use
    /// [`Self::begin_finalizing_under_sanction`] so the case head and the
    /// liability state are serialized in one transaction.
    #[cfg(test)]
    pub fn begin_finalizing(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.transition_liability(
            liability_key,
            expected_state,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::Finalizing,
            Some(true),
            now,
        )
    }

    /// Compare-and-set `pending_appeal -> finalizing` only while the named
    /// sanction is still the exact live governance case.
    ///
    /// This check and the state transition share one immediate
    /// transaction with appeal recording. Whichever write wins decides
    /// the outcome: a successful appeal that supersedes the sanction makes
    /// this edge refuse, while a finalizing edge that lands first makes a
    /// later appeal refuse because the liability is no longer pending
    /// appeal. Neither ordering can strand a successful appeal behind a
    /// finalizing head.
    pub fn begin_finalizing_under_sanction(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        sanction_case_id: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_identifier(sanction_case_id, "sanction_case_id")?;
        require_trusted_time(now, "now")?;
        require_transition_source(
            expected_state,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::Finalizing,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let head = resolve_case_head_tx(&transaction, liability_key)?.ok_or_else(|| {
            FindingChallengeStoreError::Conflict(
                "liability carries no live governance case".to_owned(),
            )
        })?;
        if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id
        {
            return Err(FindingChallengeStoreError::Conflict(
                "the named sanction is not the live governance case".to_owned(),
            ));
        }
        let (outcome, _) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::Finalizing,
            Some(true),
            now,
        )?;
        if outcome == FindingChallengeWriteOutcome::ExistingSame {
            return Ok(outcome);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Compare-and-set `finalizing -> settled`, clearing the pending
    /// publication only after every required effect is confirmed.
    ///
    /// The gate and the lifecycle transition share one immediate
    /// transaction. Exactly one required seller impairment, root
    /// publication, and retraction must exist for the liability, and no
    /// required effect may remain in any state other than `confirmed`.
    pub fn settle_liability(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(
            expected_state,
            FindingLiabilityState::Finalizing,
            FindingLiabilityState::Settled,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state == FindingLiabilityState::Settled {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected finalizing",
                liability_state_name(liability.state)
            )));
        }
        let (required, seller, root, retraction, unconfirmed): (i64, i64, i64, i64, i64) =
            transaction
                .query_row(
                    r#"
                    SELECT
                        COUNT(*),
                        COALESCE(SUM(kind = 'seller_impair'), 0),
                        COALESCE(SUM(kind = 'root_intent'), 0),
                        COALESCE(SUM(kind = 'retraction'), 0),
                        COALESCE(SUM(state <> 'confirmed'), 0)
                    FROM effect_intents
                    WHERE liability_key = ?1 AND settlement_required = 1
                    "#,
                    [liability_key],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .map_err(sqlite_error)?;
        if required < 3 || seller != 1 || root != 1 || retraction != 1 {
            return Err(FindingChallengeStoreError::Conflict(
                "liability does not carry the required finalization effect set".to_owned(),
            ));
        }
        if unconfirmed != 0 {
            return Err(FindingChallengeStoreError::Conflict(
                "liability still has unconfirmed required effects".to_owned(),
            ));
        }
        let (outcome, _) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::Finalizing,
            FindingLiabilityState::Settled,
            Some(false),
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Compare-and-set `pending_appeal -> reversed_before_impairment`,
    /// the appeal terminal. Nothing was impaired, so the head closes
    /// without a settlement and the seller is exonerated.
    ///
    /// The exoneration reaches the sale path in the same immediate
    /// transaction: the listing's sales block is lifted alongside the
    /// compare-and-set, so no restart can observe a head that cleared its
    /// appeal while the listing it names is still barred from selling.
    /// This is the one transition that lifts a block, and it is the mirror
    /// of the upheld transaction that raised it.
    ///
    /// The lift waits on the last holder. One listing carries one block
    /// however many heads reached it, so a listing another live liability
    /// still holds stays blocked and only that head's own exoneration
    /// releases it.
    pub fn reverse_liability_before_impairment(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(
            expected_state,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::ReversedBeforeImpairment,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (outcome, liability) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::ReversedBeforeImpairment,
            Some(false),
            now,
        )?;
        if !listing_holds_another_liability_tx(&transaction, &liability.listing_id, liability_key)?
        {
            lift_sales_block_tx(&transaction, &liability.listing_id, now)
                .map_err(purchase_error)?;
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Flag or clear the quarantine on one liability head. A quarantined
    /// head has an effect whose disposition cannot be established; it
    /// keeps its state and keeps purchases blocked.
    pub fn set_liability_quarantine(
        &self,
        liability_key: &str,
        quarantined: bool,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.quarantined == quarantined {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if is_terminal_liability_state(liability.state) {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "a liability in terminal state {} cannot change quarantine",
                liability_state_name(liability.state)
            )));
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE liability_heads SET quarantined = ?2, updated_at = ?3
                WHERE liability_key = ?1
                "#,
                params![
                    liability_key,
                    i64::from(quarantined),
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("liability quarantine did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// One liability head by its key.
    pub fn get_liability(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingLiabilityRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_liability_tx(&transaction, liability_key)
    }

    /// Every liability head carrying one defect, oldest first.
    pub fn list_liabilities_for_defect(
        &self,
        defect_key: &str,
    ) -> Result<Vec<FindingLiabilityRecord>, FindingChallengeStoreError> {
        require_hex64(defect_key, "defect_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {LIABILITY_COLUMNS} FROM liability_heads
                WHERE defect_key = ?1
                ORDER BY opened_at ASC, liability_key ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![defect_key, list_limit()?], map_liability)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(liability_from_raw).collect()
    }

    /// Record one governance case against a liability. A case that
    /// supersedes another stamps that predecessor superseded in the same
    /// transaction, so the index never commits a supersession only half
    /// applied. Idempotent on the case id; conflicting parameters reject,
    /// as does superseding a case that another case already superseded.
    pub fn record_governance_case(
        &self,
        input: &FindingGovernanceCaseInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_governance_case(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_case_tx(&transaction, input.case_id)? {
            if governance_case_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "case id is already bound to a different governance case".to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, input.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.finding_id != input.finding_id || liability.listing_id != input.listing_id {
            return Err(FindingChallengeStoreError::Conflict(
                "governance case does not name the liability's finding and listing".to_owned(),
            ));
        }
        // Successful appeal supersession and the transition to
        // `finalizing` contend under the same immediate-write lock. Once
        // finalization wins that compare-and-set, a late appeal cannot
        // replace the sanction between the coordinator's finality check
        // and impairment dispatch.
        if input.case_kind == FindingGovernanceCaseKind::Appeal
            && liability.state != FindingLiabilityState::PendingAppeal
        {
            return Err(FindingChallengeStoreError::Conflict(
                "an appeal may only be recorded while the liability is pending appeal".to_owned(),
            ));
        }
        if let Some(appealed) = input.appeal_of_case_id {
            let target = load_case_tx(&transaction, appealed)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict("appealed case is not recorded".to_owned())
            })?;
            if target.liability_key != input.liability_key {
                return Err(FindingChallengeStoreError::Conflict(
                    "an appeal must target a case on the same liability".to_owned(),
                ));
            }
            if target.case_kind != FindingGovernanceCaseKind::Sanction {
                return Err(FindingChallengeStoreError::Conflict(
                    "an appeal must target a sanction".to_owned(),
                ));
            }
        }
        if let Some(superseded) = input.supersedes_case_id {
            let target = load_case_tx(&transaction, superseded)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict("superseded case is not recorded".to_owned())
            })?;
            if target.liability_key != input.liability_key {
                return Err(FindingChallengeStoreError::Conflict(
                    "a case may only supersede one on the same liability".to_owned(),
                ));
            }
            if target.superseded_by_case_id.is_some() {
                return Err(FindingChallengeStoreError::Conflict(
                    "the named case has already been superseded".to_owned(),
                ));
            }
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO governance_case_index (
                    case_id, finding_id, listing_id, liability_key, case_kind,
                    case_state, appeal_of_case_id, supersedes_case_id,
                    superseded_by_case_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)
                "#,
                params![
                    input.case_id,
                    input.finding_id,
                    input.listing_id,
                    input.liability_key,
                    case_kind_name(input.case_kind),
                    input.case_state,
                    input.appeal_of_case_id,
                    input.supersedes_case_id,
                    sqlite_i64(input.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("governance case insert did not affect one row"));
        }
        if let Some(superseded) = input.supersedes_case_id {
            let changed = transaction
                .execute(
                    r#"
                    UPDATE governance_case_index SET superseded_by_case_id = ?2
                    WHERE case_id = ?1 AND superseded_by_case_id IS NULL
                    "#,
                    params![superseded, input.case_id],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant("case supersession did not affect one row"));
            }
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The single live governance case on one liability: the one no other
    /// case supersedes.
    ///
    /// Fails closed on ambiguity. Two live cases targeting one defect mean
    /// the operator cannot say which sanction or appeal governs it, and a
    /// penalty evaluated against the wrong one would slash under an
    /// authority that had been superseded, so the store refuses to name a
    /// head at all rather than pick one.
    pub fn resolve_case_head(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        resolve_case_head_tx(&transaction, liability_key)
    }

    /// One governance case by its id.
    pub fn get_governance_case(
        &self,
        case_id: &str,
    ) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_case_tx(&transaction, case_id)
    }

    /// Every governance case on one liability, oldest first.
    pub fn list_governance_cases(
        &self,
        liability_key: &str,
    ) -> Result<Vec<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {CASE_COLUMNS} FROM governance_case_index
                WHERE liability_key = ?1
                ORDER BY recorded_at ASC, case_id ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![liability_key, list_limit()?], map_case)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(case_from_raw).collect()
    }

    /// Seal one liability's claim snapshot. The snapshot is written once
    /// and stamps its two commitments onto the liability head in the same
    /// transaction, so the head can never name accounting that was not
    /// sealed. The cutoff it seals must be exactly the one the upheld
    /// transaction froze.
    ///
    /// Idempotent on an identical replay; any different figure rejects.
    pub fn seal_claim_snapshot(
        &self,
        input: &FindingClaimSnapshotInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_claim_snapshot(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_claim_snapshot_tx(&transaction, input.liability_key)? {
            if claim_snapshot_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "liability is already sealed under different claim figures".to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, input.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        match liability.state {
            FindingLiabilityState::UpheldPendingClaims | FindingLiabilityState::PendingAppeal => {}
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "a claim snapshot cannot be sealed from state {}",
                    liability_state_name(other)
                )));
            }
        }
        if liability.purchase_cutoff_slot != Some(input.cutoff_slot) {
            return Err(FindingChallengeStoreError::Conflict(
                "claim snapshot does not seal the frozen purchase cutoff".to_owned(),
            ));
        }
        // The snapshot is immutable once written, so an early seal is a
        // permanent loss of standing for every claim the window still had
        // time to admit. The frozen deadline is the only authority on when
        // that window closed.
        match liability.claim_deadline {
            Some(deadline) if input.sealed_at >= deadline => {}
            _ => {
                return Err(FindingChallengeStoreError::Conflict(
                    "claim window has not closed for this liability".to_owned(),
                ));
            }
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO claim_snapshots (
                    liability_key, cutoff_slot, snapshot_digest,
                    allocation_digest, total_realized_spend_units, currency,
                    buyer_pool_units, community_fund_units, sealed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    input.liability_key,
                    sqlite_i64(input.cutoff_slot, "cutoff_slot")?,
                    input.snapshot_digest,
                    input.allocation_digest,
                    sqlite_i64(
                        input.total_realized_spend_units,
                        "total_realized_spend_units"
                    )?,
                    input.currency,
                    sqlite_i64(input.buyer_pool_units, "buyer_pool_units")?,
                    sqlite_i64(input.community_fund_units, "community_fund_units")?,
                    sqlite_i64(input.sealed_at, "sealed_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("claim snapshot insert did not affect one row"));
        }
        let stamped = transaction
            .execute(
                r#"
                UPDATE liability_heads
                SET snapshot_digest = ?2, allocation_digest = ?3, updated_at = ?4
                WHERE liability_key = ?1 AND snapshot_digest IS NULL
                "#,
                params![
                    input.liability_key,
                    input.snapshot_digest,
                    input.allocation_digest,
                    sqlite_i64(input.sealed_at, "sealed_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if stamped != 1 {
            return Err(invariant("claim snapshot stamp did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// One liability's sealed claim snapshot.
    pub fn get_claim_snapshot(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingClaimSnapshotRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_claim_snapshot_tx(&transaction, liability_key)
    }

    /// Fence one semantic effect before anything is dispatched for it.
    ///
    /// `intent_key` is the domain-separated semantic key and
    /// `intent_digest` the canonical commitment to what that effect does.
    /// An identical retry reconciles to the same row and reports
    /// [`FindingChallengeWriteOutcome::ExistingSame`], so a resumed worker
    /// never fences twice. A different commitment under a key that is
    /// already durable is a conflicting disposition of one effect, and it
    /// rejects rather than rewriting what a dispatch may already have
    /// acted on.
    pub fn record_effect_intent(
        &self,
        intent_key: &str,
        kind: FindingEffectIntentKind,
        intent_digest: &str,
        liability_key: Option<&str>,
        settlement_required: bool,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_hex64(intent_digest, "intent_digest")?;
        if let Some(key) = liability_key {
            require_hex64(key, "liability_key")?;
        }
        if settlement_required && liability_key.is_none() {
            return Err(invariant(
                "a settlement-required effect must name its liability",
            ));
        }
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_effect_intent_tx(&transaction, intent_key)? {
            if existing.kind == kind
                && existing.intent_digest == intent_digest
                && existing.liability_key.as_deref() == liability_key
                && existing.settlement_required == settlement_required
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "conflicting effect intent under an existing intent key".to_owned(),
            ));
        }
        if let Some(key) = liability_key {
            if load_liability_tx(&transaction, key)?.is_none() {
                return Err(FindingChallengeStoreError::NotFound);
            }
        }
        let recorded_at = sqlite_i64(now, "now")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO effect_intents (
                    intent_key, liability_key, kind, intent_digest,
                    settlement_required, state, attempt_count, recorded_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6)
                "#,
                params![
                    intent_key,
                    liability_key,
                    effect_intent_kind_name(kind),
                    intent_digest,
                    i64::from(settlement_required),
                    recorded_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("effect intent insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Advance one effect intent along its dispatch lifecycle. Entering
    /// `dispatched` counts one attempt. Idempotent on the state already
    /// recorded; an illegal edge rejects.
    pub fn advance_effect_intent(
        &self,
        intent_key: &str,
        state: FindingEffectIntentState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if intent.state == state {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if !effect_intent_edge_is_legal(intent.state, state) {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "effect intent cannot move from {} to {}",
                effect_intent_state_name(intent.state),
                effect_intent_state_name(state)
            )));
        }
        let attempts = if state == FindingEffectIntentState::Dispatched {
            intent
                .attempt_count
                .checked_add(1)
                .ok_or_else(|| invariant("effect intent attempts overflowed u64"))?
        } else {
            intent.attempt_count
        };
        let changed = transaction
            .execute(
                r#"
                UPDATE effect_intents
                SET state = ?3, attempt_count = ?4, updated_at = ?5
                WHERE intent_key = ?1 AND state = ?2
                "#,
                params![
                    intent_key,
                    effect_intent_state_name(intent.state),
                    effect_intent_state_name(state),
                    sqlite_i64(attempts, "attempt_count")?,
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("effect intent transition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// One effect intent by its domain-separated key.
    pub fn get_effect_intent(
        &self,
        intent_key: &str,
    ) -> Result<Option<FindingEffectIntentRecord>, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_effect_intent_tx(&transaction, intent_key)
    }

    /// Every effect intent fenced for one liability, oldest first.
    pub fn list_effect_intents(
        &self,
        liability_key: &str,
    ) -> Result<Vec<FindingEffectIntentRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {EFFECT_INTENT_COLUMNS} FROM effect_intents
                WHERE liability_key = ?1
                ORDER BY recorded_at ASC, intent_key ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![liability_key, list_limit()?], map_effect_intent)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(effect_intent_from_raw).collect()
    }

    /// One liability edge, guarded twice: the caller names the state it
    /// believes the head is in, and that state must be the only legal
    /// source of this edge, so no caller can skip a state by naming a
    /// later one. Idempotent once the head already sits at the target.
    #[cfg(test)]
    fn transition_liability(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        source_state: FindingLiabilityState,
        target_state: FindingLiabilityState,
        publication_pending: Option<bool>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(expected_state, source_state, target_state)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (outcome, _) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            source_state,
            target_state,
            publication_pending,
            now,
        )?;
        if outcome == FindingChallengeWriteOutcome::ExistingSame {
            return Ok(outcome);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }
}

/// The caller names the state it believes a head is in, and that state
/// must be the only legal source of the edge it is asking for, so no
/// caller can skip a state by naming a later one.
fn require_transition_source(
    expected_state: FindingLiabilityState,
    source_state: FindingLiabilityState,
    target_state: FindingLiabilityState,
) -> Result<(), FindingChallengeStoreError> {
    if expected_state == source_state {
        return Ok(());
    }
    Err(FindingChallengeStoreError::Conflict(format!(
        "state {} is not the source of the transition to {}",
        liability_state_name(expected_state),
        liability_state_name(target_state)
    )))
}

/// One liability edge applied inside a caller-supplied transaction, paired
/// with the head as this transaction read it so a composing caller reaches
/// the listing it names without a second load. Identity columns are frozen
/// at insert, so the listing that record names is the one the edge moved.
/// Idempotent once the head already sits at the target.
fn apply_liability_transition_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    source_state: FindingLiabilityState,
    target_state: FindingLiabilityState,
    publication_pending: Option<bool>,
    now: u64,
) -> Result<(FindingChallengeWriteOutcome, FindingLiabilityRecord), FindingChallengeStoreError> {
    let liability = load_liability_tx(transaction, liability_key)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    if liability.state == target_state {
        return Ok((FindingChallengeWriteOutcome::ExistingSame, liability));
    }
    if liability.state != source_state {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "liability is in state {}, not the expected {}",
            liability_state_name(liability.state),
            liability_state_name(source_state)
        )));
    }
    let pending = publication_pending.unwrap_or(liability.publication_pending);
    let changed = transaction
        .execute(
            r#"
            UPDATE liability_heads
            SET state = ?3, publication_pending = ?4, updated_at = ?5
            WHERE liability_key = ?1 AND state = ?2
            "#,
            params![
                liability_key,
                liability_state_name(source_state),
                liability_state_name(target_state),
                i64::from(pending),
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("liability transition did not affect one row"));
    }
    Ok((FindingChallengeWriteOutcome::Inserted, liability))
}

/// Whether a liability head other than `liability_key` still holds one
/// listing's sales block. Every head past `open` carries an upheld
/// challenge, and so holds the listing until it is exonerated; a head that
/// never left `open` never blocked anything.
fn listing_holds_another_liability_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
    liability_key: &str,
) -> Result<bool, FindingChallengeStoreError> {
    let held: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM liability_heads
                WHERE listing_id = ?1 AND liability_key <> ?2
                  AND state NOT IN ('open', 'reversed_before_impairment')
            )
            "#,
            params![listing_id, liability_key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    Ok(held)
}

/// The upheld transaction, exposed on a caller-supplied transaction so a
/// coordinator can compose it with further writes on the same connection
/// without losing atomicity.
pub(crate) fn uphold_liability_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    challenge_id: &str,
    cutoff_slot: u64,
    claim_deadline: u64,
    now: u64,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    let liability = load_liability_tx(transaction, liability_key)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    let challenge = load_challenge_tx(transaction, challenge_id)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    if challenge.state != FindingChallengeState::Upheld {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "a challenge in state {} cannot uphold a liability",
            challenge_state_name(challenge.state)
        )));
    }
    if challenge.finding_id != liability.finding_id || challenge.listing_id != liability.listing_id
    {
        return Err(FindingChallengeStoreError::Conflict(
            "challenge does not name the liability's finding and listing".to_owned(),
        ));
    }
    // The cutoff has to cover every slot the listing has already handed
    // out. A cutoff below the high-water mark would leave buyers who paid
    // before the block sitting above the claim line, silently outside the
    // snapshot the payout derives from.
    let high_water =
        highest_slot_ordinal_tx(transaction, &liability.listing_id).map_err(purchase_error)?;
    if cutoff_slot < high_water {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "purchase cutoff {cutoff_slot} is below the listing slot high-water mark {high_water}"
        )));
    }
    if liability.state != FindingLiabilityState::Open {
        if liability.upheld_challenge_id.as_deref() == Some(challenge_id)
            && liability.purchase_cutoff_slot == Some(cutoff_slot)
        {
            // The block committed with the freeze, so it is already
            // durable; recording it again is a no-op that keeps the
            // replay path identical to the first call.
            block_new_slots_tx(transaction, &liability.listing_id, now).map_err(purchase_error)?;
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        return Err(FindingChallengeStoreError::Conflict(format!(
            "liability is in state {} and cannot be upheld again",
            liability_state_name(liability.state)
        )));
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE liability_heads
            SET state = 'upheld_pending_claims', upheld_challenge_id = ?2,
                purchase_cutoff_slot = ?3, claim_deadline = ?4, updated_at = ?5
            WHERE liability_key = ?1 AND state = 'open'
            "#,
            params![
                liability_key,
                challenge_id,
                sqlite_i64(cutoff_slot, "cutoff_slot")?,
                sqlite_i64(claim_deadline, "claim_deadline")?,
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("liability uphold did not affect one row"));
    }
    block_new_slots_tx(transaction, &liability.listing_id, now).map_err(purchase_error)?;
    Ok(FindingChallengeWriteOutcome::Inserted)
}

const CHALLENGE_COLUMNS: &str = r#"
    challenge_id, finding_id, listing_id, challenge_envelope_sha256,
    authorization_branch, evidence_class, challenger_hex, state, retry_count,
    retry_deadline, outcome_envelope_sha256, submitted_at, updated_at
"#;

struct RawChallenge {
    challenge_id: String,
    finding_id: String,
    listing_id: String,
    challenge_envelope_sha256: String,
    authorization_branch: String,
    evidence_class: String,
    challenger_hex: Option<String>,
    state: String,
    retry_count: i64,
    retry_deadline: Option<i64>,
    outcome_envelope_sha256: Option<String>,
    submitted_at: i64,
    updated_at: i64,
}

fn map_challenge(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawChallenge> {
    Ok(RawChallenge {
        challenge_id: row.get(0)?,
        finding_id: row.get(1)?,
        listing_id: row.get(2)?,
        challenge_envelope_sha256: row.get(3)?,
        authorization_branch: row.get(4)?,
        evidence_class: row.get(5)?,
        challenger_hex: row.get(6)?,
        state: row.get(7)?,
        retry_count: row.get(8)?,
        retry_deadline: row.get(9)?,
        outcome_envelope_sha256: row.get(10)?,
        submitted_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn challenge_from_raw(
    raw: RawChallenge,
) -> Result<FindingChallengeRecord, FindingChallengeStoreError> {
    Ok(FindingChallengeRecord {
        challenge_id: raw.challenge_id,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        challenge_envelope_sha256: raw.challenge_envelope_sha256,
        authorization_branch: authorization_branch_from_name(&raw.authorization_branch)?,
        evidence_class: evidence_class_from_name(&raw.evidence_class)?,
        challenger_hex: raw.challenger_hex,
        state: challenge_state_from_name(&raw.state)?,
        retry_count: stored_u64(raw.retry_count, "retry_count")?,
        retry_deadline: raw
            .retry_deadline
            .map(|value| stored_u64(value, "retry_deadline"))
            .transpose()?,
        outcome_envelope_sha256: raw.outcome_envelope_sha256,
        submitted_at: stored_u64(raw.submitted_at, "submitted_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_challenge_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
) -> Result<Option<FindingChallengeRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {CHALLENGE_COLUMNS} FROM challenges WHERE challenge_id = ?1"),
            [challenge_id],
            map_challenge,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(challenge_from_raw).transpose()
}

fn load_dispute_lock_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
) -> Result<Option<FindingDisputeLockRecord>, FindingChallengeStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT lock_id, challenge_id, owner_hex, bond_class,
                   schedule_envelope_sha256, amount_units, currency, expires_at,
                   state, locked_at, updated_at
            FROM dispute_locks WHERE challenge_id = ?1
            "#,
            [challenge_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        lock_id,
        challenge_id,
        owner_hex,
        bond_class,
        schedule_envelope_sha256,
        amount_units,
        currency,
        expires_at,
        state,
        locked_at,
        updated_at,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingDisputeLockRecord {
        lock_id,
        challenge_id,
        owner_hex,
        bond_class,
        schedule_envelope_sha256,
        amount_units: stored_u64(amount_units, "amount_units")?,
        currency,
        expires_at: stored_u64(expires_at, "expires_at")?,
        state: dispute_lock_state_from_name(&state)?,
        locked_at: stored_u64(locked_at, "locked_at")?,
        updated_at: stored_u64(updated_at, "updated_at")?,
    }))
}

const LIABILITY_COLUMNS: &str = r#"
    liability_key, defect_key, finding_id, listing_id, allocation_id, venue_id,
    chain_id, vault_contract, vault_id, state, upheld_challenge_id,
    purchase_cutoff_slot, claim_deadline, appeal_window_opened_at,
    appeal_deadline, appeal_terms_envelope_sha256, snapshot_digest,
    allocation_digest, publication_pending, quarantined, opened_at, updated_at
"#;

struct RawLiability {
    liability_key: String,
    defect_key: String,
    finding_id: String,
    listing_id: String,
    allocation_id: String,
    venue_id: String,
    chain_id: String,
    vault_contract: String,
    vault_id: String,
    state: String,
    upheld_challenge_id: Option<String>,
    purchase_cutoff_slot: Option<i64>,
    claim_deadline: Option<i64>,
    appeal_window_opened_at: Option<i64>,
    appeal_deadline: Option<i64>,
    appeal_terms_envelope_sha256: Option<String>,
    snapshot_digest: Option<String>,
    allocation_digest: Option<String>,
    publication_pending: i64,
    quarantined: i64,
    opened_at: i64,
    updated_at: i64,
}

fn map_liability(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawLiability> {
    Ok(RawLiability {
        liability_key: row.get(0)?,
        defect_key: row.get(1)?,
        finding_id: row.get(2)?,
        listing_id: row.get(3)?,
        allocation_id: row.get(4)?,
        venue_id: row.get(5)?,
        chain_id: row.get(6)?,
        vault_contract: row.get(7)?,
        vault_id: row.get(8)?,
        state: row.get(9)?,
        upheld_challenge_id: row.get(10)?,
        purchase_cutoff_slot: row.get(11)?,
        claim_deadline: row.get(12)?,
        appeal_window_opened_at: row.get(13)?,
        appeal_deadline: row.get(14)?,
        appeal_terms_envelope_sha256: row.get(15)?,
        snapshot_digest: row.get(16)?,
        allocation_digest: row.get(17)?,
        publication_pending: row.get(18)?,
        quarantined: row.get(19)?,
        opened_at: row.get(20)?,
        updated_at: row.get(21)?,
    })
}

fn liability_from_raw(
    raw: RawLiability,
) -> Result<FindingLiabilityRecord, FindingChallengeStoreError> {
    Ok(FindingLiabilityRecord {
        liability_key: raw.liability_key,
        defect_key: raw.defect_key,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        allocation_id: raw.allocation_id,
        venue_id: raw.venue_id,
        chain_id: raw.chain_id,
        vault_contract: raw.vault_contract,
        vault_id: raw.vault_id,
        state: liability_state_from_name(&raw.state)?,
        upheld_challenge_id: raw.upheld_challenge_id,
        purchase_cutoff_slot: raw
            .purchase_cutoff_slot
            .map(|value| stored_u64(value, "purchase_cutoff_slot"))
            .transpose()?,
        claim_deadline: raw
            .claim_deadline
            .map(|value| stored_u64(value, "claim_deadline"))
            .transpose()?,
        appeal_window_opened_at: raw
            .appeal_window_opened_at
            .map(|value| stored_u64(value, "appeal_window_opened_at"))
            .transpose()?,
        appeal_deadline: raw
            .appeal_deadline
            .map(|value| stored_u64(value, "appeal_deadline"))
            .transpose()?,
        appeal_terms_envelope_sha256: raw.appeal_terms_envelope_sha256,
        snapshot_digest: raw.snapshot_digest,
        allocation_digest: raw.allocation_digest,
        publication_pending: stored_flag(raw.publication_pending, "publication_pending")?,
        quarantined: stored_flag(raw.quarantined, "quarantined")?,
        opened_at: stored_u64(raw.opened_at, "opened_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_liability_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingLiabilityRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {LIABILITY_COLUMNS} FROM liability_heads WHERE liability_key = ?1"),
            [liability_key],
            map_liability,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(liability_from_raw).transpose()
}

const CASE_COLUMNS: &str = r#"
    case_id, finding_id, listing_id, liability_key, case_kind, case_state,
    appeal_of_case_id, supersedes_case_id, superseded_by_case_id, recorded_at
"#;

struct RawCase {
    case_id: String,
    finding_id: String,
    listing_id: String,
    liability_key: String,
    case_kind: String,
    case_state: String,
    appeal_of_case_id: Option<String>,
    supersedes_case_id: Option<String>,
    superseded_by_case_id: Option<String>,
    recorded_at: i64,
}

fn map_case(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCase> {
    Ok(RawCase {
        case_id: row.get(0)?,
        finding_id: row.get(1)?,
        listing_id: row.get(2)?,
        liability_key: row.get(3)?,
        case_kind: row.get(4)?,
        case_state: row.get(5)?,
        appeal_of_case_id: row.get(6)?,
        supersedes_case_id: row.get(7)?,
        superseded_by_case_id: row.get(8)?,
        recorded_at: row.get(9)?,
    })
}

fn case_from_raw(raw: RawCase) -> Result<FindingGovernanceCaseRecord, FindingChallengeStoreError> {
    Ok(FindingGovernanceCaseRecord {
        case_id: raw.case_id,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        liability_key: raw.liability_key,
        case_kind: case_kind_from_name(&raw.case_kind)?,
        case_state: raw.case_state,
        appeal_of_case_id: raw.appeal_of_case_id,
        supersedes_case_id: raw.supersedes_case_id,
        superseded_by_case_id: raw.superseded_by_case_id,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

fn load_case_tx(
    transaction: &Transaction<'_>,
    case_id: &str,
) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {CASE_COLUMNS} FROM governance_case_index WHERE case_id = ?1"),
            [case_id],
            map_case,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(case_from_raw).transpose()
}

/// Resolve the unique unsuperseded case inside a caller-owned transaction.
/// A write path uses this to serialize its lifecycle decision against case
/// insertion; the public read path uses the same ambiguity semantics.
fn resolve_case_head_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
    let mut statement = transaction
        .prepare(&format!(
            r#"
            SELECT {CASE_COLUMNS} FROM governance_case_index
            WHERE liability_key = ?1 AND superseded_by_case_id IS NULL
            ORDER BY recorded_at ASC, case_id ASC
            LIMIT 2
            "#
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([liability_key], map_case)
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let mut live = rows
        .into_iter()
        .map(case_from_raw)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    let Some(head) = live.next() else {
        return Ok(None);
    };
    if let Some(rival) = live.next() {
        return Err(FindingChallengeStoreError::AmbiguousCaseHead {
            liability_key: liability_key.to_owned(),
            first_case_id: head.case_id,
            second_case_id: rival.case_id,
        });
    }
    Ok(Some(head))
}

fn load_claim_snapshot_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingClaimSnapshotRecord>, FindingChallengeStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT liability_key, cutoff_slot, snapshot_digest,
                   allocation_digest, total_realized_spend_units, currency,
                   buyer_pool_units, community_fund_units, sealed_at
            FROM claim_snapshots WHERE liability_key = ?1
            "#,
            [liability_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        liability_key,
        cutoff_slot,
        snapshot_digest,
        allocation_digest,
        total_realized_spend_units,
        currency,
        buyer_pool_units,
        community_fund_units,
        sealed_at,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingClaimSnapshotRecord {
        liability_key,
        cutoff_slot: stored_u64(cutoff_slot, "cutoff_slot")?,
        snapshot_digest,
        allocation_digest,
        total_realized_spend_units: stored_u64(
            total_realized_spend_units,
            "total_realized_spend_units",
        )?,
        currency,
        buyer_pool_units: stored_u64(buyer_pool_units, "buyer_pool_units")?,
        community_fund_units: stored_u64(community_fund_units, "community_fund_units")?,
        sealed_at: stored_u64(sealed_at, "sealed_at")?,
    }))
}

const EFFECT_INTENT_COLUMNS: &str = r#"
    intent_key, liability_key, kind, intent_digest, settlement_required, state,
    attempt_count, recorded_at, updated_at
"#;

struct RawEffectIntent {
    intent_key: String,
    liability_key: Option<String>,
    kind: String,
    intent_digest: String,
    settlement_required: i64,
    state: String,
    attempt_count: i64,
    recorded_at: i64,
    updated_at: i64,
}

fn map_effect_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEffectIntent> {
    Ok(RawEffectIntent {
        intent_key: row.get(0)?,
        liability_key: row.get(1)?,
        kind: row.get(2)?,
        intent_digest: row.get(3)?,
        settlement_required: row.get(4)?,
        state: row.get(5)?,
        attempt_count: row.get(6)?,
        recorded_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn effect_intent_from_raw(
    raw: RawEffectIntent,
) -> Result<FindingEffectIntentRecord, FindingChallengeStoreError> {
    Ok(FindingEffectIntentRecord {
        intent_key: raw.intent_key,
        liability_key: raw.liability_key,
        kind: effect_intent_kind_from_name(&raw.kind)?,
        intent_digest: raw.intent_digest,
        settlement_required: stored_flag(raw.settlement_required, "settlement_required")?,
        state: effect_intent_state_from_name(&raw.state)?,
        attempt_count: stored_u64(raw.attempt_count, "attempt_count")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_effect_intent_tx(
    transaction: &Transaction<'_>,
    intent_key: &str,
) -> Result<Option<FindingEffectIntentRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {EFFECT_INTENT_COLUMNS} FROM effect_intents WHERE intent_key = ?1"),
            [intent_key],
            map_effect_intent,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(effect_intent_from_raw).transpose()
}

fn advance_challenge_state_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
    from: &str,
    to: &str,
    now: u64,
) -> Result<(), FindingChallengeStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE challenges SET state = ?3, updated_at = ?4
            WHERE challenge_id = ?1 AND state = ?2
            "#,
            params![challenge_id, from, to, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("challenge transition did not affect one row"));
    }
    Ok(())
}

/// Reject a natural key already bound to a different row. The unique
/// indexes make this unreachable as a silent overwrite; catching it here
/// turns a constraint abort into a typed conflict.
///
/// `query` is a compile-time-fixed statement from this module, never
/// caller input.
fn reject_bound_identifier(
    transaction: &Transaction<'_>,
    query: &str,
    value: &str,
    what: &str,
) -> Result<(), FindingChallengeStoreError> {
    let bound: Option<String> = transaction
        .query_row(query, [value], |row| row.get(0))
        .optional()
        .map_err(sqlite_error)?;
    if bound.is_some() {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "{what} is already bound to another challenge"
        )));
    }
    Ok(())
}

/// Whether a stored challenge is the same submission the caller is
/// recording. Identity is what the challenge asserts: which finding on
/// which listing, under which signed envelope, on which authorization
/// branch, in which evidence class, by which challenger.
///
/// `submitted_at` is deliberately excluded, following the sibling
/// purchase store: a caller derives it from its clock, so an honest retry
/// carries a later value than the durable row and comparing them would
/// strand the submission it is retrying. The stored row is returned
/// untouched, so the first submission time remains the durable one.
fn challenge_matches(
    existing: &FindingChallengeRecord,
    input: &FindingChallengeSubmission<'_>,
) -> bool {
    existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.challenge_envelope_sha256 == input.challenge_envelope_sha256
        && existing.authorization_branch == input.authorization_branch
        && existing.evidence_class == input.evidence_class
        && existing.challenger_hex.as_deref() == input.challenger_hex
}

/// Whether a stored dispute lock is the same bond the caller is locking.
/// `expires_at` and `locked_at` are both clock-derived, so neither is
/// part of identity; the durable row keeps the expiry the first lock
/// fenced.
fn dispute_lock_matches(
    existing: &FindingDisputeLockRecord,
    input: &FindingDisputeLockInput<'_>,
) -> bool {
    existing.lock_id == input.lock_id
        && existing.owner_hex == input.owner_hex
        && existing.schedule_envelope_sha256 == input.schedule_envelope_sha256
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
}

fn liability_matches(existing: &FindingLiabilityRecord, input: &FindingLiabilityInput<'_>) -> bool {
    existing.defect_key == input.defect_key
        && existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.allocation_id == input.allocation_id
        && existing.venue_id == input.venue_id
        && existing.chain_id == input.chain_id
        && existing.vault_contract == input.vault_contract
        && existing.vault_id == input.vault_id
}

fn governance_case_matches(
    existing: &FindingGovernanceCaseRecord,
    input: &FindingGovernanceCaseInput<'_>,
) -> bool {
    existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.liability_key == input.liability_key
        && existing.case_kind == input.case_kind
        && existing.case_state == input.case_state
        && existing.appeal_of_case_id.as_deref() == input.appeal_of_case_id
        && existing.supersedes_case_id.as_deref() == input.supersedes_case_id
}

fn claim_snapshot_matches(
    existing: &FindingClaimSnapshotRecord,
    input: &FindingClaimSnapshotInput<'_>,
) -> bool {
    existing.cutoff_slot == input.cutoff_slot
        && existing.snapshot_digest == input.snapshot_digest
        && existing.allocation_digest == input.allocation_digest
        && existing.total_realized_spend_units == input.total_realized_spend_units
        && existing.currency == input.currency
        && existing.buyer_pool_units == input.buyer_pool_units
        && existing.community_fund_units == input.community_fund_units
}

fn validate_submission(
    input: &FindingChallengeSubmission<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.challenge_id, "challenge_id")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.challenge_envelope_sha256, "challenge_envelope_sha256")?;
    match (input.authorization_branch, input.challenger_hex) {
        (FindingChallengeAuthorizationBranch::BuyerSubmission, Some(challenger)) => {
            require_hex64(challenger, "challenger_hex")?;
        }
        (FindingChallengeAuthorizationBranch::BuyerSubmission, None) => {
            return Err(invariant("a buyer submission must name its challenger"));
        }
        (FindingChallengeAuthorizationBranch::VenueAudit, Some(_)) => {
            return Err(invariant("a venue audit must not name a challenger"));
        }
        (FindingChallengeAuthorizationBranch::VenueAudit, None) => {}
    }
    require_trusted_time(input.submitted_at, "submitted_at")
}

fn validate_dispute_lock(
    input: &FindingDisputeLockInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.lock_id, "lock_id")?;
    require_identifier(input.challenge_id, "challenge_id")?;
    require_hex64(input.owner_hex, "owner_hex")?;
    require_hex64(input.schedule_envelope_sha256, "schedule_envelope_sha256")?;
    require_currency(input.currency)?;
    if input.amount_units == 0 {
        return Err(invariant("dispute bond amount must be nonzero"));
    }
    require_trusted_time(input.locked_at, "locked_at")?;
    require_trusted_time(input.expires_at, "expires_at")?;
    if input.expires_at <= input.locked_at {
        return Err(invariant("dispute bond expiry does not follow its lock"));
    }
    Ok(())
}

fn validate_liability(input: &FindingLiabilityInput<'_>) -> Result<(), FindingChallengeStoreError> {
    require_hex64(input.liability_key, "liability_key")?;
    require_hex64(input.defect_key, "defect_key")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.allocation_id, "allocation_id")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_identifier(input.venue_id, "venue_id")?;
    require_identifier(input.chain_id, "chain_id")?;
    require_identifier(input.vault_contract, "vault_contract")?;
    require_identifier(input.vault_id, "vault_id")?;
    require_trusted_time(input.opened_at, "opened_at")
}

fn validate_governance_case(
    input: &FindingGovernanceCaseInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.case_id, "case_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.liability_key, "liability_key")?;
    require_identifier(input.listing_id, "listing_id")?;
    if input.case_state.is_empty() || input.case_state.len() > MAX_CASE_STATE_BYTES {
        return Err(invariant("case_state byte length is out of bounds"));
    }
    if let Some(appealed) = input.appeal_of_case_id {
        require_identifier(appealed, "appeal_of_case_id")?;
        if input.case_kind != FindingGovernanceCaseKind::Appeal {
            return Err(invariant("only an appeal appeals a prior case"));
        }
        if appealed == input.case_id {
            return Err(invariant("a case cannot appeal itself"));
        }
    }
    if let Some(superseded) = input.supersedes_case_id {
        require_identifier(superseded, "supersedes_case_id")?;
        if superseded == input.case_id {
            return Err(invariant("a case cannot supersede itself"));
        }
    }
    require_trusted_time(input.recorded_at, "recorded_at")
}

fn validate_claim_snapshot(
    input: &FindingClaimSnapshotInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(input.liability_key, "liability_key")?;
    require_hex64(input.snapshot_digest, "snapshot_digest")?;
    require_hex64(input.allocation_digest, "allocation_digest")?;
    require_currency(input.currency)?;
    if input.buyer_pool_units > input.total_realized_spend_units {
        return Err(invariant(
            "buyer pool exceeds the realized spend it is capped by",
        ));
    }
    input
        .buyer_pool_units
        .checked_add(input.community_fund_units)
        .ok_or_else(|| invariant("sealed claim distribution overflowed u64"))?;
    require_trusted_time(input.sealed_at, "sealed_at")
}

/// Whether a verdict is consistent with the terminal state a challenge
/// already reached, which is what lets an honest replay of one verdict
/// succeed while a different verdict against the same closed challenge
/// rejects.
const fn verdict_admits_state(
    verdict: FindingChallengeVerdict,
    state: FindingChallengeState,
) -> bool {
    match verdict {
        FindingChallengeVerdict::Upheld => matches!(state, FindingChallengeState::Upheld),
        FindingChallengeVerdict::Rejected => matches!(state, FindingChallengeState::Rejected),
        FindingChallengeVerdict::Indeterminate { .. } => matches!(
            state,
            FindingChallengeState::IndeterminateRetryable
                | FindingChallengeState::IndeterminateClosed
        ),
    }
}

const fn is_terminal_challenge_state(state: FindingChallengeState) -> bool {
    matches!(
        state,
        FindingChallengeState::Rejected
            | FindingChallengeState::IndeterminateClosed
            | FindingChallengeState::Upheld
    )
}

const fn is_terminal_liability_state(state: FindingLiabilityState) -> bool {
    matches!(
        state,
        FindingLiabilityState::Settled | FindingLiabilityState::ReversedBeforeImpairment
    )
}

const fn disposed_lock_state(
    disposition: FindingDisputeLockDisposition,
) -> FindingDisputeLockState {
    match disposition {
        FindingDisputeLockDisposition::Returned => FindingDisputeLockState::Returned,
        FindingDisputeLockDisposition::Forfeited => FindingDisputeLockState::Forfeited,
    }
}

/// The effect-intent lifecycle, mirroring the schema trigger so an
/// illegal edge is a typed conflict rather than a constraint abort.
const fn effect_intent_edge_is_legal(
    from: FindingEffectIntentState,
    to: FindingEffectIntentState,
) -> bool {
    matches!(
        (from, to),
        (
            FindingEffectIntentState::Pending,
            FindingEffectIntentState::Dispatched
                | FindingEffectIntentState::Failed
                | FindingEffectIntentState::Quarantined
        ) | (
            FindingEffectIntentState::Dispatched,
            FindingEffectIntentState::Confirmed
                | FindingEffectIntentState::Failed
                | FindingEffectIntentState::Quarantined
        ) | (
            FindingEffectIntentState::Failed,
            FindingEffectIntentState::Dispatched | FindingEffectIntentState::Quarantined
        )
    )
}

const fn challenge_state_name(state: FindingChallengeState) -> &'static str {
    match state {
        FindingChallengeState::Submitted => "submitted",
        FindingChallengeState::Evaluating => "evaluating",
        FindingChallengeState::Rejected => "rejected",
        FindingChallengeState::IndeterminateRetryable => "indeterminate_retryable",
        FindingChallengeState::IndeterminateClosed => "indeterminate_closed",
        FindingChallengeState::Upheld => "upheld",
    }
}

fn challenge_state_from_name(
    name: &str,
) -> Result<FindingChallengeState, FindingChallengeStoreError> {
    match name {
        "submitted" => Ok(FindingChallengeState::Submitted),
        "evaluating" => Ok(FindingChallengeState::Evaluating),
        "rejected" => Ok(FindingChallengeState::Rejected),
        "indeterminate_retryable" => Ok(FindingChallengeState::IndeterminateRetryable),
        "indeterminate_closed" => Ok(FindingChallengeState::IndeterminateClosed),
        "upheld" => Ok(FindingChallengeState::Upheld),
        other => Err(invariant(format!("unknown challenge state {other}"))),
    }
}

const fn authorization_branch_name(branch: FindingChallengeAuthorizationBranch) -> &'static str {
    match branch {
        FindingChallengeAuthorizationBranch::BuyerSubmission => "buyer_submission",
        FindingChallengeAuthorizationBranch::VenueAudit => "venue_audit",
    }
}

fn authorization_branch_from_name(
    name: &str,
) -> Result<FindingChallengeAuthorizationBranch, FindingChallengeStoreError> {
    match name {
        "buyer_submission" => Ok(FindingChallengeAuthorizationBranch::BuyerSubmission),
        "venue_audit" => Ok(FindingChallengeAuthorizationBranch::VenueAudit),
        other => Err(invariant(format!("unknown authorization branch {other}"))),
    }
}

const fn evidence_class_name(class: FindingChallengeEvidenceClass) -> &'static str {
    match class {
        FindingChallengeEvidenceClass::DigestMismatch => "digest_mismatch",
        FindingChallengeEvidenceClass::EvidenceInvalid => "evidence_invalid",
        FindingChallengeEvidenceClass::ReplayContradiction => "replay_contradiction",
    }
}

fn evidence_class_from_name(
    name: &str,
) -> Result<FindingChallengeEvidenceClass, FindingChallengeStoreError> {
    match name {
        "digest_mismatch" => Ok(FindingChallengeEvidenceClass::DigestMismatch),
        "evidence_invalid" => Ok(FindingChallengeEvidenceClass::EvidenceInvalid),
        "replay_contradiction" => Ok(FindingChallengeEvidenceClass::ReplayContradiction),
        other => Err(invariant(format!("unknown evidence class {other}"))),
    }
}

const fn dispute_lock_state_name(state: FindingDisputeLockState) -> &'static str {
    match state {
        FindingDisputeLockState::Locked => "locked",
        FindingDisputeLockState::Returned => "returned",
        FindingDisputeLockState::Forfeited => "forfeited",
    }
}

fn dispute_lock_state_from_name(
    name: &str,
) -> Result<FindingDisputeLockState, FindingChallengeStoreError> {
    match name {
        "locked" => Ok(FindingDisputeLockState::Locked),
        "returned" => Ok(FindingDisputeLockState::Returned),
        "forfeited" => Ok(FindingDisputeLockState::Forfeited),
        other => Err(invariant(format!("unknown dispute lock state {other}"))),
    }
}

const fn liability_state_name(state: FindingLiabilityState) -> &'static str {
    match state {
        FindingLiabilityState::Open => "open",
        FindingLiabilityState::UpheldPendingClaims => "upheld_pending_claims",
        FindingLiabilityState::PendingAppeal => "pending_appeal",
        FindingLiabilityState::Finalizing => "finalizing",
        FindingLiabilityState::Settled => "settled",
        FindingLiabilityState::ReversedBeforeImpairment => "reversed_before_impairment",
    }
}

fn liability_state_from_name(
    name: &str,
) -> Result<FindingLiabilityState, FindingChallengeStoreError> {
    match name {
        "open" => Ok(FindingLiabilityState::Open),
        "upheld_pending_claims" => Ok(FindingLiabilityState::UpheldPendingClaims),
        "pending_appeal" => Ok(FindingLiabilityState::PendingAppeal),
        "finalizing" => Ok(FindingLiabilityState::Finalizing),
        "settled" => Ok(FindingLiabilityState::Settled),
        "reversed_before_impairment" => Ok(FindingLiabilityState::ReversedBeforeImpairment),
        other => Err(invariant(format!("unknown liability state {other}"))),
    }
}

const fn case_kind_name(kind: FindingGovernanceCaseKind) -> &'static str {
    match kind {
        FindingGovernanceCaseKind::Sanction => "sanction",
        FindingGovernanceCaseKind::Appeal => "appeal",
    }
}

fn case_kind_from_name(
    name: &str,
) -> Result<FindingGovernanceCaseKind, FindingChallengeStoreError> {
    match name {
        "sanction" => Ok(FindingGovernanceCaseKind::Sanction),
        "appeal" => Ok(FindingGovernanceCaseKind::Appeal),
        other => Err(invariant(format!("unknown governance case kind {other}"))),
    }
}

const fn effect_intent_kind_name(kind: FindingEffectIntentKind) -> &'static str {
    match kind {
        FindingEffectIntentKind::SellerImpair => "seller_impair",
        FindingEffectIntentKind::ChallengeBond => "challenge_bond",
        FindingEffectIntentKind::Fee => "fee",
        FindingEffectIntentKind::RootIntent => "root_intent",
        FindingEffectIntentKind::Retraction => "retraction",
    }
}

fn effect_intent_kind_from_name(
    name: &str,
) -> Result<FindingEffectIntentKind, FindingChallengeStoreError> {
    match name {
        "seller_impair" => Ok(FindingEffectIntentKind::SellerImpair),
        "challenge_bond" => Ok(FindingEffectIntentKind::ChallengeBond),
        "fee" => Ok(FindingEffectIntentKind::Fee),
        "root_intent" => Ok(FindingEffectIntentKind::RootIntent),
        "retraction" => Ok(FindingEffectIntentKind::Retraction),
        other => Err(invariant(format!("unknown effect intent kind {other}"))),
    }
}

const fn effect_intent_state_name(state: FindingEffectIntentState) -> &'static str {
    match state {
        FindingEffectIntentState::Pending => "pending",
        FindingEffectIntentState::Dispatched => "dispatched",
        FindingEffectIntentState::Confirmed => "confirmed",
        FindingEffectIntentState::Failed => "failed",
        FindingEffectIntentState::Quarantined => "quarantined",
    }
}

fn effect_intent_state_from_name(
    name: &str,
) -> Result<FindingEffectIntentState, FindingChallengeStoreError> {
    match name {
        "pending" => Ok(FindingEffectIntentState::Pending),
        "dispatched" => Ok(FindingEffectIntentState::Dispatched),
        "confirmed" => Ok(FindingEffectIntentState::Confirmed),
        "failed" => Ok(FindingEffectIntentState::Failed),
        "quarantined" => Ok(FindingEffectIntentState::Quarantined),
        other => Err(invariant(format!("unknown effect intent state {other}"))),
    }
}

pub(crate) fn initialize_finding_challenge_schema(
    connection: &mut Connection,
) -> Result<(), FindingChallengeStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_CHALLENGE_SCHEMA_KEY,
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        FINDING_CHALLENGE_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_challenge_invariants(connection);
    }
    if on_disk == 0 {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;
        crate::stamp_schema_version(
            &transaction,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| invariant(error.to_string()))?;
        verify_finding_challenge_invariants(&transaction)?;
        return transaction.commit().map_err(sqlite_error);
    }

    if !matches!(on_disk, 1 | 2) {
        return Err(invariant(format!(
            "unsupported finding challenge schema version {on_disk}"
        )));
    }

    // Later revisions add columns to existing tables. `CREATE TABLE IF
    // NOT EXISTS` cannot install them, and ALTER-produced table SQL would
    // not match the canonical schema catalog. Rebuild the two tables under
    // an immediate transaction with foreign-key enforcement temporarily
    // off, then validate every reference before committing the new version.
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_error)?;
    let migration = migrate_finding_challenge_schema(connection);
    let foreign_keys = connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(sqlite_error);
    match (migration, foreign_keys) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn migrate_finding_challenge_schema(
    connection: &mut Connection,
) -> Result<(), FindingChallengeStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;

    let has_claim_deadline = table_has_column(&transaction, "liability_heads", "claim_deadline")?;
    let has_appeal_window_opened_at =
        table_has_column(&transaction, "liability_heads", "appeal_window_opened_at")?;
    let has_appeal_deadline = table_has_column(&transaction, "liability_heads", "appeal_deadline")?;
    let has_appeal_terms = table_has_column(
        &transaction,
        "liability_heads",
        "appeal_terms_envelope_sha256",
    )?;
    let has_appeal_window = has_appeal_window_opened_at && has_appeal_deadline && has_appeal_terms;
    let has_settlement_required =
        table_has_column(&transaction, "effect_intents", "settlement_required")?;

    if (has_appeal_window_opened_at || has_appeal_deadline || has_appeal_terms)
        && !has_appeal_window
    {
        return Err(invariant(
            "legacy liability schema has only part of the appeal commitment",
        ));
    }

    if !has_claim_deadline
        && table_has_rows_where(&transaction, "liability_heads", "state <> 'open'")?
    {
        return Err(invariant(
            "v1 liability state cannot be migrated without its signed claim deadline",
        ));
    }
    if !has_appeal_window
        && table_has_rows_where(
            &transaction,
            "liability_heads",
            "state IN ('pending_appeal', 'finalizing', 'settled', 'reversed_before_impairment')",
        )?
    {
        return Err(invariant(
            "active legacy appeal state cannot be migrated without its signed appeal window",
        ));
    }
    if !has_settlement_required
        && table_has_rows_where(
            &transaction,
            "liability_heads",
            "state IN ('finalizing', 'settled')",
        )?
    {
        return Err(invariant(
            "legacy finalization state cannot be migrated without its required effect set",
        ));
    }

    let claim_deadline = if has_claim_deadline {
        "claim_deadline"
    } else {
        "NULL"
    };
    let appeal_window_opened_at = if has_appeal_window {
        "appeal_window_opened_at"
    } else {
        "NULL"
    };
    let appeal_deadline = if has_appeal_window {
        "appeal_deadline"
    } else {
        "NULL"
    };
    let appeal_terms = if has_appeal_window {
        "appeal_terms_envelope_sha256"
    } else {
        "NULL"
    };
    transaction
        .execute_batch(&format!(
            r#"
            CREATE TEMP TABLE finding_liability_heads_migration AS
            SELECT liability_key, defect_key, finding_id, listing_id,
                   allocation_id, venue_id, chain_id, vault_contract, vault_id,
                   state, upheld_challenge_id, purchase_cutoff_slot,
                   {claim_deadline} AS claim_deadline,
                   {appeal_window_opened_at} AS appeal_window_opened_at,
                   {appeal_deadline} AS appeal_deadline,
                   {appeal_terms} AS appeal_terms_envelope_sha256,
                   snapshot_digest, allocation_digest, publication_pending,
                   quarantined, opened_at, updated_at
            FROM liability_heads;
            "#
        ))
        .map_err(sqlite_error)?;

    let settlement_required = if has_settlement_required {
        "settlement_required"
    } else {
        // Before finalizing, every liability-bound effect is one of the
        // signed enforcement bindings. The later anchor-evidence fence is
        // created only from finalizing, a state rejected above when this
        // column is absent.
        "CASE WHEN liability_key IS NULL THEN 0 ELSE 1 END"
    };
    transaction
        .execute_batch(&format!(
            r#"
            CREATE TEMP TABLE finding_effect_intents_migration AS
            SELECT intent_key, liability_key, kind, intent_digest,
                   {settlement_required} AS settlement_required, state,
                   attempt_count, recorded_at, updated_at
            FROM effect_intents;

            DROP TABLE effect_intents;
            DROP TABLE liability_heads;
            "#
        ))
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO liability_heads (
                liability_key, defect_key, finding_id, listing_id,
                allocation_id, venue_id, chain_id, vault_contract, vault_id,
                state, upheld_challenge_id, purchase_cutoff_slot,
                claim_deadline, appeal_window_opened_at, appeal_deadline,
                appeal_terms_envelope_sha256, snapshot_digest,
                allocation_digest, publication_pending, quarantined,
                opened_at, updated_at
            )
            SELECT liability_key, defect_key, finding_id, listing_id,
                   allocation_id, venue_id, chain_id, vault_contract, vault_id,
                   state, upheld_challenge_id, purchase_cutoff_slot,
                   claim_deadline, appeal_window_opened_at, appeal_deadline,
                   appeal_terms_envelope_sha256, snapshot_digest,
                   allocation_digest, publication_pending, quarantined,
                   opened_at, updated_at
            FROM finding_liability_heads_migration;

            INSERT INTO effect_intents (
                intent_key, liability_key, kind, intent_digest,
                settlement_required, state, attempt_count, recorded_at,
                updated_at
            )
            SELECT intent_key, liability_key, kind, intent_digest,
                   settlement_required, state, attempt_count, recorded_at,
                   updated_at
            FROM finding_effect_intents_migration;

            DROP TABLE finding_effect_intents_migration;
            DROP TABLE finding_liability_heads_migration;
            "#,
        )
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_CHALLENGE_SCHEMA_KEY,
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_challenge_invariants(&transaction)?;
    let foreign_key_violation: Option<String> = transaction
        .query_row(
            "SELECT 'foreign key violation in ' || \"table\" FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(detail) = foreign_key_violation {
        return Err(invariant(detail));
    }
    transaction.commit().map_err(sqlite_error)
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, FindingChallengeStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
            params![table, column],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn table_has_rows_where(
    connection: &Connection,
    table: &str,
    predicate: &str,
) -> Result<bool, FindingChallengeStoreError> {
    // Both inputs are private constants at the call sites above. Keeping the
    // query helper here makes the migration preconditions auditable without
    // accepting caller-controlled SQL.
    connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Verify the challenge schema's shape: this database's table, index, and
/// trigger definitions against a freshly created canonical schema. The
/// cost is a handful of `sqlite_schema` rows, independent of how many
/// challenges have accumulated, so this runs on every open.
///
/// Fails closed: any schema-shape difference rejects the open, because a
/// missing lifecycle trigger is exactly the difference between a state
/// machine and a mutable row.
pub(crate) fn verify_finding_challenge_invariants(
    connection: &Connection,
) -> Result<(), FindingChallengeStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .map_err(sqlite_error)?;
    if finding_challenge_schema_catalog(connection)? != finding_challenge_schema_catalog(&expected)?
    {
        return Err(invariant(
            "finding challenge schema differs from the canonical definition",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_challenge_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingChallengeStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'challenges*' OR tbl_name GLOB 'challenges*'
               OR name GLOB 'dispute_locks*' OR tbl_name GLOB 'dispute_locks*'
               OR name GLOB 'liability_heads*'
               OR tbl_name GLOB 'liability_heads*'
               OR name GLOB 'governance_case_index*'
               OR tbl_name GLOB 'governance_case_index*'
               OR name GLOB 'claim_snapshots*'
               OR tbl_name GLOB 'claim_snapshots*'
               OR name GLOB 'effect_intents*'
               OR tbl_name GLOB 'effect_intents*'
               ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn list_limit() -> Result<i64, FindingChallengeStoreError> {
    sqlite_i64(u64::try_from(MAX_LIST_ROWS).unwrap_or(u64::MAX), "limit")
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_currency(currency: &str) -> Result<(), FindingChallengeStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

fn require_trusted_time(value: u64, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingChallengeStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingChallengeStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn stored_flag(value: i64, field: &'static str) -> Result<bool, FindingChallengeStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invariant(format!("{field} is not a boolean flag"))),
    }
}

fn invariant(detail: impl Into<String>) -> FindingChallengeStoreError {
    FindingChallengeStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingChallengeStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingChallengeStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingChallengeStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

/// Map a purchase-store failure raised inside a shared transaction. The
/// sales block is part of the upheld transaction, so its failures are the
/// challenge lane's failures.
fn purchase_error(error: FindingPurchaseStoreError) -> FindingChallengeStoreError {
    match error {
        FindingPurchaseStoreError::Fenced => FindingChallengeStoreError::Fenced,
        FindingPurchaseStoreError::NotFound => FindingChallengeStoreError::NotFound,
        FindingPurchaseStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        FindingPurchaseStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        FindingPurchaseStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        other => FindingChallengeStoreError::Conflict(other.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingChallengeStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingChallengeStoreError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
#[path = "finding_challenge_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
