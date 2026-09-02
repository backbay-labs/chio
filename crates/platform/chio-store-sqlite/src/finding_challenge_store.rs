//! Durable storage for the finding challenge and audit lane: submitted
//! challenges and the verdicts that close them, the exclusive dispute
//! bond a buyer submission locks, the liability head one defect opens,
//! the governance case index that resolves that head's authoritative
//! case, the sealed claim snapshot, and the domain-keyed effect intents
//! fenced before anything leaves this operator.
//!
//! Dedicated tables back the lane. `challenges` is the adjudication record:
//! one authorization branch, one evidence class, one bounded retry, and a
//! lifecycle that only ever runs
//! `submitted -> evaluating -> rejected | indeterminate_retryable |
//! indeterminate_closed | upheld`, with `indeterminate_retryable` the one
//! state that may re-enter evaluation. `finding_challenge_outcomes` retains
//! every exact signed outcome in the same transaction that records its
//! verdict. `dispute_lock_reservations` fences a
//! lock identity before any external debit, and `dispute_locks` holds the
//! confirmed bond: exclusive per challenge, disposed exactly once, and
//! never reused for a second challenge. `liability_heads` is
//! the money-bearing head: one row per defect on one backed listing,
//! advanced only by compare-and-set from `open` through
//! `upheld_pending_claims`, `pending_appeal`, and `finalizing` to
//! `settled`, with `reversed_before_impairment` as the appeal terminal.
//! `governance_case_index` records the sanction and appeal cases that
//! target a liability and resolves the single live head among them.
//! `claim_snapshots` seals the frozen accounting the payout derives from.
//! `finding_finalizing_authorizations` retains the exact signed
//! authorization in the transition that enters `finalizing`, and
//! `finding_finalizing_authorization_refreshes` appends every permitted
//! pre-dispatch snapshot refresh.
//! `effect_intents` is the durable fence every external effect passes
//! through before it is dispatched. `effect_root_bindings` immutably
//! refines a root intent with the exact Merkle root and evidence hash that
//! publication must confirm, while
//! `finding_seller_impairment_reconciliations` retains the exact verified
//! transaction evidence that allowed a seller impairment to confirm;
//! `effect_root_bindings_refreshes` retains each failed-retry root replacement.
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

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::PublicKey;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_finding::{
    verify_signed_challenge_outcome,
    FindingChallengeAuthorizationKind as ArtifactAuthorizationKind,
    FindingChallengeEvidenceKind as ArtifactEvidenceKind,
    FindingChallengeVerdict as ArtifactVerdict, SignedFindingChallengeOutcome,
};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_settle::ConfirmedFindingImpairmentReconciliation;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
use crate::finding_purchase_store::{
    block_new_slots_tx, highest_slot_ordinal_tx, lift_sales_block_tx,
    outstanding_exposure_total_tx, FindingPurchaseStoreError,
};
use crate::serving_owner::SqliteServingOwner;

mod submission_retention;
pub use submission_retention::*;
use submission_retention::{
    store_challenge_submission_tx, validate_submission, verify_challenge_submissions,
};

const FINDING_CHALLENGE_SCHEMA_KEY: &str = "finding_challenge";
/// Revision 14 retains exact signed challenge submissions atomically.
/// Revision 13 combines authenticated seller-impairment reconciliations,
/// append-only enforcement-root refreshes, and exact legacy anchor-binding
/// recovery; revision 11 retains pre-dispatch authorization refreshes.
/// revision 10 retains the initial exact finalizing authorization atomically
/// with the liability transition; revision 9 retains exact signed evaluator
/// outcomes with their verdict.
pub(crate) const FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION: i32 = 14;
const FINDING_CHALLENGE_SCHEMA_ANCHORS: &[&str] = &[
    "challenges",
    "finding_challenge_projection_commits",
    "admission_operations",
    "chio_serving_owner",
];
const FINDING_CHALLENGE_SCHEMA: &str = include_str!("finding_challenge_store.sql");
/// Explicit non-key carried only by projected legacy terminal liabilities.
/// Those rows remain auditable, but this value cannot authorize a future
/// seller impairment and terminal lifecycle triggers forbid any transition.
const LEGACY_TERMINAL_UNBOUND_SELLER_HEX: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Upper bound on every opaque identifier this store persists. An
/// unbounded identifier is an amplification vector rather than a name.
const MAX_IDENTIFIER_BYTES: usize = 512;
/// Upper bound on the opaque governance case state. The governance
/// surface owns that vocabulary; the store only refuses one too long to
/// be a state name.
const MAX_CASE_STATE_BYTES: usize = 64;
/// Bound on one retained signed outcome envelope.
const MAX_OUTCOME_ENVELOPE_BYTES: usize = 1_048_576;
/// Bound on one retained finalizing authorization, including its signed
/// enforcement and penalty envelopes.
const MAX_FINALIZING_AUTHORIZATION_BYTES: usize = 4_194_304;

const DISPUTE_BOND_FUNDING_DOMAIN: &str = "chio.finding.dispute-bond-funding.v1";
const DISPUTE_BOND_RETURN_DOMAIN: &str = "chio.finding.dispute-bond-return.v1";
const EFFECT_FEE_DOMAIN: &str = "chio.finding.effect.fee.v1";
const DISPUTE_FEE_OPERATION_DOMAIN: &str = "chio.finding.dispute-fee-operation.v1";
const DISPUTE_FEE_RETURN_OPERATION_DOMAIN: &str = "chio.finding.dispute-fee-return-operation.v1";
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
    pub challenge_envelope_json: &'a [u8],
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

/// One exact signed evaluator outcome retained with a verdict transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingChallengeOutcomeRecord {
    pub challenge_id: String,
    pub outcome_envelope_sha256: String,
    pub outcome_envelope_json: Vec<u8>,
    pub recorded_at: u64,
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
    pub pool_principal_id: &'a str,
    pub pool_rail_destination: &'a str,
    pub pool_authority_epoch: u64,
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

/// Durable key for the filing-fee debit of one exact challenge.
#[must_use]
pub fn derive_dispute_fee_collection_intent_key(challenge_id: &str) -> String {
    let operation_id =
        sha256_hex(format!("{DISPUTE_FEE_OPERATION_DOMAIN}\0{challenge_id}").as_bytes());
    sha256_hex(format!("{EFFECT_FEE_DOMAIN}\0{challenge_id}\0{operation_id}").as_bytes())
}

/// Durable key for returning the filing fee of one exact challenge.
#[must_use]
pub fn derive_dispute_fee_return_intent_key(challenge_id: &str) -> String {
    let operation_id =
        sha256_hex(format!("{DISPUTE_FEE_RETURN_OPERATION_DOMAIN}\0{challenge_id}").as_bytes());
    sha256_hex(format!("{EFFECT_FEE_DOMAIN}\0{challenge_id}\0{operation_id}").as_bytes())
}

/// Commitment a confirmed funding intent must carry before the store will
/// turn it into an evaluable dispute lock.
#[must_use]
pub fn dispute_bond_funding_intent_digest(input: &FindingDisputeLockInput<'_>) -> String {
    sha256_hex(
        format!(
            "{DISPUTE_BOND_FUNDING_DOMAIN}\0{challenge}\0{lock}\0{owner}\0{schedule}\0{units}\0{currency}\0{pool}\0{destination}\0{pool_epoch}\0{expiry}",
            challenge = input.challenge_id,
            lock = input.lock_id,
            owner = input.owner_hex,
            schedule = input.schedule_envelope_sha256,
            units = input.amount_units,
            currency = input.currency,
            pool = input.pool_principal_id,
            destination = input.pool_rail_destination,
            pool_epoch = input.pool_authority_epoch,
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
            "{DISPUTE_BOND_RETURN_DOMAIN}\0{challenge}\0{lock}\0{owner}\0{schedule}\0{units}\0{currency}\0{pool}\0{destination}\0{pool_epoch}\0{expiry}",
            challenge = input.challenge_id,
            lock = input.lock_id,
            owner = input.owner_hex,
            schedule = input.schedule_envelope_sha256,
            units = input.amount_units,
            currency = input.currency,
            pool = input.pool_principal_id,
            destination = input.pool_rail_destination,
            pool_epoch = input.pool_authority_epoch,
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
    pub pool_principal_id: String,
    pub pool_rail_destination: String,
    pub pool_authority_epoch: u64,
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
    pub seller_hex: &'a str,
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
    pub seller_hex: String,
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

/// Exact canonical authorization retained in the same transaction that
/// moves a liability into `finalizing`.
#[derive(Debug, Clone, Copy)]
pub struct FindingFinalizingAuthorizationInput<'a> {
    pub liability_key: &'a str,
    pub authorization_json: &'a [u8],
    pub authorization_sha256: &'a str,
    pub recorded_at: u64,
}

/// One retained finalizing authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFinalizingAuthorizationRecord {
    pub liability_key: String,
    pub authorization_json: Vec<u8>,
    pub authorization_sha256: String,
    pub recorded_at: u64,
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

/// Exact reconciliation evidence retained with a confirmed seller
/// impairment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSellerImpairmentReconciliationRecord {
    pub intent_key: String,
    pub liability_key: String,
    pub intent_digest: String,
    pub tx_hash: String,
    pub reconciliation_sha256: String,
    pub recorded_at: u64,
}

#[derive(Clone, Copy)]
struct SellerImpairmentReconciliationEvidence<'a> {
    intent_key: &'a str,
    liability_key: &'a str,
    tx_hash: &'a str,
    reconciliation_sha256: &'a str,
}

/// Immutable anchor-proof refinement for one root effect intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEffectRootBindingRecord {
    pub intent_key: String,
    pub liability_key: String,
    pub merkle_root: String,
    pub evidence_hash: String,
    pub bound_at: u64,
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
        self.serving_owner
            .append_finding_challenge_projection_if_changed(&transaction)
            .map_err(|error| FindingChallengeStoreError::Unavailable(error.to_string()))?;
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
}

include!("finding_challenge_store/challenge_lifecycle.rs");
include!("finding_challenge_store/dispute_locks.rs");
include!("finding_challenge_store/liability_lifecycle.rs");
include!("finding_challenge_store/governance_claims.rs");
include!("finding_challenge_store/effect_intents.rs");
include!("finding_challenge_store/effect_root_recovery.rs");
include!("finding_challenge_store/write_transactions.rs");
include!("finding_challenge_store/row_mappers.rs");
include!("finding_challenge_store/record_validation.rs");
include!("finding_challenge_store/schema_migrations.rs");
include!("finding_challenge_store/input_bounds.rs");
include!("finding_challenge_store_root_refresh.rs");

#[cfg(test)]
#[path = "finding_challenge_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
