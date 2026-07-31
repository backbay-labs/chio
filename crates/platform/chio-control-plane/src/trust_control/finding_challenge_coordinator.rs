//! Single-operator coordinator for the finding challenge and audit lane.
//!
//! Adjudication is not this module's job. The pure evaluator decides a
//! verdict from artifacts alone, and the slash module computes every
//! amount that moves. What is left is everything those two cannot do
//! without a clock or a database: authenticating a filing, charging the
//! dispute fee exactly once, locking and disposing the buyer's bond,
//! linearizing the upheld transaction against the purchase line, sealing
//! the claim accounting, running the appeal, fencing every external
//! effect before it is dispatched, and driving the liability head through
//! its compare-and-set lifecycle. This coordinator owns exactly that, and
//! it never re-implements the two it delegates to.
//!
//! Five entry points, each fenced by durable state rather than by call
//! order:
//!
//! - [`FindingChallengeCoordinator::submit`] authenticates the signed
//!   challenge, records it, and, for a buyer submission only, charges the
//!   dispute fee to the admission-pinned challenge-administration pool and
//!   locks the dispute bond. A venue audit charges nothing and locks
//!   nothing; the closed authorization union makes a fee or bond field on
//!   that branch unrepresentable rather than merely refused.
//! - [`FindingChallengeCoordinator::evaluate`] admits the evaluation,
//!   calls the pure evaluator, signs the outcome under the evaluator role,
//!   records the verdict, and disposes the bond. `Indeterminate` never
//!   forfeits, and a closed retry window returns the lock exactly once
//!   without charging a second fee.
//! - [`FindingChallengeCoordinator::uphold`] runs the critical
//!   transaction: the liability compare-and-set, the sales block, and the
//!   purchase-cutoff freeze commit together, then the pre-cutoff slots
//!   must close before the claim snapshot is computed and sealed, then the
//!   pending-appeal sanction and hold are minted and evaluated.
//! - [`FindingChallengeCoordinator::resolve_appeal`] reverses a timely
//!   successful appeal, or, on appeal finality with no reversal, signs the
//!   enforcement instruction and fences every domain-keyed effect intent
//!   before the liability enters finalizing. An unresolved appeal
//!   quarantines; it is never read as a denial.
//! - [`FindingChallengeCoordinator::finalize`] verifies the enforcement
//!   pair through the settlement choke point, plans the impairment,
//!   dispatches it through the injected publisher, and settles only on a
//!   confirmed reconciliation.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use std::sync::Arc;

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    compute_enforcement_id, derive_outcome_id, ensure_challenge_class_compatibility,
    signed_envelope_sha256, verify_finding, verify_pinned_envelope, verify_signed_audit_epoch,
    verify_signed_challenge, verify_signed_challenge_outcome, verify_signed_purchase_record,
    Finding, FindingChallenge, FindingChallengeAuthorization, FindingChallengeAuthorizationKind,
    FindingChallengeEnforcement, FindingChallengeEvidenceKind, FindingChallengeOutcome,
    FindingEffectIntentBinding, FindingEnforcementDestination, FindingPenaltyCalculation,
    FindingPurchaseRecord, SignedFindingAuditEpoch, SignedFindingChallenge,
    SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome,
    SignedFindingChallengeVerifierProfile, SignedFindingFinalizedBondSnapshot,
    SignedFindingPurchaseRecord, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeEvaluation,
    FindingChallengeEvaluationInput,
};
use chio_open_market::evaluation::{
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest,
};
use chio_open_market::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference};
use chio_open_market::fee_schedule::{OpenMarketBondClass, SignedOpenMarketFeeSchedule};
use chio_open_market::finding_audit::{select_audit_targets, EligibleListing};
use chio_open_market::finding_penalty::{
    evaluate_finding_penalty, FindingPenaltyBranch, FindingPenaltyContext,
};
use chio_open_market::finding_slash_amount::{
    compute_slash_distribution, DistributionEntry, SlashDistribution, SlashInputs, VerifiedHarm,
};
use chio_open_market::governance::generic::SignedGenericGovernanceCase;
use chio_open_market::listing::{
    GenericRegistryPublisher, SignedGenericListing, SignedGenericTrustActivation,
};
use chio_open_market::penalty::{
    build_open_market_penalty_artifact_with_trusted_signers, OpenMarketAbuseClass,
    OpenMarketPenaltyAction, OpenMarketPenaltyIssueRequest, OpenMarketPenaltyState,
    SignedOpenMarketPenalty,
};
use chio_settle::{
    dispatch_finding_impairment, plan_finding_impairment, verify_finding_enforcement,
    EvmBondSnapshot, FindingEnforcementPins, FindingImpairmentOutcome, FindingImpairmentPublisher,
    FindingImpairmentQuarantine, SettlementChainConfig,
};
use chio_store_sqlite::{
    FindingChallengeAuthorizationBranch, FindingChallengeEvaluationStart,
    FindingChallengeEvidenceClass, FindingChallengeState, FindingChallengeSubmission,
    FindingChallengeVerdict as StoreVerdict, FindingChallengeWriteOutcome,
    FindingClaimSnapshotInput, FindingDisputeLockDisposition, FindingDisputeLockInput,
    FindingEffectIntentKind, FindingEffectIntentState, FindingGovernanceCaseInput,
    FindingGovernanceCaseKind, FindingLiabilityInput, FindingLiabilityRecord,
    FindingLiabilityState, SqliteFindingChallengeStore, SqliteFindingPurchaseStore,
};

use super::finding_handlers::{FindingRailInstruction, FindingRailObserver};
use super::service_types::{FindingMarketConfig, FindingPoolPin};

/// Domain separator for the per-finding defect identity.
const DEFECT_DOMAIN: &str = "chio.finding.defect.v1";

/// Domain separator for the liability head identity.
const LIABILITY_DOMAIN: &str = "chio.finding.liability.v1";

/// Domain separator for the seller-impairment effect.
const EFFECT_SELLER_IMPAIR_DOMAIN: &str = "chio.finding.effect.seller-impair.v1";

/// Domain separator for the challenge-bond disposition effect.
const EFFECT_CHALLENGE_BOND_DOMAIN: &str = "chio.finding.effect.challenge-bond.v1";

/// Domain separator for the dispute-fee effect.
const EFFECT_FEE_DOMAIN: &str = "chio.finding.effect.fee.v1";

/// Domain separator for the enforcement/root semantic effect.
const EFFECT_ROOT_INTENT_DOMAIN: &str = "chio.finding.effect.root-intent.v1";

/// Domain separator for the status-feed retraction effect.
const EFFECT_RETRACTION_DOMAIN: &str = "chio.finding.effect.retraction.v1";

/// Domain separator for the deterministic dispute-fee operation id.
const DISPUTE_FEE_OPERATION_DOMAIN: &str = "chio.finding.dispute-fee-operation.v1";

/// Domain separator for the retraction intent id the retraction effect
/// key is derived over.
const RETRACTION_INTENT_DOMAIN: &str = "chio.finding.retraction-intent.v1";

/// Domain separator for the evidence-bundle commitment an outcome binds.
const EVIDENCE_BUNDLE_DOMAIN: &str = "chio.finding.challenge-evidence-bundle.v1";

/// Domain separator for the per-evaluation trigger commitment.
const TRIGGER_DOMAIN: &str = "chio.finding.challenge-trigger.v1";

/// Domain separator for the sealed purchase-snapshot commitment.
const PURCHASE_SNAPSHOT_DOMAIN: &str = "chio.finding.claim-snapshot.v1";

/// Domain separator for the sealed deterministic-allocation commitment.
const ALLOCATION_DIGEST_DOMAIN: &str = "chio.finding.claim-allocation.v1";

/// Root domain the enforcement anchor is published under. It is part of
/// the root-intent preimage so an anchor published under one root can
/// never reconcile against an intent fenced for another.
const ENFORCEMENT_ROOT_DOMAIN: &str = "chio.finding.enforcement-root.v1";

/// Upper bound on the raw finding bytes a submission may carry, matching
/// the evidence verifier's ingress bound. An unbounded artifact is an
/// amplification vector rather than a finding.
const MAX_RAW_FINDING_BYTES: usize = 1_048_576;

/// Derive the per-finding defect identity. One defect spans every class
/// and evidence subset, which is what stops a second corroborating
/// challenge opening a second slashable liability.
#[must_use]
pub fn derive_defect_key(finding_id: &str) -> String {
    sha256_hex(format!("{DEFECT_DOMAIN}\0{finding_id}").as_bytes())
}

/// The exact backed listing and vault one defect is charged against.
#[derive(Debug, Clone, Copy)]
pub struct FindingLiabilityIdentity<'a> {
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub allocation_id: &'a str,
    pub chain_id: &'a str,
    pub vault_contract: &'a str,
    pub vault_id: &'a str,
}

/// Derive the liability head identity for one defect on one backed
/// listing at one vault.
#[must_use]
pub fn derive_liability_key(
    defect_key: &str,
    venue_id: &str,
    identity: &FindingLiabilityIdentity<'_>,
) -> String {
    sha256_hex(
        format!(
            "{LIABILITY_DOMAIN}\0{defect_key}\0{venue_id}\0{listing}\0{allocation}\0{chain}\0{contract}\0{vault}",
            listing = identity.listing_id,
            allocation = identity.allocation_id,
            chain = identity.chain_id,
            contract = identity.vault_contract,
            vault = identity.vault_id,
        )
        .as_bytes(),
    )
}

/// Domain-keyed identity of the single unbatched seller impairment.
#[must_use]
pub fn derive_seller_impair_intent_key(
    chain_id: &str,
    vault_contract: &str,
    liability_key: &str,
    allocation_digest: &str,
) -> String {
    sha256_hex(
        format!(
            "{EFFECT_SELLER_IMPAIR_DOMAIN}\0{chain_id}\0{vault_contract}\0{liability_key}\0{allocation_digest}"
        )
        .as_bytes(),
    )
}

/// Domain-keyed identity of one challenge-bond disposition.
#[must_use]
pub fn derive_challenge_bond_intent_key(challenge_id: &str, lock_id: &str) -> String {
    sha256_hex(format!("{EFFECT_CHALLENGE_BOND_DOMAIN}\0{challenge_id}\0{lock_id}").as_bytes())
}

/// Domain-keyed identity of one dispute-fee or audit-cost charge.
#[must_use]
pub fn derive_fee_intent_key(submission_id: &str, fee_operation_id: &str) -> String {
    sha256_hex(format!("{EFFECT_FEE_DOMAIN}\0{submission_id}\0{fee_operation_id}").as_bytes())
}

/// Domain-keyed identity of the enforcement/root semantic intent.
///
/// The key is liability-scoped identity only. The penalty envelope digest
/// belongs in the commitment fenced under this key rather than in the key
/// itself: a second penalty minted for one liability has to collide with
/// what is already durable and reject, and a key that varied with the
/// penalty would silently open a second intent instead.
#[must_use]
pub fn derive_root_intent_key(
    operator_id: &str,
    liability_key: &str,
    outcome_id: &str,
    allocation_digest: &str,
) -> String {
    sha256_hex(
        format!(
            "{EFFECT_ROOT_INTENT_DOMAIN}\0{operator_id}\0{ENFORCEMENT_ROOT_DOMAIN}\0{liability_key}\0{outcome_id}\0{allocation_digest}"
        )
        .as_bytes(),
    )
}

/// Domain-keyed identity of the status-feed retraction.
#[must_use]
pub fn derive_retraction_intent_key(
    finding_id: &str,
    feed_id: &str,
    retraction_intent_id: &str,
) -> String {
    sha256_hex(
        format!("{EFFECT_RETRACTION_DOMAIN}\0{finding_id}\0{feed_id}\0{retraction_intent_id}")
            .as_bytes(),
    )
}

/// Typed rejections from the coordinator. Every variant refuses the
/// requested transition and leaves the durable state where it was.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeCoordinatorError {
    #[error("finding-market configuration rejected: {0}")]
    Configuration(String),
    #[error("signing key does not match its configured role pin: {0}")]
    AuthorityPinMismatch(&'static str),
    #[error("signed challenge rejected: {0}")]
    ChallengeEnvelope(String),
    #[error("raw finding artifact rejected: {0}")]
    FindingArtifact(String),
    #[error("challenge does not bind the supplied finding: {0}")]
    FindingBinding(&'static str),
    #[error("challenge class is not compatible with the finding: {0}")]
    ClassIncompatible(String),
    #[error("challenge is filed ahead of the venue clock")]
    FilingClock,
    #[error("dispute fee does not name the pinned challenge-administration pool")]
    DisputeFeePool,
    #[error("dispute fee payer is not the challenger the submission names")]
    DisputeFeePayer,
    #[error("dispute bond lock is not live at the venue clock")]
    DisputeBondWindow,
    #[error("dispute bond currency does not match the challenge-administration pool")]
    DisputeBondCurrency,
    #[error("buyer filing has not collected its dispute fee and locked its bond")]
    FilingUnfunded,
    #[error("filing binds a fee schedule this venue never published")]
    UnknownFeeSchedule,
    #[error("filing binds an audit round this venue never published")]
    UnknownAuditRound,
    #[error("signed audit epoch rejected: {0}")]
    AuditEpoch(String),
    #[error("audit round selection rejected: {0}")]
    AuditSelection(String),
    #[error("venue audit does not bind the round that drew it: {0}")]
    AuditRoundBinding(&'static str),
    #[error("resolved fee schedule rejected: {0}")]
    FeeScheduleArtifact(String),
    #[error("filing terms are not the ones the signed fee schedule sets: {0}")]
    DisputeTerms(&'static str),
    #[error("dispute fee rail dispatch failed: {0}")]
    FeeRail(String),
    #[error("semantic effect intent is not durably fenced before dispatch")]
    EffectIntentUnfenced,
    #[error("signed challenge outcome rejected: {0}")]
    OutcomeEnvelope(String),
    #[error("only an upheld outcome may enter the penalty lane")]
    VerdictNotUpheld,
    #[error("outcome does not bind this challenge")]
    OutcomeBinding,
    #[error("pre-cutoff purchase slots have not all closed")]
    ClaimWindowOpen,
    #[error("purchase record {0} is not resolvable in the authoritative index")]
    UnknownPurchaseRecord(String),
    #[error("purchase record {0} does not belong to this liability at the frozen cutoff")]
    PurchaseOutsideCutoff(String),
    #[error("purchase record {0} names a payout destination that was never admitted")]
    UnadmittedPayoutDestination(String),
    #[error("checked slash arithmetic refused the distribution: {0}")]
    SlashArithmetic(String),
    #[error("sealed claim accounting does not match the recomputed distribution")]
    SealedClaimMismatch,
    #[error("nothing is impairable for this liability")]
    NothingToImpair,
    #[error("penalty minting rejected: {0}")]
    PenaltyMint(String),
    #[error("penalty evaluation rejected: {0}")]
    PenaltyEvaluation(String),
    #[error("liability is in a state this transition does not start from: {0}")]
    LiabilityState(&'static str),
    #[error("identity does not match the durable liability head: {0}")]
    LiabilityIdentity(&'static str),
    #[error("settlement choke point rejected the enforcement: {0}")]
    Settlement(String),
    #[error("impairment publisher failed: {0}")]
    Publisher(String),
    #[error("artifact body failed its own validator: {0}")]
    ArtifactValidation(String),
    #[error("durable challenge store rejected the transition: {0}")]
    ChallengeStore(String),
    #[error("durable purchase store rejected the transition: {0}")]
    PurchaseStore(String),
    #[error("artifact signing failed")]
    Signing,
    #[error("canonicalization failed")]
    Canonical,
}

/// One published audit round, in the form anyone can replay it: the signed
/// epoch that fixed the round's inputs before it sampled, the seed the
/// venue revealed afterwards, and the eligible listing snapshot the epoch
/// committed the digest of.
#[derive(Debug, Clone)]
pub struct FindingAuditRound {
    pub epoch: SignedFindingAuditEpoch,
    pub revealed_seed: String,
    pub eligible: Vec<EligibleListing>,
}

/// Resolution of the signed artifacts a filing binds by digest.
///
/// A challenge carries digests, never the artifacts behind them, so the
/// venue answers from its own published record. Nothing a filer sends can
/// widen what a resolver returns, and a digest the venue cannot resolve
/// denies the filing rather than admitting it on the digest alone.
pub trait FindingFilingResolver: Send + Sync {
    /// The signed open-market fee schedule published under this envelope
    /// digest, or `None` when the venue published no such schedule.
    fn fee_schedule(&self, envelope_sha256: &str) -> Option<SignedOpenMarketFeeSchedule>;

    /// The audit round published under this epoch envelope digest, or
    /// `None` when the venue published no such round.
    fn audit_round(&self, epoch_envelope_sha256: &str) -> Option<FindingAuditRound>;
}

/// The pinned public roles this coordinator verifies against. None of
/// them is ever read out of an artifact.
struct ChallengeRolePins {
    audit_authority: PublicKey,
    governance_authority: PublicKey,
    purchase_authority: PublicKey,
    settlement_observer: PublicKey,
}

/// One submitted challenge, as the coordinator recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSubmissionOutcome {
    pub challenge_id: String,
    pub branch: FindingChallengeAuthorizationBranch,
    pub write: FindingChallengeWriteOutcome,
    /// Present only for a buyer submission: the domain-keyed dispute-fee
    /// effect that was charged exactly once.
    pub dispute_fee_intent_key: Option<String>,
    /// Present only for a buyer submission.
    pub dispute_bond_lock_id: Option<String>,
}

/// Whether an evaluation may proceed, and what the admission itself did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationAdmission {
    /// The challenge is evaluating and the caller may adjudicate.
    Admitted,
    /// The signed retry window lapsed before this attempt, so the store
    /// closed the challenge indeterminate. The lock, if any, was returned
    /// exactly once and no second fee was charged.
    RetryWindowClosed {
        disposition: Option<FindingDisputeLockDisposition>,
    },
}

/// The collateral facts one checked penalty calculation is derived from.
/// Every member comes from a signed artifact the caller already verified.
#[derive(Debug, Clone, Copy)]
pub struct FindingCollateralFacts<'a> {
    /// Seller precommitment from the admitted market terms.
    pub base_finding_stake: &'a MonetaryAmount,
    /// The signed listing bond requirement, which caps the candidate.
    pub listing_required_amount: &'a MonetaryAmount,
    /// Live collateral the finalized bond snapshot observed.
    pub live_allocated_collateral_units: u64,
    /// Allocation whose open per-sale encumbrances the candidate adds.
    pub allocation_id: &'a str,
}

/// One adjudication request: the challenge, the artifacts it binds, and
/// the resolved evidence its class selects.
pub struct ChallengeEvaluationRequest<'a> {
    pub challenge: &'a SignedFindingChallenge,
    /// The EXACT canonical bytes of the signed finding artifact.
    pub raw_finding: &'a str,
    pub profile: &'a SignedFindingChallengeVerifierProfile,
    pub evidence: &'a FindingChallengeClassEvidence<'a>,
    pub backing_allocation_id: &'a str,
    pub collateral: &'a FindingCollateralFacts<'a>,
    /// Deadline of the signed retry window an indeterminate verdict may
    /// use. Absent means no retry was granted.
    pub retry_deadline: Option<u64>,
    pub evaluator_key_epoch: u64,
    pub now: u64,
}

/// One adjudicated challenge and everything the coordinator did with it.
#[derive(Debug, Clone)]
pub struct ChallengeEvaluationOutcome {
    pub state: FindingChallengeState,
    pub outcome: SignedFindingChallengeOutcome,
    pub outcome_envelope_sha256: String,
    /// Absent when the bond is still held through a retry window, or when
    /// the filing was a bondless venue audit.
    pub bond_disposition: Option<FindingDisputeLockDisposition>,
}

/// The governance context a finding penalty is minted and evaluated
/// against. The coordinator owns every finding-specific field; the caller
/// supplies only the governance artifacts and the operator identity.
///
/// No authority travels with these artifacts. The charter, the case, and
/// the activation authenticate against the pinned governance root, and the
/// fee schedule against the pinned fee-schedule operator set, so an
/// artifact's own embedded signer can never widen the set it is checked
/// against.
pub struct FindingPenaltyGovernance<'a> {
    pub local_operator_id: &'a str,
    pub subject_operator_id: &'a str,
    pub issued_by: &'a str,
    pub fee_schedule: &'a SignedOpenMarketFeeSchedule,
    pub charter: &'a chio_open_market::governance::generic::SignedGenericGovernanceCharter,
    pub listing: &'a SignedGenericListing,
    pub activation: Option<&'a SignedGenericTrustActivation>,
    pub current_publisher: &'a GenericRegistryPublisher,
    pub penalty_expires_at: Option<u64>,
}

/// One minted and cleanly evaluated finding penalty.
#[derive(Debug, Clone)]
pub struct FindingPenaltyOutcome {
    pub penalty: SignedOpenMarketPenalty,
    pub penalty_envelope_sha256: String,
    pub evaluation: OpenMarketPenaltyEvaluation,
}

/// The frozen accounting one liability's payout derives from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedClaimSnapshot {
    pub liability_key: String,
    pub cutoff_slot: u64,
    pub snapshot_digest: String,
    pub allocation_digest: String,
    pub total_realized_spend_units: u64,
    pub distribution: SlashDistribution,
}

/// Everything the upheld transaction produced.
#[derive(Debug, Clone)]
pub struct UpheldLiability {
    pub liability_key: String,
    pub sealed: SealedClaimSnapshot,
    pub sanction_case_id: String,
    pub hold: FindingPenaltyOutcome,
}

/// What the venue observed about the appeal window when it closed.
pub enum AppealDisposition<'a> {
    /// A timely enforced appeal naming the exact sanction, with the hold
    /// it reverses.
    Successful {
        appeal_case: &'a SignedGenericGovernanceCase,
        appeal_case_id: &'a str,
    },
    /// No filing by the signed deadline, or a terminal denied appeal.
    /// Neither creates an appeal case head, so the original sanction
    /// still governs.
    Final {
        sanction_case: &'a SignedGenericGovernanceCase,
    },
    /// Open, escalated, unresolved, or unavailable. This is not a denial.
    Unresolved { reason: &'a str },
}

/// The signed instruction and fenced effects one authorized impairment
/// produced. Boxed inside [`AppealResolution`]: an enforcement carries a
/// full ordered destination list and two signed envelopes, which is an
/// order of magnitude larger than the other terminals.
#[derive(Debug, Clone)]
pub struct AuthorizedImpairment {
    pub enforcement: SignedFindingChallengeEnforcement,
    pub enforcement_envelope_sha256: String,
    pub slash: FindingPenaltyOutcome,
    pub effect_intent_keys: Vec<(FindingEffectIntentKind, String)>,
}

/// The terminal one appeal resolution reached.
#[derive(Debug, Clone)]
pub enum AppealResolution {
    /// The hold was reversed before anything was impaired.
    ReversedBeforeImpairment {
        reversal: Box<FindingPenaltyOutcome>,
    },
    /// The impairment is authorized, signed, and fully fenced.
    Finalizing(Box<AuthorizedImpairment>),
    /// The appeal state could not be established, so the liability is
    /// quarantined and nothing was impaired.
    Quarantined { reason: String },
}

/// What one finalization attempt did with the fenced impairment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingFinalization {
    /// The publisher was asked to move the impairment on this call, and
    /// this is what the reconciliation proved about it.
    Reconciled(FindingImpairmentOutcome),
    /// An earlier attempt already proved the impairment landed and died
    /// before it could settle the head. Nothing was dispatched a second
    /// time; this call finished the interrupted settlement.
    AlreadyConfirmed,
}

/// The authoritative single-operator challenge coordinator.
pub struct FindingChallengeCoordinator {
    challenges: SqliteFindingChallengeStore,
    purchases: SqliteFindingPurchaseStore,
    pins: ChallengeRolePins,
    /// Pinned fee-schedule signer set. A schedule reaching the penalty
    /// lane verifies against this roster and nothing else.
    fee_schedule_operators: Vec<PublicKey>,
    evaluator_authority: Keypair,
    finalization_authority: Keypair,
    penalty_authority: Keypair,
    rail: Arc<dyn FindingRailObserver>,
    /// Resolves the signed artifacts a filing binds by digest.
    filings: Arc<dyn FindingFilingResolver>,
    venue_id: String,
    challenge_administration_pool: FindingPoolPin,
    community_fund_destination: String,
    status_feed_operator_ref: String,
    /// Disposition a rejected challenge's bond takes, predeclared by the
    /// admitted market terms rather than chosen per case.
    failed_challenge_disposition: FindingDisputeLockDisposition,
}

impl FindingChallengeCoordinator {
    /// Build the coordinator over the two durable stores that share one
    /// connection, verifying every signing key against its configured pin
    /// and refusing a key that holds more than one role.
    ///
    /// The roster check runs before anything else: the whole lane rests on
    /// the evaluator, the finalization authority, the penalty authority,
    /// and the settlement observer being four different keys, so a
    /// configuration that collapses any two of them must never load.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenges: SqliteFindingChallengeStore,
        purchases: SqliteFindingPurchaseStore,
        config: &FindingMarketConfig,
        evaluator_authority: Keypair,
        finalization_authority: Keypair,
        penalty_authority: Keypair,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<Self, ChallengeCoordinatorError> {
        config
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Configuration(error.to_string()))?;
        let pin = |pin: &super::service_types::FindingAuthorityPin, label: &'static str| {
            pin.key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch(label))
        };
        if evaluator_authority.public_key() != pin(&config.challenge_evaluator, "evaluator")? {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch("evaluator"));
        }
        if finalization_authority.public_key() != pin(&config.venue_finalization, "finalization")? {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "finalization",
            ));
        }
        if penalty_authority.public_key() != pin(&config.market_penalty, "penalty")? {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch("penalty"));
        }
        let fee_schedule_operators = config
            .fee_schedule_operators()
            .map_err(|error| ChallengeCoordinatorError::Configuration(error.to_string()))?;
        // A fee schedule is one of the artifacts the penalty rests on, so
        // the roster that may sign one must not contain a key this lane
        // signs with: such a key would authorize its own inputs.
        for operator in &fee_schedule_operators {
            if operator == &evaluator_authority.public_key()
                || operator == &finalization_authority.public_key()
                || operator == &penalty_authority.public_key()
            {
                return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                    "fee schedule operator",
                ));
            }
        }
        Ok(Self {
            challenges,
            purchases,
            fee_schedule_operators,
            pins: ChallengeRolePins {
                audit_authority: pin(&config.audit_authority, "audit")?,
                governance_authority: pin(&config.governance_root, "governance")?,
                purchase_authority: pin(&config.purchase, "purchase")?,
                settlement_observer: pin(&config.settlement_observer, "settlement observer")?,
            },
            evaluator_authority,
            finalization_authority,
            penalty_authority,
            rail,
            filings,
            venue_id: config.venue_id.clone(),
            challenge_administration_pool: config.challenge_administration_pool.clone(),
            community_fund_destination: config.community_fund_destination.clone(),
            status_feed_operator_ref: config.status_feed_operator_ref.clone(),
            failed_challenge_disposition,
        })
    }

    /// Authenticate and durably record one challenge, charging the
    /// dispute fee and locking the dispute bond for a buyer submission.
    ///
    /// Ordering guarantee. Every pure check runs first, including the fee
    /// and bond preconditions the durable row does not carry, so a filing
    /// that cannot be authenticated writes nothing. The challenge row is
    /// then recorded before the fee, because a charge against a challenge
    /// the store never accepted would be a stranded debit with nothing to
    /// resolve it. The fee is fenced before dispatch and the bond is
    /// locked last, so a crash anywhere replays into the same durable
    /// state: the challenge replays as an existing row, the fee intent
    /// reconciles or re-dispatches from `failed`, and the lock replays as
    /// the same lock.
    ///
    /// That ordering is why the row is not evidence of a funded filing.
    /// The lock is written only once the fee has reconciled, so it is the
    /// lock that makes a buyer submission evaluable, and a filing that
    /// stopped short of it stays inert until a replay completes it.
    ///
    /// A venue audit takes none of that path. Its authorization branch has
    /// no fee, bond, forfeiture, or reward member at all, so those fields
    /// are unrepresentable on it rather than merely rejected, and this
    /// method charges and locks nothing for it. What it owes instead is
    /// the round: a bondless filing is admitted only against the published
    /// selection that drew this listing.
    pub fn submit(
        &self,
        challenge: &SignedFindingChallenge,
        raw_finding: &str,
        now: u64,
    ) -> Result<ChallengeSubmissionOutcome, ChallengeCoordinatorError> {
        // The pinned audit authority is the only key that may file a
        // bondless audit; a buyer submission verifies against the
        // challenger it names, so neither branch can borrow the other's
        // authorization.
        verify_signed_challenge(challenge, &self.pins.audit_authority)
            .map_err(|error| ChallengeCoordinatorError::ChallengeEnvelope(error.to_string()))?;
        let body = &challenge.body;
        if body.filed_at > now {
            return Err(ChallengeCoordinatorError::FilingClock);
        }
        let finding = self.resolve_finding(raw_finding, body)?;
        // The closed compatibility matrix is the only gate between a
        // challenge class and the finding it targets, and it needs both.
        ensure_challenge_class_compatibility(
            body.evidence.kind(),
            finding.guarantee_class,
            finding.evidence_class,
        )
        .map_err(|error| ChallengeCoordinatorError::ClassIncompatible(error.to_string()))?;

        let challenge_envelope_sha256 = self.envelope_digest(challenge)?;
        let (branch, challenger_hex) = match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => (
                FindingChallengeAuthorizationBranch::BuyerSubmission,
                Some(submission.challenger.to_hex()),
            ),
            FindingChallengeAuthorization::VenueAudit(_) => {
                (FindingChallengeAuthorizationBranch::VenueAudit, None)
            }
        };
        // The durable row carries neither the money terms of a buyer
        // filing nor the round behind a bondless one, so a filing whose
        // branch cannot be authorized must be refused before anything
        // about it becomes durable.
        match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                self.require_dispute_terms(submission, now)?;
            }
            FindingChallengeAuthorization::VenueAudit(audit) => {
                self.require_audit_selection(audit, body)?;
            }
        }
        let write = self
            .challenges
            .submit_challenge(&FindingChallengeSubmission {
                challenge_id: &body.challenge_id,
                finding_id: &body.finding_id,
                listing_id: &body.listing_id,
                challenge_envelope_sha256: &challenge_envelope_sha256,
                authorization_branch: branch,
                evidence_class: evidence_class_of(body.evidence.kind()),
                challenger_hex: challenger_hex.as_deref(),
                submitted_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        let FindingChallengeAuthorization::BuyerSubmission(submission) = &body.authorization else {
            return Ok(ChallengeSubmissionOutcome {
                challenge_id: body.challenge_id.clone(),
                branch,
                write,
                dispute_fee_intent_key: None,
                dispute_bond_lock_id: None,
            });
        };
        let lock = &submission.dispute_lock_ref;
        let fee_intent_key = self.charge_dispute_fee(&body.challenge_id, submission, now)?;
        self.challenges
            .lock_dispute_bond(&FindingDisputeLockInput {
                lock_id: &lock.lock_id,
                challenge_id: &body.challenge_id,
                owner_hex: &submission.challenger.to_hex(),
                schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
                amount_units: lock.amount.units,
                currency: &lock.amount.currency,
                expires_at: lock.expiry,
                locked_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(ChallengeSubmissionOutcome {
            challenge_id: body.challenge_id.clone(),
            branch,
            write,
            dispute_fee_intent_key: Some(fee_intent_key),
            dispute_bond_lock_id: Some(lock.lock_id.clone()),
        })
    }

    /// Admit one evaluation attempt against the venue clock.
    ///
    /// Evaluability is proved before the clock is consulted, so a filing
    /// that never funded itself cannot enter evaluation and cannot be
    /// moved on by a lapsed retry window either.
    ///
    /// A challenge whose signed retry window has already lapsed is closed
    /// indeterminate by the store rather than admitted, and its bond is
    /// returned here, exactly once. That path charges no second fee: the
    /// retry reuses the same challenge, fee, lock, profile, and evidence
    /// identity, so there is nothing further to collect.
    pub fn admit_evaluation(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<EvaluationAdmission, ChallengeCoordinatorError> {
        self.require_funded_filing(challenge_id)?;
        let start = self
            .challenges
            .begin_evaluation(challenge_id, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match start {
            FindingChallengeEvaluationStart::Started
            | FindingChallengeEvaluationStart::AlreadyEvaluating => {
                Ok(EvaluationAdmission::Admitted)
            }
            FindingChallengeEvaluationStart::RetryWindowExpired => {
                let disposition = self.dispose_dispute_bond(challenge_id, now)?;
                Ok(EvaluationAdmission::RetryWindowClosed { disposition })
            }
        }
    }

    /// Adjudicate one challenge: admit the attempt, delegate the decision
    /// to the pure evaluator, sign the outcome under the evaluator role,
    /// record the verdict, and dispose the bond the verdict calls for.
    ///
    /// An inadmissible submission produces no verdict and no signed
    /// outcome. The challenge is left evaluating, which is recoverable:
    /// nothing was held, sanctioned, forfeited, or transitioned, and a
    /// corrected attempt re-enters the same evaluation.
    pub fn evaluate(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<Option<ChallengeEvaluationOutcome>, ChallengeCoordinatorError> {
        let body = &request.challenge.body;
        if self.admit_evaluation(&body.challenge_id, request.now)? != EvaluationAdmission::Admitted
        {
            return Ok(None);
        }
        let input = FindingChallengeEvaluationInput {
            challenge: request.challenge,
            pinned_audit_authority: &self.pins.audit_authority,
            raw_finding: request.raw_finding,
            profile: request.profile,
            governance_authority: &self.pins.governance_authority,
            evidence: request.evidence,
        };
        let FindingChallengeEvaluation::Adjudicated(adjudication) =
            evaluate_finding_challenge(&input)
        else {
            return Ok(None);
        };
        let (verdict, facet, reason) = adjudication.into_parts();

        let challenge_envelope_sha256 = self.envelope_digest(request.challenge)?;
        let profile_envelope_sha256 = self.envelope_digest(request.profile)?;
        let evidence_bundle_digest = self.evidence_bundle_digest(body)?;
        let attempt = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .map_or(0, |record| record.retry_count);
        let penalty_calculation = match verdict {
            chio_finding::FindingChallengeVerdict::Upheld => {
                Some(self.checked_penalty_calculation(request.collateral, request.now)?)
            }
            _ => None,
        };
        let mut outcome = FindingChallengeOutcome {
            schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_owned(),
            outcome_id: String::new(),
            challenge_envelope_sha256: challenge_envelope_sha256.clone(),
            finding_id: body.finding_id.clone(),
            listing_id: body.listing_id.clone(),
            backing_allocation_id: request.backing_allocation_id.to_owned(),
            authorization: body.authorization.kind(),
            evidence_kind: body.evidence.kind(),
            verifier_profile_envelope_sha256: profile_envelope_sha256.clone(),
            evidence_bundle_digest: evidence_bundle_digest.clone(),
            verdict,
            facet,
            reason: reason.code().to_owned(),
            trigger_digest: sha256_hex(
                format!(
                    "{TRIGGER_DOMAIN}\0{challenge_envelope_sha256}\0{profile_envelope_sha256}\0{artifact}\0{evidence_bundle_digest}\0{attempt}",
                    artifact = body.finding_artifact_sha256,
                )
                .as_bytes(),
            ),
            penalty_calculation,
            evaluator_key_epoch: request.evaluator_key_epoch,
            evaluated_at: request.now,
        };
        outcome.outcome_id =
            derive_outcome_id(&outcome).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        // The store keeps this envelope forever and the penalty lane binds
        // its digest, so a body its own validator rejects must never be
        // signed.
        outcome
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let signed = SignedFindingChallengeOutcome::sign(outcome, &self.evaluator_authority)
            .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let outcome_envelope_sha256 = self.envelope_digest(&signed)?;

        let state = self
            .challenges
            .record_verdict(
                &body.challenge_id,
                store_verdict(verdict, request.retry_deadline),
                &outcome_envelope_sha256,
                request.now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let bond_disposition = self.dispose_dispute_bond(&body.challenge_id, request.now)?;
        Ok(Some(ChallengeEvaluationOutcome {
            state,
            outcome: signed,
            outcome_envelope_sha256,
            bond_disposition,
        }))
    }

    /// Apply the bond rule the challenge's terminal state calls for.
    ///
    /// Upheld returns the lock. Rejected applies the predeclared
    /// failed-challenge rule. Indeterminate never forfeits: while the
    /// challenge is still retryable the same lock is retained, and once
    /// it closes the lock is returned. A bondless venue audit has no
    /// disposition under any verdict. The store additionally refuses a
    /// forfeit against anything but a rejected challenge, so this rule
    /// and that fence agree by construction.
    pub fn dispose_dispute_bond(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<Option<FindingDisputeLockDisposition>, ChallengeCoordinatorError> {
        let Some(_lock) = self
            .challenges
            .get_dispute_lock(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let disposition = match challenge.state {
            FindingChallengeState::Upheld | FindingChallengeState::IndeterminateClosed => {
                FindingDisputeLockDisposition::Returned
            }
            FindingChallengeState::Rejected => self.failed_challenge_disposition,
            FindingChallengeState::Submitted
            | FindingChallengeState::Evaluating
            | FindingChallengeState::IndeterminateRetryable => return Ok(None),
        };
        self.challenges
            .release_dispute_bond(challenge_id, disposition, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(Some(disposition))
    }

    /// The critical transaction, and everything that has to follow it
    /// before an appeal window can open.
    ///
    /// The liability compare-and-set, the sales block, and the purchase
    /// cutoff freeze commit in one store call on the connection the
    /// purchase store shares, so no slot can open above the cutoff and
    /// below the block. The claim snapshot then waits: every slot at or
    /// below the frozen cutoff must have reached a settled record or a
    /// denial before the accounting is computed, because a slot still in
    /// flight is a buyer who may yet belong in it. Only then is the
    /// snapshot sealed, the sanction recorded, and the pending-appeal hold
    /// minted and evaluated.
    ///
    /// Returns [`ChallengeCoordinatorError::ClaimWindowOpen`] while slots
    /// remain open. That is a retry, not a failure: the liability stays
    /// upheld-pending-claims with sales already blocked, and a later call
    /// replays the compare-and-set as a no-op and continues.
    ///
    /// Two preconditions of the hold are checked before any of that
    /// commits, because both are pure and both would otherwise wedge the
    /// listing behind a hold that can never be minted, with no transition
    /// left to release it: the governance artifacts must carry pinned
    /// signatures, and the collateral must be able to fund a nonzero
    /// amount, which the penalty artifacts require.
    #[allow(clippy::too_many_arguments)]
    pub fn uphold(
        &self,
        challenge_id: &str,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        governance: &FindingPenaltyGovernance<'_>,
        sanction_case: &SignedGenericGovernanceCase,
        now: u64,
    ) -> Result<UpheldLiability, ChallengeCoordinatorError> {
        verify_signed_challenge_outcome(outcome, &self.evaluator_authority.public_key())
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        if outcome.body.verdict != chio_finding::FindingChallengeVerdict::Upheld {
            return Err(ChallengeCoordinatorError::VerdictNotUpheld);
        }
        if outcome.body.finding_id != identity.finding_id
            || outcome.body.listing_id != identity.listing_id
            || outcome.body.backing_allocation_id != identity.allocation_id
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        self.require_pinned_governance(governance, sanction_case, None)?;
        self.require_impairable_collateral(collateral, now)?;
        let defect_key = derive_defect_key(identity.finding_id);
        let liability_key = derive_liability_key(&defect_key, &self.venue_id, identity);
        self.challenges
            .open_liability(&FindingLiabilityInput {
                liability_key: &liability_key,
                defect_key: &defect_key,
                finding_id: identity.finding_id,
                listing_id: identity.listing_id,
                allocation_id: identity.allocation_id,
                venue_id: &self.venue_id,
                chain_id: identity.chain_id,
                vault_contract: identity.vault_contract,
                vault_id: identity.vault_id,
                opened_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        self.challenges
            .uphold_liability(&liability_key, challenge_id, cutoff_slot, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        if !self
            .purchases
            .all_slots_closed_at_or_below(identity.listing_id, cutoff_slot)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::ClaimWindowOpen);
        }

        let sealed = self.seal_claim_snapshot(
            &liability_key,
            identity,
            cutoff_slot,
            claim_candidates,
            collateral,
            now,
        )?;

        self.challenges
            .record_governance_case(&FindingGovernanceCaseInput {
                case_id: &sanction_case.body.case_id,
                finding_id: identity.finding_id,
                listing_id: identity.listing_id,
                liability_key: &liability_key,
                case_kind: FindingGovernanceCaseKind::Sanction,
                case_state: case_state_name(sanction_case),
                appeal_of_case_id: None,
                supersedes_case_id: None,
                recorded_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        let hold = self.mint_penalty(
            FindingPenaltyBranch::PendingAppeal,
            governance,
            sanction_case,
            None,
            &sealed.distribution.slash,
            outcome,
            &sanction_case.body.case_id,
            None,
            now,
        )?;

        self.challenges
            .begin_appeal_window(
                &liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        Ok(UpheldLiability {
            liability_key,
            sealed,
            sanction_case_id: sanction_case.body.case_id.clone(),
            hold,
        })
    }

    /// Close the appeal window.
    ///
    /// A timely successful appeal evaluates the reverse-slash branch and
    /// drives the liability to `reversed_before_impairment`; nothing was
    /// impaired, so nothing has to be undone. Appeal finality with no
    /// reversal evaluates the impairment branch, signs the enforcement
    /// instruction, fences every domain-keyed effect intent, and moves the
    /// liability to `finalizing` with publication pending. Anything else
    /// quarantines: an open, escalated, unresolved, or unavailable appeal
    /// is not a denial, and treating it as one would slash a seller whose
    /// appeal was still live.
    ///
    /// Fencing order. Every intent is persisted before the liability
    /// enters `finalizing`, and nothing is dispatched until it does, so no
    /// external effect can precede its own durable intent. The store
    /// exposes one intent per call rather than a batch, so a crash mid-way
    /// leaves a prefix of pending intents and the liability still in
    /// `pending_appeal`; the replay re-records each intent identically and
    /// continues, because an identical retry reconciles and a conflicting
    /// one rejects.
    ///
    /// Authority. Nothing about the target is taken from the caller. The
    /// durable head is the only authority on which finding, listing,
    /// allocation, and vault this liability may impair, and the only
    /// outcome that may authorize it is the exact envelope the store
    /// recorded for the challenge that upheld it.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_appeal(
        &self,
        liability_key: &str,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        sealed: &SealedClaimSnapshot,
        governance: &FindingPenaltyGovernance<'_>,
        disposition: &AppealDisposition<'_>,
        sanction_case_id: &str,
        hold: &FindingPenaltyOutcome,
        bond_snapshot_envelope_sha256: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        verify_signed_challenge_outcome(outcome, &self.evaluator_authority.public_key())
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        let record = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        self.require_identity_matches_head(liability_key, identity, &record)?;
        self.require_outcome_upheld_this_liability(outcome, &record)?;
        self.require_sealed_matches_store(liability_key, sealed)?;

        match disposition {
            AppealDisposition::Unresolved { reason } => {
                self.challenges
                    .set_liability_quarantine(liability_key, true, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(AppealResolution::Quarantined {
                    reason: (*reason).to_owned(),
                })
            }
            AppealDisposition::Successful {
                appeal_case,
                appeal_case_id,
            } => {
                self.challenges
                    .record_governance_case(&FindingGovernanceCaseInput {
                        case_id: appeal_case_id,
                        finding_id: &record.finding_id,
                        listing_id: &record.listing_id,
                        liability_key,
                        case_kind: FindingGovernanceCaseKind::Appeal,
                        case_state: case_state_name(appeal_case),
                        appeal_of_case_id: Some(sanction_case_id),
                        supersedes_case_id: Some(sanction_case_id),
                        recorded_at: now,
                    })
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                let reversal = self.mint_penalty(
                    FindingPenaltyBranch::SuccessfulAppeal,
                    governance,
                    appeal_case,
                    Some(&hold.penalty),
                    &sealed.distribution.slash,
                    outcome,
                    sanction_case_id,
                    Some(&hold.evaluation.penalty_id),
                    now,
                )?;
                self.challenges
                    .reverse_liability_before_impairment(
                        liability_key,
                        FindingLiabilityState::PendingAppeal,
                        now,
                    )
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(AppealResolution::ReversedBeforeImpairment {
                    reversal: Box::new(reversal),
                })
            }
            AppealDisposition::Final { sanction_case } => {
                let slash = self.mint_penalty(
                    FindingPenaltyBranch::AppealFinalImpairment,
                    governance,
                    sanction_case,
                    Some(&hold.penalty),
                    &sealed.distribution.slash,
                    outcome,
                    sanction_case_id,
                    Some(&hold.evaluation.penalty_id),
                    now,
                )?;
                self.finalize_enforcement(
                    &record,
                    outcome,
                    sealed,
                    &slash,
                    governance.local_operator_id,
                    bond_snapshot_envelope_sha256,
                    now,
                )
            }
        }
    }

    /// Verify the enforcement pair, prepare the exact authorized call,
    /// dispatch it through the injected publisher, and reconcile.
    ///
    /// Only a reconciliation that proved a finalized transaction is this
    /// exact frozen intent settles the liability. A quarantined
    /// reconciliation is not a slash and is never reported as one: the
    /// liability stays `finalizing`, publication stays pending, and
    /// purchases stay blocked. A clean vault rejection leaves the intent
    /// failed and retryable, in the same state.
    ///
    /// The terminal `quarantined` intent state is reserved for external
    /// state no further attempt can disambiguate. A receipt that has not
    /// arrived, has not finalized, or reverted is the ordinary shape of a
    /// broadcast that has not landed yet, so those leave the intent failed
    /// and dispatchable rather than closing the only edge out.
    ///
    /// Resumable. The confirmed intent and the settled head are two
    /// transactions, so an attempt can die between them. A re-entry that
    /// finds the fenced intent already confirmed dispatches nothing and
    /// finishes the settlement instead.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        seller: &PublicKey,
        max_snapshot_age_secs: u64,
        settlement_config: &SettlementChainConfig,
        operator_address: &str,
        vault_snapshot: &EvmBondSnapshot,
        anchor_proof: &AnchorInclusionProof,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<FindingFinalization, ChallengeCoordinatorError> {
        let liability = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(ChallengeCoordinatorError::LiabilityState("finalizing"));
        }
        if enforcement.body.liability_key != liability_key {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement does not name this liability".to_owned(),
            ));
        }
        // Everything downstream binds the vault, the allocation, and the
        // seller to the enforcement's own self-declaration. The head is
        // what anchors that triple to the defect being settled, so one
        // liability can never authorize an impairment against a target it
        // was not opened against.
        let body = &enforcement.body;
        let bindings: [(&str, &str, &'static str); 6] = [
            (&liability.finding_id, &body.finding_id, "finding_id"),
            (&liability.listing_id, &body.listing_id, "listing_id"),
            (
                &liability.allocation_id,
                &body.seller_allocation_id,
                "allocation_id",
            ),
            (&liability.chain_id, &body.vault.chain_id, "chain_id"),
            (
                &liability.vault_contract,
                &body.vault.vault_contract,
                "vault_contract",
            ),
            (&liability.vault_id, &body.vault.vault_id, "vault_id"),
        ];
        for (durable, declared, label) in bindings {
            if durable != declared {
                return Err(ChallengeCoordinatorError::LiabilityIdentity(label));
            }
        }
        let pins = FindingEnforcementPins {
            finalization_authority: self.finalization_authority.public_key(),
            settlement_observer: self.pins.settlement_observer.clone(),
            seller: seller.clone(),
            max_snapshot_age_secs,
        };
        let verified = verify_finding_enforcement(enforcement, bond_snapshot, &pins, now)
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let planned = plan_finding_impairment(
            settlement_config,
            &verified,
            operator_address,
            vault_snapshot,
            anchor_proof,
        )
        .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;

        let intent_key = planned.intent().intent_id.clone();
        // The intent must already be durable: the publisher contract
        // refuses an unfenced dispatch, and so does this coordinator.
        let intent = self
            .challenges
            .get_effect_intent(&intent_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if intent.state == FindingEffectIntentState::Confirmed {
            // The impairment already landed and was proved to be this
            // intent. Dispatching again would ask the vault to move the
            // same collateral twice, and the confirmed state has no
            // outgoing edge, so the settle is the only work left.
            self.challenges
                .settle_liability(liability_key, FindingLiabilityState::Finalizing, now)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
            return Ok(FindingFinalization::AlreadyConfirmed);
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let outcome = dispatch_finding_impairment(&planned, publisher)
            .map_err(|error| ChallengeCoordinatorError::Publisher(error.to_string()))?;

        match &outcome {
            FindingImpairmentOutcome::Confirmed { .. } => {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                self.challenges
                    .settle_liability(liability_key, FindingLiabilityState::Finalizing, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingImpairmentOutcome::Quarantined { reason } if quarantine_is_pending(*reason) => {
                // A broadcast whose receipt has not arrived, has not
                // finalized, or reverted is an observation still in
                // flight. It leaves the intent failed and dispatchable,
                // because the terminal quarantined state would close the
                // only edge the same transaction can still be proved on.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingImpairmentOutcome::Quarantined { .. } => {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Quarantined, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                self.challenges
                    .set_liability_quarantine(liability_key, true, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingImpairmentOutcome::Failed { .. } => {
                // A clean vault rejection is unambiguous and retryable, so
                // the intent returns to failed rather than quarantined.
                // The liability keeps blocking purchases either way.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
        }
        Ok(FindingFinalization::Reconciled(outcome))
    }

    /// The sealed claim snapshot for one liability, when one exists.
    pub fn sealed_claim(
        &self,
        liability_key: &str,
    ) -> Result<Option<(String, String)>, ChallengeCoordinatorError> {
        Ok(self
            .challenges
            .get_claim_snapshot(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .map(|record| (record.snapshot_digest, record.allocation_digest)))
    }

    // -----------------------------------------------------------------
    // Internal steps
    // -----------------------------------------------------------------

    /// Resolve the finding from the exact bytes whose digest the
    /// challenge binds. A typed view handed in beside those bytes would
    /// be a different artifact with the same name, so only the bytes are
    /// accepted here.
    fn resolve_finding(
        &self,
        raw_finding: &str,
        challenge: &FindingChallenge,
    ) -> Result<Finding, ChallengeCoordinatorError> {
        if raw_finding.len() > MAX_RAW_FINDING_BYTES {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding artifact exceeds the ingress bound".to_owned(),
            ));
        }
        if sha256_hex(raw_finding.as_bytes()) != challenge.finding_artifact_sha256 {
            return Err(ChallengeCoordinatorError::FindingBinding(
                "finding_artifact_sha256",
            ));
        }
        let finding: Finding = serde_json::from_str(raw_finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        verify_finding(&finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        if finding.finding_id != challenge.finding_id {
            return Err(ChallengeCoordinatorError::FindingBinding("finding_id"));
        }
        Ok(finding)
    }

    /// Require a buyer filing to have finished paying for itself before it
    /// can be adjudicated.
    ///
    /// The challenge row is recorded before the fee is charged, so a
    /// filing whose charge failed leaves that row behind in `submitted`.
    /// The dispute lock is the last write a submission makes and it
    /// happens only after the fee has reconciled, so the lock, not the
    /// row, is what proves both money steps landed. Without it the
    /// challenge would be adjudicated with no fee collected and no stake
    /// at risk, which is exactly what makes a frivolous filing free.
    ///
    /// A venue audit has no fee, bond, or lock member at all, so it is
    /// evaluable on its authorization alone.
    fn require_funded_filing(&self, challenge_id: &str) -> Result<(), ChallengeCoordinatorError> {
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Ok(());
        }
        if self
            .challenges
            .get_dispute_lock(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .is_none()
        {
            return Err(ChallengeCoordinatorError::FilingUnfunded);
        }
        Ok(())
    }

    /// Require the fee and bond a buyer submission carries to be the ones
    /// the admitted market terms pinned and the signed fee schedule
    /// priced.
    ///
    /// The two shipped fee event kinds are hard-pinned to the audit pool
    /// so a seller cannot redirect participation fees. The dispute fee is
    /// the third charge path and is pinned just as hard, in the other
    /// direction: it reaches the challenge-administration pool or it does
    /// not settle.
    ///
    /// The amounts are then held to the schedule the filing itself names.
    /// A submission that binds a schedule digest but is never checked
    /// against the schedule behind it prices its own filing, which leaves
    /// the stake a frivolous challenge risks entirely to the challenger.
    fn require_dispute_terms(
        &self,
        submission: &chio_finding::FindingBuyerSubmission,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        let pool = &self.challenge_administration_pool;
        if fee.beneficiary_pool_principal_id != pool.principal_id
            || fee.rail_destination != pool.rail_destination
            || fee.amount.currency != pool.currency
        {
            return Err(ChallengeCoordinatorError::DisputeFeePool);
        }
        if fee.payer != submission.challenger {
            return Err(ChallengeCoordinatorError::DisputeFeePayer);
        }
        let lock = &submission.dispute_lock_ref;
        if lock.expiry <= now {
            return Err(ChallengeCoordinatorError::DisputeBondWindow);
        }
        if lock.amount.currency != pool.currency {
            return Err(ChallengeCoordinatorError::DisputeBondCurrency);
        }
        // The fee and the bond are two halves of one filing and one
        // schedule prices both. A submission naming two would take its fee
        // from the cheaper and its stake from the smaller.
        if fee.fee_schedule_envelope_sha256 != lock.fee_schedule_envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "fee_schedule_envelope_sha256",
            ));
        }
        let terms = self
            .resolve_fee_schedule(&fee.fee_schedule_envelope_sha256)?
            .body;
        // A schedule that has not been issued yet, or that has expired,
        // prices nothing: the window a filing is admitted in is the window
        // its own schedule is live in.
        if now < terms.issued_at || terms.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(ChallengeCoordinatorError::DisputeTerms("filing window"));
        }
        if fee.amount.units != terms.dispute_fee.units
            || fee.amount.currency != terms.dispute_fee.currency
        {
            return Err(ChallengeCoordinatorError::DisputeTerms("dispute fee"));
        }
        // The dispute-class requirement is unique in a schedule its own
        // validator accepted, and it fixes the stake exactly: a smaller
        // bond underprices a frivolous filing, and a larger one would let
        // a forfeiture take more than any signed schedule authorizes.
        let requirement = terms
            .bond_requirements
            .iter()
            .find(|requirement| requirement.bond_class == OpenMarketBondClass::Dispute)
            .ok_or(ChallengeCoordinatorError::DisputeTerms(
                "dispute bond requirement",
            ))?;
        if lock.amount.units != requirement.required_amount.units
            || lock.amount.currency != requirement.required_amount.currency
        {
            return Err(ChallengeCoordinatorError::DisputeTerms("dispute bond"));
        }
        Ok(())
    }

    /// Require a bondless venue audit to be one the published round drew.
    ///
    /// The audit branch is the only filing that stakes nothing, so the
    /// round is the whole of what stands between it and an unbounded free
    /// challenge. Verifying that the pinned audit authority signed the
    /// envelope proves who filed, never what was drawn: the three digests
    /// the branch carries have to resolve to a published round and to the
    /// draw that round deterministically produces for this exact listing.
    fn require_audit_selection(
        &self,
        audit: &chio_finding::FindingVenueAuditAuthorization,
        challenge: &FindingChallenge,
    ) -> Result<(), ChallengeCoordinatorError> {
        let round = self
            .filings
            .audit_round(&audit.audit_epoch_envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownAuditRound)?;
        // Re-derived from the resolved envelope, so a resolver answering
        // with any other round is caught here rather than authorizing a
        // filing against a round the audit never named.
        if self.envelope_digest(&round.epoch)? != audit.audit_epoch_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "audit_epoch_envelope_sha256",
            ));
        }
        verify_signed_audit_epoch(&round.epoch, &self.pins.audit_authority)
            .map_err(|error| ChallengeCoordinatorError::AuditEpoch(error.to_string()))?;
        if round.epoch.body.authorization_digest != audit.authorization_digest {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "authorization_digest",
            ));
        }
        // The selection is a pure function of inputs the epoch committed
        // to before the seed was revealed, so it is recomputed here rather
        // than read from anything the filing carries. A listing the round
        // never drew has no entry to find.
        let selection =
            select_audit_targets(&round.epoch.body, &round.revealed_seed, &round.eligible)
                .map_err(|error| ChallengeCoordinatorError::AuditSelection(error.to_string()))?;
        let drawn = selection
            .iter()
            .find(|target| {
                target.finding_id == challenge.finding_id
                    && target.listing_id == challenge.listing_id
            })
            .ok_or(ChallengeCoordinatorError::AuditRoundBinding("selection"))?;
        if drawn.draw != audit.selection_digest {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "selection_digest",
            ));
        }
        Ok(())
    }

    /// Resolve the signed fee schedule one filing bound by digest, and
    /// prove it is a schedule this venue authorized.
    ///
    /// The digest is re-derived from the resolved envelope, so a resolver
    /// answering with any other artifact is caught here rather than
    /// pricing the filing. The signer must be one of the pinned
    /// fee-schedule operators and the signature must verify strictly
    /// against that pin, so an envelope's own embedded key never widens
    /// the roster it is checked against.
    fn resolve_fee_schedule(
        &self,
        envelope_sha256: &str,
    ) -> Result<SignedOpenMarketFeeSchedule, ChallengeCoordinatorError> {
        let schedule = self
            .filings
            .fee_schedule(envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownFeeSchedule)?;
        if self.envelope_digest(&schedule)? != envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "resolved fee schedule digest",
            ));
        }
        let operator = self
            .fee_schedule_operators
            .iter()
            .find(|operator| *operator == &schedule.signer_key)
            .ok_or(ChallengeCoordinatorError::AuthorityPinMismatch(
                "fee schedule",
            ))?;
        verify_pinned_envelope(&schedule, operator, "fee schedule")
            .map_err(|error| ChallengeCoordinatorError::FeeScheduleArtifact(error.to_string()))?;
        schedule
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::FeeScheduleArtifact)?;
        Ok(schedule)
    }

    /// Require every governance artifact behind a penalty to carry a
    /// pinned signature.
    ///
    /// The charter, the case, and the activation are governance-root
    /// artifacts; the fee schedule verifies against its own operator
    /// roster; a superseded penalty can only be one this lane signed. The
    /// listing is left to the namespace-owner rule the penalty surface
    /// applies, and is bound to the case, which is pinned here.
    fn require_pinned_governance(
        &self,
        governance: &FindingPenaltyGovernance<'_>,
        case: &SignedGenericGovernanceCase,
        prior_penalty: Option<&SignedOpenMarketPenalty>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let governance_key = &self.pins.governance_authority;
        // The listing authenticates against its own namespace owner rather
        // than a pinned key, so the case is what anchors it: a listing the
        // pinned case does not name cannot be the one being sanctioned.
        if governance.listing.body.listing_id != case.body.listing_id {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "penalty listing",
            ));
        }
        if !self
            .fee_schedule_operators
            .contains(&governance.fee_schedule.signer_key)
        {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "fee schedule",
            ));
        }
        if &governance.charter.signer_key != governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance charter",
            ));
        }
        if &case.signer_key != governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance case",
            ));
        }
        if governance
            .activation
            .is_some_and(|activation| &activation.signer_key != governance_key)
        {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "trust activation",
            ));
        }
        if prior_penalty
            .is_some_and(|prior| prior.signer_key != self.penalty_authority.public_key())
        {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "prior penalty",
            ));
        }
        Ok(())
    }

    /// Require the collateral behind this defect to be able to fund a
    /// nonzero impairment, on the same inputs the sealed accounting is
    /// computed from.
    fn require_impairable_collateral(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let open = self
            .purchases
            .list_outstanding_exposure_total(collateral.allocation_id, now)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let candidate = collateral
            .base_finding_stake
            .units
            .checked_add(open)
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic(
                    "computed exposure overflowed".to_owned(),
                )
            })?;
        if candidate.min(collateral.live_allocated_collateral_units) == 0 {
            return Err(ChallengeCoordinatorError::NothingToImpair);
        }
        Ok(())
    }

    /// Require the caller's identity to be exactly the one the durable
    /// head carries, and that head to be the one that identity derives.
    fn require_identity_matches_head(
        &self,
        liability_key: &str,
        identity: &FindingLiabilityIdentity<'_>,
        record: &FindingLiabilityRecord,
    ) -> Result<(), ChallengeCoordinatorError> {
        let fields: [(&str, &str, &'static str); 6] = [
            (&record.finding_id, identity.finding_id, "finding_id"),
            (&record.listing_id, identity.listing_id, "listing_id"),
            (
                &record.allocation_id,
                identity.allocation_id,
                "allocation_id",
            ),
            (&record.chain_id, identity.chain_id, "chain_id"),
            (
                &record.vault_contract,
                identity.vault_contract,
                "vault_contract",
            ),
            (&record.vault_id, identity.vault_id, "vault_id"),
        ];
        for (durable, supplied, label) in fields {
            if durable != supplied {
                return Err(ChallengeCoordinatorError::LiabilityIdentity(label));
            }
        }
        // The key is a commitment to this exact identity, so re-deriving
        // it proves the head named by the key is the head that identity
        // belongs to rather than one that merely exists.
        if derive_liability_key(
            &derive_defect_key(&record.finding_id),
            &self.venue_id,
            identity,
        ) != liability_key
        {
            return Err(ChallengeCoordinatorError::LiabilityIdentity(
                "liability_key",
            ));
        }
        Ok(())
    }

    /// Require the presented outcome to be the exact upheld adjudication
    /// this liability was opened on.
    ///
    /// The envelope digest is compared against the one the store recorded
    /// with the verdict, so neither a differently signed outcome for the
    /// same challenge nor an upheld outcome from another defect can carry
    /// an impairment.
    fn require_outcome_upheld_this_liability(
        &self,
        outcome: &SignedFindingChallengeOutcome,
        record: &FindingLiabilityRecord,
    ) -> Result<(), ChallengeCoordinatorError> {
        if outcome.body.verdict != chio_finding::FindingChallengeVerdict::Upheld {
            return Err(ChallengeCoordinatorError::VerdictNotUpheld);
        }
        if outcome.body.finding_id != record.finding_id
            || outcome.body.listing_id != record.listing_id
            || outcome.body.backing_allocation_id != record.allocation_id
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let challenge_id = record
            .upheld_challenge_id
            .as_deref()
            .ok_or(ChallengeCoordinatorError::LiabilityState("upheld"))?;
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let presented = self.envelope_digest(outcome)?;
        if challenge.outcome_envelope_sha256.as_deref() != Some(presented.as_str()) {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        Ok(())
    }

    /// Charge the dispute fee to the challenge-administration pool
    /// exactly once, through the same fence-then-dispatch-then-reconcile
    /// shape the shipped participation charge uses.
    ///
    /// The fee lives on the challenge lane's own effect fence rather than
    /// the admission fee ledger: that ledger is keyed by a closed event
    /// vocabulary whose two members are hard-pinned to the audit pool, so
    /// a dispute filing borrowing one of those keys would collide with the
    /// seller's own publication or participation charge for the same
    /// finding and listing, and settle nothing.
    fn charge_dispute_fee(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        let fee_operation_id = sha256_hex(
            format!(
                "{DISPUTE_FEE_OPERATION_DOMAIN}\0{challenge_id}\0{schedule}",
                schedule = fee.fee_schedule_envelope_sha256,
            )
            .as_bytes(),
        );
        let intent_key = derive_fee_intent_key(challenge_id, &fee_operation_id);
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: fee.payer.to_hex(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: fee.beneficiary_pool_principal_id.clone(),
            rail_destination: fee.rail_destination.clone(),
        };
        // The commitment is the whole instruction, so a replay that names
        // a different amount, currency, pool, or destination collides with
        // what is already durable and rejects rather than charging twice
        // under one identity.
        let intent_digest = canonical_digest_of(&instruction)?;
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::Fee,
                &intent_digest,
                None,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if fenced == FindingChallengeWriteOutcome::ExistingSame {
            let state = self
                .challenges
                .get_effect_intent(&intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .map(|record| record.state);
            if state == Some(FindingEffectIntentState::Confirmed) {
                // Settled by an earlier attempt: dispatching again would
                // ask the rail to move the same money twice.
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match self.rail.dispatch(&instruction) {
            Ok(_) => {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Err(reason) => {
                // The intent stays durable and unreconciled, so the filing
                // cannot proceed on an uncollected fee, and a retry
                // re-dispatches from `failed` rather than fencing again.
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(reason))
            }
        }
    }

    /// Compute the checked penalty calculation the outcome carries.
    ///
    /// The formula is predeclared and every member is recorded, so the
    /// penalty lane rechecks it rather than trusting one number. The open
    /// per-sale encumbrances come from the authoritative purchase store,
    /// never from the filing.
    fn checked_penalty_calculation(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<FindingPenaltyCalculation, ChallengeCoordinatorError> {
        let open = self
            .purchases
            .list_outstanding_exposure_total(collateral.allocation_id, now)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let computed = collateral
            .base_finding_stake
            .units
            .checked_add(open)
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic(
                    "computed exposure overflowed".to_owned(),
                )
            })?;
        let calculation = FindingPenaltyCalculation {
            base_finding_stake_units: collateral.base_finding_stake.units,
            open_per_sale_encumbrance_units: open,
            computed_exposure_units: computed,
            listing_required_amount_units: collateral.listing_required_amount.units,
            live_allocated_collateral_units: collateral.live_allocated_collateral_units,
            penalty_amount: MonetaryAmount {
                units: computed.min(collateral.live_allocated_collateral_units),
                currency: collateral.base_finding_stake.currency.clone(),
            },
        };
        Ok(calculation)
    }

    /// Derive, check, and seal the accounting the payout comes from.
    ///
    /// Candidate purchase keys are hints. Every figure that reaches the
    /// distribution is re-read from the authoritative purchase index and
    /// re-verified: the record must verify under the pinned purchase
    /// authority, name this liability's finding and listing, sit at or
    /// below the frozen cutoff on a slot that closed against a settled
    /// record, and pay a destination that was admitted at capture. No
    /// caller-supplied amount or address survives.
    fn seal_claim_snapshot(
        &self,
        liability_key: &str,
        identity: &FindingLiabilityIdentity<'_>,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<SealedClaimSnapshot, ChallengeCoordinatorError> {
        let harms = self.verified_harms(identity, cutoff_slot, claim_candidates)?;
        let total_realized_spend_units = harms
            .iter()
            .try_fold(0_u64, |total, harm| {
                total.checked_add(harm.realized_spend_units)
            })
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic("verified harm overflowed".to_owned())
            })?;
        let open = self
            .purchases
            .list_outstanding_exposure_total(collateral.allocation_id, now)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let distribution = compute_slash_distribution(
            &SlashInputs {
                base_finding_stake: collateral.base_finding_stake,
                open_per_sale_encumbrances: open,
                live_allocated_collateral: collateral.live_allocated_collateral_units,
                listing_required_amount: collateral.listing_required_amount,
                community_fund_destination: &self.community_fund_destination,
            },
            &harms,
        )
        .map_err(|error| ChallengeCoordinatorError::SlashArithmetic(error.to_string()))?;

        let snapshot_digest = snapshot_digest_of(&harms)?;
        let allocation_digest = allocation_digest_of(&distribution)?;
        self.challenges
            .seal_claim_snapshot(&FindingClaimSnapshotInput {
                liability_key,
                cutoff_slot,
                snapshot_digest: &snapshot_digest,
                allocation_digest: &allocation_digest,
                total_realized_spend_units,
                currency: &distribution.slash.currency,
                buyer_pool_units: distribution.buyer_pool_units,
                community_fund_units: distribution.community_fund_units,
                sealed_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(SealedClaimSnapshot {
            liability_key: liability_key.to_owned(),
            cutoff_slot,
            snapshot_digest,
            allocation_digest,
            total_realized_spend_units,
            distribution,
        })
    }

    /// Re-resolve every candidate purchase through the authoritative
    /// index and build the verified harm set.
    ///
    /// Two settled purchases can name one immutable destination, which the
    /// enforcement instruction forbids repeating, so harms sharing a
    /// destination are folded into one entry carrying the summed spend and
    /// the lowest purchase key. Folding rather than rejecting keeps a
    /// buyer who bought twice whole, and keying on the lowest purchase key
    /// keeps the remainder order deterministic.
    fn verified_harms(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        cutoff_slot: u64,
        claim_candidates: &[String],
    ) -> Result<Vec<VerifiedHarm>, ChallengeCoordinatorError> {
        let admitted = self
            .purchases
            .list_payout_destinations(identity.allocation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let mut folded: std::collections::BTreeMap<String, VerifiedHarm> =
            std::collections::BTreeMap::new();
        let mut keys: Vec<&String> = claim_candidates.iter().collect();
        keys.sort();
        keys.dedup();
        for purchase_key in keys {
            let row = self
                .purchases
                .get_purchase_record(purchase_key)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::UnknownPurchaseRecord(purchase_key.clone())
                })?;
            let signed: SignedFindingPurchaseRecord = serde_json::from_slice(&row.record_json)
                .map_err(|error| {
                    ChallengeCoordinatorError::ArtifactValidation(error.to_string())
                })?;
            verify_signed_purchase_record(&signed, &self.pins.purchase_authority).map_err(
                |error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()),
            )?;
            let record: &FindingPurchaseRecord = &signed.body;
            if record.finding_id != identity.finding_id
                || record.listing_id != identity.listing_id
                || &record.purchase_key != purchase_key
            {
                return Err(ChallengeCoordinatorError::PurchaseOutsideCutoff(
                    purchase_key.clone(),
                ));
            }
            let slot = self
                .purchases
                .get_slot(&row.reservation_id)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::PurchaseOutsideCutoff(purchase_key.clone())
                })?;
            if slot.listing_id != identity.listing_id || slot.slot_ordinal > cutoff_slot {
                return Err(ChallengeCoordinatorError::PurchaseOutsideCutoff(
                    purchase_key.clone(),
                ));
            }
            if !admitted
                .iter()
                .any(|(_, destination)| destination == &record.payout_destination)
            {
                return Err(ChallengeCoordinatorError::UnadmittedPayoutDestination(
                    purchase_key.clone(),
                ));
            }
            let entry = folded
                .entry(record.payout_destination.clone())
                .or_insert_with(|| VerifiedHarm {
                    purchase_key: record.purchase_key.clone(),
                    destination: record.payout_destination.clone(),
                    realized_spend_units: 0,
                });
            if record.purchase_key < entry.purchase_key {
                entry.purchase_key = record.purchase_key.clone();
            }
            entry.realized_spend_units = entry
                .realized_spend_units
                .checked_add(record.realized_spend.units)
                .ok_or_else(|| {
                    ChallengeCoordinatorError::SlashArithmetic(
                        "folded realized spend overflowed".to_owned(),
                    )
                })?;
        }
        let mut harms: Vec<VerifiedHarm> = folded.into_values().collect();
        harms.sort_by(|left, right| left.purchase_key.cmp(&right.purchase_key));
        Ok(harms)
    }

    /// Require the carried accounting to be exactly what the store
    /// sealed. The sealed row is the fence: a caller cannot substitute a
    /// different distribution for the one the claim window produced.
    fn require_sealed_matches_store(
        &self,
        liability_key: &str,
        sealed: &SealedClaimSnapshot,
    ) -> Result<(), ChallengeCoordinatorError> {
        let record = self
            .challenges
            .get_claim_snapshot(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
        let allocation_digest = allocation_digest_of(&sealed.distribution)?;
        if record.snapshot_digest != sealed.snapshot_digest
            || record.allocation_digest != sealed.allocation_digest
            || record.allocation_digest != allocation_digest
            || record.cutoff_slot != sealed.cutoff_slot
            || record.total_realized_spend_units != sealed.total_realized_spend_units
            || record.buyer_pool_units != sealed.distribution.buyer_pool_units
            || record.community_fund_units != sealed.distribution.community_fund_units
        {
            return Err(ChallengeCoordinatorError::SealedClaimMismatch);
        }
        Ok(())
    }

    /// Sign the enforcement instruction and fence every domain-keyed
    /// effect intent before the liability enters finalizing.
    ///
    /// Every field of the instruction that names a target comes from the
    /// durable head rather than from the call, so the signed authorization
    /// can only ever point at the allocation and vault the liability was
    /// opened against.
    #[allow(clippy::too_many_arguments)]
    fn finalize_enforcement(
        &self,
        record: &FindingLiabilityRecord,
        outcome: &SignedFindingChallengeOutcome,
        sealed: &SealedClaimSnapshot,
        slash: &FindingPenaltyOutcome,
        operator_id: &str,
        bond_snapshot_envelope_sha256: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        if sealed.distribution.slash.units == 0 || sealed.distribution.entries.is_empty() {
            return Err(ChallengeCoordinatorError::NothingToImpair);
        }
        let liability_key = record.liability_key.as_str();
        let outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        let seller_impair_key = derive_seller_impair_intent_key(
            &record.chain_id,
            &record.vault_contract,
            liability_key,
            &sealed.allocation_digest,
        );
        let root_intent_key = derive_root_intent_key(
            operator_id,
            liability_key,
            &outcome.body.outcome_id,
            &sealed.allocation_digest,
        );
        let retraction_intent_id = sha256_hex(
            format!(
                "{RETRACTION_INTENT_DOMAIN}\0{liability_key}\0{outcome}",
                outcome = outcome.body.outcome_id
            )
            .as_bytes(),
        );
        let retraction_key = derive_retraction_intent_key(
            &record.finding_id,
            &self.status_feed_operator_ref,
            &retraction_intent_id,
        );

        let mut bindings = vec![
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::SellerImpair,
                intent_id: seller_impair_key.clone(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::RootIntent,
                intent_id: root_intent_key.clone(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::Retraction,
                intent_id: retraction_key.clone(),
            },
        ];
        let mut fenced = vec![
            (
                FindingEffectIntentKind::SellerImpair,
                seller_impair_key.clone(),
                // The commitment carries the vault the impairment targets
                // as well as the money it moves, so two enforcements for
                // one liability naming different vaults collide on this
                // key and reject instead of reconciling as identical.
                format!(
                    "{EFFECT_SELLER_IMPAIR_DOMAIN}\0{chain}\0{contract}\0{vault}\0{allocation}",
                    chain = record.chain_id,
                    contract = record.vault_contract,
                    vault = record.vault_id,
                    allocation = sealed.allocation_digest,
                ),
            ),
            (
                FindingEffectIntentKind::RootIntent,
                root_intent_key.clone(),
                sha256_hex(
                    format!(
                        "{EFFECT_ROOT_INTENT_DOMAIN}\0{liability_key}\0{digest}",
                        digest = slash.penalty_envelope_sha256
                    )
                    .as_bytes(),
                ),
            ),
            (
                FindingEffectIntentKind::Retraction,
                retraction_key.clone(),
                retraction_intent_id.clone(),
            ),
        ];

        // The challenge-bond disposition is a separate effect with its own
        // key, so a bond return can never reconcile against the seller
        // impairment or the fee.
        if let Some(challenge_id) = record.upheld_challenge_id.as_deref() {
            if let Some(lock) = self
                .challenges
                .get_dispute_lock(challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            {
                let key = derive_challenge_bond_intent_key(challenge_id, &lock.lock_id);
                // The commitment separately binds the disposition, amount,
                // currency, and destination, so two conflicting
                // dispositions of one bond collide and reject.
                let digest = sha256_hex(
                    format!(
                        "{EFFECT_CHALLENGE_BOND_DOMAIN}\0returned\0{units}\0{currency}\0{owner}",
                        units = lock.amount_units,
                        currency = lock.currency,
                        owner = lock.owner_hex,
                    )
                    .as_bytes(),
                );
                bindings.push(FindingEffectIntentBinding {
                    kind: chio_finding::FindingEffectIntentKind::ChallengeBond,
                    intent_id: key.clone(),
                });
                fenced.push((FindingEffectIntentKind::ChallengeBond, key, digest));
            }
        }

        for (kind, key, commitment) in &fenced {
            self.challenges
                .record_effect_intent(
                    key,
                    *kind,
                    &sha256_hex(commitment.as_bytes()),
                    Some(liability_key),
                    now,
                )
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        }

        let destinations = sealed
            .distribution
            .entries
            .iter()
            .map(|entry: &DistributionEntry| FindingEnforcementDestination {
                destination: entry.destination.clone(),
                amount: MonetaryAmount {
                    units: entry.amount_units,
                    currency: sealed.distribution.slash.currency.clone(),
                },
            })
            .collect();
        let mut enforcement = FindingChallengeEnforcement {
            schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_owned(),
            enforcement_id: String::new(),
            liability_key: liability_key.to_owned(),
            finding_id: record.finding_id.clone(),
            listing_id: record.listing_id.clone(),
            outcome_id: outcome.body.outcome_id.clone(),
            outcome_envelope_sha256,
            penalty_envelope_sha256: slash.penalty_envelope_sha256.clone(),
            bond_snapshot_envelope_sha256: bond_snapshot_envelope_sha256.to_owned(),
            purchase_snapshot_digest: sealed.snapshot_digest.clone(),
            deterministic_allocation_digest: sealed.allocation_digest.clone(),
            seller_allocation_id: record.allocation_id.clone(),
            vault: chio_finding::FindingVaultReference {
                chain_id: record.chain_id.clone(),
                vault_contract: record.vault_contract.clone(),
                vault_id: record.vault_id.clone(),
            },
            amount: sealed.distribution.slash.clone(),
            destinations,
            effect_intents: bindings,
            finalized_at: now,
        };
        enforcement.enforcement_id = compute_enforcement_id(&enforcement)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        enforcement
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let signed =
            SignedFindingChallengeEnforcement::sign(enforcement, &self.finalization_authority)
                .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let enforcement_envelope_sha256 = self.envelope_digest(&signed)?;

        self.challenges
            .begin_finalizing(liability_key, FindingLiabilityState::PendingAppeal, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        Ok(AppealResolution::Finalizing(Box::new(
            AuthorizedImpairment {
                enforcement: signed,
                enforcement_envelope_sha256,
                slash: slash.clone(),
                effect_intent_keys: fenced
                    .into_iter()
                    .map(|(kind, key, _)| (kind, key))
                    .collect(),
            },
        )))
    }

    /// Mint one finding penalty under the pinned penalty authority and
    /// evaluate it through the composing wrapper.
    ///
    /// Every finding-specific field is set here rather than accepted from
    /// a caller: the abuse class, the bond class, the branch's action and
    /// state, the single external evidence reference bound to the signed
    /// outcome, and the checked amount. The wrapper then runs the generic
    /// evaluation first and refuses any result carrying findings.
    ///
    /// The authority set the whole penalty lane authenticates against is
    /// built from configuration alone: the pinned governance root for the
    /// charter, the case, and the activation, the pinned fee-schedule
    /// operator roster for the schedule, and this coordinator's own
    /// penalty key for the penalty it is about to sign. A key that only
    /// appears inside an artifact never joins that set, so a self-signed
    /// governance case cannot authorize a slash.
    #[allow(clippy::too_many_arguments)]
    fn mint_penalty(
        &self,
        branch: FindingPenaltyBranch,
        governance: &FindingPenaltyGovernance<'_>,
        case: &SignedGenericGovernanceCase,
        prior_penalty: Option<&SignedOpenMarketPenalty>,
        checked_amount: &MonetaryAmount,
        outcome: &SignedFindingChallengeOutcome,
        sanction_case_id: &str,
        hold_penalty_id: Option<&str>,
        now: u64,
    ) -> Result<FindingPenaltyOutcome, ChallengeCoordinatorError> {
        let penalty_key = self.penalty_authority.public_key();
        let governance_key = &self.pins.governance_authority;
        self.require_pinned_governance(governance, case, prior_penalty)?;
        let outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        let (action, state, supersedes) = match branch {
            FindingPenaltyBranch::PendingAppeal => (
                OpenMarketPenaltyAction::HoldBond,
                OpenMarketPenaltyState::Enforced,
                None,
            ),
            FindingPenaltyBranch::SuccessfulAppeal => (
                OpenMarketPenaltyAction::ReverseSlash,
                OpenMarketPenaltyState::Reversed,
                hold_penalty_id,
            ),
            FindingPenaltyBranch::AppealFinalImpairment => (
                OpenMarketPenaltyAction::SlashBond,
                OpenMarketPenaltyState::Enforced,
                hold_penalty_id,
            ),
        };
        let issue = OpenMarketPenaltyIssueRequest {
            fee_schedule: governance.fee_schedule.clone(),
            charter: governance.charter.clone(),
            case: case.clone(),
            listing: governance.listing.clone(),
            activation: governance.activation.cloned(),
            abuse_class: OpenMarketAbuseClass::FraudulentListing,
            bond_class: OpenMarketBondClass::Listing,
            action,
            state,
            penalty_amount: checked_amount.clone(),
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::External,
                reference_id: outcome.body.outcome_id.clone(),
                uri: None,
                sha256: Some(outcome_envelope_sha256.clone()),
            }],
            subject_operator_id: Some(governance.subject_operator_id.to_owned()),
            supersedes_penalty_id: supersedes.map(str::to_owned),
            issued_by: governance.issued_by.to_owned(),
            opened_at: Some(now),
            updated_at: Some(now),
            expires_at: governance.penalty_expires_at,
            note: None,
        };
        let mut trusted = Vec::with_capacity(self.fee_schedule_operators.len().saturating_add(2));
        trusted.push(governance_key.clone());
        trusted.extend(self.fee_schedule_operators.iter().cloned());
        trusted.push(penalty_key);
        let artifact = build_open_market_penalty_artifact_with_trusted_signers(
            governance.local_operator_id,
            &issue,
            now,
            &trusted,
        )
        .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        let penalty = SignedOpenMarketPenalty::sign(artifact, &self.penalty_authority)
            .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let penalty_envelope_sha256 = self.envelope_digest(&penalty)?;
        let request = OpenMarketPenaltyEvaluationRequest {
            fee_schedule: governance.fee_schedule.clone(),
            listing: governance.listing.clone(),
            current_publisher: governance.current_publisher.clone(),
            activation: governance.activation.cloned(),
            charter: governance.charter.clone(),
            case: case.clone(),
            penalty: penalty.clone(),
            prior_penalty: prior_penalty.cloned(),
            evaluated_at: Some(now),
        };
        let evaluation = evaluate_finding_penalty(
            &request,
            branch,
            &FindingPenaltyContext {
                outcome_id: &outcome.body.outcome_id,
                outcome_envelope_sha256: &outcome_envelope_sha256,
                checked_amount,
                sanction_case_id,
                hold_penalty_id,
            },
            now,
            &trusted,
        )
        .map_err(|error| ChallengeCoordinatorError::PenaltyEvaluation(error.to_string()))?;
        Ok(FindingPenaltyOutcome {
            penalty,
            penalty_envelope_sha256,
            evaluation,
        })
    }

    /// The evidence-bundle commitment an outcome binds: the exact
    /// evidence branch the challenge selected, domain separated.
    fn evidence_bundle_digest(
        &self,
        challenge: &FindingChallenge,
    ) -> Result<String, ChallengeCoordinatorError> {
        let bytes = chio_core::canonical_json_bytes(&challenge.evidence)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let mut preimage = Vec::with_capacity(EVIDENCE_BUNDLE_DOMAIN.len() + 1 + bytes.len());
        preimage.extend_from_slice(EVIDENCE_BUNDLE_DOMAIN.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        Ok(sha256_hex(&preimage))
    }

    fn envelope_digest<T: serde::Serialize>(
        &self,
        envelope: &chio_core::receipt::lineage::SignedExportEnvelope<T>,
    ) -> Result<String, ChallengeCoordinatorError> {
        signed_envelope_sha256(envelope).map_err(|_| ChallengeCoordinatorError::Canonical)
    }
}

/// Whether a quarantine reason describes an observation that has not
/// settled yet rather than one no further attempt can resolve.
///
/// A publisher broadcasts and returns before the transaction is mined, so
/// a missing, unfinalized, or reverted receipt is the ordinary shape of an
/// impairment still in flight, and in the reverted case nothing moved at
/// all. The terminal quarantined state has no outgoing edge, so it is
/// reserved for external state that genuinely needs an operator: an
/// evidence hash consumed by an unknown transaction, a target or decoded
/// input that does not match the frozen intent, or a stored transaction
/// whose provenance cannot be established.
const fn quarantine_is_pending(reason: FindingImpairmentQuarantine) -> bool {
    matches!(
        reason,
        FindingImpairmentQuarantine::ReceiptMissing
            | FindingImpairmentQuarantine::ReceiptNotFinalized
            | FindingImpairmentQuarantine::ReceiptReverted
    )
}

/// Canonical digest of one rail instruction, matching the shipped fee
/// lane's instruction commitment.
fn canonical_digest_of<T: serde::Serialize>(
    value: &T,
) -> Result<String, ChallengeCoordinatorError> {
    let bytes =
        chio_core::canonical_json_bytes(value).map_err(|_| ChallengeCoordinatorError::Canonical)?;
    Ok(sha256_hex(&bytes))
}

/// The sealed purchase-snapshot commitment: every verified harm in
/// purchase-key order, with its destination and spend.
fn snapshot_digest_of(harms: &[VerifiedHarm]) -> Result<String, ChallengeCoordinatorError> {
    let rows: Vec<(&str, &str, u64)> = harms
        .iter()
        .map(|harm| {
            (
                harm.purchase_key.as_str(),
                harm.destination.as_str(),
                harm.realized_spend_units,
            )
        })
        .collect();
    let bytes =
        chio_core::canonical_json_bytes(&rows).map_err(|_| ChallengeCoordinatorError::Canonical)?;
    let mut preimage = Vec::with_capacity(PURCHASE_SNAPSHOT_DOMAIN.len() + 1 + bytes.len());
    preimage.extend_from_slice(PURCHASE_SNAPSHOT_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

/// The sealed deterministic-allocation commitment: the ordered
/// distribution and its two pool totals.
fn allocation_digest_of(
    distribution: &SlashDistribution,
) -> Result<String, ChallengeCoordinatorError> {
    let entries: Vec<(&str, u64)> = distribution
        .entries
        .iter()
        .map(|entry| (entry.destination.as_str(), entry.amount_units))
        .collect();
    let bytes = chio_core::canonical_json_bytes(&(
        &distribution.slash.units,
        distribution.slash.currency.as_str(),
        distribution.buyer_pool_units,
        distribution.community_fund_units,
        &entries,
    ))
    .map_err(|_| ChallengeCoordinatorError::Canonical)?;
    let mut preimage = Vec::with_capacity(ALLOCATION_DIGEST_DOMAIN.len() + 1 + bytes.len());
    preimage.extend_from_slice(ALLOCATION_DIGEST_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

const fn evidence_class_of(kind: FindingChallengeEvidenceKind) -> FindingChallengeEvidenceClass {
    match kind {
        FindingChallengeEvidenceKind::DigestMismatch => {
            FindingChallengeEvidenceClass::DigestMismatch
        }
        FindingChallengeEvidenceKind::EvidenceInvalid => {
            FindingChallengeEvidenceClass::EvidenceInvalid
        }
        FindingChallengeEvidenceKind::ReplayContradiction => {
            FindingChallengeEvidenceClass::ReplayContradiction
        }
    }
}

/// Map the adjudicated verdict onto the durable one. Only indeterminate
/// carries a retry window, and only when the caller holds a signed one.
const fn store_verdict(
    verdict: chio_finding::FindingChallengeVerdict,
    retry_deadline: Option<u64>,
) -> StoreVerdict {
    match verdict {
        chio_finding::FindingChallengeVerdict::Upheld => StoreVerdict::Upheld,
        chio_finding::FindingChallengeVerdict::Rejected => StoreVerdict::Rejected,
        chio_finding::FindingChallengeVerdict::Indeterminate => {
            StoreVerdict::Indeterminate { retry_deadline }
        }
    }
}

/// The governance surface owns the case-state vocabulary; the index
/// records it verbatim.
fn case_state_name(case: &SignedGenericGovernanceCase) -> &'static str {
    use chio_open_market::governance::generic::GenericGovernanceCaseState;
    match case.body.state {
        GenericGovernanceCaseState::Open => "open",
        GenericGovernanceCaseState::Escalated => "escalated",
        GenericGovernanceCaseState::Enforced => "enforced",
        GenericGovernanceCaseState::Resolved => "resolved",
        GenericGovernanceCaseState::Denied => "denied",
        GenericGovernanceCaseState::Superseded => "superseded",
    }
}

/// Whether the challenge lane authorization branch names a challenger.
#[must_use]
pub const fn branch_names_challenger(kind: FindingChallengeAuthorizationKind) -> bool {
    matches!(kind, FindingChallengeAuthorizationKind::BuyerSubmission)
}
