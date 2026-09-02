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
//!   transaction: the liability compare-and-set, the sales block, the
//!   purchase-cutoff freeze, and the seller-signed claim deadline commit
//!   together, then the pre-cutoff slots must close and that deadline must
//!   elapse before the claim snapshot is computed and sealed, then the
//!   pending-appeal sanction and hold are minted and evaluated.
//! - [`FindingChallengeCoordinator::resolve_appeal`] reverses a timely
//!   successful appeal, or, on appeal finality with no reversal, signs the
//!   enforcement instruction and fences every domain-keyed effect intent
//!   before the liability enters finalizing. An unresolved appeal
//!   quarantines; it is never read as a denial.
//! - [`FindingChallengeCoordinator::finalize`] verifies the enforcement
//!   pair through the settlement choke point, re-reads the chain state the
//!   signed snapshot rests on, plans the impairment, dispatches it through
//!   the injected publisher, and settles only on a confirmed
//!   reconciliation the chain still qualifies.
//!
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Ed25519Backend, Keypair, PublicKey, SigningBackend};
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    audit_epoch_precommitment_sha256, compute_enforcement_id, derive_outcome_id,
    derive_seller_impair_intent_id, ensure_challenge_class_compatibility, signed_envelope_sha256,
    verify_finding, verify_pinned_envelope, verify_signed_admission, verify_signed_audit_epoch,
    verify_signed_audit_round_authorization, verify_signed_challenge,
    verify_signed_challenge_outcome, verify_signed_market_terms, verify_signed_purchase_record,
    Finding, FindingChallenge, FindingChallengeAuthorization, FindingChallengeEnforcement,
    FindingChallengeEvidence, FindingChallengeEvidenceKind, FindingChallengeOutcome,
    FindingEffectIntentBinding, FindingEnforcementDestination, FindingPenaltyCalculation,
    FindingPurchaseRecord, FindingReplayRecipeInput, SignedFindingAdmission,
    SignedFindingAuditEpoch, SignedFindingAuditRoundAuthorization, SignedFindingChallenge,
    SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome,
    SignedFindingChallengeVerifierProfile, SignedFindingFinalizedBondSnapshot,
    SignedFindingMarketTerms, SignedFindingPurchaseRecord, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1,
};
pub use chio_finding::{
    FindingAuthorityStatus, SignedFindingAuthorityStatus, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeEvaluation,
    FindingChallengeEvaluationInput, FindingRetainedAuthorityPolicy,
    FindingVenueAuditSelectionEvidence,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_open_market::evaluation::{
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest,
};
use chio_open_market::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference};
use chio_open_market::fee_schedule::{OpenMarketBondClass, SignedOpenMarketFeeSchedule};
use chio_open_market::finding_audit::{
    derive_eligible_snapshot_digest, select_audit_targets, EligibleListing,
};
use chio_open_market::finding_penalty::{
    evaluate_finding_penalty, FindingPenaltyBranch, FindingPenaltyContext,
};
use chio_open_market::finding_slash_amount::{
    compute_frozen_slash_distribution, DistributionEntry, SlashDistribution, VerifiedHarm,
};
use chio_open_market::governance::generic::SignedGenericGovernanceCase;
use chio_open_market::listing::{
    ensure_generic_listing_signed_by_namespace_owner, GenericRegistryPublisher,
    SignedGenericListing, SignedGenericTrustActivation,
};
use chio_open_market::penalty::{
    build_open_market_penalty_artifact_with_trusted_signers, OpenMarketAbuseClass,
    OpenMarketPenaltyAction, OpenMarketPenaltyIssueRequest, OpenMarketPenaltyState,
    SignedOpenMarketPenalty,
};
use chio_settle::{
    dispatch_finding_impairment, plan_finding_impairment,
    plan_finding_impairment_for_reconciliation, recheck_finding_bond_observation,
    recheck_reconciled_finding_bond_observation, reobserve_finding_impairment,
    reobserve_finding_impairment_for_reconciliation, verify_finding_collateral_snapshot,
    verify_finding_enforcement, verify_finding_enforcement_for_reconciliation,
    ConfirmedFindingImpairmentReconciliation, EvmBondSnapshot, FindingAnchorPublisherEvidence,
    FindingBondObservationSource, FindingBondObservationVerdict, FindingDispatchPolicy,
    FindingEnforcementPins, FindingFinalityRequirement, FindingImpairmentOutcome,
    FindingImpairmentPublisher, FindingImpairmentQuarantine, FindingPenaltyAuthorityPolicy,
    FindingSettlementObserverEvidence, PlannedFindingImpairment,
    PlannedFindingImpairmentReconciliation, ReconciledFindingEnforcement, SettlementChainConfig,
    SignedFindingAnchorCheckpointPublication, VerifiedFindingEnforcement,
};
use chio_store_sqlite::{
    derive_dispute_bond_funding_intent_key, derive_dispute_bond_return_intent_key,
    derive_dispute_fee_collection_intent_key, derive_dispute_fee_return_intent_key,
    dispute_bond_funding_intent_digest, dispute_bond_return_intent_digest,
    FindingChallengeAuthorizationBranch, FindingChallengeEvaluationStart,
    FindingChallengeEvidenceClass, FindingChallengeState, FindingChallengeSubmission,
    FindingChallengeWriteOutcome, FindingClaimSnapshotInput, FindingDisputeLockDisposition,
    FindingDisputeLockInput, FindingDisputeLockRecord, FindingDisputeLockState,
    FindingEffectIntentKind, FindingEffectIntentState, FindingFinalizingAuthorizationInput,
    FindingGovernanceCaseInput, FindingGovernanceCaseKind, FindingLiabilityInput,
    FindingLiabilityRecord, FindingLiabilityState, FindingRetractionIntentCommitLiveness,
    FindingRetractionIntentInput, FindingRetractionIntentSource, FindingRetractionIntentState,
    SqliteFindingChallengeStore, SqliteFindingPurchaseStore, SqliteFindingStatusStore,
};
use serde::{Deserialize, Serialize};

use super::finding_handlers::{
    FindingRailInstruction, FindingRailObservation, FindingRailObserver,
};
use super::service_types::{
    require_status_feed_through, FindingAuthorityPin, FindingMarketConfig,
    FindingStatusOperatorPin, FindingStatusServiceBond,
};

#[path = "finding_challenge_coordinator/anchor_publisher.rs"]
mod anchor_publisher;
#[path = "finding_challenge_coordinator/finalization_authority.rs"]
mod finalization_authority;

/// Domain separator for the per-finding defect identity.
const DEFECT_DOMAIN: &str = "chio.finding.defect.v1";

/// Domain separator for the liability head identity.
const LIABILITY_DOMAIN: &str = "chio.finding.liability.v1";

/// Domain separator for the seller-impairment effect commitment.
const EFFECT_SELLER_IMPAIR_DOMAIN: &str = "chio.finding.effect.seller-impair.v1";

/// Domain separator for the challenge-bond disposition effect.
const EFFECT_CHALLENGE_BOND_DOMAIN: &str = "chio.finding.effect.challenge-bond.v1";

/// Domain separator for the dispute-fee effect.
const EFFECT_FEE_DOMAIN: &str = "chio.finding.effect.fee.v1";

/// Domain separator for the enforcement/root semantic effect.
const EFFECT_ROOT_INTENT_DOMAIN: &str = "chio.finding.effect.root-intent.v1";

/// Domain separator for the status-feed retraction effect.
const EFFECT_RETRACTION_DOMAIN: &str = "chio.finding.effect.retraction.v1";

/// Domain separator for the anchored evidence leaf an impairment burns.
const EFFECT_ANCHOR_EVIDENCE_DOMAIN: &str = "chio.finding.effect.anchor-evidence.v1";

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

/// How long one reading of a pinned key's revocation reference may govern.
/// Past this the reading describes the reference as it used to be, and a
/// key revoked since would still adjudicate under it.
const MAX_REVOCATION_STATUS_AGE_SECS: u64 = 3_600;

/// Shortest seller-signed appeal window the venue will admit.
const MIN_APPEAL_WINDOW_SECS: u64 = 24 * 60 * 60;

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
    let mut preimage = Vec::new();
    for component in [
        LIABILITY_DOMAIN,
        defect_key,
        venue_id,
        identity.listing_id,
        identity.allocation_id,
        identity.chain_id,
        identity.vault_contract,
        identity.vault_id,
    ] {
        preimage.extend_from_slice(&(component.len() as u64).to_be_bytes());
        preimage.extend_from_slice(component.as_bytes());
    }
    sha256_hex(&preimage)
}

/// Domain-keyed identity of the single unbatched seller impairment.
#[must_use]
pub fn derive_seller_impair_intent_key(
    chain_id: &str,
    vault_contract: &str,
    liability_key: &str,
    allocation_digest: &str,
) -> String {
    derive_seller_impair_intent_id(chain_id, vault_contract, liability_key, allocation_digest)
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

fn dispute_fee_intent_key(challenge_id: &str) -> String {
    derive_dispute_fee_collection_intent_key(challenge_id)
}

fn dispute_fee_return_intent_key(challenge_id: &str) -> String {
    derive_dispute_fee_return_intent_key(challenge_id)
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

/// Commitment the enforcement-root intent is fenced under: the liability
/// it settles and the exact penalty envelope it pays for.
///
/// The intent key is liability-scoped, so this is what stops a root
/// published for one penalty standing in for another on the same
/// liability.
#[must_use]
pub fn root_intent_commitment(liability_key: &str, penalty_envelope_sha256: &str) -> String {
    sha256_hex(
        format!("{EFFECT_ROOT_INTENT_DOMAIN}\0{liability_key}\0{penalty_envelope_sha256}")
            .as_bytes(),
    )
}

/// Domain-keyed identity of one anchored evidence leaf.
///
/// The key is the leaf and nothing else. The vault burns an evidence hash
/// globally and keeps that map private, so one anchored receipt must not
/// be able to authorize impairments on two liabilities: the second
/// presentation collides here and rejects rather than reaching the vault.
#[must_use]
pub fn derive_anchor_evidence_intent_key(evidence_hash: &str) -> String {
    sha256_hex(format!("{EFFECT_ANCHOR_EVIDENCE_DOMAIN}\0{evidence_hash}").as_bytes())
}

/// Stable commitment fenced under one anchored evidence leaf.
///
/// The enforcement envelope and its content-addressed identifier change when
/// an expired observer snapshot is refreshed. The seller-impair intent does
/// not: it already commits the liability, chain, vault contract, and sealed
/// allocation. Binding the leaf to that stable intent lets a crash after the
/// anchor fence resume with a fresh snapshot while a different impairment
/// still collides and rejects.
#[must_use]
pub(super) fn anchor_evidence_intent_commitment(
    liability_key: &str,
    seller_impair_intent_id: &str,
    penalty_envelope_sha256: &str,
    merkle_root: &str,
) -> String {
    sha256_hex(
        format!(
            "{EFFECT_ANCHOR_EVIDENCE_DOMAIN}\0{liability_key}\0{seller_impair_intent_id}\0{penalty_envelope_sha256}\0{merkle_root}"
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
    #[error("published filing artifact resolver is unavailable: {0}")]
    FilingResolver(String),
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
    #[error("challenge backing does not resolve to a retained venue admission")]
    UnknownAdmission,
    #[error("retained verifier profile has no authenticated governance policy")]
    UnknownProfileGovernancePolicy,
    #[error("retained governance case has no authenticated governance policy")]
    UnknownGovernanceCasePolicy,
    #[error("retained trust activation has no authenticated governance policy")]
    UnknownGovernanceActivationPolicy,
    #[error("retained prior penalty has no authenticated penalty-authority policy")]
    UnknownPenaltyAuthorityPolicy,
    #[error("retained challenge outcome has no authenticated evaluator policy")]
    UnknownEvaluatorPolicy,
    #[error("penalty-authority policy could not be retained: {0}")]
    PenaltyPolicyRetention(String),
    #[error("evaluator policy could not be retained: {0}")]
    EvaluatorPolicyRetention(String),
    #[error("retained venue-audit challenge has no authenticated audit policy")]
    UnknownAuditAuthorityPolicy,
    #[error("retained audit epoch has no authenticated randomness-witness policy")]
    UnknownAuditRandomnessWitnessPolicy,
    #[error("retained audit authorization has no authenticated governance policy")]
    UnknownAuditGovernancePolicy,
    #[error("resolved venue admission rejected: {0}")]
    AdmissionEnvelope(String),
    #[error("resolved venue admission does not bind the challenge: {0}")]
    AdmissionBinding(&'static str),
    #[error("filing binds a fee schedule this venue never published")]
    UnknownFeeSchedule,
    #[error("resolved fee schedule rejected: {0}")]
    FeeScheduleArtifact(String),
    #[error("filing terms are not the ones the signed fee schedule sets: {0}")]
    DisputeTerms(&'static str),
    #[error("filing binds market terms this venue never admitted")]
    UnknownMarketTerms,
    #[error("filing terms are not the ones this venue admitted for the listing: {0}")]
    FilingTermsBinding(&'static str),
    #[error("replay recipe is not admitted by the seller-signed market terms: {0}")]
    ReplayDecisionRule(&'static str),
    #[error("filing is outside the seller-signed filing window")]
    FilingWindowClosed,
    #[error("admitted market terms do not enable venue audits for this listing")]
    AuditIneligible,
    #[error("dispute bond is outside the admitted terms' challenge bond limits")]
    DisputeBondOutsideTermsLimits,
    #[error("filing binds an audit round this venue never published")]
    UnknownAuditRound,
    #[error("signed audit epoch rejected: {0}")]
    AuditEpoch(String),
    #[error("audit round selection rejected: {0}")]
    AuditSelection(String),
    #[error("venue audit does not bind the round that drew it: {0}")]
    AuditRoundBinding(&'static str),
    #[error("evaluator key is outside the validity window its pin declares")]
    EvaluatorKeyWindow,
    #[error("evaluation declares an epoch the evaluator pin does not carry")]
    EvaluatorKeyEpoch,
    #[error("evaluator key revocation status will not support a signature: {0}")]
    EvaluatorRevocation(&'static str),
    #[error("settlement observer key is outside the lifecycle its pin declares: {0}")]
    SettlementObserverLifecycle(&'static str),
    #[error("authority role {role} is outside its authenticated lifecycle: {reason}")]
    AuthorityLifecycle {
        role: &'static str,
        reason: &'static str,
    },
    #[error("dispute fee rail dispatch failed: {0}")]
    FeeRail(String),
    #[error("dispute bond funding rail dispatch failed: {0}")]
    DisputeBondRail(String),
    #[error("semantic effect intent is not durably fenced before dispatch")]
    EffectIntentUnfenced,
    #[error("enforcement root is not confirmed: {0}")]
    EnforcementRootUnconfirmed(&'static str),
    #[error("signed challenge outcome rejected: {0}")]
    OutcomeEnvelope(String),
    #[error("only an upheld outcome may enter the penalty lane")]
    VerdictNotUpheld,
    #[error("appeal finality is not established by the durable governance state: {0}")]
    AppealNotFinal(&'static str),
    #[error("outcome does not bind this challenge")]
    OutcomeBinding,
    #[error("governance artifacts do not bind this liability: {0}")]
    GovernanceBinding(&'static str),
    #[error("collateral facts do not name the allocation this liability is charged to")]
    CollateralAllocation,
    #[error("authenticated collateral snapshot rejected: {0}")]
    CollateralSnapshot(&'static str),
    #[error("signed market terms rejected: {0}")]
    TermsEnvelope(String),
    #[error("market terms do not bind this liability: {0}")]
    TermsBinding(&'static str),
    #[error("the claim window this liability owes has not closed")]
    ClaimWindowOpen,
    #[error("claim candidates do not exactly match the authoritative settled purchase set")]
    ClaimSetMismatch,
    #[error("purchase record {0} is not resolvable in the authoritative index")]
    UnknownPurchaseRecord(String),
    #[error("purchase standing rejected: {0}")]
    PurchaseStanding(String),
    #[error("purchase record {0} does not belong to this liability at the frozen cutoff")]
    PurchaseOutsideCutoff(String),
    #[error("purchase record {0} charged its exposure to a different collateral allocation")]
    PurchaseOutsideAllocation(String),
    #[error("purchase record {0} names a payout destination that was never admitted")]
    UnadmittedPayoutDestination(String),
    #[error("purchase record {0} attests a realized spend the bond currency does not carry")]
    PurchaseCurrencyMismatch(String),
    #[error("checked slash arithmetic refused the distribution: {0}")]
    SlashArithmetic(String),
    #[error("sealed claim accounting does not match the recomputed distribution")]
    SealedClaimMismatch,
    #[error("authoritative collateral does not match the evaluator-signed penalty calculation")]
    PenaltyCalculationMismatch,
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
    #[error("bond observation no longer qualifies at the chain head: {0}")]
    BondObservation(String),
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingAuditRound {
    pub epoch: SignedFindingAuditEpoch,
    /// Governance-root-signed authorization for every epoch field other
    /// than the authorization digest and content-addressed epoch id.
    pub authorization: SignedFindingAuditRoundAuthorization,
    pub revealed_seed: String,
    pub eligible: Vec<EligibleListing>,
}

pub(crate) struct ResolvedFindingAuditSelection {
    round: FindingAuditRound,
    audit_authority: PublicKey,
    randomness_witness: PublicKey,
    governance_authority: PublicKey,
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
    fn fee_schedule(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedOpenMarketFeeSchedule>, String>;

    /// The audit round published under this epoch envelope digest, or
    /// `None` when the venue published no such round.
    fn audit_round(&self, epoch_envelope_sha256: &str)
        -> Result<Option<FindingAuditRound>, String>;

    /// The retained activated admission for one challenged backing. This
    /// includes a superseded admission because a challenge adjudicates the
    /// backing that governed the sale, not whichever admission is current.
    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String>;

    /// The retained admission envelope named by a historical purchase
    /// record. Purchase-authority rotation is resolved from this exact
    /// venue-signed snapshot rather than from the deployment's current key.
    fn admission_by_envelope_sha256(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String>;

    /// The venue authority lifecycle policy that authenticated this exact
    /// retained admission envelope. Key rotation must not strand an
    /// admission that governed a historical purchase or challenged backing.
    fn venue_policy_for_admission(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The governance policy that authenticated this exact retained
    /// verifier profile. A profile remains usable across governance-key
    /// rotation only when the venue retained the policy that signed it.
    fn governance_policy_for_profile(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The retained governance policy that authenticated this exact signed
    /// case envelope. A sanction remains enforceable across governance-key
    /// rotation only when the venue retained the policy that admitted it.
    fn governance_policy_for_case(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The retained governance policy that authenticated this exact trust
    /// activation. Activation and appeal cases can legitimately span a
    /// governance-key rotation.
    fn governance_policy_for_activation(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The retained penalty-authority policy that authenticated this exact
    /// signed penalty envelope.
    fn penalty_policy_for_penalty(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// Retain the trusted policy used to mint an exact penalty so a later
    /// appeal can authenticate it after authority rotation.
    fn retain_penalty_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String>;

    /// The evaluator policy retained when this exact signed outcome was
    /// minted. Outcome-authored role fields never select their own trust.
    fn evaluator_policy_for_outcome(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// Retain the configured evaluator policy before the exact signed
    /// outcome becomes reachable from the durable verdict record.
    fn retain_evaluator_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String>;

    /// The retained audit-authority policy that authenticated this exact
    /// audit epoch. Reusing a signer key for a renewed lifecycle policy must
    /// not replace the policy of an in-flight historical round.
    fn audit_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The retained randomness-witness policy that authenticated this exact
    /// audit epoch. An in-flight round remains verifiable across witness-key
    /// rotation only when the venue retained the policy bound to the epoch.
    fn randomness_witness_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The retained governance policy that authenticated this exact audit
    /// authorization. The authorization digest, rather than a caller-named
    /// key, selects the historical policy.
    fn governance_policy_for_audit_authorization(
        &self,
        authorization_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String>;

    /// The seller-signed market terms this venue admitted under this
    /// envelope digest, or `None` when the venue admitted no such terms.
    fn market_terms(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingMarketTerms>, String>;
}

/// The pinned public roles this coordinator verifies against. None of
/// them is ever read out of an artifact.
struct ChallengeRolePins {
    audit_authority: FindingAuthorityPin,
    audit_randomness_witness: FindingAuthorityPin,
    authority_status: FindingAuthorityPin,
    settlement_observer: FindingAuthorityPin,
    anchor_publisher: FindingAuthorityPin,
    settlement_finality_requirement: FindingFinalityRequirement,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiredFeeOnlyRecovery {
    Unchanged,
    Compensated,
    FundingConfirmed { received_at: u64 },
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

/// The authenticated collateral inputs one checked penalty calculation uses.
/// The coordinator verifies the snapshot against its settlement-observer pin
/// before deriving the live balance.
#[derive(Debug, Clone)]
pub struct FindingCollateralFacts<'a> {
    /// Seller precommitment from the admitted market terms.
    pub base_finding_stake: &'a MonetaryAmount,
    /// Settlement-observer-signed live collateral reading. The allocation,
    /// currency, and live amount are all derived from this envelope.
    pub bond_snapshot: SignedFindingFinalizedBondSnapshot,
}

/// Trusted resolver for a pin's externally published revocation source.
/// The returned envelope is still verified by the coordinator against the
/// independent status-authority pin and exact role fields.
pub trait FindingAuthorityStatusResolver: Send + Sync {
    fn resolve(
        &self,
        pin: &FindingAuthorityPin,
        now: u64,
    ) -> Result<SignedFindingAuthorityStatus, String>;

    /// Independently attest that the exact signed checkpoint statement was
    /// durably visible at the resolver's trusted observation time.
    fn checkpoint_publication(
        &self,
        proof: &AnchorInclusionProof,
        now: u64,
    ) -> Result<SignedFindingAnchorCheckpointPublication, String>;
}

/// One adjudication request: the challenge, the artifacts it binds, and
/// the resolved evidence its class selects.
pub struct ChallengeEvaluationRequest<'a> {
    pub challenge: &'a SignedFindingChallenge,
    /// The EXACT canonical bytes of the signed finding artifact.
    pub raw_finding: &'a str,
    pub profile: &'a SignedFindingChallengeVerifierProfile,
    pub evidence: &'a FindingChallengeClassEvidence<'a>,
    pub collateral: &'a FindingCollateralFacts<'a>,
    /// The epoch the caller believes the evaluator key is in. It is
    /// checked against the pin rather than carried into the outcome.
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
/// fee schedule against the exact retained venue admission that accepted
/// it, so later operator rotation does not invalidate a historical sale.
pub struct FindingPenaltyGovernance<'a> {
    pub local_operator_id: &'a str,
    pub subject_operator_id: &'a str,
    pub issued_by: &'a str,
    pub fee_schedule: &'a SignedOpenMarketFeeSchedule,
    /// Exact venue-signed admission that accepted this schedule for the
    /// historical listing. This survives fee-operator rotation.
    pub admission: &'a SignedFindingAdmission,
    pub charter: &'a chio_open_market::governance::generic::SignedGenericGovernanceCharter,
    pub listing: &'a SignedGenericListing,
    pub activation: Option<&'a SignedGenericTrustActivation>,
    pub current_publisher: &'a GenericRegistryPublisher,
    pub penalty_expires_at: Option<u64>,
}

/// One minted and cleanly evaluated finding penalty.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// No filing by the venue's appeal deadline, or a terminal denied
    /// appeal. Neither creates an appeal case head, so the original
    /// sanction still governs.
    ///
    /// Naming this variant asserts nothing. The coordinator proves
    /// finality against the durable case index and the clock: the
    /// sanction must still be the single live case on the liability, the
    /// deadline must respect [`MIN_APPEAL_WINDOW_SECS`] measured from the
    /// instant that sanction was indexed, and the venue clock must be
    /// past it.
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

/// Canonical payload retained atomically with the finalizing transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetainedAuthorizedImpairment {
    enforcement: SignedFindingChallengeEnforcement,
    slash: FindingPenaltyOutcome,
    finalization_policy: FindingAuthorityPin,
    settlement_observer_policy: FindingAuthorityPin,
    sanction_case_id: String,
    held_penalty_id: String,
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
    /// The impairment is confirmed, but the exact retraction is not yet in a
    /// signed status epoch (or another required effect is still unfinished).
    AwaitingStatusPublication,
}

/// Clock sampled while the status outbox write transaction is held.
///
/// The caller's earlier venue timestamp is supplied only so deterministic
/// test clocks can model the same instant. Production clocks independently
/// sample wall time at the durable transition.
pub trait FindingStatusCommitClock: Send + Sync {
    fn now_unix_secs(&self, venue_now: u64) -> u64;
}

struct SystemFindingStatusCommitClock;

impl FindingStatusCommitClock for SystemFindingStatusCommitClock {
    fn now_unix_secs(&self, _venue_now: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// The authoritative single-operator challenge coordinator.
pub struct FindingChallengeCoordinator {
    challenges: SqliteFindingChallengeStore,
    purchases: SqliteFindingPurchaseStore,
    market_config: FindingMarketConfig,
    status: SqliteFindingStatusStore,
    pins: ChallengeRolePins,
    evaluator_authority: Arc<dyn SigningBackend>,
    /// The evaluator role's full lifecycle pin. Like every other
    /// value-bearing role, its key, epoch, window, and authenticated
    /// revocation source all have to hold when it acts.
    evaluator_pin: FindingAuthorityPin,
    finalization_authority: Arc<dyn SigningBackend>,
    finalization_pin: FindingAuthorityPin,
    penalty_authority: Arc<dyn SigningBackend>,
    penalty_pin: FindingAuthorityPin,
    authority_status: Arc<dyn FindingAuthorityStatusResolver>,
    rail: Arc<dyn FindingRailObserver>,
    /// Resolves the signed artifacts a filing binds by digest.
    filings: Arc<dyn FindingFilingResolver>,
    venue_id: String,
    status_feed_operator_ref: String,
    status_feed_operator: FindingStatusOperatorPin,
    status_feed_service_bond: FindingStatusServiceBond,
    status_commit_clock: Arc<dyn FindingStatusCommitClock>,
    /// Disposition a rejected challenge's bond takes, predeclared by the
    /// admitted market terms rather than chosen per case.
    failed_challenge_disposition: FindingDisputeLockDisposition,
}

impl FindingChallengeCoordinator {
    /// Build with custody-backed signers and an injected commit clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_signing_backends_and_status_commit_clock(
        challenges: SqliteFindingChallengeStore,
        purchases: SqliteFindingPurchaseStore,
        status: SqliteFindingStatusStore,
        config: &FindingMarketConfig,
        evaluator_authority: Arc<dyn SigningBackend>,
        finalization_authority: Arc<dyn SigningBackend>,
        penalty_authority: Arc<dyn SigningBackend>,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
        status_commit_clock: Arc<dyn FindingStatusCommitClock>,
    ) -> Result<Self, ChallengeCoordinatorError> {
        config
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Configuration(error.to_string()))?;
        if challenges.mutation_fence() != purchases.mutation_fence()
            || challenges.mutation_fence() != status.mutation_fence()
        {
            return Err(ChallengeCoordinatorError::Configuration(
                "challenge, purchase, and status stores do not share one serving authority"
                    .to_string(),
            ));
        }
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
            market_config: config.clone(),
            status,
            pins: ChallengeRolePins {
                audit_authority: config.audit_authority.clone(),
                audit_randomness_witness: config.audit_randomness_witness.clone(),
                authority_status: config.authority_status.clone(),
                settlement_observer: config.settlement_observer.clone(),
                anchor_publisher: config.anchor_publisher.clone(),
                settlement_finality_requirement: config.settlement_finality_requirement,
            },
            evaluator_authority,
            evaluator_pin: config.challenge_evaluator.clone(),
            finalization_authority,
            finalization_pin: config.venue_finalization.clone(),
            penalty_authority,
            penalty_pin: config.market_penalty.clone(),
            authority_status,
            rail,
            filings,
            venue_id: config.venue_id.clone(),
            status_feed_operator_ref: config.status_feed_operator_ref.clone(),
            status_feed_operator: config.status_feed_operator.clone(),
            status_feed_service_bond: config.status_feed_service_bond.clone(),
            status_commit_clock,
            failed_challenge_disposition,
        })
    }
}

include!("finding_challenge_coordinator/submission.rs");
include!("finding_challenge_coordinator/evaluation.rs");
include!("finding_challenge_coordinator/uphold_appeal.rs");
include!("finding_challenge_coordinator/finalization.rs");

include!("finding_challenge_coordinator/status_settlement.rs");
include!("finding_challenge_coordinator/artifact_resolution.rs");
include!("finding_challenge_coordinator/read_api.rs");
include!("finding_challenge_coordinator/constructors.rs");
include!("finding_challenge_coordinator/admission_filing.rs");
include!("finding_challenge_coordinator/governance_pins.rs");
include!("finding_challenge_coordinator/enforcement_checks.rs");
include!("finding_challenge_coordinator/dispute_funds.rs");
include!("finding_challenge_coordinator/claim_sealing.rs");
include!("finding_challenge_coordinator/enforcement_settlement.rs");

/// Bind a replay recipe's decision rule to the exact seller-signed terms
/// resolved from durable venue state. Recipe semantics remain the pure
/// evaluator's responsibility; this is the missing economic-policy edge.
pub(crate) fn require_admitted_replay_decision_rule(
    terms: &SignedFindingMarketTerms,
    evidence: &FindingChallengeEvidence,
) -> Result<(), ChallengeCoordinatorError> {
    let FindingChallengeEvidence::ReplayContradiction {
        recipe_preimage, ..
    } = evidence
    else {
        return Ok(());
    };
    let strict = canonical_json_bytes_from_str(recipe_preimage)
        .map_err(|_| ChallengeCoordinatorError::ReplayDecisionRule("recipe is not canonical"))?;
    let recipe: FindingReplayRecipeInput = serde_json::from_slice(&strict)
        .map_err(|_| ChallengeCoordinatorError::ReplayDecisionRule("recipe is not typed"))?;
    recipe
        .validate()
        .map_err(|_| ChallengeCoordinatorError::ReplayDecisionRule("recipe is invalid"))?;
    if canonical_json_bytes(&recipe).map_err(|_| ChallengeCoordinatorError::Canonical)? != strict {
        return Err(ChallengeCoordinatorError::ReplayDecisionRule(
            "recipe projection is not exact",
        ));
    }
    if !terms
        .body
        .decision_rule_refs
        .contains(&recipe.decision_rule_ref)
    {
        return Err(ChallengeCoordinatorError::ReplayDecisionRule(
            "decision_rule_ref",
        ));
    }
    Ok(())
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

/// Convert the durable control-plane authority assignment into the settlement
/// choke point's independent policy input. Parsing still fails closed even
/// though the enclosing market configuration was validated at startup.
fn settlement_penalty_authority_policy(
    pin: &FindingAuthorityPin,
) -> Result<FindingPenaltyAuthorityPolicy, ChallengeCoordinatorError> {
    Ok(FindingPenaltyAuthorityPolicy {
        authority_id: pin.authority_id.clone(),
        key: pin
            .key()
            .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("penalty"))?,
        key_epoch: pin.key_epoch,
        valid_from: pin.valid_from,
        valid_until: pin.valid_until,
        revocation_status_ref: pin.revocation_status_ref.clone(),
    })
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

pub(super) fn rail_observation_matches(
    instruction: &FindingRailInstruction,
    instruction_digest: &str,
    observation: &FindingRailObservation,
) -> bool {
    observation.instruction_sha256 == instruction_digest
        && observation.amount_units == instruction.amount_units
        && observation.currency == instruction.currency
        && observation.rail_destination == instruction.rail_destination
        && !observation.rail.trim().is_empty()
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

fn enforcement_effect_intent_keys(
    enforcement: &SignedFindingChallengeEnforcement,
) -> Vec<(FindingEffectIntentKind, String)> {
    enforcement
        .body
        .effect_intents
        .iter()
        .map(|binding| {
            let kind = match binding.kind {
                chio_finding::FindingEffectIntentKind::SellerImpair => {
                    FindingEffectIntentKind::SellerImpair
                }
                chio_finding::FindingEffectIntentKind::ChallengeBond => {
                    FindingEffectIntentKind::ChallengeBond
                }
                chio_finding::FindingEffectIntentKind::Fee => FindingEffectIntentKind::Fee,
                chio_finding::FindingEffectIntentKind::RootIntent => {
                    FindingEffectIntentKind::RootIntent
                }
                chio_finding::FindingEffectIntentKind::Retraction => {
                    FindingEffectIntentKind::Retraction
                }
            };
            (kind, binding.intent_id.clone())
        })
        .collect()
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
