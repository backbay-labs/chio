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
//! Compiled only under the `cognition-market-experimental` feature.

use std::sync::Arc;

use chio_core::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    audit_epoch_precommitment_sha256, compute_enforcement_id, derive_outcome_id,
    ensure_challenge_class_compatibility, signed_envelope_sha256, verify_finding,
    verify_pinned_envelope, verify_signed_admission, verify_signed_audit_epoch,
    verify_signed_audit_round_authorization, verify_signed_challenge,
    verify_signed_challenge_outcome, verify_signed_market_terms, verify_signed_purchase_record,
    Finding, FindingChallenge, FindingChallengeAuthorization, FindingChallengeEnforcement,
    FindingChallengeEvidenceKind, FindingChallengeOutcome, FindingEffectIntentBinding,
    FindingEnforcementDestination, FindingPenaltyCalculation, FindingPurchaseRecord,
    SignedFindingAdmission, SignedFindingAuditEpoch, SignedFindingAuditRoundAuthorization,
    SignedFindingChallenge, SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome,
    SignedFindingChallengeVerifierProfile, SignedFindingFinalizedBondSnapshot,
    SignedFindingMarketTerms, SignedFindingPurchaseRecord, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1,
};
pub use chio_finding::{
    FindingAuthorityStatus, SignedFindingAuthorityStatus, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeEvaluation,
    FindingChallengeEvaluationInput,
};
use chio_kernel::admission_operation::StoreMutationFence;
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
    dispatch_finding_impairment, plan_finding_impairment, recheck_finding_bond_observation,
    reobserve_finding_impairment, verify_finding_collateral_snapshot, verify_finding_enforcement,
    verify_finding_enforcement_for_reconciliation, EvmBondSnapshot, FindingBondObservationSource,
    FindingEnforcementPins, FindingFinalityRequirement, FindingImpairmentOutcome,
    FindingImpairmentPublisher, FindingImpairmentQuarantine, PlannedFindingImpairment,
    SettlementChainConfig, VerifiedFindingEnforcement,
};
use chio_store_sqlite::{
    derive_dispute_bond_funding_intent_key, derive_dispute_bond_return_intent_key,
    dispute_bond_funding_intent_digest, dispute_bond_return_intent_digest,
    FindingChallengeAuthorizationBranch, FindingChallengeEvaluationStart,
    FindingChallengeEvidenceClass, FindingChallengeState, FindingChallengeSubmission,
    FindingChallengeVerdict as StoreVerdict, FindingChallengeWriteOutcome,
    FindingClaimSnapshotInput, FindingDisputeLockDisposition, FindingDisputeLockInput,
    FindingDisputeLockRecord, FindingDisputeLockState, FindingEffectIntentKind,
    FindingEffectIntentState, FindingFinalizingAuthorizationInput, FindingGovernanceCaseInput,
    FindingGovernanceCaseKind, FindingLiabilityInput, FindingLiabilityRecord,
    FindingLiabilityState, SqliteFindingChallengeStore, SqliteFindingPurchaseStore,
};
use serde::{Deserialize, Serialize};

use super::finding_handlers::{
    FindingRailInstruction, FindingRailObservation, FindingRailObserver,
};
use super::service_types::{FindingAuthorityPin, FindingMarketConfig};

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

/// Domain separator for the anchored evidence leaf an impairment burns.
const EFFECT_ANCHOR_EVIDENCE_DOMAIN: &str = "chio.finding.effect.anchor-evidence.v1";

/// Domain separator for the deterministic dispute-fee operation id.
const DISPUTE_FEE_OPERATION_DOMAIN: &str = "chio.finding.dispute-fee-operation.v1";

/// Domain separator for returning a collected fee when its bond never funds.
const DISPUTE_FEE_RETURN_OPERATION_DOMAIN: &str = "chio.finding.dispute-fee-return-operation.v1";

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

fn dispute_fee_intent_key(challenge_id: &str) -> String {
    let operation_id =
        sha256_hex(format!("{DISPUTE_FEE_OPERATION_DOMAIN}\0{challenge_id}").as_bytes());
    derive_fee_intent_key(challenge_id, &operation_id)
}

fn dispute_fee_return_intent_key(challenge_id: &str) -> String {
    let operation_id =
        sha256_hex(format!("{DISPUTE_FEE_RETURN_OPERATION_DOMAIN}\0{challenge_id}").as_bytes());
    derive_fee_intent_key(challenge_id, &operation_id)
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
    #[error("retained venue-audit challenge has no authenticated audit policy")]
    UnknownAuditAuthorityPolicy,
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
#[derive(Debug, Clone)]
pub struct FindingAuditRound {
    pub epoch: SignedFindingAuditEpoch,
    /// Governance-root-signed authorization for every epoch field other
    /// than the authorization digest and content-addressed epoch id.
    pub authorization: SignedFindingAuditRoundAuthorization,
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

    /// The retained activated admission for one challenged backing. This
    /// includes a superseded admission because a challenge adjudicates the
    /// backing that governed the sale, not whichever admission is current.
    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Option<SignedFindingAdmission>;

    /// The retained admission envelope named by a historical purchase
    /// record. Purchase-authority rotation is resolved from this exact
    /// venue-signed snapshot rather than from the deployment's current key.
    fn admission_by_envelope_sha256(&self, envelope_sha256: &str)
        -> Option<SignedFindingAdmission>;

    /// The venue authority lifecycle policy that authenticated this exact
    /// retained admission envelope. Key rotation must not strand an
    /// admission that governed a historical purchase or challenged backing.
    fn venue_policy_for_admission(&self, envelope_sha256: &str) -> Option<FindingAuthorityPin>;

    /// The governance policy that authenticated this exact retained
    /// verifier profile. A profile remains usable across governance-key
    /// rotation only when the venue retained the policy that signed it.
    fn governance_policy_for_profile(&self, envelope_sha256: &str) -> Option<FindingAuthorityPin>;

    /// A governance-published historical audit-authority policy, resolved
    /// independently of the challenge envelope that names its signer.
    fn audit_policy_for_key(&self, key: &PublicKey) -> Option<FindingAuthorityPin>;

    /// The seller-signed market terms this venue admitted under this
    /// envelope digest, or `None` when the venue admitted no such terms.
    fn market_terms(&self, envelope_sha256: &str) -> Option<SignedFindingMarketTerms>;
}

/// The pinned public roles this coordinator verifies against. None of
/// them is ever read out of an artifact.
struct ChallengeRolePins {
    audit_authority: FindingAuthorityPin,
    audit_randomness_witness: FindingAuthorityPin,
    governance_authority: FindingAuthorityPin,
    authority_status: FindingAuthorityPin,
    settlement_observer: FindingAuthorityPin,
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
    /// The seller impairment is confirmed, but another effect bound by
    /// the signed enforcement is still pending. Publication remains open.
    AwaitingEffects,
}

/// The authoritative single-operator challenge coordinator.
pub struct FindingChallengeCoordinator {
    challenges: SqliteFindingChallengeStore,
    purchases: SqliteFindingPurchaseStore,
    market_config: FindingMarketConfig,
    pins: ChallengeRolePins,
    evaluator_authority: Keypair,
    /// The evaluator role's full lifecycle pin. Like every other
    /// value-bearing role, its key, epoch, window, and authenticated
    /// revocation source all have to hold when it acts.
    evaluator_pin: FindingAuthorityPin,
    finalization_authority: Keypair,
    finalization_pin: FindingAuthorityPin,
    penalty_authority: Keypair,
    penalty_pin: FindingAuthorityPin,
    authority_status: Arc<dyn FindingAuthorityStatusResolver>,
    rail: Arc<dyn FindingRailObserver>,
    /// Resolves the signed artifacts a filing binds by digest.
    filings: Arc<dyn FindingFilingResolver>,
    venue_id: String,
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
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<Self, ChallengeCoordinatorError> {
        config
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Configuration(error.to_string()))?;
        if challenges.mutation_fence() != purchases.mutation_fence() {
            return Err(ChallengeCoordinatorError::Configuration(
                "challenge and purchase stores do not share one serving authority".to_string(),
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
            pins: ChallengeRolePins {
                audit_authority: config.audit_authority.clone(),
                audit_randomness_witness: config.audit_randomness_witness.clone(),
                governance_authority: config.governance_root.clone(),
                authority_status: config.authority_status.clone(),
                settlement_observer: config.settlement_observer.clone(),
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
            failed_challenge_disposition,
        })
    }

    /// Serving identity shared by the coordinator's durable stores.
    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.challenges.mutation_fence()
    }

    /// Exact validated market configuration this coordinator enforces.
    #[must_use]
    pub const fn market_config(&self) -> &FindingMarketConfig {
        &self.market_config
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
        let body = &challenge.body;
        // The pinned audit authority is the only key that may file a
        // bondless audit; a buyer submission verifies against the
        // challenger it names, so neither branch can borrow the other's
        // authorization.
        let audit_authority = match &body.authorization {
            FindingChallengeAuthorization::VenueAudit(_) => {
                self.require_live_role(&self.pins.audit_authority, body.filed_at, now, "audit")?
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => self
                .pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?,
        };
        verify_signed_challenge(challenge, &audit_authority)
            .map_err(|error| ChallengeCoordinatorError::ChallengeEnvelope(error.to_string()))?;
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
        // about it becomes durable. Both branches file against the
        // seller-signed market terms the challenge binds by digest: the
        // terms carry the filing window, the audit toggle, and the bond
        // limits the seller committed the listing to.
        let terms = self.resolve_market_terms(body)?;
        let prior_filing = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if prior_filing.is_none() {
            self.require_filing_window(&terms.body, body.filed_at, now)?;
        }
        match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                self.require_bond_within_terms_limits(
                    &terms.body,
                    submission,
                    finding.guarantee_class,
                )?;
            }
            FindingChallengeAuthorization::VenueAudit(_) => {
                // A seller may sign terms that never enter the audit
                // rotation; a bondless audit against those terms has no
                // authorization to stand on, whatever round drew it.
                if !terms.body.audit_eligible {
                    return Err(ChallengeCoordinatorError::AuditIneligible);
                }
            }
        }
        // Resolve the retained admission before any durable row or money
        // effect. Its pool binding governed this sale and remains the only
        // authorized destination after venue configuration rotates. An
        // exact retained filing is provisionally checked at its original
        // receipt time so an already-funded bond remains refundable after
        // key rotation; an unfunded retry is checked again at `now` below.
        let admission_validation_at = prior_filing
            .as_ref()
            .filter(|recorded| {
                recorded.challenge_envelope_sha256 == challenge_envelope_sha256
                    && recorded.finding_id == body.finding_id
                    && recorded.listing_id == body.listing_id
            })
            .map_or(now, |recorded| recorded.submitted_at);
        let admission = self.resolve_admission(body, admission_validation_at)?;
        if let FindingChallengeAuthorization::VenueAudit(audit) = &body.authorization {
            self.require_audit_selection(audit, body, &admission, now)?;
        }
        let mut recovered_received_at = match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => self
                .confirmed_funded_submission_received_at(
                    body,
                    &challenge_envelope_sha256,
                    submission,
                    &admission.body.challenge_administration_pool,
                )?,
            FindingChallengeAuthorization::VenueAudit(_) => None,
        };
        if recovered_received_at.is_none() {
            if let FindingChallengeAuthorization::BuyerSubmission(submission) = &body.authorization
            {
                match self.recover_expired_fee_only_submission(
                    body,
                    &challenge_envelope_sha256,
                    submission,
                    &terms.body,
                    &admission.body.challenge_administration_pool,
                    now,
                )? {
                    ExpiredFeeOnlyRecovery::Compensated => {
                        return Err(ChallengeCoordinatorError::DisputeBondWindow)
                    }
                    ExpiredFeeOnlyRecovery::FundingConfirmed { received_at } => {
                        recovered_received_at = Some(received_at);
                    }
                    ExpiredFeeOnlyRecovery::Unchanged => {}
                }
            }
            let exact_audit_replay = matches!(
                &body.authorization,
                FindingChallengeAuthorization::VenueAudit(_)
            ) && admission_validation_at != now;
            if recovered_received_at.is_none() && !exact_audit_replay {
                if admission_validation_at != now {
                    self.resolve_admission(body, now)?;
                }
                self.require_filing_window(&terms.body, body.filed_at, now)?;
            }
        }
        let received_at = recovered_received_at.unwrap_or(now);
        match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                self.require_dispute_terms(
                    submission,
                    &admission,
                    &admission.body.challenge_administration_pool,
                    received_at,
                )?;
            }
            FindingChallengeAuthorization::VenueAudit(_) => {}
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
        let recorded = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let pool = &admission.body.challenge_administration_pool;
        let owner_hex = recorded
            .challenger_hex
            .as_deref()
            .ok_or(ChallengeCoordinatorError::DisputeFeePayer)?;
        let lock_input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &body.challenge_id,
            owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at: recorded.submitted_at,
        };
        self.challenges
            .reserve_dispute_lock(&lock_input, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let fee_intent_key = self.charge_dispute_fee(&body.challenge_id, submission, now)?;
        self.fund_dispute_bond(
            &body.challenge_id,
            submission,
            pool,
            recorded.submitted_at,
            now,
        )?;
        self.challenges
            .lock_dispute_bond(&lock_input)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if lock.expiry <= now
            && matches!(
                recorded.state,
                FindingChallengeState::Submitted | FindingChallengeState::IndeterminateClosed
            )
        {
            if recorded.state == FindingChallengeState::Submitted {
                self.challenges
                    .close_expired_submitted_filing(&body.challenge_id, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            self.dispose_dispute_bond(&body.challenge_id, now)?;
        }
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
        self.require_funded_filing(challenge_id, now)?;
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
    /// outcome. Its durable state remains submitted, so a funded filing
    /// can still reach its ordinary expiry and bond-return path rather than
    /// becoming stranded in evaluation.
    ///
    /// The evaluator key's own lifecycle is proved before the attempt is
    /// admitted, so a key that has expired, that is revoked, or that is
    /// not in the epoch the caller declares leaves the challenge exactly
    /// where it was rather than consuming an attempt against it.
    pub fn evaluate(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<Option<ChallengeEvaluationOutcome>, ChallengeCoordinatorError> {
        if let Some(recovered) = self.recover_terminal_evaluation(request)? {
            return Ok(Some(recovered));
        }
        self.require_live_evaluator_key(request)?;
        let body = &request.challenge.body;
        let admission = self.resolve_admission(body, request.now)?;
        let purchase_authority_status = self.require_authoritative_purchase_standing(
            &admission,
            request.evidence,
            request.now,
        )?;
        self.require_failed_delivery_reservation_binding(body, request.evidence, &admission)?;
        if request.collateral.bond_snapshot.body.allocation_id
            != admission.body.backing_allocation_id
        {
            return Err(ChallengeCoordinatorError::CollateralAllocation);
        }
        let schedule =
            self.resolve_fee_schedule(&admission, &admission.body.fee_schedule_envelope_sha256)?;
        let listing_requirement = Self::listing_bond_requirement(&schedule)?;
        let terms = self.resolve_market_terms(body)?;
        Self::require_signed_base_stake(&terms, request.collateral)?;
        // Funding is still the admission ticket to evaluator work. The
        // lifecycle transition itself waits until the pure evaluator has
        // produced an adjudication, so an immutable refusal cannot strand
        // the funded filing in `evaluating`.
        self.require_funded_filing(&body.challenge_id, request.now)?;
        let audit_authority = if matches!(
            &body.authorization,
            FindingChallengeAuthorization::VenueAudit(_)
        ) {
            let historical_policy = self
                .filings
                .audit_policy_for_key(&request.challenge.signer_key)
                .ok_or(ChallengeCoordinatorError::UnknownAuditAuthorityPolicy)?;
            self.require_live_role(
                &historical_policy,
                body.filed_at,
                request.now,
                "historical audit",
            )?
        } else {
            self.pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?
        };
        let profile_envelope_sha256 = self.envelope_digest(request.profile)?;
        if profile_envelope_sha256 != admission.body.profile_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "profile_envelope_sha256",
            ));
        }
        let profile_governance_policy = self
            .filings
            .governance_policy_for_profile(&profile_envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownProfileGovernancePolicy)?;
        let governance_authority = self.require_live_role(
            &profile_governance_policy,
            request.profile.body.issued_at,
            request.now,
            "historical profile governance",
        )?;
        let authority_status_key = self
            .pins
            .authority_status
            .key()
            .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("authority status"))?;
        let input = FindingChallengeEvaluationInput {
            challenge: request.challenge,
            pinned_audit_authority: &audit_authority,
            raw_finding: request.raw_finding,
            profile: request.profile,
            governance_authority: &governance_authority,
            pinned_admission_profile_envelope_sha256: &admission.body.profile_envelope_sha256,
            pinned_purchase_authority: &admission.body.purchase_authority,
            purchase_authority_status: purchase_authority_status.as_ref(),
            pinned_authority_status_key: &authority_status_key,
            evaluated_at: request.now,
            evidence: request.evidence,
        };
        let FindingChallengeEvaluation::Adjudicated(adjudication) =
            evaluate_finding_challenge(&input)
        else {
            return Ok(None);
        };
        let (verdict, facet, reason) = adjudication.into_parts();
        if verdict == chio_finding::FindingChallengeVerdict::Upheld {
            self.require_impairable_collateral(request.collateral, request.now)?;
        }
        if self.admit_evaluation(&body.challenge_id, request.now)? != EvaluationAdmission::Admitted
        {
            return Ok(None);
        }

        let challenge_envelope_sha256 = self.envelope_digest(request.challenge)?;
        let evidence_bundle_digest = self.evidence_bundle_digest(body, request.evidence)?;
        let attempt = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .map_or(0, |record| record.retry_count);
        let penalty_calculation = match verdict {
            chio_finding::FindingChallengeVerdict::Upheld => {
                Some(self.checked_penalty_calculation(
                    request.collateral,
                    listing_requirement,
                    request.now,
                )?)
            }
            _ => None,
        };
        let retry_deadline = match verdict {
            chio_finding::FindingChallengeVerdict::Indeterminate if attempt == 0 => {
                self.derive_retry_deadline(body, &terms, request.now)?
            }
            _ => None,
        };
        let mut outcome = FindingChallengeOutcome {
            schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_owned(),
            outcome_id: String::new(),
            challenge_envelope_sha256: challenge_envelope_sha256.clone(),
            finding_id: body.finding_id.clone(),
            listing_id: body.listing_id.clone(),
            backing_allocation_id: admission.body.backing_allocation_id.clone(),
            authorization: body.authorization.kind(),
            audit_epoch_envelope_sha256: match &body.authorization {
                chio_finding::FindingChallengeAuthorization::BuyerSubmission(_) => None,
                chio_finding::FindingChallengeAuthorization::VenueAudit(audit) => {
                    Some(audit.audit_epoch_envelope_sha256.clone())
                }
            },
            evidence_kind: body.evidence.kind(),
            verifier_profile_envelope_sha256: profile_envelope_sha256.clone(),
            evidence_bundle_digest: evidence_bundle_digest.clone(),
            verdict,
            facet,
            reason: reason.code().to_owned(),
            trigger_digest: sha256_hex(
                format!(
                    "{TRIGGER_DOMAIN}\0{challenge_envelope_sha256}\0{profile_envelope_sha256}\0{artifact}\0{evidence_bundle_digest}\0{attempt}\0{retry}",
                    artifact = body.finding_artifact_sha256,
                    retry = retry_deadline.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                )
                .as_bytes(),
            ),
            penalty_calculation,
            retry_deadline,
            evaluator_authority_id: self.evaluator_pin.authority_id.clone(),
            evaluator_key: self.evaluator_authority.public_key(),
            // The epoch the outcome carries is the pinned one, which the
            // request has just been held to, so the signed artifact states
            // the deployment's epoch rather than the caller's claim.
            evaluator_key_epoch: self.evaluator_pin.key_epoch,
            evaluator_valid_from: self.evaluator_pin.valid_from,
            evaluator_valid_until: self.evaluator_pin.valid_until,
            evaluator_revocation_status_ref: self
                .evaluator_pin
                .revocation_status_ref
                .clone(),
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
        let outcome_envelope_json =
            canonical_json_bytes(&signed).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let outcome_envelope_sha256 = sha256_hex(&outcome_envelope_json);

        let state = match signed.body.penalty_calculation.as_ref() {
            Some(calculation) => self.challenges.record_upheld_verdict_with_exposure_fence(
                &body.challenge_id,
                &outcome_envelope_sha256,
                &outcome_envelope_json,
                &admission.body.backing_allocation_id,
                calculation.open_per_sale_encumbrance_units,
                request.now,
            ),
            None => self.challenges.record_verdict(
                &body.challenge_id,
                store_verdict(verdict, signed.body.retry_deadline),
                &outcome_envelope_sha256,
                &outcome_envelope_json,
                request.now,
            ),
        }
        .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let bond_disposition = self.dispose_dispute_bond(&body.challenge_id, request.now)?;
        Ok(Some(ChallengeEvaluationOutcome {
            state,
            outcome: signed,
            outcome_envelope_sha256,
            bond_disposition,
        }))
    }

    /// Recover the exact signed artifact for a terminal verdict whose
    /// response or bond disposition was interrupted after the atomic verdict
    /// commit. No re-evaluation occurs and the historical evaluator policy is
    /// authenticated before the retained bytes are returned.
    fn recover_terminal_evaluation(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<Option<ChallengeEvaluationOutcome>, ChallengeCoordinatorError> {
        let challenge_id = &request.challenge.body.challenge_id;
        let Some(challenge) = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        if !matches!(
            challenge.state,
            FindingChallengeState::Upheld
                | FindingChallengeState::Rejected
                | FindingChallengeState::IndeterminateClosed
        ) {
            return Ok(None);
        }
        let challenge_envelope_sha256 = self.envelope_digest(request.challenge)?;
        if challenge.challenge_envelope_sha256 != challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let outcome_envelope_sha256 =
            challenge
                .outcome_envelope_sha256
                .as_deref()
                .ok_or_else(|| {
                    ChallengeCoordinatorError::ChallengeStore(
                        "terminal challenge has no outcome digest".to_owned(),
                    )
                })?;
        let retained = self
            .challenges
            .get_outcome_envelope(outcome_envelope_sha256)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "terminal challenge has no retained outcome envelope".to_owned(),
                )
            })?;
        if retained.challenge_id != *challenge_id {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let outcome: SignedFindingChallengeOutcome =
            serde_json::from_slice(&retained.outcome_envelope_json)
                .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        let canonical =
            canonical_json_bytes(&outcome).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if canonical != retained.outcome_envelope_json
            || outcome.body.challenge_envelope_sha256 != challenge_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        self.require_recorded_outcome_signature(challenge_id, &outcome, request.now)?;
        let bond_disposition = self.dispose_dispute_bond(challenge_id, request.now)?;
        Ok(Some(ChallengeEvaluationOutcome {
            state: challenge.state,
            outcome,
            outcome_envelope_sha256: outcome_envelope_sha256.to_owned(),
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
        let Some(lock) = self
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
        if disposition == FindingDisputeLockDisposition::Returned {
            self.return_dispute_bond(&lock, now)?;
        }
        self.challenges
            .release_dispute_bond(challenge_id, disposition, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(Some(disposition))
    }

    /// The critical transaction, and everything that has to follow it
    /// before an appeal window can open.
    ///
    /// The terminal upheld verdict has already fenced its signed exposure
    /// and raised the sales block in one transaction. This step freezes the
    /// purchase cutoff and claim deadline while replaying that same block on
    /// the shared connection, so no slot can open above the cutoff. The
    /// claim snapshot then waits on two
    /// conditions. Every slot at or below the frozen cutoff must have
    /// reached a settled record or a denial, because a slot still in
    /// flight is a buyer who may yet belong in it. And the seller-signed
    /// claim window must have elapsed, because the snapshot is immutable:
    /// sealing it the instant adjudication lands would close the payout
    /// against every harmed buyer and omission proof still inside the
    /// window the seller signed for. Only then is the snapshot sealed, the
    /// sanction recorded, and the pending-appeal hold minted and
    /// evaluated.
    ///
    /// Returns [`ChallengeCoordinatorError::ClaimWindowOpen`] until both
    /// hold. That is a retry, not a failure: the liability stays
    /// upheld-pending-claims with sales already blocked, and a later call
    /// replays the compare-and-set as a no-op and continues. It follows
    /// that no single call can both open the window and seal the payout.
    ///
    /// Two preconditions of the hold are checked before a liability is
    /// opened: the governance artifacts must carry pinned signatures, and
    /// the collateral must still fund the evaluator-signed amount. A
    /// failure opens no liability, while the terminal fraud verdict keeps
    /// the listing's fail-closed sales block in place for reconciliation.
    #[allow(clippy::too_many_arguments)]
    pub fn uphold(
        &self,
        challenge_id: &str,
        signed_challenge: &SignedFindingChallenge,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        terms: &SignedFindingMarketTerms,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        governance: &FindingPenaltyGovernance<'_>,
        sanction_case: &SignedGenericGovernanceCase,
        now: u64,
    ) -> Result<UpheldLiability, ChallengeCoordinatorError> {
        self.require_recorded_outcome_signature(challenge_id, outcome, now)?;
        if outcome.body.verdict != chio_finding::FindingChallengeVerdict::Upheld {
            return Err(ChallengeCoordinatorError::VerdictNotUpheld);
        }
        if outcome.body.finding_id != identity.finding_id
            || outcome.body.listing_id != identity.listing_id
            || outcome.body.backing_allocation_id != identity.allocation_id
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        if signed_challenge.body.challenge_id != challenge_id {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let challenge_envelope_sha256 = self.envelope_digest(signed_challenge)?;
        // Resolve the historical signer only after the exact submitted
        // envelope has been recovered from durable state. The challenge
        // cannot self-select a retired audit key and policy.
        let recorded_challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        if challenge_envelope_sha256 != recorded_challenge.challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let audit_authority = if matches!(
            &signed_challenge.body.authorization,
            FindingChallengeAuthorization::VenueAudit(_)
        ) {
            let historical_policy = self
                .filings
                .audit_policy_for_key(&signed_challenge.signer_key)
                .ok_or(ChallengeCoordinatorError::UnknownAuditAuthorityPolicy)?;
            self.require_live_role(
                &historical_policy,
                signed_challenge.body.filed_at,
                now,
                "historical audit",
            )?
        } else {
            self.pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?
        };
        verify_signed_challenge(signed_challenge, &audit_authority)
            .map_err(|error| ChallengeCoordinatorError::ChallengeEnvelope(error.to_string()))?;
        let admission = self.resolve_admission(&signed_challenge.body, now)?;
        if admission.body.backing_allocation_id != identity.allocation_id {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "backing_allocation_id",
            ));
        }
        if outcome.body.challenge_envelope_sha256 != challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        // The outcome adjudicates exactly one challenge: the one whose
        // signed envelope digest it embeds. The durable row for the
        // challenge being upheld carries that digest, so an outcome
        // presented beside any other challenge id sanctions nothing, even
        // when both challenges target the same finding and listing.
        let presented_outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        if recorded_challenge.outcome_envelope_sha256.as_deref()
            != Some(presented_outcome_envelope_sha256.as_str())
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        // Every exposure figure behind the penalty is read against one
        // allocation, and it has to be the one this liability's vault is
        // charged to. Facts naming another allocation would size the
        // slash from a different seller's open encumbrances, so they are
        // refused here, before anything durable is written.
        if collateral.bond_snapshot.body.allocation_id != identity.allocation_id {
            return Err(ChallengeCoordinatorError::CollateralAllocation);
        }
        let snapshot = &collateral.bond_snapshot.body;
        if snapshot.chain_id != identity.chain_id
            || snapshot.vault_contract != identity.vault_contract
            || snapshot.vault_id != identity.vault_id
        {
            return Err(ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot does not name this liability's vault",
            ));
        }
        let terms_envelope_sha256 = self.envelope_digest(terms)?;
        if terms_envelope_sha256 != signed_challenge.body.terms_envelope_sha256 {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "terms_envelope_sha256",
            ));
        }
        let claim_deadline = self.require_claim_window(terms, identity, now)?;
        if terms.body.appeal_window_secs < MIN_APPEAL_WINDOW_SECS {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "appeal_window_secs",
            ));
        }
        let appeal_terms_envelope_sha256 = terms_envelope_sha256.clone();
        Self::require_signed_base_stake(terms, collateral)?;
        let signed_stake = &terms.body.backing_requirement.base_finding_stake;
        if sanction_case.body.listing_id != identity.listing_id {
            return Err(ChallengeCoordinatorError::GovernanceBinding("listing_id"));
        }
        self.require_pinned_governance(governance, sanction_case, None, now)?;
        if self.envelope_digest(governance.fee_schedule)?
            != admission.body.fee_schedule_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::GovernanceBinding(
                "fee_schedule_envelope_sha256",
            ));
        }
        let listing_requirement = Self::listing_bond_requirement(governance.fee_schedule)?;
        self.require_live_role(&self.penalty_pin, now, now, "penalty")?;
        let authoritative_claims = self
            .purchases
            .list_settled_purchase_keys_at_or_below(
                identity.listing_id,
                identity.allocation_id,
                cutoff_slot,
            )
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let mut supplied_claims = claim_candidates.to_vec();
        supplied_claims.sort();
        supplied_claims.dedup();
        if supplied_claims != authoritative_claims {
            return Err(ChallengeCoordinatorError::ClaimSetMismatch);
        }
        self.require_purchase_authority_for_candidates(identity, &authoritative_claims, now)?;
        self.require_impairable_collateral(collateral, now)?;
        let signed_calculation = outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or(ChallengeCoordinatorError::PenaltyCalculationMismatch)?;
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        if signed_calculation.base_finding_stake_units != signed_stake.units
            || signed_calculation.listing_required_amount_units != listing_requirement.units
            || signed_calculation.penalty_amount.currency != signed_stake.currency
            || listing_requirement.currency != signed_stake.currency
            || signed_calculation.penalty_amount.units > live_allocated_collateral
        {
            return Err(ChallengeCoordinatorError::PenaltyCalculationMismatch);
        }
        let defect_key = derive_defect_key(identity.finding_id);
        let liability_key = derive_liability_key(&defect_key, &self.venue_id, identity);
        let seller_hex = terms.body.seller.to_hex();
        self.challenges
            .open_liability(&FindingLiabilityInput {
                liability_key: &liability_key,
                defect_key: &defect_key,
                finding_id: identity.finding_id,
                listing_id: identity.listing_id,
                allocation_id: identity.allocation_id,
                seller_hex: &seller_hex,
                venue_id: &self.venue_id,
                chain_id: identity.chain_id,
                vault_contract: identity.vault_contract,
                vault_id: identity.vault_id,
                opened_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        self.challenges
            .uphold_liability(
                &liability_key,
                challenge_id,
                cutoff_slot,
                claim_deadline,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        // Re-enumerate after the upheld transaction raised the sales block,
        // and prove closure in the same SQLite snapshot as that enumeration.
        // A reservation settling across the earlier pure checks is therefore
        // either still open here or included in the immutable claim set.
        let authoritative_claims = self
            .purchases
            .closed_settled_purchase_keys_at_or_below(
                identity.listing_id,
                identity.allocation_id,
                cutoff_slot,
            )
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::ClaimWindowOpen)?;
        if supplied_claims != authoritative_claims {
            return Err(ChallengeCoordinatorError::ClaimSetMismatch);
        }
        self.require_purchase_authority_for_candidates(identity, &authoritative_claims, now)?;
        // The deadline the head froze when the window opened governs, not
        // the one this call just derived: a retry reads the instant harmed
        // buyers were promised rather than one measured from its own
        // clock, so no later attempt can shorten the window it resumes.
        let frozen = self
            .challenges
            .get_liability(&liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "liability head is not recorded".to_owned(),
                )
            })?;
        match frozen.claim_deadline {
            Some(deadline) if now >= deadline => {}
            _ => return Err(ChallengeCoordinatorError::ClaimWindowOpen),
        }

        let sealed = self.seal_claim_snapshot(
            &liability_key,
            identity,
            cutoff_slot,
            &authoritative_claims,
            collateral,
            &signed_calculation.penalty_amount,
            &admission.body.community_fund_destination,
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
            now,
        )?;

        self.challenges
            .begin_appeal_window(
                &liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &appeal_terms_envelope_sha256,
                terms.body.appeal_window_secs,
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
    /// Authority. Nothing about the target is taken from the caller, and
    /// neither is finality. The durable head is the only authority on
    /// which finding, listing, allocation, and vault this liability may
    /// impair, the only outcome that may authorize it is the exact
    /// envelope the store recorded for the challenge that upheld it, and
    /// the appeal window is proved closed against the durable case index
    /// rather than asserted by naming a disposition.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_appeal(
        &self,
        liability_key: &str,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        sealed: Option<&SealedClaimSnapshot>,
        governance: &FindingPenaltyGovernance<'_>,
        disposition: &AppealDisposition<'_>,
        sanction_case_id: &str,
        hold: &FindingPenaltyOutcome,
        bond_snapshot_envelope_sha256: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        let record = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        let challenge_id = record
            .upheld_challenge_id
            .as_deref()
            .ok_or(ChallengeCoordinatorError::LiabilityState("upheld"))?;
        self.require_recorded_outcome_signature(challenge_id, outcome, now)?;
        self.require_identity_matches_head(liability_key, identity, &record)?;
        self.require_outcome_upheld_this_liability(outcome, &record)?;

        match disposition {
            AppealDisposition::Unresolved { reason } => {
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
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
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
                self.require_timely_appeal(&record, appeal_case, appeal_case_id)?;
                // The reversal is minted before the case is indexed. A
                // recorded appeal stamps the sanction superseded, and the
                // index admits exactly one supersession per case, so an
                // appeal that cannot authenticate must leave no head
                // behind: otherwise a malformed filing would permanently
                // consume the supersession a legitimate appeal needs.
                // Minting moves nothing on its own; it authenticates the
                // filing and signs, which is why it can run first.
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
                    now,
                )?;
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
                if record.state == FindingLiabilityState::Finalizing {
                    return self.recover_finalizing_authorization(
                        &record,
                        outcome,
                        sanction_case_id,
                        now,
                    );
                }
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
                if record.state != FindingLiabilityState::PendingAppeal {
                    return Err(ChallengeCoordinatorError::LiabilityState("pending_appeal"));
                }
                self.require_live_role(&self.finalization_pin, now, now, "finalization")?;
                self.require_appeal_window_closed(&record, sanction_case, sanction_case_id, now)?;
                let penalty_issued_at = record
                    .appeal_deadline
                    .and_then(|deadline| deadline.checked_add(1))
                    .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                        "appeal deadline has no representable successor",
                    ))?;
                let slash = self.mint_penalty(
                    FindingPenaltyBranch::AppealFinalImpairment,
                    governance,
                    sanction_case,
                    Some(&hold.penalty),
                    &sealed.distribution.slash,
                    outcome,
                    sanction_case_id,
                    Some(&hold.evaluation.penalty_id),
                    penalty_issued_at,
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

    /// Re-sign a finalizing enforcement against a fresh, verified bond
    /// snapshot before the seller impairment has ever been dispatched.
    ///
    /// Snapshot freshness is intentionally checked at publication time,
    /// but queueing or reconciliation delay can age out the snapshot that
    /// closed the appeal. The liability and every semantic effect remain
    /// frozen; only the observer-signed snapshot digest and finalization
    /// instant change. Once the seller intent leaves `pending`, refresh is
    /// refused because an external impairment may already exist.
    pub fn refresh_finalizing_enforcement(
        &self,
        authorized: &AuthorizedImpairment,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        seller: &PublicKey,
        now: u64,
    ) -> Result<AuthorizedImpairment, ChallengeCoordinatorError> {
        let old = &authorized.enforcement;
        self.require_enforcement_signature(old, now)?;
        if self.envelope_digest(old)? != authorized.enforcement_envelope_sha256 {
            return Err(ChallengeCoordinatorError::Settlement(
                "authorized impairment digest does not match its enforcement".to_owned(),
            ));
        }
        let liability = self
            .challenges
            .get_liability(&old.body.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(ChallengeCoordinatorError::LiabilityState("finalizing"));
        }
        let durable_seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
            ChallengeCoordinatorError::ChallengeStore(
                "liability carries an invalid durable seller key".to_owned(),
            )
        })?;
        if seller != &durable_seller {
            return Err(ChallengeCoordinatorError::LiabilityIdentity("seller"));
        }
        self.require_penalty_matches_enforcement(&liability, old, &authorized.slash.penalty, now)?;
        let seller_intent_id = old
            .body
            .effect_intents
            .iter()
            .find(|binding| binding.kind == chio_finding::FindingEffectIntentKind::SellerImpair)
            .map(|binding| binding.intent_id.as_str())
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let seller_intent = self
            .challenges
            .get_effect_intent(seller_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if seller_intent.kind != FindingEffectIntentKind::SellerImpair
            || seller_intent.liability_key.as_deref() != Some(old.body.liability_key.as_str())
            || seller_intent.state != FindingEffectIntentState::Pending
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "bond snapshot refresh is permitted only before impairment dispatch".to_owned(),
            ));
        }
        self.require_retained_finalizing_authorization(
            &old.body.liability_key,
            old,
            &authorized.slash.penalty,
            true,
        )?;

        let mut body = old.body.clone();
        body.bond_snapshot_envelope_sha256 = self.envelope_digest(bond_snapshot)?;
        body.finalized_at = now;
        body.finalization_authority_id = self.finalization_pin.authority_id.clone();
        body.finalization_key = self.finalization_authority.public_key();
        body.finalization_key_epoch = self.finalization_pin.key_epoch;
        body.finalization_valid_from = self.finalization_pin.valid_from;
        body.finalization_valid_until = self.finalization_pin.valid_until;
        body.finalization_revocation_status_ref =
            self.finalization_pin.revocation_status_ref.clone();
        body.enforcement_id.clear();
        body.enforcement_id =
            compute_enforcement_id(&body).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        body.validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        self.require_live_role(&self.finalization_pin, now, now, "finalization")?;
        let refreshed = SignedFindingChallengeEnforcement::sign(body, &self.finalization_authority)
            .map_err(|_| ChallengeCoordinatorError::Signing)?;

        self.require_live_settlement_observer(bond_snapshot, now)?;
        let settlement_observer = self.require_live_role(
            &self.pins.settlement_observer,
            bond_snapshot.body.observed_at,
            now,
            "settlement observer",
        )?;
        let pins = FindingEnforcementPins {
            finalization_authority: self.finalization_authority.public_key(),
            settlement_observer,
            seller: durable_seller,
            finality_requirement: self.pins.settlement_finality_requirement,
            max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
        };
        verify_finding_enforcement(&refreshed, bond_snapshot, &pins, now)
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        Ok(AuthorizedImpairment {
            enforcement_envelope_sha256: self.envelope_digest(&refreshed)?,
            enforcement: refreshed,
            slash: authorized.slash.clone(),
            effect_intent_keys: authorized.effect_intent_keys.clone(),
        })
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
    ///
    /// Live state. A signed snapshot attests what an observer saw at one
    /// block, which is not the same as what is true now. Before dispatch,
    /// the injected observation source is read against that snapshot both
    /// before the call is prepared and before the head settles. Recovery
    /// instead re-observes the exact confirmed transaction, so an operator
    /// rotation cannot either authorize a new dispatch or strand collateral
    /// that already moved.
    ///
    /// Authorization to broadcast. The vault verifies the impairment
    /// against a published root, so both effects the instruction binds are
    /// resolved before anything leaves: the enforcement root must be
    /// confirmed for this liability and this penalty, and the anchored
    /// evidence leaf is fenced under its own key so one proof can
    /// authorize one impairment and no more.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        seller: &PublicKey,
        settlement_config: &SettlementChainConfig,
        operator_address: &str,
        vault_snapshot: &EvmBondSnapshot,
        anchor_proof: &AnchorInclusionProof,
        observations: &dyn FindingBondObservationSource,
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
        let durable_seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
            ChallengeCoordinatorError::ChallengeStore(
                "liability carries an invalid durable seller key".to_owned(),
            )
        })?;
        if seller != &durable_seller {
            return Err(ChallengeCoordinatorError::LiabilityIdentity("seller"));
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
        let finalization_authority = self.require_enforcement_signature(enforcement, now)?;
        self.require_penalty_matches_enforcement(&liability, enforcement, penalty, now)?;
        let seller_intent_id = enforcement
            .body
            .effect_intents
            .iter()
            .find(|binding| binding.kind == chio_finding::FindingEffectIntentKind::SellerImpair)
            .map(|binding| binding.intent_id.as_str())
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let seller_intent = self
            .challenges
            .get_effect_intent(seller_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if seller_intent.kind != FindingEffectIntentKind::SellerImpair
            || seller_intent.liability_key.as_deref() != Some(liability_key)
            || !seller_intent.settlement_required
        {
            return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
        }
        self.require_retained_finalizing_authorization(
            liability_key,
            enforcement,
            penalty,
            matches!(
                seller_intent.state,
                FindingEffectIntentState::Pending
                    | FindingEffectIntentState::Failed
                    | FindingEffectIntentState::Confirmed
            ),
        )?;
        let seller_was_confirmed = seller_intent.state == FindingEffectIntentState::Confirmed;
        let settlement_observer = if seller_was_confirmed {
            // The finalization authority content-bound this exact signed
            // snapshot before dispatch. Recovery authenticates that frozen
            // history under its original observer even after the configured
            // operator rotates; the confirmed transaction itself is
            // independently re-observed below.
            bond_snapshot.signer_key.clone()
        } else {
            self.require_live_settlement_observer(bond_snapshot, now)?;
            self.require_live_role(
                &self.pins.settlement_observer,
                bond_snapshot.body.observed_at,
                now,
                "settlement observer",
            )?
        };
        let pins = FindingEnforcementPins {
            finalization_authority,
            settlement_observer,
            seller: durable_seller,
            finality_requirement: self.pins.settlement_finality_requirement,
            max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
        };
        let verified = if seller_was_confirmed {
            // Recovery authenticates the frozen observation but does not
            // require it to remain publication-fresh. The transaction and
            // its canonical receipt are independently re-observed below.
            verify_finding_enforcement_for_reconciliation(enforcement, bond_snapshot, &pins, now)
        } else {
            verify_finding_enforcement(enforcement, bond_snapshot, &pins, now)
        }
        .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        if !seller_was_confirmed {
            // Before dispatch, the snapshot's signature proves who observed
            // the collateral, not that what they observed is still true. A
            // reorg or operator rotation leaves the authorized amount
            // unknown, so the chain is re-read before preparing the call.
            self.require_qualified_observation(&verified, observations)?;
        }
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
            self.require_confirmed_enforcement_root(liability_key, &verified, planned.intent())?;
            // The impairment already landed and was proved to be this
            // intent. Dispatching again would ask the vault to move the
            // same collateral twice. Re-read the stored transaction before
            // settlement so a later reorg or loss of finality cannot inherit
            // an earlier confirmation as current chain truth.
            if let Err(error) = self.require_reobserved_impairment(&planned, publisher, None) {
                self.challenges
                    .set_liability_quarantine(liability_key, true, now)
                    .map_err(|store| {
                        ChallengeCoordinatorError::ChallengeStore(store.to_string())
                    })?;
                return Err(error);
            }
            return self.finish_confirmed_impairment(
                liability_key,
                enforcement,
                bond_snapshot,
                now,
            );
        }
        self.require_sanction_governs(liability_key, &penalty.body.case_id)?;
        self.bind_enforcement_root(liability_key, &verified, planned.intent(), now)?;
        self.require_confirmed_enforcement_root(liability_key, &verified, planned.intent())?;
        self.fence_anchor_evidence(liability_key, &verified, planned.intent(), now)?;
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let outcome = match dispatch_finding_impairment(&planned, publisher) {
            Ok(outcome) => outcome,
            Err(error) => {
                // A publisher that cannot say what happened leaves the
                // intent dispatchable, and it returns to `failed` to say
                // so. Leaving it in `dispatched` would be the same
                // resumable state, but the next attempt would reconcile
                // as an identical retry and count nothing, so every
                // attempt after the first would vanish from the record an
                // operator reads a stuck impairment out of.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|store| {
                        ChallengeCoordinatorError::ChallengeStore(store.to_string())
                    })?;
                return Err(ChallengeCoordinatorError::Publisher(error.to_string()));
            }
        };

        match &outcome {
            FindingImpairmentOutcome::Confirmed { tx_hash } => {
                // Settling is the separate question. The head closes only
                // if the observation the amount was computed against is
                // still the canonical one at the receipt's finality; a
                // reorg or a rotation across the broadcast means an
                // operator has to reconcile what actually moved, and a
                // settled head would have closed the last edge to do it
                // from. Confirmation and quarantine are one store
                // transaction on that failure path, so no concurrent
                // finalizer can observe the confirmation without its
                // fail-closed head state.
                if let Err(error) =
                    self.require_reobserved_impairment(&planned, publisher, Some(tx_hash.as_str()))
                {
                    // The publisher is idempotent by intent, so a failed
                    // recheck returns this intent to the recoverable lane
                    // without authorizing another semantic impairment.
                    self.challenges
                        .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                        .map_err(|store| {
                            ChallengeCoordinatorError::ChallengeStore(store.to_string())
                        })?;
                    self.challenges
                        .set_liability_quarantine(liability_key, true, now)
                        .map_err(|store| {
                            ChallengeCoordinatorError::ChallengeStore(store.to_string())
                        })?;
                    return Err(error);
                }
                if let Err(error) = self.require_qualified_observation(&verified, observations) {
                    self.challenges
                        .confirm_seller_impairment_and_quarantine(&intent_key, liability_key, now)
                        .map_err(|store| {
                            ChallengeCoordinatorError::ChallengeStore(store.to_string())
                        })?;
                    return Err(error);
                }
                // A finalized transaction was proved to be this exact
                // intent, so the intent is confirmed: leaving it
                // dispatchable would invite a second impairment of the
                // same collateral.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                self.settle_if_enforcement_effects_confirmed(liability_key, enforcement, now)?;
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
        let strict = canonical_json_bytes_from_str(raw_finding).map_err(|_| {
            ChallengeCoordinatorError::FindingArtifact(
                "raw finding is not strict canonical I-JSON".to_owned(),
            )
        })?;
        if strict.as_slice() != raw_finding.as_bytes() {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding bytes are not the canonical serialization".to_owned(),
            ));
        }
        let finding: Finding = serde_json::from_str(raw_finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        let typed = canonical_json_bytes(&finding).map_err(|_| {
            ChallengeCoordinatorError::FindingArtifact(
                "raw finding could not be canonically serialized".to_owned(),
            )
        })?;
        if typed != strict {
            return Err(ChallengeCoordinatorError::FindingArtifact(
                "raw finding does not match its typed canonical body".to_owned(),
            ));
        }
        verify_finding(&finding)
            .map_err(|error| ChallengeCoordinatorError::FindingArtifact(error.to_string()))?;
        if finding.finding_id != challenge.finding_id {
            return Err(ChallengeCoordinatorError::FindingBinding("finding_id"));
        }
        Ok(finding)
    }

    /// Resolve and verify the retained venue admission that bound the
    /// challenged backing. The allocation in the evaluator-signed outcome
    /// comes only from this artifact.
    fn resolve_admission(
        &self,
        challenge: &FindingChallenge,
        now: u64,
    ) -> Result<SignedFindingAdmission, ChallengeCoordinatorError> {
        let admission = self
            .filings
            .admission_for_backing(
                &challenge.finding_id,
                &challenge.listing_id,
                &challenge.backing_envelope_sha256,
            )
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        if self.envelope_digest(&admission)? != challenge.venue_admission_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "venue_admission_envelope_sha256",
            ));
        }
        let admission_digest = self.envelope_digest(&admission)?;
        let venue_policy = self
            .filings
            .venue_policy_for_admission(&admission_digest)
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        let venue_authority = self.require_live_role(
            &venue_policy,
            admission.body.issued_at,
            now,
            "historical venue",
        )?;
        verify_signed_admission(&admission, &venue_authority, &self.venue_id)
            .map_err(|error| ChallengeCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        let bindings: [(&str, &str, &'static str); 6] = [
            (
                &admission.body.finding_id,
                &challenge.finding_id,
                "finding_id",
            ),
            (
                &admission.body.finding_artifact_sha256,
                &challenge.finding_artifact_sha256,
                "finding_artifact_sha256",
            ),
            (
                &admission.body.listing_id,
                &challenge.listing_id,
                "listing_id",
            ),
            (
                &admission.body.terms_envelope_sha256,
                &challenge.terms_envelope_sha256,
                "terms_envelope_sha256",
            ),
            (
                &admission.body.profile_envelope_sha256,
                &challenge.profile_envelope_sha256,
                "profile_envelope_sha256",
            ),
            (
                &admission.body.backing_envelope_sha256,
                &challenge.backing_envelope_sha256,
                "backing_envelope_sha256",
            ),
        ];
        for (admitted, challenged, label) in bindings {
            if admitted != challenged {
                return Err(ChallengeCoordinatorError::AdmissionBinding(label));
            }
        }
        Ok(admission)
    }

    /// Bind a failed-delivery terminal back to the durable reservation that
    /// produced it. A listing may be rebacked after a denial, so matching
    /// only finding and listing would let an old zero-charge terminal slash
    /// a new allocation that never backed that attempted sale.
    fn require_failed_delivery_reservation_binding(
        &self,
        challenge: &FindingChallenge,
        evidence: &FindingChallengeClassEvidence<'_>,
        admission: &SignedFindingAdmission,
    ) -> Result<(), ChallengeCoordinatorError> {
        let FindingChallengeClassEvidence::DigestMismatch(evidence) = evidence else {
            return Ok(());
        };
        let terminal = &evidence.failed_delivery.body;
        let retained = self
            .purchases
            .get_failed_delivery_record(&terminal.failed_delivery_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ))?;
        let reservation = self
            .purchases
            .get_reservation(&terminal.reservation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ))?;
        let encumbrance = self
            .purchases
            .get_encumbrance(&terminal.reservation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_backing",
            ))?;
        if terminal.finding_id != challenge.finding_id
            || terminal.listing_id != challenge.listing_id
            || retained.reservation_id != terminal.reservation_id
            || retained.record_sha256 != self.envelope_digest(evidence.failed_delivery)?
            || terminal.accepted_bid_envelope_sha256 != reservation.bid_envelope_sha256
            || terminal.purchase_intent_id != reservation.purchase_intent_id
            || terminal.authoritative_payment_operation_id
                != reservation.authoritative_payment_operation_id
            || terminal.buyer.to_hex() != reservation.payer_hex
            || reservation.finding_id != challenge.finding_id
            || reservation.listing_id != challenge.listing_id
            || reservation.admission_envelope_sha256 != challenge.venue_admission_envelope_sha256
            || reservation.admission_envelope_sha256 != self.envelope_digest(admission)?
            || encumbrance.allocation_id != admission.body.backing_allocation_id
        {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ));
        }
        Ok(())
    }

    /// Derive the only retry horizon the signed artifacts authorize. The
    /// filing horizon and terms expiry are seller signed; a buyer lock is
    /// an additional signed cap because retry can never retain that lock
    /// beyond its own expiry.
    fn derive_retry_deadline(
        &self,
        challenge: &FindingChallenge,
        terms: &SignedFindingMarketTerms,
        now: u64,
    ) -> Result<Option<u64>, ChallengeCoordinatorError> {
        let filing_deadline = terms
            .body
            .issued_at
            .checked_add(terms.body.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::TermsBinding(
                "filing window end is not representable",
            ))?;
        let mut deadline = filing_deadline.min(terms.body.expires_at);
        if let FindingChallengeAuthorization::BuyerSubmission(submission) = &challenge.authorization
        {
            deadline = deadline.min(submission.dispute_lock_ref.expiry);
        }
        Ok((deadline > now).then_some(deadline))
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
    fn require_funded_filing(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
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
        let lock = self
            .challenges
            .get_dispute_lock(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::FilingUnfunded)?;
        if lock.state != FindingDisputeLockState::Locked {
            return Err(ChallengeCoordinatorError::DisputeBondWindow);
        }
        if lock.expires_at <= now {
            // The signed retry horizon may be capped exactly at the lock
            // expiry. That instant authorizes closure and return, never a
            // new attempt, so let `begin_evaluation` take only its
            // RetryWindowExpired edge. Every other expired lock denies.
            let closing_retry = challenge.state == FindingChallengeState::IndeterminateRetryable
                && challenge
                    .retry_deadline
                    .is_some_and(|deadline| deadline <= now);
            if !closing_retry {
                return Err(ChallengeCoordinatorError::DisputeBondWindow);
            }
        }
        Ok(())
    }

    /// Return a collected filing fee once the signed funding horizon has
    /// closed and no dispute bond ever became durable.
    ///
    /// The original fee and its compensation have distinct semantic keys.
    /// A crash after either rail observation therefore resumes without a
    /// second debit or credit. A still-live filing is left untouched so a
    /// transient bond-rail outage can retry and complete normally.
    fn recover_expired_fee_only_submission(
        &self,
        challenge: &FindingChallenge,
        challenge_envelope_sha256: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        terms: &chio_finding::FindingMarketTerms,
        pool: &chio_finding::FindingPoolBinding,
        now: u64,
    ) -> Result<ExpiredFeeOnlyRecovery, ChallengeCoordinatorError> {
        let Some(recorded) = self
            .challenges
            .get_challenge(&challenge.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        };
        let owner_hex = submission.challenger.to_hex();
        if recorded.state != FindingChallengeState::Submitted
            || recorded.challenge_envelope_sha256 != challenge_envelope_sha256
            || recorded.finding_id != challenge.finding_id
            || recorded.listing_id != challenge.listing_id
            || recorded.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission
            || recorded.challenger_hex.as_deref() != Some(owner_hex.as_str())
            || self
                .challenges
                .get_dispute_lock(&challenge.challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .is_some()
        {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }
        let filing_deadline = terms
            .issued_at
            .checked_add(terms.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::FilingWindowClosed)?;
        let expired = now > filing_deadline
            || now >= terms.expires_at
            || now >= submission.dispute_lock_ref.expiry;
        if !expired {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }

        let fee = &submission.dispute_fee_terminal;
        let collected_instruction = FindingRailInstruction {
            idempotency_key: dispute_fee_intent_key(&challenge.challenge_id),
            payer: fee.payer.to_hex(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: fee.beneficiary_pool_principal_id.clone(),
            rail_destination: fee.rail_destination.clone(),
        };
        let collected_digest = canonical_digest_of(&collected_instruction)?;
        let collected = self
            .challenges
            .get_effect_intent(&collected_instruction.idempotency_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if !collected.is_some_and(|intent| {
            intent.kind == FindingEffectIntentKind::Fee
                && intent.liability_key.is_none()
                && !intent.settlement_required
                && intent.intent_digest == collected_digest
                && intent.state == FindingEffectIntentState::Confirmed
        }) {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }
        let funding_key = derive_dispute_bond_funding_intent_key(
            &challenge.challenge_id,
            &submission.dispute_lock_ref.lock_id,
        );
        let funding = self
            .challenges
            .get_effect_intent(&funding_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if let Some(intent) = &funding {
            if intent.state == FindingEffectIntentState::Confirmed {
                return Ok(ExpiredFeeOnlyRecovery::FundingConfirmed {
                    received_at: recorded.submitted_at,
                });
            }
            if intent.state == FindingEffectIntentState::Quarantined {
                return Ok(ExpiredFeeOnlyRecovery::Unchanged);
            }
            if matches!(
                intent.state,
                FindingEffectIntentState::Dispatched | FindingEffectIntentState::Failed
            ) {
                let lock = &submission.dispute_lock_ref;
                let input = FindingDisputeLockInput {
                    lock_id: &lock.lock_id,
                    challenge_id: &challenge.challenge_id,
                    owner_hex: &owner_hex,
                    schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
                    amount_units: lock.amount.units,
                    currency: &lock.amount.currency,
                    pool_principal_id: &pool.principal_id,
                    pool_rail_destination: &pool.rail_destination,
                    pool_authority_epoch: pool.authority_epoch,
                    expires_at: lock.expiry,
                    locked_at: recorded.submitted_at,
                };
                let expected_digest = dispute_bond_funding_intent_digest(&input);
                if intent.kind != FindingEffectIntentKind::ChallengeBond
                    || intent.liability_key.is_some()
                    || intent.settlement_required
                    || intent.intent_digest != expected_digest
                {
                    return Ok(ExpiredFeeOnlyRecovery::Unchanged);
                }
                self.challenges
                    .advance_effect_intent(&funding_key, FindingEffectIntentState::Dispatched, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                let instruction = FindingRailInstruction {
                    idempotency_key: funding_key.clone(),
                    payer: owner_hex,
                    amount_units: lock.amount.units,
                    currency: lock.amount.currency.clone(),
                    pool_principal_id: pool.principal_id.clone(),
                    rail_destination: pool.rail_destination.clone(),
                };
                let instruction_digest = canonical_digest_of(&instruction)?;
                match self.rail.dispatch(&instruction) {
                    Ok(observation)
                        if rail_observation_matches(
                            &instruction,
                            &instruction_digest,
                            &observation,
                        ) =>
                    {
                        self.challenges
                            .advance_effect_intent(
                                &funding_key,
                                FindingEffectIntentState::Confirmed,
                                now,
                            )
                            .map_err(|error| {
                                ChallengeCoordinatorError::ChallengeStore(error.to_string())
                            })?;
                        return Ok(ExpiredFeeOnlyRecovery::FundingConfirmed {
                            received_at: recorded.submitted_at,
                        });
                    }
                    Ok(_) => {
                        let _ = self.challenges.advance_effect_intent(
                            &funding_key,
                            FindingEffectIntentState::Failed,
                            now,
                        );
                        return Err(ChallengeCoordinatorError::DisputeBondRail(
                            "rail observation does not reconcile to the dispatched instruction"
                                .to_owned(),
                        ));
                    }
                    Err(reason) => {
                        let _ = self.challenges.advance_effect_intent(
                            &funding_key,
                            FindingEffectIntentState::Failed,
                            now,
                        );
                        return Err(ChallengeCoordinatorError::DisputeBondRail(reason));
                    }
                }
            }
        }

        let returned_fee_key =
            self.return_dispute_fee(&challenge.challenge_id, submission, pool, now)?;
        self.challenges
            .close_compensated_unfunded_filing(
                &challenge.challenge_id,
                &collected_instruction.idempotency_key,
                &returned_fee_key,
                &funding_key,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(ExpiredFeeOnlyRecovery::Compensated)
    }

    /// Recover the venue receipt time only when this exact challenge and
    /// this exact admission-pinned bond already reached confirmed funding.
    /// This lets a crash after the debit reconstruct and return an expired
    /// lock without treating a fresh backdated filing as timely.
    fn confirmed_funded_submission_received_at(
        &self,
        challenge: &FindingChallenge,
        challenge_envelope_sha256: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
    ) -> Result<Option<u64>, ChallengeCoordinatorError> {
        let Some(recorded) = self
            .challenges
            .get_challenge(&challenge.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        let owner_hex = submission.challenger.to_hex();
        if recorded.challenge_envelope_sha256 != challenge_envelope_sha256
            || recorded.finding_id != challenge.finding_id
            || recorded.listing_id != challenge.listing_id
            || recorded.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission
            || recorded.challenger_hex.as_deref() != Some(owner_hex.as_str())
        {
            return Ok(None);
        }
        let lock = &submission.dispute_lock_ref;
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &challenge.challenge_id,
            owner_hex: &owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at: recorded.submitted_at,
        };
        let key = derive_dispute_bond_funding_intent_key(&challenge.challenge_id, &lock.lock_id);
        let confirmed = self
            .challenges
            .get_effect_intent(&key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .is_some_and(|intent| {
                intent.kind == FindingEffectIntentKind::ChallengeBond
                    && intent.liability_key.is_none()
                    && !intent.settlement_required
                    && intent.intent_digest == dispute_bond_funding_intent_digest(&input)
                    && intent.state == FindingEffectIntentState::Confirmed
            });
        Ok(confirmed.then_some(recorded.submitted_at))
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
        admission: &SignedFindingAdmission,
        pool: &chio_finding::FindingPoolBinding,
        received_at: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
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
        if lock.expiry <= received_at {
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
            .resolve_fee_schedule(admission, &fee.fee_schedule_envelope_sha256)?
            .body;
        // A schedule that has not been issued yet, or that has expired,
        // prices nothing: the window a filing is admitted in is the window
        // its own schedule is live in.
        if received_at < terms.issued_at
            || terms.expires_at.is_some_and(|expiry| received_at >= expiry)
        {
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

    /// Require the evaluator key to be live at the instant it would sign.
    fn require_live_evaluator_key(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let pin = &self.evaluator_pin;
        if request.evaluator_key_epoch != pin.key_epoch {
            return Err(ChallengeCoordinatorError::EvaluatorKeyEpoch);
        }
        if !pin.covers(request.now) {
            return Err(ChallengeCoordinatorError::EvaluatorKeyWindow);
        }
        self.require_live_role(pin, request.now, request.now, "evaluator")
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::EvaluatorRevocation(reason)
                }
                other => other,
            })?;
        Ok(())
    }

    fn require_live_settlement_observer(
        &self,
        snapshot: &SignedFindingFinalizedBondSnapshot,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let pin = &self.pins.settlement_observer;
        self.require_live_role(pin, snapshot.body.observed_at, now, "settlement observer")
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::SettlementObserverLifecycle(reason)
                }
                other => other,
            })?;
        if snapshot.body.operator_key_epoch != pin.key_epoch {
            return Err(ChallengeCoordinatorError::SettlementObserverLifecycle(
                "snapshot names another key epoch",
            ));
        }
        Ok(())
    }

    /// Authenticate one role's exact lifecycle policy against the
    /// governance-signed reading returned by the deployment resolver.
    fn require_live_role(
        &self,
        pin: &FindingAuthorityPin,
        acted_at: u64,
        now: u64,
        role: &'static str,
    ) -> Result<PublicKey, ChallengeCoordinatorError> {
        self.resolve_live_role(pin, acted_at, now, role)
            .map(|(key, _)| key)
    }

    fn resolve_live_role(
        &self,
        pin: &FindingAuthorityPin,
        acted_at: u64,
        now: u64,
        role: &'static str,
    ) -> Result<(PublicKey, SignedFindingAuthorityStatus), ChallengeCoordinatorError> {
        let reject = |reason| ChallengeCoordinatorError::AuthorityLifecycle { role, reason };
        if acted_at > now {
            return Err(reject("role action is ahead of the venue clock"));
        }
        if !pin.covers(acted_at) {
            return Err(reject(
                "role action is outside the configured validity window",
            ));
        }
        let signed = self
            .authority_status
            .resolve(pin, now)
            .map_err(|_| reject("revocation source could not be resolved"))?;
        let status_key = self
            .pins
            .authority_status
            .key()
            .map_err(|_| reject("status authority pin is invalid"))?;
        verify_pinned_envelope(&signed, &status_key, "authority status")
            .map_err(|_| reject("revocation status signature is invalid"))?;
        let body = &signed.body;
        if !self.pins.authority_status.covers(body.observed_at) {
            return Err(reject(
                "status authority is outside its configured validity window",
            ));
        }
        let key = pin.key().map_err(|_| reject("authority pin is invalid"))?;
        if body.schema != FINDING_AUTHORITY_STATUS_SCHEMA_V1
            || body.status_ref != pin.revocation_status_ref
            || body.authority_id != pin.authority_id
            || body.key != key
            || body.key_epoch != pin.key_epoch
        {
            return Err(reject("revocation status does not bind the configured pin"));
        }
        if body.observed_at < acted_at
            || body.observed_at > now
            || now.saturating_sub(body.observed_at) > MAX_REVOCATION_STATUS_AGE_SECS
        {
            return Err(reject(
                "revocation status is not a fresh post-action reading",
            ));
        }
        if body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from > body.observed_at)
        {
            return Err(reject(
                "revocation status declares an unobserved future event",
            ));
        }
        if body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= acted_at)
        {
            return Err(reject("key was revoked when the role acted"));
        }
        Ok((key, signed))
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
        admission: &SignedFindingAdmission,
        now: u64,
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
        let audit_authority = self.require_live_role(
            &self.pins.audit_authority,
            round.epoch.body.committed_at,
            now,
            "audit",
        )?;
        let randomness_witness = self.require_live_role(
            &self.pins.audit_randomness_witness,
            round.epoch.body.seed_witnessed_at,
            now,
            "audit randomness witness",
        )?;
        verify_signed_audit_epoch(&round.epoch, &audit_authority, &randomness_witness)
            .map_err(|error| ChallengeCoordinatorError::AuditEpoch(error.to_string()))?;
        let authorization_digest = self.envelope_digest(&round.authorization)?;
        if round.epoch.body.authorization_digest != authorization_digest
            || audit.authorization_digest != authorization_digest
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "authorization_digest",
            ));
        }
        round
            .authorization
            .body
            .validate()
            .map_err(|_| ChallengeCoordinatorError::AuditRoundBinding("authorization_body"))?;
        let governance_authority = self.require_live_role(
            &self.pins.governance_authority,
            round.authorization.body.authorized_at,
            now,
            "governance",
        )?;
        verify_signed_audit_round_authorization(&round.authorization, &governance_authority)
            .map_err(|_| ChallengeCoordinatorError::AuditRoundBinding("authorization_signature"))?;
        if round.authorization.body.authorized_at > round.epoch.body.committed_at
            || round.authorization.body.expires_at <= round.epoch.body.committed_at
            || round.authorization.body.epoch_precommitment_sha256
                != audit_epoch_precommitment_sha256(&round.epoch.body)
                    .map_err(|_| ChallengeCoordinatorError::Canonical)?
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "authorization_epoch",
            ));
        }
        if challenge.filed_at <= round.epoch.body.committed_at {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "filing_after_epoch",
            ));
        }
        if round.epoch.body.fee_schedule_envelope_sha256
            != admission.body.fee_schedule_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "fee_schedule_envelope_sha256",
            ));
        }
        // The selection is a pure function of inputs the epoch committed
        // to before the seed was revealed, so it is recomputed here rather
        // than read from anything the filing carries. A listing the round
        // never drew has no entry to find.
        let selection = select_audit_targets(
            &round.epoch.body,
            &randomness_witness,
            &round.revealed_seed,
            &round.eligible,
        )
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
    /// prove it is the exact schedule the retained venue admission
    /// authorized.
    ///
    /// The digest is re-derived from the resolved envelope, so a resolver
    /// answering with any other artifact is caught here rather than
    /// pricing the filing. The admission was authenticated under the venue
    /// policy that covered its issue time, so later fee-operator rotation
    /// cannot strand a historical filing. The schedule still verifies
    /// strictly under the signer whose exact envelope the admission bound.
    fn resolve_fee_schedule(
        &self,
        admission: &SignedFindingAdmission,
        envelope_sha256: &str,
    ) -> Result<SignedOpenMarketFeeSchedule, ChallengeCoordinatorError> {
        if admission.body.fee_schedule_envelope_sha256 != envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "fee_schedule_envelope_sha256",
            ));
        }
        let schedule = self
            .filings
            .fee_schedule(envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownFeeSchedule)?;
        if self.envelope_digest(&schedule)? != envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "resolved fee schedule digest",
            ));
        }
        verify_pinned_envelope(&schedule, &schedule.signer_key, "fee schedule")
            .map_err(|error| ChallengeCoordinatorError::FeeScheduleArtifact(error.to_string()))?;
        schedule
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::FeeScheduleArtifact)?;
        Ok(schedule)
    }

    /// The listing-class requirement is unique in a validated schedule and
    /// is the only ceiling the penalty calculation may use.
    fn listing_bond_requirement(
        schedule: &SignedOpenMarketFeeSchedule,
    ) -> Result<&MonetaryAmount, ChallengeCoordinatorError> {
        schedule
            .body
            .bond_requirements
            .iter()
            .find(|requirement| requirement.bond_class == OpenMarketBondClass::Listing)
            .map(|requirement| &requirement.required_amount)
            .ok_or(ChallengeCoordinatorError::DisputeTerms(
                "listing bond requirement",
            ))
    }

    /// Resolve the seller-signed market terms one filing binds by digest,
    /// and prove they are the terms this venue admitted for the exact
    /// finding artifact and listing being challenged.
    ///
    /// The digest is re-derived from the resolved envelope, so a resolver
    /// answering with any other artifact is caught here. The envelope must
    /// verify under its embedded seller, and it must name the challenged
    /// finding bytes and listing: terms for another artifact or listing
    /// would lend this filing a window, an audit toggle, and bond limits
    /// their seller never signed for it.
    fn resolve_market_terms(
        &self,
        challenge: &FindingChallenge,
    ) -> Result<SignedFindingMarketTerms, ChallengeCoordinatorError> {
        let terms = self
            .filings
            .market_terms(&challenge.terms_envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownMarketTerms)?;
        if self.envelope_digest(&terms)? != challenge.terms_envelope_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "envelope digest",
            ));
        }
        verify_signed_market_terms(&terms)
            .map_err(|error| ChallengeCoordinatorError::TermsEnvelope(error.to_string()))?;
        if terms.body.finding_id != challenge.finding_id {
            return Err(ChallengeCoordinatorError::FilingTermsBinding("finding_id"));
        }
        if terms.body.finding_artifact_sha256 != challenge.finding_artifact_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "finding_artifact_sha256",
            ));
        }
        if terms.body.verifier_profile_envelope_sha256 != challenge.profile_envelope_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "verifier_profile_envelope_sha256",
            ));
        }
        if terms.body.listing_id != challenge.listing_id {
            return Err(ChallengeCoordinatorError::FilingTermsBinding("listing_id"));
        }
        if terms.body.appeal_window_secs < MIN_APPEAL_WINDOW_SECS {
            return Err(ChallengeCoordinatorError::DisputeTerms("appeal window"));
        }
        Ok(terms)
    }

    /// Require both the signed filing instant and the venue's receipt
    /// instant to sit inside the seller-signed filing window.
    ///
    /// The window is the exposure horizon the seller committed to when
    /// the terms were issued: `filing_window_secs` from their issuance is
    /// how long a challenge may still be filed against the listing. A
    /// self-signed `filed_at` alone is not an authoritative receipt
    /// clock: a caller could backdate a freshly signed filing after the
    /// deadline. The signed instant still has to follow terms issuance,
    /// and the venue clock must not have crossed the same deadline. A
    /// window end that is not representable admits nothing.
    fn require_filing_window(
        &self,
        terms: &chio_finding::FindingMarketTerms,
        filed_at: u64,
        received_at: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let deadline = terms
            .issued_at
            .checked_add(terms.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::FilingWindowClosed)?;
        if filed_at < terms.issued_at || filed_at > deadline || received_at > deadline {
            return Err(ChallengeCoordinatorError::FilingWindowClosed);
        }
        Ok(())
    }

    /// Require a buyer's dispute bond to sit inside the seller-signed
    /// bond limits for the challenged finding's guarantee class.
    ///
    /// The signed fee schedule fixes the bond exactly; these limits are
    /// the seller's own anti-griefing floor and ceiling, signed into the
    /// terms per guarantee class. Both artifacts must agree: a schedule
    /// pricing the bond outside the seller's signed band, or a class the
    /// terms never priced, refuses the filing.
    fn require_bond_within_terms_limits(
        &self,
        terms: &chio_finding::FindingMarketTerms,
        submission: &chio_finding::FindingBuyerSubmission,
        guarantee_class: chio_finding::FindingGuaranteeClass,
    ) -> Result<(), ChallengeCoordinatorError> {
        let limit = terms
            .challenge_bond_limits
            .iter()
            .find(|limit| limit.guarantee_class == guarantee_class)
            .ok_or(ChallengeCoordinatorError::DisputeBondOutsideTermsLimits)?;
        let bond = &submission.dispute_lock_ref.amount;
        if bond.currency != limit.min_bond.currency
            || bond.units < limit.min_bond.units
            || bond.units > limit.max_bond.units
        {
            return Err(ChallengeCoordinatorError::DisputeBondOutsideTermsLimits);
        }
        Ok(())
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
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let governance_key = self.require_live_role(
            &self.pins.governance_authority,
            case.body.updated_at,
            now,
            "governance",
        )?;
        let charter_governance_key = self.require_live_role(
            &self.pins.governance_authority,
            governance.charter.body.issued_at,
            now,
            "governance charter",
        )?;
        // The listing authenticates against its own namespace owner rather
        // than a pinned key, so the case is what anchors it: a listing the
        // pinned case does not name cannot be the one being sanctioned.
        if governance.listing.body.listing_id != case.body.listing_id {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "penalty listing",
            ));
        }
        let schedule_digest = self.envelope_digest(governance.fee_schedule)?;
        if governance.admission.body.listing_id != case.body.listing_id
            || governance.admission.body.fee_schedule_envelope_sha256 != schedule_digest
        {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "admitted fee schedule",
            ));
        }
        let admission_digest = self.envelope_digest(governance.admission)?;
        let venue_policy = self
            .filings
            .venue_policy_for_admission(&admission_digest)
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        let historical_venue = self.require_live_role(
            &venue_policy,
            governance.admission.body.issued_at,
            now,
            "historical venue",
        )?;
        verify_signed_admission(governance.admission, &historical_venue, &self.venue_id)
            .map_err(|error| ChallengeCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        if governance.charter.signer_key != charter_governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance charter",
            ));
        }
        if case.signer_key != governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance case",
            ));
        }
        if governance
            .activation
            .is_some_and(|activation| activation.signer_key != governance_key)
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
        ensure_generic_listing_signed_by_namespace_owner(governance.listing, "penalty listing")
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        governance
            .fee_schedule
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !governance
            .fee_schedule
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "fee schedule signature is invalid".to_owned(),
            ));
        }
        governance
            .charter
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !governance
            .charter
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "governance charter signature is invalid".to_owned(),
            ));
        }
        case.body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !case
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "governance case signature is invalid".to_owned(),
            ));
        }
        if let Some(activation) = governance.activation {
            activation
                .body
                .validate()
                .map_err(ChallengeCoordinatorError::PenaltyMint)?;
            if !activation
                .verify_signature()
                .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
            {
                return Err(ChallengeCoordinatorError::PenaltyMint(
                    "trust activation signature is invalid".to_owned(),
                ));
            }
        }
        if let Some(prior) = prior_penalty {
            prior
                .body
                .validate()
                .map_err(ChallengeCoordinatorError::PenaltyMint)?;
            if !prior
                .verify_signature()
                .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
            {
                return Err(ChallengeCoordinatorError::PenaltyMint(
                    "prior penalty signature is invalid".to_owned(),
                ));
            }
        }
        governance
            .current_publisher
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        Ok(())
    }

    /// Resolve the instant this liability's claim window closes.
    ///
    /// The length is a term the seller signed for this exact finding and
    /// listing, never an operator's choice: the snapshot it gates is what
    /// harmed buyers and omission proofs are paid from, so the venue must
    /// not be able to shorten it once adjudication has landed. Terms for
    /// another listing, or an envelope the embedded seller did not sign,
    /// bind nothing here.
    fn require_claim_window(
        &self,
        terms: &SignedFindingMarketTerms,
        identity: &FindingLiabilityIdentity<'_>,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        verify_signed_market_terms(terms)
            .map_err(|error| ChallengeCoordinatorError::TermsEnvelope(error.to_string()))?;
        if terms.body.finding_id != identity.finding_id {
            return Err(ChallengeCoordinatorError::TermsBinding("finding_id"));
        }
        if terms.body.listing_id != identity.listing_id {
            return Err(ChallengeCoordinatorError::TermsBinding("listing_id"));
        }
        now.checked_add(terms.body.claim_window_secs)
            .ok_or(ChallengeCoordinatorError::TermsBinding("claim_window_secs"))
    }

    /// Require penalty facts to carry the seller's signed base stake before
    /// either an outcome or a liability transition can become durable.
    ///
    /// The evaluation and liability-opening paths consume the same facts at
    /// different times. Checking only when the liability opens would let the
    /// evaluator sign and record an upheld verdict that can never progress.
    fn require_signed_base_stake(
        terms: &SignedFindingMarketTerms,
        collateral: &FindingCollateralFacts<'_>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let signed_stake = &terms.body.backing_requirement.base_finding_stake;
        if collateral.base_finding_stake.units != signed_stake.units
            || collateral.base_finding_stake.currency != signed_stake.currency
        {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "base_finding_stake",
            ));
        }
        Ok(())
    }

    /// Exposure still outstanding against one allocation, read after the
    /// expiry sweep has retired every reservation whose expiry has
    /// passed.
    ///
    /// The sweep releases exposure no purchase can realize any more, so
    /// the figure every slash input reads is backed by reservations that
    /// can still settle. The store serializes the sweep and the read on
    /// one connection, and the query applies the same expiry rule itself,
    /// so a lagging sweep can only overstate the encumbrance, never let a
    /// dead reservation slip back in.
    fn outstanding_exposure(
        &self,
        allocation_id: &str,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        self.purchases
            .expire_reservations(now, usize::MAX)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        self.purchases
            .list_outstanding_exposure_total(allocation_id, now)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))
    }

    /// Require the collateral behind this defect to be able to fund a
    /// nonzero impairment, on the same inputs the sealed accounting is
    /// computed from.
    fn require_impairable_collateral(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        let open = self.outstanding_exposure(&collateral.bond_snapshot.body.allocation_id, now)?;
        let candidate = collateral
            .base_finding_stake
            .units
            .checked_add(open)
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic(
                    "computed exposure overflowed".to_owned(),
                )
            })?;
        if candidate.min(live_allocated_collateral) == 0 {
            return Err(ChallengeCoordinatorError::NothingToImpair);
        }
        Ok(())
    }

    /// Authenticate and derive the only live collateral figure penalty math
    /// may consume.
    fn authenticated_live_collateral(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        let snapshot = &collateral.bond_snapshot;
        self.require_live_settlement_observer(snapshot, now)?;
        let settlement_observer =
            self.pins.settlement_observer.key().map_err(|_| {
                ChallengeCoordinatorError::AuthorityPinMismatch("settlement observer")
            })?;
        if snapshot.body.currency != collateral.base_finding_stake.currency {
            return Err(ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot currency does not match the signed base stake",
            ));
        }
        verify_finding_collateral_snapshot(
            snapshot,
            &settlement_observer,
            self.pins.settlement_finality_requirement,
            self.market_config.max_snapshot_age_secs,
            now,
        )
        .map_err(|_| {
            ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot signature, finality, freshness, or balance is invalid",
            )
        })
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

    /// Bind a still-pending root intent to the concrete proof this finalize
    /// attempt prepared. The generic liability and penalty commitment is
    /// checked first, so a mismatched intent cannot be poisoned with a
    /// binding that belongs elsewhere.
    fn bind_enforcement_root(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        planned: &chio_settle::FindingImpairmentIntent,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let root = self
            .challenges
            .get_effect_intent(verified.root_intent_id())
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let expected = sha256_hex(
            root_intent_commitment(
                liability_key,
                &verified.enforcement().penalty_envelope_sha256,
            )
            .as_bytes(),
        );
        if root.kind != FindingEffectIntentKind::RootIntent
            || root.liability_key.as_deref() != Some(liability_key)
            || root.intent_digest != expected
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the named root intent does not fence this liability and penalty",
            ));
        }
        self.challenges
            .bind_effect_root(
                verified.root_intent_id(),
                liability_key,
                &planned.merkle_root,
                &planned.evidence_hash,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(())
    }

    /// Require the exact root this impairment carries to be published and
    /// confirmed.
    ///
    /// The vault checks the impairment proof against a root, so the call
    /// is only authorized once that root is on chain. The instruction
    /// names the intent that fences it, but naming is not evidence: the
    /// durable record has to belong to this liability, carry the
    /// commitment this exact penalty derives, and sit in `confirmed`.
    fn require_confirmed_enforcement_root(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        planned: &chio_settle::FindingImpairmentIntent,
    ) -> Result<(), ChallengeCoordinatorError> {
        let root = self
            .challenges
            .get_effect_intent(verified.root_intent_id())
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if root.kind != FindingEffectIntentKind::RootIntent
            || root.liability_key.as_deref() != Some(liability_key)
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the named root intent does not fence this liability",
            ));
        }
        let expected = sha256_hex(
            root_intent_commitment(
                liability_key,
                &verified.enforcement().penalty_envelope_sha256,
            )
            .as_bytes(),
        );
        if root.intent_digest != expected {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the fenced root does not commit to the penalty this enforcement pays",
            ));
        }
        let binding = self
            .challenges
            .get_effect_root_binding(verified.root_intent_id())
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the enforcement root has no prepared anchor binding",
            ))?;
        if binding.liability_key != liability_key
            || binding.merkle_root != planned.merkle_root
            || binding.evidence_hash != planned.evidence_hash
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the confirmed root does not bind this Merkle root and evidence hash",
            ));
        }
        if root.state != FindingEffectIntentState::Confirmed {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the enforcement root has not been published",
            ));
        }
        Ok(())
    }

    /// Finish a previously confirmed impairment without dispatching it
    /// again.
    ///
    /// The liability is loaded again here because another finalizer may
    /// have quarantined it after this caller's initial read. Settlement
    /// repeats the same check in its write transaction, closing the race
    /// between this read and the lifecycle transition.
    fn finish_confirmed_impairment(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        now: u64,
    ) -> Result<FindingFinalization, ChallengeCoordinatorError> {
        let liability = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        // If a post-dispatch chain recheck quarantined the liability,
        // recovery must explicitly authenticate the original snapshot. The
        // caller has already re-observed the exact confirmed transaction at
        // current finality, so a later observer-key rotation cannot strand
        // an impairment that already moved collateral.
        if liability.quarantined {
            let seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
                ChallengeCoordinatorError::ChallengeStore(
                    "liability carries an invalid durable seller key".to_owned(),
                )
            })?;
            let finalization_authority = self.require_enforcement_signature(enforcement, now)?;
            let pins = FindingEnforcementPins {
                finalization_authority,
                settlement_observer: bond_snapshot.signer_key.clone(),
                seller,
                finality_requirement: self.pins.settlement_finality_requirement,
                max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
            };
            verify_finding_enforcement_for_reconciliation(enforcement, bond_snapshot, &pins, now)
                .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
            self.challenges
                .set_liability_quarantine(liability_key, false, now)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        }
        if self.settle_if_enforcement_effects_confirmed(liability_key, enforcement, now)? {
            Ok(FindingFinalization::AlreadyConfirmed)
        } else {
            Ok(FindingFinalization::AwaitingEffects)
        }
    }

    /// Re-read the exact stored transaction and require it still to be a
    /// canonical finalized execution of the frozen impairment call.
    fn require_reobserved_impairment(
        &self,
        planned: &PlannedFindingImpairment,
        publisher: &dyn FindingImpairmentPublisher,
        expected_tx_hash: Option<&str>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let outcome = reobserve_finding_impairment(planned, publisher)
            .map_err(|error| ChallengeCoordinatorError::Publisher(error.to_string()))?;
        match outcome {
            FindingImpairmentOutcome::Confirmed { tx_hash }
                if expected_tx_hash.is_none_or(|expected| expected == tx_hash) =>
            {
                Ok(())
            }
            FindingImpairmentOutcome::Confirmed { .. } => {
                Err(ChallengeCoordinatorError::Settlement(
                    "re-observed impairment transaction does not match the published transaction"
                        .to_owned(),
                ))
            }
            FindingImpairmentOutcome::Quarantined { .. }
            | FindingImpairmentOutcome::Failed { .. } => {
                Err(ChallengeCoordinatorError::Settlement(
                    "re-observed impairment transaction is not finalized on the canonical chain"
                        .to_owned(),
                ))
            }
        }
    }

    /// Clear publication pending only after every effect the signed
    /// enforcement binds has reached its durable confirmed state.
    fn settle_if_enforcement_effects_confirmed(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        now: u64,
    ) -> Result<bool, ChallengeCoordinatorError> {
        for binding in &enforcement.body.effect_intents {
            let expected_kind = match binding.kind {
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
            let intent = self
                .challenges
                .get_effect_intent(&binding.intent_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
            if intent.liability_key.as_deref() != Some(liability_key)
                || intent.kind != expected_kind
                || !intent.settlement_required
            {
                return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
            }
            if intent.state != FindingEffectIntentState::Confirmed {
                return Ok(false);
            }
        }
        self.challenges
            .settle_liability(liability_key, FindingLiabilityState::Finalizing, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(true)
    }

    /// Fence the anchored evidence leaf this impairment burns.
    ///
    /// The anchor proof arrives beside the instruction and authenticates
    /// only as a proof: nothing in it names the enforcement it is being
    /// spent on. The leaf is therefore committed here, before the call
    /// leaves, to the liability, the stable seller-impair intent, and the
    /// penalty it pays, under a key that is the leaf itself. The stable
    /// intent survives an allowed observer-snapshot refresh, while one
    /// anchored receipt still authorizes exactly one impairment: presenting
    /// it again under different terms collides with what is already durable
    /// and rejects, and replaying the same terms reconciles.
    fn fence_anchor_evidence(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        intent: &chio_settle::FindingImpairmentIntent,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let commitment = anchor_evidence_intent_commitment(
            liability_key,
            &intent.intent_id,
            &verified.enforcement().penalty_envelope_sha256,
            &intent.merkle_root,
        );
        self.challenges
            .record_effect_intent(
                &derive_anchor_evidence_intent_key(&intent.evidence_hash),
                FindingEffectIntentKind::RootIntent,
                &commitment,
                Some(liability_key),
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(())
    }

    /// Re-read the chain and identity state behind a verified snapshot and
    /// require it to still qualify.
    ///
    /// The read itself is injected, so a source that cannot complete it
    /// denies rather than returning state it is unsure of. Unknown chain
    /// state and a disqualified observation are the same answer here:
    /// neither authorizes moving collateral.
    fn require_qualified_observation(
        &self,
        verified: &VerifiedFindingEnforcement,
        observations: &dyn FindingBondObservationSource,
    ) -> Result<(), ChallengeCoordinatorError> {
        let observed = observations
            .observe(verified)
            .map_err(|error| ChallengeCoordinatorError::BondObservation(error.to_string()))?;
        let verdict = recheck_finding_bond_observation(verified, &observed);
        if !verdict.is_qualified() {
            return Err(ChallengeCoordinatorError::BondObservation(
                verdict.reason().to_owned(),
            ));
        }
        Ok(())
    }

    /// Require a successful appeal to have been opened inside the exact
    /// seller-signed window frozen when the liability entered pending
    /// appeal. Resolution may finish later; filing itself must be timely.
    fn require_timely_appeal(
        &self,
        record: &FindingLiabilityRecord,
        appeal_case: &SignedGenericGovernanceCase,
        appeal_case_id: &str,
    ) -> Result<(), ChallengeCoordinatorError> {
        if appeal_case.body.case_id != appeal_case_id {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal case id does not match the signed case",
            ));
        }
        let opened =
            record
                .appeal_window_opened_at
                .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                    "appeal window was not frozen",
                ))?;
        let deadline = record
            .appeal_deadline
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "appeal deadline was not frozen",
            ))?;
        if appeal_case.body.opened_at < opened {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal predates the durable appeal window",
            ));
        }
        if appeal_case.body.opened_at > deadline {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal was opened after the durable deadline",
            ));
        }
        Ok(())
    }

    /// Require the appeal window on this liability to be provably closed
    /// with the presented sanction still governing it. The deadline is
    /// the value frozen from seller-signed terms, never a caller input.
    fn require_appeal_window_closed(
        &self,
        record: &FindingLiabilityRecord,
        sanction_case: &SignedGenericGovernanceCase,
        sanction_case_id: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        if sanction_case.body.case_id != sanction_case_id {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "sanction case does not name the sanction being closed",
            ));
        }
        let head = self
            .challenges
            .resolve_case_head(&record.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "liability carries no live governance case",
            ))?;
        if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id
        {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "the sanction is no longer the live case on this liability",
            ));
        }
        let appeal_deadline =
            record
                .appeal_deadline
                .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                    "appeal deadline was not frozen",
                ))?;
        if now <= appeal_deadline {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal deadline has not passed at the venue clock",
            ));
        }
        Ok(())
    }

    /// Require a sanction to still be the live governance case on this
    /// liability before its impairment dispatches.
    ///
    /// The appeal window was proved closed when the enforcement was
    /// signed, but the durable case index can move between that instant
    /// and this dispatch: a recorded successful appeal supersedes the
    /// sanction, and an impairment sent afterwards would slash under an
    /// authority that no longer governs. The head is re-read here, and
    /// anything but a live sanction (including an ambiguous head) refuses
    /// the dispatch.
    fn require_sanction_governs(
        &self,
        liability_key: &str,
        sanction_case_id: &str,
    ) -> Result<(), ChallengeCoordinatorError> {
        let head = self
            .challenges
            .resolve_case_head(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "liability carries no live governance case",
            ))?;
        if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id
        {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "the sanction no longer governs this liability",
            ));
        }
        Ok(())
    }

    /// Authenticate the exact slash penalty the enforcement commits to.
    ///
    /// The enforcement carries only an envelope digest. Presenting the
    /// signed artifact here recovers the governance case identity behind
    /// that digest, while the pinned penalty key prevents a caller from
    /// inventing a different case under otherwise self-consistent bytes.
    fn require_penalty_matches_enforcement(
        &self,
        liability: &FindingLiabilityRecord,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        penalty
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let historical_pin = FindingAuthorityPin {
            authority_id: enforcement.body.penalty_authority_id.clone(),
            key_hex: enforcement.body.penalty_key.to_hex(),
            key_epoch: enforcement.body.penalty_key_epoch,
            valid_from: enforcement.body.penalty_valid_from,
            valid_until: enforcement.body.penalty_valid_until,
            revocation_status_ref: enforcement.body.penalty_revocation_status_ref.clone(),
        };
        let historical_key = self.require_live_role(
            &historical_pin,
            penalty.body.updated_at,
            now,
            "historical penalty",
        )?;
        verify_pinned_envelope(penalty, &historical_key, "market penalty")
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let digest = self.envelope_digest(penalty)?;
        if digest != enforcement.body.penalty_envelope_sha256 {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement does not bind the presented penalty envelope".to_owned(),
            ));
        }
        if penalty.body.listing_id != liability.listing_id {
            return Err(ChallengeCoordinatorError::Settlement(
                "penalty does not name this liability's listing".to_owned(),
            ));
        }
        if penalty.body.action != OpenMarketPenaltyAction::SlashBond
            || penalty.body.state != OpenMarketPenaltyState::Enforced
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "finalization requires an enforced slash penalty".to_owned(),
            ));
        }
        if penalty.body.penalty_amount != enforcement.body.amount {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement amount does not match the bound penalty".to_owned(),
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

    /// Verify the exact durable adjudication with the evaluator policy that
    /// covered its historical signing time, not the coordinator's current
    /// post-rotation key.
    fn require_recorded_outcome_signature(
        &self,
        challenge_id: &str,
        outcome: &SignedFindingChallengeOutcome,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
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
        outcome
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        let historical_pin = FindingAuthorityPin {
            authority_id: outcome.body.evaluator_authority_id.clone(),
            key_hex: outcome.body.evaluator_key.to_hex(),
            key_epoch: outcome.body.evaluator_key_epoch,
            valid_from: outcome.body.evaluator_valid_from,
            valid_until: outcome.body.evaluator_valid_until,
            revocation_status_ref: outcome.body.evaluator_revocation_status_ref.clone(),
        };
        let evaluator = self
            .require_live_role(
                &historical_pin,
                outcome.body.evaluated_at,
                now,
                "historical evaluator",
            )
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::EvaluatorRevocation(reason)
                }
                other => other,
            })?;
        verify_signed_challenge_outcome(outcome, &evaluator)
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))
    }

    /// Authenticate one retained enforcement under the exact historical
    /// finalization policy its signed body commits, then verify the envelope
    /// under the resulting key. The externally authenticated status resolver
    /// keeps these body fields from self-authorizing a signer.
    fn require_enforcement_signature(
        &self,
        enforcement: &SignedFindingChallengeEnforcement,
        now: u64,
    ) -> Result<PublicKey, ChallengeCoordinatorError> {
        enforcement
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let body = &enforcement.body;
        let historical_pin = FindingAuthorityPin {
            authority_id: body.finalization_authority_id.clone(),
            key_hex: body.finalization_key.to_hex(),
            key_epoch: body.finalization_key_epoch,
            valid_from: body.finalization_valid_from,
            valid_until: body.finalization_valid_until,
            revocation_status_ref: body.finalization_revocation_status_ref.clone(),
        };
        let authority = self.require_live_role(
            &historical_pin,
            body.finalized_at,
            now,
            "historical finalization",
        )?;
        verify_pinned_envelope(enforcement, &authority, "finding challenge enforcement")
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        Ok(authority)
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
        let intent_key = dispute_fee_intent_key(challenge_id);
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
                false,
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
            Ok(observation)
                if rail_observation_matches(&instruction, &intent_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(
                    "rail observation does not reconcile to the dispatched instruction".to_owned(),
                ))
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

    /// Compensate a collected dispute fee when the paired bond never
    /// funded before the signed filing horizon closed.
    fn return_dispute_fee(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        let intent_key = dispute_fee_return_intent_key(challenge_id);
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: pool.principal_id.clone(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: pool.principal_id.clone(),
            rail_destination: fee.payer.to_hex(),
        };
        let intent_digest = canonical_digest_of(&instruction)?;
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::Fee,
                &intent_digest,
                None,
                false,
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
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &intent_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(
                    "fee return observation does not reconcile to the dispatched instruction"
                        .to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(reason))
            }
        }
    }

    fn fund_dispute_bond(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
        locked_at: u64,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let lock = &submission.dispute_lock_ref;
        let owner_hex = submission.challenger.to_hex();
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id,
            owner_hex: &owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at,
        };
        let intent_key = derive_dispute_bond_funding_intent_key(challenge_id, &lock.lock_id);
        let intent_digest = dispute_bond_funding_intent_digest(&input);
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::ChallengeBond,
                &intent_digest,
                None,
                false,
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
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: submission.challenger.to_hex(),
            amount_units: lock.amount.units,
            currency: lock.amount.currency.clone(),
            pool_principal_id: pool.principal_id.clone(),
            rail_destination: pool.rail_destination.clone(),
        };
        let instruction_digest = canonical_digest_of(&instruction)?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &instruction_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(
                    "rail observation does not reconcile to the dispatched instruction".to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(reason))
            }
        }
    }

    /// Reconcile the reverse rail instruction before reporting a funded
    /// lock as returned. The distinct effect key makes the credit replay
    /// safe without confusing it with the original debit.
    fn return_dispute_bond(
        &self,
        lock: &FindingDisputeLockRecord,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &lock.challenge_id,
            owner_hex: &lock.owner_hex,
            schedule_envelope_sha256: &lock.schedule_envelope_sha256,
            amount_units: lock.amount_units,
            currency: &lock.currency,
            pool_principal_id: &lock.pool_principal_id,
            pool_rail_destination: &lock.pool_rail_destination,
            pool_authority_epoch: lock.pool_authority_epoch,
            expires_at: lock.expires_at,
            locked_at: lock.locked_at,
        };
        let intent_key = derive_dispute_bond_return_intent_key(&lock.challenge_id, &lock.lock_id);
        let intent_digest = dispute_bond_return_intent_digest(&input);
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::ChallengeBond,
                &intent_digest,
                None,
                false,
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
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: lock.pool_principal_id.clone(),
            amount_units: lock.amount_units,
            currency: lock.currency.clone(),
            pool_principal_id: lock.pool_principal_id.clone(),
            rail_destination: lock.owner_hex.clone(),
        };
        let instruction_digest = canonical_digest_of(&instruction)?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &instruction_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(
                    "return observation does not reconcile to the dispatched instruction"
                        .to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(reason))
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
        listing_required_amount: &MonetaryAmount,
        now: u64,
    ) -> Result<FindingPenaltyCalculation, ChallengeCoordinatorError> {
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        let open = self.outstanding_exposure(&collateral.bond_snapshot.body.allocation_id, now)?;
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
            listing_required_amount_units: listing_required_amount.units,
            live_allocated_collateral_units: live_allocated_collateral,
            penalty_amount: MonetaryAmount {
                units: computed.min(live_allocated_collateral),
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
    /// record, have charged its exposure to this liability's allocation,
    /// pay a destination that was admitted at capture, and be denominated
    /// in the bond currency. No caller-supplied amount or address
    /// survives.
    fn seal_claim_snapshot(
        &self,
        liability_key: &str,
        identity: &FindingLiabilityIdentity<'_>,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        expected_penalty: &MonetaryAmount,
        community_fund_destination: &str,
        now: u64,
    ) -> Result<SealedClaimSnapshot, ChallengeCoordinatorError> {
        let harms = self.verified_harms(
            identity,
            &collateral.base_finding_stake.currency,
            cutoff_slot,
            claim_candidates,
            now,
        )?;
        let total_realized_spend_units = harms
            .iter()
            .try_fold(0_u64, |total, harm| {
                total.checked_add(harm.realized_spend_units)
            })
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic("verified harm overflowed".to_owned())
            })?;
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        if expected_penalty.currency != collateral.base_finding_stake.currency
            || expected_penalty.units > live_allocated_collateral
        {
            return Err(ChallengeCoordinatorError::PenaltyCalculationMismatch);
        }
        let distribution =
            compute_frozen_slash_distribution(expected_penalty, community_fund_destination, &harms)
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
        bond_currency: &str,
        cutoff_slot: u64,
        claim_candidates: &[String],
        now: u64,
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
            self.verify_purchase_record_from_retained_admission(identity, &signed, now)?;
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
            // The reservation's encumbrance is what charged this sale to a
            // vault, and a listing may be rebacked between sales. A record
            // whose exposure was booked against another allocation is not
            // this liability's harm: paying it here would take the money
            // from a seller who never sold it.
            let encumbrance = self
                .purchases
                .get_encumbrance(&row.reservation_id)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::PurchaseOutsideAllocation(purchase_key.clone())
                })?;
            if encumbrance.allocation_id != identity.allocation_id {
                return Err(ChallengeCoordinatorError::PurchaseOutsideAllocation(
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
            // A verified harm carries bare units that the distribution
            // reads as bond currency, so the denomination has to be proven
            // here. Folding a spend attested in another currency would pay
            // it out unit for unit against collateral it never priced.
            if record.realized_spend.currency != bond_currency {
                return Err(ChallengeCoordinatorError::PurchaseCurrencyMismatch(
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

    /// Authenticate every candidate purchase before the liability
    /// transaction blocks sales. The full listing, cutoff, allocation,
    /// and payout checks still run while sealing.
    fn require_purchase_authority_for_candidates(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        claim_candidates: &[String],
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
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
            self.verify_purchase_record_from_retained_admission(identity, &signed, now)?;
        }
        Ok(())
    }

    /// Authenticate purchase standing against both durable existence and
    /// the admission-pinned authority lifecycle before pure adjudication.
    /// A caller-supplied signed record is not standing merely because its
    /// signer can backdate `recorded_at`: the exact envelope must be the one
    /// the purchase authority retained when the sale settled.
    fn require_authoritative_purchase_standing(
        &self,
        admission: &SignedFindingAdmission,
        evidence: &FindingChallengeClassEvidence<'_>,
        now: u64,
    ) -> Result<Option<SignedFindingAuthorityStatus>, ChallengeCoordinatorError> {
        let signed = match evidence {
            FindingChallengeClassEvidence::EvidenceInvalid(evidence) => evidence.purchase_record,
            FindingChallengeClassEvidence::ReplayContradiction(evidence) => {
                evidence.purchase_record
            }
            FindingChallengeClassEvidence::DigestMismatch(_) => return Ok(None),
        };
        let record = &signed.body;
        let stored = self
            .purchases
            .get_purchase_record(&record.purchase_key)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::UnknownPurchaseRecord(record.purchase_key.clone())
            })?;
        let presented_json =
            canonical_json_bytes(signed).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if stored.record_json != presented_json
            || stored.record_sha256 != sha256_hex(&presented_json)
            || stored.recorded_at != record.recorded_at
        {
            return Err(ChallengeCoordinatorError::PurchaseStanding(
                "the supplied envelope is not the retained settled record".to_owned(),
            ));
        }
        if self.envelope_digest(admission)? != record.venue_admission_envelope_sha256 {
            return Err(ChallengeCoordinatorError::PurchaseStanding(
                "the retained record names another venue admission".to_owned(),
            ));
        }
        let policy = &admission.body.purchase_authority;
        policy
            .validate("purchase_authority")
            .map_err(|error| ChallengeCoordinatorError::PurchaseStanding(error.to_string()))?;
        let standing_pin = FindingAuthorityPin {
            authority_id: policy.authority_id.clone(),
            key_hex: policy.key.to_hex(),
            key_epoch: policy.key_epoch,
            valid_from: policy.valid_from,
            valid_until: policy.valid_until,
            revocation_status_ref: policy.revocation_status_ref.clone(),
        };
        let (purchase_authority, purchase_authority_status) =
            self.resolve_live_role(&standing_pin, record.recorded_at, now, "purchase standing")?;
        verify_signed_purchase_record(signed, &purchase_authority)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStanding(error.to_string()))?;
        Ok(Some(purchase_authority_status))
    }

    /// Verify a historical purchase under the authority policy the venue
    /// authenticated for that exact sale. A later deployment rotation does
    /// not invalidate an earlier record, while the retained policy's own
    /// validity window and independently signed revocation status still
    /// fail closed.
    fn verify_purchase_record_from_retained_admission(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        signed: &SignedFindingPurchaseRecord,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let record = &signed.body;
        let admission = self
            .filings
            .admission_by_envelope_sha256(&record.venue_admission_envelope_sha256)
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        if self.envelope_digest(&admission)? != record.venue_admission_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "venue_admission_envelope_sha256",
            ));
        }
        let admission_digest = self.envelope_digest(&admission)?;
        let venue_policy = self
            .filings
            .venue_policy_for_admission(&admission_digest)
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        let venue_authority = self.require_live_role(
            &venue_policy,
            admission.body.issued_at,
            now,
            "historical venue",
        )?;
        verify_signed_admission(&admission, &venue_authority, &self.venue_id)
            .map_err(|error| ChallengeCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        if admission.body.finding_id != record.finding_id
            || admission.body.listing_id != record.listing_id
            || admission.body.backing_allocation_id != identity.allocation_id
            || admission.body.backing_envelope_sha256 != record.seller_backing_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "purchase_record",
            ));
        }
        let policy = &admission.body.purchase_authority;
        policy
            .validate("purchase_authority")
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let retained_pin = FindingAuthorityPin {
            authority_id: policy.authority_id.clone(),
            key_hex: policy.key.to_hex(),
            key_epoch: policy.key_epoch,
            valid_from: policy.valid_from,
            valid_until: policy.valid_until,
            revocation_status_ref: policy.revocation_status_ref.clone(),
        };
        let purchase_authority =
            self.require_live_role(&retained_pin, record.recorded_at, now, "retained purchase")?;
        verify_signed_purchase_record(signed, &purchase_authority)
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))
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

    fn load_retained_finalizing_authorization(
        &self,
        liability_key: &str,
    ) -> Result<(RetainedAuthorizedImpairment, u64), ChallengeCoordinatorError> {
        let stored = self
            .challenges
            .get_finalizing_authorization(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "finalizing liability has no retained authorization".to_owned(),
                )
            })?;
        if sha256_hex(&stored.authorization_json) != stored.authorization_sha256 {
            return Err(ChallengeCoordinatorError::ChallengeStore(
                "retained finalizing authorization digest mismatch".to_owned(),
            ));
        }
        let retained: RetainedAuthorizedImpairment =
            serde_json::from_slice(&stored.authorization_json).map_err(|error| {
                ChallengeCoordinatorError::ChallengeStore(format!(
                    "retained finalizing authorization is invalid: {error}"
                ))
            })?;
        let canonical =
            canonical_json_bytes(&retained).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if canonical != stored.authorization_json {
            return Err(ChallengeCoordinatorError::ChallengeStore(
                "retained finalizing authorization is not canonical".to_owned(),
            ));
        }
        Ok((retained, stored.recorded_at))
    }

    /// Bind a finalization attempt to the immutable authorization retained
    /// with the state transition. The only permitted difference is the
    /// coordinator's authenticated pre-dispatch snapshot refresh: every
    /// semantic field remains byte-for-byte equal, and the configured live
    /// finalization authority signs the new snapshot digest and timestamp.
    fn require_retained_finalizing_authorization(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        allow_snapshot_refresh: bool,
    ) -> Result<(), ChallengeCoordinatorError> {
        let (retained, _) = self.load_retained_finalizing_authorization(liability_key)?;
        if self.envelope_digest(penalty)? != self.envelope_digest(&retained.slash.penalty)? {
            return Err(ChallengeCoordinatorError::Settlement(
                "presented penalty is not the retained finalizing authorization".to_owned(),
            ));
        }
        if self.envelope_digest(enforcement)? == self.envelope_digest(&retained.enforcement)? {
            return Ok(());
        }
        if !allow_snapshot_refresh {
            return Err(ChallengeCoordinatorError::Settlement(
                "presented enforcement is not the retained finalizing authorization".to_owned(),
            ));
        }

        let retained_body = &retained.enforcement.body;
        let body = &enforcement.body;
        if body.bond_snapshot_envelope_sha256 == retained_body.bond_snapshot_envelope_sha256
            || body.finalized_at <= retained_body.finalized_at
            || body.finalization_authority_id != self.finalization_pin.authority_id
            || body.finalization_key != self.finalization_authority.public_key()
            || body.finalization_key_epoch != self.finalization_pin.key_epoch
            || body.finalization_valid_from != self.finalization_pin.valid_from
            || body.finalization_valid_until != self.finalization_pin.valid_until
            || body.finalization_revocation_status_ref
                != self.finalization_pin.revocation_status_ref
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "snapshot refresh is outside the retained authorization".to_owned(),
            ));
        }
        let mut normalized = body.clone();
        normalized.enforcement_id = retained_body.enforcement_id.clone();
        normalized.bond_snapshot_envelope_sha256 =
            retained_body.bond_snapshot_envelope_sha256.clone();
        normalized.finalization_authority_id = retained_body.finalization_authority_id.clone();
        normalized.finalization_key = retained_body.finalization_key.clone();
        normalized.finalization_key_epoch = retained_body.finalization_key_epoch;
        normalized.finalization_valid_from = retained_body.finalization_valid_from;
        normalized.finalization_valid_until = retained_body.finalization_valid_until;
        normalized.finalization_revocation_status_ref =
            retained_body.finalization_revocation_status_ref.clone();
        normalized.finalized_at = retained_body.finalized_at;
        if normalized != *retained_body {
            return Err(ChallengeCoordinatorError::Settlement(
                "snapshot refresh changed retained enforcement semantics".to_owned(),
            ));
        }
        Ok(())
    }

    /// Recover the exact authorization retained atomically with a prior
    /// `pending_appeal -> finalizing` transition.
    fn recover_finalizing_authorization(
        &self,
        record: &FindingLiabilityRecord,
        outcome: &SignedFindingChallengeOutcome,
        sanction_case_id: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        self.require_sanction_governs(&record.liability_key, sanction_case_id)?;
        let (retained, retained_at) =
            self.load_retained_finalizing_authorization(&record.liability_key)?;
        let enforcement = &retained.enforcement;
        enforcement
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        self.require_enforcement_signature(enforcement, now)?;
        let snapshot = self
            .challenges
            .get_claim_snapshot(&record.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
        let sealed = SealedClaimSnapshot {
            liability_key: snapshot.liability_key,
            cutoff_slot: snapshot.cutoff_slot,
            snapshot_digest: snapshot.snapshot_digest,
            allocation_digest: snapshot.allocation_digest,
            total_realized_spend_units: snapshot.total_realized_spend_units,
            distribution: SlashDistribution {
                slash: enforcement.body.amount.clone(),
                buyer_pool_units: snapshot.buyer_pool_units,
                community_fund_units: snapshot.community_fund_units,
                entries: enforcement
                    .body
                    .destinations
                    .iter()
                    .map(|destination| DistributionEntry {
                        destination: destination.destination.clone(),
                        amount_units: destination.amount.units,
                    })
                    .collect(),
            },
        };
        self.require_sealed_matches_store(&record.liability_key, &sealed)?;
        let outcome_digest = self.envelope_digest(outcome)?;
        if retained_at != enforcement.body.finalized_at
            || enforcement.body.liability_key != record.liability_key
            || enforcement.body.finding_id != record.finding_id
            || enforcement.body.listing_id != record.listing_id
            || enforcement.body.outcome_id != outcome.body.outcome_id
            || enforcement.body.outcome_envelope_sha256 != outcome_digest
            || enforcement.body.purchase_snapshot_digest != sealed.snapshot_digest
            || enforcement.body.deterministic_allocation_digest != sealed.allocation_digest
            || enforcement.body.seller_allocation_id != record.allocation_id
            || retained.slash.penalty.body.case_id != sanction_case_id
            || retained.slash.evaluation.penalty_id != retained.slash.penalty.body.penalty_id
            || !retained.slash.evaluation.findings.is_empty()
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "retained finalizing authorization conflicts with the durable liability".to_owned(),
            ));
        }
        self.require_penalty_matches_enforcement(
            record,
            enforcement,
            &retained.slash.penalty,
            now,
        )?;
        let effect_intent_keys = enforcement_effect_intent_keys(enforcement);
        for (kind, key) in &effect_intent_keys {
            let intent = self
                .challenges
                .get_effect_intent(key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
            if intent.kind != *kind
                || intent.liability_key.as_deref() != Some(record.liability_key.as_str())
                || !intent.settlement_required
            {
                return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
            }
        }
        let enforcement_envelope_sha256 = self.envelope_digest(enforcement)?;
        Ok(AppealResolution::Finalizing(Box::new(
            AuthorizedImpairment {
                enforcement: retained.enforcement,
                enforcement_envelope_sha256,
                slash: retained.slash,
                effect_intent_keys,
            },
        )))
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
                root_intent_commitment(liability_key, &slash.penalty_envelope_sha256),
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
                if lock.state != FindingDisputeLockState::Returned {
                    return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
                }
                let collected_fee_key = dispute_fee_intent_key(challenge_id);
                let collected_fee = self
                    .challenges
                    .get_effect_intent(&collected_fee_key)
                    .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                    .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
                if collected_fee.kind != FindingEffectIntentKind::Fee
                    || collected_fee.liability_key.is_some()
                    || collected_fee.settlement_required
                    || collected_fee.state != FindingEffectIntentState::Confirmed
                {
                    return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
                }
                let fee_key = derive_fee_intent_key(liability_key, &collected_fee_key);
                let fee_commitment = format!(
                    "{EFFECT_FEE_DOMAIN}\0collected\0{collected_fee_key}\0{digest}",
                    digest = collected_fee.intent_digest,
                );
                bindings.push(FindingEffectIntentBinding {
                    kind: chio_finding::FindingEffectIntentKind::Fee,
                    intent_id: fee_key.clone(),
                });
                fenced.push((FindingEffectIntentKind::Fee, fee_key, fee_commitment));
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
                    true,
                    now,
                )
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
            if matches!(
                *kind,
                FindingEffectIntentKind::ChallengeBond | FindingEffectIntentKind::Fee
            ) {
                let state = self
                    .challenges
                    .get_effect_intent(key)
                    .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                    .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?
                    .state;
                if state == FindingEffectIntentState::Pending {
                    self.challenges
                        .advance_effect_intent(key, FindingEffectIntentState::Dispatched, now)
                        .map_err(|error| {
                            ChallengeCoordinatorError::ChallengeStore(error.to_string())
                        })?;
                    self.challenges
                        .advance_effect_intent(key, FindingEffectIntentState::Confirmed, now)
                        .map_err(|error| {
                            ChallengeCoordinatorError::ChallengeStore(error.to_string())
                        })?;
                }
            }
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
            penalty_authority_id: self.penalty_pin.authority_id.clone(),
            penalty_key: self.penalty_authority.public_key(),
            penalty_key_epoch: self.penalty_pin.key_epoch,
            penalty_valid_from: self.penalty_pin.valid_from,
            penalty_valid_until: self.penalty_pin.valid_until,
            penalty_revocation_status_ref: self.penalty_pin.revocation_status_ref.clone(),
            finalization_authority_id: self.finalization_pin.authority_id.clone(),
            finalization_key: self.finalization_authority.public_key(),
            finalization_key_epoch: self.finalization_pin.key_epoch,
            finalization_valid_from: self.finalization_pin.valid_from,
            finalization_valid_until: self.finalization_pin.valid_until,
            finalization_revocation_status_ref: self.finalization_pin.revocation_status_ref.clone(),
            finalized_at: now,
        };
        enforcement.enforcement_id = compute_enforcement_id(&enforcement)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        enforcement
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        self.require_live_role(&self.finalization_pin, now, now, "finalization")?;
        let signed =
            SignedFindingChallengeEnforcement::sign(enforcement, &self.finalization_authority)
                .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let enforcement_envelope_sha256 = self.envelope_digest(&signed)?;

        let authorized = AuthorizedImpairment {
            enforcement: signed,
            enforcement_envelope_sha256,
            slash: slash.clone(),
            effect_intent_keys: fenced
                .into_iter()
                .map(|(kind, key, _)| (kind, key))
                .collect(),
        };
        let retained = RetainedAuthorizedImpairment {
            enforcement: authorized.enforcement.clone(),
            slash: authorized.slash.clone(),
        };
        let authorization_json =
            canonical_json_bytes(&retained).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let authorization_sha256 = sha256_hex(&authorization_json);
        self.challenges
            .begin_finalizing_under_sanction(
                liability_key,
                FindingLiabilityState::PendingAppeal,
                &slash.penalty.body.case_id,
                &FindingFinalizingAuthorizationInput {
                    liability_key,
                    authorization_json: &authorization_json,
                    authorization_sha256: &authorization_sha256,
                    recorded_at: now,
                },
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        Ok(AppealResolution::Finalizing(Box::new(authorized)))
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
    /// built from the pinned governance root for the charter, case, and
    /// activation, the exact schedule signer bound by the authenticated
    /// historical admission, and this coordinator's own penalty key. A
    /// key that appears only in an unadmitted artifact never joins that
    /// set, so a self-signed governance case cannot authorize a slash.
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
        issued_at: u64,
        now: u64,
    ) -> Result<FindingPenaltyOutcome, ChallengeCoordinatorError> {
        self.require_live_role(&self.penalty_pin, issued_at, now, "penalty")?;
        let penalty_key = self.penalty_authority.public_key();
        let governance_key = self.require_live_role(
            &self.pins.governance_authority,
            case.body.updated_at,
            now,
            "governance",
        )?;
        self.require_pinned_governance(governance, case, prior_penalty, now)?;
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
            opened_at: Some(issued_at),
            updated_at: Some(issued_at),
            expires_at: governance.penalty_expires_at,
            note: None,
        };
        let trusted = vec![
            governance_key,
            governance.fee_schedule.signer_key.clone(),
            penalty_key,
        ];
        let artifact = build_open_market_penalty_artifact_with_trusted_signers(
            governance.local_operator_id,
            &issue,
            issued_at,
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
    pub(crate) fn evidence_bundle_digest(
        &self,
        challenge: &FindingChallenge,
        evidence: &FindingChallengeClassEvidence<'_>,
    ) -> Result<String, ChallengeCoordinatorError> {
        let bytes = chio_core::canonical_json_bytes(&challenge.evidence)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let (branch, supplemental_digests) = match evidence {
            FindingChallengeClassEvidence::EvidenceInvalid(resolved) => {
                let mut digests = vec![self.envelope_digest(resolved.purchase_record)?];
                for receipt in resolved.challenged_receipts {
                    digests.push(self.resolved_receipt_digest(
                        &receipt.canonical_receipt_bytes,
                        &receipt.inclusion_proof,
                    )?);
                }
                digests.push(self.canonical_digest(resolved.challenged_checkpoint)?);
                digests.push(self.canonical_digest(resolved.checkpoint_transparency)?);
                for proof in resolved.revoked_keys {
                    digests.push(self.envelope_digest(proof.statement)?);
                }
                ("evidence_invalid", digests)
            }
            FindingChallengeClassEvidence::DigestMismatch(resolved) => (
                "digest_mismatch",
                vec![
                    self.envelope_digest(resolved.failed_delivery)?,
                    self.envelope_digest(resolved.failed_delivery_authority_status)?,
                    self.envelope_digest(resolved.delivery_authority_status)?,
                    self.resolved_receipt_digest(
                        &resolved.deny_receipt.canonical_receipt_bytes,
                        &resolved.deny_receipt.inclusion_proof,
                    )?,
                    self.canonical_digest(resolved.deny_checkpoint)?,
                    self.canonical_digest(resolved.checkpoint_transparency)?,
                ],
            ),
            FindingChallengeClassEvidence::ReplayContradiction(resolved) => {
                let mut digests = vec![
                    self.envelope_digest(resolved.purchase_record)?,
                    self.envelope_digest(resolved.replay_authority_status)?,
                ];
                for reproduction in resolved.reproductions {
                    let reproduction_digest = self.canonical_digest(&(
                        self.resolved_receipt_digest(
                            &reproduction.receipt.canonical_receipt_bytes,
                            &reproduction.receipt.inclusion_proof,
                        )?,
                        self.canonical_digest(reproduction.checkpoint)?,
                        self.canonical_digest(reproduction.checkpoint_transparency)?,
                    ))?;
                    digests.push(reproduction_digest);
                }
                ("replay_contradiction", digests)
            }
        };
        let resolved_bytes = self.canonical_bytes(&(branch, supplemental_digests))?;
        let mut preimage = Vec::with_capacity(
            EVIDENCE_BUNDLE_DOMAIN.len() + 1 + bytes.len() + 1 + resolved_bytes.len(),
        );
        preimage.extend_from_slice(EVIDENCE_BUNDLE_DOMAIN.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        preimage.push(0);
        preimage.extend_from_slice(&resolved_bytes);
        Ok(sha256_hex(&preimage))
    }

    fn resolved_receipt_digest<T: Serialize>(
        &self,
        canonical_receipt_bytes: &[u8],
        inclusion_proof: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        self.canonical_digest(&(sha256_hex(canonical_receipt_bytes), inclusion_proof))
    }

    fn canonical_digest<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        Ok(sha256_hex(&self.canonical_bytes(value)?))
    }

    fn canonical_bytes<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, ChallengeCoordinatorError> {
        canonical_json_bytes(value).map_err(|_| ChallengeCoordinatorError::Canonical)
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

fn rail_observation_matches(
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
