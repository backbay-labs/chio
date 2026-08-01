//! Admission-gated marketplace entry for cognition-market findings.
//!
//! Trusted bid accepts a finding listing ONLY through a current
//! venue-signed admission bundle. [`verify_finding_admission`] is the pure
//! verifier over externally pinned inputs: venue-pinned strict envelope
//! verification, liveness at the caller's clock, the exact
//! terms/backing/fee-schedule envelope bindings, the fiscal authorization
//! gate, the sizing inequality against the schedule's slashable
//! `Listing`-class requirement, collateral liveness, and the
//! earliest-constituent-expiry bound. It returns the
//! [`VerifiedFindingAdmission`] witness whose existence is the only proof
//! of currency [`bid_with_finding_admission`] accepts before delegating to
//! the real [`bid`] path unchanged.

use chio_finding::{
    signed_envelope_sha256, verify_signed_admission, verify_signed_bond_backing,
    verify_signed_market_terms, FindingAdmission, FindingError, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingMarketTerms,
};
use chio_fiscal::FiscalResolver;

use crate::bidding::{bid, BidMintContext, BiddingError, SignedAskResponse, SignedBidRequest};
use crate::capability::scope::{
    Constraint, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount,
};
use crate::crypto::PublicKey;
use crate::evaluation::OpenMarketPenaltyEvaluation;
use crate::fee_schedule::{OpenMarketBondClass, SignedOpenMarketFeeSchedule};
use crate::fiscal_adapter::{
    authorize_fiscal_open_market_fee_schedule, signed_fee_schedule_digest, verify_legacy_schedule,
    FiscalLegacyFeeScheduleBinding, FiscalOpenMarketError,
};

/// Fee-schedule authorization mode for admission verification.
#[derive(Clone, Copy)]
pub enum FindingFeeScheduleGate<'a> {
    /// No fiscal runtime configured: legacy signer verification only.
    Legacy,
    /// Fiscal governance live: authorize through the resolver, with the
    /// governed-mode binding when applicable.
    Fiscal {
        resolver: &'a FiscalResolver<'a>,
        binding: Option<&'a FiscalLegacyFeeScheduleBinding>,
    },
}

/// Penalty posture for admission verification.
#[derive(Clone, Copy)]
pub enum FindingAdmissionPenaltyGate<'a> {
    /// No penalty lane governs this venue: there is no evaluation to
    /// consult.
    Ungoverned,
    /// The venue's current penalty evaluation for the admitted listing.
    /// A blocking or unresolved evaluation denies the admission.
    Evaluated(&'a OpenMarketPenaltyEvaluation),
}

/// Typed rejections from [`verify_finding_admission`] and
/// [`bid_with_finding_admission`]. Every variant denies.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FindingAdmissionError {
    #[error("admission envelope rejected: {0}")]
    AdmissionEnvelope(FindingError),
    #[error("admission is not yet live at the verification time")]
    AdmissionNotYetLive,
    #[error("admission has expired at the verification time")]
    AdmissionExpired,
    #[error("terms envelope digest does not match the admission binding")]
    TermsDigestMismatch,
    #[error("terms envelope rejected: {0}")]
    TermsEnvelope(FindingError),
    #[error("backing envelope digest does not match the admission binding")]
    BackingDigestMismatch,
    #[error("backing envelope rejected: {0}")]
    BackingEnvelope(FindingError),
    #[error("backing allocation id does not match the admission binding")]
    AllocationMismatch,
    #[error("terms identity does not match the admission finding or listing")]
    TermsIdentityMismatch,
    #[error("backing identity does not match the admission finding or listing")]
    BackingIdentityMismatch,
    #[error("backing commits different terms, profile, or fee schedule than the admission")]
    BackingBindingMismatch,
    #[error("backing allocation snapshot does not match the admission or backing envelope")]
    AllocationSnapshotMismatch,
    #[error("backing allocation has expired at the verification time")]
    AllocationExpired,
    #[error("backing allocation has been released")]
    AllocationReleased,
    #[error("backing allocation is not available for activation")]
    AllocationUnavailableForActivation,
    #[error("admission is not active for the consumed backing allocation")]
    AdmissionNotActiveForAllocation,
    #[error("verifier report claims bond backing before the allocation existed")]
    BondObservationBeforeAllocation,
    #[error("penalty evaluation does not name the admitted listing")]
    PenaltyEvaluationMismatch,
    #[error("penalty evaluation carries findings and establishes nothing")]
    PenaltyEvaluationUnresolved,
    #[error("an enforced penalty blocks admission for this listing")]
    AdmissionBlockedByPenalty,
    #[error("fee schedule envelope digest does not match the admission binding")]
    FeeScheduleDigestMismatch,
    #[error("fee schedule envelope rejected: {0}")]
    FeeScheduleEnvelope(FiscalOpenMarketError),
    #[error("fee schedule rejected by the fiscal authorization gate: {0}")]
    FeeScheduleUnauthorized(FiscalOpenMarketError),
    #[error("fee schedule defines no Listing-class bond requirement")]
    ListingRequirementMissing,
    #[error("Listing-class bond requirement is not slashable")]
    ListingRequirementNotSlashable,
    #[error("requirement, stake, exposure, and locked amount currencies must all match")]
    CurrencyMismatch,
    #[error("base_finding_stake + maximum_sale_exposure overflows u64")]
    BackingSumOverflow,
    #[error("Listing-class requirement is below base_finding_stake + maximum_sale_exposure")]
    ListingRequirementUndersized,
    #[error("backing locked amount is below base_finding_stake + maximum_sale_exposure")]
    BackingUnderfunded,
    #[error("admission expires after a constituent bound: {0}")]
    ExpiryBeyondConstituent(&'static str),
    #[error("admission capability scope does not match the listing pricing hint scope")]
    ScopeMismatch,
    #[error("bid listing is not the listing the admission was issued for")]
    ListingMismatch,
    #[error("bid pricing hint is not the hint the admission binds")]
    PricingHintMismatch,
    #[error("bid rejected: {0}")]
    Bidding(BiddingError),
    #[error("finding artifact is not the finding the admission was issued for")]
    FindingMismatch,
    #[error("finding is not yet live at the purchase clock")]
    FindingNotYetLive,
    #[error("finding has expired at the purchase clock")]
    FindingExpired,
    #[error("finding payload digest is not canonical lowercase 64-hex")]
    FindingDigestMalformed,
    #[error("purchase mint requires the caller to leave grant authorship to the provider")]
    MintContextPreoccupied,
    #[error("purchase bid must request exactly one invocation")]
    InvocationCardinality,
    #[error("purchase token offer violates the single-grant delivery profile")]
    TokenOfferProfile,
    #[error("purchase amounts must be exactly equal in units and currency")]
    AmountMismatch,
}

/// Lifecycle state of the allocation named by a finding admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingAllocationStatus {
    /// Registered and still available for one activation transaction.
    Available,
    /// Atomically consumed by an active admission.
    Consumed,
    /// Its signed backing window has elapsed.
    Expired,
    /// Its collateral has been released.
    Released,
}

/// Fresh point-in-time view of the backing allocation named by the
/// admission, taken from the venue collateral store by the caller. Exact
/// identity and envelope bindings prevent a snapshot for another
/// allocation from supplying lifecycle evidence here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingAllocationSnapshot {
    pub allocation_id: String,
    pub backing_envelope_sha256: String,
    pub expires_at: u64,
    pub status: FindingAllocationStatus,
    /// Present only when this allocation is consumed by the named active
    /// admission. The store derives this from the active-admission row in
    /// the same snapshot transaction.
    pub active_admission_id: Option<String>,
    /// Present only while an exact durable activation prepare owns the
    /// consumed allocation but has not published its active admission.
    pub prepared_admission_id: Option<String>,
    /// Venue trusted time when the collateral authority registered the
    /// allocation (the report-before-backing ordering input).
    pub accepted_at: u64,
}

/// Expiry windows resolved from the signed constituents that are supplied
/// to the activation surface but represented only by digests in the
/// admission verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingConstituentExpiryBounds {
    pub finding: u64,
    pub listing: u64,
    pub pricing_hint: u64,
    pub seller_authorization: u64,
    pub profile: u64,
}

/// Externally pinned inputs for [`verify_finding_admission`]. Every
/// authority here comes from deployment configuration, never from the
/// admission itself.
#[derive(Clone)]
pub struct FindingAdmissionContext<'a> {
    /// Configured venue authority key the admission must verify under.
    pub venue_authority: &'a PublicKey,
    /// Configured venue identity the admission body must name.
    pub venue_id: &'a str,
    /// Unix seconds at verification; both admission liveness bounds are
    /// checked against it.
    pub now: u64,
    /// The exact signed fee schedule the admission binds by envelope
    /// digest.
    pub fee_schedule: &'a SignedOpenMarketFeeSchedule,
    /// Fee-schedule authorization gate. With no fiscal runtime the
    /// schedule verifies as a legacy artifact against the trusted
    /// operator signers (the issuance precedent); with fiscal governance
    /// live it authorizes through the resolver.
    pub fee_schedule_gate: FindingFeeScheduleGate<'a>,
    /// Trusted open-market governing authority signers.
    pub trusted_local_operator_signers: &'a [PublicKey],
    /// The seller-signed terms envelope the admission binds by digest.
    pub terms: &'a SignedFindingMarketTerms,
    /// The collateral-authority-signed backing envelope the admission
    /// binds by digest.
    pub backing: &'a SignedFindingBondBacking,
    /// Fresh allocation-state snapshot for the named backing allocation.
    pub allocation_snapshot: FindingAllocationSnapshot,
    /// The instant the verifier report affirmed bond backing, or `None`
    /// when the report made no affirmative bond claim. An affirmative
    /// observation must postdate the allocation's registration: a report
    /// evaluated before the allocation existed observed some other
    /// collateral, whatever its verdict names.
    pub bond_backing_observed_at: Option<u64>,
    /// Penalty posture for the admitted listing. A venue that runs the
    /// penalty lane resolves the listing's current evaluation and passes
    /// it here; a listing under an enforced hold or slash never
    /// re-admits.
    pub penalty_gate: FindingAdmissionPenaltyGate<'a>,
    /// Configured collateral authority key the backing must verify under.
    pub collateral_authority: &'a PublicKey,
    /// Explicit expiry bounds for constituents the admission carries only
    /// as digests, resolved by the caller that holds their exact bytes.
    pub constituent_expiry_bounds: FindingConstituentExpiryBounds,
}

/// Witness that a signed admission passed every check in
/// [`verify_finding_admission`] against pinned inputs. Construction is
/// private; holding one is the only proof of admission currency the bid
/// seam accepts.
#[derive(Debug, Clone)]
pub struct VerifiedFindingAdmission {
    admission: FindingAdmission,
}

impl VerifiedFindingAdmission {
    /// The verified admission body.
    #[must_use]
    pub fn admission(&self) -> &FindingAdmission {
        &self.admission
    }

    /// The admitted finding id.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.admission.finding_id
    }

    /// The admitted listing id.
    #[must_use]
    pub fn listing_id(&self) -> &str {
        &self.admission.listing_id
    }

    /// The exact `finding:<finding_id>` capability scope the admission
    /// qualifies.
    #[must_use]
    pub fn capability_scope(&self) -> &str {
        &self.admission.capability_scope
    }

    /// Unix seconds when the admission stops being current.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.admission.expires_at
    }
}

/// Verify a venue-signed admission bundle against externally pinned
/// inputs for a current bid. The allocation must already be consumed by
/// this exact active admission.
pub fn verify_finding_admission(
    signed: &SignedFindingAdmission,
    context: &FindingAdmissionContext<'_>,
) -> Result<VerifiedFindingAdmission, FindingAdmissionError> {
    verify_finding_admission_inner(signed, context, AllocationRequirement::ActiveAdmission)
}

/// Verify the same signed bindings immediately before the durable
/// activation transaction. This check cannot produce a bid witness: it
/// accepts only an available, admission-unbound allocation that the store
/// transaction will consume atomically.
pub fn verify_finding_admission_for_activation(
    signed: &SignedFindingAdmission,
    context: &FindingAdmissionContext<'_>,
) -> Result<(), FindingAdmissionError> {
    verify_finding_admission_inner(
        signed,
        context,
        AllocationRequirement::AvailableForActivation,
    )
    .map(|_| ())
}

#[derive(Debug, Clone, Copy)]
enum AllocationRequirement {
    AvailableForActivation,
    ActiveAdmission,
}

fn verify_finding_admission_inner(
    signed: &SignedFindingAdmission,
    context: &FindingAdmissionContext<'_>,
    allocation_requirement: AllocationRequirement,
) -> Result<VerifiedFindingAdmission, FindingAdmissionError> {
    verify_signed_admission(signed, context.venue_authority, context.venue_id)
        .map_err(FindingAdmissionError::AdmissionEnvelope)?;
    let admission = &signed.body;

    // Liveness at the caller's clock, both bounds.
    if context.now < admission.issued_at {
        return Err(FindingAdmissionError::AdmissionNotYetLive);
    }
    if context.now >= admission.expires_at {
        return Err(FindingAdmissionError::AdmissionExpired);
    }

    // A listing under an enforced hold or slash must not re-enter the
    // market through a fresh admission. The evaluation consulted here has
    // to be for this exact listing, and one that failed to establish the
    // penalty state proves nothing and therefore admits nothing.
    match context.penalty_gate {
        FindingAdmissionPenaltyGate::Ungoverned => {}
        FindingAdmissionPenaltyGate::Evaluated(evaluation) => {
            if evaluation.listing_id != admission.listing_id {
                return Err(FindingAdmissionError::PenaltyEvaluationMismatch);
            }
            if !evaluation.findings.is_empty() {
                return Err(FindingAdmissionError::PenaltyEvaluationUnresolved);
            }
            if evaluation.blocks_admission {
                return Err(FindingAdmissionError::AdmissionBlockedByPenalty);
            }
        }
    }

    // The exact seller-signed terms envelope, bound by digest.
    let terms_digest =
        signed_envelope_sha256(context.terms).map_err(FindingAdmissionError::TermsEnvelope)?;
    if terms_digest != admission.terms_envelope_sha256 {
        return Err(FindingAdmissionError::TermsDigestMismatch);
    }
    verify_signed_market_terms(context.terms).map_err(FindingAdmissionError::TermsEnvelope)?;
    if context.terms.body.finding_id != admission.finding_id
        || context.terms.body.finding_artifact_sha256 != admission.finding_artifact_sha256
        || context.terms.body.listing_id != admission.listing_id
        || context.terms.body.verifier_profile_envelope_sha256 != admission.profile_envelope_sha256
    {
        return Err(FindingAdmissionError::TermsIdentityMismatch);
    }

    // The exact backing envelope, bound by digest and verified under the
    // pinned collateral authority.
    let backing_digest =
        signed_envelope_sha256(context.backing).map_err(FindingAdmissionError::BackingEnvelope)?;
    if backing_digest != admission.backing_envelope_sha256 {
        return Err(FindingAdmissionError::BackingDigestMismatch);
    }
    verify_signed_bond_backing(context.backing, context.collateral_authority)
        .map_err(FindingAdmissionError::BackingEnvelope)?;
    if context.backing.body.allocation_id != admission.backing_allocation_id {
        return Err(FindingAdmissionError::AllocationMismatch);
    }
    if context.backing.body.finding_id != admission.finding_id
        || context.backing.body.listing_id != admission.listing_id
        || context.backing.body.seller != context.terms.body.seller
    {
        return Err(FindingAdmissionError::BackingIdentityMismatch);
    }
    let snapshot = &context.allocation_snapshot;
    if snapshot.allocation_id != context.backing.body.allocation_id
        || snapshot.backing_envelope_sha256 != backing_digest
        || snapshot.expires_at != context.backing.body.expires_at
    {
        return Err(FindingAdmissionError::AllocationSnapshotMismatch);
    }
    if context.now >= snapshot.expires_at || snapshot.status == FindingAllocationStatus::Expired {
        return Err(FindingAdmissionError::AllocationExpired);
    }
    if snapshot.status == FindingAllocationStatus::Released {
        return Err(FindingAdmissionError::AllocationReleased);
    }
    match allocation_requirement {
        AllocationRequirement::AvailableForActivation => {
            let available = snapshot.status == FindingAllocationStatus::Available
                && snapshot.active_admission_id.is_none()
                && snapshot.prepared_admission_id.is_none();
            let exact_prepared_replay = snapshot.status == FindingAllocationStatus::Consumed
                && snapshot.active_admission_id.is_none()
                && snapshot.prepared_admission_id.as_deref()
                    == Some(admission.admission_id.as_str());
            if !available && !exact_prepared_replay {
                return Err(FindingAdmissionError::AllocationUnavailableForActivation);
            }
        }
        AllocationRequirement::ActiveAdmission => {
            if snapshot.status != FindingAllocationStatus::Consumed
                || snapshot.active_admission_id.as_deref() != Some(admission.admission_id.as_str())
                || snapshot.prepared_admission_id.is_some()
            {
                return Err(FindingAdmissionError::AdmissionNotActiveForAllocation);
            }
        }
    }
    // Report-before-backing ordering: collateral registered at or after
    // an affirmative observation cannot be what that observation saw.
    if let Some(observed_at) = context.bond_backing_observed_at {
        if context.allocation_snapshot.accepted_at >= observed_at {
            return Err(FindingAdmissionError::BondObservationBeforeAllocation);
        }
    }

    // The exact signed fee schedule, bound by digest, authorized by the
    // fiscal governance gate.
    let schedule_digest = signed_fee_schedule_digest(context.fee_schedule)
        .map_err(FindingAdmissionError::FeeScheduleEnvelope)?;
    if schedule_digest != admission.fee_schedule_envelope_sha256 {
        return Err(FindingAdmissionError::FeeScheduleDigestMismatch);
    }
    match context.fee_schedule_gate {
        FindingFeeScheduleGate::Legacy => {
            verify_legacy_schedule(context.fee_schedule, context.trusted_local_operator_signers)
                .map_err(FindingAdmissionError::FeeScheduleUnauthorized)?;
        }
        FindingFeeScheduleGate::Fiscal { resolver, binding } => {
            authorize_fiscal_open_market_fee_schedule(
                context.fee_schedule,
                binding,
                resolver,
                context.trusted_local_operator_signers,
            )
            .map_err(FindingAdmissionError::FeeScheduleUnauthorized)?;
        }
    }

    // Sizing inequality: the schedule's slashable Listing-class
    // requirement (unique after the duplicate-bond-class rejection the
    // authorization gate just enforced) must cover the promised backing,
    // and the locked collateral must too, all in one currency.
    let requirement = context
        .fee_schedule
        .body
        .bond_requirements
        .iter()
        .find(|requirement| requirement.bond_class == OpenMarketBondClass::Listing)
        .ok_or(FindingAdmissionError::ListingRequirementMissing)?;
    if !requirement.slashable {
        return Err(FindingAdmissionError::ListingRequirementNotSlashable);
    }
    let stake = &context.terms.body.backing_requirement.base_finding_stake;
    let exposure = &context.terms.body.backing_requirement.maximum_sale_exposure;
    let locked = &context.backing.body.locked_amount;
    if requirement.required_amount.currency != stake.currency
        || stake.currency != exposure.currency
        || exposure.currency != locked.currency
    {
        return Err(FindingAdmissionError::CurrencyMismatch);
    }
    let promised_backing = context
        .terms
        .body
        .backing_requirement
        .required_backing_units()
        .map_err(|_| FindingAdmissionError::BackingSumOverflow)?;
    if requirement.required_amount.units < promised_backing {
        return Err(FindingAdmissionError::ListingRequirementUndersized);
    }
    if locked.units < promised_backing {
        return Err(FindingAdmissionError::BackingUnderfunded);
    }

    // Admission expiry never outlives a constituent: the windows supplied
    // in full here, the authority policy snapshots the admission body
    // itself carries, and every digest-only constituent resolved by the
    // caller.
    let expiry_bounds = [
        (context.terms.body.expires_at, "terms"),
        (context.backing.body.expires_at, "backing"),
        (
            admission.purchase_authority.valid_until,
            "purchase_authority",
        ),
        (
            admission.failed_delivery_authority.valid_until,
            "failed_delivery_authority",
        ),
        (context.constituent_expiry_bounds.finding, "finding"),
        (context.constituent_expiry_bounds.listing, "listing"),
        (
            context.constituent_expiry_bounds.pricing_hint,
            "pricing_hint",
        ),
        (
            context.constituent_expiry_bounds.seller_authorization,
            "seller_authorization",
        ),
        (context.constituent_expiry_bounds.profile, "profile"),
        // A schedule with no expiry never lapses, so absence is an
        // unbounded ceiling rather than a missing bound.
        (
            context.fee_schedule.body.expires_at.unwrap_or(u64::MAX),
            "fee_schedule",
        ),
    ];
    for (bound, label) in expiry_bounds {
        if admission.expires_at > bound {
            return Err(FindingAdmissionError::ExpiryBeyondConstituent(label));
        }
    }

    // The allocation commits the terms, profile, and fee schedule it was
    // sized against. Without these equalities an allocation minted for one
    // set of terms could back an admission citing another.
    if context.backing.body.terms_envelope_sha256 != admission.terms_envelope_sha256
        || context.backing.body.profile_envelope_sha256 != admission.profile_envelope_sha256
        || context.backing.body.fee_schedule_envelope_sha256
            != admission.fee_schedule_envelope_sha256
    {
        return Err(FindingAdmissionError::BackingBindingMismatch);
    }

    Ok(VerifiedFindingAdmission {
        admission: admission.clone(),
    })
}

/// Bid on an admitted finding listing through the real marketplace path.
///
/// The witness's existence proves admission currency; this seam only
/// asserts the admission qualifies exactly the scope the listing pricing
/// hint advertises, then delegates to [`bid`] unchanged.
pub fn bid_with_finding_admission(
    request: &SignedBidRequest,
    bid_context: BidMintContext<'_>,
    admission: &VerifiedFindingAdmission,
) -> Result<SignedAskResponse, FindingAdmissionError> {
    // The witness certifies bindings as of its own verification time, so
    // spending it later must re-check currency against the bid clock.
    if bid_context.now >= admission.expires_at() {
        return Err(FindingAdmissionError::AdmissionExpired);
    }
    // Scope equality alone binds nothing: every listing for one finding
    // advertises the same `finding:<id>` scope, so a bid could ride an
    // admission issued for a different listing. Bind the exact listing
    // and pricing-hint envelopes the admission was signed over.
    if bid_context.listing.pricing.body.capability_scope != admission.capability_scope() {
        return Err(FindingAdmissionError::ScopeMismatch);
    }
    if bid_context.listing.listing_id() != admission.listing_id() {
        return Err(FindingAdmissionError::ListingMismatch);
    }
    let listing_digest = signed_envelope_sha256(&bid_context.listing.listing)
        .map_err(FindingAdmissionError::AdmissionEnvelope)?;
    if listing_digest != admission.admission().listing_envelope_sha256 {
        return Err(FindingAdmissionError::ListingMismatch);
    }
    let hint_digest = signed_envelope_sha256(&bid_context.listing.pricing)
        .map_err(FindingAdmissionError::AdmissionEnvelope)?;
    if hint_digest != admission.admission().pricing_hint_envelope_sha256 {
        return Err(FindingAdmissionError::PricingHintMismatch);
    }
    bid(request, bid_context).map_err(FindingAdmissionError::Bidding)
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Mint a delivery-committed purchase ask for an admitted finding.
///
/// The provider, not the buyer, authors the grant bindings: exactly one
/// output-digest constraint equal to the signed finding's payload
/// commitment and exactly one purchase marker naming the admitted finding
/// and listing under the local reversible-hold rail, with a mandatory DPoP
/// binding and a single invocation. The caller supplies a mint context with
/// no constraints of its own; a preoccupied context is rejected rather than
/// merged so grant authorship stays unambiguous.
///
/// The finding's liveness bounds are re-checked at the mint clock: the
/// artifact validator is deliberately clockless, so currency is this
/// caller's responsibility.
pub fn bid_with_finding_purchase(
    request: &SignedBidRequest,
    mut bid_context: BidMintContext<'_>,
    admission: &VerifiedFindingAdmission,
    finding: &chio_finding::Finding,
) -> Result<SignedAskResponse, FindingAdmissionError> {
    if !bid_context.grant_constraints.is_empty() || bid_context.dpop_required.is_some() {
        return Err(FindingAdmissionError::MintContextPreoccupied);
    }
    if finding.finding_id != admission.finding_id() {
        return Err(FindingAdmissionError::FindingMismatch);
    }
    if !is_lowercase_sha256_hex(&finding.payload_sha256) {
        return Err(FindingAdmissionError::FindingDigestMalformed);
    }
    if bid_context.now < finding.issued_at {
        return Err(FindingAdmissionError::FindingNotYetLive);
    }
    if bid_context.now >= finding.expires_at {
        return Err(FindingAdmissionError::FindingExpired);
    }
    if request.body.requested_scope.max_invocations != Some(1) {
        return Err(FindingAdmissionError::InvocationCardinality);
    }
    bid_context.grant_constraints = vec![
        Constraint::OutputDigestSha256(finding.payload_sha256.clone()),
        Constraint::RequireFindingPurchase(Box::new(FindingPurchaseMarkerV1 {
            finding_id: finding.finding_id.clone(),
            listing_id: admission.listing_id().to_string(),
            settlement: FindingSettlementSelector::LocalReversibleHold,
        })),
    ];
    bid_context.dpop_required = Some(true);
    bid_with_finding_admission(request, bid_context, admission)
}

/// Accept a delivery-committed purchase ask against the authoritative
/// reservation, enforcing the exact single-grant delivery profile and
/// exact amount equality before delegating to the unchanged pure
/// [`accept`](crate::bidding::accept).
///
/// The pure accept path tolerates a reservation that covers at least the
/// token liability; a purchase requires exact equality across the quoted
/// price, both grant ceilings, and the reserved amount, all in one
/// currency, so an oversized reservation cannot mask a mispriced mint.
pub fn accept_finding_purchase(
    ask: &SignedAskResponse,
    reservation: &crate::bidding::VerifiedReservationReceipt,
    acceptor_keypair: &crate::crypto::Keypair,
    accepted_at: u64,
    admission: &VerifiedFindingAdmission,
    finding: &chio_finding::Finding,
) -> Result<crate::bidding::SignedAcceptedBid, FindingAdmissionError> {
    if finding.finding_id != admission.finding_id() {
        return Err(FindingAdmissionError::FindingMismatch);
    }
    let grants = &ask.body.token_offer.scope.grants;
    let [grant] = grants.as_slice() else {
        return Err(FindingAdmissionError::TokenOfferProfile);
    };
    if grant.max_invocations != Some(1)
        || grant.dpop_required != Some(true)
        || !ask.body.token_offer.scope.resource_grants.is_empty()
        || !ask.body.token_offer.scope.prompt_grants.is_empty()
    {
        return Err(FindingAdmissionError::TokenOfferProfile);
    }
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest)
        } else {
            None
        }
    });
    match (digests.next(), digests.next()) {
        (Some(digest), None) if digest == &finding.payload_sha256 => {}
        _ => return Err(FindingAdmissionError::TokenOfferProfile),
    }
    let mut markers = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::RequireFindingPurchase(marker) = constraint {
            Some(marker)
        } else {
            None
        }
    });
    match (markers.next(), markers.next()) {
        (Some(marker), None)
            if marker.finding_id == finding.finding_id
                && marker.listing_id == admission.listing_id()
                && marker.settlement == FindingSettlementSelector::LocalReversibleHold => {}
        _ => return Err(FindingAdmissionError::TokenOfferProfile),
    }
    let price = &ask.body.quoted_price;
    let exact =
        |amount: &MonetaryAmount| amount.units == price.units && amount.currency == price.currency;
    if !grant.max_cost_per_invocation.as_ref().is_some_and(exact)
        || !grant.max_total_cost.as_ref().is_some_and(exact)
        || !exact(reservation.reserved_amount())
    {
        return Err(FindingAdmissionError::AmountMismatch);
    }
    crate::bidding::accept(ask, reservation, acceptor_keypair, accepted_at)
        .map_err(FindingAdmissionError::Bidding)
}
