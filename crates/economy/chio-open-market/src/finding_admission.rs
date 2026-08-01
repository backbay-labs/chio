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
//!
//! Compiled only under the `cognition-market-experimental` feature; default
//! builds omit this module entirely.

use chio_finding::{
    signed_envelope_sha256, verify_signed_admission, verify_signed_bond_backing,
    verify_signed_market_terms, FindingAdmission, FindingError, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingMarketTerms,
};
use chio_fiscal::FiscalResolver;

use crate::bidding::{bid, BidMintContext, BiddingError, SignedAskResponse, SignedBidRequest};
use crate::crypto::PublicKey;
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
