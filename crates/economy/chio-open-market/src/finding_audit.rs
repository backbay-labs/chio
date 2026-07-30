//! Verifiable target selection for one published-rate audit round.
//!
//! A published audit rate is an operator assumption unless the round fixes
//! its inputs before it samples and anyone can replay the sample afterwards.
//! `chio.finding.audit-epoch.v1` commits the eligible listing snapshot, the
//! rate, the algorithm, and a commitment to the randomness; this module is
//! the algorithm that commitment names, and `chio.finding.audit-report.v1`
//! is the round it later has to answer for.
//!
//! Everything here is a pure function of committed bytes: no clock, no
//! random source, no storage, no network. A buyer, the venue, and an
//! external auditor derive the same targets from the same epoch, seed, and
//! snapshot, and every input that would let a venue choose the outcome
//! after the fact is refused rather than tolerated: a seed outside the
//! published commitment, a substituted or resized eligible snapshot, and an
//! algorithm identifier this module does not implement.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use chio_core_types::hashing::sha256;
use chio_finding::{
    derive_audit_seed_commitment, FindingAuditEpoch, FindingAuditReport, FindingError,
    MAX_AUDIT_SELECTION, MAX_FINDING_IDENTIFIER_BYTES, MAX_PUBLISHED_RATE_BPS,
};

use crate::capability::scope::MonetaryAmount;

/// The selection algorithm this module implements, named exactly as an
/// epoch must name it.
///
/// The identifier is part of the precommitment: an epoch that names another
/// algorithm is refused here rather than sampled with this one. A change to
/// the draw, the ordering, or the rounding is a new identifier, never a
/// quiet change of behavior under this one.
pub const AUDIT_SELECTION_ALGORITHM_V1: &str = "chio.finding.audit-selection.weighted-draw.v1";

/// Domain separator for the per-listing draw. The trailing NUL keeps the
/// separator unambiguous against the seed that follows it.
const AUDIT_DRAW_DOMAIN: &[u8] = b"chio.finding.audit-draw.v1\0";

/// Domain separator for the canonical eligible-snapshot digest.
const ELIGIBLE_SNAPSHOT_DOMAIN: &[u8] = b"chio.finding.audit-eligible-snapshot.v1\0";

/// Basis-point denominator for the published rate.
const BPS_DENOMINATOR: u128 = 10_000;

/// The weight an entry carries when it names none.
const DEFAULT_ELIGIBLE_WEIGHT: u64 = 1;

/// One listing of the eligible snapshot an epoch commits to.
///
/// The snapshot is the round's entire universe: a listing absent from it can
/// never be selected, which is why the epoch commits its digest and its
/// count before the seed is revealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleListing {
    /// Content-addressed finding identity, 64 lowercase hex characters, the
    /// same shape a report's selection list carries.
    pub finding_id: String,
    /// The backed listing the finding is sold through.
    pub listing_id: String,
    /// Relative selection weight, where a larger weight is audited more
    /// often. `None` is exactly weight 1: both encode identically into the
    /// snapshot digest and the ordering, so a caller and an auditor cannot
    /// disagree about an omitted weight.
    pub weight_or_none: Option<u64>,
}

impl EligibleListing {
    fn weight(&self) -> u64 {
        self.weight_or_none.unwrap_or(DEFAULT_ELIGIBLE_WEIGHT)
    }

    fn validate(&self) -> Result<(), FindingAuditError> {
        if !is_hex64(&self.finding_id) {
            return Err(FindingAuditError::InvalidEligibleField("finding_id"));
        }
        if self.listing_id.trim().is_empty()
            || self.listing_id.len() > MAX_FINDING_IDENTIFIER_BYTES
            || self.listing_id.chars().any(char::is_control)
        {
            return Err(FindingAuditError::InvalidEligibleField("listing_id"));
        }
        // A zero weight silently shrinks the eligible universe below the
        // count the epoch committed to, so it is refused rather than
        // treated as an unselectable listing.
        if self.weight_or_none == Some(0) {
            return Err(FindingAuditError::InvalidEligibleField("weight_or_none"));
        }
        Ok(())
    }
}

/// One selected audit target, in selection order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSelection {
    pub finding_id: String,
    pub listing_id: String,
    /// The effective weight the draw was scaled by.
    pub weight: u64,
    /// The listing's draw for this round, as the full lowercase hex digest
    /// of its domain-separated preimage, so a third party can recheck one
    /// target without recomputing the round.
    pub draw: String,
}

/// Typed rejections. Every variant refuses to produce or accept a selection
/// rather than proceeding on an input the epoch did not commit to.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FindingAuditError {
    #[error("audit epoch rejected: {0}")]
    Epoch(FindingError),
    #[error("audit report rejected: {0}")]
    Report(FindingError),
    #[error("epoch names selection algorithm {0}, which this module does not implement")]
    UnsupportedAlgorithm(String),
    #[error("revealed seed is not a 64 character lowercase hex value")]
    InvalidSeed,
    #[error("revealed seed does not reproduce the epoch's seed commitment")]
    SeedCommitmentMismatch,
    #[error("epoch committed {committed} eligible listings, {presented} were presented")]
    EligibleCountMismatch { committed: u64, presented: u64 },
    #[error("eligible snapshot digest does not equal the epoch's committed digest")]
    SnapshotDigestMismatch,
    #[error("eligible snapshot names finding {0} more than once")]
    DuplicateEligibleListing(String),
    #[error("eligible listing field {0} is not well formed")]
    InvalidEligibleField(&'static str),
    #[error("published rate {0} bps exceeds one hundred percent")]
    RateOutOfRange(u64),
    #[error("rate implies {target} targets, above the {bound} a report can carry")]
    SelectionExceedsReportBound { target: usize, bound: usize },
    #[error("per-attempt cost is denominated differently from the epoch budget")]
    AttemptCostCurrencyMismatch,
    #[error("per-attempt cost must be greater than zero")]
    ZeroAttemptCost,
    #[error("report does not bind the presented epoch envelope digest")]
    EpochEnvelopeMismatch,
    #[error("epoch envelope digest is not a 64 character lowercase hex value")]
    InvalidEpochEnvelopeDigest,
    #[error("report selects finding {0}, which this round did not select")]
    UnexpectedSelection(String),
    #[error("report omits selected finding {0}")]
    MissingSelection(String),
    #[error("{attempted} selected findings were attempted but only {attempt_receipts} attempt receipts account for them")]
    UnaccountedSelection {
        attempted: usize,
        attempt_receipts: usize,
    },
    #[error("{attempt_receipts} attempt receipts exceed the {attempted} attempted selections")]
    ExtraneousAttempt {
        attempted: usize,
        attempt_receipts: usize,
    },
    #[error("{outcomes} signed outcomes exceed the {attempted} attempted selections")]
    ExtraneousOutcome { attempted: usize, outcomes: usize },
    #[error("audit arithmetic exceeded its representable range")]
    Overflow,
}

/// Derive one listing's draw for a round.
///
/// The preimage is domain-separated and then binds the revealed seed to the
/// listing identity, so a draw computed for one round or one listing is
/// meaningless for any other, and no listing identity can be shifted into
/// another's draw by concatenation.
#[must_use]
pub fn derive_audit_draw(revealed_seed: &str, finding_id: &str, listing_id: &str) -> String {
    audit_draw(revealed_seed, finding_id, listing_id).0
}

/// Digest of the canonical eligible snapshot.
///
/// This is the value an epoch commits as `eligible_snapshot_digest`. It is
/// domain-separated, taken over the entries sorted by finding id, and binds
/// the entry count and every effective weight, so the caller that publishes
/// the epoch and the auditor that rechecks it derive it identically from
/// any ordering of the same set.
pub fn derive_eligible_snapshot_digest(
    eligible: &[EligibleListing],
) -> Result<String, FindingAuditError> {
    let ordered = canonical_eligible(eligible)?;
    Ok(snapshot_digest_of(&ordered))
}

/// The number of targets a published rate implies over an eligible count.
///
/// Rounding is UP: a published rate is a floor on how much of the venue is
/// audited, so any nonzero rate over a nonempty eligible set selects at
/// least one listing, and a small venue cannot round its obligation away.
/// The result never exceeds the eligible count, because the rate itself is
/// bounded at one hundred percent.
pub fn audit_target_count(
    published_rate_bps: u64,
    eligible_count: u64,
) -> Result<u64, FindingAuditError> {
    if published_rate_bps > MAX_PUBLISHED_RATE_BPS {
        return Err(FindingAuditError::RateOutOfRange(published_rate_bps));
    }
    let numerator = u128::from(eligible_count)
        .checked_mul(u128::from(published_rate_bps))
        .ok_or(FindingAuditError::Overflow)?;
    u64::try_from(numerator.div_ceil(BPS_DENOMINATOR)).map_err(|_| FindingAuditError::Overflow)
}

/// Select the round's audit targets from the revealed seed.
///
/// The algorithm, pinned as [`AUDIT_SELECTION_ALGORITHM_V1`]:
///
/// 1. Validate the epoch, require it to name this algorithm, and require the
///    revealed seed to reproduce its published seed commitment.
/// 2. Sort the eligible snapshot canonically by finding id, require its
///    count and its digest to equal the values the epoch committed, and
///    refuse a snapshot that names any finding twice.
/// 3. Compute the target count from the published rate, rounding up.
/// 4. Draw each listing as `sha256(domain, seed, finding_id, listing_id)`
///    and order by the exact rational priority `draw / weight`, smallest
///    first, comparing by cross multiplication so no rounding enters the
///    order. With uniform weights this is exactly an ordering by draw; a
///    larger weight moves a listing earlier. Equal priorities break by
///    finding id ascending, which is a total order because finding ids are
///    unique in the snapshot.
/// 5. Take the first target count entries.
///
/// There is no random source: the seed is the only entropy, and it was
/// committed before the snapshot could be shaped around it.
pub fn select_audit_targets(
    epoch: &FindingAuditEpoch,
    revealed_seed: &str,
    eligible: &[EligibleListing],
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_targets(epoch, revealed_seed, eligible, None)
}

/// Select the round's audit targets, capped by what the committed budget
/// can pay for at `per_attempt_cost`.
///
/// The cap is a planning bound for the venue running the round, never a
/// verification rule: the epoch commits a budget but not a per-attempt
/// cost, so an external auditor cannot reproduce the cap and
/// [`verify_audit_report`] always re-runs the uncapped selection. A round
/// that cannot fund every target still owes the report a missed-attempt
/// entry, with its reason, for each target it did not attempt.
///
/// The capped result is a prefix of [`select_audit_targets`], so the two
/// never disagree about which listings come first.
pub fn select_audit_targets_within_budget(
    epoch: &FindingAuditEpoch,
    revealed_seed: &str,
    eligible: &[EligibleListing],
    per_attempt_cost: &MonetaryAmount,
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_targets(epoch, revealed_seed, eligible, Some(per_attempt_cost))
}

/// Verify a published audit report against its epoch, as an independent
/// auditor.
///
/// The report is bound to its epoch by ENVELOPE digest, so the round it
/// answers for is the exact signed artifact the caller presents, not merely
/// one with equal contents. From the seed the report reveals, the selection
/// is re-run here and the report's selected set must equal it exactly: an
/// added target, a dropped target, or a seed outside the commitment each
/// reject with their own error.
///
/// Accounting is then complete in both directions. Every selected finding is
/// either recorded as a missed attempt with a reason or attempted, and each
/// attempted selection owes exactly one attempt receipt, so a round can
/// neither drop a target silently nor pad its receipts. Attempt receipt and
/// outcome identifiers are opaque to the report, so they are held to that
/// exact count rather than matched per finding; a lane that keys receipts to
/// findings can tighten this to a per-finding match.
///
/// Selection order is not part of the report's contract: the artifact's
/// list carries no ordering semantics, so set equality is required and the
/// ordered form stays with [`select_audit_targets`].
pub fn verify_audit_report(
    epoch: &FindingAuditEpoch,
    epoch_envelope_sha256: &str,
    report: &FindingAuditReport,
    eligible: &[EligibleListing],
) -> Result<(), FindingAuditError> {
    if !is_hex64(epoch_envelope_sha256) {
        return Err(FindingAuditError::InvalidEpochEnvelopeDigest);
    }
    report.validate().map_err(FindingAuditError::Report)?;
    if report.audit_epoch_envelope_sha256 != epoch_envelope_sha256 {
        return Err(FindingAuditError::EpochEnvelopeMismatch);
    }

    let expected = select_audit_targets(epoch, &report.revealed_seed, eligible)?;
    let expected_ids: BTreeSet<&str> = expected
        .iter()
        .map(|selection| selection.finding_id.as_str())
        .collect();
    let reported_ids: BTreeSet<&str> = report
        .selected_finding_ids
        .iter()
        .map(String::as_str)
        .collect();
    for reported in &reported_ids {
        if !expected_ids.contains(reported) {
            return Err(FindingAuditError::UnexpectedSelection(
                (*reported).to_owned(),
            ));
        }
    }
    for selection in &expected {
        if !reported_ids.contains(selection.finding_id.as_str()) {
            return Err(FindingAuditError::MissingSelection(
                selection.finding_id.clone(),
            ));
        }
    }

    // Misses are unique and inside the selection by the report's own
    // validation, which the equality above has just tied to this round.
    let attempted = expected_ids
        .len()
        .checked_sub(report.missed_attempts.len())
        .ok_or(FindingAuditError::Overflow)?;
    let attempt_receipts = report.attempt_receipt_ids.len();
    match attempt_receipts.cmp(&attempted) {
        Ordering::Less => {
            return Err(FindingAuditError::UnaccountedSelection {
                attempted,
                attempt_receipts,
            })
        }
        Ordering::Greater => {
            return Err(FindingAuditError::ExtraneousAttempt {
                attempted,
                attempt_receipts,
            })
        }
        Ordering::Equal => {}
    }
    let outcomes = report.outcome_envelope_digests.len();
    if outcomes > attempted {
        return Err(FindingAuditError::ExtraneousOutcome {
            attempted,
            outcomes,
        });
    }
    Ok(())
}

/// One drawn candidate, carrying the numeric draw the ordering compares.
struct DrawnListing {
    selection: AuditSelection,
    value: u64,
}

fn select_targets(
    epoch: &FindingAuditEpoch,
    revealed_seed: &str,
    eligible: &[EligibleListing],
    per_attempt_cost: Option<&MonetaryAmount>,
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    epoch.validate().map_err(FindingAuditError::Epoch)?;
    if epoch.selection_algorithm_id != AUDIT_SELECTION_ALGORITHM_V1 {
        return Err(FindingAuditError::UnsupportedAlgorithm(
            epoch.selection_algorithm_id.clone(),
        ));
    }
    // The seed must be exactly what a report can reveal, so a round can
    // never be selected from a seed no valid report could carry.
    if !is_hex64(revealed_seed) {
        return Err(FindingAuditError::InvalidSeed);
    }
    if derive_audit_seed_commitment(revealed_seed) != epoch.seed_commitment {
        return Err(FindingAuditError::SeedCommitmentMismatch);
    }

    let ordered = canonical_eligible(eligible)?;
    let presented = u64::try_from(ordered.len()).map_err(|_| FindingAuditError::Overflow)?;
    if presented != epoch.eligible_listing_count {
        return Err(FindingAuditError::EligibleCountMismatch {
            committed: epoch.eligible_listing_count,
            presented,
        });
    }
    if snapshot_digest_of(&ordered) != epoch.eligible_snapshot_digest {
        return Err(FindingAuditError::SnapshotDigestMismatch);
    }

    let mut target = usize::try_from(audit_target_count(epoch.published_rate_bps, presented)?)
        .map_err(|_| FindingAuditError::Overflow)?;
    // A round that cannot be reported cannot be run: refuse rather than
    // quietly audit fewer listings than the published rate promises.
    if target > MAX_AUDIT_SELECTION {
        return Err(FindingAuditError::SelectionExceedsReportBound {
            target,
            bound: MAX_AUDIT_SELECTION,
        });
    }
    if let Some(cost) = per_attempt_cost {
        target = target.min(affordable_attempts(&epoch.available_budget, cost)?);
    }

    let mut drawn: Vec<DrawnListing> = ordered
        .iter()
        .map(|entry| {
            let (draw, value) = audit_draw(revealed_seed, &entry.finding_id, &entry.listing_id);
            DrawnListing {
                selection: AuditSelection {
                    finding_id: entry.finding_id.clone(),
                    listing_id: entry.listing_id.clone(),
                    weight: entry.weight(),
                    draw,
                },
                value,
            }
        })
        .collect();
    drawn.sort_by(compare_priority);
    drawn.truncate(target);
    Ok(drawn.into_iter().map(|entry| entry.selection).collect())
}

/// Order by the exact rational priority `draw / weight`, smallest first.
///
/// The comparison is a cross multiplication of two `u64` values widened to
/// `u128`, so it is exact and cannot overflow. Ties break by finding id,
/// which is a total order over a snapshot whose finding ids are unique.
fn compare_priority(left: &DrawnListing, right: &DrawnListing) -> Ordering {
    let left_key = u128::from(left.value) * u128::from(right.selection.weight);
    let right_key = u128::from(right.value) * u128::from(left.selection.weight);
    left_key
        .cmp(&right_key)
        .then_with(|| left.selection.finding_id.cmp(&right.selection.finding_id))
}

fn canonical_eligible(
    eligible: &[EligibleListing],
) -> Result<Vec<&EligibleListing>, FindingAuditError> {
    let mut ordered: Vec<&EligibleListing> = Vec::with_capacity(eligible.len());
    for entry in eligible {
        entry.validate()?;
        ordered.push(entry);
    }
    ordered.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    for pair in ordered.windows(2) {
        if pair[0].finding_id == pair[1].finding_id {
            return Err(FindingAuditError::DuplicateEligibleListing(
                pair[0].finding_id.clone(),
            ));
        }
    }
    Ok(ordered)
}

/// Digest the canonically ordered snapshot.
///
/// Fields are NUL-delimited, which is unambiguous because every field is
/// validated free of control characters before it reaches the preimage.
fn snapshot_digest_of(ordered: &[&EligibleListing]) -> String {
    let mut preimage = Vec::with_capacity(ELIGIBLE_SNAPSHOT_DOMAIN.len() + ordered.len() * 96);
    preimage.extend_from_slice(ELIGIBLE_SNAPSHOT_DOMAIN);
    preimage.extend_from_slice(ordered.len().to_string().as_bytes());
    preimage.push(0);
    for entry in ordered {
        preimage.extend_from_slice(entry.finding_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(entry.listing_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(entry.weight().to_string().as_bytes());
        preimage.push(0);
    }
    sha256(&preimage).to_hex()
}

fn audit_draw(revealed_seed: &str, finding_id: &str, listing_id: &str) -> (String, u64) {
    let mut preimage = Vec::with_capacity(
        AUDIT_DRAW_DOMAIN.len() + revealed_seed.len() + finding_id.len() + listing_id.len() + 2,
    );
    preimage.extend_from_slice(AUDIT_DRAW_DOMAIN);
    preimage.extend_from_slice(revealed_seed.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(finding_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(listing_id.as_bytes());
    let digest = sha256(&preimage);
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    (digest.to_hex(), u64::from_be_bytes(head))
}

fn affordable_attempts(
    available_budget: &MonetaryAmount,
    per_attempt_cost: &MonetaryAmount,
) -> Result<usize, FindingAuditError> {
    if available_budget.currency != per_attempt_cost.currency {
        return Err(FindingAuditError::AttemptCostCurrencyMismatch);
    }
    if per_attempt_cost.units == 0 {
        return Err(FindingAuditError::ZeroAttemptCost);
    }
    let affordable = available_budget.units / per_attempt_cost.units;
    // A budget larger than any addressable selection funds every target.
    Ok(usize::try_from(affordable).unwrap_or(usize::MAX))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
