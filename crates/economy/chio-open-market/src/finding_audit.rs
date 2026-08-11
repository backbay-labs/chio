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

use chio_core_types::crypto::PublicKey;
use chio_core_types::hashing::sha256;
use chio_finding::{
    audit_epoch_precommitment_sha256, derive_audit_seed_commitment, signed_envelope_sha256,
    verify_outcome_challenge_binding, verify_signed_audit_epoch, verify_signed_audit_report,
    verify_signed_audit_round_authorization, verify_signed_authority_status,
    verify_signed_challenge, verify_signed_challenge_outcome, FindingAuditEpoch,
    FindingAuthorityKeyPolicy, FindingChallengeAuthorization, FindingChallengeAuthorizationKind,
    FindingError, SignedFindingAuditEpoch, SignedFindingAuditReport,
    SignedFindingAuditRoundAuthorization, SignedFindingAuthorityStatus, SignedFindingChallenge,
    SignedFindingChallengeOutcome, MAX_AUDIT_SELECTION, MAX_FINDING_IDENTIFIER_BYTES,
    MAX_PUBLISHED_RATE_BPS,
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

/// Maximum age of an evaluator status reading at report publication.
const MAX_AUDIT_STATUS_AGE_SECS: u64 = 3_600;

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

/// Externally resolved authorities and signed attempt/outcome artifacts for
/// one report verification. Grouping the witness set keeps the verifier API
/// explicit without an error-prone positional authority list.
pub struct FindingAuditReportWitnesses<'a> {
    /// Governance-pinned lifecycle policy for the independent randomness
    /// witness that committed the seed before it was revealed.
    pub pinned_seed_witness_policy: FindingAuthorityKeyPolicy,
    /// Governance-authenticated lifecycle policy for the authority that
    /// signs the epoch, attempts, and report.
    pub pinned_audit_policy: FindingAuthorityKeyPolicy,
    pub pinned_governance_policy: FindingAuthorityKeyPolicy,
    pub round_authorization: SignedFindingAuditRoundAuthorization,
    pub pinned_status_authority: PublicKey,
    /// Fresh post-publication status for the audit authority policy.
    pub audit_status: SignedFindingAuthorityStatus,
    /// Fresh authenticated status covering the instant the seed witness
    /// signed its commitment.
    pub seed_witness_status: SignedFindingAuthorityStatus,
    /// Fresh status reading for the exact governance policy that authorized
    /// this round. It must cover the authorization instant and remain fresh
    /// at report publication.
    pub governance_status: SignedFindingAuthorityStatus,
    /// Governance-authenticated historical evaluator policies. Every
    /// outcome resolves its own exact policy from this set, so a rotation
    /// during a round does not invalidate earlier outcomes or let an
    /// outcome self-authorize its signer.
    pub pinned_evaluator_policies: &'a [FindingAuthorityKeyPolicy],
    /// Authenticated status readings for the exact historical evaluator
    /// policies used by this report. Each reading must be fresh at report
    /// publication and cover its outcome's evaluation time.
    pub evaluator_statuses: Vec<SignedFindingAuthorityStatus>,
    pub audit_attempts: &'a [SignedFindingChallenge],
    pub resolved_outcomes: &'a [SignedFindingChallengeOutcome],
}

/// Typed rejections. Every variant refuses to produce or accept a selection
/// rather than proceeding on an input the epoch did not commit to.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FindingAuditError {
    #[error("audit epoch rejected: {0}")]
    Epoch(FindingError),
    #[error("audit report rejected: {0}")]
    Report(FindingError),
    #[error("audit authority policy rejected: {0}")]
    AuditAuthorityPolicy(FindingError),
    #[error("audit authority policy does not cover the signed round")]
    AuditAuthorityWindow,
    #[error("audit authority status rejected: {0}")]
    AuditAuthorityStatus(FindingError),
    #[error("audit authority status does not bind the pinned policy")]
    AuditAuthorityStatusBinding,
    #[error("audit authority status is not a fresh post-report reading")]
    AuditAuthorityStatusStale,
    #[error("audit authority was revoked when it published the report")]
    AuditAuthorityRevoked,
    #[error("audit seed-witness policy rejected: {0}")]
    SeedWitnessPolicy(FindingError),
    #[error("audit seed-witness policy does not cover the signed commitment")]
    SeedWitnessWindow,
    #[error("audit seed-witness status rejected: {0}")]
    SeedWitnessStatus(FindingError),
    #[error("audit seed-witness status does not bind the pinned policy")]
    SeedWitnessStatusBinding,
    #[error("audit seed-witness status is not fresh at report publication")]
    SeedWitnessStatusStale,
    #[error("audit seed witness was revoked when it signed the commitment")]
    SeedWitnessRevoked,
    #[error("audit round authorization rejected: {0}")]
    RoundAuthorization(FindingError),
    #[error("audit epoch does not bind its governance authorization")]
    RoundAuthorizationBinding,
    #[error("audit governance authorization was not live at epoch commitment")]
    RoundAuthorizationWindow,
    #[error("audit governance status rejected: {0}")]
    GovernanceStatus(FindingError),
    #[error("audit governance status does not bind the authorization policy")]
    GovernanceStatusBinding,
    #[error("audit governance status is not a fresh post-authorization reading")]
    GovernanceStatusStale,
    #[error("audit governance authority was revoked when it authorized the round")]
    GovernanceAuthorityRevoked,
    #[error("epoch names selection algorithm {0}, which this module does not implement")]
    UnsupportedAlgorithm(String),
    #[error("revealed seed is not a 64 character lowercase hex value")]
    InvalidSeed,
    #[error("revealed seed does not reproduce the epoch's seed commitment")]
    SeedCommitmentMismatch,
    #[error("audit epoch randomness witness does not match the deployment pin")]
    RandomnessWitnessMismatch,
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
    #[error("audit report must be published strictly after its epoch commitment")]
    ReportNotAfterEpoch,
    #[error("report selects finding {0}, which this round did not select")]
    UnexpectedSelection(String),
    #[error("report omits selected finding {0}")]
    MissingSelection(String),
    #[error("{attempted} selected findings were attempted but only {attempt_envelopes} signed attempt envelopes account for them")]
    UnaccountedSelection {
        attempted: usize,
        attempt_envelopes: usize,
    },
    #[error(
        "{attempt_envelopes} signed attempt envelopes exceed the {attempted} attempted selections"
    )]
    ExtraneousAttempt {
        attempted: usize,
        attempt_envelopes: usize,
    },
    #[error("{outcomes} signed outcomes exceed the {attempted} attempted selections")]
    ExtraneousOutcome { attempted: usize, outcomes: usize },
    #[error("{attempted} selected findings were attempted but only {outcomes} signed outcomes account for them")]
    MissingOutcome { attempted: usize, outcomes: usize },
    #[error("audit outcome rejected: {0}")]
    Outcome(FindingError),
    #[error("audit outcome {0} has no exact authenticated evaluator policy")]
    OutcomeAuthorityNotEstablished(String),
    #[error("audit outcome {0} has no exact authenticated evaluator status")]
    OutcomeStatusNotEstablished(String),
    #[error("audit evaluator status rejected: {0}")]
    OutcomeStatus(FindingError),
    #[error("audit outcome {0} has conflicting evaluator status readings at the same time")]
    OutcomeStatusConflict(String),
    #[error("audit outcome {0} has no fresh post-evaluation status reading")]
    OutcomeStatusStale(String),
    #[error("audit outcome {0} was signed by a revoked evaluator")]
    OutcomeEvaluatorRevoked(String),
    #[error("audit attempt rejected: {0}")]
    Attempt(FindingError),
    #[error("audit attempt {0} did not use the venue-audit authorization branch")]
    AttemptAuthorization(String),
    #[error("audit attempt {0} does not bind this audit epoch envelope")]
    AttemptRoundBinding(String),
    #[error("audit attempt {0} was not filed inside the committed report interval")]
    AttemptTimeBinding(String),
    #[error("audit attempt {0} does not name one attempted selection")]
    AttemptSelectionBinding(String),
    #[error("more than one signed attempt names attempted finding {0}")]
    DuplicateAttempt(String),
    #[error("signed attempt envelope {0} is absent from the report")]
    AttemptDigestMismatch(String),
    #[error("audit outcome {0} does not resolve one reported attempt")]
    OutcomeAttemptBinding(String),
    #[error("audit outcome {0} did not use the venue-audit authorization branch")]
    OutcomeAuthorization(String),
    #[error("audit outcome {0} does not bind this audit epoch envelope")]
    OutcomeRoundBinding(String),
    #[error("audit outcome {0} was not evaluated inside the committed report interval")]
    OutcomeTimeBinding(String),
    #[error("audit outcome {0} does not name one attempted selection")]
    OutcomeSelectionBinding(String),
    #[error("more than one signed outcome names attempted finding {0}")]
    DuplicateOutcome(String),
    #[error("signed outcome envelope {0} is absent from the report")]
    OutcomeDigestMismatch(String),
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
///    first, where the draw is the whole 256-bit digest read big-endian.
///    The comparison is a cross multiplication over every bit of both
///    draws, so neither rounding nor truncation enters the order. With
///    uniform weights this is exactly an ordering by draw; a larger weight
///    moves a listing earlier. Equal priorities break by finding id
///    ascending, which is a total order because finding ids are unique in
///    the snapshot.
/// 5. Take the first target count entries.
///
/// There is no random source: the seed is the only entropy, and it was
/// committed before the snapshot could be shaped around it.
pub fn select_audit_targets(
    epoch: &FindingAuditEpoch,
    pinned_seed_witness: &PublicKey,
    revealed_seed: &str,
    eligible: &[EligibleListing],
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_targets(epoch, pinned_seed_witness, revealed_seed, eligible, None)
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
    pinned_seed_witness: &PublicKey,
    revealed_seed: &str,
    eligible: &[EligibleListing],
    per_attempt_cost: &MonetaryAmount,
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_targets(
        epoch,
        pinned_seed_witness,
        revealed_seed,
        eligible,
        Some(per_attempt_cost),
    )
}

/// Verify a published signed audit report against its signed epoch, as an
/// independent auditor.
///
/// The report is bound to its epoch by ENVELOPE digest, so the round it
/// answers for is the exact signed artifact the caller presents, not merely
/// one with equal contents. From the seed the report reveals, the selection
/// is re-run here and the report's selected set must equal it exactly: an
/// added target, a dropped target, or a seed outside the commitment each
/// reject with their own error.
///
/// The bound epoch is validated before the report time is compared, and the
/// report must be published strictly after the epoch commitment. A report
/// cannot attest to a seed reveal or selection that had not yet been
/// committed.
///
/// Accounting is then complete in both directions. Every selected finding is
/// either recorded as a missed attempt with a reason or attempted, and each
/// attempted selection owes exactly one signed attempt envelope and one
/// resolved, evaluator-signed outcome. The outcome must name that selection, use the
/// venue-audit authorization branch, carry this exact epoch envelope from its
/// signed challenge authorization, and be evaluated after commitment but no
/// later than publication.
/// The report must carry the digest of each exact signed outcome envelope.
///
/// Selection order is not part of the report's contract: the artifact's
/// list carries no ordering semantics, so set equality is required and the
/// ordered form stays with [`select_audit_targets`].
pub fn verify_audit_report(
    epoch: &SignedFindingAuditEpoch,
    report: &SignedFindingAuditReport,
    eligible: &[EligibleListing],
    witnesses: &FindingAuditReportWitnesses<'_>,
) -> Result<(), FindingAuditError> {
    witnesses
        .pinned_seed_witness_policy
        .validate("audit seed witness policy")
        .map_err(FindingAuditError::SeedWitnessPolicy)?;
    witnesses
        .pinned_audit_policy
        .validate("audit authority policy")
        .map_err(FindingAuditError::AuditAuthorityPolicy)?;
    verify_signed_audit_epoch(
        epoch,
        &witnesses.pinned_audit_policy.key,
        &witnesses.pinned_seed_witness_policy.key,
    )
    .map_err(FindingAuditError::Epoch)?;
    verify_signed_audit_report(report, &witnesses.pinned_audit_policy.key)
        .map_err(FindingAuditError::Report)?;
    if report.body.reported_at <= epoch.body.committed_at {
        return Err(FindingAuditError::ReportNotAfterEpoch);
    }
    if epoch.body.committed_at < witnesses.pinned_audit_policy.valid_from
        || report.body.reported_at >= witnesses.pinned_audit_policy.valid_until
    {
        return Err(FindingAuditError::AuditAuthorityWindow);
    }
    verify_signed_authority_status(&witnesses.audit_status, &witnesses.pinned_status_authority)
        .map_err(FindingAuditError::AuditAuthorityStatus)?;
    let audit_status = &witnesses.audit_status.body;
    if audit_status.status_ref != witnesses.pinned_audit_policy.revocation_status_ref
        || audit_status.authority_id != witnesses.pinned_audit_policy.authority_id
        || audit_status.key != witnesses.pinned_audit_policy.key
        || audit_status.key_epoch != witnesses.pinned_audit_policy.key_epoch
    {
        return Err(FindingAuditError::AuditAuthorityStatusBinding);
    }
    if audit_status.observed_at < report.body.reported_at
        || audit_status
            .observed_at
            .saturating_sub(report.body.reported_at)
            > MAX_AUDIT_STATUS_AGE_SECS
    {
        return Err(FindingAuditError::AuditAuthorityStatusStale);
    }
    if audit_status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= report.body.reported_at)
    {
        return Err(FindingAuditError::AuditAuthorityRevoked);
    }
    if epoch.body.seed_witnessed_at < witnesses.pinned_seed_witness_policy.valid_from
        || epoch.body.seed_witnessed_at >= witnesses.pinned_seed_witness_policy.valid_until
    {
        return Err(FindingAuditError::SeedWitnessWindow);
    }
    verify_signed_authority_status(
        &witnesses.seed_witness_status,
        &witnesses.pinned_status_authority,
    )
    .map_err(FindingAuditError::SeedWitnessStatus)?;
    let seed_status = &witnesses.seed_witness_status.body;
    if seed_status.status_ref != witnesses.pinned_seed_witness_policy.revocation_status_ref
        || seed_status.authority_id != witnesses.pinned_seed_witness_policy.authority_id
        || seed_status.key != witnesses.pinned_seed_witness_policy.key
        || seed_status.key_epoch != witnesses.pinned_seed_witness_policy.key_epoch
    {
        return Err(FindingAuditError::SeedWitnessStatusBinding);
    }
    if seed_status.observed_at < epoch.body.seed_witnessed_at
        || seed_status.observed_at > report.body.reported_at
        || report
            .body
            .reported_at
            .saturating_sub(seed_status.observed_at)
            > MAX_AUDIT_STATUS_AGE_SECS
    {
        return Err(FindingAuditError::SeedWitnessStatusStale);
    }
    if seed_status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= epoch.body.seed_witnessed_at)
    {
        return Err(FindingAuditError::SeedWitnessRevoked);
    }
    witnesses
        .pinned_governance_policy
        .validate("audit governance policy")
        .map_err(FindingAuditError::RoundAuthorization)?;
    verify_signed_audit_round_authorization(
        &witnesses.round_authorization,
        &witnesses.pinned_governance_policy.key,
    )
    .map_err(FindingAuditError::RoundAuthorization)?;
    let authorization_digest = signed_envelope_sha256(&witnesses.round_authorization)
        .map_err(FindingAuditError::RoundAuthorization)?;
    if epoch.body.authorization_digest != authorization_digest
        || witnesses
            .round_authorization
            .body
            .epoch_precommitment_sha256
            != audit_epoch_precommitment_sha256(&epoch.body)
                .map_err(FindingAuditError::RoundAuthorization)?
    {
        return Err(FindingAuditError::RoundAuthorizationBinding);
    }
    if witnesses.round_authorization.body.authorized_at
        < witnesses.pinned_governance_policy.valid_from
        || witnesses.round_authorization.body.authorized_at
            >= witnesses.pinned_governance_policy.valid_until
        || witnesses.round_authorization.body.authorized_at > epoch.body.committed_at
        || witnesses.round_authorization.body.expires_at <= epoch.body.committed_at
    {
        return Err(FindingAuditError::RoundAuthorizationWindow);
    }
    let epoch_envelope_sha256 = signed_envelope_sha256(epoch).map_err(FindingAuditError::Epoch)?;
    let epoch = &epoch.body;
    let report = &report.body;
    if report.audit_epoch_envelope_sha256 != epoch_envelope_sha256 {
        return Err(FindingAuditError::EpochEnvelopeMismatch);
    }

    let expected = select_audit_targets(
        epoch,
        &witnesses.pinned_seed_witness_policy.key,
        &report.revealed_seed,
        eligible,
    )?;
    verify_signed_authority_status(
        &witnesses.governance_status,
        &witnesses.pinned_status_authority,
    )
    .map_err(FindingAuditError::GovernanceStatus)?;
    let governance_status = &witnesses.governance_status.body;
    if governance_status.status_ref != witnesses.pinned_governance_policy.revocation_status_ref
        || governance_status.authority_id != witnesses.pinned_governance_policy.authority_id
        || governance_status.key != witnesses.pinned_governance_policy.key
        || governance_status.key_epoch != witnesses.pinned_governance_policy.key_epoch
    {
        return Err(FindingAuditError::GovernanceStatusBinding);
    }
    let authorized_at = witnesses.round_authorization.body.authorized_at;
    if governance_status.observed_at < authorized_at
        || governance_status.observed_at > report.reported_at
        || report
            .reported_at
            .saturating_sub(governance_status.observed_at)
            > MAX_AUDIT_STATUS_AGE_SECS
    {
        return Err(FindingAuditError::GovernanceStatusStale);
    }
    if governance_status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= authorized_at)
    {
        return Err(FindingAuditError::GovernanceAuthorityRevoked);
    }
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
    let attempt_envelopes = report.attempt_envelope_sha256s.len();
    match attempt_envelopes.cmp(&attempted) {
        Ordering::Less => {
            return Err(FindingAuditError::UnaccountedSelection {
                attempted,
                attempt_envelopes,
            })
        }
        Ordering::Greater => {
            return Err(FindingAuditError::ExtraneousAttempt {
                attempted,
                attempt_envelopes,
            })
        }
        Ordering::Equal => {}
    }
    let outcomes = report.outcome_envelope_digests.len();
    match outcomes.cmp(&attempted) {
        Ordering::Less => {
            return Err(FindingAuditError::MissingOutcome {
                attempted,
                outcomes,
            })
        }
        Ordering::Greater => {
            return Err(FindingAuditError::ExtraneousOutcome {
                attempted,
                outcomes,
            })
        }
        Ordering::Equal => {}
    }
    match witnesses.resolved_outcomes.len().cmp(&attempted) {
        Ordering::Less => {
            return Err(FindingAuditError::MissingOutcome {
                attempted,
                outcomes: witnesses.resolved_outcomes.len(),
            })
        }
        Ordering::Greater => {
            return Err(FindingAuditError::ExtraneousOutcome {
                attempted,
                outcomes: witnesses.resolved_outcomes.len(),
            })
        }
        Ordering::Equal => {}
    }

    let missed: BTreeSet<&str> = report
        .missed_attempts
        .iter()
        .map(|missed| missed.finding_id.as_str())
        .collect();
    let attempted_selections: BTreeSet<(&str, &str)> = expected
        .iter()
        .filter(|selection| !missed.contains(selection.finding_id.as_str()))
        .map(|selection| (selection.finding_id.as_str(), selection.listing_id.as_str()))
        .collect();
    match witnesses.audit_attempts.len().cmp(&attempted) {
        Ordering::Less => {
            return Err(FindingAuditError::UnaccountedSelection {
                attempted,
                attempt_envelopes: witnesses.audit_attempts.len(),
            })
        }
        Ordering::Greater => {
            return Err(FindingAuditError::ExtraneousAttempt {
                attempted,
                attempt_envelopes: witnesses.audit_attempts.len(),
            })
        }
        Ordering::Equal => {}
    }
    let reported_attempt_digests: BTreeSet<&str> = report
        .attempt_envelope_sha256s
        .iter()
        .map(String::as_str)
        .collect();
    let mut resolved_attempts = Vec::with_capacity(witnesses.audit_attempts.len());
    let mut attempted_once = BTreeSet::new();
    for signed in witnesses.audit_attempts {
        verify_signed_challenge(signed, &witnesses.pinned_audit_policy.key)
            .map_err(FindingAuditError::Attempt)?;
        let challenge = &signed.body;
        let FindingChallengeAuthorization::VenueAudit(authorization) = &challenge.authorization
        else {
            return Err(FindingAuditError::AttemptAuthorization(
                challenge.challenge_id.clone(),
            ));
        };
        if authorization.audit_epoch_envelope_sha256 != epoch_envelope_sha256 {
            return Err(FindingAuditError::AttemptRoundBinding(
                challenge.challenge_id.clone(),
            ));
        }
        if challenge.filed_at <= epoch.committed_at || challenge.filed_at > report.reported_at {
            return Err(FindingAuditError::AttemptTimeBinding(
                challenge.challenge_id.clone(),
            ));
        }
        let selection = (challenge.finding_id.as_str(), challenge.listing_id.as_str());
        if !attempted_selections.contains(&selection) {
            return Err(FindingAuditError::AttemptSelectionBinding(
                challenge.challenge_id.clone(),
            ));
        }
        if !attempted_once.insert(selection) {
            return Err(FindingAuditError::DuplicateAttempt(
                challenge.finding_id.clone(),
            ));
        }
        let envelope_digest = signed_envelope_sha256(signed).map_err(FindingAuditError::Attempt)?;
        if !reported_attempt_digests.contains(envelope_digest.as_str()) {
            return Err(FindingAuditError::AttemptDigestMismatch(envelope_digest));
        }
        resolved_attempts.push((envelope_digest, signed));
    }
    let reported_digests: BTreeSet<&str> = report
        .outcome_envelope_digests
        .iter()
        .map(String::as_str)
        .collect();
    let mut resolved_selections = BTreeSet::new();
    for signed in witnesses.resolved_outcomes {
        let outcome = &signed.body;
        let Some(policy) = witnesses.pinned_evaluator_policies.iter().find(|policy| {
            policy.authority_id == outcome.evaluator_authority_id
                && policy.key == outcome.evaluator_key
                && policy.key_epoch == outcome.evaluator_key_epoch
                && policy.valid_from == outcome.evaluator_valid_from
                && policy.valid_until == outcome.evaluator_valid_until
                && policy.revocation_status_ref == outcome.evaluator_revocation_status_ref
        }) else {
            return Err(FindingAuditError::OutcomeAuthorityNotEstablished(
                outcome.outcome_id.clone(),
            ));
        };
        policy
            .validate("audit evaluator policy")
            .map_err(FindingAuditError::Outcome)?;
        let mut latest_status: Option<&SignedFindingAuthorityStatus> = None;
        for status in witnesses.evaluator_statuses.iter().filter(|status| {
            status.body.status_ref == policy.revocation_status_ref
                && status.body.authority_id == policy.authority_id
                && status.body.key == policy.key
                && status.body.key_epoch == policy.key_epoch
        }) {
            verify_signed_authority_status(status, &witnesses.pinned_status_authority)
                .map_err(FindingAuditError::OutcomeStatus)?;
            match latest_status {
                None => latest_status = Some(status),
                Some(latest) => match status.body.observed_at.cmp(&latest.body.observed_at) {
                    Ordering::Greater => latest_status = Some(status),
                    Ordering::Equal if status.body.revoked_from != latest.body.revoked_from => {
                        return Err(FindingAuditError::OutcomeStatusConflict(
                            outcome.outcome_id.clone(),
                        ));
                    }
                    Ordering::Equal | Ordering::Less => {}
                },
            }
        }
        let Some(status) = latest_status else {
            return Err(FindingAuditError::OutcomeStatusNotEstablished(
                outcome.outcome_id.clone(),
            ));
        };
        if status.body.observed_at < outcome.evaluated_at
            || status.body.observed_at > report.reported_at
            || report.reported_at.saturating_sub(status.body.observed_at)
                > MAX_AUDIT_STATUS_AGE_SECS
        {
            return Err(FindingAuditError::OutcomeStatusStale(
                outcome.outcome_id.clone(),
            ));
        }
        if status
            .body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= outcome.evaluated_at)
        {
            return Err(FindingAuditError::OutcomeEvaluatorRevoked(
                outcome.outcome_id.clone(),
            ));
        }
        verify_signed_challenge_outcome(signed, &policy.key).map_err(FindingAuditError::Outcome)?;
        if outcome.authorization != FindingChallengeAuthorizationKind::VenueAudit {
            return Err(FindingAuditError::OutcomeAuthorization(
                outcome.outcome_id.clone(),
            ));
        }
        if outcome.audit_epoch_envelope_sha256.as_deref() != Some(epoch_envelope_sha256.as_str()) {
            return Err(FindingAuditError::OutcomeRoundBinding(
                outcome.outcome_id.clone(),
            ));
        }
        if outcome.evaluated_at <= epoch.committed_at || outcome.evaluated_at > report.reported_at {
            return Err(FindingAuditError::OutcomeTimeBinding(
                outcome.outcome_id.clone(),
            ));
        }
        let selection = (outcome.finding_id.as_str(), outcome.listing_id.as_str());
        if !attempted_selections.contains(&selection) {
            return Err(FindingAuditError::OutcomeSelectionBinding(
                outcome.outcome_id.clone(),
            ));
        }
        if !resolved_selections.insert(selection) {
            return Err(FindingAuditError::DuplicateOutcome(
                outcome.finding_id.clone(),
            ));
        }
        let Some((_, attempt)) = resolved_attempts
            .iter()
            .find(|(digest, _)| digest == &outcome.challenge_envelope_sha256)
        else {
            return Err(FindingAuditError::OutcomeAttemptBinding(
                outcome.outcome_id.clone(),
            ));
        };
        if outcome.evaluated_at < attempt.body.filed_at {
            return Err(FindingAuditError::OutcomeTimeBinding(
                outcome.outcome_id.clone(),
            ));
        }
        verify_outcome_challenge_binding(outcome, attempt).map_err(FindingAuditError::Outcome)?;
        if outcome.evidence_kind != attempt.body.evidence.kind()
            || outcome.verifier_profile_envelope_sha256 != attempt.body.profile_envelope_sha256
        {
            return Err(FindingAuditError::OutcomeAttemptBinding(
                outcome.outcome_id.clone(),
            ));
        }
        let envelope_digest = signed_envelope_sha256(signed).map_err(FindingAuditError::Outcome)?;
        if !reported_digests.contains(envelope_digest.as_str()) {
            return Err(FindingAuditError::OutcomeDigestMismatch(envelope_digest));
        }
    }
    Ok(())
}

/// One listing's draw as the integer the ordering compares it as: the
/// digest read big-endian, in 64-bit limbs, most significant first.
type DrawValue = [u64; 4];

/// A draw scaled by a weight. A 256-bit draw times a 64-bit weight needs
/// 320 bits, so the scaled form is one limb wider than the draw.
type ScaledDraw = [u64; 5];

/// One drawn candidate, carrying the numeric draw the ordering compares.
struct DrawnListing {
    selection: AuditSelection,
    /// The same value as `selection.draw`, in the form the weighted
    /// ordering compares. The hex form is what a third party rechecks.
    draw: DrawValue,
}

fn select_targets(
    epoch: &FindingAuditEpoch,
    pinned_seed_witness: &PublicKey,
    revealed_seed: &str,
    eligible: &[EligibleListing],
    per_attempt_cost: Option<&MonetaryAmount>,
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    epoch.validate().map_err(FindingAuditError::Epoch)?;
    if epoch.seed_witness != *pinned_seed_witness {
        return Err(FindingAuditError::RandomnessWitnessMismatch);
    }
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
            let (hex, draw) = audit_draw(revealed_seed, &entry.finding_id, &entry.listing_id);
            DrawnListing {
                selection: AuditSelection {
                    finding_id: entry.finding_id.clone(),
                    listing_id: entry.listing_id.clone(),
                    weight: entry.weight(),
                    draw: hex,
                },
                draw,
            }
        })
        .collect();
    drawn.sort_by(compare_priority);
    drawn.truncate(target);
    Ok(drawn.into_iter().map(|entry| entry.selection).collect())
}

/// Order by the exact rational priority `draw / weight`, smallest first.
///
/// The comparison cross multiplies each listing's draw by the other's
/// weight, over every one of the draw's 256 bits. Comparing a prefix
/// instead would make distinct draws tie, hand the order to the finding-id
/// tiebreak, and let a venue that also chooses the weights aim at a 64-bit
/// target rather than the whole digest. Ties break by finding id, which is
/// a total order over a snapshot whose finding ids are unique.
fn compare_priority(left: &DrawnListing, right: &DrawnListing) -> Ordering {
    scale_draw(&left.draw, right.selection.weight)
        .cmp(&scale_draw(&right.draw, left.selection.weight))
        .then_with(|| left.selection.finding_id.cmp(&right.selection.finding_id))
}

/// Multiply a 256-bit draw by a 64-bit weight, exactly.
///
/// Schoolbook limb multiplication, most significant limb last: every limb
/// widens to `u128` before it is scaled, so a limb product plus its
/// incoming carry always fits and no bit of either input is discarded. The
/// result is big-endian, so comparing two scaled draws is the ordinary
/// lexicographic comparison of their limbs.
fn scale_draw(draw: &DrawValue, weight: u64) -> ScaledDraw {
    let mut scaled: ScaledDraw = [0; 5];
    let mut carry = 0_u64;
    for (index, limb) in draw.iter().enumerate().rev() {
        let product = u128::from(*limb) * u128::from(weight) + u128::from(carry);
        scaled[index + 1] = product as u64;
        carry = (product >> 64) as u64;
    }
    scaled[0] = carry;
    scaled
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

/// One listing's draw, as the hex digest a report publishes and as the
/// integer the weighted ordering compares. Both are the same 256 bits.
fn audit_draw(revealed_seed: &str, finding_id: &str, listing_id: &str) -> (String, DrawValue) {
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
    let mut draw: DrawValue = [0; 4];
    for (limb, chunk) in draw.iter_mut().zip(digest.as_bytes().chunks_exact(8)) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(bytes);
    }
    (digest.to_hex(), draw)
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
