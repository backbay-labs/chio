#![cfg(feature = "cognition-market-experimental")]

//! Direct coverage for the verifiable audit selection: the deterministic
//! decision about which listings one published-rate round must audit, and
//! the independent recheck of the report that round publishes.
//!
//! One valid epoch, seed, and eligible snapshot are assembled from real
//! signed artifacts; every other case changes exactly one thing and asserts
//! the exact typed rejection, so a dropped or reordered check cannot pass
//! unnoticed.

use chio_finding::{
    audit_seed_witness_signing_bytes, compute_audit_epoch_id, compute_audit_report_id,
    derive_audit_seed_commitment, signed_envelope_sha256, FindingAuditEpoch, FindingAuditReport,
    FindingMissedAudit, FINDING_AUDIT_EPOCH_SCHEMA_V1, FINDING_AUDIT_REPORT_SCHEMA_V1,
};
use chio_open_market::{
    capability::scope::MonetaryAmount,
    crypto::{sha256_hex, Keypair},
    finding_audit::{
        audit_target_count, derive_audit_draw, derive_eligible_snapshot_digest,
        select_audit_targets as select_audit_targets_with_witness,
        select_audit_targets_within_budget as select_audit_targets_within_budget_with_witness,
        verify_audit_report as verify_audit_report_with_witness, AuditSelection, EligibleListing,
        FindingAuditError, AUDIT_SELECTION_ALGORITHM_V1,
    },
    receipt::lineage::SignedExportEnvelope,
};
use chio_test_support::prelude::*;

/// Committed seed for the round, in the exact shape a report can reveal.
const SEED: &str = "5eed00000000000000000000000000000000000000000000000000000000beef";
const OTHER_SEED: &str = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
const BUDGET_UNITS: u64 = 750;
const RATE_BPS: u64 = 2_500;
const COMMITTED_AT: u64 = 1_750_000_000;
const REPORTED_AT: u64 = 1_750_050_000;

fn audit_authority() -> Keypair {
    Keypair::from_seed(&[42_u8; 32])
}

fn seed_witness() -> Keypair {
    Keypair::from_seed(&[43_u8; 32])
}

fn select_audit_targets(
    epoch: &FindingAuditEpoch,
    seed: &str,
    eligible: &[EligibleListing],
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_audit_targets_with_witness(epoch, &seed_witness().public_key(), seed, eligible)
}

fn select_audit_targets_within_budget(
    epoch: &FindingAuditEpoch,
    seed: &str,
    eligible: &[EligibleListing],
    cost: &MonetaryAmount,
) -> Result<Vec<AuditSelection>, FindingAuditError> {
    select_audit_targets_within_budget_with_witness(
        epoch,
        &seed_witness().public_key(),
        seed,
        eligible,
        cost,
    )
}

fn verify_audit_report(
    epoch: &FindingAuditEpoch,
    epoch_envelope_sha256: &str,
    report: &FindingAuditReport,
    eligible: &[EligibleListing],
) -> Result<(), FindingAuditError> {
    verify_audit_report_with_witness(
        epoch,
        &seed_witness().public_key(),
        epoch_envelope_sha256,
        report,
        eligible,
    )
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_owned(),
    }
}

fn finding_id(index: usize) -> String {
    sha256_hex(format!("eligible-finding-{index}").as_bytes())
}

fn tie_finding_id(index: usize) -> String {
    sha256_hex(format!("audit-priority-tie-{index}").as_bytes())
}

fn tie_listing_id(index: usize) -> String {
    format!("listing-audit-priority-tie-{index:04}")
}

/// The leading 64 bits of a hex draw, which is the prefix a truncating
/// comparison would order by.
fn leading_u64(draw: &str) -> u64 {
    u64::from_str_radix(&draw[..16], 16).test_expect("draw prefix")
}

/// `count` eligible listings with no weights, so the ordering is exactly an
/// ordering by draw.
fn eligible_snapshot(count: usize) -> Vec<EligibleListing> {
    (0..count)
        .map(|index| EligibleListing {
            finding_id: finding_id(index),
            listing_id: format!("listing-finding-audit-{index:04}"),
            weight_or_none: None,
        })
        .collect()
}

fn epoch_for(eligible: &[EligibleListing], rate_bps: u64, budget_units: u64) -> FindingAuditEpoch {
    let audit_authority = audit_authority();
    let seed_witness = seed_witness();
    let seed_witnessed_at = COMMITTED_AT - 2;
    let eligible_snapshot_at = COMMITTED_AT - 1;
    let seed_commitment = derive_audit_seed_commitment(SEED);
    let mut epoch = FindingAuditEpoch {
        schema: FINDING_AUDIT_EPOCH_SCHEMA_V1.to_owned(),
        audit_epoch_id: String::new(),
        epoch_index: 7,
        audit_authority: audit_authority.public_key(),
        seed_witnessed_at,
        eligible_snapshot_at,
        seed_witness: seed_witness.public_key(),
        seed_witness_signature: seed_witness.sign(&audit_seed_witness_signing_bytes(
            &audit_authority.public_key(),
            7,
            &seed_commitment,
            seed_witnessed_at,
            eligible_snapshot_at,
        )),
        eligible_snapshot_digest: derive_eligible_snapshot_digest(eligible)
            .test_expect("snapshot digest"),
        eligible_listing_count: eligible.len() as u64,
        fee_schedule_envelope_sha256: sha256_hex(b"fee-schedule-envelope"),
        seed_commitment,
        selection_algorithm_id: AUDIT_SELECTION_ALGORITHM_V1.to_owned(),
        published_rate_bps: rate_bps,
        available_budget: usd(budget_units),
        authorization_digest: sha256_hex(b"audit-round-authorization"),
        committed_at: COMMITTED_AT,
    };
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch).test_expect("epoch id");
    epoch
}

/// The standard round: twelve eligible listings at 25 percent, so the rate
/// implies exactly three targets.
fn standard_round() -> (Vec<EligibleListing>, FindingAuditEpoch) {
    let eligible = eligible_snapshot(12);
    let epoch = epoch_for(&eligible, RATE_BPS, BUDGET_UNITS);
    (eligible, epoch)
}

fn selected_ids(selection: &[AuditSelection]) -> Vec<String> {
    selection
        .iter()
        .map(|target| target.finding_id.clone())
        .collect()
}

fn signed_epoch_digest(epoch: &FindingAuditEpoch) -> String {
    let audit_authority = audit_authority();
    let signed =
        SignedExportEnvelope::sign(epoch.clone(), &audit_authority).test_expect("sign audit epoch");
    signed_envelope_sha256(&signed).test_expect("epoch envelope digest")
}

/// A report that accounts for the standard round exactly: three selected,
/// one recorded as missed, two attempted with one receipt each.
fn report_for(
    epoch_envelope_sha256: &str,
    selection: &[AuditSelection],
) -> chio_finding::FindingAuditReport {
    let ids = selected_ids(selection);
    let mut report = FindingAuditReport {
        schema: FINDING_AUDIT_REPORT_SCHEMA_V1.to_owned(),
        audit_report_id: String::new(),
        audit_epoch_envelope_sha256: epoch_envelope_sha256.to_owned(),
        revealed_seed: SEED.to_owned(),
        selected_finding_ids: ids.clone(),
        attempt_receipt_ids: vec![
            "audit-attempt-0001".to_owned(),
            "audit-attempt-0002".to_owned(),
        ],
        missed_attempts: vec![FindingMissedAudit {
            finding_id: ids[2].clone(),
            reason: "retained replay inputs expired before the attempt".to_owned(),
        }],
        outcome_envelope_digests: vec![
            sha256_hex(b"audit-outcome-envelope-1"),
            sha256_hex(b"audit-outcome-envelope-2"),
        ],
        reported_at: REPORTED_AT,
    };
    report.audit_report_id = compute_audit_report_id(&report).test_expect("report id");
    report
}

fn reseal(report: &mut FindingAuditReport) {
    report.audit_report_id = String::new();
    report.audit_report_id = compute_audit_report_id(report).test_expect("report id");
}

#[test]
fn the_selection_is_identical_across_input_permutations() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    assert_eq!(selection.len(), 3, "25 percent of twelve listings");

    let mut reversed = eligible.clone();
    reversed.reverse();
    let mut rotated = eligible.clone();
    rotated.rotate_left(5);

    for permutation in [&reversed, &rotated] {
        assert_eq!(
            derive_eligible_snapshot_digest(permutation).test_expect("digest"),
            epoch.eligible_snapshot_digest,
            "the snapshot digest is order independent"
        );
        assert_eq!(
            select_audit_targets(&epoch, SEED, permutation).test_expect("selection"),
            selection,
            "input order must not change the selection or its order"
        );
    }

    // Replay is byte identical, including each published draw.
    let replayed = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    assert_eq!(replayed, selection);
    for target in &selection {
        assert_eq!(
            target.draw,
            derive_audit_draw(SEED, &target.finding_id, &target.listing_id)
        );
    }
}

#[test]
fn a_seed_outside_the_commitment_rejects() {
    let (eligible, epoch) = standard_round();
    assert_eq!(
        select_audit_targets(&epoch, OTHER_SEED, &eligible).test_unwrap_err(),
        FindingAuditError::SeedCommitmentMismatch
    );
    // A seed that no valid report could carry rejects on its shape first.
    assert_eq!(
        select_audit_targets(&epoch, "not-a-seed", &eligible).test_unwrap_err(),
        FindingAuditError::InvalidSeed
    );
}

#[test]
fn a_substituted_eligible_snapshot_rejects() {
    let (eligible, epoch) = standard_round();

    let mut substituted = eligible.clone();
    substituted[4].finding_id = sha256_hex(b"listing-swapped-in-after-the-commitment");
    assert_eq!(
        select_audit_targets(&epoch, SEED, &substituted).test_unwrap_err(),
        FindingAuditError::SnapshotDigestMismatch,
        "same count, different membership"
    );

    let mut reweighted = eligible.clone();
    reweighted[2].weight_or_none = Some(9);
    assert_eq!(
        select_audit_targets(&epoch, SEED, &reweighted).test_unwrap_err(),
        FindingAuditError::SnapshotDigestMismatch,
        "weights are committed, not caller chosen"
    );

    let mut resized = eligible.clone();
    resized.pop();
    assert_eq!(
        select_audit_targets(&epoch, SEED, &resized).test_unwrap_err(),
        FindingAuditError::EligibleCountMismatch {
            committed: 12,
            presented: 11,
        }
    );

    let mut duplicated = eligible.clone();
    duplicated[11].finding_id = duplicated[0].finding_id.clone();
    assert_eq!(
        select_audit_targets(&epoch, SEED, &duplicated).test_unwrap_err(),
        FindingAuditError::DuplicateEligibleListing(eligible[0].finding_id.clone())
    );

    let mut zero_weight = eligible.clone();
    zero_weight[3].weight_or_none = Some(0);
    assert_eq!(
        select_audit_targets(&epoch, SEED, &zero_weight).test_unwrap_err(),
        FindingAuditError::InvalidEligibleField("weight_or_none")
    );
}

#[test]
fn an_absent_weight_is_exactly_weight_one() {
    let eligible = eligible_snapshot(6);
    let explicit: Vec<EligibleListing> = eligible
        .iter()
        .map(|entry| EligibleListing {
            weight_or_none: Some(1),
            ..entry.clone()
        })
        .collect();
    let epoch = epoch_for(&eligible, RATE_BPS, BUDGET_UNITS);
    assert_eq!(
        derive_eligible_snapshot_digest(&explicit).test_expect("digest"),
        epoch.eligible_snapshot_digest
    );
    assert_eq!(
        select_audit_targets(&epoch, SEED, &explicit).test_expect("selection"),
        select_audit_targets(&epoch, SEED, &eligible).test_expect("selection")
    );
}

#[test]
fn the_weighted_order_compares_the_whole_draw() {
    // The priority is `draw / weight` over the full 256-bit draw. A venue
    // that sets each listing's weight to the leading 64 bits of that
    // listing's own draw makes both cross products agree on their leading
    // bits exactly, so an implementation that compares a prefix of the draw
    // sees a tie and settles the round on the finding id instead. The
    // remaining bits of the draw decide this pair, and they select the
    // listing the finding-id order would have placed second.
    let eligible: Vec<EligibleListing> = [0_usize, 2]
        .into_iter()
        .map(|index| {
            let finding_id = tie_finding_id(index);
            let listing_id = tie_listing_id(index);
            let draw = derive_audit_draw(SEED, &finding_id, &listing_id);
            EligibleListing {
                weight_or_none: Some(leading_u64(&draw)),
                finding_id,
                listing_id,
            }
        })
        .collect();
    assert!(
        eligible[0].finding_id < eligible[1].finding_id,
        "a finding-id tiebreak would select the first entry"
    );

    // Two eligible listings at fifty percent round up to exactly one target.
    let epoch = epoch_for(&eligible, 5_000, BUDGET_UNITS);
    let selected = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");

    assert_eq!(
        selected_ids(&selected),
        vec![eligible[1].finding_id.clone()],
        "the full draw decides the order, not its leading bits"
    );
}

#[test]
fn the_published_rate_rounds_up_at_every_eligible_size() {
    // Documented direction: the rate is a floor on how much of the venue is
    // audited, so the count rounds UP.
    assert_eq!(audit_target_count(2_500, 0).test_expect("count"), 0);
    assert_eq!(audit_target_count(2_500, 1).test_expect("count"), 1);
    assert_eq!(audit_target_count(1, 1).test_expect("count"), 1);
    assert_eq!(audit_target_count(2_500, 4).test_expect("count"), 1);
    assert_eq!(audit_target_count(2_500, 5).test_expect("count"), 2);
    assert_eq!(audit_target_count(2_500, 12).test_expect("count"), 3);
    assert_eq!(audit_target_count(10_000, 12).test_expect("count"), 12);
    assert_eq!(
        audit_target_count(10_001, 12).test_unwrap_err(),
        FindingAuditError::RateOutOfRange(10_001)
    );

    // A one-listing round selects that listing rather than rounding its
    // obligation away. A zero-listing round has no epoch: the artifact
    // refuses to commit an empty eligible count, so the count above is the
    // only place a zero size is reachable.
    let single = eligible_snapshot(1);
    let epoch = epoch_for(&single, 250, BUDGET_UNITS);
    let selection = select_audit_targets(&epoch, SEED, &single).test_expect("selection");
    assert_eq!(selected_ids(&selection), vec![single[0].finding_id.clone()]);

    for size in [2_usize, 5, 12, 40] {
        let eligible = eligible_snapshot(size);
        let epoch = epoch_for(&eligible, RATE_BPS, BUDGET_UNITS);
        let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
        let expected = audit_target_count(RATE_BPS, size as u64).test_expect("count");
        assert_eq!(selection.len() as u64, expected, "eligible size {size}");
    }
}

#[test]
fn budget_exhaustion_caps_the_selection() {
    let (eligible, epoch) = standard_round();
    let full = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    assert_eq!(full.len(), 3);

    // The budget funds every target.
    assert_eq!(
        select_audit_targets_within_budget(&epoch, SEED, &eligible, &usd(250))
            .test_expect("selection"),
        full
    );

    // The budget funds two of three; the capped result is a prefix.
    let capped = select_audit_targets_within_budget(&epoch, SEED, &eligible, &usd(300))
        .test_expect("selection");
    assert_eq!(capped, full[..2].to_vec());

    // A budget that funds nothing selects nothing rather than overspending.
    let starved =
        select_audit_targets_within_budget(&epoch, SEED, &eligible, &usd(BUDGET_UNITS + 1))
            .test_expect("selection");
    assert!(starved.is_empty());

    assert_eq!(
        select_audit_targets_within_budget(
            &epoch,
            SEED,
            &eligible,
            &MonetaryAmount {
                units: 100,
                currency: "EUR".to_owned(),
            }
        )
        .test_unwrap_err(),
        FindingAuditError::AttemptCostCurrencyMismatch
    );
    assert_eq!(
        select_audit_targets_within_budget(&epoch, SEED, &eligible, &usd(0)).test_unwrap_err(),
        FindingAuditError::ZeroAttemptCost
    );
}

#[test]
fn an_unknown_selection_algorithm_rejects() {
    let (eligible, epoch) = standard_round();
    let mut future = epoch;
    future.selection_algorithm_id = "chio.finding.audit-selection.stratified.v9".to_owned();
    future.audit_epoch_id = String::new();
    future.audit_epoch_id = compute_audit_epoch_id(&future).test_expect("epoch id");
    assert_eq!(
        select_audit_targets(&future, SEED, &eligible).test_unwrap_err(),
        FindingAuditError::UnsupportedAlgorithm(
            "chio.finding.audit-selection.stratified.v9".to_owned()
        )
    );
}

#[test]
fn an_exact_match_report_verifies() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);
    verify_audit_report(&epoch, &envelope, &report, &eligible).test_expect("report verifies");

    // Selection order is not part of the report's contract.
    let mut reordered = report;
    reordered.selected_finding_ids.reverse();
    reseal(&mut reordered);
    verify_audit_report(&epoch, &envelope, &reordered, &eligible)
        .test_expect("reordered report verifies");
}

#[test]
fn a_report_that_does_not_strictly_follow_its_epoch_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);

    for reported_at in [COMMITTED_AT - 1, COMMITTED_AT] {
        let mut report = report_for(&envelope, &selection);
        report.reported_at = reported_at;
        reseal(&mut report);
        assert_eq!(
            verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
            FindingAuditError::ReportNotAfterEpoch,
            "reported_at={reported_at} must strictly follow the epoch commitment"
        );
    }
}

#[test]
fn a_report_revealing_a_wrong_seed_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    report.revealed_seed = OTHER_SEED.to_owned();
    reseal(&mut report);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::SeedCommitmentMismatch
    );
}

#[test]
fn a_snapshot_cutoff_substituted_after_the_seed_witnessed_it_rejects() {
    let (eligible, mut epoch) = standard_round();
    epoch.eligible_snapshot_at += 1;
    epoch.audit_epoch_id = String::new();
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch).test_expect("epoch id");
    assert_eq!(
        select_audit_targets(&epoch, SEED, &eligible).test_unwrap_err(),
        FindingAuditError::Epoch(chio_finding::FindingError::EnvelopeSignatureInvalid(
            "audit_seed_witness"
        ))
    );
}

#[test]
fn the_venue_key_cannot_substitute_for_the_pinned_randomness_witness() {
    let (eligible, epoch) = standard_round();
    assert_eq!(
        select_audit_targets_with_witness(
            &epoch,
            &audit_authority().public_key(),
            SEED,
            &eligible,
        )
        .test_unwrap_err(),
        FindingAuditError::RandomnessWitnessMismatch
    );
}

#[test]
fn a_report_with_an_added_selection_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    // A listing the round did not draw, smuggled into the reported set.
    let unselected = eligible
        .iter()
        .map(|entry| entry.finding_id.clone())
        .find(|candidate| !selected_ids(&selection).contains(candidate))
        .test_expect("an eligible listing outside the selection");
    report.selected_finding_ids.push(unselected.clone());
    reseal(&mut report);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::UnexpectedSelection(unselected)
    );
}

#[test]
fn a_report_with_a_dropped_selection_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    let dropped = report.selected_finding_ids.remove(0);
    report.attempt_receipt_ids.truncate(1);
    reseal(&mut report);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::MissingSelection(dropped)
    );
}

#[test]
fn a_report_leaving_a_target_unaccounted_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);

    // Two of three targets attempted, but only one attempt receipt: the
    // third is neither attempted nor recorded as missed.
    let mut short = report_for(&envelope, &selection);
    short.attempt_receipt_ids.truncate(1);
    reseal(&mut short);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &short, &eligible).test_unwrap_err(),
        FindingAuditError::UnaccountedSelection {
            attempted: 2,
            attempt_receipts: 1,
        }
    );

    // Padding the receipts past the attempted count fails just as loudly.
    let mut padded = report_for(&envelope, &selection);
    padded
        .attempt_receipt_ids
        .push("audit-attempt-0003".to_owned());
    reseal(&mut padded);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &padded, &eligible).test_unwrap_err(),
        FindingAuditError::ExtraneousAttempt {
            attempted: 2,
            attempt_receipts: 3,
        }
    );

    // Every attempted target also owes one signed outcome envelope.
    let mut missing_outcome = report_for(&envelope, &selection);
    missing_outcome.outcome_envelope_digests.truncate(1);
    reseal(&mut missing_outcome);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &missing_outcome, &eligible).test_unwrap_err(),
        FindingAuditError::MissingOutcome {
            attempted: 2,
            outcomes: 1,
        }
    );

    // So does a signed outcome for a target that was never attempted.
    let mut extra_outcome = report_for(&envelope, &selection);
    extra_outcome
        .outcome_envelope_digests
        .push(sha256_hex(b"third-audit-outcome-envelope"));
    reseal(&mut extra_outcome);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &extra_outcome, &eligible).test_unwrap_err(),
        FindingAuditError::ExtraneousOutcome {
            attempted: 2,
            outcomes: 3,
        }
    );
}

#[test]
fn a_report_bound_to_another_epoch_envelope_rejects() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);

    // Same body, different signed round: the report answers for exactly one
    // envelope, not for any epoch with equal contents.
    let other_envelope = signed_epoch_digest(&epoch_for(&eligible, RATE_BPS, BUDGET_UNITS + 1));
    assert_ne!(other_envelope, envelope);
    assert_eq!(
        verify_audit_report(&epoch, &other_envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::EpochEnvelopeMismatch
    );
    assert_eq!(
        verify_audit_report(&epoch, "not-a-digest", &report, &eligible).test_unwrap_err(),
        FindingAuditError::InvalidEpochEnvelopeDigest
    );
}
