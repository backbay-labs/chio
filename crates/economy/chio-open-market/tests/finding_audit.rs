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
    audit_epoch_precommitment_sha256, audit_seed_witness_signing_bytes, compute_audit_epoch_id,
    compute_audit_report_id, compute_challenge_id, derive_audit_seed_commitment, derive_outcome_id,
    signed_envelope_sha256, FindingAuditEpoch, FindingAuditReport, FindingAuditRoundAuthorization,
    FindingAuthorityKeyPolicy, FindingAuthorityStatus, FindingChallenge,
    FindingChallengeAuthorization, FindingChallengeAuthorizationKind, FindingChallengeEvidence,
    FindingChallengeEvidenceKind, FindingChallengeFacet, FindingChallengeOutcome,
    FindingChallengeVerdict, FindingCheckpointRef, FindingEvidenceInvalidFacet,
    FindingEvidenceInvalidity, FindingMissedAudit, FindingReceiptRef,
    FindingVenueAuditAuthorization, SignedFindingAuditEpoch, SignedFindingAuditReport,
    SignedFindingAuditRoundAuthorization, SignedFindingAuthorityStatus, SignedFindingChallenge,
    SignedFindingChallengeOutcome, FINDING_AUDIT_EPOCH_SCHEMA_V1, FINDING_AUDIT_REPORT_SCHEMA_V1,
    FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1, FINDING_CHALLENGE_SCHEMA_V1,
};
use chio_open_market::{
    capability::scope::MonetaryAmount,
    crypto::{sha256_hex, Keypair},
    finding_audit::{
        audit_target_count, derive_audit_draw, derive_eligible_snapshot_digest,
        select_audit_targets as select_audit_targets_with_witness,
        select_audit_targets_within_budget as select_audit_targets_within_budget_with_witness,
        verify_audit_report as verify_audit_report_with_witness, AuditSelection, EligibleListing,
        FindingAuditError, FindingAuditReportWitnesses, AUDIT_SELECTION_ALGORITHM_V1,
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

fn audit_evaluator() -> Keypair {
    Keypair::from_seed(&[44_u8; 32])
}

fn governance_authority() -> Keypair {
    Keypair::from_seed(&[47_u8; 32])
}

fn status_authority() -> Keypair {
    Keypair::from_seed(&[48_u8; 32])
}

fn evaluator_policy(
    authority_id: &str,
    key: chio_open_market::crypto::PublicKey,
    key_epoch: u64,
) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: authority_id.to_owned(),
        key,
        key_epoch,
        valid_from: COMMITTED_AT.saturating_sub(1),
        valid_until: REPORTED_AT.saturating_add(1),
        rotation_policy_ref: "rotation/audit-evaluator".to_owned(),
        revocation_status_ref: format!("revocations/{authority_id}"),
    }
}

fn audit_evaluator_policy() -> FindingAuthorityKeyPolicy {
    evaluator_policy("audit-evaluator", audit_evaluator().public_key(), 1)
}

fn governance_policy() -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: "audit-governance".to_owned(),
        key: governance_authority().public_key(),
        key_epoch: 1,
        valid_from: COMMITTED_AT - 2,
        valid_until: REPORTED_AT + 2,
        rotation_policy_ref: "rotation/audit-governance".to_owned(),
        revocation_status_ref: "revocations/audit-governance".to_owned(),
    }
}

fn round_authorization(epoch: &FindingAuditEpoch) -> SignedFindingAuditRoundAuthorization {
    SignedFindingAuditRoundAuthorization::sign(
        FindingAuditRoundAuthorization {
            schema: FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1.to_owned(),
            epoch_precommitment_sha256: audit_epoch_precommitment_sha256(epoch)
                .test_expect("epoch precommitment"),
            authorized_at: COMMITTED_AT - 1,
            expires_at: REPORTED_AT + 1,
        },
        &governance_authority(),
    )
    .test_expect("sign round authorization")
}

fn evaluator_status(
    policy: &FindingAuthorityKeyPolicy,
    revoked_from: Option<u64>,
) -> SignedFindingAuthorityStatus {
    SignedFindingAuthorityStatus::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
            status_ref: policy.revocation_status_ref.clone(),
            authority_id: policy.authority_id.clone(),
            key: policy.key.clone(),
            key_epoch: policy.key_epoch,
            revoked_from,
            observed_at: REPORTED_AT,
        },
        &status_authority(),
    )
    .test_expect("sign evaluator status")
}

fn report_witnesses<'a>(
    epoch: &FindingAuditEpoch,
    policies: &'a [FindingAuthorityKeyPolicy],
    audit_attempts: &'a [SignedFindingChallenge],
    resolved_outcomes: &'a [SignedFindingChallengeOutcome],
) -> FindingAuditReportWitnesses<'a> {
    FindingAuditReportWitnesses {
        pinned_seed_witness: seed_witness().public_key(),
        pinned_audit_authority: audit_authority().public_key(),
        pinned_governance_policy: governance_policy(),
        round_authorization: round_authorization(epoch),
        pinned_status_authority: status_authority().public_key(),
        pinned_evaluator_policies: policies,
        evaluator_statuses: policies
            .iter()
            .map(|policy| evaluator_status(policy, None))
            .collect(),
        audit_attempts,
        resolved_outcomes,
    }
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
    let audit_attempts = audit_attempts_for_report(report, eligible);
    let resolved_outcomes = resolved_outcomes_for_report(report, eligible, &audit_attempts);
    let evaluator_policies = [audit_evaluator_policy()];
    let witnesses = report_witnesses(
        epoch,
        &evaluator_policies,
        &audit_attempts,
        &resolved_outcomes,
    );
    let signed_epoch = sign_epoch(epoch);
    assert_eq!(
        signed_envelope_sha256(&signed_epoch).test_expect("epoch digest"),
        epoch_envelope_sha256,
        "test helper must present the digest of the exact signed epoch"
    );
    verify_audit_report_with_witness(&signed_epoch, &sign_report(report), eligible, &witnesses)
}

fn sign_epoch(epoch: &FindingAuditEpoch) -> SignedFindingAuditEpoch {
    SignedFindingAuditEpoch::sign(epoch.clone(), &audit_authority()).test_expect("sign audit epoch")
}

fn sign_report(report: &FindingAuditReport) -> SignedFindingAuditReport {
    SignedFindingAuditReport::sign(report.clone(), &audit_authority())
        .test_expect("sign audit report")
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
        authorization_digest: String::new(),
        committed_at: COMMITTED_AT,
    };
    epoch.authorization_digest = signed_envelope_sha256(&round_authorization(&epoch))
        .test_expect("round authorization digest");
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

fn audit_attempts_for_report(
    report: &FindingAuditReport,
    eligible: &[EligibleListing],
) -> Vec<SignedFindingChallenge> {
    report
        .selected_finding_ids
        .iter()
        .filter(|finding_id| {
            !report
                .missed_attempts
                .iter()
                .any(|missed| missed.finding_id == **finding_id)
        })
        .map(|finding_id| {
            let listing = eligible
                .iter()
                .find(|entry| entry.finding_id == *finding_id)
                .test_expect("reported finding is eligible");
            let profile = sha256_hex(b"audit verifier profile");
            let receipt_sha256 = sha256_hex(format!("audit receipt:{finding_id}").as_bytes());
            let checkpoint_sha256 = sha256_hex(format!("audit checkpoint:{finding_id}").as_bytes());
            let mut challenge = FindingChallenge {
                schema: FINDING_CHALLENGE_SCHEMA_V1.to_owned(),
                challenge_id: String::new(),
                finding_id: finding_id.clone(),
                finding_artifact_sha256: sha256_hex(
                    format!("audit finding artifact:{finding_id}").as_bytes(),
                ),
                listing_id: listing.listing_id.clone(),
                terms_envelope_sha256: sha256_hex(b"audit terms envelope"),
                profile_envelope_sha256: profile,
                venue_admission_envelope_sha256: sha256_hex(b"audit venue admission"),
                backing_envelope_sha256: sha256_hex(b"audit backing envelope"),
                filed_at: report.reported_at.saturating_sub(2),
                affected_deliveries: Vec::new(),
                authorization: FindingChallengeAuthorization::VenueAudit(
                    FindingVenueAuditAuthorization {
                        audit_epoch_envelope_sha256: report.audit_epoch_envelope_sha256.clone(),
                        selection_digest: sha256_hex(
                            format!("audit selection:{finding_id}:{}", listing.listing_id)
                                .as_bytes(),
                        ),
                        authorization_digest: sha256_hex(
                            format!("audit authorization:{finding_id}").as_bytes(),
                        ),
                    },
                ),
                evidence: FindingChallengeEvidence::EvidenceInvalid {
                    challenged_evidence_receipt_refs: vec![FindingReceiptRef {
                        receipt_id: format!("audit-receipt-{finding_id}"),
                        receipt_sha256,
                    }],
                    challenged_checkpoint_ref: FindingCheckpointRef {
                        checkpoint_ref: format!("audit-checkpoint-{finding_id}"),
                        checkpoint_sha256,
                    },
                    purchase_record_envelope_sha256: sha256_hex(
                        format!("audit purchase:{finding_id}").as_bytes(),
                    ),
                },
            };
            challenge.challenge_id =
                compute_challenge_id(&challenge).test_expect("audit challenge id");
            SignedFindingChallenge::sign(challenge, &audit_authority())
                .test_expect("sign audit attempt")
        })
        .collect()
}

fn resolved_outcomes_for_report(
    report: &FindingAuditReport,
    eligible: &[EligibleListing],
    audit_attempts: &[SignedFindingChallenge],
) -> Vec<SignedFindingChallengeOutcome> {
    report
        .selected_finding_ids
        .iter()
        .filter(|finding_id| {
            !report
                .missed_attempts
                .iter()
                .any(|missed| missed.finding_id == **finding_id)
        })
        .map(|finding_id| {
            let listing = eligible
                .iter()
                .find(|entry| entry.finding_id == *finding_id)
                .test_expect("reported finding is eligible");
            let attempt = audit_attempts
                .iter()
                .find(|attempt| attempt.body.finding_id == *finding_id)
                .test_expect("reported finding has an audit attempt");
            let mut outcome = FindingChallengeOutcome {
                schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_owned(),
                outcome_id: String::new(),
                challenge_envelope_sha256: signed_envelope_sha256(attempt)
                    .test_expect("audit attempt envelope digest"),
                finding_id: finding_id.clone(),
                listing_id: listing.listing_id.clone(),
                backing_allocation_id: sha256_hex(
                    format!("audit backing allocation:{finding_id}").as_bytes(),
                ),
                authorization: FindingChallengeAuthorizationKind::VenueAudit,
                audit_epoch_envelope_sha256: Some(report.audit_epoch_envelope_sha256.clone()),
                evidence_kind: FindingChallengeEvidenceKind::EvidenceInvalid,
                verifier_profile_envelope_sha256: sha256_hex(b"audit verifier profile"),
                evidence_bundle_digest: sha256_hex(
                    format!("audit evidence bundle:{finding_id}").as_bytes(),
                ),
                verdict: FindingChallengeVerdict::Rejected,
                facet: FindingChallengeFacet::EvidenceInvalid(FindingEvidenceInvalidFacet {
                    challenged_receipt_ids: vec![format!("audit-receipt-{finding_id}")],
                    invalidity: FindingEvidenceInvalidity::NoAffirmativeInvalidity,
                }),
                reason: "the selected evidence resolved without affirmative invalidity".to_owned(),
                trigger_digest: report.audit_epoch_envelope_sha256.clone(),
                retry_deadline: None,
                penalty_calculation: None,
                evaluator_authority_id: "audit-evaluator".to_owned(),
                evaluator_key: audit_evaluator().public_key(),
                evaluator_key_epoch: 1,
                evaluator_valid_from: COMMITTED_AT.saturating_sub(1),
                evaluator_valid_until: REPORTED_AT.saturating_add(1),
                evaluator_revocation_status_ref: "revocations/audit-evaluator".to_owned(),
                evaluated_at: report.reported_at.saturating_sub(1),
            };
            outcome.outcome_id = derive_outcome_id(&outcome).test_expect("outcome id");
            SignedFindingChallengeOutcome::sign(outcome, &audit_evaluator())
                .test_expect("sign audit outcome")
        })
        .collect()
}

/// A report that accounts for the standard round exactly: three selected,
/// one recorded as missed, two attempted with one signed envelope each.
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
        attempt_envelope_sha256s: vec![
            sha256_hex(b"audit attempt envelope 1"),
            sha256_hex(b"audit attempt envelope 2"),
        ],
        missed_attempts: vec![FindingMissedAudit {
            finding_id: ids[2].clone(),
            reason: "retained replay inputs expired before the attempt".to_owned(),
        }],
        outcome_envelope_digests: Vec::new(),
        reported_at: REPORTED_AT,
    };
    let selected_entries: Vec<EligibleListing> = selection
        .iter()
        .map(|selected| EligibleListing {
            finding_id: selected.finding_id.clone(),
            listing_id: selected.listing_id.clone(),
            weight_or_none: Some(selected.weight),
        })
        .collect();
    let audit_attempts = audit_attempts_for_report(&report, &selected_entries);
    report.attempt_envelope_sha256s = audit_attempts
        .iter()
        .map(|attempt| signed_envelope_sha256(attempt).test_expect("audit attempt envelope digest"))
        .collect();
    report.outcome_envelope_digests =
        resolved_outcomes_for_report(&report, &selected_entries, &audit_attempts)
            .iter()
            .map(|outcome| signed_envelope_sha256(outcome).test_expect("outcome envelope digest"))
            .collect();
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
fn report_verification_authenticates_the_governance_round_authorization() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    let policies = [audit_evaluator_policy()];
    let mut witnesses = report_witnesses(&epoch, &policies, &audit_attempts, &outcomes);

    witnesses.round_authorization = SignedFindingAuditRoundAuthorization::sign(
        witnesses.round_authorization.body.clone(),
        &Keypair::from_seed(&[49_u8; 32]),
    )
    .test_expect("sign authorization with an unpinned key");
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::RoundAuthorization(chio_finding::FindingError::AuthorityMismatch(
            "audit_round_authorization"
        ))
    ));

    let mut substituted = round_authorization(&epoch).body;
    substituted.epoch_precommitment_sha256 = sha256_hex(b"another audit precommitment");
    witnesses.round_authorization =
        SignedFindingAuditRoundAuthorization::sign(substituted, &governance_authority())
            .test_expect("sign substituted authorization");
    assert_eq!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::RoundAuthorizationBinding
    );

    witnesses.round_authorization = round_authorization(&epoch);
    witnesses.pinned_governance_policy.valid_from = COMMITTED_AT;
    assert_eq!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::RoundAuthorizationWindow
    );
}

#[test]
fn report_verification_requires_fresh_authenticated_evaluator_status() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    let policies = [audit_evaluator_policy()];
    let mut witnesses = report_witnesses(&epoch, &policies, &audit_attempts, &outcomes);

    witnesses.evaluator_statuses.clear();
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeStatusNotEstablished(_)
    ));

    witnesses.evaluator_statuses = vec![SignedFindingAuthorityStatus::sign(
        evaluator_status(&policies[0], None).body,
        &Keypair::from_seed(&[49_u8; 32]),
    )
    .test_expect("sign status with an unpinned key")];
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeStatus(chio_finding::FindingError::AuthorityMismatch(
            "authority_status"
        ))
    ));

    witnesses.evaluator_statuses = vec![evaluator_status(
        &policies[0],
        Some(outcomes[0].body.evaluated_at),
    )];
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeEvaluatorRevoked(_)
    ));

    let mut stale_report = report;
    stale_report.reported_at = REPORTED_AT + 3_601;
    reseal(&mut stale_report);
    witnesses.evaluator_statuses = vec![evaluator_status(&policies[0], None)];
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&stale_report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeStatusStale(_)
    ));
}

#[test]
fn report_verification_requires_pinned_epoch_and_report_signatures() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let resolved_outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    let policies = [audit_evaluator_policy()];
    let witnesses = report_witnesses(&epoch, &policies, &audit_attempts, &resolved_outcomes);

    let forged_report =
        SignedFindingAuditReport::sign(report.clone(), &Keypair::from_seed(&[99_u8; 32]))
            .test_expect("sign forged report");
    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &forged_report,
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::Report(_)
    ));

    let forged_epoch = SignedFindingAuditEpoch::sign(epoch, &Keypair::from_seed(&[98_u8; 32]))
        .test_expect("sign forged epoch");
    assert!(matches!(
        verify_audit_report_with_witness(
            &forged_epoch,
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::Epoch(_)
    ));
}

#[test]
fn an_outcome_cannot_predate_its_signed_audit_attempt() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let mut resolved_outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    let attempt_filed_at = audit_attempts[0].body.filed_at;
    resolved_outcomes[0].body.evaluated_at = attempt_filed_at - 1;
    resolved_outcomes[0].body.outcome_id =
        derive_outcome_id(&resolved_outcomes[0].body).test_expect("outcome id");
    resolved_outcomes[0] =
        SignedFindingChallengeOutcome::sign(resolved_outcomes[0].body.clone(), &audit_evaluator())
            .test_expect("sign predating outcome");
    report.outcome_envelope_digests[0] = signed_envelope_sha256(&resolved_outcomes[0])
        .test_expect("predating outcome envelope digest");
    reseal(&mut report);
    let policies = [audit_evaluator_policy()];
    let witnesses = report_witnesses(&epoch, &policies, &audit_attempts, &resolved_outcomes);

    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &witnesses,
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeTimeBinding(_)
    ));
}

#[test]
fn a_report_cannot_fabricate_an_outcome_envelope_digest() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    report.outcome_envelope_digests[0] = sha256_hex(b"fabricated audit outcome envelope");
    reseal(&mut report);

    assert!(matches!(
        verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::OutcomeDigestMismatch(_)
    ));
}

#[test]
fn a_report_cannot_fabricate_an_attempt_envelope_digest() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    report.attempt_envelope_sha256s[0] = sha256_hex(b"fabricated audit attempt envelope");
    reseal(&mut report);

    assert!(matches!(
        verify_audit_report(&epoch, &envelope, &report, &eligible).test_unwrap_err(),
        FindingAuditError::AttemptDigestMismatch(_)
    ));
}

#[test]
fn an_outcome_from_an_unpinned_evaluator_cannot_resolve_a_report() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let outcomes: Vec<SignedFindingChallengeOutcome> =
        resolved_outcomes_for_report(&report, &eligible, &audit_attempts)
            .into_iter()
            .map(|signed| {
                SignedFindingChallengeOutcome::sign(signed.body, &Keypair::from_seed(&[45_u8; 32]))
                    .test_expect("sign with unpinned evaluator")
            })
            .collect();
    let policies = [audit_evaluator_policy()];

    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &report_witnesses(&epoch, &policies, &audit_attempts, &outcomes),
        )
        .test_unwrap_err(),
        FindingAuditError::Outcome(chio_finding::FindingError::AuthorityMismatch(
            "challenge_outcome"
        ))
    ));
}

#[test]
fn a_report_authenticates_each_historical_evaluator_across_rotation() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let mut outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    let rotated = Keypair::from_seed(&[46_u8; 32]);
    let rotated_policy = evaluator_policy("audit-evaluator-rotated", rotated.public_key(), 2);
    let old_digest = signed_envelope_sha256(&outcomes[1]).test_expect("old outcome digest");
    outcomes[1].body.evaluator_authority_id = rotated_policy.authority_id.clone();
    outcomes[1].body.evaluator_key = rotated_policy.key.clone();
    outcomes[1].body.evaluator_key_epoch = rotated_policy.key_epoch;
    outcomes[1].body.evaluator_valid_from = rotated_policy.valid_from;
    outcomes[1].body.evaluator_valid_until = rotated_policy.valid_until;
    outcomes[1].body.evaluator_revocation_status_ref = rotated_policy.revocation_status_ref.clone();
    outcomes[1].body.outcome_id =
        derive_outcome_id(&outcomes[1].body).test_expect("rotated outcome id");
    outcomes[1] = SignedFindingChallengeOutcome::sign(outcomes[1].body.clone(), &rotated)
        .test_expect("sign rotated outcome");
    let rotated_digest = signed_envelope_sha256(&outcomes[1]).test_expect("rotated outcome digest");
    let reported = report
        .outcome_envelope_digests
        .iter_mut()
        .find(|digest| **digest == old_digest)
        .test_expect("report names old outcome");
    *reported = rotated_digest;
    reseal(&mut report);
    let policies = [audit_evaluator_policy(), rotated_policy];

    verify_audit_report_with_witness(
        &sign_epoch(&epoch),
        &sign_report(&report),
        &eligible,
        &report_witnesses(&epoch, &policies, &audit_attempts, &outcomes),
    )
    .test_expect("each outcome resolves its historical evaluator policy");
}

#[test]
fn a_signed_outcome_for_an_unattempted_selection_cannot_resolve_a_report() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let mut outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    outcomes[0].body.finding_id = report.missed_attempts[0].finding_id.clone();
    outcomes[0].body.listing_id = selection[2].listing_id.clone();
    outcomes[0].body.outcome_id = derive_outcome_id(&outcomes[0].body).test_expect("outcome id");
    outcomes[0] = SignedFindingChallengeOutcome::sign(outcomes[0].body.clone(), &audit_evaluator())
        .test_expect("sign substituted outcome");
    report.outcome_envelope_digests[0] =
        signed_envelope_sha256(&outcomes[0]).test_expect("outcome envelope digest");
    reseal(&mut report);
    let policies = [audit_evaluator_policy()];

    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &report_witnesses(&epoch, &policies, &audit_attempts, &outcomes),
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeSelectionBinding(_)
    ));
}

#[test]
fn an_outcome_from_another_audit_round_cannot_resolve_a_report() {
    let (eligible, epoch) = standard_round();
    let selection = select_audit_targets(&epoch, SEED, &eligible).test_expect("selection");
    let envelope = signed_epoch_digest(&epoch);
    let mut report = report_for(&envelope, &selection);
    let audit_attempts = audit_attempts_for_report(&report, &eligible);
    let mut outcomes = resolved_outcomes_for_report(&report, &eligible, &audit_attempts);
    outcomes[0].body.audit_epoch_envelope_sha256 =
        Some(sha256_hex(b"another audit epoch envelope"));
    outcomes[0].body.outcome_id = derive_outcome_id(&outcomes[0].body).test_expect("outcome id");
    outcomes[0] = SignedFindingChallengeOutcome::sign(outcomes[0].body.clone(), &audit_evaluator())
        .test_expect("sign cross-round outcome");
    report.outcome_envelope_digests[0] =
        signed_envelope_sha256(&outcomes[0]).test_expect("outcome envelope digest");
    reseal(&mut report);
    let policies = [audit_evaluator_policy()];

    assert!(matches!(
        verify_audit_report_with_witness(
            &sign_epoch(&epoch),
            &sign_report(&report),
            &eligible,
            &report_witnesses(&epoch, &policies, &audit_attempts, &outcomes),
        )
        .test_unwrap_err(),
        FindingAuditError::OutcomeRoundBinding(_)
    ));
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
    report.attempt_envelope_sha256s.truncate(1);
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

    // Two of three targets attempted, but only one attempt envelope: the
    // third is neither attempted nor recorded as missed.
    let mut short = report_for(&envelope, &selection);
    short.attempt_envelope_sha256s.truncate(1);
    reseal(&mut short);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &short, &eligible).test_unwrap_err(),
        FindingAuditError::UnaccountedSelection {
            attempted: 2,
            attempt_envelopes: 1,
        }
    );

    // Padding the receipts past the attempted count fails just as loudly.
    let mut padded = report_for(&envelope, &selection);
    padded
        .attempt_envelope_sha256s
        .push(sha256_hex(b"audit attempt envelope 3"));
    reseal(&mut padded);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &padded, &eligible).test_unwrap_err(),
        FindingAuditError::ExtraneousAttempt {
            attempted: 2,
            attempt_envelopes: 3,
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
    let mut cross_round = report.clone();
    cross_round.audit_epoch_envelope_sha256 = other_envelope;
    reseal(&mut cross_round);
    assert_eq!(
        verify_audit_report(&epoch, &envelope, &cross_round, &eligible).test_unwrap_err(),
        FindingAuditError::EpochEnvelopeMismatch
    );

    let mut malformed = report;
    malformed.audit_epoch_envelope_sha256 = "not-a-digest".to_owned();
    reseal(&mut malformed);
    assert!(matches!(
        verify_audit_report(&epoch, &envelope, &malformed, &eligible).test_unwrap_err(),
        FindingAuditError::Report(chio_finding::FindingError::MalformedDigest(
            "audit_epoch_envelope_sha256"
        ))
    ));
}
