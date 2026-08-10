//! Class-independent admission: the closed compatibility matrix, the
//! strict-raw-first ingress, the pinned authorities, the standing a buyer
//! filing must carry, and the reason vocabulary's partition of the three
//! verdicts.

mod support;

use chio_finding::{
    ensure_challenge_class_compatibility, FindingChallengeEvidenceKind, FindingChallengeVerdict,
    FindingEvidenceClass, FindingGuaranteeClass,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeEvaluation, FindingChallengeEvaluationInput,
    FindingChallengeInadmissible, FindingChallengeReason, FindingChallengeReasonClass,
    FindingIngressError,
};

use support::{
    buyer_challenge_bound_to_profile, digest_case, evidence_case, evidence_case_with_standing,
    expect_inadmissible, keypair, profile_with_foreign_governance_authority, reissued_profile,
    replay_case, tampered_finding, venue_digest_case, world, world_with_classes, DenyShape,
    EvidenceShape, FindingClasses, ReplayShape, StandingShape, TestResult,
};

const GUARANTEE_CLASSES: [FindingGuaranteeClass; 3] = [
    FindingGuaranteeClass::DeterministicReplay,
    FindingGuaranteeClass::MeteredAttested,
    FindingGuaranteeClass::Asserted,
];

const EVIDENCE_CLASSES: [FindingEvidenceClass; 3] = [
    FindingEvidenceClass::Asserted,
    FindingEvidenceClass::Observed,
    FindingEvidenceClass::Verified,
];

const REASONS: [FindingChallengeReason; 25] = [
    FindingChallengeReason::SellerOriginDigestMismatch,
    FindingChallengeReason::EvidenceSignatureInvalid,
    FindingChallengeReason::EvidenceCheckpointContradiction,
    FindingChallengeReason::EvidenceSemanticCrossBindingFailure,
    FindingChallengeReason::EvidenceKeyRevokedAtPublication,
    FindingChallengeReason::ReplayContradictionConfirmed,
    FindingChallengeReason::DeliveredOutputMatchesCommitment,
    FindingChallengeReason::DenialNotSellerOrigin,
    FindingChallengeReason::DenialOutputPolicyExpectation,
    FindingChallengeReason::DenialMediaTypeMismatch,
    FindingChallengeReason::ChallengedEvidenceValid,
    FindingChallengeReason::ReplayReproductionConsistent,
    FindingChallengeReason::DeliveryAuthorityNotEstablished,
    FindingChallengeReason::DeliveryEvidenceNotEstablished,
    FindingChallengeReason::DeliveryCheckpointNotEstablished,
    FindingChallengeReason::EvidenceReceiptNotEstablished,
    FindingChallengeReason::EvidenceCheckpointNotEstablished,
    FindingChallengeReason::EvidenceAuthorityNotEstablished,
    FindingChallengeReason::EvidenceKeyRevokedAfterPublication,
    FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
    FindingChallengeReason::ReplayAuthorityNotEstablished,
    FindingChallengeReason::ReplayObservationNotEstablished,
    FindingChallengeReason::ReplayRunIncomplete,
    FindingChallengeReason::ReplayPhasesAmbiguous,
    FindingChallengeReason::ReplayPredicateNotAdmitted,
];

/// Every cell of the closed compatibility matrix, evaluated end to end. An
/// inadmissible pairing must produce no verdict at all, and an admissible one
/// must reach an adjudication.
#[test]
fn every_cross_class_pairing_rejects_before_evaluation() -> TestResult {
    let mut admitted = 0_usize;
    for guarantee in GUARANTEE_CLASSES {
        for evidence_class in EVIDENCE_CLASSES {
            let world = world_with_classes(FindingClasses {
                guarantee,
                evidence: evidence_class,
            })?;
            for kind in [
                FindingChallengeEvidenceKind::DigestMismatch,
                FindingChallengeEvidenceKind::EvidenceInvalid,
                FindingChallengeEvidenceKind::ReplayContradiction,
            ] {
                let compatible =
                    ensure_challenge_class_compatibility(kind, guarantee, evidence_class).is_ok();
                let evaluation = match kind {
                    FindingChallengeEvidenceKind::DigestMismatch => {
                        let case = digest_case(&world, &DenyShape::seller_origin())?;
                        let evidence = case.evidence();
                        evaluate_finding_challenge(&world.input(&case.challenge, &evidence))
                    }
                    FindingChallengeEvidenceKind::EvidenceInvalid => {
                        let case = evidence_case(&world, EvidenceShape::Sound)?;
                        let proofs = case.revocation_proofs();
                        let evidence = case.evidence(&proofs);
                        evaluate_finding_challenge(&world.input(&case.challenge, &evidence))
                    }
                    FindingChallengeEvidenceKind::ReplayContradiction => {
                        let case = replay_case(&world, &ReplayShape::default())?;
                        let reproductions = case.reproductions();
                        let evidence = case.evidence(&reproductions);
                        evaluate_finding_challenge(&world.input(&case.challenge, &evidence))
                    }
                };
                if compatible {
                    admitted += 1;
                    assert!(
                        evaluation.verdict().is_some(),
                        "{kind:?} with {guarantee:?}/{evidence_class:?} should evaluate"
                    );
                } else {
                    match &evaluation {
                        FindingChallengeEvaluation::Inadmissible(
                            FindingChallengeInadmissible::ClassIncompatible(_),
                        ) => {}
                        other => panic!(
                            "{kind:?} with {guarantee:?}/{evidence_class:?} should reject, got {other:?}"
                        ),
                    }
                    assert!(evaluation.verdict().is_none());
                }
            }
        }
    }
    // Nine digest-mismatch cells, six evidence-invalid cells, one replay cell.
    assert_eq!(admitted, 16);
    Ok(())
}

#[test]
fn evidence_from_another_class_is_inadmissible() -> TestResult {
    let world = world()?;
    let digest = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = evidence.revocation_proofs();

    // A digest-mismatch challenge with an evidence-invalid evidence set.
    let mismatched = evidence.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&digest.challenge, &mismatched));
    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::ClassEvidenceMismatch,
    )?;

    // And the reverse pairing.
    let mismatched = digest.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&evidence.challenge, &mismatched));
    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::ClassEvidenceMismatch,
    )?;
    Ok(())
}

#[test]
fn the_raw_finding_must_be_its_own_canonical_serialization() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let padded = format!(" {}", world.raw_finding);
    let input = FindingChallengeEvaluationInput {
        challenge: &case.challenge,
        pinned_audit_authority: &world.audit_authority_key,
        raw_finding: &padded,
        profile: &world.profile,
        governance_authority: &world.governance_key,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };
    let evaluation = evaluate_finding_challenge(&input);
    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::FindingIngress(FindingIngressError::NonCanonicalSpelling),
    )?;
    Ok(())
}

#[test]
fn the_profile_must_be_the_one_the_challenge_names() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let other_profile = reissued_profile(&world, "another-venue-operator")?;
    let input = FindingChallengeEvaluationInput {
        challenge: &case.challenge,
        pinned_audit_authority: &world.audit_authority_key,
        raw_finding: &world.raw_finding,
        profile: &other_profile,
        governance_authority: &world.governance_key,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };
    let evaluation = evaluate_finding_challenge(&input);
    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::ProfileBindingMismatch,
    )?;
    Ok(())
}

#[test]
fn the_profile_must_verify_under_the_pinned_governance_root() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let interloper = keypair(9).public_key();
    let input = FindingChallengeEvaluationInput {
        challenge: &case.challenge,
        pinned_audit_authority: &world.audit_authority_key,
        raw_finding: &world.raw_finding,
        profile: &world.profile,
        governance_authority: &interloper,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };
    let evaluation = evaluate_finding_challenge(&input);
    match &evaluation {
        FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::ProfileRejected(_),
        ) => {}
        other => panic!("expected the profile to be rejected, got {other:?}"),
    }
    Ok(())
}

#[test]
fn the_profile_body_must_name_the_pinned_governance_root() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let profile = profile_with_foreign_governance_authority(&world)?;
    let challenge = buyer_challenge_bound_to_profile(&world, &case.challenge, &profile)?;
    let input = FindingChallengeEvaluationInput {
        challenge: &challenge,
        pinned_audit_authority: &world.audit_authority_key,
        raw_finding: &world.raw_finding,
        profile: &profile,
        governance_authority: &world.governance_key,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };

    let evaluation = evaluate_finding_challenge(&input);
    match &evaluation {
        FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::ProfileRejected(_),
        ) => {}
        other => panic!("expected the profile body authority to be rejected, got {other:?}"),
    }
    Ok(())
}

#[test]
fn a_venue_audit_must_verify_under_the_pinned_audit_authority() -> TestResult {
    let world = world()?;
    let case = venue_digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let interloper = keypair(9).public_key();
    let input = FindingChallengeEvaluationInput {
        challenge: &case.challenge,
        pinned_audit_authority: &interloper,
        raw_finding: &world.raw_finding,
        profile: &world.profile,
        governance_authority: &world.governance_key,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };
    let evaluation = evaluate_finding_challenge(&input);
    match &evaluation {
        FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::ChallengeRejected(_),
        ) => {}
        other => panic!("expected the challenge to be rejected, got {other:?}"),
    }
    Ok(())
}

#[test]
fn the_finding_artifact_must_verify_as_its_issuer_signed_it() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let tampered = tampered_finding(&world)?;
    let input = FindingChallengeEvaluationInput {
        challenge: &case.challenge,
        pinned_audit_authority: &world.audit_authority_key,
        raw_finding: &tampered,
        profile: &world.profile,
        governance_authority: &world.governance_key,
        pinned_purchase_authority: &world.profile.body.purchase_authority,
        pinned_authority_status_key: &world.authority_status_key,
        evidence: &evidence,
    };
    let evaluation = evaluate_finding_challenge(&input);
    match &evaluation {
        FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::FindingRejected(_),
        ) => {}
        other => panic!("expected the finding to be rejected, got {other:?}"),
    }
    assert!(evaluation.verdict().is_none());
    Ok(())
}

/// Standing is what makes a buyer's filing this buyer's filing about this
/// sale. Each of these keeps every other artifact sound, so the gate named by
/// the expected variant is the only one that can produce the rejection.
#[test]
fn standing_must_be_signed_by_the_profiles_purchase_authority() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignAuthority)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    match &evaluation {
        FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::StandingRejected(_),
        ) => {}
        other => panic!("expected the standing artifact to be rejected, got {other:?}"),
    }
    assert!(evaluation.verdict().is_none());
    Ok(())
}

#[test]
fn standing_uses_the_exact_admission_purchase_authority_after_rotation() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::AdmissionAuthority)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let mut admission_policy = world.profile.body.purchase_authority.clone();
    admission_policy.authority_id = "purchase-rotated".to_owned();
    admission_policy.key = world.delivery_kernel.public_key();
    admission_policy.key_epoch += 1;
    let mut input = world.input(&case.challenge, &evidence);
    input.pinned_purchase_authority = &admission_policy;

    let evaluation = evaluate_finding_challenge(&input);
    let adjudication = evaluation
        .adjudication()
        .ok_or("the admission-pinned purchase authority establishes standing")?;
    assert_eq!(
        adjudication.reason(),
        FindingChallengeReason::EvidenceKeyRevocationNotEstablished
    );
    assert_eq!(
        adjudication.verdict(),
        chio_finding::FindingChallengeVerdict::Indeterminate
    );
    Ok(())
}

#[test]
fn standing_must_be_the_record_the_challenge_names() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::UnnamedRecord)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("purchase_record_envelope_sha256"),
    )?;
    Ok(())
}

#[test]
fn standing_must_settle_the_challenged_finding() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignFinding)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("finding_id"),
    )?;
    Ok(())
}

#[test]
fn standing_must_settle_the_challenged_listing() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignListing)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("listing_id"),
    )?;
    Ok(())
}

#[test]
fn standing_must_settle_under_the_challenged_backing() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignBacking)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("seller_backing_envelope_sha256"),
    )?;
    Ok(())
}

#[test]
fn standing_must_settle_under_the_challenged_admission() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignAdmission)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("venue_admission_envelope_sha256"),
    )?;
    Ok(())
}

#[test]
fn standing_must_belong_to_the_challenger() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignBuyer)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("buyer"),
    )?;
    Ok(())
}

/// A key policy states when a key was an authority, not that it is one
/// today. A record settled outside the purchase authority's window carries
/// the right signature from the wrong moment, which is what an expired or
/// withdrawn authority key would produce, so it establishes no standing.
#[test]
fn standing_must_settle_inside_the_purchase_authority_window() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::OutsideAuthorityWindow)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingAuthorityNotEstablished,
    )?;
    Ok(())
}

#[test]
fn standing_must_name_the_purchase_key_the_record_carries() -> TestResult {
    let world = world()?;
    let case = evidence_case_with_standing(&world, StandingShape::ForeignPurchaseKey)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::StandingBindingMismatch("purchase_key"),
    )?;
    Ok(())
}

#[test]
fn the_reason_vocabulary_partitions_the_three_verdicts() -> TestResult {
    let mut codes: Vec<&'static str> = REASONS.iter().map(|reason| reason.code()).collect();
    codes.sort_unstable();
    let unique = codes.len();
    codes.dedup();
    assert_eq!(codes.len(), unique, "reason codes must be unique");

    let mut fraud = 0_usize;
    let mut clean = 0_usize;
    let mut unestablished = 0_usize;
    for reason in REASONS {
        match reason.class() {
            FindingChallengeReasonClass::AffirmativeFraud => {
                assert_eq!(reason.verdict(), FindingChallengeVerdict::Upheld);
                fraud += 1;
            }
            FindingChallengeReasonClass::EvaluatedClean => {
                assert_eq!(reason.verdict(), FindingChallengeVerdict::Rejected);
                clean += 1;
            }
            FindingChallengeReasonClass::InputsNotEstablished => {
                assert_eq!(reason.verdict(), FindingChallengeVerdict::Indeterminate);
                unestablished += 1;
            }
        }
        assert!(!reason.message().is_empty());
        assert!(reason.to_string().contains(reason.code()));
    }
    assert_eq!(fraud + clean + unestablished, REASONS.len());
    // Only six reasons can sanction a seller, and every one of them names an
    // affirmative act rather than a missing input.
    assert_eq!(fraud, 6);
    assert_eq!(clean, 6);
    assert_eq!(unestablished, 13);
    Ok(())
}
