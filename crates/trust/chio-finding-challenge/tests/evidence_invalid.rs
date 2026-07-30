//! The `evidence_invalid` branch: what counts as affirmative invalidity, and
//! what is only an unresolved input wearing its clothes.

mod support;

use chio_finding::{FindingChallengeVerdict, FindingEvidenceClass, FindingGuaranteeClass};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeInadmissible, FindingChallengeReason,
};

use support::{
    evidence_case, evidence_case_with_revocations, expect_inadmissible, expect_reason, outcome_for,
    world, world_with, world_with_classes, EvidenceShape, FindingClasses, ProductionShape,
    RevokedKey, TestResult, PUBLISHED_AT,
};

#[test]
fn sound_evidence_is_rejected_rather_than_left_open() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::ChallengedEvidenceValid)?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn an_evidence_receipt_that_does_not_verify_upholds() -> TestResult {
    let world = world_with(FindingClasses::default(), ProductionShape::ForeignSignature)?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceSignatureInvalid,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn an_evidence_receipt_that_contradicts_its_own_action_upholds() -> TestResult {
    let world = world_with(
        FindingClasses::default(),
        ProductionShape::ActionCommitmentBroken,
    )?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceSemanticCrossBindingFailure,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_checkpoint_proof_that_contradicts_membership_upholds() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::ContradictoryCheckpoint)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceCheckpointContradiction,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_key_proven_revoked_at_publication_upholds() -> TestResult {
    let world = world()?;
    let revoked = vec![RevokedKey {
        key: world.production_kernel.public_key(),
        revoked_from: PUBLISHED_AT - 1,
        proof_ref: "revocations/finding-market#42".to_string(),
    }];
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevokedAtPublication,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_key_revoked_only_afterwards_is_indeterminate() -> TestResult {
    let world = world()?;
    let revoked = vec![RevokedKey {
        key: world.production_kernel.public_key(),
        revoked_from: PUBLISHED_AT + 1,
        proof_ref: "revocations/finding-market#43".to_string(),
    }];
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevokedAfterPublication,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn an_unresolved_checkpoint_is_indeterminate() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::UnresolvedCheckpoint)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceCheckpointNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn evidence_signed_outside_the_production_role_is_indeterminate() -> TestResult {
    let world = world_with(FindingClasses::default(), ProductionShape::ForeignSigner)?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceAuthorityNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    Ok(())
}

#[test]
fn an_asserted_finding_has_no_evidence_to_invalidate() -> TestResult {
    let world = world_with_classes(FindingClasses {
        guarantee: FindingGuaranteeClass::Asserted,
        evidence: FindingEvidenceClass::Asserted,
    })?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    match &evaluation {
        chio_finding_challenge::FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::ClassIncompatible(_),
        ) => {}
        other => panic!("expected a cross-class rejection, got {other:?}"),
    }
    assert!(evaluation.verdict().is_none());
    Ok(())
}

#[test]
fn contesting_evidence_the_finding_never_named_is_inadmissible() -> TestResult {
    let world = world()?;
    // The two worlds share no receipts, so this challenge contests receipts
    // that belong to a different finding's evidence set.
    let other = world_with(FindingClasses::default(), ProductionShape::ForeignSigner)?;
    let case = evidence_case(&other, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::FindingBindingMismatch("finding_artifact_sha256"),
    )?;
    Ok(())
}
