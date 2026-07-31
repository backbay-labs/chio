//! The `evidence_invalid` branch: what counts as affirmative invalidity, and
//! what is only an unresolved input wearing its clothes.

mod support;

use chio_finding::{FindingChallengeVerdict, FindingEvidenceClass, FindingGuaranteeClass};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeInadmissible,
    FindingChallengeReason, FindingEvidenceInvalidEvidence,
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
fn a_checkpointed_receipt_that_does_not_verify_upholds() -> TestResult {
    let world = world_with(
        FindingClasses::default(),
        ProductionShape::CheckpointedForeignSignature,
    )?;
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

/// The finding's content address covers a receipt body, and the envelope's
/// signature sits outside it, so anyone who holds the seller's receipt can
/// re-sign it and claim the digest of the result. Only the log decides which
/// bytes are the seller's, and bytes it never committed cannot slash anyone.
#[test]
fn a_signature_the_log_never_committed_is_indeterminate() -> TestResult {
    let world = world_with(
        FindingClasses::default(),
        ProductionShape::SuppliedForeignSignature,
    )?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceReceiptNotEstablished,
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

/// Only the inclusion path settles membership. The wrapper carrying it is
/// unsigned and resolver-supplied, so a wrapper that disagrees with the
/// venue's signed checkpoint is a defect of whoever assembled it and cannot
/// be read as the seller's fraud.
#[test]
fn an_inclusion_wrapper_the_checkpoint_disagrees_with_is_indeterminate() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::InconsistentProof)?;
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
    assert!(!evaluation.authorizes_penalty());
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

/// A checkpoint that does not verify under the log signer the profile pins is
/// an artifact anyone can mint from public material, so it can no more
/// contradict the finding's anchoring than it can confirm it.
#[test]
fn a_checkpoint_that_is_not_the_venues_own_is_indeterminate() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::ForgedCheckpoint)?;
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
    assert!(!evaluation.authorizes_penalty());
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
fn evidence_signed_before_the_production_key_window_is_indeterminate() -> TestResult {
    let world = world_with(
        FindingClasses::default(),
        ProductionShape::SignedBeforeKeyWindow,
    )?;
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
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_challenge_bound_to_another_findings_artifact_is_inadmissible() -> TestResult {
    let world = world()?;
    // The challenge names the other world's finding digest, which is not the
    // artifact this evaluation supplies.
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

#[test]
fn contesting_a_receipt_the_finding_never_named_is_inadmissible() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::UnnamedReceipt)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::EvidenceBindingMismatch("challenged_evidence_receipt_refs"),
    )?;
    Ok(())
}

#[test]
fn contesting_a_checkpoint_the_finding_never_named_is_inadmissible() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::ForeignCheckpoint)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::EvidenceBindingMismatch("challenged_checkpoint_ref"),
    )?;
    Ok(())
}

#[test]
fn an_evidence_set_smaller_than_the_contested_subset_is_inadmissible() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::Sound)?;
    let proofs = case.revocation_proofs();
    // The challenge contests two receipts; the resolver supplied one.
    let evidence = FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
        purchase_record: &case.purchase_record,
        challenged_receipts: &case.challenged_receipts[..1],
        challenged_checkpoint: &case.challenged_checkpoint,
        revoked_keys: &proofs,
    });
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::EvidenceSetMismatch("challenged_receipts"),
    )?;
    Ok(())
}
