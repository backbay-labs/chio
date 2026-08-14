//! The `evidence_invalid` branch: what counts as affirmative invalidity, and
//! what is only an unresolved input wearing its clothes.

mod support;

use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    FindingChallengeVerdict, FindingEvidenceClass, FindingGuaranteeClass, FindingReceiptRole,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeInadmissible,
    FindingChallengeReason, FindingEvidenceInvalidEvidence, FindingPurchaseStandingEvidence,
};

use support::{
    evidence_case, evidence_case_with_revocations, expect_inadmissible, expect_reason, outcome_for,
    world, world_with, world_with_classes, EvidenceShape, FindingClasses, ProductionShape,
    RevocationShape, TestResult, PUBLISHED_AT,
};

#[test]
fn authenticated_non_revocation_rejects_a_challenge_to_sound_evidence() -> TestResult {
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
fn production_status_revoked_by_publication_cannot_clear_the_challenge() -> TestResult {
    let world = world()?;
    let mut case = evidence_case(&world, EvidenceShape::Sound)?;
    let production_policy = world
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Production)
        .map(|signer| &signer.policy)
        .ok_or("missing production role policy")?;
    case.production_authority_status =
        world.status_for_policy(production_policy, Some(PUBLISHED_AT - 1))?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    Ok(())
}

#[test]
fn a_revocation_signed_after_governance_compromise_cannot_uphold() -> TestResult {
    let world = world()?;
    let mut revoked = vec![world.revocation(
        &world.production_kernel.public_key(),
        PUBLISHED_AT - 1,
        RevocationShape::Sound,
    )?];
    let recorded_at = revoked[0].statement.body.recorded_at;
    revoked[0].governance_authority_status =
        world.status_for_policy(&world.governance_policy, Some(recorded_at))?;
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    Ok(())
}

#[test]
fn a_backdated_revocation_published_after_governance_withdrawal_cannot_uphold() -> TestResult {
    let world = world()?;
    let mut revoked = vec![world.revocation(
        &world.production_kernel.public_key(),
        PUBLISHED_AT - 1,
        RevocationShape::Sound,
    )?];
    let recorded_at = revoked[0].statement.body.recorded_at;
    let governance_revoked_from = recorded_at + 100;
    revoked[0].governance_authority_status =
        world.status_for_policy(&world.governance_policy, Some(governance_revoked_from))?;
    let mut late_publication = revoked[0].publication_status.body.clone();
    late_publication.observed_at = governance_revoked_from + 1;
    revoked[0].publication_status =
        SignedExportEnvelope::sign(late_publication, &world.authority_status)?;
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
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

#[test]
fn evidence_created_after_the_finding_issuance_upholds() -> TestResult {
    let world = world_with(
        FindingClasses::default(),
        ProductionShape::SignedAfterPublication,
    )?;
    // The key is withdrawn after publication but before the receipt can be
    // treated as evidence. Previously the publication-time revocation check
    // classified this as merely indeterminate even though the receipt itself
    // proved it did not exist when the finding was issued.
    let revoked = vec![world.revocation(
        &world.production_kernel.public_key(),
        PUBLISHED_AT + 1,
        RevocationShape::Sound,
    )?];
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
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

/// The signed checkpoint still matches the finding and every wrapper field
/// still agrees with it. Only an unsigned sibling hash is changed, so the bad
/// path establishes caller input failure rather than seller fraud.
#[test]
fn an_invalid_unsigned_inclusion_path_is_indeterminate() -> TestResult {
    let world = world()?;
    let case = evidence_case(&world, EvidenceShape::ContradictoryCheckpoint)?;
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
    let revoked = vec![world.revocation(
        &world.production_kernel.public_key(),
        PUBLISHED_AT - 1,
        RevocationShape::Sound,
    )?];
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
    let revoked = vec![world.revocation(
        &world.production_kernel.public_key(),
        PUBLISHED_AT + 1,
        RevocationShape::Sound,
    )?];
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

/// Revocation is the one fact that can condemn a receipt the venue's log
/// commits, signed by the pinned authority, inside its validity window. Every
/// shape below leaves the statement well formed and breaks exactly one of the
/// bindings that make it the committed profile's own, and none of them may
/// sanction the seller.
#[test]
fn a_revocation_the_profile_does_not_establish_cannot_uphold() -> TestResult {
    for shape in [
        RevocationShape::ForeignSigner,
        RevocationShape::ForeignFeed,
        RevocationShape::ForeignAuthority,
        RevocationShape::ForeignEpoch,
    ] {
        let world = world()?;
        let revoked = vec![world.revocation(
            &world.production_kernel.public_key(),
            PUBLISHED_AT - 1,
            shape,
        )?];
        let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
        let proofs = case.revocation_proofs();
        let evidence = case.evidence(&proofs);
        let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

        let adjudication = expect_reason(
            &evaluation,
            FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
        )
        .map_err(|error| format!("{shape:?}: {error}"))?;
        assert_eq!(
            adjudication.verdict(),
            FindingChallengeVerdict::Indeterminate,
            "{shape:?} must not settle the key's standing"
        );
        assert!(!evaluation.authorizes_penalty(), "{shape:?}");
        outcome_for(&world, &case.challenge, &adjudication)?;
    }
    Ok(())
}

/// An unestablished statement leaves the key's standing open, and an open
/// question is not closed by a second statement that does authenticate.
#[test]
fn one_unestablished_revocation_outweighs_an_established_one() -> TestResult {
    let world = world()?;
    let key = world.production_kernel.public_key();
    let revoked = vec![
        world.revocation(&key, PUBLISHED_AT - 1, RevocationShape::Sound)?,
        world.revocation(&key, PUBLISHED_AT - 1, RevocationShape::ForeignSigner)?,
    ];
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::EvidenceKeyRevocationNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    Ok(())
}

/// A statement about another key does not override the challenged key's
/// independently authenticated non-revocation status.
#[test]
fn a_revocation_of_another_key_does_not_affect_the_challenged_key() -> TestResult {
    let world = world()?;
    let revoked = vec![world.revocation(
        &world.replay_kernel.public_key(),
        PUBLISHED_AT - 1,
        RevocationShape::Sound,
    )?];
    let case = evidence_case_with_revocations(&world, EvidenceShape::Sound, revoked)?;
    let proofs = case.revocation_proofs();
    let evidence = case.evidence(&proofs);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::ChallengedEvidenceValid)?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
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
        purchase_standing: FindingPurchaseStandingEvidence {
            purchase_record: &case.purchase_record,
            delivery_receipt: &case.purchase_standing.delivery_receipt,
            delivery_checkpoint: &case.purchase_standing.delivery_checkpoint,
            delivery_checkpoint_transparency: &case
                .purchase_standing
                .delivery_checkpoint_transparency,
            delivery_authority_status: &case.purchase_standing.delivery_authority_status,
        },
        challenged_receipts: &case.challenged_receipts[..1],
        challenged_checkpoint: &case.challenged_checkpoint,
        checkpoint_transparency: &case.checkpoint_transparency,
        production_authority_status: &case.production_authority_status,
        revoked_keys: &proofs,
    });
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::EvidenceSetMismatch("challenged_receipts"),
    )?;
    Ok(())
}
