//! The `digest_mismatch` branch, including the denials that look like fraud
//! and are not.

mod support;

use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{DeliveryResult, FindingMediaTypeCheck};
use chio_finding::{
    compute_challenge_id, signed_envelope_sha256, FindingChallengeAuthorization,
    FindingChallengeEvidence, FindingChallengeStanding, FindingChallengeVerdict,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeInadmissible, FindingChallengeReason,
};

use support::{
    digest_case, expect_inadmissible, expect_reason, keypair, outcome_for, venue_digest_case,
    world, DenyShape, DenySigner, TestResult, EVALUATED_AT, HEX64_THIRD,
};

#[test]
fn authenticated_seller_origin_mismatch_upholds() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::SellerOriginDigestMismatch,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    assert!(evaluation.authorizes_penalty());

    // The facet the caller signs must satisfy the artifact family, including
    // the identity profile, the zero realized spend, and the requirement that
    // an upheld mismatch actually differ.
    let outcome = outcome_for(&world, &case.challenge, &adjudication)?;
    assert!(outcome.penalty_calculation.is_some());
    Ok(())
}

#[test]
fn admission_pinned_failed_delivery_rotation_overrides_the_reusable_profile() -> TestResult {
    let world = world()?;
    let mut case = digest_case(&world, &DenyShape::seller_origin())?;
    let rotated_authority = keypair(91);
    let mut admission_policy = world.profile.body.failed_delivery_authority.clone();
    admission_policy.authority_id = "authority-failed-delivery-admission".to_string();
    admission_policy.key = rotated_authority.public_key();
    admission_policy.key_epoch += 1;

    case.failed_delivery =
        SignedExportEnvelope::sign(case.failed_delivery.body.clone(), &rotated_authority)?;
    let failed_delivery_envelope_sha256 = signed_envelope_sha256(&case.failed_delivery)?;
    let FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: challenged_digest,
        ..
    } = &mut case.challenge.body.evidence
    else {
        return Err("digest case must contain digest-mismatch evidence".into());
    };
    *challenged_digest = failed_delivery_envelope_sha256.clone();
    let FindingChallengeAuthorization::BuyerSubmission(submission) =
        &mut case.challenge.body.authorization
    else {
        return Err("digest case must be buyer authorized".into());
    };
    let FindingChallengeStanding::FailedDelivery {
        failed_delivery_envelope_sha256: standing_digest,
        ..
    } = &mut submission.standing
    else {
        return Err("digest case must carry failed-delivery standing".into());
    };
    *standing_digest = failed_delivery_envelope_sha256;
    case.challenge.body.challenge_id = compute_challenge_id(&case.challenge.body)?;
    case.challenge = SignedExportEnvelope::sign(case.challenge.body.clone(), &world.buyer)?;
    case.failed_delivery_authority_status = world.status_for_policy(&admission_policy, None)?;

    let evidence = case.evidence();
    let mut input = world.input(&case.challenge, &evidence);
    input.pinned_failed_delivery_authority = &admission_policy;
    let evaluation = evaluate_finding_challenge(&input);

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::SellerOriginDigestMismatch,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    Ok(())
}

#[test]
fn revoked_failed_delivery_authority_cannot_establish_standing() -> TestResult {
    let world = world()?;
    let mut case = digest_case(&world, &DenyShape::seller_origin())?;
    let mut status = case.failed_delivery_authority_status.body.clone();
    status.revoked_from = Some(case.failed_delivery.body.recorded_at);
    case.failed_delivery_authority_status =
        SignedExportEnvelope::sign(status, &world.authority_status)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::FailedDeliveryAuthorityNotEstablished,
    )
}

#[test]
fn stale_failed_delivery_status_cannot_establish_standing() -> TestResult {
    let world = world()?;
    let mut case = digest_case(&world, &DenyShape::seller_origin())?;
    let mut status = case.failed_delivery_authority_status.body.clone();
    status.observed_at = EVALUATED_AT - 3_601;
    case.failed_delivery_authority_status =
        SignedExportEnvelope::sign(status, &world.authority_status)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::FailedDeliveryAuthorityNotEstablished,
    )
}

#[test]
fn revoked_delivery_receipt_key_cannot_establish_a_mismatch() -> TestResult {
    let world = world()?;
    let mut case = digest_case(&world, &DenyShape::seller_origin())?;
    let mut status = case.delivery_authority_status.body.clone();
    status.revoked_from = Some(case.deny_receipt.receipt.timestamp);
    case.delivery_authority_status = SignedExportEnvelope::sign(status, &world.authority_status)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryAuthorityNotEstablished,
    )?;
    Ok(())
}

#[test]
fn a_deny_receipt_with_a_broken_action_commitment_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        break_action_commitment: true,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryEvidenceNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    Ok(())
}

#[test]
fn a_venue_audit_may_file_the_same_class() -> TestResult {
    let world = world()?;
    let case = venue_digest_case(&world, &DenyShape::seller_origin())?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::SellerOriginDigestMismatch,
    )?;
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_delivery_that_matched_its_commitment_is_rejected() -> TestResult {
    let world = world()?;
    let case = digest_case(&world, &DenyShape::matched())?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveredOutputMatchesCommitment,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_matched_overlay_disagreeing_with_the_delivery_contract_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        contract_result: DeliveryResult::Mismatched,
        overlay_digest_check: DeliveryResult::Matched,
        observed_digest: HEX64_THIRD.to_string(),
        ..DenyShape::matched()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryEvidenceNotEstablished,
    )?;
    Ok(())
}

#[test]
fn a_matched_comparison_against_an_operator_expectation_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        expected_digest: Some(HEX64_THIRD.to_string()),
        observed_digest: HEX64_THIRD.to_string(),
        ..DenyShape::matched()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryEvidenceNotEstablished,
    )?;
    Ok(())
}

#[test]
fn a_generic_digest_denial_can_never_uphold() -> TestResult {
    let world = world()?;
    // No finding-delivery overlay: nothing establishes that the expectation
    // was the seller's own commitment or that the transform plan was frozen.
    let shape = DenyShape {
        include_overlay: false,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::DenialNotSellerOrigin)?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn an_output_policy_transform_denial_can_never_uphold() -> TestResult {
    let world = world()?;
    // The kernel compared the output against an expectation the operator
    // chose rather than the digest the signed finding committed.
    let shape = DenyShape {
        expected_digest: Some(HEX64_THIRD.to_string()),
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::DenialOutputPolicyExpectation,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_media_type_denial_can_never_uphold() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        contract_result: DeliveryResult::Matched,
        overlay_digest_check: DeliveryResult::Matched,
        media_type_check: FindingMediaTypeCheck::Mismatched,
        observed_digest: world.finding.payload_sha256.clone(),
        decision: Decision::Deny {
            reason: "delivered reveal envelope media type does not match the advertised type"
                .to_string(),
            guard: "finding_delivery".to_string(),
        },
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::DenialMediaTypeMismatch)?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_denial_signed_outside_the_delivery_role_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        signer: DenySigner::Production,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryAuthorityNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn an_unresolved_denial_checkpoint_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        substitute_checkpoint: true,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryCheckpointNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    Ok(())
}

#[test]
fn a_denial_without_delivery_evidence_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        include_contract: false,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryEvidenceNotEstablished,
    )?;
    Ok(())
}

#[test]
fn a_receipt_that_is_not_a_denial_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = DenyShape {
        decision: Decision::Allow,
        ..DenyShape::seller_origin()
    };
    let case = digest_case(&world, &shape)?;
    let evidence = case.evidence();
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::DeliveryEvidenceNotEstablished,
    )?;
    Ok(())
}
