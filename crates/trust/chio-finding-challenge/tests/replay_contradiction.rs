//! The `replay_contradiction` branch: the recipe gate, the reproduction
//! bindings, and the nested predicate mapping.

mod support;

use chio_core_types::receipt::decision::Decision;
use chio_finding::{
    verdict_for_replay_predicate, FindingChallengeVerdict, FindingEvidenceClass,
    FindingGuaranteeClass, FindingReplayPredicateResult, FindingReplayTerminalResult,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeInadmissible,
    FindingChallengeReason, FindingReplayContradictionEvidence,
};

use support::{
    expect_inadmissible, expect_reason, foreign_recipe_preimage, outcome_for, replay_case, world,
    world_with_classes, FindingClasses, PhaseShape, ReplayShape, TestResult, HEX64_THIRD,
};

#[test]
fn a_reproduction_that_agrees_with_the_claim_is_rejected() -> TestResult {
    let world = world()?;
    let case = replay_case(&world, &ReplayShape::default())?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayReproductionConsistent,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Rejected);
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_reproduction_that_contradicts_the_claim_upholds() -> TestResult {
    let world = world()?;
    // The seller claimed the predicate holds; the candidate phase did not
    // pass, so the committed predicate fails on the reproduced run.
    let shape = ReplayShape {
        phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayContradictionConfirmed,
    )?;
    assert_eq!(adjudication.verdict(), FindingChallengeVerdict::Upheld);
    assert!(evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_baseline_that_also_passes_contradicts_the_claim() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![
            PhaseShape::baseline_passes(),
            PhaseShape::candidate_passes(),
        ],
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayContradictionConfirmed,
    )?;
    Ok(())
}

#[test]
fn a_phase_that_did_not_complete_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![
            PhaseShape::baseline_fails(),
            PhaseShape {
                terminal: FindingReplayTerminalResult::TimedOut,
                ..PhaseShape::candidate_fails()
            },
        ],
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::ReplayRunIncomplete)?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_runner_error_is_indeterminate_rather_than_a_failed_predicate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![
            PhaseShape {
                terminal: FindingReplayTerminalResult::RunnerError,
                ..PhaseShape::baseline_fails()
            },
            PhaseShape::candidate_fails(),
        ],
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(&evaluation, FindingChallengeReason::ReplayRunIncomplete)?;
    Ok(())
}

#[test]
fn a_missing_phase_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![PhaseShape::baseline_fails()],
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(&evaluation, FindingChallengeReason::ReplayPhasesAmbiguous)?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    outcome_for(&world, &case.challenge, &adjudication)?;
    Ok(())
}

#[test]
fn a_reproduction_signed_outside_the_replay_role_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        signer: Some(55),
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayAuthorityNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    Ok(())
}

#[test]
fn a_receipt_that_does_not_commit_its_observation_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        break_content_commitment: true,
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayObservationNotEstablished,
    )?;
    Ok(())
}

#[test]
fn a_receipt_with_a_broken_action_commitment_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        break_action_commitment: true,
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayObservationNotEstablished,
    )?;
    assert_eq!(
        adjudication.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert!(!evaluation.authorizes_penalty());
    Ok(())
}

#[test]
fn a_denied_replay_receipt_cannot_establish_an_execution() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        decision: Decision::Deny {
            reason: "replay execution was not authorized".to_string(),
            guard: "replay_policy".to_string(),
        },
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayObservationNotEstablished,
    )?;
    Ok(())
}

/// The environment is the commitment that decides whether an exit code is
/// reproducible at all, so a run under one the recipe never committed cannot
/// contradict the claim, however cleanly it reproduced.
#[test]
fn a_reproduction_under_an_uncommitted_environment_is_indeterminate() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        // Phases that would otherwise confirm a contradiction.
        phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        environment_digest: Some(HEX64_THIRD.to_string()),
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    let adjudication = expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayObservationNotEstablished,
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
fn a_reproduction_set_smaller_than_the_challenge_is_inadmissible() -> TestResult {
    let world = world()?;
    let case = replay_case(&world, &ReplayShape::default())?;
    let reproductions = case.reproductions();
    // The challenge carries two tuples; the resolver supplied one.
    let evidence =
        FindingChallengeClassEvidence::ReplayContradiction(FindingReplayContradictionEvidence {
            purchase_record: &case.purchase_record,
            reproductions: &reproductions[..1],
        });
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::EvidenceSetMismatch("reproductions"),
    )?;
    Ok(())
}

#[test]
fn a_recipe_preimage_that_is_not_the_committed_one_rejects_before_evaluation() -> TestResult {
    let world = world()?;
    let shape = ReplayShape {
        recipe_preimage: Some(foreign_recipe_preimage(&world)?),
        ..ReplayShape::default()
    };
    let case = replay_case(&world, &shape)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_inadmissible(
        &evaluation,
        &FindingChallengeInadmissible::RecipePreimageMismatch,
    )?;
    Ok(())
}

#[test]
fn a_finding_without_a_committed_recipe_cannot_be_replay_challenged() -> TestResult {
    let world = world_with_classes(FindingClasses {
        guarantee: FindingGuaranteeClass::MeteredAttested,
        evidence: FindingEvidenceClass::Verified,
    })?;
    let case = replay_case(&world, &ReplayShape::default())?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    match &evaluation {
        chio_finding_challenge::FindingChallengeEvaluation::Inadmissible(
            FindingChallengeInadmissible::ClassIncompatible(_),
        ) => {}
        other => panic!("expected a cross-class rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn the_nested_predicate_mapping_is_total_and_reachable() -> TestResult {
    // The mapping itself.
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::ConfirmedContradiction),
        FindingChallengeVerdict::Upheld
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Consistent),
        FindingChallengeVerdict::Rejected
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Indeterminate),
        FindingChallengeVerdict::Indeterminate
    );

    // Every arm is reachable through the evaluator, and each carries the
    // nested result the outcome validator will recheck against the verdict.
    let world = world()?;
    let cases = [
        (
            ReplayShape {
                phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
                ..ReplayShape::default()
            },
            FindingReplayPredicateResult::ConfirmedContradiction,
        ),
        (
            ReplayShape::default(),
            FindingReplayPredicateResult::Consistent,
        ),
        (
            ReplayShape {
                phases: vec![PhaseShape::baseline_fails()],
                ..ReplayShape::default()
            },
            FindingReplayPredicateResult::Indeterminate,
        ),
    ];
    for (shape, expected) in cases {
        let case = replay_case(&world, &shape)?;
        let reproductions = case.reproductions();
        let evidence = case.evidence(&reproductions);
        let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));
        let adjudication = evaluation
            .adjudication()
            .ok_or_else(|| std::io::Error::other(format!("expected {expected:?}")))?;
        assert_eq!(
            adjudication.verdict(),
            verdict_for_replay_predicate(expected)
        );
        match adjudication.facet() {
            chio_finding::FindingChallengeFacet::ReplayContradiction(facet) => {
                assert_eq!(facet.predicate_result, expected);
                assert_eq!(facet.recipe_sha256, world.recipe_sha256);
            }
            other => panic!("expected a replay facet, got {other:?}"),
        }
        outcome_for(&world, &case.challenge, adjudication)?;
    }
    Ok(())
}
