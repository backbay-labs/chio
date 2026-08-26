//! The `replay_contradiction` branch: the recipe gate, the reproduction
//! bindings, and the nested predicate mapping.

mod support;

use chio_core_types::canonical_json_string;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_finding_id, sign_finding, verdict_for_replay_predicate, FindingChallengeVerdict,
    FindingEvidenceClass, FindingGuaranteeClass, FindingReplayPredicateResult,
    FindingReplayRecipeInput, FindingReplayTerminalResult,
};
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeClassEvidence, FindingChallengeInadmissible,
    FindingChallengeReason, FindingPurchaseStandingEvidence, FindingReplayContradictionEvidence,
};

use support::{
    expect_inadmissible, expect_reason, foreign_recipe_preimage, outcome_for, replay_case, world,
    world_with_classes, FindingClasses, PhaseShape, ReplayShape, TestResult, World, HEX64_ALT,
    HEX64_THIRD,
};

fn recommit_recipe(world: &mut World) -> TestResult {
    world.recipe_preimage = canonical_json_string(&world.recipe)?;
    world.recipe_sha256 = sha256_hex(world.recipe_preimage.as_bytes());
    world.finding.replay_recipe_sha256 = Some(world.recipe_sha256.clone());
    world.finding.finding_id = compute_finding_id(&world.finding)?;
    world.finding = sign_finding(world.finding.clone(), &world.issuer)?;
    world.raw_finding = canonical_json_string(&world.finding)?;
    world.finding_artifact_sha256 = sha256_hex(world.raw_finding.as_bytes());
    Ok(())
}

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
fn a_reproduction_signed_by_a_revoked_replay_key_is_indeterminate() -> TestResult {
    let world = world()?;
    let mut case = replay_case(&world, &ReplayShape::default())?;
    let mut status = case.replay_authority_status.body.clone();
    status.revoked_from = Some(case.receipts[0].receipt.timestamp);
    case.replay_authority_status = SignedExportEnvelope::sign(status, &world.authority_status)?;
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));

    expect_reason(
        &evaluation,
        FindingChallengeReason::ReplayAuthorityNotEstablished,
    )?;
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
fn a_replay_receipt_must_bind_the_committed_invocation() -> TestResult {
    let world = world()?;
    let shapes = [
        ReplayShape {
            receipt_tool_server: Some("attacker-runner".to_string()),
            ..ReplayShape::default()
        },
        ReplayShape {
            receipt_tool_name: Some("finding.replay-uncommitted".to_string()),
            ..ReplayShape::default()
        },
        ReplayShape {
            action_parameters: Some(serde_json::json!({
                "parameters_sha256": HEX64_THIRD,
                "phase": "candidate",
                "replay_run_id": "attacker-run",
            })),
            ..ReplayShape::default()
        },
    ];

    for shape in shapes {
        let case = replay_case(&world, &shape)?;
        let reproductions = case.reproductions();
        let evidence = case.evidence(&reproductions);
        let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));
        expect_reason(
            &evaluation,
            FindingChallengeReason::ReplayObservationNotEstablished,
        )?;
    }
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
            purchase_standing: FindingPurchaseStandingEvidence {
                purchase_record: &case.purchase_record,
                bid_request: &case.purchase_standing.bid_request,
                accepted_bid: &case.purchase_standing.accepted_bid,
                reservation_receipt: &case.purchase_standing.reservation_receipt,
                delivery_receipt: &case.purchase_standing.delivery_receipt,
                delivery_checkpoint: &case.purchase_standing.delivery_checkpoint,
                delivery_checkpoint_transparency: &case
                    .purchase_standing
                    .delivery_checkpoint_transparency,
                delivery_authority_status: &case.purchase_standing.delivery_authority_status,
            },
            replay_authority_status: &case.replay_authority_status,
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
fn a_committed_recipe_must_bind_the_challenged_finding_and_profile() -> TestResult {
    type RecipeMutation = fn(&mut FindingReplayRecipeInput);
    let cases: [(&str, RecipeMutation); 4] = [
        ("context_sha256", |recipe| {
            recipe.context_sha256 = HEX64_ALT.to_string()
        }),
        ("payload_sha256", |recipe| {
            recipe.payload_sha256 = HEX64_ALT.to_string()
        }),
        ("resource_bounds", |recipe| {
            recipe.resource_bounds.max_runtime_secs += 1;
        }),
        ("runner_manifest_sha256", |recipe| {
            recipe.runner_manifest_sha256 = HEX64_ALT.to_string();
        }),
    ];

    for (field, mutate) in cases {
        let mut world = world()?;
        mutate(&mut world.recipe);
        recommit_recipe(&mut world)?;
        let case = replay_case(&world, &ReplayShape::default())?;
        let reproductions = case.reproductions();
        let evidence = case.evidence(&reproductions);
        let evaluation = evaluate_finding_challenge(&world.input(&case.challenge, &evidence));
        expect_inadmissible(
            &evaluation,
            &FindingChallengeInadmissible::RecipeBindingMismatch(field),
        )?;
    }
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
