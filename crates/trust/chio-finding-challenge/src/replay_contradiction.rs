//! The `replay_contradiction` branch.
//!
//! The recipe is the seller's own precommitment, so the first thing this
//! branch does is prove the carried preimage IS that recipe: strict-parse it,
//! hash it, and require equality with the digest the signed finding
//! committed. A preimage that does not hash to the commitment is not weak
//! evidence, it is a different document, and the submission rejects before
//! anything is evaluated.
//!
//! Each reproduction is then held to the same standard: role-scoped to the
//! profile's replay authority, checkpoint-proved, and terminated by a receipt
//! whose content hash IS the digest of the exact observation preimage the
//! challenge carried. Every pre-run commitment the recipe fixed holds for the
//! run that produced it as well (the runner manifest, the phase input bundle,
//! and the execution environment), because a divergence in any of them makes
//! the exit code a fact about the run rather than about the claim. Only
//! observations that ran to completion feed the predicate. A phase that failed to run, timed out, exhausted a cap, or died
//! in the runner is an infrastructure fact and can never become seller fraud.
//!
//! The contradiction is against the recipe's claimed verdict, not against an
//! opinion in the observation: the observation deliberately has no member for
//! a conclusion, so the conclusion is computed here from the committed
//! predicate and compared with what the seller claimed.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::decision::Decision;
use chio_finding::{
    FindingChallengeFacet, FindingClaimedVerdict, FindingPredicate, FindingReceiptRole,
    FindingRecipePhaseKind, FindingReplayContradictionFacet, FindingReplayObservation,
    FindingReplayPredicateResult, FindingReplayRecipeInput, FindingReplayReproduction,
    FindingReplayTerminalResult, MAX_CHALLENGE_RECIPE_PREIMAGE_BYTES, MAX_REPLAY_OBSERVATION_BYTES,
};
use chio_finding_verifier::{verify_checkpoint_membership, verify_receipt_strict};

use crate::evaluate::EvaluationContext;
use crate::ingress::strict_parse;
use crate::input::{
    FindingChallengeAdjudication, FindingChallengeInadmissible, FindingReplayContradictionEvidence,
};
use crate::reason::FindingChallengeReason;
use crate::receipts::{
    checkpoint_matches_reference, policy_covers, receipt_matches_reference, role_policy,
};
use crate::standing::bind_purchase_record;

pub(crate) fn evaluate_replay_contradiction(
    context: &EvaluationContext<'_>,
    reproduction: &[FindingReplayReproduction],
    recipe_preimage: &str,
    purchase_record_envelope_sha256: &str,
    evidence: &FindingReplayContradictionEvidence<'_>,
) -> Result<FindingChallengeAdjudication, FindingChallengeInadmissible> {
    bind_purchase_record(
        context,
        evidence.purchase_record,
        purchase_record_envelope_sha256,
    )?;

    let Some(committed_recipe_sha256) = context.finding.replay_recipe_sha256.as_deref() else {
        return Err(FindingChallengeInadmissible::RecipeCommitmentAbsent);
    };
    let (recipe, recipe_bytes) = strict_parse::<FindingReplayRecipeInput>(
        recipe_preimage,
        MAX_CHALLENGE_RECIPE_PREIMAGE_BYTES,
    )
    .map_err(FindingChallengeInadmissible::RecipePreimageRejected)?;
    let recipe_sha256 = sha256_hex(&recipe_bytes);
    if recipe_sha256 != committed_recipe_sha256 {
        return Err(FindingChallengeInadmissible::RecipePreimageMismatch);
    }

    if evidence.reproductions.len() != reproduction.len() {
        return Err(FindingChallengeInadmissible::EvidenceSetMismatch(
            "reproductions",
        ));
    }

    // The carried observations are the preimages whose digests the mediated
    // receipts committed; parse them all before anything is evaluated so a
    // malformed one rejects the submission rather than degrading it.
    let mut observations: Vec<ResolvedObservation> = Vec::with_capacity(reproduction.len());
    for tuple in reproduction {
        let (observation, observation_bytes) = strict_parse::<FindingReplayObservation>(
            &tuple.observation_bytes,
            MAX_REPLAY_OBSERVATION_BYTES,
        )
        .map_err(FindingChallengeInadmissible::ObservationRejected)?;
        if observation.recipe_digest != recipe_sha256 {
            return Err(FindingChallengeInadmissible::ObservationBindingMismatch(
                "recipe_digest",
            ));
        }
        if observation.verifier_profile_digest != context.profile_envelope_sha256 {
            return Err(FindingChallengeInadmissible::ObservationBindingMismatch(
                "verifier_profile_digest",
            ));
        }
        if let Some(first) = observations.first() {
            if first.observation.replay_run_id != observation.replay_run_id {
                return Err(FindingChallengeInadmissible::ObservationBindingMismatch(
                    "replay_run_id",
                ));
            }
        }
        observations.push(ResolvedObservation {
            digest: sha256_hex(&observation_bytes),
            observation,
        });
    }
    let Some(first) = observations.first() else {
        return Err(FindingChallengeInadmissible::EvidenceSetMismatch(
            "reproductions",
        ));
    };
    let mut observation_digests: Vec<String> = Vec::with_capacity(observations.len());
    for resolved in &observations {
        if !observation_digests.contains(&resolved.digest) {
            observation_digests.push(resolved.digest.clone());
        }
    }
    let facet = ReplayFacet {
        replay_run_id: first.observation.replay_run_id.clone(),
        recipe_sha256,
        predicate: recipe.predicate,
        observation_digests,
    };

    // A predicate the governance profile does not admit cannot adjudicate
    // anything, however well the run reproduced.
    if !context
        .profile
        .allowed_predicates
        .contains(&recipe.predicate)
    {
        return Ok(facet.adjudication(
            FindingReplayPredicateResult::Indeterminate,
            FindingChallengeReason::ReplayPredicateNotAdmitted,
        ));
    }
    let Some(replay_policy) = role_policy(context.profile, FindingReceiptRole::Replay) else {
        return Ok(facet.adjudication(
            FindingReplayPredicateResult::Indeterminate,
            FindingChallengeReason::ReplayAuthorityNotEstablished,
        ));
    };
    // The environment is an exact commitment of the seller's own recipe, so
    // the digest each run must report is derived from that recipe here rather
    // than taken from the run.
    let Ok(committed_environment) =
        canonical_json_bytes(&recipe.environment).map(|bytes| sha256_hex(&bytes))
    else {
        return Ok(facet.adjudication(
            FindingReplayPredicateResult::Indeterminate,
            FindingChallengeReason::ReplayObservationNotEstablished,
        ));
    };

    for ((tuple, carried), resolved) in reproduction
        .iter()
        .zip(&observations)
        .zip(evidence.reproductions)
    {
        let observation = &carried.observation;
        if !receipt_matches_reference(
            resolved.receipt,
            &tuple.receipt_ref.receipt_id,
            &tuple.receipt_ref.receipt_sha256,
        ) || !checkpoint_matches_reference(resolved.checkpoint, &tuple.checkpoint_ref)
            || verify_receipt_strict(&resolved.receipt.receipt).is_err()
        {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        let receipt = &resolved.receipt.receipt;
        if !matches!(receipt.decision, Some(Decision::Allow)) {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        if receipt.kernel_key != replay_policy.key
            || !policy_covers(replay_policy, receipt.timestamp)
        {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayAuthorityNotEstablished,
            ));
        }
        if verify_checkpoint_membership(
            core::slice::from_ref(resolved.receipt),
            core::slice::from_ref(resolved.checkpoint),
            resolved.checkpoint_transparency,
            context.profile,
            &tuple.checkpoint_ref.checkpoint_ref,
        )
        .is_err()
        {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        // The terminal receipt commits the observation by digest. Without
        // this equality the carried bytes are a restatement rather than the
        // thing the runner actually emitted.
        if receipt.content_hash != carried.digest {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        if observation.runner_manifest_digest != recipe.runner_manifest_sha256
            || !context
                .profile
                .allowed_runner_manifests
                .contains(&observation.runner_manifest_digest)
        {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        // An exit code produced under an environment the recipe never
        // committed is a fact about that environment, never about the claim.
        if observation.environment_digest != committed_environment {
            return Ok(facet.adjudication(
                FindingReplayPredicateResult::Indeterminate,
                FindingChallengeReason::ReplayObservationNotEstablished,
            ));
        }
        let phase = recipe
            .phases
            .iter()
            .find(|phase| phase.phase == observation.phase_id);
        match phase {
            Some(phase)
                if phase.input_bundle_sha256 == observation.resolved_input_bundle_digest => {}
            _ => {
                return Ok(facet.adjudication(
                    FindingReplayPredicateResult::Indeterminate,
                    FindingChallengeReason::ReplayObservationNotEstablished,
                ))
            }
        }
        // Only a completed phase is a fact about the claim. Every other
        // terminal is a fact about the infrastructure.
        match observation.terminal_result {
            FindingReplayTerminalResult::Completed => {}
            FindingReplayTerminalResult::Failed
            | FindingReplayTerminalResult::TimedOut
            | FindingReplayTerminalResult::ResourceExhausted
            | FindingReplayTerminalResult::RunnerError => {
                return Ok(facet.adjudication(
                    FindingReplayPredicateResult::Indeterminate,
                    FindingChallengeReason::ReplayRunIncomplete,
                ))
            }
        }
    }

    let (Some(baseline), Some(candidate)) = (
        single_phase(&observations, FindingRecipePhaseKind::Baseline),
        single_phase(&observations, FindingRecipePhaseKind::Candidate),
    ) else {
        return Ok(facet.adjudication(
            FindingReplayPredicateResult::Indeterminate,
            FindingChallengeReason::ReplayPhasesAmbiguous,
        ));
    };
    if observations.len() != 2 {
        return Ok(facet.adjudication(
            FindingReplayPredicateResult::Indeterminate,
            FindingChallengeReason::ReplayPhasesAmbiguous,
        ));
    }

    let observed = match recipe.predicate {
        FindingPredicate::BaselineFailsCandidatePassesV1 => {
            baseline.exit_code != 0 && candidate.exit_code == 0
        }
    };
    let claimed = match recipe.claimed_verdict {
        FindingClaimedVerdict::PredicateHolds => true,
        FindingClaimedVerdict::PredicateFails => false,
    };
    if observed == claimed {
        Ok(facet.adjudication(
            FindingReplayPredicateResult::Consistent,
            FindingChallengeReason::ReplayReproductionConsistent,
        ))
    } else {
        Ok(facet.adjudication(
            FindingReplayPredicateResult::ConfirmedContradiction,
            FindingChallengeReason::ReplayContradictionConfirmed,
        ))
    }
}

/// One carried observation and the digest of the exact bytes that carried
/// it, which is the value the terminal receipt must have committed.
struct ResolvedObservation {
    digest: String,
    observation: FindingReplayObservation,
}

/// The single observation for one phase, or `None` when the set presents
/// zero or several.
fn single_phase(
    observations: &[ResolvedObservation],
    phase: FindingRecipePhaseKind,
) -> Option<&FindingReplayObservation> {
    let mut matching = observations
        .iter()
        .map(|resolved| &resolved.observation)
        .filter(|observation| observation.phase_id == phase);
    let first = matching.next()?;
    match matching.next() {
        Some(_) => None,
        None => Some(first),
    }
}

/// The facet members fixed before evaluation, so every exit builds the same
/// facet with only the predicate result differing.
struct ReplayFacet {
    replay_run_id: String,
    recipe_sha256: String,
    predicate: FindingPredicate,
    observation_digests: Vec<String>,
}

impl ReplayFacet {
    fn adjudication(
        &self,
        predicate_result: FindingReplayPredicateResult,
        reason: FindingChallengeReason,
    ) -> FindingChallengeAdjudication {
        debug_assert_eq!(
            chio_finding::verdict_for_replay_predicate(predicate_result),
            reason.verdict()
        );
        FindingChallengeAdjudication::new(
            FindingChallengeFacet::ReplayContradiction(FindingReplayContradictionFacet {
                replay_run_id: self.replay_run_id.clone(),
                recipe_sha256: self.recipe_sha256.clone(),
                predicate: self.predicate,
                predicate_result,
                observation_digests: self.observation_digests.clone(),
            }),
            reason,
        )
    }
}
