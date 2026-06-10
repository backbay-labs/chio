//! Adversary reference scenarios integration test.
//!
//! Loads each of the four reference scenarios under
//! `arena/scenarios/adversary/`, instantiates the declared adversary
//! population, and asserts:
//!
//!   1. The scenario parses (DSL schema and inline-secret invariants hold).
//!   2. The population's [`AdversaryClass`] matches the scenario's class id.
//!   3. Every adversary action lands fail-closed under the toy guard pool
//!      keyed to the scenario's expected (server, tool) scope.
//!   4. Two passes over the same scenario produce byte-identical sequences
//!      of adversary actions, proving the populations are deterministic
//!      with respect to the scenario witness.

use std::path::Path;

use chio_arena::{
    evaluate_against_guards, load_scenario, population_from_block, AdversaryAction, AdversaryClass,
    IssuedScope, ScenarioVerdict,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const REFERENCE_SCENARIOS: &[(&str, AdversaryClass)] = &[
    (
        "../../../arena/scenarios/adversary/prompt_injection.toml",
        AdversaryClass::PromptInjection,
    ),
    (
        "../../../arena/scenarios/adversary/capability_overrequest.toml",
        AdversaryClass::CapabilityOverrequest,
    ),
    (
        "../../../arena/scenarios/adversary/replay_attempt.toml",
        AdversaryClass::ReplayAttempt,
    ),
    (
        "../../../arena/scenarios/adversary/scope_escape.toml",
        AdversaryClass::ScopeEscape,
    ),
];

fn issued_scope_for(class: AdversaryClass) -> IssuedScope {
    let mut scope = IssuedScope::allow("filesystem", "read_file");
    if class == AdversaryClass::ReplayAttempt {
        // The replay-attempt reference scenario sets nonce to this value;
        // mark it as already seen so the toy evaluator denies on reuse.
        scope
            .seen_nonces
            .insert("captured-nonce-feed-cafe".to_string(), ());
    }
    scope
}

#[test]
fn every_adversary_class_has_a_reference_scenario() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (relative_path, _) in REFERENCE_SCENARIOS {
        let path = manifest_dir.join(relative_path);
        assert!(
            path.exists(),
            "reference scenario missing: {}",
            path.display()
        );
    }
}

#[test]
fn reference_scenarios_load_and_attack_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (relative_path, expected_class) in REFERENCE_SCENARIOS {
        let path = manifest_dir.join(relative_path);
        let scenario = load_scenario(&path)?;
        assert_eq!(scenario.adversaries.len(), 1, "{}", path.display());

        let block = &scenario.adversaries[0];
        let mut population = population_from_block(block)?;
        assert_eq!(population.class(), *expected_class, "{}", path.display());

        let issued = issued_scope_for(*expected_class);
        let base_step = scenario.steps[0].clone();
        let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
        for _ in 0..population.len() {
            let action: AdversaryAction = population.next_action(&base_step, &mut rng);
            assert_eq!(action.expected_verdict, ScenarioVerdict::Deny);
            let evaluation = evaluate_against_guards(&action, &issued);
            assert_eq!(
                evaluation.verdict,
                ScenarioVerdict::Deny,
                "scenario {} action {} did not deny",
                path.display(),
                action.mutated_step.id
            );
            assert_eq!(evaluation.reason, action.reason_marker);
        }
    }
    Ok(())
}

#[test]
fn reference_scenarios_are_byte_deterministic_across_runs() -> Result<(), Box<dyn std::error::Error>>
{
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (relative_path, _) in REFERENCE_SCENARIOS {
        let path = manifest_dir.join(relative_path);
        let scenario = load_scenario(&path)?;
        let block = &scenario.adversaries[0];

        let trace_a = trace_actions(block, scenario.rng_seed, &scenario.steps[0])?;
        let trace_b = trace_actions(block, scenario.rng_seed, &scenario.steps[0])?;
        assert_eq!(
            trace_a,
            trace_b,
            "scenario {} adversary trace diverged across runs",
            path.display()
        );
    }
    Ok(())
}

fn trace_actions(
    block: &chio_arena::scenario::ScenarioAdversary,
    rng_seed: u64,
    base_step: &chio_arena::ScenarioStep,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut population = population_from_block(block)?;
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut bytes: Vec<u8> = Vec::new();
    for _ in 0..population.len() {
        let action = population.next_action(base_step, &mut rng);
        let line = format!(
            "{}|{}|{}|{}|{}\n",
            action.class,
            action.population,
            action.mutated_step.id,
            action.reason_marker,
            serde_json::to_string(&action.mutated_step.arguments)?
        );
        bytes.extend_from_slice(line.as_bytes());
    }
    Ok(bytes)
}
