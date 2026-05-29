//! Fitness-function tests.
//!
//! Asserts the per-adversary survival-rate computation, the verdict-tuple
//! shape borrowed from the verdict-matrix oracle, and the fitness
//! aggregation across multiple populations. Determinism is covered
//! separately by `coevolve_determinism.rs`; these tests only assert the
//! static contract of the fitness surface.

use chio_arena::adversary::capability_overrequest::OverrequestVariant;
use chio_arena::adversary::scope_escape::ScopeEscalation;
use chio_arena::{
    evaluate_population, parse_scenario_str, population_from_block, AdversaryClass,
    AdversaryPopulation, CapabilityOverrequestAdversary, FitnessError, FitnessInputs,
    FitnessReport, FitnessSample, IssuedScope, MatrixVerdict, ScopeEscapeAdversary,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SCENARIO: &str = r#"
schema_version = "chio.arena.scenario/v1"
id = "fitness_round_robin"
title = "Fitness round-robin"
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/fitness.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/fitness.txt" }
expect_verdict = "allow"

[[adversaries]]
class = "prompt-injection"
population = "fitness-injection"
seed_ref = "fuzz/artifacts"

[adversaries.params]
patterns = ["ignore-previous-instructions", "system-prompt-leak"]
"#;

fn population() -> Result<AdversaryPopulation, Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    Ok(population_from_block(&scenario.adversaries[0])?)
}

#[test]
fn fitness_sample_records_survival_and_defeat_counts() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let mut population = population()?;
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let issued = IssuedScope::allow("filesystem", "read_file");

    let sample = evaluate_population(
        &mut population,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        4,
    )?;
    assert_eq!(sample.class, AdversaryClass::PromptInjection);
    assert_eq!(sample.population, "fitness-injection");
    assert_eq!(sample.tuples.len(), 4);
    assert_eq!(sample.step_ids.len(), 4);
    // Prompt-injection actions are denied by the toy guard pool, so the
    // adversary defeat count covers every action.
    assert_eq!(sample.defeats, 4);
    assert_eq!(sample.survivals, 0);
    assert_eq!(sample.total(), 4);
    assert!((sample.survival_rate() - 0.0).abs() < f64::EPSILON);
    for tuple in &sample.tuples {
        assert_eq!(tuple.verdict, MatrixVerdict::Deny);
        assert_eq!(tuple.scope_set, vec!["filesystem:read_file".to_string()]);
        assert!(!tuple.reason_code.is_empty());
    }
    Ok(())
}

#[test]
fn capability_overrequest_population_survives_against_narrow_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    // Capability-overrequest adversaries ask for tools outside the issued
    // scope; the toy guards Allow actions that match the issued scope and
    // Deny the rest. We exercise a single adversary that asks for
    // `secrets:read_file` while the issued scope only permits
    // `filesystem:read_file`, so survival rate is 0.0; another that asks
    // for the issuer's own tool, so survival rate is 1.0.
    let scenario = parse_scenario_str(SCENARIO)?;
    let escaping = CapabilityOverrequestAdversary::new(
        "escape",
        OverrequestVariant {
            label: "deny-target".to_string(),
            target_server: "secrets".to_string(),
            target_tool: "read_file".to_string(),
        },
    );
    let on_target = CapabilityOverrequestAdversary::new(
        "subset",
        OverrequestVariant {
            label: "allow-target".to_string(),
            target_server: "filesystem".to_string(),
            target_tool: "read_file".to_string(),
        },
    );
    let mut escape_pop = AdversaryPopulation::new("escape", vec![Box::new(escaping)])?;
    let mut subset_pop = AdversaryPopulation::new("subset", vec![Box::new(on_target)])?;
    let issued = IssuedScope::allow("filesystem", "read_file");

    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let escape_sample = evaluate_population(
        &mut escape_pop,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        3,
    )?;
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let subset_sample = evaluate_population(
        &mut subset_pop,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        3,
    )?;
    assert!((escape_sample.survival_rate() - 0.0).abs() < f64::EPSILON);
    assert!((subset_sample.survival_rate() - 1.0).abs() < f64::EPSILON);
    Ok(())
}

#[test]
fn fitness_report_ranks_populations_descending_by_survival_rate(
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");

    // Two populations, deliberately given different on-/off-scope targets
    // so their survival rates differ.
    let on = CapabilityOverrequestAdversary::new(
        "on",
        OverrequestVariant {
            label: "on".to_string(),
            target_server: "filesystem".to_string(),
            target_tool: "read_file".to_string(),
        },
    );
    let off = ScopeEscapeAdversary::new(
        "off",
        ScopeEscalation {
            label: "broaden".to_string(),
            server: "filesystem".to_string(),
            tool: "write_file".to_string(),
        },
    );
    let mut on_pop = AdversaryPopulation::new("on", vec![Box::new(on)])?;
    let mut off_pop = AdversaryPopulation::new("off", vec![Box::new(off)])?;

    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let on_sample = evaluate_population(
        &mut on_pop,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        2,
    )?;
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let off_sample = evaluate_population(
        &mut off_pop,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        2,
    )?;
    let mut samples: std::collections::BTreeMap<String, FitnessSample> = Default::default();
    samples.insert(on_sample.population.clone(), on_sample);
    samples.insert(off_sample.population.clone(), off_sample);
    let report = FitnessReport { samples };
    assert!((report.best_survival_rate() - 1.0).abs() < f64::EPSILON);
    let ranked = report.ranked_population_names();
    assert_eq!(ranked.first().map(String::as_str), Some("on"));
    Ok(())
}

#[test]
fn fitness_evaluation_rejects_zero_rounds() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let mut population = population()?;
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let issued = IssuedScope::allow("filesystem", "read_file");
    let err = evaluate_population(
        &mut population,
        &mut rng,
        FitnessInputs {
            base_step: &scenario.steps[0],
            issued_scope: &issued,
        },
        0,
    )
    .err();
    assert_eq!(err, Some(FitnessError::ZeroRounds));
    Ok(())
}
