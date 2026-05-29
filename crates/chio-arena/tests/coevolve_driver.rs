//! Co-evolution driver tests.
//!
//! Asserts:
//!
//!   * The driver completes the requested generation count when budget
//!     is generous and emits one trace entry per generation.
//!   * Outcome reflects the budget gate: `Completed` when generations
//!     finish, `BudgetExceeded` when the wall-clock cap fires.
//!   * Empty parent pool, zero generations, and zero fitness rounds are
//!     fail-closed.
//!   * Determinism: same witness produces byte-identical traces (this is
//!     also covered exhaustively by `coevolve_determinism.rs`).

use std::time::Duration;

use chio_arena::adversary::capability_overrequest::OverrequestVariant;
use chio_arena::adversary::scope_escape::ScopeEscalation;
use chio_arena::{
    parse_scenario_str, run_coevolution, CoevolutionBudget, CoevolutionConfig, CoevolutionInputs,
    CoevolutionOutcome, DriverError, IssuedScope, OverrequestBlueprint, PopulationBlueprint,
    PromptInjectionBlueprint, ScopeEscapeBlueprint, SeedCorpus,
};

const SCENARIO: &str = r#"
schema_version = "chio.arena.scenario/v1"
id = "driver_smoke"
title = "Driver smoke"
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/driver.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/driver.txt" }
expect_verdict = "allow"
"#;

fn empty_corpus() -> SeedCorpus {
    SeedCorpus {
        artifacts: Vec::new(),
        missing_sources: Vec::new(),
    }
}

fn parents() -> Vec<PopulationBlueprint> {
    vec![
        PopulationBlueprint::PromptInjection(PromptInjectionBlueprint {
            population: "alpha-injection".to_string(),
            patterns: vec!["ignore-previous-instructions", "system-prompt-leak"],
        }),
        PopulationBlueprint::Overrequest(OverrequestBlueprint {
            population: "beta-overrequest".to_string(),
            variants: vec![OverrequestVariant {
                label: "v1".to_string(),
                target_server: "secrets".to_string(),
                target_tool: "read_file".to_string(),
            }],
        }),
        PopulationBlueprint::ScopeEscape(ScopeEscapeBlueprint {
            population: "gamma-escape".to_string(),
            escalations: vec![ScopeEscalation {
                label: "broaden".to_string(),
                server: "filesystem".to_string(),
                tool: "write_file".to_string(),
            }],
        }),
    ]
}

#[test]
fn driver_completes_requested_generations() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let config = CoevolutionConfig {
        generations: 3,
        elite_count: 1,
        fitness_rounds: 2,
        ..Default::default()
    };
    let run = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed,
    })?;
    assert_eq!(run.outcome, CoevolutionOutcome::Completed);
    assert_eq!(run.trace.entries.len(), 3);
    assert!(run
        .trace
        .entries
        .iter()
        .all(|entry| !entry.samples.is_empty()));
    Ok(())
}

#[test]
fn driver_marks_budget_exceeded_when_wall_clock_zero() -> Result<(), Box<dyn std::error::Error>> {
    // Wall-clock budget of zero: the driver checks the budget at the top
    // of every generation, so the first iteration immediately reports
    // BudgetExceeded with zero entries recorded.
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let config = CoevolutionConfig {
        generations: 4,
        elite_count: 1,
        fitness_rounds: 2,
        budget: CoevolutionBudget {
            max_generations: 4,
            max_wall_clock: Duration::from_nanos(0),
        },
        ..Default::default()
    };
    let run = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed,
    })?;
    assert_eq!(run.outcome, CoevolutionOutcome::BudgetExceeded);
    assert!(run.trace.entries.is_empty());
    Ok(())
}

#[test]
fn driver_caps_generations_at_budget_max() -> Result<(), Box<dyn std::error::Error>> {
    // Configured generations is 10 but budget allows 2; the driver
    // honours the lower of the two and reports BudgetExceeded.
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let config = CoevolutionConfig {
        generations: 10,
        elite_count: 1,
        fitness_rounds: 1,
        budget: CoevolutionBudget {
            max_generations: 2,
            max_wall_clock: Duration::from_secs(30 * 60),
        },
        ..Default::default()
    };
    let run = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed,
    })?;
    assert_eq!(run.trace.entries.len(), 2);
    assert_eq!(run.outcome, CoevolutionOutcome::BudgetExceeded);
    Ok(())
}

#[test]
fn driver_rejects_empty_population_pool() {
    let scenario = match parse_scenario_str(SCENARIO) {
        Ok(value) => value,
        Err(error) => panic!("scenario parses: {error}"),
    };
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let err = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: Vec::new(),
        seed_corpus: &corpus,
        config: CoevolutionConfig::default(),
        witness_seed: scenario.rng_seed,
    });
    assert!(matches!(err, Err(DriverError::EmptyPopulationPool)));
}

#[test]
fn driver_rejects_zero_generations() {
    let scenario = match parse_scenario_str(SCENARIO) {
        Ok(value) => value,
        Err(error) => panic!("scenario parses: {error}"),
    };
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let config = CoevolutionConfig {
        generations: 0,
        ..Default::default()
    };
    let err = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed,
    });
    assert!(matches!(err, Err(DriverError::ZeroGenerations)));
}

#[test]
fn driver_rejects_zero_fitness_rounds() {
    let scenario = match parse_scenario_str(SCENARIO) {
        Ok(value) => value,
        Err(error) => panic!("scenario parses: {error}"),
    };
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = empty_corpus();
    let config = CoevolutionConfig {
        fitness_rounds: 0,
        ..Default::default()
    };
    let err = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed,
    });
    assert!(matches!(err, Err(DriverError::ZeroFitnessRounds)));
}

#[test]
fn driver_records_seed_corpus_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = SeedCorpus {
        artifacts: Vec::new(),
        missing_sources: vec!["fuzz_artifacts".to_string()],
    };
    let run = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config: CoevolutionConfig {
            generations: 2,
            ..Default::default()
        },
        witness_seed: scenario.rng_seed,
    })?;
    assert_eq!(run.trace.seed_corpus_fingerprint, corpus.fingerprint_hex());
    Ok(())
}
