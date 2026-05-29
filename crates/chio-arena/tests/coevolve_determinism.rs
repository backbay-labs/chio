//! Co-evolution determinism test.
//!
//! Asserts that two co-evolution runs with identical inputs produce
//! byte-identical generation traces. The test is a downstream backstop
//! for the per-module determinism contracts already proven in
//! `coevolve_mutation.rs`, `coevolve_crossover.rs`, and
//! `coevolve_driver.rs`; it locks the contract end-to-end at the level
//! the determinism gate consumes (the serialised `GenerationTrace`).
//!
//! The test serialises the trace through `serde_json::to_vec` (canonical
//! BTreeMap ordering) and compares the resulting byte buffers, mirroring
//! the determinism canary's "two runs, byte-equal output" pattern.

use chio_arena::adversary::capability_overrequest::OverrequestVariant;
use chio_arena::adversary::scope_escape::ScopeEscalation;
use chio_arena::{
    parse_scenario_str, run_coevolution, CoevolutionConfig, CoevolutionInputs, IssuedScope,
    OverrequestBlueprint, PopulationBlueprint, PromptInjectionBlueprint, ReplayAttemptBlueprint,
    ReplayAttemptEntry, ScopeEscapeBlueprint, SeedCorpus,
};

const SCENARIO: &str = r#"
schema_version = "chio.arena.scenario/v1"
id = "determinism_witness"
title = "Determinism witness"
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
seed_prompt_ref = "prompts/determinism.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/determinism.txt" }
expect_verdict = "allow"
"#;

fn parents() -> Vec<PopulationBlueprint> {
    vec![
        PopulationBlueprint::PromptInjection(PromptInjectionBlueprint {
            population: "alpha-injection".to_string(),
            patterns: vec![
                "ignore-previous-instructions",
                "system-prompt-leak",
                "tool-name-spoof",
            ],
        }),
        PopulationBlueprint::Overrequest(OverrequestBlueprint {
            population: "beta-overrequest".to_string(),
            variants: vec![
                OverrequestVariant {
                    label: "v1".to_string(),
                    target_server: "secrets".to_string(),
                    target_tool: "read_file".to_string(),
                },
                OverrequestVariant {
                    label: "v2".to_string(),
                    target_server: "network".to_string(),
                    target_tool: "http_post".to_string(),
                },
            ],
        }),
        PopulationBlueprint::ReplayAttempt(ReplayAttemptBlueprint {
            population: "delta-replay".to_string(),
            entries: vec![
                ReplayAttemptEntry {
                    pattern: "immediate-reuse",
                    captured_nonce: "nonce-1".to_string(),
                },
                ReplayAttemptEntry {
                    pattern: "stale-nonce",
                    captured_nonce: "nonce-2".to_string(),
                },
            ],
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

fn corpus() -> SeedCorpus {
    SeedCorpus {
        artifacts: Vec::new(),
        missing_sources: vec!["fuzz_artifacts".to_string()],
    }
}

#[test]
fn coevolution_traces_are_byte_identical_across_runs() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = corpus();
    let config = CoevolutionConfig {
        generations: 5,
        elite_count: 1,
        fitness_rounds: 3,
        ..Default::default()
    };

    let run_a = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config: config.clone(),
        witness_seed: scenario.rng_seed,
    })?;
    let run_b = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config: config.clone(),
        witness_seed: scenario.rng_seed,
    })?;

    let bytes_a = serde_json::to_vec(&run_a.trace)?;
    let bytes_b = serde_json::to_vec(&run_b.trace)?;
    assert_eq!(bytes_a, bytes_b, "generation traces must be byte-identical");
    assert_eq!(run_a.outcome, run_b.outcome);
    Ok(())
}

#[test]
fn coevolution_traces_diverge_when_witness_seed_changes() -> Result<(), Box<dyn std::error::Error>>
{
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let corpus = corpus();
    let config = CoevolutionConfig {
        generations: 3,
        elite_count: 1,
        fitness_rounds: 2,
        ..Default::default()
    };

    let run_a = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config: config.clone(),
        witness_seed: scenario.rng_seed,
    })?;
    let run_b = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &corpus,
        config,
        witness_seed: scenario.rng_seed.wrapping_add(1),
    })?;

    let bytes_a = serde_json::to_vec(&run_a.trace)?;
    let bytes_b = serde_json::to_vec(&run_b.trace)?;
    assert_ne!(
        bytes_a, bytes_b,
        "different witness seeds must produce diverging traces"
    );
    Ok(())
}

#[test]
fn coevolution_traces_diverge_when_seed_corpus_changes() -> Result<(), Box<dyn std::error::Error>> {
    // The seed-corpus fingerprint is recorded into the trace; rotating
    // the corpus must produce different bytes even when every other
    // input is held constant.
    let scenario = parse_scenario_str(SCENARIO)?;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let config = CoevolutionConfig {
        generations: 2,
        elite_count: 1,
        fitness_rounds: 2,
        ..Default::default()
    };

    let baseline = corpus();
    let rotated = SeedCorpus {
        artifacts: Vec::new(),
        missing_sources: vec!["fuzz_artifacts".to_string(), "replay_attack".to_string()],
    };
    let run_a = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &baseline,
        config: config.clone(),
        witness_seed: scenario.rng_seed,
    })?;
    let run_b = run_coevolution(CoevolutionInputs {
        base_step: &scenario.steps[0],
        issued_scope: &issued,
        parents: parents(),
        seed_corpus: &rotated,
        config,
        witness_seed: scenario.rng_seed,
    })?;

    let bytes_a = serde_json::to_vec(&run_a.trace)?;
    let bytes_b = serde_json::to_vec(&run_b.trace)?;
    assert_ne!(bytes_a, bytes_b);
    Ok(())
}
