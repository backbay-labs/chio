//! Leaderboard renderer (Markdown + stable-schema JSON) using the
//! verdict_matrix oracle. Exercises `Leaderboard` construction from a synthetic `FitnessReport` and asserts the schema marker, sort order, and rendered artifacts.

use std::collections::BTreeMap;

use chio_arena::coevolve::{FitnessReport, FitnessSample};
use chio_arena::AdversaryClass;
use chio_arena::{render_leaderboard, Leaderboard, LEADERBOARD_SCHEMA};
use serde_json::Value;

fn sample(class: AdversaryClass, survivals: u32, defeats: u32, population: &str) -> FitnessSample {
    FitnessSample {
        class,
        population: population.to_string(),
        step_ids: vec!["step-1".to_string()],
        tuples: Vec::new(),
        survivals,
        defeats,
    }
}

fn report() -> FitnessReport {
    let mut samples = BTreeMap::new();
    samples.insert(
        "alpha".to_string(),
        sample(AdversaryClass::PromptInjection, 9, 1, "alpha"),
    );
    samples.insert(
        "bravo".to_string(),
        sample(AdversaryClass::CapabilityOverrequest, 5, 5, "bravo"),
    );
    samples.insert(
        "charlie".to_string(),
        sample(AdversaryClass::ReplayAttempt, 0, 10, "charlie"),
    );
    samples.insert(
        "delta".to_string(),
        sample(AdversaryClass::ScopeEscape, 5, 5, "delta"),
    );
    FitnessReport { samples }
}

#[test]
fn ranks_by_survival_rate_with_stable_tiebreak() {
    let leaderboard = Leaderboard::from_fitness_report(&report(), "scenario-x", 7);
    assert_eq!(leaderboard.schema_version, LEADERBOARD_SCHEMA);
    assert_eq!(leaderboard.scenario_id, "scenario-x");
    assert_eq!(leaderboard.generation, 7);
    let names: Vec<&str> = leaderboard
        .rows
        .iter()
        .map(|r| r.population.as_str())
        .collect();
    // alpha has 0.9, bravo and delta tie at 0.5 (alphabetical), charlie at 0.0.
    assert_eq!(names, vec!["alpha", "bravo", "delta", "charlie"]);
    assert_eq!(leaderboard.rows[0].rank, 1);
    assert_eq!(leaderboard.rows[3].rank, 4);
    assert!((leaderboard.rows[0].survival_rate - 0.9).abs() < 1e-9);
}

#[test]
fn renders_markdown_with_schema_header() {
    let leaderboard = Leaderboard::from_fitness_report(&report(), "scenario-md", 0);
    let md = leaderboard.to_markdown();
    assert!(md.contains("Arena leaderboard"));
    assert!(md.contains("scenario-md"));
    assert!(md.contains("| Rank | Population |"));
    assert!(md.contains("| 1 | alpha |"));
}

#[test]
fn writes_canonical_json_and_markdown() -> Result<(), Box<dyn std::error::Error>> {
    let leaderboard = Leaderboard::from_fitness_report(&report(), "scenario-out", 0);
    let tmp = tempfile::tempdir()?;
    let artifacts = render_leaderboard(tmp.path(), &leaderboard)?;
    assert!(artifacts.json_path.is_file());
    assert!(artifacts.markdown_path.is_file());
    let bytes = std::fs::read(&artifacts.json_path)?;
    let parsed: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(parsed["schema_version"], LEADERBOARD_SCHEMA);
    assert_eq!(parsed["scenario_id"], "scenario-out");
    assert_eq!(parsed["rows"][0]["population"], "alpha");
    Ok(())
}

#[test]
fn schema_v1_string_is_present_in_module() {
    // The gate_check greps for the schema string in src/leaderboard.rs; this
    // test enforces the same invariant from the test side.
    assert_eq!(LEADERBOARD_SCHEMA, "chio.arena.leaderboard/v1");
}
