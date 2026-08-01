#![forbid(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use chio_conformance::econsim::{
    validate_econsim_qualification_matrix, validate_econsim_scenario_result, EconsimDisposition,
    EconsimFindingSeverity, EconsimHarnessProvenance, EconsimOutcome, EconsimQualificationMatrix,
    EconsimScenarioResult, EconsimTargetStatus, EconsimValidationError,
    ECONSIM_QUALIFICATION_MATRIX_SCHEMA, ECONSIM_SCENARIO_CLASSES, ECONSIM_SCENARIO_RESULT_SCHEMA,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository root resolves: {error}"))
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn held(class: &str, seed: u64) -> EconsimScenarioResult {
    EconsimScenarioResult {
        schema: ECONSIM_SCENARIO_RESULT_SCHEMA.to_owned(),
        scenario_id: format!("{class}-seed-{seed}"),
        scenario_class: class.to_owned(),
        seed,
        corpus_manifest_digest: "a".repeat(64),
        requirement_ids: vec!["AE-QUALIFICATION".to_owned()],
        expected_disposition: EconsimDisposition::FailClosed,
        observed_disposition: Some(EconsimDisposition::FailClosed),
        target_status: EconsimTargetStatus::Bound,
        outcome: EconsimOutcome::Held,
        finding_severity: None,
        assertion_scope: "the named production boundary rejected its fixed corpus".to_owned(),
        explicit_limits: vec!["internal qualification only".to_owned()],
    }
}

fn matrix() -> EconsimQualificationMatrix {
    EconsimQualificationMatrix {
        schema: ECONSIM_QUALIFICATION_MATRIX_SCHEMA.to_owned(),
        profile_id: "econsim-v1".to_owned(),
        harness_provenance: EconsimHarnessProvenance {
            git_commit: "fixture".to_owned(),
            source_tree_state: "clean".to_owned(),
            source_tree_digest: "b".repeat(64),
            executable_digest: "c".repeat(64),
            cargo_lock_digest: "d".repeat(64),
            enabled_features: Vec::new(),
            target_triple: "fixture-target".to_owned(),
            rustc_version: "rustc fixture".to_owned(),
            cargo_version: "cargo fixture".to_owned(),
            command: vec!["chio-econsim-runner".to_owned()],
            scenario_manifest_digest: "e".repeat(64),
            corpus_manifest_digest: "a".repeat(64),
            runner_key_id: "fixture-key".to_owned(),
            qualification_scope: "internal qualification only".to_owned(),
        },
        cases: ECONSIM_SCENARIO_CLASSES
            .into_iter()
            .enumerate()
            .map(|(index, class)| held(class, 10_000 + index as u64))
            .collect(),
    }
}

#[test]
fn committed_econsim_fixtures_validate_against_both_schemas() -> TestResult {
    let schema_dir = root().join("spec/schemas/chio-econsim/v1");
    let scenario = load_json(&schema_dir.join("fixtures/scenario-result.positive.json"))?;
    let matrix = load_json(&schema_dir.join("fixtures/qualification-matrix.positive.json"))?;
    let scenario_schema = load_json(&schema_dir.join("scenario-result.schema.json"))?;
    jsonschema::validator_for(&scenario_schema)?
        .validate(&scenario)
        .map_err(|error| error.to_string())?;
    let registry = jsonschema::Registry::new()
        .add(
            "https://spec.chio.dev/schemas/chio-econsim/v1/scenario-result.schema.json",
            scenario_schema,
        )?
        .prepare()?;
    let matrix_schema = load_json(&schema_dir.join("qualification-matrix.schema.json"))?;
    jsonschema::options()
        .with_registry(&registry)
        .build(&matrix_schema)?
        .validate(&matrix)
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[test]
fn six_class_results_and_matrix_are_deterministic_for_one_seed_set() -> TestResult {
    let first = serde_json::to_vec(&matrix())?;
    let second = serde_json::to_vec(&matrix())?;
    assert_eq!(first, second);
    validate_econsim_qualification_matrix(&matrix())?;
    Ok(())
}

#[test]
fn each_class_fails_closed_on_invalid_result_combinations() {
    for class in ECONSIM_SCENARIO_CLASSES {
        let mut result = held(class, 7);
        result.outcome = EconsimOutcome::Finding;
        result.finding_severity = Some(EconsimFindingSeverity::High);
        assert_eq!(
            validate_econsim_scenario_result(&result),
            Err(EconsimValidationError::InvalidResult(
                "outcome, target, disposition, and severity disagree"
            )),
            "{class} accepted a finding without an observed breach"
        );
    }
}

#[test]
fn matrix_rejects_duplicate_and_incomplete_class_coverage() {
    let mut duplicate = matrix();
    duplicate.cases[1].scenario_id = duplicate.cases[0].scenario_id.clone();
    assert!(matches!(
        validate_econsim_qualification_matrix(&duplicate),
        Err(EconsimValidationError::DuplicateScenario(_))
    ));

    let mut incomplete = matrix();
    incomplete.cases.pop();
    assert!(matches!(
        validate_econsim_qualification_matrix(&incomplete),
        Err(EconsimValidationError::MissingClass(_))
    ));
}
