#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod verdict_matrix;

use verdict_matrix::diff_oracle::{
    diff_manifest_reports, expected_tuple_map, load_manifest, verify_manifest_corpus_hash,
    DriverReport,
};
use verdict_matrix::driver::{
    category_counts, load_scenarios, DriverStatus, RustKernelDriver, RUST_KERNEL_DRIVER,
};
use verdict_matrix::ScenarioCategory;

fn verdict_matrix_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("verdict_matrix")
}

fn load_manifest_and_corpus() -> (
    verdict_matrix::diff_oracle::VerdictMatrixManifest,
    Vec<verdict_matrix::driver::VerdictScenario>,
) {
    let root = verdict_matrix_root();
    let manifest_path = root.join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };
    if let Err(error) = verify_manifest_corpus_hash(&root, &manifest) {
        panic!("manifest hash verification failed: {error}");
    }
    let scenarios = match load_scenarios(&root.join(&manifest.corpus.scenario_root)) {
        Ok(scenarios) => scenarios,
        Err(error) => panic!("failed to load verdict scenarios: {error}"),
    };
    (manifest, scenarios)
}

fn load_corpus() -> Vec<verdict_matrix::driver::VerdictScenario> {
    let (_, scenarios) = load_manifest_and_corpus();
    scenarios
}

#[test]
fn corpus_satisfies_verdict_matrix_counts() {
    let scenarios = load_corpus();
    assert_eq!(scenarios.len(), 48);

    let counts = category_counts(&scenarios);
    let expected_counts = BTreeMap::from([
        (ScenarioCategory::Capability, 12),
        (ScenarioCategory::Revocation, 12),
        (ScenarioCategory::Replay, 12),
        (ScenarioCategory::Redaction, 12),
    ]);
    assert_eq!(counts, expected_counts);
}

#[test]
fn rust_kernel_driver_matches_expected_tuples() {
    let (manifest, scenarios) = load_manifest_and_corpus();
    let driver = RustKernelDriver;
    let outcomes = driver.run_all(&scenarios);

    let mut failures = Vec::new();
    let mut tuple_report = BTreeMap::new();
    for outcome in outcomes {
        match outcome.status {
            DriverStatus::Pass => {
                if let Some(actual) = outcome.actual {
                    tuple_report.insert(outcome.scenario_id, actual.normalized());
                } else {
                    failures.push(format!(
                        "{} passed without an actual tuple",
                        outcome.scenario_id
                    ));
                }
            }
            DriverStatus::Fail => failures.push(format!(
                "{} diverged: expected {:?}, actual {:?}",
                outcome.scenario_id, outcome.expected, outcome.actual
            )),
            DriverStatus::Unsupported => failures.push(format!(
                "{} was unsupported: {:?}",
                outcome.scenario_id, outcome.diagnostic
            )),
        }
    }

    if !failures.is_empty() {
        panic!(
            "rust verdict driver failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    let expected = expected_tuple_map(&scenarios);
    let reports = [DriverReport {
        driver: RUST_KERNEL_DRIVER.to_string(),
        tuples: tuple_report,
    }];
    let divergences = diff_manifest_reports(&manifest, &expected, &reports);
    assert!(
        divergences.is_empty(),
        "diff oracle found divergences: {divergences:?}"
    );
}
