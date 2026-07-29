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
    category_counts, load_scenarios, DriverStatus, RustKernelDriver, VerdictScenario,
    RUST_KERNEL_DRIVER,
};
use verdict_matrix::ScenarioCategory;

fn verdict_matrix_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join(verdict_matrix::MANIFEST_PATH).is_file() {
        manifest_dir.to_path_buf()
    } else {
        manifest_dir.join("verdict_matrix")
    }
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

fn first_capability_scenario() -> VerdictScenario {
    let scenarios = load_corpus();
    match scenarios
        .into_iter()
        .find(|scenario| scenario.category == ScenarioCategory::Capability)
    {
        Some(scenario) => scenario,
        None => panic!("corpus does not contain a capability scenario"),
    }
}

#[test]
fn corpus_satisfies_verdict_matrix_counts() {
    let scenarios = load_corpus();
    assert_eq!(scenarios.len(), 72);

    let counts = category_counts(&scenarios);
    let expected_counts = BTreeMap::from([
        (ScenarioCategory::Capability, 12),
        (ScenarioCategory::Revocation, 12),
        (ScenarioCategory::Replay, 12),
        (ScenarioCategory::Redaction, 12),
        (ScenarioCategory::DeliveryContract, 12),
        (ScenarioCategory::FindingPurchase, 12),
    ]);
    assert_eq!(counts, expected_counts);
}

#[test]
fn rust_kernel_supports_kernel_capability_requirements() {
    let mut scenario = first_capability_scenario();
    scenario.requires = vec![
        String::from("kernel-semantics"),
        String::from("capability-authority"),
        String::from("revocation-store"),
        String::from("replay-nonce"),
        String::from("execution-nonce-store"),
        String::from("guard-pipeline"),
        String::from("receipt-log"),
    ];

    let driver = RustKernelDriver;
    let outcome = driver.run(&scenario);
    assert_ne!(
        outcome.status,
        DriverStatus::Unsupported,
        "rust-kernel should satisfy kernel capability requirements: {:?}",
        outcome.diagnostic
    );
}

#[test]
fn rust_kernel_reports_unknown_driver_requirements_as_unsupported() {
    let mut scenario = first_capability_scenario();
    scenario.requires = vec![String::from("sidecar-only-driver")];

    let driver = RustKernelDriver;
    let outcome = driver.run(&scenario);
    assert_eq!(outcome.status, DriverStatus::Unsupported);
    assert_eq!(
        outcome.diagnostic.as_deref(),
        Some("unsupported requirement `sidecar-only-driver`")
    );
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
