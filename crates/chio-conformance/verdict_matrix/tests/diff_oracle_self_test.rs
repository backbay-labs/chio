#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod verdict_matrix;

use verdict_matrix::diff_oracle::{
    diff_expected_reports, diff_manifest_reports, expected_tuple_map, load_error_registry_urns,
    load_manifest, scenario_index_hash, validate_reason_codes, verify_manifest_corpus_hash,
    DriverReport,
};
use verdict_matrix::driver::{load_scenarios, REASON_NONE};
use verdict_matrix::{Verdict, VerdictTuple};

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut candidate: Option<&Path> = Some(manifest_dir);
    while let Some(dir) = candidate {
        if dir
            .join("spec")
            .join("errors")
            .join("registry.yaml")
            .is_file()
        {
            return dir.to_path_buf();
        }
        candidate = dir.parent();
    }
    panic!(
        "failed to find repo root from CARGO_MANIFEST_DIR {}",
        manifest_dir.display()
    );
}

fn verdict_matrix_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join(verdict_matrix::MANIFEST_PATH).is_file() {
        manifest_dir.to_path_buf()
    } else {
        manifest_dir.join("verdict_matrix")
    }
}

fn load_corpus() -> Vec<verdict_matrix::driver::VerdictScenario> {
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
    match load_scenarios(&root.join(&manifest.corpus.scenario_root)) {
        Ok(scenarios) => scenarios,
        Err(error) => panic!("failed to load scenarios: {error}"),
    }
}

#[test]
fn manifest_hash_pins_current_scenario_index() {
    let root = verdict_matrix_root();
    let manifest_path = root.join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };
    let scenario_root = root.join(&manifest.corpus.scenario_root);
    let actual_hash = match scenario_index_hash(&scenario_root) {
        Ok(hash) => hash,
        Err(error) => panic!("failed to hash scenario index: {error}"),
    };
    assert_eq!(actual_hash, manifest.corpus.scenario_index_hash);
}

#[test]
fn reason_codes_are_registered_or_none() {
    let scenarios = load_corpus();
    let registry_path = repo_root().join("spec/errors/registry.yaml");
    let registry = match load_error_registry_urns(&registry_path) {
        Ok(registry) => registry,
        Err(error) => panic!(
            "failed to load registry {}: {error}",
            registry_path.display()
        ),
    };
    assert!(registry.contains("urn:chio:error:capability:scope-exceeded"));
    assert!(registry.contains("urn:chio:error:guard:input-redacted"));
    assert!(registry.contains("urn:chio:error:replay:deterministic-mismatch"));

    if let Err(error) = validate_reason_codes(&scenarios, &registry) {
        panic!("scenario reason-code validation failed: {error}");
    }
    assert!(scenarios
        .iter()
        .any(|scenario| scenario.expected.reason_code == REASON_NONE));
}

#[test]
fn diff_oracle_normalizes_scope_order() {
    let mut expected = BTreeMap::new();
    expected.insert(
        "scope-order".to_string(),
        VerdictTuple {
            verdict: Verdict::Allow,
            reason_code: REASON_NONE.to_string(),
            scope_set: vec!["tool:read".to_string(), "tool:write".to_string()],
        },
    );
    let reports = [DriverReport {
        driver: "rust-kernel".to_string(),
        tuples: BTreeMap::from([(
            "scope-order".to_string(),
            VerdictTuple {
                verdict: Verdict::Allow,
                reason_code: REASON_NONE.to_string(),
                scope_set: vec!["tool:write".to_string(), "tool:read".to_string()],
            },
        )]),
    }];
    assert!(diff_expected_reports(&expected, &reports).is_empty());
}

#[test]
fn diff_oracle_reports_reason_code_divergence() {
    let mut expected = BTreeMap::new();
    expected.insert(
        "reason-drift".to_string(),
        VerdictTuple {
            verdict: Verdict::Deny,
            reason_code: "urn:chio:error:capability:revoked".to_string(),
            scope_set: vec!["tool:read".to_string()],
        },
    );
    let reports = [DriverReport {
        driver: "rust-kernel".to_string(),
        tuples: BTreeMap::from([(
            "reason-drift".to_string(),
            VerdictTuple {
                verdict: Verdict::Deny,
                reason_code: "urn:chio:error:capability:scope-exceeded".to_string(),
                scope_set: vec!["tool:read".to_string()],
            },
        )]),
    }];
    let divergences = diff_expected_reports(&expected, &reports);
    assert_eq!(divergences.len(), 1);
    assert_eq!(divergences[0].scenario_id, "reason-drift");
}

#[test]
fn loaded_corpus_builds_expected_tuple_map() {
    let scenarios = load_corpus();
    let expected = expected_tuple_map(&scenarios);
    assert_eq!(expected.len(), scenarios.len());
    assert!(expected.contains_key("capability-subset-001-read-exact"));
    assert!(expected.contains_key("redaction-determinism-012-no-redaction-tool-call"));
}

#[test]
fn manifest_required_driver_absence_is_divergence() {
    let root = verdict_matrix_root();
    let manifest_path = root.join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };
    let scenarios = load_corpus();
    let expected = expected_tuple_map(&scenarios);
    let divergences = diff_manifest_reports(&manifest, &expected, &[]);

    assert_eq!(divergences.len(), expected.len());
    assert!(divergences
        .iter()
        .all(|divergence| { divergence.driver == "rust-kernel" && divergence.actual.is_none() }));
}
