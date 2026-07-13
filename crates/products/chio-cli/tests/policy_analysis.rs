#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guards/chio-policy/tests/fixtures/analyze")
        .join(name)
}

fn report_schema() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/policy/analysis-report.schema.json");
    serde_json::from_slice(&std::fs::read(path).expect("read analysis schema"))
        .expect("parse analysis schema")
}

fn run(args: &[&str], policy: &Path) -> Output {
    Command::new(chio())
        .args(["policy", "analyze"])
        .args(args)
        .arg(policy)
        .args(["--format", "json"])
        .output()
        .expect("run policy analyzer")
}

#[test]
fn policy_analysis_exit_codes_distinguish_findings_from_failures() {
    let clean = run(&[], &fixture("clean.yaml"));
    assert_eq!(clean.status.code(), Some(0));
    let clean_report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(clean_report["schema"], "chio.policy-analysis.v1");
    let validator = jsonschema::validator_for(&report_schema()).expect("compile analysis schema");
    assert!(validator.is_valid(&clean_report));

    let findings = run(&[], &fixture("contradictory.yaml"));
    assert_eq!(findings.status.code(), Some(1));

    let invalid = run(&[], &fixture("invalid.yaml"));
    assert_eq!(invalid.status.code(), Some(2));
    let error: serde_json::Value = serde_json::from_slice(&invalid.stderr).unwrap();
    assert_eq!(error["schema"], "chio.policy-analysis.error.v1");
}

#[test]
fn policy_analysis_refinement_emits_a_witness() {
    let old = fixture("old.yaml");
    let output = run(
        &["--against", old.to_str().expect("UTF-8 fixture path")],
        &fixture("new-widened.yaml"),
    );
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["refinement"]["status"], "does_not_refine");
    let validator = jsonschema::validator_for(&report_schema()).expect("compile analysis schema");
    assert!(validator.is_valid(&report));
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding.get("witness").is_some()));
}

#[test]
fn policy_analysis_table_includes_stable_finding_ids() {
    let output = Command::new(chio())
        .args(["policy", "analyze"])
        .arg(fixture("contradictory.yaml"))
        .args(["--format", "table"])
        .output()
        .expect("run policy analyzer table output");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("table output is UTF-8");
    assert!(stdout.contains("ID           SEVERITY"));
    assert!(stdout.contains("CONTRA-0001"));
}
