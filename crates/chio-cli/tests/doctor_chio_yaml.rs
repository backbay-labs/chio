//! Integration tests for the `chio.yaml` schema probe (M01.P3.T6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::process::Command;

fn write_chio_yaml(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("chio.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

fn doctor_in(dir: &std::path::Path) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .current_dir(dir)
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    serde_json::from_str(stdout.trim()).expect("valid JSON output")
}

#[test]
fn chio_yaml_probe_passes_on_complete_doc() {
    let dir = tempfile::tempdir().unwrap();
    write_chio_yaml(dir.path(), "version: 1\npolicy: ./policy.yaml\n");
    let parsed = doctor_in(dir.path());
    let report = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "chio_yaml")
        .expect("chio_yaml report");
    assert_eq!(report["severity"], "ok");
}

#[test]
fn chio_yaml_probe_fails_when_required_keys_missing() {
    let dir = tempfile::tempdir().unwrap();
    write_chio_yaml(dir.path(), "name: demo\n");
    let parsed = doctor_in(dir.path());
    let report = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "chio_yaml")
        .expect("chio_yaml report");
    assert_eq!(report["severity"], "error");
    assert_eq!(
        report["code"].as_str().unwrap(),
        "urn:chio:error:cli:doctor-chio-yaml-invalid"
    );
    let context = report["context"].as_array().unwrap();
    assert!(context.iter().any(|ctx| ctx["key"] == "missing"));
    assert!(context.iter().any(|ctx| ctx["key"] == "line"));
    assert!(context.iter().any(|ctx| ctx["key"] == "column"));
}

#[test]
fn chio_yaml_parse_error_carries_line_and_column() {
    let dir = tempfile::tempdir().unwrap();
    write_chio_yaml(dir.path(), "version: 1\n  bad: indent\n");
    let parsed = doctor_in(dir.path());
    let report = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "chio_yaml")
        .expect("chio_yaml report");
    assert_eq!(report["severity"], "error");
    assert_eq!(
        report["code"].as_str().unwrap(),
        "urn:chio:error:cli:doctor-chio-yaml-invalid"
    );
    let context = report["context"].as_array().unwrap();
    assert!(context.iter().any(|ctx| ctx["key"] == "line"));
    assert!(context.iter().any(|ctx| ctx["key"] == "column"));
}

#[test]
fn chio_yaml_probe_returns_info_when_no_doc() {
    let dir = tempfile::tempdir().unwrap();
    let parsed = doctor_in(dir.path());
    let report = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "chio_yaml")
        .expect("chio_yaml report");
    assert_eq!(report["severity"], "info");
}
