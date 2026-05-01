//! Integration tests for the `chio doctor` skeleton.
//!
//! Exercises the clap surface, the JSON envelope, and the severity-driven
//! exit code via `assert_cmd`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn cargo_bin(name: &str) -> std::path::PathBuf {
    let target = env!("CARGO_BIN_EXE_chio").to_string();
    if name == "chio" {
        return std::path::PathBuf::from(target);
    }
    panic!("unexpected bin: {name}");
}

#[test]
fn doctor_help_advertises_probe_set() {
    let out = Command::new(cargo_bin("chio"))
        .args(["doctor", "--help"])
        .output()
        .expect("doctor --help");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Probe"),
        "expected 'Probe' in help, got: {stdout}"
    );
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--fix"));
    assert!(stdout.contains("--skip-network"));
}

#[test]
fn doctor_json_envelope_carries_schema_and_reports() {
    let out = Command::new(cargo_bin("chio"))
        .args(["doctor", "--json", "--skip-network"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("doctor must emit valid JSON");
    assert_eq!(parsed["schema"], "chio.doctor.v1");
    assert!(parsed["reports"].is_array());
    let names: Vec<String> = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["probe"].as_str().unwrap().to_string())
        .collect();
    // The six canonical probes must be present in canonical order.
    assert_eq!(
        names,
        vec![
            "toolchain",
            "oci",
            "cosign",
            "otel",
            "kernel_runtime",
            "chio_yaml",
        ]
    );
}

#[test]
fn doctor_human_output_includes_probe_markers() {
    let out = Command::new(cargo_bin("chio"))
        .args(["doctor", "--skip-network"])
        .output()
        .expect("doctor");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("chio doctor"));
    assert!(stdout.contains("toolchain"));
    assert!(stdout.contains("summary:"));
}

#[test]
fn doctor_exit_code_is_zero_when_all_probes_pass_or_warn() {
    // The default workspace has no chio.yaml / OCI / cosign config, so
    // every probe falls back to info/ok and the exit code is zero.
    let status = Command::new(cargo_bin("chio"))
        .args(["doctor", "--skip-network"])
        .status()
        .expect("doctor status");
    assert!(status.success());
}
