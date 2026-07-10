//! Integration tests for the toolchain probe.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn doctor_emits_toolchain_probe_and_attaches_msrv_context() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .args(["doctor", "--json", "--skip-network"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let reports = parsed["reports"].as_array().unwrap();
    let toolchain = reports
        .iter()
        .find(|r| r["probe"] == "toolchain")
        .expect("toolchain report present");
    // Severity must be one of the registry-anchored tiers.
    let severity = toolchain["severity"].as_str().unwrap();
    assert!(["ok", "info", "warning", "error", "fatal"].contains(&severity));
    // Toolchain probe always attaches a cargo_version context line on
    // success; on failure it still emits the same key.
    let context = toolchain["context"].as_array().unwrap();
    assert!(context
        .iter()
        .any(|ctx| ctx["key"] == "cargo_version"
            && ctx["value"].as_str().unwrap().starts_with("cargo ")));
}

#[test]
fn toolchain_probe_uses_doctor_toolchain_mismatch_code_on_failure() {
    // Smoke-test the negative path through the public unit tests in
    // `crates/products/chio-cli/src/doctor/toolchain.rs`. The integration here
    // asserts the probe URN is present in the binary so the
    // registry lookup never silently drifts.
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_chio"));
    let bytes = std::fs::read(path).expect("read chio binary");
    let needle = b"urn:chio:error:cli:doctor-toolchain-mismatch";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "toolchain mismatch URN must be embedded in chio binary"
    );
}
