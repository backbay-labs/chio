//! Integration tests for the cosign freshness probe.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn cosign_probe_no_bundle_returns_info() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env_remove("CHIO_GUARD_BUNDLE")
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let cosign = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "cosign")
        .expect("cosign probe report");
    assert_eq!(cosign["severity"], "info");
}

#[test]
fn cosign_probe_with_fresh_bundle_returns_ok() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("guard-bundle.sigstore.json");
    std::fs::write(&bundle, "{\"stub\":true}").unwrap();
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env("CHIO_GUARD_BUNDLE", bundle)
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let cosign = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "cosign")
        .expect("cosign probe report");
    assert_eq!(cosign["severity"], "ok");
}

#[test]
fn cosign_stale_urn_present_in_binary() {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_chio"));
    let bytes = std::fs::read(path).expect("read chio binary");
    let needle = b"urn:chio:error:cli:doctor-cosign-stale";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "cosign-stale URN must be embedded in chio binary"
    );
}
