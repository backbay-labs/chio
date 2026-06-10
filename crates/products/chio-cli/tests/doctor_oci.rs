//! Integration tests for the OCI reachability probe.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn oci_probe_skip_network_returns_ok_with_registry() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env("CHIO_GUARD_REGISTRY", "ghcr.io/example/chio")
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let oci = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "oci")
        .expect("oci probe report");
    assert_eq!(oci["severity"], "ok");
    let context = oci["context"].as_array().unwrap();
    assert!(context
        .iter()
        .any(|ctx| ctx["key"] == "registry" && ctx["value"] == "ghcr.io/example/chio"));
}

#[test]
fn oci_probe_no_registry_returns_info() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env_remove("CHIO_GUARD_REGISTRY")
        .env_remove("CHIO_GUARD_REGISTRY_REFERENCE")
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let oci = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "oci")
        .expect("oci probe report");
    assert_eq!(oci["severity"], "info");
}

#[test]
fn oci_unreachable_urn_present_in_binary() {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_chio"));
    let bytes = std::fs::read(path).expect("read chio binary");
    let needle = b"urn:chio:error:cli:doctor-oci-unreachable";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "oci-unreachable URN must be embedded in chio binary"
    );
}
