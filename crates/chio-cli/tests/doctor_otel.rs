//! Integration tests for the OTEL endpoint + kernel runtime probes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn otel_probe_resolves_endpoint_when_set() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "https://otel.example/v1/traces",
        )
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let otel = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "otel")
        .expect("otel probe report");
    assert_eq!(otel["severity"], "ok");
}

#[test]
fn otel_probe_returns_info_when_unset() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("CHIO_OTEL_RECEIPT_EXPORTER_ENDPOINT")
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let otel = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "otel")
        .expect("otel probe report");
    assert_eq!(otel["severity"], "info");
}

#[test]
fn kernel_runtime_probe_announces_inflight_gauge() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let out = Command::new(bin)
        .env("CHIO_KERNEL_METRICS_URL", "http://localhost:9100/metrics")
        .env("CHIO_DOCTOR_SKIP_NETWORK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("doctor --json");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let kernel = parsed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["probe"] == "kernel_runtime")
        .expect("kernel_runtime probe report");
    assert_eq!(kernel["severity"], "ok");
    let context = kernel["context"].as_array().unwrap();
    assert!(context.iter().any(
        |ctx| ctx["key"] == "expected_gauge" && ctx["value"] == "chio_kernel_dispatch_inflight"
    ));
}

#[test]
fn otel_unresolved_urn_present_in_binary() {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_chio"));
    let bytes = std::fs::read(path).expect("read chio binary");
    let needle = b"urn:chio:error:cli:doctor-otel-unresolved";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "otel-unresolved URN must be embedded in chio binary"
    );
}
