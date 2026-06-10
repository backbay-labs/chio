//! Integration coverage for `chio bind <provider> --card <path>`.
//!
//! Builds the `chio` binary via env!("CARGO_BIN_EXE_chio"), writes a
//! canonical-JSON model card to a temp file, runs the subcommand, and
//! asserts the resolved-binding summary covers `weights_hash` and
//! `allowed_capability_set`. Includes a `--help` smoke test that locks
//! the `--card` flag in the help output (the gate_check command also
//! greps `bind --help` for `--card`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::process::Command;

use chio_weights::card::{ModelCard, StringSet};
use chrono::{TimeZone, Utc};

const BIN: &str = env!("CARGO_BIN_EXE_chio");

fn write_card_to_temp() -> tempfile::NamedTempFile {
    let issued = Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap();
    let card = ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer",
        issued,
        issued + chrono::Duration::days(30),
    )
    .unwrap();
    let bytes = card.to_canonical_json().unwrap();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&bytes).unwrap();
    tmp.flush().unwrap();
    tmp
}

#[test]
fn bind_help_advertises_card_flag() {
    let out = Command::new(BIN).args(["bind", "--help"]).output().unwrap();
    assert!(
        out.status.success(),
        "bind --help must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--card"),
        "bind --help must advertise --card flag, got: {stdout}"
    );
    assert!(
        stdout.contains("--bundle"),
        "bind --help must advertise --bundle flag, got: {stdout}"
    );
    assert!(
        stdout.contains("--weights-binding-mode"),
        "bind --help must advertise --weights-binding-mode flag, got: {stdout}"
    );
}

#[test]
fn bind_prints_resolved_weights_hash_and_capability_set() {
    let card_file = write_card_to_temp();
    let out = Command::new(BIN)
        .args([
            "bind",
            "demo-provider",
            "--card",
            card_file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "bind must succeed for a valid card; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("provider: demo-provider"),
        "stdout must report provider: {stdout}"
    );
    assert!(
        stdout.contains(
            "weights_hash: 0000000000000000000000000000000000000000000000000000000000000001"
        ),
        "stdout must include resolved weights_hash: {stdout}"
    );
    assert!(
        stdout.contains("allowed_capability_set:"),
        "stdout must list allowed_capability_set: {stdout}"
    );
    assert!(
        stdout.contains("- tool:read"),
        "stdout must include tool:read scope: {stdout}"
    );
    assert!(
        stdout.contains("- tool:write"),
        "stdout must include tool:write scope: {stdout}"
    );
    assert!(
        stdout.contains("banned_tools:"),
        "stdout must list banned_tools: {stdout}"
    );
    assert!(
        stdout.contains("- tool:exec"),
        "stdout must include tool:exec banned tool: {stdout}"
    );
    assert!(
        stdout.contains("cosign: skipped"),
        "without --bundle, cosign verification must be reported as skipped: {stdout}"
    );
}

#[test]
fn bind_emits_json_when_format_json_supplied() {
    let card_file = write_card_to_temp();
    let out = Command::new(BIN)
        .args([
            "--format",
            "json",
            "bind",
            "demo-provider",
            "--card",
            card_file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "bind --format json must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("must emit JSON: {e}; got: {stdout}"));
    assert_eq!(v["provider"].as_str(), Some("demo-provider"));
    assert_eq!(v["card_version"].as_str(), Some("1"));
    assert_eq!(
        v["weights_hash"].as_str(),
        Some("0000000000000000000000000000000000000000000000000000000000000001")
    );
    assert_eq!(v["cosign"].as_str(), Some("skipped"));
    assert_eq!(
        v["allowed_capability_set"].as_array().map(|a| a.len()),
        Some(2)
    );
}

#[test]
fn bind_rejects_missing_card_file() {
    let out = Command::new(BIN)
        .args([
            "bind",
            "demo-provider",
            "--card",
            "/path/that/does/not/exist/card.json",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bind must fail when --card path does not exist"
    );
}

#[test]
fn bind_rejects_invalid_card_bytes() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"this is not a model card").unwrap();
    tmp.flush().unwrap();
    let out = Command::new(BIN)
        .args([
            "bind",
            "demo-provider",
            "--card",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bind must fail when the card bytes do not decode"
    );
}

#[test]
fn bind_rejects_bundle_without_issuer_pins() {
    let card_file = write_card_to_temp();
    let mut bundle = tempfile::NamedTempFile::new().unwrap();
    bundle.write_all(b"{}").unwrap();
    bundle.flush().unwrap();
    let out = Command::new(BIN)
        .args([
            "bind",
            "demo-provider",
            "--card",
            card_file.path().to_str().unwrap(),
            "--bundle",
            bundle.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bind --bundle without --issuer-san-regex / --issuer-oidc must fail"
    );
}

#[test]
fn bind_rejects_required_mode_without_cosign_bundle() {
    let card_file = write_card_to_temp();
    let out = Command::new(BIN)
        .args([
            "bind",
            "demo-provider",
            "--card",
            card_file.path().to_str().unwrap(),
            "--weights-binding-mode",
            "required",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bind --weights-binding-mode required must fail without --bundle"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--weights-binding-mode required requires --bundle"),
        "unexpected stderr: {stderr}"
    );
}
