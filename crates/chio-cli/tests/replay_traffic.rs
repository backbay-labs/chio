#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::Engine;
use chio_tee_frame::Frame;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("replay_traffic")
        .join("fixtures")
        .join(name)
}

fn run_traffic(fixture: &Path, extra: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .arg("replay")
        .arg("traffic")
        .arg("--from")
        .arg(fixture)
        .arg("--json");
    for arg in extra {
        command.arg(arg);
    }
    command.output().expect("spawn chio replay traffic")
}

fn run_from_tee(fixture: &Path, extra: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .arg("replay")
        .arg(fixture)
        .arg("--from-tee")
        .arg("--json");
    for arg in extra {
        command.arg(arg);
    }
    command.output().expect("spawn chio replay --from-tee")
}

fn assert_exit(output: &Output, expected: i32) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code().unwrap_or(i32::MIN),
        expected,
        "stdout=<<<{stdout}>>>\nstderr=<<<{stderr}>>>",
    );
}

fn write_allow_all_policy(dir: &Path) -> PathBuf {
    let path = dir.join("allow-all-policy.yaml");
    fs::write(
        &path,
        r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  allow_sampling: false
  allow_sampling_tool_use: false
  allow_elicitation: false
  require_web3_evidence: false
  checkpoint_batch_size: 100
guards: {}
capabilities: {}
"#,
    )
    .expect("write allow policy");
    path
}

fn tenant_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn write_tenant_pubkey(dir: &Path, key: &SigningKey) -> PathBuf {
    let path = dir.join("tenant.pub");
    fs::write(&path, key.verifying_key().to_bytes()).expect("write tenant pubkey");
    path
}

fn sign_frame(frame: &mut Frame, key: &SigningKey) {
    let mut value = serde_json::to_value(&*frame).expect("frame to value");
    value
        .as_object_mut()
        .expect("frame is json object")
        .remove("tenant_sig");
    let payload =
        chio_core::canonical::canonical_json_bytes(&value).expect("canonical signing payload");
    let signature = key.sign(&payload);
    let encoded = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    frame.tenant_sig = format!("ed25519:{encoded}");
}

fn signed_fixture_copy(name: &str, dir: &Path, key: &SigningKey) -> PathBuf {
    let source = fixture_path(name);
    let target = dir.join(name);
    let mut output = String::new();
    for line in fs::read_to_string(source).expect("read fixture").lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut frame: Frame = serde_json::from_str(line).expect("fixture frame");
        sign_frame(&mut frame, key);
        output.push_str(&serde_json::to_string(&frame).expect("serialize frame"));
        output.push('\n');
    }
    fs::write(&target, output).expect("write signed fixture copy");
    target
}

fn against_args(policy: &Path) -> Vec<String> {
    vec![
        "--against".to_string(),
        policy.display().to_string(),
        "--run-id".to_string(),
        "m10p2t4".to_string(),
    ]
}

#[test]
fn clean_match_exits_zero() {
    let output = run_traffic(&fixture_path("clean_match.ndjson"), &[]);

    assert_exit(&output, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["first_error"], serde_json::Value::Null);
}

#[test]
fn legacy_from_tee_requires_tenant_pubkey() {
    let output = run_from_tee(&fixture_path("clean_match.ndjson"), &[]);

    assert_exit(&output, 20);
}

#[test]
fn legacy_from_tee_accepts_signed_capture_with_pubkey() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = tenant_signing_key();
    let fixture = signed_fixture_copy("clean_match.ndjson", dir.path(), &key);
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let extra = vec![
        "--tenant-pubkey".to_string(),
        pubkey_path.display().to_string(),
    ];

    let output = run_from_tee(&fixture, &extra);

    assert_exit(&output, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["exit_code"], 0);
}

#[test]
fn verdict_drift_exits_ten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let key = tenant_signing_key();
    let fixture = signed_fixture_copy("verdict_drift.ndjson", dir.path(), &key);
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let mut extra = against_args(&policy);
    extra.push("--tenant-pubkey".to_string());
    extra.push(pubkey_path.display().to_string());

    let output = run_traffic(&fixture, &extra);

    assert_exit(&output, 10);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["drifts"], 1);
    assert_eq!(report["groups"][0]["class"], "allow_deny_flip");
}

#[test]
fn sig_mismatch_exits_twenty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = tenant_signing_key();
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let extra = vec![
        "--tenant-pubkey".to_string(),
        pubkey_path.display().to_string(),
    ];

    let output = run_traffic(&fixture_path("sig_mismatch.ndjson"), &extra);

    assert_exit(&output, 20);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 20);
}

#[test]
fn parse_error_exits_thirty() {
    let output = run_traffic(&fixture_path("parse_error.ndjson"), &[]);

    assert_exit(&output, 30);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 30);
}

#[test]
fn schema_mismatch_exits_forty() {
    let output = run_traffic(&fixture_path("schema_mismatch.ndjson"), &[]);

    assert_exit(&output, 40);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 40);
}

#[test]
fn redaction_mismatch_exits_fifty() {
    let output = run_traffic(&fixture_path("redaction_mismatch.ndjson"), &[]);

    assert_exit(&output, 50);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json replay report");
    assert_eq!(report["first_error"]["exit_code"], 50);
}

#[test]
fn schema_mismatch_against_exits_forty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let key = tenant_signing_key();
    let fixture = signed_fixture_copy("schema_mismatch.ndjson", dir.path(), &key);
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let mut extra = against_args(&policy);
    extra.push("--tenant-pubkey".to_string());
    extra.push(pubkey_path.display().to_string());

    let output = run_traffic(&fixture, &extra);

    assert_exit(&output, 40);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["errors"], 1);
    assert!(report["error_outcomes"][0]["error"]
        .as_str()
        .unwrap_or_default()
        .contains("schema-version gate failed"));
}

#[test]
fn sig_mismatch_against_exits_twenty_without_pubkey() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let extra = against_args(&policy);

    let output = run_traffic(&fixture_path("sig_mismatch.ndjson"), &extra);

    assert_exit(&output, 20);
}

#[test]
fn sig_mismatch_against_exits_twenty_when_pubkey_configured() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let key = tenant_signing_key();
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let mut extra = against_args(&policy);
    extra.push("--tenant-pubkey".to_string());
    extra.push(pubkey_path.display().to_string());

    let output = run_traffic(&fixture_path("sig_mismatch.ndjson"), &extra);

    assert_exit(&output, 20);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["errors"], 1);
    assert!(report["error_outcomes"][0]["error"]
        .as_str()
        .unwrap_or_default()
        .contains("tenant signature verification failed"));
}

#[test]
fn redaction_mismatch_against_exits_fifty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let key = tenant_signing_key();
    let fixture = signed_fixture_copy("redaction_mismatch.ndjson", dir.path(), &key);
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let mut extra = against_args(&policy);
    extra.push("--tenant-pubkey".to_string());
    extra.push(pubkey_path.display().to_string());

    let output = run_traffic(&fixture, &extra);

    assert_exit(&output, 50);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["errors"], 1);
    assert!(report["error_outcomes"][0]["error"]
        .as_str()
        .unwrap_or_default()
        .contains("redaction mismatch"));
}

#[test]
fn empty_against_capture_exits_thirty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = write_allow_all_policy(dir.path());
    let fixture = dir.path().join("empty.ndjson");
    fs::write(&fixture, "").expect("write empty fixture");
    let key = tenant_signing_key();
    let pubkey_path = write_tenant_pubkey(dir.path(), &key);
    let mut extra = against_args(&policy);
    extra.push("--tenant-pubkey".to_string());
    extra.push(pubkey_path.display().to_string());

    let output = run_traffic(&fixture, &extra);

    assert_exit(&output, 30);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json diff report");
    assert_eq!(report["errors"], 1);
    assert!(report["error_outcomes"][0]["error"]
        .as_str()
        .unwrap_or_default()
        .contains("empty capture"));
}
