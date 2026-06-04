//! Integration coverage for `chio arena replay`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn cargo_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

#[test]
fn arena_replay_resolves_bundle_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_root = tmp.path().join("target").join("arena");
    let bundle_dir = bundle_root.join("cli_replay");
    std::fs::create_dir_all(&bundle_dir).unwrap();
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "replay",
            "cli_replay",
            "--output-root",
            bundle_root.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("arena replay");
    assert!(
        out.status.success(),
        "arena replay should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("arena replay must emit JSON");
    assert_eq!(parsed["schema_version"], "chio.arena.replay/v1");
    assert_eq!(parsed["scenario_id"], "cli_replay");
    assert!(parsed["bundle_dir"]
        .as_str()
        .unwrap()
        .contains("cli_replay"));
    assert_eq!(parsed["engine"], "chio-replay-corpus");
}

#[test]
fn arena_replay_refuses_missing_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "replay",
            "no_such_scenario",
            "--output-root",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .expect("arena replay missing");
    assert!(!out.status.success(), "missing bundle should fail");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("does not exist") || stderr.contains("bundle"),
        "expected missing-bundle error, got {stderr}"
    );
}

#[test]
fn arena_replay_rejects_path_traversal_scenario_id() {
    let tmp = tempfile::tempdir().unwrap();
    let escaped = tmp.path().join("escaped");
    std::fs::create_dir_all(&escaped).unwrap();
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "replay",
            "../escaped",
            "--output-root",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .expect("arena replay traversal");
    assert!(!out.status.success(), "traversal id should fail closed");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("scenario id") || stderr.contains("ASCII"),
        "expected invalid scenario id error, got {stderr}"
    );
}

#[test]
fn arena_replay_rejects_parent_directory_segment_scenario_id() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_root = tmp.path().join("target").join("arena");
    std::fs::create_dir_all(&bundle_root).unwrap();
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "replay",
            "..",
            "--output-root",
            bundle_root.to_str().unwrap(),
        ])
        .output()
        .expect("arena replay parent segment");
    assert!(
        !out.status.success(),
        "parent segment id should fail closed"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("scenario id") || stderr.contains("ASCII"),
        "expected invalid scenario id error, got {stderr}"
    );
}

#[test]
fn arena_replay_accepts_explicit_bundle_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_dir = tmp.path().join("custom-bundle");
    std::fs::create_dir_all(&custom_dir).unwrap();
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "replay",
            "scenario_id",
            "--bundle-dir",
            custom_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("arena replay --bundle-dir");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(parsed["bundle_dir"]
        .as_str()
        .unwrap()
        .contains("custom-bundle"));
}
