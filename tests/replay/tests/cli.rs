#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_chio-replay-gate")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must canonicalize")
}

#[test]
fn help_mentions_bless() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("help command must run");

    assert!(output.status.success(), "--help should exit 0");
    let stdout = String::from_utf8(output.stdout).expect("help stdout must be utf8");
    assert!(stdout.contains("chio-replay-gate"));
    assert!(stdout.contains("--bless"));
}

#[test]
fn goldens_root_json_report_uses_schema_v1() {
    let output = Command::new(binary())
        .current_dir(workspace_root())
        .args(["tests/replay/goldens", "--json"])
        .output()
        .expect("json command must run");

    assert!(
        output.status.success(),
        "json validation should pass, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("json stdout must be utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a JSON report");
    assert_eq!(report["schema"], "chio.replay.report/v1");
    assert_eq!(report["accepted"], true);
    assert_eq!(report["checkedFixtures"], 50);
    assert_eq!(report["divergences"].as_array().unwrap().len(), 0);
}

#[test]
fn single_scenario_expect_root_accepts_root_hex() {
    let root = workspace_root();
    let expected_root = fs::read_to_string(
        root.join("tests/replay/goldens/allow_simple/01_basic_capability/root.hex"),
    )
    .expect("root.hex must be readable");
    let output = Command::new(binary())
        .current_dir(&root)
        .args([
            "tests/replay/goldens/allow_simple/01_basic_capability",
            "--expect-root",
            &expected_root,
            "--json",
        ])
        .output()
        .expect("single-scenario command must run");

    assert!(
        output.status.success(),
        "single-scenario validation should pass, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("json stdout must be utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a JSON report");
    assert_eq!(report["checkedFixtures"], 1);
    assert_eq!(report["computedRoot"], expected_root);
    assert_eq!(report["expectedRoot"], expected_root);
    assert_eq!(report["divergences"].as_array().unwrap().len(), 0);
}

#[test]
fn bless_without_chio_bless_fails_closed() {
    let output = Command::new(binary())
        .current_dir(workspace_root())
        .env_remove("CHIO_BLESS")
        .env_remove("BLESS_REASON")
        .args([
            "--bless",
            "tests/replay/fixtures/allow_simple/01_basic_capability.json",
        ])
        .output()
        .expect("bless command must run");

    assert!(
        !output.status.success(),
        "bless without CHIO_BLESS must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr must be utf8");
    assert!(stderr.contains("CHIO_BLESS"), "stderr was: {stderr}");
}
