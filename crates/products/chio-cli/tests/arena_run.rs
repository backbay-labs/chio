//! Integration coverage for `chio arena run`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn cargo_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn write_scenario(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("scenario.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "chio.arena.scenario/v1"
id = "cli_smoke"
title = "CLI smoke"
rng_seed = 1
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 1
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/cli.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/cli.txt" }
expect_verdict = "allow"
"#,
    )
    .unwrap();
    path
}

#[test]
fn arena_run_help_advertises_subcommands() {
    let out = Command::new(cargo_bin())
        .args(["arena", "--help"])
        .output()
        .expect("arena --help");
    assert!(out.status.success(), "arena --help should succeed");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("run"), "missing 'run': {stdout}");
    assert!(stdout.contains("replay"), "missing 'replay': {stdout}");
    assert!(stdout.contains("evolve"), "missing 'evolve': {stdout}");
}

#[test]
fn arena_run_emits_json_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let scenario = write_scenario(tmp.path());
    let out_root = tmp.path().join("out");
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "run",
            scenario.to_str().unwrap(),
            "--output-root",
            out_root.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("arena run");
    assert!(
        out.status.success(),
        "arena run should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("arena run must emit JSON");
    assert_eq!(parsed["schema_version"], "chio.arena.run/v1");
    assert_eq!(parsed["scenario_id"], "cli_smoke");
    assert!(parsed["bundle_dir"]
        .as_str()
        .unwrap()
        .ends_with("cli_smoke"));
    assert_eq!(parsed["determinism"]["scheduler"], "single-agent-v1");
}

#[test]
fn arena_run_creates_bundle_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let scenario = write_scenario(tmp.path());
    let out_root = tmp.path().join("bundle-root");
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "run",
            scenario.to_str().unwrap(),
            "--output-root",
            out_root.to_str().unwrap(),
        ])
        .output()
        .expect("arena run");
    assert!(out.status.success());
    assert!(out_root.join("cli_smoke").is_dir());
}
