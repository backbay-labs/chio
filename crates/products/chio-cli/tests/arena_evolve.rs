//! Integration coverage for `chio arena evolve`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn cargo_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn write_seed(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("seed.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "chio.arena.scenario/v1"
id = "evolve_smoke"
title = "Evolve smoke"
rng_seed = 17
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 17
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/evolve.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/evolve.txt" }
expect_verdict = "deny"
"#,
    )
    .unwrap();
    path
}

#[test]
fn arena_evolve_emits_json_summary_with_budget_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = write_seed(tmp.path());
    let out_root = tmp.path().join("evolve-out");
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "evolve",
            seed.to_str().unwrap(),
            "--generations",
            "3",
            "--wall-seconds",
            "120",
            "--output-root",
            out_root.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("arena evolve");
    assert!(
        out.status.success(),
        "arena evolve should succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("arena evolve must emit JSON");
    assert_eq!(parsed["schema_version"], "chio.arena.evolve/v1");
    assert_eq!(parsed["scenario_id"], "evolve_smoke");
    assert_eq!(parsed["generations"], 3);
    assert_eq!(parsed["wall_seconds"], 120);
    assert!(parsed["budget_gate"].as_str().unwrap().contains("bounded"));
}

#[test]
fn arena_evolve_refuses_zero_generations() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = write_seed(tmp.path());
    let out = Command::new(cargo_bin())
        .args([
            "arena",
            "evolve",
            seed.to_str().unwrap(),
            "--generations",
            "0",
        ])
        .output()
        .expect("arena evolve --generations 0");
    assert!(!out.status.success(), "zero generations should fail");
}

#[test]
fn arena_evolve_rejects_budget_overrides_above_milestone_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = write_seed(tmp.path());
    let too_many_generations = Command::new(cargo_bin())
        .args([
            "arena",
            "evolve",
            seed.to_str().unwrap(),
            "--generations",
            "201",
        ])
        .output()
        .expect("arena evolve high generations");
    assert!(
        !too_many_generations.status.success(),
        "generation cap should fail closed"
    );
    let stderr = String::from_utf8(too_many_generations.stderr).unwrap();
    assert!(
        stderr.contains("--generations") && stderr.contains("200"),
        "expected generation cap error, got {stderr}"
    );

    let too_much_wall = Command::new(cargo_bin())
        .args([
            "arena",
            "evolve",
            seed.to_str().unwrap(),
            "--wall-seconds",
            "1801",
        ])
        .output()
        .expect("arena evolve high wall clock");
    assert!(
        !too_much_wall.status.success(),
        "wall-clock cap should fail closed"
    );
    let stderr = String::from_utf8(too_much_wall.stderr).unwrap();
    assert!(
        stderr.contains("--wall-seconds") && stderr.contains("1800"),
        "expected wall-clock cap error, got {stderr}"
    );
}
