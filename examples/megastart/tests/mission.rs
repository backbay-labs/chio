use anyhow::Result;
use chio_megastart::{operations::repair, read};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Project(PathBuf);
impl Project {
    fn new() -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("chio-megastart-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
    fn state(&self) -> PathBuf {
        self.0.join("mission")
    }
    fn command(&self, args: &[&str]) -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_megastart"))
            .arg("--state")
            .arg(self.state())
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()?)
    }
    fn ok(&self, args: &[&str]) -> Result<String> {
        let result = self.command(args)?;
        anyhow::ensure!(
            result.status.success(),
            "{:?}: {}\n{}",
            args,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(String::from_utf8(result.stdout)?)
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("Test cleanup: {error}");
        }
    }
}
fn effects(path: &Path) -> Result<usize> {
    Ok(std::fs::read_dir(path.join("effects"))?.count())
}

#[test]
fn mission_refusals_candidate_approval_and_portable_evidence() -> Result<()> {
    let project = Project::new()?;
    project.ok(&["init"])?;
    project.ok(&["drill", "authority"])?;
    assert_eq!(effects(&project.state())?, 0);
    let output = project.ok(&["run"])?;
    assert!(output.contains("3 swarm coordinators, 6 workers"));
    assert_eq!(effects(&project.state())?, 6);
    assert!(!project.state().join("release").exists());
    project.ok(&["drill", "allowance"])?;
    project.ok(&["drill", "approval"])?;
    assert_eq!(effects(&project.state())?, 6);
    assert!(!project.state().join("release").exists());
    let authority: Value = read(&project.state().join("authority.json"))?;
    let workers = authority["workers"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Missing workers"))?;
    assert_eq!(workers.len(), 6);
    for cap in workers.values() {
        assert_eq!(cap["delegation_chain"].as_array().map(Vec::len), Some(1));
    }
    let proposal: Value = read(&project.state().join("proposal.json"))?;
    let candidate = proposal["candidate_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing candidate"))?;
    assert!(!project
        .command(&["approve", "--candidate", "wrong"])?
        .status
        .success());
    project.ok(&["approve", "--candidate", candidate])?;
    let release = std::fs::read(project.state().join("release/lib.rs"))?;
    project.ok(&["approve", "--candidate", candidate])?;
    assert_eq!(
        release,
        std::fs::read(project.state().join("release/lib.rs"))?
    );
    let key = project.ok(&["key"])?;
    project.ok(&["verify", "--trusted-key", key.trim()])?;
    assert!(!project
        .command(&["verify", "--trusted-key", &"0".repeat(64)])?
        .status
        .success());
    let exported = project.0.join("evidence");
    project.ok(&[
        "export",
        "--output",
        exported
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 temporary path"))?,
    ])?;
    assert!(!exported.join("kernel").exists());
    chio_megastart::mission::inspect(&exported, key.trim())?;
    let outcome_path = std::fs::read_dir(exported.join("outcomes"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No exported receipt"))??
        .path();
    let original = std::fs::read(&outcome_path)?;
    let mut forged: Value = serde_json::from_slice(&original)?;
    forged["receipt"]["tool_name"] = serde_json::json!("forged_operation");
    std::fs::write(&outcome_path, serde_json::to_vec(&forged)?)?;
    assert!(chio_megastart::mission::inspect(&exported, key.trim()).is_err());
    std::fs::write(&outcome_path, original)?;
    std::fs::write(
        exported.join("release/lib.rs"),
        b"modified after publication",
    )?;
    assert!(chio_megastart::mission::inspect(&exported, key.trim()).is_err());
    Ok(())
}

#[test]
fn process_crash_recovers_original_effects_without_new_dispatch() -> Result<()> {
    let project = Project::new()?;
    project.ok(&["init"])?;
    let interrupted = project.command(&["run", "--crash-after-repair"])?;
    assert_eq!(
        interrupted.status.code(),
        Some(75),
        "{}",
        String::from_utf8_lossy(&interrupted.stderr)
    );
    assert_eq!(effects(&project.state())?, 4);
    let before: Vec<_> = std::fs::read_dir(project.state().join("effects"))?
        .map(|entry| {
            let path = entry?.path();
            Ok((path.clone(), std::fs::read(&path)?))
        })
        .collect::<std::io::Result<_>>()?;
    let output = project.ok(&["recover"])?;
    assert_eq!(
        output
            .matches("original receipt retained; no dispatch")
            .count(),
        4
    );
    assert_eq!(effects(&project.state())?, 6);
    for (path, bytes) in before {
        assert_eq!(std::fs::read(path)?, bytes);
    }
    project.ok(&["drill", "allowance"])?;
    Ok(())
}

#[test]
fn unknown_request_outcome_requires_reconciliation() -> Result<()> {
    let project = Project::new()?;
    project.ok(&["init"])?;
    project.ok(&["run"])?;
    let assignment: Value = read(&project.state().join("assignments/inspect.json"))?;
    let id = assignment["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing ID"))?;
    std::fs::remove_file(project.state().join("outcomes").join(format!("{id}.json")))?;
    let result = project.command(&["recover"])?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unresolved"));
    assert_eq!(effects(&project.state())?, 6);
    Ok(())
}

#[test]
fn unsupported_source_is_an_explicit_adapter_error() {
    assert!(repair("pub fn different() {}", true).is_err());
}

#[test]
fn changing_a_reviewed_candidate_prevents_publication() -> Result<()> {
    let project = Project::new()?;
    project.ok(&["init"])?;
    project.ok(&["run"])?;
    let proposal: Value = read(&project.state().join("proposal.json"))?;
    let id = proposal["candidate"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing candidate"))?;
    let hash = proposal["candidate_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing digest"))?;
    std::fs::write(
        project.state().join("candidates").join(id).join("lib.rs"),
        b"changed after review",
    )?;
    assert!(!project
        .command(&["approve", "--candidate", hash])?
        .status
        .success());
    assert!(!project.state().join("release").exists());
    Ok(())
}

#[test]
fn an_extended_regression_harness_changes_the_tested_mission() -> Result<()> {
    let project = Project::new()?;
    let input = project.0.join("extended-project");
    std::fs::create_dir(&input)?;
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("project/lib.rs"),
        input.join("lib.rs"),
    )?;
    let mut tests =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("project/tests.rs"))?;
    tests.push_str("\n#[test] fn singleton() { assert_eq!(moving_average(&[u64::MAX], 1), Ok(vec![u64::MAX])); }\n");
    std::fs::write(input.join("tests.rs"), tests)?;
    project.ok(&[
        "init",
        "--project",
        input
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid test path"))?,
    ])?;
    project.ok(&["run"])?;
    let proposal: Value = read(&project.state().join("proposal.json"))?;
    let id = proposal["candidate"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing candidate"))?;
    let log = std::fs::read_to_string(
        project
            .state()
            .join("candidates")
            .join(id)
            .join("tests.stdout"),
    )?;
    assert!(log.contains("6 passed"));
    Ok(())
}
