//! Execution adapters own the protected files and publish immutable effects.
use crate::{digest, retain};
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

pub struct Workspace(pub PathBuf);

pub fn source(directory: &Path) -> Result<String> {
    Ok(files::read_text(&directory.join("lib.rs"), 64_000)?)
}

pub async fn tests(directory: &Path, confined: bool) -> Result<Value> {
    let binary = directory.join("regression-tests");
    let mut compiler_command = if confined {
        let output = std::process::Command::new("rustup")
            .args(["which", "--toolchain", "1.94.1", "rustc"])
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "Cannot resolve the configured Rust compiler"
        );
        let path = PathBuf::from(String::from_utf8(output.stdout)?.trim());
        crate::sandbox::command(&path, directory)?
    } else {
        Command::new("rustc")
    };
    compiler_command
        .args(["--edition=2021", "--test", "tests.rs", "-o"])
        .arg(&binary);
    let compiler = execute(directory, "compile", &mut compiler_command).await?;
    if compiler["success"] != true {
        return Ok(json!({"passed": false, "compiler": compiler}));
    }
    let mut test_command = if confined {
        crate::sandbox::command(&binary, directory)?
    } else {
        Command::new(&binary)
    };
    let result = execute(directory, "tests", test_command.args(["--test-threads=1"])).await?;
    Ok(json!({"passed": result["success"], "result": result}))
}

async fn execute(directory: &Path, name: &str, command: &mut Command) -> Result<Value> {
    // Logs go to files, not unbounded in-memory pipes. The supplied harness is
    // trusted local code; workspace separation does not provide an OS sandbox.
    let stdout = directory.join(format!("{name}.stdout"));
    let stderr = directory.join(format!("{name}.stderr"));
    let mut child = command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("TMPDIR", directory.canonicalize()?)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(&stderr)?)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("Start {name}"))?;
    let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(result) => result?,
        Err(_) => {
            child.kill().await?;
            child.wait().await?;
            anyhow::bail!("{name} exceeded 30 seconds; inspect retained logs");
        }
    };
    Ok(
        json!({"success": status.success(), "exit_code": status.code(), "status":status.to_string(),
        "stdout": files::read_text(&stdout, 64_000)?, "stderr": files::read_text(&stderr, 64_000)?}),
    )
}

impl Workspace {
    async fn perform(&self, tool: &str, input: &Value) -> Result<Value> {
        let id = input["operation_id"]
            .as_str()
            .context("Operation ID missing")?;
        uuid::Uuid::parse_str(id)?;
        let destination = self.0.join("effects").join(format!("{id}.json"));
        anyhow::ensure!(
            !destination.exists(),
            "Effect already exists; reconcile before dispatch"
        );
        let source_directory = self.0.join("source");
        let baseline = source(&source_directory)?;
        anyhow::ensure!(
            input["source_sha256"] == digest(&baseline)?,
            "Source version changed after assignment"
        );
        let model = input["mode"] == "model";
        let result = match tool {
            "inspect" if model => crate::model::ask("Investigate this Rust regression. Return JSON with findings (array of specific findings). Do not claim to have executed tests.", json!({"source":baseline,"tests":files::read_text(&source_directory.join("tests.rs"),64_000)?})).await?,
            "inspect" => {
                json!({"source": baseline, "tests": files::read_text(&source_directory.join("tests.rs"), 64_000)?,
                "findings": ["Zero-length windows reach a division", "A u64 sum can overflow before division"],
                "method": "Deterministic inspection of the supplied rolling-window regression"})
            }
            "reproduce" => tests(&source_directory, model).await?,
            "repair" => {
                let proposed = if model {
                    crate::model::ask("Repair the supplied Rust source while preserving its public API and immutable tests. Return JSON with source (the complete replacement lib.rs, no Markdown fences) and rationale. Correct all failing cases. Avoid unsafe code, external dependencies, file I/O and network I/O.", json!({"source":baseline,"tests":files::read_text(&source_directory.join("tests.rs"),64_000)?,"approach":input["strategy"]})).await?
                } else { json!({"answer":{"source":input["candidate_source"]}}) };
                let candidate_source = proposed["answer"]["source"]
                    .as_str()
                    .context("Worker did not propose source")?;
                anyhow::ensure!(
                    candidate_source.len() <= 64_000,
                    "Candidate exceeds size limit"
                );
                let stage = files::StagedDirectory::new(&self.0.join("candidates"))?;
                files::create(&stage.path().join("lib.rs"), candidate_source.as_bytes())?;
                files::create(
                    &stage.path().join("tests.rs"),
                    files::read_text(&source_directory.join("tests.rs"), 64_000)?.as_bytes(),
                )?;
                let candidate_dir = self.0.join("candidates").join(id);
                stage.publish(&candidate_dir)?;
                let tests = tests(&candidate_dir, model).await?;
                json!({"candidate": id, "candidate_sha256": digest(&candidate_source)?, "tests": tests,
                    "strategy": input["strategy"], "planning": proposed, "tests_sha256": digest(&files::read_text(&source_directory.join("tests.rs"), 64_000)?)?})
            }
            "test" | "review" => {
                let candidate = input["candidate"].as_str().context("Candidate missing")?;
                uuid::Uuid::parse_str(candidate)?;
                let directory = self.0.join("candidates").join(candidate);
                let actual = source(&directory)?;
                anyhow::ensure!(
                    digest(&actual)? == input["candidate_sha256"],
                    "Candidate changed after selection"
                );
                let original_tests = files::read_text(&source_directory.join("tests.rs"), 64_000)?;
                anyhow::ensure!(
                    files::read_text(&directory.join("tests.rs"), 64_000)? == original_tests,
                    "Candidate changed immutable tests"
                );
                if tool == "test" {
                    json!({"candidate_sha256": digest(&actual)?, "tests": tests(&directory, model).await?})
                } else if model {
                    let report = crate::model::ask("Independently review this exact Rust candidate against its original source and tests. Return JSON with accepted (boolean), findings (array), and rationale. Look for correctness, edge cases and unexpected effects. You have not executed tests; a separate worker does that.", json!({"original":baseline,"candidate":actual,"tests":original_tests})).await?;
                    json!({"candidate_sha256":digest(&actual)?,"accepted":report["answer"]["accepted"] == true,"review":report,"method":"Independent model review of the exact candidate"})
                } else {
                    // Mechanical review checks the allowed transformation, not
                    // semantic correctness of arbitrary generated Rust.
                    let expected = repair(&baseline, true)?;
                    json!({"candidate_sha256": digest(&actual)?, "accepted": actual == expected,
                        "method": "Exact bounded repair transformation and unchanged regression tests"})
                }
            }
            "write" => {
                // Registered so the authority drill attempts a real effectful
                // operation. No research capability grants this operation.
                files::replace(&self.0.join("protected.txt"), b"unauthorized write\n")?;
                json!({"written": true})
            }
            _ => anyhow::bail!("Unknown operation {tool}"),
        };
        let effect = json!({"operation_id": id, "tool": tool, "input_sha256": digest(input)?, "result": result});
        retain(&destination, &effect)?;
        Ok(effect)
    }
}

/// The two implementation workers explore different repairs against real tests.
/// This is a bounded source transformation, not an autonomous model patch.
pub fn repair(source: &str, widen: bool) -> Result<String> {
    anyhow::ensure!(
        source.contains("    if window > values.len() {"),
        "Unsupported source: supply an adapter for this project"
    );
    let mut candidate = source.replacen("    if window > values.len() {", "    if window == 0 {\n        return Err(\"window must be positive\");\n    }\n    if window > values.len() {", 1);
    if widen {
        anyhow::ensure!(
            candidate.contains("let mut sum: u64 = values[..window].iter().copied().sum();"),
            "Expected accumulator was not found"
        );
        candidate = candidate.replace("let mut sum: u64 = values[..window].iter().copied().sum();", "let mut sum: u128 = values[..window].iter().map(|&value| u128::from(value)).sum();")
            .replace("window as u64", "window as u128")
            .replace("values[index - window] as u64", "u128::from(values[index - window])")
            .replace("values[index] as u64", "u128::from(values[index])");
    }
    Ok(candidate)
}

#[async_trait::async_trait]
impl ToolServerConnection for Workspace {
    fn server_id(&self) -> &str {
        "workspace"
    }
    fn tool_names(&self) -> Vec<String> {
        ["inspect", "reproduce", "repair", "test", "review", "write"]
            .map(str::to_owned)
            .to_vec()
    }
    async fn invoke(
        &self,
        tool: &str,
        input: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.perform(tool, &input)
            .await
            .map_err(|error| KernelError::ToolServerError(format!("{error:#}")))
    }
}
