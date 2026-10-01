//! Native sessions supply artifacts; the existing Rust executor validates them.
use super::launcher::{self, Installation};
use crate::{mission::Mission, protocol::Assignment, read, retain};
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub first_port: u16,
    pub swarms: BTreeMap<String, Installation>,
}

impl Configuration {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1024..=65529).contains(&self.first_port),
            "Invalid native endpoint range"
        );
        anyhow::ensure!(
            self.swarms.len() == 3
                && ["research", "implementation", "review"]
                    .iter()
                    .all(|name| self.swarms.contains_key(*name)),
            "Select one installed agent for each swarm"
        );
        Ok(())
    }
}

pub async fn round(mission: &Mission, tasks: Vec<Assignment>) -> Result<Vec<Value>> {
    anyhow::ensure!(tasks.len() == 2, "Each swarm requires two assignments");
    let (first, second) = tokio::join!(perform(mission, &tasks[0]), perform(mission, &tasks[1]));
    let (first, second) = (first?, second?);
    anyhow::ensure!(
        first["allowed"] == true && second["allowed"] == true,
        "Native swarm did not complete its governed operations"
    );
    mission.report_capacity()?;
    Ok(vec![first, second])
}

async fn perform(mission: &Mission, assignment: &Assignment) -> Result<Value> {
    let config = mission
        .config
        .native
        .as_ref()
        .context("Native configuration missing")?;
    config.validate()?;
    let swarm = assignment
        .worker
        .rsplit_once('-')
        .context("Invalid worker identity")?
        .0;
    let installation = config
        .swarms
        .get(swarm)
        .context("Swarm has no selected agent")?;
    let root = mission.directory.join("native");
    let handoff_path = root
        .join("resource/handoffs")
        .join(format!("{}.json", assignment.id));
    let mut handoff = json!({"assignment":assignment,"mission_source_sha256":mission.config.source_sha256,"tests_sha256":mission.config.tests_sha256});
    if let Some(candidate) = assignment.input["candidate"].as_str() {
        uuid::Uuid::parse_str(candidate)?;
        let source =
            crate::operations::source(&mission.directory.join("candidates").join(candidate))?;
        anyhow::ensure!(
            crate::digest(&source)? == assignment.input["candidate_sha256"],
            "Handoff candidate changed"
        );
        handoff["candidate_source"] = json!(source);
        let validation: Value = read(
            &mission
                .directory
                .join("outcomes")
                .join(format!("{candidate}.json")),
        )?;
        handoff["candidate_validation"] = handoff_outcome(&validation)?;
    }
    if assignment.tool == "repair" {
        let mut research = Vec::new();
        for name in ["inspect", "reproduce"] {
            let task: Assignment = read(
                &mission
                    .directory
                    .join("assignments")
                    .join(format!("{name}.json")),
            )?;
            research.push(read::<Value>(
                &mission
                    .directory
                    .join("outcomes")
                    .join(format!("{}.json", task.id)),
            )?);
        }
        anyhow::ensure!(
            crate::digest(&research)? == assignment.input["findings_sha256"],
            "Research handoff changed"
        );
        handoff["research"] = json!(research
            .iter()
            .map(handoff_outcome)
            .collect::<Result<Vec<_>>>()?);
    }
    if handoff_path.exists() {
        anyhow::ensure!(
            read::<Value>(&handoff_path)? == handoff,
            "Retained native handoff changed"
        );
    } else {
        retain(&handoff_path, &handoff)?;
    }
    let destination = format!(
        "/workspace/outputs/{}/{}.json",
        assignment.worker, assignment.id
    );
    let instruction = match assignment.tool.as_str() {
        "repair" => "Produce a complete corrected lib.rs preserving the public API. Return an object with source (complete Rust source) and rationale. Avoid unsafe, dependencies, I/O and subprocesses. The host will compile and run the immutable tests.",
        "review" => "Independently review the exact candidate source in the handoff against the original and tests. Return accepted (boolean), findings (array), and rationale. Do not claim you ran tests.",
        "test" => "Inspect the candidate and identify the regression cases the host must run. Return findings (array) and rationale. The trusted host executes the immutable tests after this artifact is retained.",
        _ => "Investigate the failing source and immutable tests. Return findings (array) and rationale. Distinguish inferred failures from executed tests; the trusted host reproduces the failure.",
    };
    let prompt = format!("You are {} in a governed repair mission. Use the Chio filesystem tools to read /workspace/source/lib.rs, then /workspace/source/tests.rs, then /workspace/handoffs/{}.json. Make exactly one tool call per turn and wait for its result before the next call; never issue parallel tool calls. {instruction} Keep findings and rationale concise. Include only the requested fields; do not repeat the assignment, source, or handoff in research/review artifacts. Write exactly one final JSON artifact using write_file at {destination}. Do not modify source, tests, or other workers' outputs. Do not invoke shell tools. Finish after the write succeeds.", assignment.worker, assignment.id);
    crate::journal::emit(
        &mission.directory,
        "native.task",
        &assignment.worker,
        json!({"assignment":assignment.id,"agent":installation.agent,"handoff_sha256":crate::digest(&handoff)?}),
    )?;
    let result = launcher::task_bound(
        &root.join(&assignment.worker),
        installation,
        &prompt,
        &assignment.id,
    )
    .await?;
    anyhow::ensure!(
        result["unresolved"] == false,
        "Native assignment retains unresolved operations"
    );
    let artifact = files::read_text(
        &root
            .join("resource/outputs")
            .join(&assignment.worker)
            .join(format!("{}.json", assignment.id)),
        64_000,
    )?;
    let answer: Value = serde_json::from_str(&artifact).context("Native artifact is not JSON")?;
    anyhow::ensure!(answer.is_object(), "Native artifact must be an object");
    validate_answer(&assignment.tool, &answer)?;
    let operations = result["operations"]
        .as_array()
        .context("Native task has no operation records")?;
    let delivered = operations
        .iter()
        .find(|record| {
            record["state"] == "completed"
                && record["acknowledged"] == true
                && record["hostDeliveryConfirmed"] == true
                && record["request"]["tool"] == "write_file"
                && record["request"]["arguments"]["path"] == destination
                && record["request"]["arguments"]["content"] == artifact
        })
        .context("Artifact has no exactly matching delivered write")?;
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(delivered["outcome"]["receipt"].clone())?;
    anyhow::ensure!(
        receipt.verify_signature()?
            && receipt.kernel_key == mission.host.signer
            && receipt.capability_id == mission.authority.workers[&assignment.worker].id
            && receipt.tool_server == "fs"
            && receipt.tool_name == "write_file"
            && receipt.action.parameter_hash == crate::digest(&delivered["request"]["arguments"])?
            && receipt.decision == Some(chio_core::receipt::decision::Decision::Allow),
        "Native artifact receipt binding failed"
    );
    let mut task = assignment.clone();
    task.input["native_answer"] = answer;
    // A native process can fail after delivering its artifact. Accept only the
    // exact verified write above; preserve the process error without rerunning it.
    if result["native_exit"] != 0 {
        crate::journal::emit(
            &mission.directory,
            "native.artifact.reconciled",
            &assignment.worker,
            json!({"assignment":assignment.id,"native_exit":result["native_exit"],"receipt":receipt.id,"session":result["session"]}),
        )?;
    }
    task.input["native_evidence"] = json!({"session":result["session"],"artifact_sha256":chio_core::sha256_hex(artifact.as_bytes()),"receipt":receipt.id,"request":delivered["requestId"],"agent":installation.agent,"native_exit":result["native_exit"]});
    mission.dispatch(&task).await
}

/// Keep the complete signed outcome in retained storage. Workers receive the
/// useful result and its identity, without recursively repeating native journals,
/// source, and delivery envelopes until the host truncates the MCP response.
fn handoff_outcome(outcome: &Value) -> Result<Value> {
    let result = &outcome["output"]["result"];
    let answer = &outcome["assignment"]["input"]["native_answer"];
    Ok(json!({
        "assignment": outcome["assignment"]["id"],
        "worker": outcome["assignment"]["worker"],
        "tool": outcome["assignment"]["tool"],
        "outcome_sha256": crate::digest(outcome)?,
        "findings": answer["findings"],
        "rationale": answer["rationale"],
        "tests": if result["tests"].is_object() { result["tests"].clone() }
                 else if result["passed"].is_boolean() { result.clone() } else { Value::Null },
    }))
}

fn validate_answer(tool: &str, answer: &Value) -> Result<()> {
    anyhow::ensure!(
        answer["rationale"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty()),
        "Native artifact needs a rationale"
    );
    if tool == "repair" {
        anyhow::ensure!(
            answer["source"]
                .as_str()
                .is_some_and(|text| !text.trim().is_empty() && text.len() <= 64_000),
            "Repair artifact needs complete bounded source"
        );
    } else {
        let findings = answer["findings"]
            .as_array()
            .context("Native artifact needs findings")?;
        anyhow::ensure!(
            findings.len() <= 64
                && findings.iter().all(|finding| {
                    finding.as_str().is_some_and(|text| !text.trim().is_empty())
                        || finding.as_object().is_some_and(|object| !object.is_empty())
                }),
            "Findings must be a bounded array of text or structured records"
        );
        if tool == "review" {
            anyhow::ensure!(
                answer["accepted"].is_boolean(),
                "Review must make an explicit boolean decision"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_retains_findings_and_tests_without_recursive_evidence() {
        let outcome = json!({
            "assignment": {"id":"assignment", "worker":"research-0", "tool":"inspect",
                "input":{"native_answer":{"findings":["empty windows fail"],"rationale":"missing guard"},
                         "native_evidence":{"large":"x".repeat(60_000)}}},
            "output":{"result":{"tests":{"passed":true,"result":{"exit_code":0}}}},
            "receipt":{"signature":"original-signature"}
        });
        let projection = handoff_outcome(&outcome).unwrap();
        assert_eq!(
            projection["outcome_sha256"],
            crate::digest(&outcome).unwrap()
        );
        assert_eq!(projection["findings"][0], "empty windows fail");
        assert_eq!(projection["tests"]["passed"], true);
        assert!(projection.to_string().len() < 1000);
        assert!(projection.get("receipt").is_none());
        assert!(projection.get("native_evidence").is_none());
    }

    #[test]
    fn textual_approval_and_missing_source_are_refused() {
        assert!(validate_answer(
            "review",
            &json!({"accepted":"yes","findings":[],"rationale":"looks fine"})
        )
        .is_err());
        assert!(validate_answer("repair", &json!({"rationale":"fixed it"})).is_err());
        assert!(validate_answer(
            "review",
            &json!({"accepted":false,"findings":["overflow"],"rationale":"sum still uses u64"})
        )
        .is_ok());
    }
}
