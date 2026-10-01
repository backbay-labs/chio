use super::{
    setup::{Setup, Workers},
    workspace::{self, Entry},
};
use crate::{digest, journal, read};
use anyhow::{ensure, Context, Result};
use chio_agent_os_shared::runtime::files;
use serde_json::{json, Value};
use std::path::Path;

pub fn native_available() -> bool {
    cfg!(all(
        feature = "native-agents",
        target_os = "macos",
        target_arch = "aarch64"
    )) && crate::sandbox::available()
}
// These are the bounded implementation candidates. Release qualification is
// separate and the website must use the published qualification manifest.
pub fn native_teams() -> Value {
    json!([
        {"research":"codex","implementation":"codex","review":"codex"},
        {"research":"hermes","implementation":"codex","review":"pi"}
    ])
}
pub fn supported(setup: &Setup) -> bool {
    match &setup.workers {
        Workers::Reference => true,
        Workers::Native { roles } => {
            native_available()
                && native_teams().as_array().is_some_and(|teams| {
                    teams.contains(&serde_json::to_value(roles).unwrap_or(Value::Null))
                })
        }
    }
}

pub fn readiness(setup: &Setup) -> Result<Value> {
    let mut checks = vec![];
    let native = matches!(setup.workers, Workers::Native { .. });
    let mut rust = std::process::Command::new(if native { "rustup" } else { "rustc" });
    rust.args(if native {
        &["which", "--toolchain", "1.94.1", "rustc"][..]
    } else {
        &["--version"][..]
    });
    let compiler = bounded_check(rust);
    checks.push(json!({"id":"compiler","label":"Rust compiler","status":if compiler{"ready"}else{"missing"},"blocking":true,"message":if compiler{"Rust compiler is available."}else if native{"Install Rust toolchain 1.94.1, then refresh."}else{"Install Rust, then reopen this workshop from a terminal with rustc on PATH."},"guide":"installation"}));
    if let Workers::Native { roles } = &setup.workers {
        checks.push(json!({"id":"sandbox","label":"Native execution","status":if native_available(){"ready"}else{"unsupported"},"blocking":true,"message":if native_available(){"The supported local sandbox is available."}else{"This native setup requires Apple Silicon macOS and an operator built with native support."},"guide":"native-agents"}));
        checks.push(json!({"id":"crew","label":"Selected agents","status":if supported(setup){"ready"}else{"unsupported"},"blocking":true,"message":if supported(setup){"This operator supports the selected role combination."}else{"This agent combination is not enabled in this operator."}}));
        #[cfg(feature = "native-agents")]
        {
            use crate::agents::{connections, launcher::Installation};
            let mut names = std::collections::BTreeSet::new();
            let mut needs_preparation = false;
            for agent in [roles.research, roles.implementation, roles.review] {
                if !names.insert(agent.name()) {
                    continue;
                }
                let path = connections::directory()?
                    .join(agent.name())
                    .join("installation.json");
                let prepared = read::<Installation>(&path).is_ok_and(|i| {
                    serde_json::to_value(i.agent).ok() == Some(json!(agent.name()))
                        && connections::validate(&i).is_ok()
                });
                needs_preparation |= !prepared;
                checks.push(json!({"id":format!("agent-{}",agent.name()),"label":format!("{} integration",agent.name()),"agent":agent,"status":if prepared{"ready"}else{"missing"},"blocking":true,"message":if prepared{"Pinned integration files and required local login files are present."}else{"Prepare this agent using your existing login."},"guide":"native-agents"}));
                if prepared {
                    checks.push(json!({"id":format!("login-{}",agent.name()),"label":format!("{} account",agent.name()),"agent":agent,"status":"unverified","blocking":false,"message":"Account validity is checked when you explicitly start. Preparation does not make a model request."}));
                }
            }
            if needs_preparation {
                let mut node = std::process::Command::new("node");
                node.args(["-e", "const [major,minor]=process.versions.node.split('.').map(Number);process.exit(major>22||(major===22&&minor>=19)?0:1)"]);
                let available = bounded_check(node);
                checks.push(json!({"id":"prepare-node","label":"Node.js","status":if available{"ready"}else{"missing"},"blocking":true,"message":if available{"Node.js meets the native preparation requirement."}else{"Install Node.js 22.19 or newer, then reopen the host from that terminal."},"guide":"installation"}));
                for tool in ["npm", "git"] {
                    let available =
                        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                            .any(|directory| directory.join(tool).is_file());
                    checks.push(json!({"id":format!("prepare-{tool}"),"label":tool,"status":if available{"ready"}else{"missing"},"blocking":true,"message":if available{format!("{tool} is available for preparation.")}else{format!("Install {tool}, then reopen the host from that terminal.")},"guide":"installation"}));
                }
            }
        }
        #[cfg(not(feature = "native-agents"))]
        let _ = roles;
    }
    Ok(json!(checks))
}

fn bounded_check(mut command: std::process::Command) -> bool {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let Ok(mut child) = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

pub fn ready(setup: &Setup) -> Result<()> {
    ensure!(
        supported(setup),
        "Selected setup is unavailable on this operator"
    );
    let checks = readiness(setup)?;
    ensure!(
        !checks
            .as_array()
            .context("Readiness missing")?
            .iter()
            .any(|c| c["blocking"] == true && c["status"] != "ready"),
        "Complete the missing local prerequisites before continuing"
    );
    Ok(())
}

pub fn normalize_tests(tests: &Value, candidate: Value, harness: &str) -> Value {
    let compiler_output = tests["compiler"]["stderr"].as_str().map(str::to_owned);
    let output = tests["result"]["stdout"].as_str();
    let mut checks = vec![];
    let mut names = std::collections::HashSet::new();
    let mut invalid = false;
    if let Some(output) = output {
        for line in output.lines() {
            if let Some((name, status)) = line
                .strip_prefix("test ")
                .and_then(|l| l.split_once(" ... "))
            {
                let mapped = match status {
                    "ok" => "passed",
                    "FAILED" => "failed",
                    "ignored" => "ignored",
                    _ => {
                        invalid = true;
                        continue;
                    }
                };
                if name.len() > 256 || !names.insert(name) || checks.len() >= 512 {
                    invalid = true;
                    continue;
                }
                checks.push(json!({"name":name,"status":mapped}));
            }
        }
    }
    let passed = checks.iter().filter(|c| c["status"] == "passed").count();
    let failed = checks.iter().filter(|c| c["status"] == "failed").count();
    let ignored = checks.iter().filter(|c| c["status"] == "ignored").count();
    let prefix = format!(
        "test result: {}. {passed} passed; {failed} failed; {ignored} ignored;",
        if failed == 0 { "ok" } else { "FAILED" }
    );
    let complete = !invalid
        && !checks.is_empty()
        && output.is_some_and(|text| text.lines().any(|line| line.starts_with(&prefix)));
    let status = if tests.is_null() {
        "pending"
    } else if tests["compiler"]["success"] == false {
        "compile_failed"
    } else if tests["result"]["success"] == false {
        if complete && failed > 0 {
            "failed"
        } else {
            "runner_failed"
        }
    } else if tests["passed"] == true
        && tests["result"]["success"] == true
        && complete
        && failed == 0
    {
        "passed"
    } else {
        "unknown"
    };
    json!({"status":status,"checks":checks,"output":output,"compiler_output":compiler_output,"candidate_digest":candidate,"harness_digest":harness,"complete":complete})
}

struct Art {
    descriptor: Value,
    content: Option<String>,
}
fn artifact(
    id: &str,
    label: &str,
    kind: &str,
    content: Option<String>,
    operation: Value,
) -> Result<Art> {
    Ok(Art {
        descriptor: json!({"id":id,"label":label,"kind":kind,"status":if content.is_some(){"available"}else{"pending"},"digest":content.as_ref().map(digest).transpose()?,"digest_scheme":"canonical-json-sha256","operation_id":operation}),
        content,
    })
}

fn data(root: &Path, entry: &Entry) -> Result<(Value, Vec<Art>)> {
    let raw = journal::snapshot(root)?;
    let source = raw["original"]
        .as_str()
        .context("Original source unavailable")?;
    let harness = files::read_text(&root.join("source/tests.rs"), 64_000)?;
    let source_digest = digest(&source)?;
    let harness_digest = digest(&harness)?;
    ensure!(
        raw["config"]["source_sha256"] == source_digest
            && raw["config"]["tests_sha256"] == harness_digest,
        "Frozen mission input changed"
    );
    let input_identity =
        digest(&json!({"source_digest":source_digest,"harness_digest":harness_digest}))?;
    let proposal = &raw["proposal"];
    let candidate = raw["candidate"].as_str();
    if !proposal.is_null() {
        ensure!(
            proposal["source_sha256"] == source_digest
                && proposal["tests_sha256"] == harness_digest
                && proposal["candidate_sha256"]
                    == digest(&candidate.context("Candidate unavailable")?)?,
            "Candidate or proposal identity changed"
        );
    }
    let outcomes = raw["outcomes"].as_array().context("Outcomes unavailable")?;
    let test_outcome = if !proposal.is_null() {
        outcomes.iter().find(|o| {
            o["allowed"] == true
                && o["receipt"]["id"] == proposal["test_receipt"]
                && o["output"]["result"]["candidate_sha256"] == proposal["candidate_sha256"]
        })
    } else {
        outcomes
            .iter()
            .rev()
            .find(|o| o["allowed"] == true && o["output"]["result"]["tests"].is_object())
    };
    let tests = normalize_tests(
        test_outcome
            .map(|o| &o["output"]["result"]["tests"])
            .unwrap_or(&Value::Null),
        test_outcome
            .map(|o| o["output"]["result"]["candidate_sha256"].clone())
            .unwrap_or(Value::Null),
        &harness_digest,
    );
    let review = outcomes.iter().find(|o| {
        !proposal.is_null()
            && o["allowed"] == true
            && o["receipt"]["id"] == proposal["review_receipt"]
            && o["output"]["result"]["candidate_sha256"] == proposal["candidate_sha256"]
    });
    if !proposal.is_null() {
        ensure!(
            test_outcome.is_some() && review.is_some(),
            "Proposal receipts do not match retained outcomes"
        );
    }
    let publication = if raw["published"] == true {
        let release: Value = read(&root.join("release/release.json"))?;
        ensure!(
            &release == proposal
                && digest(&files::read_text(&root.join("release/lib.rs"), 64_000)?)?
                    == proposal["candidate_sha256"],
            "Retained publication identity changed"
        );
        json!({"candidate_digest":proposal["candidate_sha256"],"destination":root.join("release").display().to_string()})
    } else {
        Value::Null
    };
    let op = test_outcome
        .map(|o| o["output"]["operation_id"].clone())
        .unwrap_or(Value::Null);
    let arts = vec![
        artifact("original", "lib.rs · original", "original", Some(source.to_string()), Value::Null)?,
        artifact("harness", "tests.rs", "harness", Some(harness), Value::Null)?,
        artifact("candidate", "lib.rs · candidate", "candidate", candidate.map(str::to_owned), Value::Null)?,
        artifact("test-output", "Test output", "test-output", tests["output"].as_str().map(str::to_owned), op.clone())?,
        artifact("compiler-output", "Compiler output", "compiler-output", tests["compiler_output"].as_str().map(str::to_owned), op)?,
        artifact("review", "Review", "review", review.map(|o| serde_json::to_string_pretty(&json!({"accepted":o["output"]["result"]["accepted"],"method":o["output"]["result"]["method"],"candidate_digest":proposal["candidate_sha256"],"receipt":proposal["review_receipt"]}))).transpose()?, Value::Null)?,
        artifact("published", "Published lib.rs", "published", if publication.is_null(){None}else{candidate.map(str::to_owned)}, Value::Null)?,
    ];
    let phase = raw["phase"].as_str().unwrap_or("unknown");
    let active = if ["research", "implementation", "review"].contains(&phase) {
        json!(phase)
    } else {
        Value::Null
    };
    let normalized_proposal = if proposal.is_null() {
        Value::Null
    } else {
        json!({"candidate_id":proposal["candidate"],"candidate_digest":proposal["candidate_sha256"],"harness_digest":harness_digest,"source_digest":source_digest,"test_receipt":proposal["test_receipt"],"review_receipt":proposal["review_receipt"]})
    };
    Ok((
        json!({"id":entry.id,"label":entry.label,"phase":phase,"mode":if raw["agents"].is_object(){"native"}else if raw["config"]["model"] == true{"model"}else{"reference"},"agents":raw["agents"],"source_digest":source_digest,"harness_digest":harness_digest,"input_identity":input_identity,"artifacts":arts.iter().map(|a|a.descriptor.clone()).collect::<Vec<_>>(),"tests":tests,"proposal":normalized_proposal,"publication":publication,"allowance":raw["capacity"],"active_role":active}),
        arts,
    ))
}

pub fn mission(root: &Path, entry: &Entry) -> Result<Value> {
    Ok(data(root, entry)?.0)
}
pub fn artifact_content(root: &Path, entry: &Entry, id: &str) -> Result<Value> {
    let (_, arts) = data(root, entry)?;
    let art = arts
        .into_iter()
        .find(|a| a.descriptor["id"] == id)
        .context("Unknown artifact")?;
    let content = art.content.context("Artifact is not available yet")?;
    ensure!(content.len() <= 64_000, "Artifact exceeds display limit");
    Ok(
        json!({"schema_version":1,"mission_id":entry.id,"artifact":art.descriptor,"content":content,"truncated":false}),
    )
}

pub fn state(
    root: &Path,
    epoch: uuid::Uuid,
    selected: Option<uuid::Uuid>,
    active: Value,
) -> Result<Value> {
    let m = workspace::load(root)?;
    let selected = selected.or(m.selected_mission_id);
    let mut last_event = 0;
    let mission = if let Some(id) = selected {
        let path = workspace::mission_path(root, &m, id)?;
        // Capture the cursor before the projection. Later events may repeat a
        // snapshot observation, but no event can be skipped during a read race.
        last_event = journal::events(&path)?
            .last()
            .and_then(|e| e["sequence"].as_u64())
            .unwrap_or(0);
        self::mission(&path, workspace::entry(&m, id)?)?
    } else {
        Value::Null
    };
    let mut state = json!({"schema_version":1,"host":{"epoch":epoch,"operator_version":env!("CARGO_PKG_VERSION"),"ui_build_id":super::assets::BUILD_ID,"target":format!("{}-{}",std::env::consts::ARCH,std::env::consts::OS)},"workspace":{"id":m.id,"schema_version":1,"selected_mission_id":selected,"setup":m.setup,"missions":m.missions},"capabilities":{"commands":["prepare_agent","initialize","run","resume","approve","create_revision"],"reference":true,"native":native_available(),"native_teams":if native_available(){native_teams()}else{json!([])}},"readiness":readiness(&m.setup)?,"mission":mission,"last_event_sequence":last_event,"active_command":active});
    #[cfg(unix)]
    {
        let writable = workspace::writable(root);
        state["readiness"].as_array_mut().context("Readiness is not a list")?.push(json!({"id":"storage","label":"Workspace permissions","status":if writable{"ready"}else{"missing"},"blocking":true,"message":if writable{"Workspace directories permit writes by their owner."}else{"Restore owner write and directory access permissions before continuing. Retained work remains available for inspection."},"guide":"installation"}));
    }
    state["snapshot_id"] = json!(digest(&state)?);
    ensure!(
        serde_json::to_vec(&state)?.len() <= 2_000_000,
        "Workshop snapshot exceeds display limit"
    );
    Ok(state)
}
