use super::{
    projection,
    setup::{Agent, Setup},
    workspace,
};
use crate::{digest, read};
use anyhow::{ensure, Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub host_epoch: Uuid,
    pub mission_input_identity: Option<String>,
    pub candidate_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    PrepareAgent { agent: Agent },
    Initialize { setup: Setup },
    Run,
    Resume,
    Approve { candidate_digest: String },
    CreateRevision { recipe: String },
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::PrepareAgent { .. } => "prepare_agent",
            Self::Initialize { .. } => "initialize",
            Self::Run => "run",
            Self::Resume => "resume",
            Self::Approve { .. } => "approve",
            Self::CreateRevision { .. } => "create_revision",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub request_id: Uuid,
    pub workspace_id: Uuid,
    pub mission_id: Option<Uuid>,
    pub expected: Expected,
    pub command: Command,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request: Request,
    payload_digest: String,
    observation: Value,
}

#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub status: axum::http::StatusCode,
}
impl Failure {
    pub fn new(code: &'static str, message: &str, status: axum::http::StatusCode) -> Self {
        Self {
            code,
            message: message.into(),
            status,
        }
    }
    pub fn conflict(code: &'static str, message: &str) -> Self {
        Self::new(code, message, axum::http::StatusCode::CONFLICT)
    }
}
impl<E: Into<anyhow::Error>> From<E> for Failure {
    fn from(error: E) -> Self {
        eprintln!("Workshop storage/operation diagnostic: {:#}", error.into());
        Self::new("STORAGE_ERROR", "The host could not read or retain this operation. Inspect the local host log before continuing.", axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    }
}
impl axum::response::IntoResponse for Failure {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(json!({"error":{"code":self.code,"message":self.message,"recovery":"Refresh the workshop to inspect its current state."}}))).into_response()
    }
}
fn record_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("commands").join(format!("{id}.json"))
}
fn persist(root: &Path, record: &Record) -> Result<()> {
    files::replace(
        &record_path(root, record.request.request_id),
        &serde_json::to_vec_pretty(record)?,
    )?;
    Ok(())
}
pub fn observation(root: &Path, id: Uuid) -> Result<Value, Failure> {
    let path = record_path(root, id);
    if !path.exists() {
        return Err(Failure::new("UNKNOWN_OUTCOME","This host has no retained command with that identity. Inspect the mission before making another explicit decision.",axum::http::StatusCode::NOT_FOUND));
    }
    let record: Record = read(&path)?;
    Ok(record.observation)
}
pub fn active(root: &Path) -> Result<Value> {
    let mut active = None;
    for entry in std::fs::read_dir(root.join("commands"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let record: Record = read(&path)?;
            if ["accepted", "running", "unknown"]
                .contains(&record.observation["status"].as_str().unwrap_or(""))
            {
                ensure!(
                    active.is_none(),
                    "Multiple unresolved commands require reconciliation"
                );
                active = Some(record.observation);
            }
        }
    }
    Ok(active.unwrap_or(Value::Null))
}

/// Reopening observes retained completion; it never dispatches a mutation.
pub fn reconcile(root: &Path) -> Result<()> {
    let m = workspace::load(root)?;
    for entry in std::fs::read_dir(root.join("commands"))? {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let mut record: Record = read(&path)?;
        if !["accepted", "running", "unknown"]
            .contains(&record.observation["status"].as_str().unwrap_or(""))
        {
            continue;
        }
        let result_id = match &record.request.command {
            Command::Initialize { .. } => m
                .missions
                .iter()
                .find(|e| e.parent_id.is_none())
                .map(|e| e.id),
            Command::CreateRevision { .. } => m
                .missions
                .iter()
                .find(|e| {
                    e.parent_id == record.request.mission_id
                        && e.recipe.as_deref() == Some(workspace::RECIPE)
                })
                .map(|e| e.id),
            _ => record.request.mission_id,
        };
        let state = result_id.and_then(|id| {
            workspace::mission_path(root, &m, id)
                .ok()
                .and_then(|p| projection::mission(&p, workspace::entry(&m, id).ok()?).ok())
        });
        let done = match &record.request.command {
            Command::Initialize { .. } | Command::CreateRevision { .. } => result_id.is_some(),
            Command::Run | Command::Resume => state.as_ref().is_some_and(|s| {
                ["awaiting_review", "published"].contains(&s["phase"].as_str().unwrap_or(""))
            }),
            Command::Approve { candidate_digest } => state
                .as_ref()
                .is_some_and(|s| s["publication"]["candidate_digest"] == *candidate_digest),
            Command::PrepareAgent { .. } => false,
        };
        let running = state.as_ref().is_some_and(|s| {
            ["research", "implementation", "review"].contains(&s["phase"].as_str().unwrap_or(""))
        });
        record.observation["status"] = json!(if done {
            "succeeded"
        } else if running {
            "unknown"
        } else {
            "interrupted"
        });
        record.observation["message"] = json!(if done {
            "Completion established from retained work."
        } else if running {
            "A process still owns this mission. Wait for it to stop, then reopen."
        } else {
            "The previous host stopped before completion was established. Inspect the retained work before explicitly continuing."
        });
        if done {
            record.observation["result_mission_id"] = json!(result_id);
        }
        persist(root, &record)?;
    }
    Ok(())
}

fn preconditions(root: &Path, epoch: Uuid, request: &Request) -> Result<(), Failure> {
    let m = workspace::load(root)?;
    if request.schema_version != 1 {
        return Err(Failure::new(
            "UNSUPPORTED_VERSION",
            "This host requires workshop API v1.",
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        ));
    }
    if request.workspace_id != m.id || request.expected.host_epoch != epoch {
        return Err(Failure::conflict(
            "STALE_CONTEXT",
            "The host or workspace changed. Refresh before continuing.",
        ));
    }
    if let Some(id) = request.mission_id {
        workspace::entry(&m, id).map_err(|_| {
            Failure::new(
                "STALE_CONTEXT",
                "This mission is outside the workspace.",
                axum::http::StatusCode::NOT_FOUND,
            )
        })?;
    }
    match &request.command {
        Command::PrepareAgent { agent } => {
            if !projection::native_available() {
                return Err(Failure::new(
                    "UNQUALIFIED_SETUP",
                    "Native preparation is unavailable on this host.",
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                ));
            }
            let selected = match &m.setup.workers {
                super::setup::Workers::Native { roles } => {
                    [roles.research, roles.implementation, roles.review].contains(agent)
                }
                _ => false,
            };
            if !selected {
                return Err(Failure::conflict(
                    "INVALID_SETUP",
                    "Prepare only an agent selected in this workspace.",
                ));
            }
        }
        Command::Initialize { setup } => {
            setup
                .validate()
                .map_err(|_| Failure::conflict("INVALID_SETUP", "Unsupported setup."))?;
            if setup != &m.setup || request.mission_id.is_some() {
                return Err(Failure::conflict(
                    "STALE_CONTEXT",
                    "Initialization must match this workspace's setup draft.",
                ));
            }
            projection::ready(setup).map_err(|_| {
                Failure::new(
                    "DEPENDENCY_MISSING",
                    "Complete the prerequisites shown in setup, then try again.",
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                )
            })?;
        }
        _ => {
            let id = request.mission_id.ok_or_else(|| {
                Failure::conflict("STALE_CONTEXT", "Select an initialized mission.")
            })?;
            let path = workspace::mission_path(root, &m, id)?;
            let state = projection::mission(&path, workspace::entry(&m, id)?)?;
            if request.expected.mission_input_identity.as_deref()
                != state["input_identity"].as_str()
            {
                return Err(Failure::conflict(
                    "STALE_CONTEXT",
                    "Mission inputs changed. Refresh before continuing.",
                ));
            }
            let phase = state["phase"].as_str().unwrap_or("unknown");
            match &request.command {
                Command::Run | Command::Resume => {
                    let valid = if matches!(request.command, Command::Run) {
                        phase == "ready"
                    } else {
                        ["interrupted", "blocked"].contains(&phase)
                    };
                    if !valid {
                        return Err(Failure::conflict(
                            "STALE_CONTEXT",
                            "This action does not match the mission's current phase.",
                        ));
                    }
                    projection::ready(&m.setup).map_err(|_| {
                        Failure::new(
                            "DEPENDENCY_MISSING",
                            "Complete the prerequisites shown in setup, then try again.",
                            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )
                    })?;
                }
                Command::Approve { candidate_digest } => {
                    if phase != "awaiting_review"
                        || candidate_digest.len() != 64
                        || !candidate_digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || request.expected.candidate_digest.as_ref() != Some(candidate_digest)
                        || state["proposal"]["candidate_digest"] != *candidate_digest
                        || state["tests"]["candidate_digest"] != *candidate_digest
                        || state["tests"]["status"] != "passed"
                        || state["tests"]["complete"] != true
                    {
                        return Err(Failure::conflict("CANDIDATE_CHANGED","Approval requires the exact current candidate and its complete results. Review it again."));
                    }
                }
                Command::CreateRevision { recipe } => {
                    if recipe != workspace::RECIPE
                        || workspace::entry(&m, id)?.recipe.is_some()
                        || !["awaiting_review", "published"].contains(&phase)
                        || state["tests"]["status"] != "passed"
                        || state["tests"]["complete"] != true
                    {
                        return Err(Failure::conflict(
                            "INVALID_SETUP",
                            "Complete the baseline before adding this regression.",
                        ));
                    }
                    projection::ready(&m.setup).map_err(|_| {
                        Failure::new(
                            "DEPENDENCY_MISSING",
                            "Restore this mission's selected agents before creating its child.",
                            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                        )
                    })?;
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

pub async fn submit(
    root: PathBuf,
    epoch: Uuid,
    busy: Arc<Mutex<()>>,
    request: Request,
) -> Result<Value, Failure> {
    let m = workspace::load(&root)?;
    if request.workspace_id != m.id {
        return Err(Failure::conflict(
            "STALE_CONTEXT",
            "The request belongs to another workspace.",
        ));
    }
    let payload_digest = digest(&request)?;
    // Repeat lookup both before and after taking the gate. A racing identical
    // request can observe the accepted record without dispatching a second job.
    let previous = || -> Result<Option<Value>, Failure> {
        let path = record_path(&root, request.request_id);
        if !path.exists() {
            return Ok(None);
        }
        let record: Record = read(&path)?;
        if record.payload_digest != payload_digest {
            return Err(Failure::conflict(
                "REQUEST_ID_CONFLICT",
                "This request identity was already used for a different decision.",
            ));
        }
        Ok(Some(record.observation))
    };
    if let Some(observation) = previous()? {
        return Ok(observation);
    }
    let permit = busy.try_lock_owned().map_err(|_| {
        Failure::conflict(
            "HOST_BUSY",
            "Another operation is running. Inspect its status before continuing.",
        )
    })?;
    if let Some(observation) = previous()? {
        return Ok(observation);
    }
    if !active(&root)?.is_null() {
        return Err(Failure::conflict("UNKNOWN_OUTCOME","A retained operation is unresolved. Inspect it and reopen the host after its process stops."));
    }
    preconditions(&root, epoch, &request)?;
    if std::fs::read_dir(root.join("commands"))?.count() >= 2048 {
        return Err(Failure::conflict(
            "CAPACITY_EXHAUSTED",
            "This workspace's command history is full. Preserve it and create a new workspace.",
        ));
    }
    let observation = json!({"request_id":request.request_id,"workspace_id":request.workspace_id,"mission_id":request.mission_id,"type":request.command.name(),"status":"accepted","message":"Accepted by the local host.","result_mission_id":null});
    let mut record = Record {
        request,
        payload_digest,
        observation: observation.clone(),
    };
    crate::retain(&record_path(&root, record.request.request_id), &record)?;
    tokio::spawn(async move {
        record.observation["status"] = json!("running");
        let result = match persist(&root, &record) {
            Ok(()) => execute(&root, &record.request).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(id) => {
                record.observation["status"] = json!("succeeded");
                record.observation["message"] =
                    json!("Operation completed. Inspect the retained result.");
                record.observation["result_mission_id"] = json!(id);
            }
            Err(error) => {
                eprintln!(
                    "Workshop command {} failed: {error:#}",
                    record.request.request_id
                );
                record.observation["status"] = json!("failed");
                record.observation["message"] = json!("The operation stopped. Inspect the mission and the local host log before trying again.");
            }
        }
        if let Err(error) = persist(&root, &record) {
            eprintln!("Cannot retain command completion: {error:#}");
        }
        drop(permit);
    });
    Ok(observation)
}

async fn execute(root: &Path, request: &Request) -> Result<Option<Uuid>> {
    let root = root.to_owned();
    match &request.command {
        Command::Initialize { setup } => {
            let setup = setup.clone();
            return Ok(Some(
                tokio::task::spawn_blocking(move || workspace::initialize(&root, &setup)).await??,
            ));
        }
        Command::CreateRevision { .. } => {
            let parent = request.mission_id.context("Parent missing")?;
            return Ok(Some(
                tokio::task::spawn_blocking(move || workspace::create_revision(&root, parent))
                    .await??,
            ));
        }
        _ => {}
    }
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    match &request.command {
        Command::PrepareAgent { agent } => {
            command.args(["connect", agent.name()]);
        }
        _ => {
            let m = workspace::load(&root)?;
            let path =
                workspace::mission_path(&root, &m, request.mission_id.context("Mission missing")?)?;
            command.arg("--state").arg(&path);
            match &request.command {
                Command::Run | Command::Resume => {
                    command.arg("run");
                }
                Command::Approve { candidate_digest } => {
                    command.args(["approve", "--candidate", candidate_digest]);
                }
                _ => unreachable!(),
            }
        }
    }
    let log_path = root
        .join("commands")
        .join(format!("{}.log", request.request_id));
    files::create(&log_path, b"")?;
    let log = std::fs::OpenOptions::new().append(true).open(log_path)?;
    let status = command
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("Local operation exited with {status}");
    }
    if let Some(id) = request.mission_id {
        let m = workspace::load(&root)?;
        let state = projection::mission(
            &workspace::mission_path(&root, &m, id)?,
            workspace::entry(&m, id)?,
        )?;
        match &request.command {
            Command::Run | Command::Resume => ensure!(
                ["awaiting_review", "published"].contains(&state["phase"].as_str().unwrap_or("")),
                "Process exited without a retained proposal"
            ),
            Command::Approve { candidate_digest } => ensure!(
                state["publication"]["candidate_digest"] == *candidate_digest,
                "Publication is not retained"
            ),
            _ => {}
        }
    }
    Ok(request.mission_id)
}
