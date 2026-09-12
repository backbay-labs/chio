//! Loopback operator service. The browser observes durable mission state.
use crate::{journal, mission::Mission, read};
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Service {
    root: PathBuf,
    token: String,
    host: String,
    busy: Arc<Mutex<()>>,
}
#[derive(Deserialize)]
struct Cursor {
    #[serde(default)]
    after: u64,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Action {
    Initialize {
        model: bool,
        project: Option<PathBuf>,
    },
    Run,
    Resume,
    Approve {
        candidate: String,
    },
    Exercise,
}
struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":self.0.to_string()})),
        )
            .into_response()
    }
}

fn authorize(service: &Service, headers: &HeaderMap) -> Result<()> {
    anyhow::ensure!(
        headers.get("host").and_then(|h| h.to_str().ok()) == Some(service.host.as_str()),
        "Use the console's loopback address"
    );
    anyhow::ensure!(
        headers.get("authorization").and_then(|h| h.to_str().ok())
            == Some(format!("Bearer {}", service.token).as_str()),
        "Reconnect using the URL printed by Megastart"
    );
    if let Some(origin) = headers.get("origin") {
        anyhow::ensure!(
            origin.to_str()? == format!("http://{}", service.host),
            "Cross-origin console request refused"
        );
    }
    Ok(())
}

async fn snapshot(State(s): State<Service>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers)?;
    let root = s.root.clone();
    let data = tokio::task::spawn_blocking(move || {
        if root.join("mission.json").exists() {
            journal::snapshot(&root)
        } else {
            Ok(json!({"phase":"setup"}))
        }
    })
    .await??;
    Ok(Json(
        json!({"state":data,"busy":s.busy.try_lock().is_err(),"model_configured":crate::model::configured(),"sandbox_available":crate::sandbox::available()}),
    ))
}
async fn events(
    State(s): State<Service>,
    headers: HeaderMap,
    Query(cursor): Query<Cursor>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers)?;
    let entries = tokio::task::spawn_blocking(move || journal::events(&s.root)).await??;
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e["sequence"].as_u64().is_some_and(|n| n > cursor.after))
        .collect();
    Ok(Json(json!({"events":entries})))
}
async fn action(
    State(s): State<Service>,
    headers: HeaderMap,
    Json(action): Json<Action>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers)?;
    let permit = s
        .busy
        .clone()
        .try_lock_owned()
        .context("A mission operation is already running")?;
    if let Action::Initialize { model, project } = action {
        require(
            !model || (crate::model::configured() && crate::sandbox::available()),
            "A configured host model and supported sandbox are required",
        )?;
        let root = s.root.clone();
        tokio::task::spawn_blocking(move || initialize(&root, project.as_deref(), model)).await??;
        return Ok(Json(json!({"started":true})));
    }
    require(
        s.root.join("mission.json").exists(),
        "Configure your mission first",
    )?;
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command.arg("--state").arg(&s.root);
    match action {
        Action::Run | Action::Resume => {
            command.arg("run");
        }
        Action::Approve { candidate } => {
            require(
                candidate.len() == 64 && candidate.bytes().all(|b| b.is_ascii_hexdigit()),
                "Candidate digest is invalid",
            )?;
            command.args(["approve", "--candidate", &candidate]);
        }
        Action::Exercise => {
            command.arg("exercise");
        }
        Action::Initialize { .. } => unreachable!(),
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(s.root.join("operator.log"))?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()?;
    tokio::spawn(async move {
        let result = child.wait().await;
        if !result.is_ok_and(|status| status.success()) {
            let _ = journal::emit(
                &s.root,
                "mission.phase",
                "host",
                json!({"phase":"blocked","message":"Operation stopped. Open the retained outcomes and operator log before resuming."}),
            );
        }
        drop(permit);
    });
    Ok(Json(json!({"started":true})))
}

pub fn initialize(root: &Path, project: Option<&Path>, model: bool) -> Result<()> {
    let fixture;
    let project = if let Some(project) = project {
        project
    } else {
        fixture = std::env::temp_dir().join(format!("chio-megastart-{}", uuid::Uuid::new_v4()));
        chio_agent_os_shared::runtime::files::private_directory(&fixture)?;
        std::fs::write(fixture.join("lib.rs"), include_str!("../project/lib.rs"))?;
        std::fs::write(
            fixture.join("tests.rs"),
            include_str!("../project/tests.rs"),
        )?;
        &fixture
    };
    Mission::initialize(root, project, 6)?;
    let mut config: Value = read(&root.join("mission.json"))?;
    config["model"] = json!(model);
    chio_agent_os_shared::runtime::files::replace(
        &root.join("mission.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    journal::emit(
        root,
        "mission.phase",
        "host",
        json!({"phase":"ready","mode":if model{"model"}else{"reference"}}),
    )?;
    Ok(())
}

pub fn status(root: &Path, json_output: bool) -> Result<()> {
    let state = journal::snapshot(root)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }
    println!(
        "\nMegastart · {}\n",
        state["mission"].as_str().unwrap_or("Mission")
    );
    println!(
        "State        {}",
        state["phase"].as_str().unwrap_or("unknown")
    );
    println!(
        "Workers      {}",
        if state["config"]["model"] == true {
            "Model connected"
        } else {
            "Reproducible reference"
        }
    );
    for (name, prefix) in [
        ("Research", "research"),
        ("Implementation", "implementation"),
        ("Review", "review"),
    ] {
        let done = state["outcomes"]
            .as_array()
            .context("Outcomes missing")?
            .iter()
            .filter(|o| {
                o["allowed"] == true
                    && o["assignment"]["worker"]
                        .as_str()
                        .is_some_and(|w| w.starts_with(prefix))
            })
            .count();
        println!("{name:16}{done}/2 operations complete");
    }
    if !state["capacity"].is_null() {
        println!(
            "Allowance    {} / {} remaining",
            state["capacity"]["remaining"], state["capacity"]["total"]
        );
    }
    println!(
        "Publication  {}",
        if state["published"] == true {
            "Published locally"
        } else {
            "Not authorized"
        }
    );
    println!("\nNext: megastart review, or megastart to open the console.\n");
    Ok(())
}

pub async fn review(root: &Path) -> Result<()> {
    use std::io::{IsTerminal, Write};
    let state = journal::snapshot(root)?;
    let proposal = state["proposal"]
        .as_object()
        .context("No candidate is ready for review")?;
    println!(
        "\nOriginal source\n{}\n\nReviewed candidate\n{}",
        state["original"].as_str().unwrap_or(""),
        state["candidate"].as_str().unwrap_or("")
    );
    for outcome in state["outcomes"].as_array().context("Outcomes missing")? {
        if outcome["assignment"]["worker"]
            .as_str()
            .is_some_and(|w| w.starts_with("review"))
        {
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome["output"]["result"])?
            );
        }
    }
    println!("Destination: {}", root.join("release").display());
    anyhow::ensure!(std::io::stdin().is_terminal(),"Review interactively to approve, or use approve --candidate with the exact inspected digest");
    print!("Publish this exact candidate locally? Type publish: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim() == "publish" {
        Mission::open(root)?
            .publish(
                proposal["candidate_sha256"]
                    .as_str()
                    .context("Candidate digest missing")?,
                true,
            )
            .await?;
    } else {
        println!("No publication authorized.");
    }
    Ok(())
}

pub async fn serve(root: PathBuf, port: u16, open: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let host = listener.local_addr()?.to_string();
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let url = format!("http://{host}/#{token}");
    let service = Service {
        root,
        token,
        host,
        busy: Arc::new(Mutex::new(())),
    };
    println!("\nMegastart is ready.\nOpen your mission console:\n{url}\n\nKeep this host running. Closing the browser does not stop work.\n");
    if open {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener)
            .arg(&url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../ui/index.html")) }),
        )
        .route("/api/state", get(snapshot))
        .route("/api/events", get(events))
        .route("/api/action", post(action))
        .layer(DefaultBodyLimit::max(16_384))
        .with_state(service);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn require(condition: bool, message: &str) -> Result<()> {
    anyhow::ensure!(condition, "{message}");
    Ok(())
}
