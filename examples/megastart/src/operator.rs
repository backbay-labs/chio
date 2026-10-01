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
pub(crate) struct Service {
    pub(crate) root: PathBuf,
    pub(crate) token: String,
    pub(crate) host: String,
    pub(crate) busy: Arc<Mutex<()>>,
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) epoch: uuid::Uuid,
}
#[derive(Deserialize)]
struct Cursor {
    #[serde(default)]
    after: u64,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    #[cfg(feature = "native-agents")]
    Connect {
        agent: crate::agents::launcher::Agent,
    },
    Initialize {
        #[serde(default)]
        model: bool,
        #[cfg(feature = "native-agents")]
        native: Option<crate::agents::connections::Selection>,
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
    let root = legacy_root(&s)?;
    let data = tokio::task::spawn_blocking(move || {
        if root.join("mission.json").exists() {
            journal::snapshot(&root)
        } else {
            Ok(json!({"phase":"setup"}))
        }
    })
    .await??;
    #[cfg(feature = "native-agents")]
    let connections = crate::agents::connections::snapshot()?;
    #[cfg(not(feature = "native-agents"))]
    let connections = json!({"available":false,"agents":[]});
    Ok(Json(
        json!({"protocol_version":1,"state":data,"busy":s.busy.try_lock().is_err(),"model_configured":crate::model::configured(),"sandbox_available":crate::sandbox::available(),"connections":connections}),
    ))
}
async fn events(
    State(s): State<Service>,
    headers: HeaderMap,
    Query(cursor): Query<Cursor>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers)?;
    let root = legacy_root(&s)?;
    let entries = tokio::task::spawn_blocking(move || {
        if root.join("mission.json").exists() {
            journal::events(&root)
        } else {
            Ok(Vec::new())
        }
    })
    .await??;
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e["sequence"].as_u64().is_some_and(|n| n > cursor.after))
        .collect();
    Ok(Json(json!({"protocol_version":1,"events":entries})))
}
async fn action(
    State(mut s): State<Service>,
    headers: HeaderMap,
    Json(action): Json<Action>,
) -> Result<Json<Value>, ApiError> {
    authorize(&s, &headers)?;
    if s.workspace.is_some() && matches!(action, Action::Initialize { .. } | Action::Exercise) {
        return Err(anyhow::anyhow!(
            "Use the workspace controls to initialize or revise this mission"
        )
        .into());
    }
    s.root = legacy_root(&s)?;
    let permit = s
        .busy
        .clone()
        .try_lock_owned()
        .context("A mission operation is already running")?;
    #[cfg(feature = "native-agents")]
    if let Action::Connect { agent } = action {
        let job = tokio::spawn(async move {
            let result = crate::agents::connections::prepare(agent).await;
            drop(permit);
            result
        });
        job.await??;
        return Ok(Json(json!({"prepared":true})));
    }
    if let Action::Initialize {
        model,
        project,
        #[cfg(feature = "native-agents")]
        native,
    } = action
    {
        #[cfg(feature = "native-agents")]
        if let Some(selection) = native {
            require(
                !model && crate::sandbox::available(),
                "Native agents require the supported host sandbox",
            )?;
            let root = s.root.clone();
            tokio::task::spawn_blocking(move || {
                initialize_native(&root, project.as_deref(), selection)
            })
            .await??;
            return Ok(Json(json!({"started":true})));
        }
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
    let exercise = matches!(&action, Action::Exercise);
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
        #[cfg(feature = "native-agents")]
        Action::Connect { .. } => unreachable!(),
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
                if exercise {
                    "exercise.failed"
                } else {
                    "mission.phase"
                },
                "host",
                json!({"phase":"blocked","message":"Operation stopped. Open the retained outcomes and operator log before resuming."}),
            );
        }
        drop(permit);
    });
    Ok(Json(json!({"started":true})))
}

fn initialize_project(root: &Path, project: Option<&Path>, allowance: u32) -> Result<()> {
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
    Mission::initialize(root, project, allowance)
}

pub fn initialize(root: &Path, project: Option<&Path>, model: bool) -> Result<()> {
    initialize_project(root, project, 6)?;
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

#[cfg(feature = "native-agents")]
pub(crate) fn initialize_native(
    root: &Path,
    project: Option<&Path>,
    selection: crate::agents::connections::Selection,
) -> Result<()> {
    let native = crate::agents::connections::configuration(selection)?;
    initialize_project(root, project, 64)?;
    let path = root.join("mission.json");
    let mut config: crate::mission::Config = read(&path)?;
    config.native = Some(native);
    chio_agent_os_shared::runtime::files::replace(&path, &serde_json::to_vec_pretty(&config)?)?;
    journal::emit(
        root,
        "mission.phase",
        "host",
        json!({"phase":"ready","mode":"native"}),
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
        if state["agents"].is_object() {
            "Native agent sessions"
        } else if state["config"]["model"] == true {
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
        let unit = if state["agents"].is_object() {
            "assignments"
        } else {
            "operations"
        };
        println!("{name:16}{done}/2 {unit} complete");
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
    serve_connected(root, port, open, None).await
}

/// A descriptor is an operator credential, never a worker configuration.
/// Its lifetime lock prevents two hosts from replacing one client's identity.
pub async fn serve_connected(
    root: PathBuf,
    port: u16,
    open: bool,
    connection_file: Option<PathBuf>,
) -> Result<()> {
    serve_host(root, port, open, connection_file, None).await
}

pub async fn serve_workspace(root: PathBuf, port: u16, open: bool) -> Result<()> {
    let manifest = crate::workshop::workspace::load(&root)?;
    let descriptor = root.join("connections/console.json");
    match crate::workshop::workspace::lock(&root.join("connections"), "console.lock") {
        Ok(probe) => drop(probe),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            // An existing host owns the descriptor. Verify its loopback session,
            // workspace identity and embedded UI before reusing the browser URL.
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = std::fs::symlink_metadata(&descriptor)?;
            anyhow::ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.permissions().mode() & 0o077 == 0
                    && metadata.uid() == unsafe { libc::geteuid() },
                "Retained connection must be a private file owned by this user"
            );
            let retained: Value = read(&descriptor)?;
            anyhow::ensure!(
                retained["protocol_version"] == 1
                    && retained["mission_root"]
                        .as_str()
                        .map(PathBuf::from)
                        .is_some_and(|path| path == root),
                "Retained connection belongs to a different workspace"
            );
            let pid = retained["pid"]
                .as_u64()
                .and_then(|pid| i32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .context("Retained host PID missing")?;
            anyhow::ensure!(
                unsafe { libc::kill(pid, 0) } == 0,
                "Retained workshop host is no longer running"
            );
            let endpoint = reqwest::Url::parse(
                retained["endpoint"]
                    .as_str()
                    .context("Retained endpoint missing")?,
            )?;
            anyhow::ensure!(
                endpoint.scheme() == "http"
                    && endpoint.host_str() == Some("127.0.0.1")
                    && endpoint.port().is_some()
                    && endpoint.username().is_empty()
                    && endpoint.password().is_none()
                    && endpoint.path() == "/"
                    && endpoint.query().is_none()
                    && endpoint.fragment().is_none(),
                "Retained connection is not a loopback workshop"
            );
            let token = retained["token"]
                .as_str()
                .context("Retained session missing")?;
            anyhow::ensure!(
                token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
                "Retained session is invalid"
            );
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build()?;
            let mut response = client
                .get(endpoint.join("api/workshop/v1/state")?)
                .bearer_auth(token)
                .send()
                .await?
                .error_for_status()?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len() + chunk.len() <= 2_000_000,
                    "Retained host response exceeded the supported limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let observed: Value = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(observed["schema_version"] == 1 && observed["workspace"]["id"] == manifest.id.to_string() && observed["host"]["ui_build_id"] == crate::workshop::assets::BUILD_ID && observed["host"]["operator_version"] == env!("CARGO_PKG_VERSION"), "Another workshop version is running. Stop its host terminal, then reopen this workspace.");
            let url = format!("{}workshop#{token}", endpoint);
            println!("\nYour existing Chio workshop is ready.\n{url}\n");
            if open {
                open_browser(&url);
            }
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    serve_host(root.clone(), port, open, Some(descriptor), Some(root)).await
}

async fn serve_host(
    root: PathBuf,
    port: u16,
    open: bool,
    connection_file: Option<PathBuf>,
    workspace: Option<PathBuf>,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let root = std::path::absolute(root)?;
    let _connection_lock = if let Some(path) = &connection_file {
        use std::os::unix::fs::PermissionsExt;
        let parent = path
            .parent()
            .context("Connection descriptor needs a parent directory")?;
        let metadata = std::fs::symlink_metadata(parent)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "Connection directory must be private (mode 0700)"
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.with_extension("lock"))?;
        fs2::FileExt::try_lock_exclusive(&file)
            .context("This operator connection already has a host")?;
        Some(file)
    } else {
        None
    };
    if let Some(root) = &workspace {
        crate::workshop::commands::reconcile(root)?;
    }
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let host = listener.local_addr()?.to_string();
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let url = format!(
        "http://{host}/{}#{token}",
        if workspace.is_some() { "workshop" } else { "" }
    );
    if let Some(path) = &connection_file {
        // The caller supplies a private directory outside the not-yet-created mission.
        let bytes = serde_json::to_vec(
            &json!({"protocol_version":1,"endpoint":format!("http://{host}"),"token":token,"mission_root":root,"pid":std::process::id()}),
        )?;
        chio_agent_os_shared::runtime::files::replace(path, &bytes)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let service = Service {
        root,
        token,
        host,
        busy: Arc::new(Mutex::new(())),
        workspace: workspace.clone(),
        epoch: uuid::Uuid::new_v4(),
    };
    if workspace.is_some() {
        println!("\nChio workshop is ready.\n{url}\n\nKeep this terminal running. Closing the browser does not stop work.\nWorkspace: {}\n", root_display(&service.root));
    } else if connection_file.is_none() {
        println!("\nMegastart is ready.\nOpen your mission console:\n{url}\n\nKeep this host running. Closing the browser does not stop work.\n");
    } else {
        println!("Megastart operator ready. Private connection descriptor written.");
    }
    if open {
        open_browser(&url);
    }
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../ui/index.html")) }),
        )
        .route(
            "/brands/{name}",
            get(
                |axum::extract::Path(name): axum::extract::Path<String>| async move {
                    let (content_type, bytes): (&str, &'static [u8]) = match name.as_str() {
                        "claude.svg" => {
                            ("image/svg+xml", include_bytes!("../ui/brands/claude.svg"))
                        }
                        "codex.svg" => ("image/svg+xml", include_bytes!("../ui/brands/codex.svg")),
                        "hermes.svg" => {
                            ("image/svg+xml", include_bytes!("../ui/brands/hermes.svg"))
                        }
                        "pi.svg" => ("image/svg+xml", include_bytes!("../ui/brands/pi.svg")),
                        "herdr.png" => ("image/png", include_bytes!("../ui/brands/herdr.png")),
                        _ => return StatusCode::NOT_FOUND.into_response(),
                    };
                    ([(axum::http::header::CONTENT_TYPE, content_type)], bytes).into_response()
                },
            ),
        )
        .merge(crate::workshop::http::routes())
        .route("/workshop/assets/{name}", get(crate::workshop::http::asset))
        .route("/workshop", get(crate::workshop::http::html))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/state", get(snapshot))
        .route("/api/events", get(events))
        .route("/api/action", post(action))
        .layer(DefaultBodyLimit::max(16_384))
        .layer(axum::middleware::map_response(secure_headers))
        .with_state(service);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn root_display(root: &Path) -> String {
    root.display().to_string()
}
fn legacy_root(service: &Service) -> Result<PathBuf> {
    if let Some(root) = &service.workspace {
        let manifest = crate::workshop::workspace::load(root)?;
        if let Some(id) = manifest.selected_mission_id {
            return crate::workshop::workspace::mission_path(root, &manifest, id);
        }
        return Ok(root.join("missions/not-initialized"));
    }
    Ok(service.root.clone())
}

fn require(condition: bool, message: &str) -> Result<()> {
    anyhow::ensure!(condition, "{message}");
    Ok(())
}

async fn secure_headers(mut response: axum::response::Response) -> axum::response::Response {
    use axum::http::HeaderValue;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    ] { if !response.headers().contains_key(name) { response.headers_mut().insert(name, HeaderValue::from_static(value)); } }
    response
}
