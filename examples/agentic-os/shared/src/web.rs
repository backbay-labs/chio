use crate::{Application, Run};
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};

#[derive(Clone)]
struct Service {
    app: Arc<dyn Application>,
    root: PathBuf,
    runs: Arc<Mutex<HashMap<String, Run>>>,
    capacity: Arc<Semaphore>,
    tasks: Arc<Mutex<HashMap<String, tokio::task::AbortHandle>>>,
}

async fn start(
    State(state): State<Service>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError("Missing host".into()))?;
    let allowed = ["127.0.0.1:", "localhost:", "[::1]:"].iter().any(|prefix| {
        host.strip_prefix(prefix)
            .is_some_and(|port| port.parse::<u16>().is_ok())
    });
    if !allowed {
        return Err(ApiError("Use the application's localhost address".into()));
    }
    // Browser writes must originate from the same local application origin.
    if let Some(origin) = headers.get("origin") {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError("Missing host".into()))?;
        if origin.to_str().ok() != Some(format!("http://{host}").as_str()) {
            return Err(ApiError(
                "Open this application in its own browser tab".into(),
            ));
        }
    }
    let permit = state.capacity.clone().try_acquire_owned().map_err(|_| {
        ApiError("Two runs are active; wait for a result before starting another".into())
    })?;
    let run = Run::create(&state.root, state.app.name(), &input)?;
    let id = run.id()?;
    state.runs.lock().await.insert(id.clone(), run.clone());
    tokio::spawn(async move {
        let execution_run = run.clone();
        let app = state.app.clone();
        let mut task = tokio::spawn(async move { app.execute(input, execution_run).await });
        if let Ok(id) = run.id() {
            state.tasks.lock().await.insert(id, task.abort_handle());
        }
        let result = match tokio::time::timeout(std::time::Duration::from_secs(600), &mut task)
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow::anyhow!(
                "Application worker stopped unexpectedly; inspect retained effects before retrying"
            )),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(anyhow::anyhow!("Run reached its ten-minute limit; retained effects require reconciliation before retrying"))
            }
        };
        if let Err(error) = run.finish(&result) {
            eprintln!("Could not retain run result: {error}");
        }
        if let Ok(id) = run.id() {
            state.runs.lock().await.remove(&id);
            state.tasks.lock().await.remove(&id);
        }
        drop(permit);
    });
    Ok(Json(json!({"id":id})))
}

async fn cancel(
    State(state): State<Service>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError("Missing host".into()))?;
    if headers.get("origin").and_then(|v| v.to_str().ok())
        != Some(format!("http://{host}").as_str())
        || !["127.0.0.1:", "localhost:", "[::1]:"]
            .iter()
            .any(|prefix| host.starts_with(prefix))
    {
        return Err(ApiError(
            "Stop a run from its local application page".into(),
        ));
    }
    let tasks = state.tasks.lock().await;
    let task = tasks.get(&id).ok_or_else(|| {
        ApiError("Run has already ended or has not started; reconnect to inspect it".into())
    })?;
    task.abort();
    Ok(Json(json!({"stop_requested":true})))
}

async fn read(
    State(state): State<Service>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if let Some(run) = state.runs.lock().await.get(&id) {
        return Ok(Json(run.snapshot()?));
    }
    Ok(Json(Run::capture(&state.root, &id)?))
}

async fn page(State(state): State<Service>) -> Html<String> {
    let config = json!({
        "title":state.app.title(),
        "description":state.app.description(),
        "sample":state.app.sample(),
        "id":state.app.name()
    });
    Html(include_str!("studio.html").replace(
        "__APPLICATION__",
        &config.to_string().replace('<', "\\u003c"),
    ))
}

struct ApiError(String);
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(e.to_string())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(json!({"error":self.0}))).into_response()
    }
}

/// No-argument startup opens the project's own loopback interface. The capture
/// path runs exactly the same Application implementation used by that server.
pub async fn main(app: impl Application) -> Result<()> {
    let app: Arc<dyn Application> = Arc::new(app);
    let root = PathBuf::from(std::env::var("CHIO_RUNS").unwrap_or_else(|_| "runs".into()));
    crate::host::private_directory(&root)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--describe") {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"id":app.name(),"title":app.title(),"description":app.description(),"sample":app.sample()})
            )?
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--capture") {
        let id = args.get(1).context("Provide the run ID to read")?;
        println!("{}", serde_json::to_string(&Run::capture(&root, id)?)?);
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--run") {
        let path = args.get(1).context("Use --run input.json")?;
        let input = serde_json::from_slice(&std::fs::read(path)?)?;
        let run = Run::create(&root, app.name(), &input)?;
        let result = app.execute(input, run.clone()).await;
        run.finish(&result)?;
        println!("{}", serde_json::to_string_pretty(&run.snapshot()?)?);
        result?;
        return Ok(());
    }
    anyhow::ensure!(
        args.is_empty(),
        "Run without arguments for the interface, or use --run input.json"
    );
    let state = Service {
        app,
        root,
        runs: Arc::new(Mutex::new(HashMap::new())),
        capacity: Arc::new(Semaphore::new(2)),
        tasks: Arc::new(Mutex::new(HashMap::new())),
    };
    let router = Router::new()
        .route("/", get(page))
        .route("/api/runs", post(start))
        .route("/api/runs/{id}", get(read).delete(cancel))
        .layer(DefaultBodyLimit::max(300_000))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4317")
        .await
        .context("Port 4317 is occupied; stop the previous application and retry")?;
    println!("Open http://127.0.0.1:4317");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
