use super::{
    commands::{self, Failure, Request},
    projection, workspace,
};
use crate::operator::Service;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    mission: Option<Uuid>,
    #[serde(default)]
    after: u64,
}
fn authenticate(s: &Service, headers: &HeaderMap) -> Result<PathBuf, Failure> {
    if headers.get("host").and_then(|h| h.to_str().ok()) != Some(&s.host) {
        return Err(Failure::new(
            "ORIGIN_REFUSED",
            "Use the printed loopback address.",
            StatusCode::FORBIDDEN,
        ));
    }
    if headers.get("authorization").and_then(|h| h.to_str().ok())
        != Some(format!("Bearer {}", s.token).as_str())
    {
        return Err(Failure::new(
            "AUTH_REQUIRED",
            "Reopen the local URL printed by this host.",
            StatusCode::UNAUTHORIZED,
        ));
    }
    if let Some(origin) = headers.get("origin") {
        if origin.to_str().ok() != Some(format!("http://{}", s.host).as_str()) {
            return Err(Failure::new(
                "ORIGIN_REFUSED",
                "Cross-origin workshop access was refused.",
                StatusCode::FORBIDDEN,
            ));
        }
    }
    s.workspace.clone().ok_or_else(|| {
        Failure::new(
            "UNSUPPORTED_VERSION",
            "Open this operator with the workshop command.",
            StatusCode::NOT_FOUND,
        )
    })
}
fn selected(root: &std::path::Path, id: Option<Uuid>) -> Result<(), Failure> {
    if let Some(id) = id {
        let manifest = workspace::load(root)?;
        if !manifest.missions.iter().any(|mission| mission.id == id) {
            return Err(Failure::new(
                "MISSION_UNAVAILABLE",
                "This mission is outside the workshop. Select a retained mission.",
                StatusCode::NOT_FOUND,
            ));
        }
    }
    Ok(())
}
async fn state(
    State(s): State<Service>,
    headers: HeaderMap,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, Failure> {
    let root = authenticate(&s, &headers)?;
    selected(&root, q.mission)?;
    let state = tokio::task::spawn_blocking(move || {
        projection::state(&root, s.epoch, q.mission, commands::active(&root)?)
    })
    .await??;
    Ok(Json(state))
}
async fn events(
    State(s): State<Service>,
    headers: HeaderMap,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, Failure> {
    let root = authenticate(&s, &headers)?;
    selected(&root, q.mission)?;
    let id = q.mission.ok_or_else(|| {
        Failure::new(
            "STALE_CONTEXT",
            "Select a mission for its event stream.",
            StatusCode::BAD_REQUEST,
        )
    })?;
    let result=tokio::task::spawn_blocking(move|| -> Result<Value,Failure> {
        let m=workspace::load(&root)?;
        let path=workspace::mission_path(&root,&m,id)?;
        let all=crate::journal::events(&path)?;
        let mut bytes=0; let mut entries=vec![]; let mut more=false;
        let maximum=all.last().and_then(|e|e["sequence"].as_u64()).unwrap_or(0);
        if q.after > maximum { return Err(Failure::conflict("EVENT_GAP", "The event cursor is outside this journal. Refresh the mission snapshot.")); }
        for (count, event) in all.into_iter().filter(|e|e["sequence"].as_u64().is_some_and(|n|n>q.after)).enumerate() {
            let size=serde_json::to_vec(&event)?.len();
            if size > 1_000_000 { return Err(Failure::new("CAPACITY_EXHAUSTED", "A retained event exceeds the transport limit. Inspect the host log.", StatusCode::PAYLOAD_TOO_LARGE)); }
            if count==128 || bytes+size>1_000_000 {more=true;break;}
            bytes+=size;entries.push(event);
        }
        let last=entries.last().and_then(|e|e["sequence"].as_u64()).unwrap_or(q.after);
        Ok(json!({"schema_version":1,"host_epoch":s.epoch,"mission_id":id,"events":entries,"has_more":more,"last_sequence":last}))
    }).await??;
    Ok(Json(result))
}
async fn artifact(
    State(s): State<Service>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, Failure> {
    let root = authenticate(&s, &headers)?;
    selected(&root, q.mission)?;
    if ![
        "original",
        "harness",
        "candidate",
        "test-output",
        "compiler-output",
        "review",
        "published",
    ]
    .contains(&id.as_str())
    {
        return Err(Failure::new(
            "ARTIFACT_UNAVAILABLE",
            "Unknown artifact.",
            StatusCode::NOT_FOUND,
        ));
    }
    let mission = q.mission.ok_or_else(|| {
        Failure::new(
            "STALE_CONTEXT",
            "Select a mission for its artifacts.",
            StatusCode::BAD_REQUEST,
        )
    })?;
    let content=tokio::task::spawn_blocking(move|| -> anyhow::Result<Value> {
        let m=workspace::load(&root)?;
        projection::artifact_content(&workspace::mission_path(&root,&m,mission)?,workspace::entry(&m,mission)?,&id)
    }).await?.map_err(|_|Failure::new("ARTIFACT_UNAVAILABLE","This artifact is unavailable or its retained identity changed. Refresh and inspect the host log.",StatusCode::NOT_FOUND))?;
    Ok(Json(content))
}
async fn command(
    State(s): State<Service>,
    headers: HeaderMap,
    payload: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, Failure> {
    let root = authenticate(&s, &headers)?;
    let Json(request) = payload.map_err(|_| {
        Failure::new(
            "INVALID_SETUP",
            "The command does not match the supported request schema.",
            StatusCode::BAD_REQUEST,
        )
    })?;
    let observation = commands::submit(root, s.epoch, s.busy, request).await?;
    Ok((StatusCode::ACCEPTED, Json(observation)))
}
async fn observation(
    State(s): State<Service>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Failure> {
    let root = authenticate(&s, &headers)?;
    Ok(Json(commands::observation(&root, id)?))
}
pub(crate) fn routes() -> Router<Service> {
    Router::new()
        .route("/api/workshop/v1/state", get(state))
        .route("/api/workshop/v1/events", get(events))
        .route("/api/workshop/v1/artifacts/{id}", get(artifact))
        .route("/api/workshop/v1/commands", post(command))
        .route("/api/workshop/v1/commands/{id}", get(observation))
}

pub(crate) async fn html() -> impl IntoResponse {
    ([("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")], axum::response::Html(super::assets::HTML))
}
pub(crate) async fn asset(Path(name): Path<String>) -> axum::response::Response {
    match super::assets::asset(&name) {
        Some((mime, bytes)) => (
            [
                ("content-type", mime),
                ("cache-control", "public, max-age=31536000, immutable"),
            ],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
