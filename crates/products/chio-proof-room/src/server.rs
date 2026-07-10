use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path as AxumPath, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use tower_http::services::{ServeDir, ServeFile};

use super::{
    build_proof_room_fixture_catalog, parse_embedded_evidence_graph, proof_room_fixture_asset,
    proof_room_fixture_asset_with_root, proof_room_fixture_failure_code,
    proof_room_fixture_report_status, verify_proof_room_quickstart, ProofRoomError,
    ProofRoomFixtureCatalog,
};

#[derive(Debug, Clone)]
pub struct ProofRoomServeConfig {
    pub bundle: PathBuf,
    pub ui_dir: PathBuf,
    pub listen: SocketAddr,
    pub doctor_report: Option<PathBuf>,
    pub fixture_root: Option<PathBuf>,
}

#[derive(Clone)]
struct ProofRoomServeState {
    bundle: PathBuf,
    ui_dir: Option<PathBuf>,
    allowed_bundle_paths: BTreeSet<String>,
    fixture_root: Option<PathBuf>,
}

type UploadError = (StatusCode, String);
type UploadResult<T> = Result<T, UploadError>;
type UploadPart = (String, Vec<u8>);
static UPLOAD_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

pub async fn serve_proof_room(config: ProofRoomServeConfig) -> Result<(), ProofRoomError> {
    verify_proof_room_ui_dir(&config.ui_dir)?;
    verify_proof_room_quickstart(&config.bundle, config.doctor_report.as_deref())?;

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|source| ProofRoomError::Io {
            context: "proof-room.listen",
            source,
        })?;
    let router =
        proof_room_router_with_fixture_root(config.bundle, config.ui_dir, config.fixture_root)?;
    axum::serve(listener, router)
        .await
        .map_err(ProofRoomError::Serve)
}

fn verify_proof_room_ui_dir(ui_dir: &Path) -> Result<(), ProofRoomError> {
    let index = ui_dir.join("index.html");
    let metadata = fs::metadata(&index).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ProofRoomError::Validation(format!("proof-room.ui.index-missing: {}", index.display()))
        } else {
            ProofRoomError::Io {
                context: "proof-room.ui.index",
                source,
            }
        }
    })?;
    if !metadata.is_file() {
        return Err(ProofRoomError::Validation(format!(
            "proof-room.ui.index-missing: {}",
            index.display()
        )));
    }
    Ok(())
}

pub fn proof_room_router(bundle: PathBuf, ui_dir: PathBuf) -> Result<Router, ProofRoomError> {
    proof_room_router_with_fixture_root(bundle, ui_dir, None)
}

pub fn proof_room_router_with_fixture_root(
    bundle: PathBuf,
    ui_dir: PathBuf,
    fixture_root: Option<PathBuf>,
) -> Result<Router, ProofRoomError> {
    proof_room_router_with_optional_ui_root(bundle, Some(ui_dir), fixture_root)
}

pub fn proof_room_router_with_optional_ui_root(
    bundle: PathBuf,
    ui_dir: Option<PathBuf>,
    fixture_root: Option<PathBuf>,
) -> Result<Router, ProofRoomError> {
    let allowed_bundle_paths = if bundle.join("manifest.json").exists() {
        proof_room_served_bundle_paths(&bundle).map_err(ProofRoomError::Validation)?
    } else {
        BTreeSet::new()
    };
    let state = ProofRoomServeState {
        bundle,
        ui_dir: ui_dir.clone(),
        allowed_bundle_paths,
        fixture_root,
    };
    let router = Router::new()
        .route("/", get(proof_room_view_redirect))
        .route(
            "/proof-room/upload/verify",
            post(proof_room_upload_verify).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route(
            "/proof-room-fixture-catalog.json",
            get(proof_room_fixture_catalog_response),
        )
        .route(
            "/proof-room-trusted-bundle-signers.json",
            get(proof_room_trusted_bundle_signers_response),
        )
        .route(
            "/proof-room-fixtures/{fixture_id}/{*asset_path}",
            get(proof_room_fixture_asset_with_state_response),
        )
        .route("/manifest.json", get(proof_room_manifest_asset))
        .route("/artifacts/{*asset_path}", get(proof_room_artifacts_asset))
        .route("/negatives/{*asset_path}", get(proof_room_negatives_asset))
        .route("/roots/{*asset_path}", get(proof_room_roots_asset))
        .route("/ui/{*asset_path}", get(proof_room_bundle_ui_asset))
        .route("/verifier/{*asset_path}", get(proof_room_verifier_asset))
        .fallback(get(proof_room_fallback_asset))
        .with_state(state);

    if let Some(ui_dir) = ui_dir {
        Ok(router
            .nest_service("/assets", ServeDir::new(ui_dir.join("assets")))
            .route_service("/proof-room", ServeFile::new(ui_dir.join("index.html"))))
    } else {
        Ok(router)
    }
}

async fn proof_room_view_redirect() -> Redirect {
    Redirect::temporary("/proof-room?view=proof-room")
}

async fn proof_room_upload_verify(headers: HeaderMap, body: Bytes) -> Response {
    match verify_uploaded_proof_room_bundle(&headers, &body) {
        Ok(bundle_id) => proof_room_upload_verification_response(
            StatusCode::OK,
            "verified",
            None,
            Some(bundle_id),
        ),
        Err((status, error)) => {
            proof_room_upload_verification_response(status, "failed", Some(error), None)
        }
    }
}

fn verify_uploaded_proof_room_bundle(headers: &HeaderMap, body: &[u8]) -> UploadResult<String> {
    let upload = UploadedProofRoomBundle::create().map_err(upload_io_error)?;
    write_uploaded_proof_room_bundle(headers, body, upload.path())?;
    let manifest_path = upload.path().join("manifest.json");
    super::verify_proof_room_bundle(&manifest_path)
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))?;
    uploaded_bundle_id(&manifest_path).map_err(upload_io_error)
}

fn write_uploaded_proof_room_bundle(
    headers: &HeaderMap,
    body: &[u8],
    root: &Path,
) -> UploadResult<()> {
    let mut file_count = 0usize;
    let mut paths = BTreeSet::new();
    let boundary = multipart_boundary(headers)?;
    for (relative_path, bytes) in parse_uploaded_multipart(body, &boundary)? {
        super::validate_bundle_relative_path(&relative_path)
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        if !paths.insert(relative_path.clone()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.upload.duplicate-path: {relative_path}"),
            ));
        }
        let destination = root.join(&relative_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(upload_io_error)?;
        }
        fs::write(destination, &bytes).map_err(upload_io_error)?;
        file_count += 1;
    }
    if file_count == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof-room.upload.empty".to_string(),
        ));
    }
    Ok(())
}

fn multipart_boundary(headers: &HeaderMap) -> UploadResult<String> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "proof-room.upload.content-type-missing".to_string(),
            )
        })?;
    for segment in content_type.split(';') {
        let segment = segment.trim();
        if let Some(value) = segment.strip_prefix("boundary=") {
            let boundary = value.trim_matches('"');
            if boundary.is_empty()
                || boundary.len() > 200
                || boundary.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "proof-room.upload.boundary-invalid".to_string(),
                ));
            }
            return Ok(boundary.to_string());
        }
    }
    Err((
        StatusCode::BAD_REQUEST,
        "proof-room.upload.boundary-missing".to_string(),
    ))
}

fn parse_uploaded_multipart(body: &[u8], boundary: &str) -> UploadResult<Vec<UploadPart>> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    let part_delimiter = format!("\r\n--{boundary}");
    let part_delimiter = part_delimiter.as_bytes();
    if !body.starts_with(delimiter) {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof-room.upload.multipart-boundary-missing".to_string(),
        ));
    }

    let mut parts = Vec::new();
    let mut cursor = delimiter.len();
    loop {
        if body.get(cursor..cursor + 2) == Some(b"--") {
            break;
        }
        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err((
                StatusCode::BAD_REQUEST,
                "proof-room.upload.multipart-part-malformed".to_string(),
            ));
        }
        cursor += 2;
        let header_end = find_bytes(&body[cursor..], b"\r\n\r\n")
            .map(|offset| cursor + offset)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "proof-room.upload.multipart-headers-missing".to_string(),
                )
            })?;
        let headers = std::str::from_utf8(&body[cursor..header_end]).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "proof-room.upload.multipart-headers-invalid".to_string(),
            )
        })?;
        let path = multipart_part_path(headers)?;
        let content_start = header_end + 4;
        let next_delimiter = find_bytes(&body[content_start..], part_delimiter)
            .map(|offset| content_start + offset)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "proof-room.upload.multipart-delimiter-missing".to_string(),
                )
            })?;
        parts.push((path, body[content_start..next_delimiter].to_vec()));
        cursor = next_delimiter + part_delimiter.len();
    }
    Ok(parts)
}

fn multipart_part_path(headers: &str) -> Result<String, (StatusCode, String)> {
    let disposition = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-disposition") {
                Some(value.trim())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "proof-room.upload.disposition-missing".to_string(),
            )
        })?;
    disposition_param(disposition, "filename")
        .or_else(|| disposition_param(disposition, "name"))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "proof-room.upload.path-missing".to_string(),
            )
        })
}

fn disposition_param(disposition: &str, key: &str) -> Option<String> {
    for segment in disposition.split(';') {
        if let Some((name, value)) = segment.trim().split_once('=') {
            if name.trim().eq_ignore_ascii_case(key) {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn uploaded_bundle_id(manifest_path: &Path) -> Result<String, std::io::Error> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path)?).map_err(std::io::Error::other)?;
    Ok(manifest
        .get("bundle_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string())
}

fn proof_room_upload_verification_response(
    status: StatusCode,
    verdict: &str,
    error: Option<String>,
    bundle_id: Option<String>,
) -> Response {
    let mut body = serde_json::json!({
        "schema": "chio.proof-room.upload-verification.v1",
        "verdict": verdict,
    });
    if let Some(error) = error {
        body["error"] = serde_json::Value::String(error);
    }
    if let Some(bundle_id) = bundle_id {
        body["bundle_id"] = serde_json::Value::String(bundle_id);
    }
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn upload_io_error(error: std::io::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("proof-room.upload.io: {error}"),
    )
}

struct UploadedProofRoomBundle {
    path: PathBuf,
}

impl UploadedProofRoomBundle {
    fn create() -> Result<Self, std::io::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let sequence = UPLOAD_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chio-proof-room-upload-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UploadedProofRoomBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn proof_room_trusted_bundle_signers_response() -> Response {
    match super::proof_room_trusted_bundle_signer_keys_from_env() {
        Ok(keys) if !keys.is_empty() => Json(serde_json::json!({
            "schema": "chio.proof-room.trusted-bundle-signers.v1",
            "keys": keys.into_iter().collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(_) => (
            StatusCode::PRECONDITION_FAILED,
            [(CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "schema": "chio.proof-room.trusted-bundle-signers.v1",
                "error": "proof-room.signature.trusted-signers-missing",
            })
            .to_string(),
        )
            .into_response(),
        Err(error) => (
            StatusCode::PRECONDITION_FAILED,
            [(CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "schema": "chio.proof-room.trusted-bundle-signers.v1",
                "error": error,
            })
            .to_string(),
        )
            .into_response(),
    }
}

async fn proof_room_manifest_asset(State(state): State<ProofRoomServeState>) -> Response {
    proof_room_bundle_asset_response(&state, "manifest.json").await
}

async fn proof_room_artifacts_asset(
    State(state): State<ProofRoomServeState>,
    AxumPath(asset_path): AxumPath<String>,
) -> Response {
    proof_room_prefixed_bundle_asset_response(&state, "artifacts", &asset_path).await
}

async fn proof_room_negatives_asset(
    State(state): State<ProofRoomServeState>,
    AxumPath(asset_path): AxumPath<String>,
) -> Response {
    proof_room_prefixed_bundle_asset_response(&state, "negatives", &asset_path).await
}

async fn proof_room_roots_asset(
    State(state): State<ProofRoomServeState>,
    AxumPath(asset_path): AxumPath<String>,
) -> Response {
    proof_room_prefixed_bundle_asset_response(&state, "roots", &asset_path).await
}

async fn proof_room_bundle_ui_asset(
    State(state): State<ProofRoomServeState>,
    AxumPath(asset_path): AxumPath<String>,
) -> Response {
    proof_room_prefixed_bundle_asset_response(&state, "ui", &asset_path).await
}

async fn proof_room_verifier_asset(
    State(state): State<ProofRoomServeState>,
    AxumPath(asset_path): AxumPath<String>,
) -> Response {
    proof_room_prefixed_bundle_asset_response(&state, "verifier", &asset_path).await
}

async fn proof_room_fallback_asset(
    State(state): State<ProofRoomServeState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let asset_path = uri.path().trim_start_matches('/');
    if asset_path.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if state.allowed_bundle_paths.contains(asset_path) {
        return proof_room_bundle_asset_response(&state, asset_path).await;
    }
    if is_proof_room_bundle_namespace(asset_path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ui_dir) = &state.ui_dir {
        proof_room_ui_asset_response(ui_dir, asset_path).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn proof_room_prefixed_bundle_asset_response(
    state: &ProofRoomServeState,
    prefix: &str,
    asset_path: &str,
) -> Response {
    proof_room_bundle_asset_response(state, &format!("{prefix}/{asset_path}")).await
}

async fn proof_room_bundle_asset_response(
    state: &ProofRoomServeState,
    asset_path: &str,
) -> Response {
    let Ok(asset_path) = safe_served_bundle_path(asset_path, "proof-room.serve") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !state.allowed_bundle_paths.contains(&asset_path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = match resolve_proof_room_served_asset_path(&state.bundle, &asset_path) {
        Ok(path) => path,
        Err(error) => return (StatusCode::NOT_FOUND, error).into_response(),
    };
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => return (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    };
    (
        StatusCode::OK,
        [(CONTENT_TYPE, proof_room_content_type(&asset_path))],
        bytes,
    )
        .into_response()
}

async fn proof_room_ui_asset_response(ui_dir: &Path, asset_path: &str) -> Response {
    let Ok(asset_path) = safe_served_bundle_path(asset_path, "proof-room.ui") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Ok(path) = resolve_proof_room_served_asset_path(ui_dir, &asset_path) {
        if path.is_file() {
            if let Ok(bytes) = tokio::fs::read(path).await {
                return (
                    StatusCode::OK,
                    [(CONTENT_TYPE, proof_room_content_type(&asset_path))],
                    bytes,
                )
                    .into_response();
            }
        }
    }
    let index = ui_dir.join("index.html");
    match tokio::fs::read(index).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            bytes,
        )
            .into_response(),
        Err(error) => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    }
}

pub fn build_proof_room_fixture_catalog_json(bundle: &Path) -> Result<serde_json::Value, String> {
    build_proof_room_fixture_catalog_json_with_fixture_root(bundle, None)
}

pub fn build_proof_room_fixture_catalog_json_with_fixture_root(
    bundle: &Path,
    fixture_root: Option<&Path>,
) -> Result<serde_json::Value, String> {
    serde_json::to_value(build_proof_room_fixture_catalog(bundle, fixture_root)?)
        .map_err(|error| format!("proof-room.catalog.serialize: {error}"))
}

async fn proof_room_fixture_catalog_response(
    State(state): State<ProofRoomServeState>,
) -> Result<Json<ProofRoomFixtureCatalog>, (StatusCode, String)> {
    build_proof_room_fixture_catalog(&state.bundle, state.fixture_root.as_deref())
        .map(Json)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn proof_room_fixture_asset_with_state_response(
    State(state): State<ProofRoomServeState>,
    AxumPath((fixture_id, asset_path)): AxumPath<(String, String)>,
) -> Response {
    proof_room_fixture_asset_response_from_result(
        &fixture_id,
        &asset_path,
        proof_room_fixture_asset_with_root(&fixture_id, &asset_path, state.fixture_root.as_deref()),
    )
}

pub async fn proof_room_fixture_asset_response(
    AxumPath((fixture_id, asset_path)): AxumPath<(String, String)>,
) -> Response {
    proof_room_fixture_asset_response_from_result(
        &fixture_id,
        &asset_path,
        proof_room_fixture_asset(&fixture_id, &asset_path),
    )
}

fn proof_room_fixture_asset_response_from_result(
    fixture_id: &str,
    asset_path: &str,
    result: Result<(Vec<u8>, &'static str), (StatusCode, String)>,
) -> Response {
    match result {
        Ok((contents, content_type)) => {
            let status = if asset_path == "verifier-report.json" {
                proof_room_fixture_report_status(&contents)
            } else {
                StatusCode::OK
            };
            (status, [(CONTENT_TYPE, content_type)], contents).into_response()
        }
        Err((status, error)) if asset_path == "verifier-report.json" => {
            proof_room_fixture_error_response(fixture_id, asset_path, status, &error)
        }
        Err((status, error)) => (status, error).into_response(),
    }
}

fn proof_room_fixture_error_response(
    fixture_id: &str,
    asset_path: &str,
    status: StatusCode,
    error: &str,
) -> Response {
    let failure_code = proof_room_fixture_failure_code(error);
    let report = serde_json::json!({
        "schema": "chio.proof-room.fixture-error.v1",
        "fixture_id": fixture_id,
        "asset_path": asset_path,
        "verdict": "failed",
        "status": status.as_u16(),
        "failure_code": failure_code,
        "error": error,
    });
    match serde_json::to_vec(&report) {
        Ok(contents) => (status, [(CONTENT_TYPE, "application/json")], contents).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.error-encode: {fixture_id}: {error}"),
        )
            .into_response(),
    }
}

pub fn parse_listen_addr(value: &str) -> Result<SocketAddr, ProofRoomError> {
    value.parse().map_err(ProofRoomError::ListenAddress)
}

pub fn proof_room_served_bundle_paths(static_root: &Path) -> Result<BTreeSet<String>, String> {
    let manifest_path = static_root.join("manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("proof-room.serve.manifest-read: {error}"))?,
    )
    .map_err(|error| format!("proof-room.serve.manifest-json: {error}"))?;
    let mut paths = BTreeSet::new();
    insert_served_bundle_path(&mut paths, "manifest.json")?;
    if static_root.join("README.md").is_file() {
        insert_served_bundle_path(&mut paths, "README.md")?;
    }
    if let Some(path) = manifest
        .get("signature")
        .and_then(|signature| signature.get("signature_ref"))
        .and_then(serde_json::Value::as_str)
    {
        insert_served_bundle_path(&mut paths, path)?;
    } else if static_root.join("bundle-signature.dsse.json").is_file() {
        insert_served_bundle_path(&mut paths, "bundle-signature.dsse.json")?;
    }
    for field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        insert_manifest_reference_path(&mut paths, &manifest, field)?;
    }
    if let Some(artifacts) = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
    {
        for artifact in artifacts {
            insert_value_path(&mut paths, artifact, "path")?;
        }
    }
    if let Some(claims) = manifest.get("claims").and_then(serde_json::Value::as_array) {
        for claim in claims {
            for field in ["required_artifacts", "source_refs"] {
                if let Some(references) = claim.get(field).and_then(serde_json::Value::as_array) {
                    for reference in references {
                        if let Some(path) = reference.as_str() {
                            insert_served_bundle_path(&mut paths, path)?;
                        }
                    }
                }
            }
        }
    }
    if let Some(receipt_coverage) = manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
    {
        for row in receipt_coverage {
            insert_value_path(&mut paths, row, "artifact_path")?;
        }
    }
    if let Some(negative_cases) = manifest
        .get("negative_cases")
        .and_then(serde_json::Value::as_array)
    {
        for negative_case in negative_cases {
            let Some(path) = negative_case
                .get("path")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            insert_served_bundle_path(&mut paths, path)?;
            insert_negative_case_manifest_paths(static_root, &mut paths, path)?;
        }
    }
    Ok(paths)
}

fn insert_manifest_reference_path(
    paths: &mut BTreeSet<String>,
    manifest: &serde_json::Value,
    field: &str,
) -> Result<(), String> {
    if let Some(path) = manifest
        .get(field)
        .and_then(|reference| reference.get("path"))
        .and_then(serde_json::Value::as_str)
    {
        insert_served_bundle_path(paths, path)?;
    }
    Ok(())
}

fn insert_value_path(
    paths: &mut BTreeSet<String>,
    value: &serde_json::Value,
    field: &str,
) -> Result<(), String> {
    if let Some(path) = value.get(field).and_then(serde_json::Value::as_str) {
        insert_served_bundle_path(paths, path)?;
    }
    Ok(())
}

fn insert_negative_case_manifest_paths(
    static_root: &Path,
    paths: &mut BTreeSet<String>,
    negative_path: &str,
) -> Result<(), String> {
    let negative_path = safe_served_bundle_path(negative_path, "proof-room.serve")?;
    if !negative_path.ends_with("/transaction-passport.json") {
        return Ok(());
    };
    let Some((negative_dir, _passport_file)) = negative_path.rsplit_once('/') else {
        return Ok(());
    };
    let passport_bytes = fs::read(static_root.join(&negative_path)).map_err(|error| {
        format!("proof-room.serve.negative-passport-read: {negative_path}: {error}")
    })?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes).map_err(|error| {
            format!("proof-room.serve.negative-passport-json: {negative_path}: {error}")
        })?;
    let evidence_graph_path =
        negative_case_bundle_member_path(negative_dir, &passport.evidence_graph_path)?;
    let verifier_policy_path =
        negative_case_bundle_member_path(negative_dir, &passport.verifier_policy_path)?;
    insert_served_bundle_path(paths, &evidence_graph_path)?;
    insert_served_bundle_path(paths, &verifier_policy_path)?;

    let graph_bytes = fs::read(static_root.join(&evidence_graph_path)).map_err(|error| {
        format!("proof-room.serve.negative-evidence-graph-read: {evidence_graph_path}: {error}")
    })?;
    let graph =
        parse_embedded_evidence_graph(&graph_bytes, "proof-room.serve.negative-evidence-graph")
            .map_err(|error| {
                format!(
                    "proof-room.serve.negative-evidence-graph-json: {evidence_graph_path}: {error}"
                )
            })?;
    for node in graph.nodes {
        let artifact_path = negative_case_bundle_member_path(negative_dir, &node.path)?;
        insert_served_bundle_path(paths, &artifact_path)?;
    }
    Ok(())
}

fn negative_case_bundle_member_path(
    negative_dir: &str,
    member_path: &str,
) -> Result<String, String> {
    let member_path = safe_served_bundle_path(member_path, "proof-room.serve")?;
    let path = format!("{negative_dir}/{member_path}");
    safe_served_bundle_path(&path, "proof-room.serve")
}

fn insert_served_bundle_path(paths: &mut BTreeSet<String>, path: &str) -> Result<(), String> {
    let path = safe_served_bundle_path(path, "proof-room.serve")?;
    paths.insert(path);
    Ok(())
}

pub fn resolve_proof_room_served_asset_path(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    let relative_path = safe_served_bundle_path(relative_path, "proof-room.serve")?;
    let root = fs::canonicalize(root)
        .map_err(|error| format!("proof-room.serve.root-unreadable: {error}"))?;
    let resolved = fs::canonicalize(root.join(relative_path))
        .map_err(|error| format!("proof-room.serve.path-unreadable: {error}"))?;
    if resolved.starts_with(root) {
        Ok(resolved)
    } else {
        Err("proof-room.serve.path-escape".to_string())
    }
}

pub fn is_proof_room_bundle_namespace(asset_path: &str) -> bool {
    matches!(
        asset_path,
        "manifest.json" | "bundle-signature.dsse.json" | "README.md"
    ) || asset_path.starts_with("artifacts/")
        || asset_path.starts_with("negatives/")
        || asset_path.starts_with("roots/")
        || asset_path.starts_with("ui/")
        || asset_path.starts_with("verifier/")
}

pub fn proof_room_content_type(asset_path: &str) -> &'static str {
    if asset_path.ends_with(".json") {
        "application/json"
    } else if asset_path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if asset_path.ends_with(".js") {
        "application/javascript"
    } else if asset_path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if asset_path.ends_with(".md") {
        "text/markdown; charset=utf-8"
    } else if asset_path.ends_with(".svg") {
        "image/svg+xml"
    } else {
        "application/octet-stream"
    }
}

fn safe_served_bundle_path(relative: &str, label: &str) -> Result<String, String> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || relative.contains("//")
        || !relative.is_ascii()
        || relative.chars().any(char::is_whitespace)
        || relative.chars().any(char::is_control)
        || Path::new(relative).is_absolute()
    {
        return Err(format!("{label} member path {relative} is not portable"));
    }
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(format!("{label} member path {relative} is unsafe"));
        }
    }
    Ok(relative.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[tokio::test]
    async fn serve_rejects_configured_ui_dir_before_bundle_verification(
    ) -> Result<(), Box<dyn Error>> {
        let tempdir = tempfile::tempdir()?;
        let ui_dir = tempdir.path().join("empty-ui");
        fs::create_dir_all(&ui_dir)?;
        let bundle = tempdir.path().join("missing-bundle");
        let listen = "127.0.0.1:0".parse()?;

        let error = match serve_proof_room(ProofRoomServeConfig {
            bundle,
            ui_dir,
            listen,
            doctor_report: None,
            fixture_root: None,
        })
        .await
        {
            Ok(()) => return Err("server accepted empty ui dir".into()),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("proof-room.ui.index-missing"),
            "{error}"
        );
        Ok(())
    }
}
