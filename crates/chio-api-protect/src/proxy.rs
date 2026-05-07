//! Reverse proxy server that evaluates requests and forwards to upstream.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Json;
use axum::Router;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{info, warn};

use chio_core_types::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, PromptGrant, ResourceGrant,
    ToolGrant,
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_http_core::{
    client_builder_with_contract, handle_batch_respond, handle_get_approval, handle_list_pending,
    handle_respond, http_status_metadata_decision, http_status_metadata_final, send_with_contract,
    ApprovalAdmin, ApprovalHandlerError, AuthMethod, BatchRespondRequest, CallerIdentity,
    ChioHttpRequest, EvaluateResponse, HealthResponse, HttpEgressContract, HttpMethod, HttpReceipt,
    HttpReceiptBody, PendingQuery, RespondRequest, SidecarStatus, Verdict, VerifyReceiptResponse,
};
use chio_kernel::{ApprovalStore, InMemoryApprovalStore};
use chio_openapi::{ChioExtensions, DefaultPolicy};
use chio_store_sqlite::SqliteApprovalStore;

use crate::error::ProtectError;
use crate::evaluator::{RequestEvaluator, RouteEntry};
use crate::spec_discovery::{default_upstream_egress_contract, discover_spec, load_spec_from_file};

/// Configuration for the protect proxy.
pub struct ProtectConfig {
    /// Upstream URL to proxy to.
    pub upstream: String,
    /// Optional in-memory OpenAPI spec content (YAML or JSON).
    pub spec_content: Option<String>,
    /// Optional OpenAPI spec path. When omitted, the proxy auto-discovers the spec.
    pub spec_path: Option<String>,
    /// Address to listen on (e.g., "127.0.0.1:9090").
    pub listen_addr: String,
    /// Optional SQLite path for receipt persistence.
    pub receipt_db: Option<String>,
    /// Optional bearer token that authorizes remote sidecar control requests.
    pub sidecar_control_token: Option<String>,
    /// Optional seed used to keep the sidecar signer stable across restarts.
    pub signer_seed_hex: Option<String>,
    /// Explicit capability issuers trusted by the HTTP authority.
    pub trusted_capability_issuers: Vec<PublicKey>,
}

impl std::fmt::Debug for ProtectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectConfig")
            .field("upstream", &self.upstream)
            .field(
                "spec_content",
                &self.spec_content.as_ref().map(|_| "<inline>"),
            )
            .field("spec_path", &self.spec_path)
            .field("listen_addr", &self.listen_addr)
            .field("receipt_db", &self.receipt_db)
            .field(
                "sidecar_control_token",
                &self.sidecar_control_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "signer_seed_hex",
                &self.signer_seed_hex.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "trusted_capability_issuers",
                &self.trusted_capability_issuers,
            )
            .finish()
    }
}

/// Stored receipts for inspection and querying.
struct ReceiptLog {
    receipts: Vec<HttpReceipt>,
}

struct SqliteReceiptStore {
    connection: Connection,
}

impl SqliteReceiptStore {
    fn open(path: &str) -> Result<Self, ProtectError> {
        let connection = Connection::open(path)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS http_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY
                );
                ",
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(Self { connection })
    }

    fn load_receipts(&self) -> Result<Vec<HttpReceipt>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT receipt_json FROM http_receipts ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let receipt_json =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            let receipt: HttpReceipt = serde_json::from_str(&receipt_json)
                .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn append(&mut self, receipt: &HttpReceipt) -> Result<(), ProtectError> {
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO http_receipts (id, receipt_json) VALUES (?1, ?2)",
                params![receipt.id, receipt_json],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }

    fn load_revoked_capability_ids(&self) -> Result<HashSet<String>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT capability_id FROM revoked_capabilities ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut capability_ids = HashSet::new();
        for row in rows {
            let capability_id =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            capability_ids.insert(capability_id);
        }
        Ok(capability_ids)
    }

    fn revoke_capability(&mut self, capability_id: &str) -> Result<(), ProtectError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO revoked_capabilities (capability_id) VALUES (?1)",
                params![capability_id],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }
}

/// Shared proxy state.
struct ProxyState {
    evaluator: RequestEvaluator,
    signer_keypair: Keypair,
    upstream: String,
    http_client: reqwest::Client,
    egress_contract: HttpEgressContract,
    approval_admin: ApprovalAdmin,
    receipt_log: Mutex<ReceiptLog>,
    receipt_store: Option<Mutex<SqliteReceiptStore>>,
    revoked_capability_ids: Mutex<HashSet<String>>,
    sidecar_control_token: Option<String>,
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self { config }
    }

    async fn load_spec_content(&self) -> Result<String, ProtectError> {
        if let Some(spec_content) = &self.config.spec_content {
            return Ok(spec_content.clone());
        }
        if let Some(spec_path) = &self.config.spec_path {
            return load_spec_from_file(spec_path);
        }
        discover_spec(&self.config.upstream).await
    }

    /// Build the route table from the OpenAPI spec.
    /// Parses the spec directly to preserve path and method information.
    fn build_routes(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        let spec = chio_openapi::OpenApiSpec::parse(spec_content)?;
        let mut routes = Vec::new();

        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let method = match method_str.as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "PATCH" => HttpMethod::Patch,
                    "DELETE" => HttpMethod::Delete,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    _ => continue,
                };

                let extensions = ChioExtensions::from_operation(&operation.raw);
                let policy = DefaultPolicy::for_method_with_extensions(method, &extensions);
                routes.push(RouteEntry {
                    pattern: path.clone(),
                    method,
                    operation_id: operation.operation_id.clone(),
                    policy,
                });
            }
        }

        Ok(routes)
    }

    /// Start the proxy server. This blocks until the server shuts down.
    pub async fn run(self) -> Result<(), ProtectError> {
        let spec_content = self.load_spec_content().await?;
        let routes = Self::build_routes(&spec_content)?;
        let route_count = routes.len();

        let keypair = match &self.config.signer_seed_hex {
            Some(seed_hex) => Keypair::from_seed_hex(seed_hex)
                .map_err(|error| ProtectError::Config(error.to_string()))?,
            None => Keypair::generate(),
        };
        let policy_hash = chio_core_types::sha256_hex(spec_content.as_bytes());

        let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = &self.config.receipt_db {
            Arc::new(
                SqliteApprovalStore::open(path)
                    .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
            )
        } else {
            Arc::new(InMemoryApprovalStore::new())
        };

        let evaluator = RequestEvaluator::new_with_approval_store_and_trusted_capability_issuers(
            routes,
            keypair.clone(),
            policy_hash,
            Arc::clone(&approval_store),
            self.config.trusted_capability_issuers.clone(),
        );

        let (receipt_log, receipt_store, revoked_capability_ids) =
            if let Some(path) = &self.config.receipt_db {
                let store = SqliteReceiptStore::open(path)?;
                let receipts = store.load_receipts()?;
                let revoked_capability_ids = store.load_revoked_capability_ids()?;
                (
                    ReceiptLog { receipts },
                    Some(Mutex::new(store)),
                    revoked_capability_ids,
                )
            } else {
                (
                    ReceiptLog {
                        receipts: Vec::new(),
                    },
                    None,
                    HashSet::new(),
                )
            };

        let egress_contract = default_upstream_egress_contract(&self.config.upstream)?;
        let http_client = client_builder_with_contract(&egress_contract).build()?;
        let state = Arc::new(ProxyState {
            evaluator,
            signer_keypair: keypair,
            upstream: self.config.upstream.clone(),
            http_client,
            egress_contract,
            approval_admin: ApprovalAdmin::new(approval_store),
            receipt_log: Mutex::new(receipt_log),
            receipt_store,
            revoked_capability_ids: Mutex::new(revoked_capability_ids),
            sidecar_control_token: self.config.sidecar_control_token.clone(),
        });

        let app = build_app(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                ProtectError::Config(format!("cannot bind {}: {e}", self.config.listen_addr))
            })?;

        info!(
            "chio api protect: proxying {} routes to {} on {}",
            route_count, self.config.upstream, self.config.listen_addr
        );

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(ProtectError::Io)?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

fn build_app(state: Arc<ProxyState>) -> Router {
    let approval_routes = Router::new()
        .route("/approvals/pending", get(list_pending_approvals_handler))
        .route(
            "/approvals/batch/respond",
            post(batch_respond_approvals_handler),
        )
        .route("/approvals/{id}/respond", post(respond_approval_handler))
        .route("/approvals/{id}", get(get_approval_handler))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_sidecar_control_middleware,
        ));

    Router::new()
        .route("/chio/evaluate", post(sidecar_evaluate_handler))
        .route("/chio/verify", post(sidecar_verify_handler))
        .route("/chio/health", get(sidecar_health_handler))
        .merge(approval_routes)
        .route("/v1/capabilities/mint", post(sidecar_mint_handler))
        .route("/v1/capabilities/release", post(sidecar_release_handler))
        .route("/v1/receipts", post(sidecar_submit_receipt_handler))
        .route("/{*path}", any(proxy_handler))
        .route("/", any(proxy_handler))
        .with_state(state)
}

async fn list_pending_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    Query(query): Query<PendingQuery>,
) -> Response {
    match handle_list_pending(&state.approval_admin, query) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

async fn get_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
) -> Response {
    match handle_get_approval(&state.approval_admin, &approval_id) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

async fn respond_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
    body: Result<Json<RespondRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid approval response payload: {error}"
            )));
        }
    };

    let now = chrono::Utc::now().timestamp() as u64;
    match handle_respond(&state.approval_admin, &approval_id, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

async fn batch_respond_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    body: Result<Json<BatchRespondRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid batch approval payload: {error}"
            )));
        }
    };

    let now = chrono::Utc::now().timestamp() as u64;
    match handle_batch_respond(&state.approval_admin, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

async fn require_sidecar_control_middleware(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }

    next.run(request).await
}

/// Axum handler that evaluates the request and proxies to upstream.
async fn proxy_handler(State(state): State<Arc<ProxyState>>, request: Request<Body>) -> Response {
    let uri = request.uri().clone();
    let raw_headers = request.headers().clone();
    let method = match request.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => {
            return (StatusCode::METHOD_NOT_ALLOWED, "unsupported method").into_response();
        }
    };

    let path = uri.path().to_string();
    let query = parse_query_params(uri.query());
    let forwarded_query = forwarded_query_string(uri.query());

    // Extract relevant headers.
    let mut headers = HashMap::new();
    for (name, value) in &raw_headers {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    // Read body for hashing.
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!("failed to read request body: {e}");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };
    let body_length = body_bytes.len() as u64;
    let body_hash = if body_bytes.is_empty() {
        None
    } else {
        Some(chio_core_types::sha256_hex(&body_bytes))
    };

    if let Some(response) =
        revoked_proxy_response(&state, method, &path, &query, &headers, body_hash.clone()).await
    {
        return response;
    }

    // Evaluate.
    let result =
        match state
            .evaluator
            .evaluate(method, &path, &query, &headers, body_hash, body_length)
        {
            Ok(r) => r,
            Err(e) => {
                warn!("evaluation error: {e}");
                return evaluation_error_response(&e);
            }
        };

    // If denied, return structured 403.
    if result.verdict.is_denied() {
        let denied_status = StatusCode::from_u16(verdict_http_status(&result.verdict))
            .unwrap_or(StatusCode::FORBIDDEN);
        let final_receipt = match finalize_and_record_receipt(
            &state,
            &result.receipt,
            denied_status.as_u16(),
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(response) => return response,
        };
        let error_body = serde_json::json!({
            "error": "chio_access_denied",
            "message": match &result.verdict {
                Verdict::Deny { reason, .. } => reason.clone(),
                _ => "access denied".to_string(),
            },
            "receipt_id": final_receipt.id,
            "suggestion": "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
        });
        return Response::builder()
            .status(denied_status)
            .header("content-type", "application/json")
            .header("X-Chio-Receipt-Id", &final_receipt.id)
            .body(Body::from(
                serde_json::to_string(&error_body).unwrap_or_default(),
            ))
            .unwrap_or_else(|_| denied_status.into_response());
    }

    // Proxy to upstream.
    let mut upstream_url = format!("{}{}", state.upstream.trim_end_matches('/'), &path);
    if let Some(raw_query) = forwarded_query {
        upstream_url.push('?');
        upstream_url.push_str(&raw_query);
    }

    let mut upstream_req = state.http_client.request(
        match method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        },
        &upstream_url,
    );

    // Forward end-to-end request headers while keeping Chio transport and
    // hop-by-hop connection details local to the proxy.
    for (name, value) in &raw_headers {
        if should_forward_request_header(name.as_str()) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    let upstream_req = match upstream_req.build() {
        Ok(request) => request,
        Err(error) => {
            return finalize_bad_gateway(
                &state,
                &result.receipt,
                format!("failed to build upstream request: {error}"),
            )
            .await;
        }
    };

    match send_with_contract(&state.egress_contract, &state.http_client, upstream_req).await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let response_headers = resp.headers().clone();
            let response_body = resp.body().to_vec();
            let final_receipt =
                match finalize_and_record_receipt(&state, &result.receipt, status.as_u16()).await {
                    Ok(receipt) => receipt,
                    Err(response) => return response,
                };

            let mut response_builder = Response::builder().status(status);

            // Forward response headers.
            for (name, value) in &response_headers {
                response_builder = response_builder.header(name.as_str(), value.as_bytes());
            }

            // Add receipt ID header.
            response_builder = response_builder.header("X-Chio-Receipt-Id", &final_receipt.id);

            response_builder
                .body(Body::from(response_body))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "bad gateway").into_response())
        }
        Err(e) => {
            warn!("upstream error: {e}");
            finalize_bad_gateway(&state, &result.receipt, format!("upstream error: {e}")).await
        }
    }
}

async fn sidecar_evaluate_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let transport_query = parse_query_params(parts.uri.query());
    let presented_capability = extract_transport_capability(&parts.headers, &transport_query);
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read evaluation body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": "failed to read evaluation body",
                })),
            )
                .into_response();
        }
    };

    let chio_request: ChioHttpRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode ChioHttpRequest: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": format!("invalid ChioHttpRequest payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    if let Some(response) =
        revoked_sidecar_evaluate_response(&state, &chio_request, presented_capability.as_deref())
            .await
    {
        return response;
    }

    let result = match state
        .evaluator
        .evaluate_chio_request(chio_request, presented_capability.as_deref())
    {
        Ok(result) => result,
        Err(error) => {
            warn!("sidecar evaluation error: {error}");
            return evaluation_error_response(&error);
        }
    };

    if let Err(error) = record_receipt(&state, &result.receipt).await {
        warn!("failed to persist receipt: {error}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "chio_receipt_persistence_failed",
                "message": error.to_string(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        axum::Json(EvaluateResponse {
            verdict: result.verdict,
            receipt: result.receipt,
            evidence: result.evidence,
            // This sidecar evaluation endpoint preserves the existing
            // evaluate-only contract. Execution endpoints attach nonces
            // when they invoke the kernel tool-call path.
            execution_nonce: None,
        }),
    )
        .into_response()
}

async fn sidecar_verify_handler(
    State(_state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read verify body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": "failed to read receipt verification body",
                })),
            )
                .into_response();
        }
    };

    let receipt: HttpReceipt = match serde_json::from_slice(&body_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to decode HttpReceipt: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": format!("invalid HttpReceipt payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    let valid = receipt.verify_signature().unwrap_or(false);
    (StatusCode::OK, axum::Json(VerifyReceiptResponse { valid })).into_response()
}

async fn sidecar_health_handler(State(_state): State<Arc<ProxyState>>) -> Response {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: SidecarStatus::Healthy,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct SidecarMintRequest {
    subject: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    ttl: Option<u64>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    ttl_nanos: Option<u64>,
    #[serde(default)]
    job_uid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SidecarMintResponse {
    capability: CapabilityToken,
}

#[derive(Debug, Deserialize)]
struct SidecarReleaseRequest {
    capability_id: String,
    #[serde(default)]
    job_uid: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SidecarReleaseResponse {
    released: bool,
}

#[derive(Debug, Deserialize)]
struct SidecarSubmitReceiptRequest {
    job_name: String,
    namespace: String,
    job_uid: String,
    #[serde(default)]
    capability_id: Option<String>,
    outcome: String,
    #[serde(default)]
    started_at: Option<String>,
    #[serde(default)]
    completed_at: Option<String>,
    #[serde(default)]
    steps: Vec<SidecarSubmitStepReceipt>,
}

#[derive(Debug, Deserialize)]
struct SidecarSubmitStepReceipt {
    pod_name: String,
    phase: String,
    payload: String,
    observed_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SidecarSubmitReceiptResponse {
    receipt_id: String,
    accepted: bool,
}

async fn sidecar_mint_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability mint body: {error}");
            return sidecar_bad_request("failed to read capability mint body").into_response();
        }
    };

    let mint_request: SidecarMintRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode capability mint request: {error}");
            return sidecar_bad_request(&format!("invalid capability mint payload: {error}"))
                .into_response();
        }
    };

    if mint_request.subject.trim().is_empty() {
        return sidecar_bad_request("subject must not be empty").into_response();
    }

    let scope = match build_sidecar_scope(&mint_request.scopes) {
        Ok(scope) => scope,
        Err(error) => return sidecar_bad_request(&error).into_response(),
    };

    let issued_at = chrono::Utc::now().timestamp() as u64;
    let ttl_seconds = ttl_seconds_from_wire(
        mint_request.ttl_seconds,
        mint_request.ttl_nanos,
        mint_request.ttl,
    );
    let expires_at = issued_at.saturating_add(ttl_seconds);
    let subject = derive_sidecar_subject_key(&mint_request.subject, &mint_request.job_uid);
    let capability_id = match derive_sidecar_capability_id(
        &mint_request.subject,
        &mint_request.job_uid,
        ttl_seconds,
        &scope,
    ) {
        Ok(capability_id) => capability_id,
        Err(error) => {
            warn!("failed to derive deterministic capability id: {error}");
            return internal_json_error_response(
                "chio_capability_mint_failed",
                "failed to derive deterministic capability id",
            );
        }
    };

    let capability = match CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id,
            issuer: state.signer_keypair.public_key(),
            subject,
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
        },
        &state.signer_keypair,
    ) {
        Ok(capability) => capability,
        Err(error) => {
            warn!("failed to sign compatibility capability token: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "chio_capability_mint_failed",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        axum::Json(SidecarMintResponse { capability }),
    )
        .into_response()
}

async fn sidecar_release_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability release body: {error}");
            return sidecar_bad_request("failed to read capability release body").into_response();
        }
    };

    let release_request: SidecarReleaseRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode capability release request: {error}");
            return sidecar_bad_request(&format!("invalid capability release payload: {error}"))
                .into_response();
        }
    };

    if release_request.capability_id.trim().is_empty() {
        return sidecar_bad_request("capability_id must not be empty").into_response();
    }

    let capability_id = release_request.capability_id.trim().to_string();
    let Some(store) = &state.receipt_store else {
        return internal_json_error_response(
            "chio_capability_release_failed",
            "persistent receipt_db must be configured for capability release",
        );
    };
    let mut store = store.lock().await;
    if let Err(error) = store.revoke_capability(&capability_id) {
        warn!("failed to persist capability revocation: {error}");
        return internal_json_error_response("chio_capability_release_failed", &error.to_string());
    }
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(capability_id);
    let _ = (release_request.job_uid, release_request.reason);

    (
        StatusCode::OK,
        axum::Json(SidecarReleaseResponse { released: true }),
    )
        .into_response()
}

async fn sidecar_submit_receipt_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read receipt submission body: {error}");
            return sidecar_bad_request("failed to read receipt submission body").into_response();
        }
    };

    let receipt_request: SidecarSubmitReceiptRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode receipt submission payload: {error}");
            return sidecar_bad_request(&format!("invalid receipt submission payload: {error}"))
                .into_response();
        }
    };

    if receipt_request.job_name.trim().is_empty()
        || receipt_request.namespace.trim().is_empty()
        || receipt_request.job_uid.trim().is_empty()
        || receipt_request.outcome.trim().is_empty()
    {
        return sidecar_bad_request("job_name, namespace, job_uid, and outcome are required")
            .into_response();
    }

    for step in &receipt_request.steps {
        if step.pod_name.trim().is_empty()
            || step.phase.trim().is_empty()
            || step.payload.trim().is_empty()
            || step.observed_at.trim().is_empty()
        {
            return sidecar_bad_request(
                "receipt steps must include pod_name, phase, payload, and observed_at",
            )
            .into_response();
        }
    }

    let caller_identity_hash = match CallerIdentity::anonymous().identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash synthetic receipt caller identity: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    let receipt_id = uuid::Uuid::now_v7().to_string();
    let capability_id = receipt_request
        .capability_id
        .clone()
        .filter(|value| !value.trim().is_empty());
    let receipt = match HttpReceipt::sign(
        HttpReceiptBody {
            id: receipt_id.clone(),
            request_id: format!("job-receipt-submission:{}", receipt_request.job_uid),
            route_pattern: "/v1/receipts".to_string(),
            method: HttpMethod::Post,
            caller_identity_hash,
            session_id: None,
            verdict: Verdict::Allow,
            evidence: Vec::new(),
            response_status: StatusCode::OK.as_u16(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: chio_core_types::sha256_hex(&body_bytes),
            policy_hash: manual_receipt_policy_hash("chio_api_protect_sidecar_receipt_submission"),
            capability_id,
            metadata: Some(sidecar_submit_receipt_metadata(&receipt_request)),
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign submitted sidecar receipt: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    if let Err(error) = record_receipt(&state, &receipt).await {
        warn!("failed to persist submitted sidecar receipt: {error}");
        return internal_json_error_response("chio_receipt_persistence_failed", &error.to_string());
    }

    (
        StatusCode::OK,
        axum::Json(SidecarSubmitReceiptResponse {
            receipt_id,
            accepted: true,
        }),
    )
        .into_response()
}

fn parse_query_params(raw_query: Option<&str>) -> HashMap<String, String> {
    raw_query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn forwarded_query_string(raw_query: Option<&str>) -> Option<String> {
    let raw_query = raw_query?;
    let filtered = url::form_urlencoded::parse(raw_query.as_bytes())
        .filter(|(key, _)| key != "chio_capability")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return None;
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in filtered {
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    (!query.is_empty()).then_some(query)
}

fn sidecar_bad_request(message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "chio_bad_request",
            "message": message,
        })),
    )
}

#[allow(clippy::result_large_err)]
fn require_sidecar_control_request(
    request: &Request<Body>,
    expected_bearer_token: Option<&str>,
) -> Result<(), Response> {
    if let Some(expected_bearer_token) = expected_bearer_token.map(str::trim) {
        if expected_bearer_token.is_empty() {
            warn!("rejecting sidecar control request with blank bearer token configuration");
            return Err(sidecar_control_forbidden_response(true));
        }
        if sidecar_control_bearer_token_matches(request, expected_bearer_token) {
            return Ok(());
        }
        if let Some(peer) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
            warn!(
                peer = %peer.0,
                "rejecting sidecar control request without valid bearer token"
            );
        } else {
            warn!("rejecting sidecar control request without valid bearer token");
        }
        return Err(sidecar_control_forbidden_response(true));
    }

    if let Some(peer) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        if peer.0.ip().is_loopback() {
            return Ok(());
        }
    }

    if let Some(peer) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        warn!(
            peer = %peer.0,
            "rejecting non-loopback sidecar control request without configured bearer token"
        );
    } else {
        warn!("rejecting sidecar control request without peer address");
    }
    Err(sidecar_control_forbidden_response(false))
}

fn sidecar_control_bearer_token_matches(
    request: &Request<Body>,
    expected_bearer_token: &str,
) -> bool {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            if scheme.eq_ignore_ascii_case("bearer") {
                Some(token)
            } else {
                None
            }
        })
        // Constant-time compare so callers cannot recover the configured token
        // through response timing differences.
        .is_some_and(|token| {
            token
                .as_bytes()
                .ct_eq(expected_bearer_token.as_bytes())
                .into()
        })
}

fn sidecar_control_forbidden_response(remote_auth_configured: bool) -> Response {
    let message = if remote_auth_configured {
        "sidecar control endpoints require a loopback caller or valid bearer token"
    } else {
        "sidecar control endpoints require a loopback caller"
    };
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "chio_control_forbidden",
            "message": message,
        })),
    )
        .into_response()
}

fn ttl_seconds_from_wire(
    ttl_seconds_wire: Option<u64>,
    ttl_nanos_wire: Option<u64>,
    ttl_legacy_wire: Option<u64>,
) -> u64 {
    const DEFAULT_TTL_SECONDS: u64 = 3600;
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    if let Some(ttl_seconds) = ttl_seconds_wire {
        return match ttl_seconds {
            0 => DEFAULT_TTL_SECONDS,
            ttl_seconds => ttl_seconds,
        };
    }

    if let Some(ttl_nanos) = ttl_nanos_wire {
        return match ttl_nanos {
            0 => DEFAULT_TTL_SECONDS,
            ttl_nanos => std::cmp::max(
                1,
                ttl_nanos.saturating_add(NANOS_PER_SECOND - 1) / NANOS_PER_SECOND,
            ),
        };
    }

    match ttl_legacy_wire {
        Some(0) | None => DEFAULT_TTL_SECONDS,
        Some(ttl) if ttl < NANOS_PER_SECOND => ttl,
        Some(ttl) => std::cmp::max(
            1,
            ttl.saturating_add(NANOS_PER_SECOND - 1) / NANOS_PER_SECOND,
        ),
    }
}

fn derive_sidecar_subject_key(subject: &str, job_uid: &str) -> chio_core_types::crypto::PublicKey {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    hasher.update([0]);
    hasher.update(job_uid.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    Keypair::from_seed(&seed).public_key()
}

fn derive_sidecar_capability_id(
    subject: &str,
    job_uid: &str,
    ttl_seconds: u64,
    scope: &ChioScope,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct SidecarCapabilityIdMaterial<'a> {
        subject: &'a str,
        job_uid: &'a str,
        ttl_seconds: u64,
        tool_grants: Vec<String>,
        resource_grants: Vec<String>,
        prompt_grants: Vec<String>,
    }

    fn sorted_grant_encodings<T: Serialize>(
        grants: &[T],
    ) -> Result<Vec<String>, serde_json::Error> {
        let mut encodings = grants
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort_unstable();
        Ok(encodings)
    }

    let id_material = SidecarCapabilityIdMaterial {
        subject,
        job_uid,
        ttl_seconds,
        tool_grants: sorted_grant_encodings(&scope.grants)?,
        resource_grants: sorted_grant_encodings(&scope.resource_grants)?,
        prompt_grants: sorted_grant_encodings(&scope.prompt_grants)?,
    };
    let encoded = serde_json::to_vec(&id_material)?;
    Ok(format!("sidecar-{}", chio_core_types::sha256_hex(&encoded)))
}

fn build_sidecar_scope(scopes: &[String]) -> Result<ChioScope, String> {
    let mut tool_grants = Vec::new();
    let mut resource_grants = Vec::new();
    let mut prompt_grants = Vec::new();

    for scope in scopes {
        match parse_sidecar_scope(scope)? {
            SidecarScopeGrant::Tool(grant) => tool_grants.push(grant),
            SidecarScopeGrant::Resource(grant) => resource_grants.push(grant),
            SidecarScopeGrant::Prompt(grant) => prompt_grants.push(grant),
        }
    }

    Ok(ChioScope {
        grants: tool_grants,
        resource_grants,
        prompt_grants,
    })
}

enum SidecarScopeGrant {
    Tool(ToolGrant),
    Resource(ResourceGrant),
    Prompt(PromptGrant),
}

fn parse_sidecar_scope(raw: &str) -> Result<SidecarScopeGrant, String> {
    let parts: Vec<&str> = raw
        .split(':')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();

    if parts.first() == Some(&"tools") && parts.len() >= 2 {
        return Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: "*".to_string(),
            tool_name: parts[1..].join(":"),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }));
    }

    match parts.as_slice() {
        [tool_name, operation] => Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: "*".to_string(),
            tool_name: (*tool_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, true)?],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })),
        ["tool", server_id, tool_name, operation] => Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: (*server_id).to_string(),
            tool_name: (*tool_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })),
        ["resource", uri_pattern, operation] => Ok(SidecarScopeGrant::Resource(ResourceGrant {
            uri_pattern: (*uri_pattern).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
        })),
        ["prompt", prompt_name, operation] => Ok(SidecarScopeGrant::Prompt(PromptGrant {
            prompt_name: (*prompt_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
        })),
        _ => Err(format!("unsupported controller scope syntax: {raw}")),
    }
}

fn parse_sidecar_operation(raw: &str, shorthand: bool) -> Result<Operation, String> {
    match raw.to_ascii_lowercase().as_str() {
        "invoke" | "call" | "exec" | "execute" => Ok(Operation::Invoke),
        "write" if shorthand => Ok(Operation::Invoke),
        "read_result" | "result" => Ok(Operation::ReadResult),
        "read" if shorthand => Ok(Operation::Read),
        "read" => Ok(Operation::Read),
        "subscribe" | "watch" => Ok(Operation::Subscribe),
        "get" => Ok(Operation::Get),
        "delegate" => Ok(Operation::Delegate),
        _ => Err(format!("unsupported controller scope operation: {raw}")),
    }
}

fn evaluation_error_response(error: &ProtectError) -> Response {
    match error {
        ProtectError::PendingApproval {
            approval_id,
            kernel_receipt_id,
        } => {
            let mut body = serde_json::json!({
                "error": "chio_approval_required",
                "message": "request requires human approval before it can proceed",
                "kernel_receipt_id": kernel_receipt_id,
            });
            if let Some(approval_id) = approval_id {
                body["approval_id"] = serde_json::Value::String(approval_id.clone());
                body["resume_path"] =
                    serde_json::Value::String(format!("/approvals/{approval_id}/respond"));
            }
            (StatusCode::CONFLICT, axum::Json(body)).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "chio_evaluation_failed",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

fn approval_json<T>(status: StatusCode, response: T) -> Response
where
    T: Serialize,
{
    (status, Json(response)).into_response()
}

fn approval_error_response(error: ApprovalHandlerError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(error.body())).into_response()
}

fn internal_json_error_response(error: &str, message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}

fn extract_presented_capability_from_maps<'a>(
    headers: &'a HashMap<String, String>,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    headers
        .get("x-chio-capability")
        .or_else(|| headers.get("X-Chio-Capability"))
        .map(String::as_str)
        .or_else(|| query.get("chio_capability").map(String::as_str))
}

fn extract_caller_identity(headers: &HashMap<String, String>) -> CallerIdentity {
    if let Some(auth) = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            let token_hash = chio_core_types::sha256_hex(token.as_bytes());
            return CallerIdentity {
                subject: format!("bearer:{}", &token_hash[..16]),
                auth_method: AuthMethod::Bearer { token_hash },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    for key_header in &["x-api-key", "X-Api-Key", "X-API-Key"] {
        if let Some(key_value) = headers.get(*key_header) {
            let key_hash = chio_core_types::sha256_hex(key_value.as_bytes());
            return CallerIdentity {
                subject: format!("apikey:{}", &key_hash[..16]),
                auth_method: AuthMethod::ApiKey {
                    key_name: key_header.to_string(),
                    key_hash,
                },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    CallerIdentity::anonymous()
}

fn presented_capability_id(raw_capability: Option<&str>) -> Option<String> {
    serde_json::from_str::<CapabilityToken>(raw_capability?)
        .ok()
        .map(|token| token.id)
}

async fn find_revoked_capability_id(
    state: &Arc<ProxyState>,
    raw_capability: Option<&str>,
    capability_id_hint: Option<&str>,
) -> Option<String> {
    let capability_id = presented_capability_id(raw_capability)
        .or_else(|| capability_id_hint.map(ToOwned::to_owned))?;
    let revoked_capability_ids = state.revoked_capability_ids.lock().await;
    revoked_capability_ids
        .contains(&capability_id)
        .then_some(capability_id)
}

fn revoked_capability_verdict() -> Verdict {
    Verdict::deny_with_status(
        "capability token has been revoked",
        "CapabilityRevocation",
        403,
    )
}

fn manual_receipt_policy_hash(label: &str) -> String {
    chio_core_types::sha256_hex(label.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn build_manual_receipt(
    state: &Arc<ProxyState>,
    request_id: String,
    route_pattern: String,
    method: HttpMethod,
    caller_identity_hash: String,
    session_id: Option<String>,
    verdict: Verdict,
    response_status: u16,
    timestamp: u64,
    content_hash: String,
    capability_id: Option<String>,
    metadata: Option<serde_json::Value>,
    policy_label: &str,
) -> Result<HttpReceipt, ProtectError> {
    HttpReceipt::sign(
        HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id,
            route_pattern,
            method,
            caller_identity_hash,
            session_id,
            verdict,
            evidence: Vec::new(),
            response_status,
            timestamp,
            content_hash,
            policy_hash: manual_receipt_policy_hash(policy_label),
            capability_id,
            metadata,
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    )
    .map_err(|error| ProtectError::ReceiptSign(error.to_string()))
}

async fn revoked_proxy_response(
    state: &Arc<ProxyState>,
    method: HttpMethod,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HashMap<String, String>,
    body_hash: Option<String>,
) -> Option<Response> {
    let capability_id = find_revoked_capability_id(
        state,
        extract_presented_capability_from_maps(headers, query),
        None,
    )
    .await?;
    let caller = extract_caller_identity(headers);
    let caller_identity_hash = match caller.identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash caller identity for revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    let mut request = ChioHttpRequest::new(
        uuid::Uuid::now_v7().to_string(),
        method,
        path.to_string(),
        path.to_string(),
        caller,
    );
    request.query = query.clone();
    request.body_hash = body_hash;

    let content_hash = match request.content_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to compute revocation request content hash: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    let verdict = revoked_capability_verdict();
    let receipt = match build_manual_receipt(
        state,
        request.request_id.clone(),
        request.route_pattern.clone(),
        request.method,
        caller_identity_hash,
        None,
        verdict.clone(),
        StatusCode::FORBIDDEN.as_u16(),
        request.timestamp,
        content_hash,
        Some(capability_id),
        Some(http_status_metadata_final(None)),
        "chio_api_protect_revoked_capability",
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    if let Err(error) = record_receipt(state, &receipt).await {
        warn!("failed to persist revocation receipt: {error}");
        return Some(internal_json_error_response(
            "chio_receipt_persistence_failed",
            &error.to_string(),
        ));
    }

    let denied_status =
        StatusCode::from_u16(verdict_http_status(&verdict)).unwrap_or(StatusCode::FORBIDDEN);
    let error_body = serde_json::json!({
        "error": "chio_access_denied",
        "message": "capability token has been revoked",
        "receipt_id": receipt.id,
        "suggestion": "request a fresh capability token before retrying",
    });

    Some(
        Response::builder()
            .status(denied_status)
            .header("content-type", "application/json")
            .header("X-Chio-Receipt-Id", &receipt.id)
            .body(Body::from(
                serde_json::to_string(&error_body).unwrap_or_default(),
            ))
            .unwrap_or_else(|_| denied_status.into_response()),
    )
}

async fn revoked_sidecar_evaluate_response(
    state: &Arc<ProxyState>,
    request: &ChioHttpRequest,
    presented_capability: Option<&str>,
) -> Option<Response> {
    let capability_id = find_revoked_capability_id(
        state,
        presented_capability,
        request.capability_id.as_deref(),
    )
    .await?;
    let caller_identity_hash = match request.caller.identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash caller identity for sidecar revocation: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };
    let content_hash = match request.content_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to compute sidecar revocation content hash: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };
    let route_pattern = if request.route_pattern.is_empty() {
        request.path.clone()
    } else {
        request.route_pattern.clone()
    };
    let verdict = revoked_capability_verdict();
    let receipt = match build_manual_receipt(
        state,
        request.request_id.clone(),
        route_pattern,
        request.method,
        caller_identity_hash,
        request.session_id.clone(),
        verdict.clone(),
        StatusCode::FORBIDDEN.as_u16(),
        request.timestamp,
        content_hash,
        Some(capability_id),
        Some(http_status_metadata_decision()),
        "chio_api_protect_revoked_capability",
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign sidecar revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    if let Err(error) = record_receipt(state, &receipt).await {
        warn!("failed to persist sidecar revocation receipt: {error}");
        return Some(internal_json_error_response(
            "chio_receipt_persistence_failed",
            &error.to_string(),
        ));
    }

    Some(
        (
            StatusCode::OK,
            axum::Json(EvaluateResponse {
                verdict,
                receipt,
                evidence: Vec::new(),
                execution_nonce: None,
            }),
        )
            .into_response(),
    )
}

fn sidecar_submit_receipt_metadata(
    receipt_request: &SidecarSubmitReceiptRequest,
) -> serde_json::Value {
    let mut metadata = match http_status_metadata_final(None) {
        serde_json::Value::Object(object) => object,
        _ => serde_json::Map::new(),
    };
    metadata.insert(
        "submission_kind".to_string(),
        serde_json::Value::String("job_receipt".to_string()),
    );
    metadata.insert(
        "job_name".to_string(),
        serde_json::Value::String(receipt_request.job_name.clone()),
    );
    metadata.insert(
        "namespace".to_string(),
        serde_json::Value::String(receipt_request.namespace.clone()),
    );
    metadata.insert(
        "job_uid".to_string(),
        serde_json::Value::String(receipt_request.job_uid.clone()),
    );
    metadata.insert(
        "outcome".to_string(),
        serde_json::Value::String(receipt_request.outcome.clone()),
    );
    if let Some(started_at) = &receipt_request.started_at {
        metadata.insert(
            "started_at".to_string(),
            serde_json::Value::String(started_at.clone()),
        );
    }
    if let Some(completed_at) = &receipt_request.completed_at {
        metadata.insert(
            "completed_at".to_string(),
            serde_json::Value::String(completed_at.clone()),
        );
    }
    metadata.insert(
        "steps".to_string(),
        serde_json::Value::Array(
            receipt_request
                .steps
                .iter()
                .map(|step| {
                    serde_json::json!({
                        "pod_name": step.pod_name,
                        "phase": step.phase,
                        "payload": step.payload,
                        "observed_at": step.observed_at,
                    })
                })
                .collect(),
        ),
    );
    serde_json::Value::Object(metadata)
}

fn should_forward_request_header(name: &str) -> bool {
    !matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-chio-capability"
    )
}

fn verdict_http_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

fn extract_transport_capability(
    headers: &axum::http::HeaderMap,
    query: &HashMap<String, String>,
) -> Option<String> {
    headers
        .get("x-chio-capability")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| query.get("chio_capability").cloned())
}

async fn record_receipt(
    state: &Arc<ProxyState>,
    receipt: &HttpReceipt,
) -> Result<(), ProtectError> {
    if let Some(store) = &state.receipt_store {
        let mut store = store.lock().await;
        store.append(receipt)?;
    }

    let mut log = state.receipt_log.lock().await;
    log.receipts.push(receipt.clone());
    Ok(())
}

async fn finalize_and_record_receipt(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    response_status: u16,
) -> Result<HttpReceipt, Response> {
    let receipt = state
        .evaluator
        .finalize_receipt(decision_receipt, response_status)
        .map_err(|error| {
            warn!("failed to finalize receipt: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to finalize receipt",
            )
                .into_response()
        })?;

    record_receipt(state, &receipt).await.map_err(|error| {
        warn!("failed to persist receipt: {error}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist receipt",
        )
            .into_response()
    })?;

    Ok(receipt)
}

async fn finalize_bad_gateway(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    message: String,
) -> Response {
    match finalize_and_record_receipt(state, decision_receipt, StatusCode::BAD_GATEWAY.as_u16())
        .await
    {
        Ok(receipt) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("X-Chio-Receipt-Id", &receipt.id)
            .body(Body::from(message))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chio_core_types::capability::{
        CapabilityToken, CapabilityTokenBody, ChioScope, GovernedApprovalDecision,
        GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_http_core::{
        http_status_scope, RespondResponse, CHIO_HTTP_STATUS_SCOPE_DECISION,
        CHIO_HTTP_STATUS_SCOPE_FINAL,
    };
    use chio_kernel::{ApprovalOutcome, ApprovalRequest};
    use chio_openapi::PolicyDecision;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tower::ServiceExt;

    trait TestUnwrap<T> {
        fn test_unwrap(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestUnwrap<T> for Result<T, E> {
        fn test_unwrap(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("expected Ok(..), got Err({error:?})"),
            }
        }
    }

    impl<T> TestUnwrap<T> for Option<T> {
        fn test_unwrap(self) -> T {
            match self {
                Some(value) => value,
                None => panic!("expected Some(..), got None"),
            }
        }
    }

    const PETSTORE_YAML: &str = r#"
openapi: "3.0.0"
info:
  title: Petstore
  version: "1.0.0"
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      responses:
        "200":
          description: A list of pets
    post:
      operationId: createPet
      summary: Create a pet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: Created
  /pets/{petId}:
    get:
      operationId: showPetById
      summary: Info for a specific pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: A pet
    delete:
      operationId: deletePet
      summary: Delete a pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Deleted
"#;

    fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ChioScope::default(),
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            issuer,
        )
        .test_unwrap();
        serde_json::to_string(&token).test_unwrap()
    }

    struct MockUpstreamServer {
        base_url: String,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl MockUpstreamServer {
        fn bind_mock_upstream_listener() -> Option<TcpListener> {
            match TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => Some(listener),
                Err(error) => match error.kind() {
                    std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::Unsupported => {
                        eprintln!(
                            "skipping proxy mock-upstream test because loopback bind is unavailable: {error}"
                        );
                        None
                    }
                    _ => panic!("bind mock upstream listener: {error}"),
                },
            }
        }

        fn spawn(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Option<Self> {
            let listener = Self::bind_mock_upstream_listener()?;
            let address = listener.local_addr().test_unwrap();
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let request_log = Arc::clone(&requests);
            let headers = headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>();
            let body = body.to_string();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().test_unwrap();
                let request = read_http_request(&mut stream);
                request_log.lock().test_unwrap().push(request);
                write_http_response(&mut stream, status, &headers, &body);
            });
            Some(Self {
                base_url: format!("http://{}", address),
                requests,
                handle,
            })
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().test_unwrap().clone()
        }

        fn join(self) {
            self.handle.join().test_unwrap();
        }
    }

    fn test_state(routes: Vec<RouteEntry>, upstream: String) -> Arc<ProxyState> {
        test_state_with_receipt_db(routes, upstream, None)
    }

    fn test_state_with_receipt_db(
        routes: Vec<RouteEntry>,
        upstream: String,
        receipt_db: Option<&str>,
    ) -> Arc<ProxyState> {
        let keypair = Keypair::generate();
        let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = receipt_db {
            Arc::new(SqliteApprovalStore::open(path).test_unwrap())
        } else {
            Arc::new(InMemoryApprovalStore::new())
        };
        let (receipt_store, receipts, revoked_capability_ids) = if let Some(path) = receipt_db {
            let store = SqliteReceiptStore::open(path).test_unwrap();
            let receipts = store.load_receipts().test_unwrap();
            let revoked_capability_ids = store.load_revoked_capability_ids().test_unwrap();
            (Some(Mutex::new(store)), receipts, revoked_capability_ids)
        } else {
            (None, Vec::new(), HashSet::new())
        };
        let evaluator = RequestEvaluator::new_with_approval_store(
            routes,
            keypair.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        Arc::new(ProxyState {
            evaluator,
            signer_keypair: keypair,
            upstream,
            http_client,
            egress_contract,
            approval_admin: ApprovalAdmin::new(approval_store),
            receipt_log: Mutex::new(ReceiptLog { receipts }),
            receipt_store,
            revoked_capability_ids: Mutex::new(revoked_capability_ids),
            sidecar_control_token: None,
        })
    }

    fn pending_approval_request(approval_id: &str) -> (ApprovalRequest, Keypair, Keypair) {
        let request_subject = Keypair::generate();
        let approver = Keypair::generate();
        let approval = ApprovalRequest {
            approval_id: approval_id.to_string(),
            policy_id: "policy-hitl".to_string(),
            subject_id: "agent-1".to_string(),
            capability_id: "cap-1".to_string(),
            subject_public_key: Some(request_subject.public_key()),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action: "invoke".to_string(),
            parameter_hash: "hash-1".to_string(),
            expires_at: 4_000_000_000,
            callback_hint: None,
            created_at: 123,
            summary: "pending approval".to_string(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec!["force_approval".to_string()],
        };
        (approval, request_subject, approver)
    }

    fn signed_approval_response_token(
        approval_id: &str,
        subject: &Keypair,
        approver: &Keypair,
        decision: GovernedApprovalDecision,
    ) -> GovernedApprovalToken {
        let now = chrono::Utc::now().timestamp() as u64;
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("tok-{approval_id}"),
                approver: approver.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: "hash-1".to_string(),
                request_id: approval_id.to_string(),
                issued_at: now.saturating_sub(10),
                expires_at: now + 600,
                decision,
            },
            approver,
        )
        .test_unwrap()
    }

    fn temp_receipt_db_path() -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("chio-api-protect-test-{}.db", uuid::Uuid::now_v7()));
        path.to_string_lossy().to_string()
    }

    fn with_peer_addr(mut request: Request<Body>, peer: SocketAddr) -> Request<Body> {
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    fn with_loopback_peer(request: Request<Body>) -> Request<Body> {
        with_peer_addr(request, SocketAddr::from(([127, 0, 0, 1], 4100)))
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).test_unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8(request).test_unwrap()
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn write_http_response<W: Write>(
        stream: &mut W,
        status: u16,
        headers: &[(String, String)],
        body: &str,
    ) {
        let mut response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            http_status_text(status),
            body.len(),
        );
        for (name, value) in headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(body);
        stream.write_all(response.as_bytes()).test_unwrap();
    }

    fn http_status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            502 => "Bad Gateway",
            _ => "Unknown",
        }
    }

    #[test]
    fn build_routes_from_petstore() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
        assert!(!routes.is_empty());

        // Should have GET and POST for /pets, GET and DELETE for /pets/{petId}
        let get_pets = routes.iter().find(|r| {
            r.method == HttpMethod::Get
                && r.pattern.contains("/pets")
                && !r.pattern.contains("{petId}")
        });
        assert!(get_pets.is_some());

        let post_pets = routes.iter().find(|r| r.method == HttpMethod::Post);
        assert!(post_pets.is_some());
        assert_eq!(
            post_pets.map(|r| r.policy),
            Some(PolicyDecision::DenyByDefault)
        );

        let delete_pet = routes.iter().find(|r| r.method == HttpMethod::Delete);
        assert!(delete_pet.is_some());
    }

    #[test]
    fn get_routes_allowed_by_default() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
        let get_routes: Vec<_> = routes
            .iter()
            .filter(|r| r.method == HttpMethod::Get)
            .collect();
        for route in get_routes {
            assert_eq!(route.policy, PolicyDecision::SessionAllow);
        }
    }

    #[test]
    fn side_effect_routes_denied_by_default() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
        let mut_routes: Vec<_> = routes
            .iter()
            .filter(|r| r.method.requires_capability())
            .collect();
        for route in mut_routes {
            assert_eq!(route.policy, PolicyDecision::DenyByDefault);
        }
    }

    #[test]
    fn x_chio_side_effects_true_overrides_safe_method() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /dangerous-read:
    get:
      operationId: dangerousRead
      x-chio-side-effects: true
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/dangerous-read" && route.method == HttpMethod::Get)
            .test_unwrap();

        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }

    #[test]
    fn x_chio_side_effects_false_overrides_mutating_method() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /safe-post:
    post:
      operationId: safePost
      x-chio-side-effects: false
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/safe-post" && route.method == HttpMethod::Post)
            .test_unwrap();

        assert_eq!(route.policy, PolicyDecision::SessionAllow);
    }

    #[test]
    fn x_chio_approval_required_forces_deny() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /approved-read:
    get:
      operationId: approvedRead
      x-chio-side-effects: false
      x-chio-approval-required: true
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/approved-read" && route.method == HttpMethod::Get)
            .test_unwrap();

        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }

    #[test]
    fn forwarded_query_string_strips_chio_capability() {
        let token = signed_capability_token_json(&Keypair::generate(), "cap-query");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("source", "test")
            .append_pair("chio_capability", &token)
            .append_pair("mode", "full")
            .finish();

        assert_eq!(
            forwarded_query_string(Some(&query)).as_deref(),
            Some("source=test&mode=full")
        );
    }

    #[tokio::test]
    async fn evaluation_error_response_surfaces_pending_approval_state() {
        let response = evaluation_error_response(&ProtectError::PendingApproval {
            approval_id: Some("ap-123".to_string()),
            kernel_receipt_id: "kr-456".to_string(),
        });
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_approval_required");
        assert_eq!(json["approval_id"], "ap-123");
        assert_eq!(json["kernel_receipt_id"], "kr-456");
        assert_eq!(json["resume_path"], "/approvals/ap-123/respond");
    }

    #[tokio::test]
    async fn approval_routes_are_handled_before_proxy_catch_all() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let (approval, subject, approver) = pending_approval_request("ap-route-1");
        state
            .approval_admin
            .store()
            .store_pending(&approval)
            .test_unwrap();

        let token = signed_approval_response_token(
            &approval.approval_id,
            &subject,
            &approver,
            GovernedApprovalDecision::Approved,
        );
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri(format!("/approvals/{}/respond", approval.approval_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&RespondRequest {
                        outcome: ApprovalOutcome::Approved,
                        reason: Some("approved".to_string()),
                        approver: approver.public_key(),
                        token,
                    })
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let response = build_app(Arc::clone(&state))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: RespondResponse = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json.approval_id, "ap-route-1");
        assert_eq!(json.outcome, ApprovalOutcome::Approved);
        assert!(state
            .approval_admin
            .store()
            .get_pending("ap-route-1")
            .test_unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn approval_routes_reject_remote_callers_without_control_access() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

        let request = with_peer_addr(
            Request::builder()
                .method("GET")
                .uri("/approvals/pending")
                .body(Body::empty())
                .test_unwrap(),
            remote,
        );

        let response = build_app(Arc::clone(&state))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_control_forbidden");
    }

    #[test]
    fn evaluator_and_approval_routes_share_the_same_store() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let evaluator_store = state.evaluator.approval_store();

        assert!(Arc::ptr_eq(&evaluator_store, state.approval_admin.store()));
    }

    #[tokio::test]
    async fn proxy_handler_denies_without_capability_and_records_receipt() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let receipt_id = response
            .headers()
            .get("x-chio-receipt-id")
            .and_then(|value| value.to_str().ok())
            .test_unwrap()
            .to_string();
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_access_denied");
        assert_eq!(
            json["suggestion"],
            "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter"
        );
        assert!(json["receipt_id"].as_str().is_some());

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].id, receipt_id);
        assert_eq!(log.receipts[0].response_status, 403);
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
        assert!(log.receipts[0].verify_signature().test_unwrap());
    }

    #[tokio::test]
    async fn proxy_handler_forwards_allowed_requests_and_end_to_end_headers() {
        let Some(server) = MockUpstreamServer::spawn(
            201,
            vec![("content-type", "application/json"), ("x-upstream", "ok")],
            r#"{"ok":true}"#,
        ) else {
            return;
        };
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            server.base_url(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets?source=test")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("user-agent", "chio-test")
            .header("authorization", "Bearer upstream-token")
            .header("x-request-id", "req-123")
            .header(
                "x-chio-capability",
                signed_capability_token_json(&state.signer_keypair, "cap-proxy"),
            )
            .header("x-custom-app", "secret")
            .header("connection", "keep-alive")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        let receipt_id = response
            .headers()
            .get("x-chio-receipt-id")
            .and_then(|value| value.to_str().ok())
            .test_unwrap()
            .to_string();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-upstream")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        assert_eq!(body.as_ref(), br#"{"ok":true}"#);

        let requests = server.requests();
        server.join();

        assert_eq!(requests.len(), 1);
        let request_text = requests[0].to_ascii_lowercase();
        assert!(request_text.contains("post /pets?source=test http/1.1"));
        assert!(request_text.contains("content-type: application/json"));
        assert!(request_text.contains("accept: application/json"));
        assert!(request_text.contains("user-agent: chio-test"));
        assert!(request_text.contains("authorization: bearer upstream-token"));
        assert!(request_text.contains("x-request-id: req-123"));
        assert!(request_text.contains("x-custom-app: secret"));
        assert!(!request_text.contains("x-chio-capability:"));
        assert!(!request_text.contains("connection: keep-alive"));
        assert!(request_text.contains(r#"{"name":"fido"}"#));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].id, receipt_id);
        assert_eq!(log.receipts[0].response_status, 201);
        assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-proxy"));
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn proxy_handler_strips_query_capability_before_forwarding_upstream() {
        let Some(server) =
            MockUpstreamServer::spawn(200, vec![("content-type", "application/json")], "{}")
        else {
            return;
        };
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            server.base_url(),
        );
        let token = signed_capability_token_json(&state.signer_keypair, "cap-query");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("source", "test")
            .append_pair("chio_capability", &token)
            .append_pair("mode", "full")
            .finish();
        let request = Request::builder()
            .method("POST")
            .uri(format!("/pets?{query}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let requests = server.requests();
        server.join();

        assert_eq!(requests.len(), 1);
        let request_text = requests[0].to_ascii_lowercase();
        assert!(request_text.contains("post /pets?source=test&mode=full http/1.1"));
        assert!(!request_text.contains("chio_capability"));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-query"));
    }

    #[tokio::test]
    async fn proxy_handler_rejects_unsupported_methods_before_evaluation() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let request = Request::builder()
            .method("TRACE")
            .uri("/pets")
            .body(Body::empty())
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        assert_eq!(body.as_ref(), b"unsupported method");
        let log = state.receipt_log.lock().await;
        assert!(log.receipts.is_empty());
    }

    #[tokio::test]
    async fn proxy_handler_surfaces_upstream_failures_after_allowing_request() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("GET")
            .uri("/pets")
            .body(Body::empty())
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let text = String::from_utf8(body.to_vec()).test_unwrap();
        assert!(text.contains("upstream error:"));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].response_status, 502);
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn proxy_handler_denies_invalid_capability_tokens() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .header("x-chio-capability", "not-json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_access_denied");

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert!(log.receipts[0].capability_id.is_none());
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn sidecar_evaluate_returns_200_with_deny_verdict() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let body = ChioHttpRequest::new(
            "req-sidecar-deny".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            chio_http_core::CallerIdentity::anonymous(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/chio/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap();

        let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
        assert!(evaluation.receipt.verify_signature().test_unwrap());
        assert!(evaluation.verdict.is_denied());
        assert!(evaluation.receipt.is_denied());
        assert_eq!(
            http_status_scope(evaluation.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[tokio::test]
    async fn sidecar_evaluate_validates_transport_capability_header() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let token = signed_capability_token_json(&state.signer_keypair, "cap-sidecar");
        let mut body = ChioHttpRequest::new(
            "req-sidecar-allow".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            chio_http_core::CallerIdentity::anonymous(),
        );
        body.capability_id = Some("cap-sidecar".to_string());
        let request = Request::builder()
            .method("POST")
            .uri("/chio/evaluate")
            .header("content-type", "application/json")
            .header("x-chio-capability", token)
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap();

        let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
        assert!(evaluation.verdict.is_allowed());
        assert_eq!(
            evaluation.receipt.capability_id.as_deref(),
            Some("cap-sidecar")
        );
        assert_eq!(
            http_status_scope(evaluation.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[tokio::test]
    async fn sidecar_verify_reports_signature_validity() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let keypair = Keypair::generate();
        let receipt = HttpReceipt::sign(
            chio_http_core::HttpReceiptBody {
                id: "receipt-verify".to_string(),
                request_id: "req-verify".to_string(),
                route_pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                caller_identity_hash: "caller-hash".to_string(),
                session_id: None,
                verdict: chio_http_core::Verdict::Allow,
                evidence: Vec::new(),
                response_status: 200,
                timestamp: 1_700_000_000,
                content_hash: "hash".to_string(),
                policy_hash: "policy".to_string(),
                capability_id: None,
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/chio/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
            .test_unwrap();

        let response = sidecar_verify_handler(State(state), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
        assert!(verification.valid);
    }

    #[tokio::test]
    async fn sidecar_mint_returns_canonical_capability_tokens() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let response = sidecar_mint_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let mint: SidecarMintResponse = serde_json::from_slice(&bytes).test_unwrap();

        assert_eq!(mint.capability.issuer, state.signer_keypair.public_key());
        assert_eq!(mint.capability.scope.grants.len(), 2);
        assert_eq!(mint.capability.scope.grants[0].server_id, "*");
        assert_eq!(mint.capability.scope.grants[0].tool_name, "search");
        assert!(mint.capability.verify_signature().test_unwrap());
    }

    #[tokio::test]
    async fn sidecar_mint_reuses_capability_id_for_retry_requests() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let request_body = serde_json::to_vec(&serde_json::json!({
            "subject": "job/default/demo",
            "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
            "job_uid": "job-uid-1",
            "ttl_seconds": 300,
        }))
        .test_unwrap();

        let first_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(request_body.clone()))
                .test_unwrap(),
        );
        let second_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .test_unwrap(),
        );

        let first_response = sidecar_mint_handler(State(Arc::clone(&state)), first_request).await;
        let second_response = sidecar_mint_handler(State(Arc::clone(&state)), second_request).await;
        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(second_response.status(), StatusCode::OK);

        let first_bytes = to_bytes(first_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let second_bytes = to_bytes(second_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let first_mint: SidecarMintResponse = serde_json::from_slice(&first_bytes).test_unwrap();
        let second_mint: SidecarMintResponse = serde_json::from_slice(&second_bytes).test_unwrap();

        assert_eq!(
            first_mint.capability.body().id,
            second_mint.capability.body().id
        );
    }

    #[tokio::test]
    async fn sidecar_mint_changes_capability_id_for_different_scope_requests() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

        let search_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );
        let fetch_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tool:server-a:fetch:invoke"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let search_response = sidecar_mint_handler(State(Arc::clone(&state)), search_request).await;
        let fetch_response = sidecar_mint_handler(State(Arc::clone(&state)), fetch_request).await;
        assert_eq!(search_response.status(), StatusCode::OK);
        assert_eq!(fetch_response.status(), StatusCode::OK);

        let search_bytes = to_bytes(search_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let fetch_bytes = to_bytes(fetch_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let search_mint: SidecarMintResponse = serde_json::from_slice(&search_bytes).test_unwrap();
        let fetch_mint: SidecarMintResponse = serde_json::from_slice(&fetch_bytes).test_unwrap();

        assert_ne!(
            search_mint.capability.body().id,
            fetch_mint.capability.body().id
        );
    }

    #[tokio::test]
    async fn sidecar_submit_receipt_accepts_controller_job_receipts() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/receipts")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "job_name": "demo",
                        "namespace": "default",
                        "job_uid": "job-uid-1",
                        "capability_id": "cap-1",
                        "outcome": "succeeded",
                        "started_at": "2026-04-17T10:00:00Z",
                        "completed_at": "2026-04-17T10:05:00Z",
                        "steps": [{
                            "pod_name": "demo-pod",
                            "phase": "Succeeded",
                            "payload": "{\"ok\":true}",
                            "observed_at": "2026-04-17T10:05:00Z"
                        }]
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let response = sidecar_submit_receipt_handler(State(state), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let receipt: SidecarSubmitReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
        assert!(receipt.accepted);
        assert!(!receipt.receipt_id.is_empty());
    }

    #[test]
    fn ttl_seconds_from_wire_accepts_seconds_and_nanoseconds() {
        assert_eq!(ttl_seconds_from_wire(None, None, None), 3600);
        assert_eq!(ttl_seconds_from_wire(Some(3600), None, None), 3600);
        assert_eq!(ttl_seconds_from_wire(None, Some(500_000_000), None), 1);
        assert_eq!(ttl_seconds_from_wire(None, None, Some(3600)), 3600);
        assert_eq!(
            ttl_seconds_from_wire(None, None, Some(3_600_000_000_000)),
            3600
        );
    }

    #[test]
    fn parse_sidecar_operation_shorthand_read_preserves_read_scope() {
        assert_eq!(
            parse_sidecar_operation("read", true).test_unwrap(),
            Operation::Read
        );
    }

    #[tokio::test]
    async fn sidecar_release_persists_revocation_and_blocks_reuse() {
        let receipt_db = temp_receipt_db_path();
        let state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );

        let release_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/release")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "capability_id": "cap-revoked",
                        "job_uid": "job-uid-1",
                        "reason": "completed",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );
        let release_response =
            sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
        assert_eq!(release_response.status(), StatusCode::OK);

        let reloaded = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .header(
                "x-chio-capability",
                signed_capability_token_json(&reloaded.signer_keypair, "cap-revoked"),
            )
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();
        let response = proxy_handler(State(Arc::clone(&reloaded)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["message"], "capability token has been revoked");

        let _ = std::fs::remove_file(receipt_db);
    }

    #[tokio::test]
    async fn sidecar_release_requires_persistent_receipt_store() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );

        let release_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/release")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "capability_id": "cap-revoked",
                        "job_uid": "job-uid-1",
                        "reason": "completed",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );
        let release_response =
            sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
        assert_eq!(release_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = to_bytes(release_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
        assert_eq!(
            json["message"],
            "persistent receipt_db must be configured for capability release"
        );

        assert!(!state
            .revoked_capability_ids
            .lock()
            .await
            .contains("cap-revoked"));
    }

    #[tokio::test]
    async fn sidecar_submit_receipt_persists_submitted_job_receipt() {
        let receipt_db = temp_receipt_db_path();
        let state = test_state_with_receipt_db(
            Vec::new(),
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/receipts")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "job_name": "demo",
                        "namespace": "default",
                        "job_uid": "job-uid-1",
                        "capability_id": "cap-1",
                        "outcome": "succeeded",
                        "started_at": "2026-04-17T10:00:00Z",
                        "completed_at": "2026-04-17T10:05:00Z",
                        "steps": [{
                            "pod_name": "demo-pod",
                            "phase": "Succeeded",
                            "payload": "{\"ok\":true}",
                            "observed_at": "2026-04-17T10:05:00Z"
                        }]
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let response = sidecar_submit_receipt_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let submit_response: SidecarSubmitReceiptResponse =
            serde_json::from_slice(&bytes).test_unwrap();

        let reloaded = test_state_with_receipt_db(
            Vec::new(),
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let log = reloaded.receipt_log.lock().await;
        let stored = log
            .receipts
            .iter()
            .find(|receipt| receipt.id == submit_response.receipt_id)
            .test_unwrap();
        assert_eq!(stored.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(
            stored.metadata.as_ref().test_unwrap()["job_uid"],
            "job-uid-1"
        );
        assert_eq!(
            stored.metadata.as_ref().test_unwrap()["steps"][0]["pod_name"],
            "demo-pod"
        );
        assert!(stored.verify_signature().test_unwrap());

        let _ = std::fs::remove_file(receipt_db);
    }

    #[tokio::test]
    async fn sidecar_control_endpoints_reject_non_loopback_callers() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

        let mint_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
        assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

        let release_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/release")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "capability_id": "cap-revoked",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let release_response =
            sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
        assert_eq!(release_response.status(), StatusCode::FORBIDDEN);

        let receipt_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/receipts")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "job_name": "demo",
                        "namespace": "default",
                        "job_uid": "job-uid-1",
                        "outcome": "succeeded",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let receipt_response =
            sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
        assert_eq!(receipt_response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(receipt_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_control_forbidden");
        assert_eq!(
            json["message"],
            "sidecar control endpoints require a loopback caller"
        );
    }

    #[tokio::test]
    async fn sidecar_control_endpoints_allow_authenticated_non_loopback_callers() {
        let receipt_db = temp_receipt_db_path();
        let mut state = test_state_with_receipt_db(
            Vec::new(),
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
            Some("cluster-control-token".to_string());
        let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

        let mint_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .header("authorization", "Bearer cluster-control-token")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
        assert_eq!(mint_response.status(), StatusCode::OK);

        let release_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/release")
                .header("content-type", "application/json")
                .header("authorization", "Bearer cluster-control-token")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "capability_id": "cap-revoked",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let release_response =
            sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
        assert_eq!(release_response.status(), StatusCode::OK);

        let receipt_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/receipts")
                .header("content-type", "application/json")
                .header("authorization", "Bearer cluster-control-token")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "job_name": "demo",
                        "namespace": "default",
                        "job_uid": "job-uid-1",
                        "outcome": "succeeded",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );
        let receipt_response =
            sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
        assert_eq!(receipt_response.status(), StatusCode::OK);

        let _ = std::fs::remove_file(receipt_db);
    }

    #[tokio::test]
    async fn sidecar_control_endpoints_accept_lowercase_bearer_scheme() {
        let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
            Some("cluster-control-token".to_string());
        let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

        let mint_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .header("authorization", "bearer cluster-control-token")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );

        let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
        assert_eq!(mint_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sidecar_control_endpoints_require_bearer_auth_for_loopback_when_configured() {
        let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
            Some("cluster-control-token".to_string());

        let mint_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
        );

        let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
        assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_control_forbidden");
        assert_eq!(
            json["message"],
            "sidecar control endpoints require a loopback caller or valid bearer token"
        );
    }

    #[tokio::test]
    async fn sidecar_control_endpoints_reject_blank_control_token_configuration() {
        let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        Arc::get_mut(&mut state).test_unwrap().sidecar_control_token = Some("   ".to_string());
        let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

        let mint_request = with_peer_addr(
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("content-type", "application/json")
                .header("authorization", "Bearer ")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "subject": "job/default/demo",
                        "scopes": ["tools:search"],
                        "job_uid": "job-uid-1",
                    }))
                    .test_unwrap(),
                ))
                .test_unwrap(),
            remote,
        );

        let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
        assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(json["error"], "chio_control_forbidden");
    }

    #[test]
    fn sidecar_control_bearer_token_compare_is_constant_time_safe() {
        // Regression test: bearer-token comparison must use a constant-time
        // primitive so callers cannot recover the configured token through
        // response timing differences. We exercise both equal and prefix-
        // matching tokens to confirm the byte compare path is reached.
        let request = |header: &str| {
            Request::builder()
                .method("POST")
                .uri("/v1/capabilities/mint")
                .header("authorization", header)
                .body(Body::empty())
                .test_unwrap()
        };

        let configured = "cluster-control-token";
        assert!(sidecar_control_bearer_token_matches(
            &request(&format!("Bearer {configured}")),
            configured,
        ));
        assert!(!sidecar_control_bearer_token_matches(
            &request("Bearer cluster-control-toxen"),
            configured,
        ));
        assert!(!sidecar_control_bearer_token_matches(
            &request("Bearer cluster-control"),
            configured,
        ));
        assert!(!sidecar_control_bearer_token_matches(
            &request("Bearer "),
            configured,
        ));
    }

    #[tokio::test]
    async fn proxy_handler_persists_receipts_when_receipt_db_configured() {
        let receipt_db = temp_receipt_db_path();
        let state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let reloaded = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let log = reloaded.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert!(log.receipts[0].verify_signature().test_unwrap());

        let _ = std::fs::remove_file(receipt_db);
    }

    #[tokio::test]
    async fn persisted_receipts_are_visible_across_proxy_and_sidecar_flows() {
        let receipt_db = temp_receipt_db_path();
        let proxy_state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let denied_request = Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Body::from(r#"{"name":"fido"}"#))
            .test_unwrap();
        let denied_response = proxy_handler(State(Arc::clone(&proxy_state)), denied_request).await;
        assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

        let sidecar_state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        {
            let log = sidecar_state.receipt_log.lock().await;
            assert_eq!(log.receipts.len(), 1);
        }

        let body = ChioHttpRequest::new(
            "req-sidecar-persisted".to_string(),
            HttpMethod::Get,
            "/pets".to_string(),
            "/pets".to_string(),
            chio_http_core::CallerIdentity::anonymous(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/chio/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap();

        let response = sidecar_evaluate_handler(State(Arc::clone(&sidecar_state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let reloaded = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let log = reloaded.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 2);

        let _ = std::fs::remove_file(receipt_db);
    }
}
