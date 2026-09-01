use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(test)]
use axum::body::to_bytes;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, OriginalUri, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::{
    HostedAuthCredential, HostedAuthRequest, HostedAuthenticator, HostedEdgeError,
    HostedHttpMethod, HostedMutationOutcome, HostedMutationResponse, HostedPrincipalRole,
    HostedRequestContract, HostedTenantBinding, HOSTED_TENANT_HEADER,
};

const REQUEST_ID_HEADER: &str = "Chio-Request-ID";
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
const API_KEY_ID_HEADER: &str = "Chio-API-Key-ID";
const API_KEY_SECRET_HEADER: &str = "Chio-API-Key-Secret";
const CAPABILITY_HEADER: &str = "Chio-Capability";
const DPOP_HEADER: &str = "Chio-DPoP";
const PROXY_AUTHENTICATION_HEADER: &str = "Chio-Proxy-Authentication";
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const HOSTED_RELEASE_IDENTITY_SCHEMA: &str = "chio.finding.hosted-release-identity.v1";
pub const HOSTED_AUTHENTICATED_DELIVERY_SCHEMA: &str =
    "chio.finding.hosted-authenticated-delivery.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedReleaseIdentity {
    pub schema: String,
    pub deployment_id: String,
    pub candidate_sha: String,
    pub artifact_sha256: String,
    pub configuration_revision: String,
}

impl HostedReleaseIdentity {
    fn validate(&self) -> Result<(), HostedEdgeError> {
        if self.schema != HOSTED_RELEASE_IDENTITY_SCHEMA
            || self.deployment_id.is_empty()
            || self.deployment_id.len() > 256
            || self.candidate_sha.len() != 40
            || !self
                .candidate_sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.artifact_sha256.len() != 64
            || !self
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.configuration_revision.is_empty()
            || self.configuration_revision.len() > 256
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HostedHttpServerConfig {
    pub public_endpoint: String,
    pub maximum_body_bytes: usize,
    pub penalty_authority_id: String,
    pub penalty_authority_key: PublicKey,
    pub kernel_receipt_key: PublicKey,
    pub release_identity: HostedReleaseIdentity,
}

impl HostedHttpServerConfig {
    fn validate(&self) -> Result<(), HostedEdgeError> {
        let endpoint =
            url::Url::parse(&self.public_endpoint).map_err(|_| HostedEdgeError::Configuration)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || endpoint.as_str().trim_end_matches('/') != self.public_endpoint
            || self.maximum_body_bytes == 0
            || self.maximum_body_bytes > MAX_BODY_BYTES
            || self.penalty_authority_id.is_empty()
            || self.penalty_authority_id.len() > 256
            || self.penalty_authority_id.trim() != self.penalty_authority_id
            || self.penalty_authority_id.chars().any(char::is_control)
            || self.penalty_authority_key.is_weak_ed25519()
            || self.kernel_receipt_key.is_weak_ed25519()
        {
            return Err(HostedEdgeError::Configuration);
        }
        self.release_identity.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedDomainMutation {
    pub aggregate_id: String,
    pub event_id: String,
    pub expected_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_event_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_signer_key: Option<PublicKey>,
    #[serde(skip)]
    pub artifact_authority_id: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedAuthenticatedFindingDelivery {
    pub schema: String,
    pub receipt: ChioReceipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedHttpBackendOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedHttpProjection {
    pub event_kind: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub event_id: String,
    pub revision: u64,
    pub previous_event_sha256: Option<String>,
    pub event_sha256: String,
    pub artifact_schema: String,
    pub artifact_sha256: String,
    pub payload: serde_json::Value,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedHttpPage {
    pub items: Vec<HostedHttpProjection>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostedHttpBackendError {
    #[error("hosted backend input is invalid")]
    Invalid,
    #[error("hosted backend resource was not found")]
    NotFound,
    #[error("hosted backend mutation conflicts")]
    Conflict,
    #[error("hosted backend capacity is exhausted")]
    Capacity,
    #[error("hosted backend integrity check failed")]
    Integrity,
    #[error("hosted backend is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait HostedHttpBackend: Send + Sync {
    async fn ready(&self) -> Result<(), HostedHttpBackendError>;

    async fn append(
        &self,
        tenant: &crate::HostedTenantId,
        event_kind: &str,
        aggregate_kind: &str,
        mutation: &HostedDomainMutation,
        committed_at: u64,
    ) -> Result<HostedHttpBackendOutcome, HostedHttpBackendError>;

    async fn finding(
        &self,
        tenant: &crate::HostedTenantId,
        finding_id: &str,
    ) -> Result<Option<HostedHttpProjection>, HostedHttpBackendError>;

    async fn findings(
        &self,
        tenant: &crate::HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedHttpPage, HostedHttpBackendError>;

    async fn non_live_findings(
        &self,
        tenant: &crate::HostedTenantId,
        finding_ids: &[String],
    ) -> Result<BTreeSet<String>, HostedHttpBackendError>;
}

#[derive(Clone)]
pub struct HostedHttpServerState {
    config: HostedHttpServerConfig,
    authenticator: Arc<HostedAuthenticator>,
    backend: Arc<dyn HostedHttpBackend>,
    trusted_proxy: Arc<crate::HostedTrustedProxy>,
}

impl HostedHttpServerState {
    pub fn new(
        config: HostedHttpServerConfig,
        authenticator: Arc<HostedAuthenticator>,
        backend: Arc<dyn HostedHttpBackend>,
        trusted_proxy: Arc<crate::HostedTrustedProxy>,
    ) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        Ok(Self {
            config,
            authenticator,
            backend,
            trusted_proxy,
        })
    }
}

#[derive(Clone, Copy)]
struct HostedOperation {
    event_kind: &'static str,
    aggregate_kind: &'static str,
    artifact_schema: &'static str,
    action: &'static str,
    role: HostedPrincipalRole,
}

const PUBLISH_OPERATION: HostedOperation = HostedOperation {
    event_kind: "finding.published",
    aggregate_kind: "finding",
    artifact_schema: "chio.finding.v1",
    action: "finding.publish",
    role: HostedPrincipalRole::Seller,
};

impl HostedOperation {
    fn parse(value: &str) -> Option<Self> {
        let operation = match value {
            "listing" => (
                "listing.activated",
                "listing",
                "chio.finding.market-terms.v1",
                "finding.listing.activate",
                HostedPrincipalRole::Seller,
            ),
            "delivery" => (
                "delivery.accepted",
                "delivery",
                HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
                "finding.delivery.accept",
                HostedPrincipalRole::Operator,
            ),
            "challenge" => (
                "challenge.submitted",
                "challenge",
                "chio.finding.challenge.v1",
                "finding.challenge.submit",
                HostedPrincipalRole::Buyer,
            ),
            "verified-fix" => (
                "verified_fix.submitted",
                "verified_fix",
                "chio.finding.verified-fix-submission.v1",
                "finding.verified_fix.submit",
                HostedPrincipalRole::Seller,
            ),
            "retraction" => (
                "retraction.voluntary",
                "retraction",
                "chio.finding.voluntary-retraction.v1",
                "finding.retraction.submit",
                HostedPrincipalRole::Seller,
            ),
            "penalty" => (
                "penalty.assessed",
                "penalty",
                "chio.registry.market-penalty.v1",
                "finding.penalty.assess",
                HostedPrincipalRole::Operator,
            ),
            _ => return None,
        };
        Some(Self {
            event_kind: operation.0,
            aggregate_kind: operation.1,
            artifact_schema: operation.2,
            action: operation.3,
            role: operation.4,
        })
    }

    fn requires_principal_artifact_signer(self) -> bool {
        self.artifact_schema != HOSTED_AUTHENTICATED_DELIVERY_SCHEMA
    }
}

fn authenticated_artifact_signer(
    operation: HostedOperation,
    principal: &crate::HostedAuthenticatedPrincipal,
    requested_signer: Option<&PublicKey>,
    penalty_authority_key: &PublicKey,
) -> Result<Option<PublicKey>, HostedEdgeError> {
    if !operation.requires_principal_artifact_signer() {
        return if requested_signer.is_none() {
            Ok(None)
        } else {
            Err(HostedEdgeError::InvalidRequest)
        };
    }
    let trusted_signer = principal
        .artifact_signer_key
        .as_ref()
        .ok_or(HostedEdgeError::AuthorizationFailed)?;
    if requested_signer != Some(trusted_signer) {
        return Err(HostedEdgeError::AuthorizationFailed);
    }
    if operation.event_kind == "penalty.assessed" && trusted_signer != penalty_authority_key {
        return Err(HostedEdgeError::AuthorizationFailed);
    }
    Ok(Some(trusted_signer.clone()))
}

fn authenticated_artifact_authority(
    operation: HostedOperation,
    principal: &crate::HostedAuthenticatedPrincipal,
    payload: &serde_json::Value,
    penalty_authority_id: &str,
) -> Result<Option<String>, HostedEdgeError> {
    if operation.event_kind != "penalty.assessed" {
        return Ok(None);
    }
    let body = payload
        .get("body")
        .and_then(serde_json::Value::as_object)
        .ok_or(HostedEdgeError::InvalidRequest)?;
    if principal.principal_id != penalty_authority_id
        || body.get("issuedBy").and_then(serde_json::Value::as_str) != Some(penalty_authority_id)
        || body
            .get("governingOperatorId")
            .and_then(serde_json::Value::as_str)
            != Some(penalty_authority_id)
    {
        return Err(HostedEdgeError::AuthorizationFailed);
    }
    Ok(Some(penalty_authority_id.to_owned()))
}

struct FindingQuery {
    after: Option<String>,
    limit: Option<u32>,
}

pub fn hosted_market_router(state: HostedHttpServerState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/release", get(release_identity))
        .route("/v1/findings", get(list_findings))
        .route("/v1/findings/{finding_id}", get(get_finding))
        .route("/v1/findings/events/{operation}", post(mutate))
        .route("/v1/findings/publish", post(publish))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_trusted_proxy,
        ))
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(
            state.config.maximum_body_bytes,
        ))
}

/// Serve the authenticated edge only on a loopback socket. The public TLS
/// endpoint must terminate at the separately authenticated trusted proxy.
pub async fn serve_hosted_market_loopback(
    listener: tokio::net::TcpListener,
    state: HostedHttpServerState,
) -> io::Result<()> {
    serve_hosted_market_loopback_with_shutdown(listener, state, std::future::pending()).await
}

pub async fn serve_hosted_market_loopback_with_shutdown<F>(
    listener: tokio::net::TcpListener,
    state: HostedHttpServerState,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hosted cognition-market edge requires an authenticated loopback proxy",
        ));
    }
    axum::serve(
        listener,
        hosted_market_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

async fn enforce_trusted_proxy(
    State(state): State<HostedHttpServerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let result = (|| {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connection| connection.0.ip())
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        let forwarding = crate::HostedForwardingHeaders {
            forwarded: header_strings(request.headers(), "Forwarded")?,
            x_forwarded_for: header_strings(request.headers(), "X-Forwarded-For")?,
            x_forwarded_host: header_strings(request.headers(), "X-Forwarded-Host")?,
            x_forwarded_proto: header_strings(request.headers(), "X-Forwarded-Proto")?,
        };
        state.trusted_proxy.reconstruct(
            peer,
            &forwarding,
            single_header(request.headers(), PROXY_AUTHENTICATION_HEADER),
        )
    })();
    match result {
        Ok(context) => {
            let mut request = request;
            for name in [
                "Forwarded",
                "X-Forwarded-For",
                "X-Forwarded-Host",
                "X-Forwarded-Proto",
                PROXY_AUTHENTICATION_HEADER,
            ] {
                request.headers_mut().remove(name);
            }
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(error) => error_response(error, "proxy-authentication"),
    }
}

fn header_strings(headers: &HeaderMap, name: &str) -> Result<Vec<String>, HostedEdgeError> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| HostedEdgeError::InvalidRequest)
        })
        .collect()
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "live"})))
}

async fn ready(State(state): State<HostedHttpServerState>) -> Response {
    match state.backend.ready().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready"})),
        )
            .into_response(),
    }
}

async fn not_found() -> Response {
    error_response(HostedEdgeError::InvalidRequest, "route-not-found")
}

async fn release_identity(
    State(state): State<HostedHttpServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request_id = single_header(&headers, REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
    let result = async {
        let now = unix_now()?;
        authenticate(
            &state,
            &headers,
            &uri,
            "finding.release.read",
            HostedHttpMethod::Get,
            HostedPrincipalRole::Buyer,
            sha256_hex(&[]),
            None,
            now,
        )
        .await?;
        Ok::<_, HostedEdgeError>(state.config.release_identity.clone())
    }
    .await;
    match result {
        Ok(identity) => (StatusCode::OK, Json(identity)).into_response(),
        Err(error) => error_response(error, request_id),
    }
}

async fn publish(
    state: State<HostedHttpServerState>,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    publish_inner(state.0, uri.0, headers, body).await
}

async fn publish_inner(
    state: HostedHttpServerState,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = single_header(&headers, REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
    let result = async {
        let canonical_body = strict_canonical_body(&body)?;
        let finding: chio_finding::Finding =
            serde_json::from_slice(&canonical_body).map_err(|_| HostedEdgeError::InvalidRequest)?;
        chio_finding::verify_finding(&finding).map_err(|_| HostedEdgeError::InvalidRequest)?;
        let received_at = unix_now()?;
        let operation = PUBLISH_OPERATION;
        let event_id = required_header(&headers, IDEMPOTENCY_KEY_HEADER)?.to_owned();
        let principal = authenticate(
            &state,
            &headers,
            &uri,
            operation.action,
            HostedHttpMethod::Post,
            operation.role,
            sha256_hex(&canonical_body),
            Some(&event_id),
            received_at,
        )
        .await?;
        if principal.artifact_signer_key.as_ref() != Some(&finding.issuer) {
            return Err(HostedEdgeError::AuthorizationFailed);
        }
        let binding = tenant_binding(&headers)?;
        let contract = HostedRequestContract::new(
            &binding,
            &principal,
            required_header(&headers, REQUEST_ID_HEADER)?,
            operation.action,
            HostedHttpMethod::Post,
            canonical_target(&state.config.public_endpoint, &uri)?,
            sha256_hex(&canonical_body),
            Some(event_id.clone()),
            received_at,
        )?;
        let payload =
            serde_json::from_slice(&canonical_body).map_err(|_| HostedEdgeError::InvalidRequest)?;
        let mutation = HostedDomainMutation {
            aggregate_id: finding.finding_id.clone(),
            event_id,
            expected_revision: 0,
            expected_event_sha256: None,
            artifact_signer_key: principal.artifact_signer_key,
            artifact_authority_id: None,
            payload,
        };
        let outcome = state
            .backend
            .append(
                binding.tenant_id(),
                operation.event_kind,
                operation.aggregate_kind,
                &mutation,
                received_at,
            )
            .await
            .map_err(map_backend)?;
        mutation_response(contract, binding, mutation, outcome)
    }
    .await;
    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error_response(error, request_id),
    }
}

async fn mutate(
    state: State<HostedHttpServerState>,
    Path(operation): Path<String>,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mutate_inner(
        state.0,
        uri.0,
        headers,
        body,
        HostedOperation::parse(&operation),
    )
    .await
}

async fn mutate_inner(
    state: HostedHttpServerState,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
    operation: Option<HostedOperation>,
) -> Response {
    let request_id = single_header(&headers, REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
    let result = async {
        let operation = operation.ok_or(HostedEdgeError::InvalidRequest)?;
        let canonical_body = strict_canonical_body(&body)?;
        let mutation: HostedDomainMutation =
            serde_json::from_slice(&canonical_body).map_err(|_| HostedEdgeError::InvalidRequest)?;
        if mutation
            .payload
            .get("schema")
            .and_then(serde_json::Value::as_str)
            != Some(operation.artifact_schema)
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let received_at = unix_now()?;
        let idempotency_key = required_header(&headers, IDEMPOTENCY_KEY_HEADER)?.to_owned();
        let principal = authenticate(
            &state,
            &headers,
            &uri,
            operation.action,
            HostedHttpMethod::Post,
            operation.role,
            sha256_hex(&canonical_body),
            Some(&idempotency_key),
            received_at,
        )
        .await?;
        let binding = tenant_binding(&headers)?;
        let contract = HostedRequestContract::new(
            &binding,
            &principal,
            required_header(&headers, REQUEST_ID_HEADER)?,
            operation.action,
            HostedHttpMethod::Post,
            canonical_target(&state.config.public_endpoint, &uri)?,
            sha256_hex(&canonical_body),
            Some(idempotency_key),
            received_at,
        )?;
        if mutation.event_id != contract.idempotency_key().unwrap_or_default() {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let trusted_signer = authenticated_artifact_signer(
            operation,
            &principal,
            mutation.artifact_signer_key.as_ref(),
            &state.config.penalty_authority_key,
        )?;
        let mut mutation = mutation;
        mutation.artifact_signer_key = if operation.event_kind == "delivery.accepted" {
            Some(state.config.kernel_receipt_key.clone())
        } else {
            trusted_signer
        };
        mutation.artifact_authority_id = authenticated_artifact_authority(
            operation,
            &principal,
            &mutation.payload,
            &state.config.penalty_authority_id,
        )?;
        let outcome = state
            .backend
            .append(
                binding.tenant_id(),
                operation.event_kind,
                operation.aggregate_kind,
                &mutation,
                received_at,
            )
            .await
            .map_err(map_backend)?;
        mutation_response(contract, binding, mutation, outcome)
    }
    .await;
    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error_response(error, request_id),
    }
}

async fn get_finding(
    State(state): State<HostedHttpServerState>,
    Path(finding_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request_id = single_header(&headers, REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
    let result = async {
        let binding = tenant_binding(&headers)?;
        let requested_at = unix_now()?;
        authenticate(
            &state,
            &headers,
            &uri,
            "finding.read",
            HostedHttpMethod::Get,
            HostedPrincipalRole::Buyer,
            sha256_hex(&[]),
            None,
            requested_at,
        )
        .await?;
        let projection = state
            .backend
            .finding(binding.tenant_id(), &finding_id)
            .await
            .map_err(map_backend)?
            .ok_or(HostedEdgeError::NotFound)?;
        let payload =
            live_finding_payload(&projection, requested_at)?.ok_or(HostedEdgeError::NotFound)?;
        let non_live = state
            .backend
            .non_live_findings(binding.tenant_id(), std::slice::from_ref(&finding_id))
            .await
            .map_err(map_backend)?;
        ensure_non_live_subset(std::slice::from_ref(&finding_id), &non_live)?;
        if non_live.contains(&finding_id) {
            return Err(HostedEdgeError::NotFound);
        }
        Ok(payload)
    }
    .await;
    match result {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => error_response(error, request_id),
    }
}

async fn list_findings(
    State(state): State<HostedHttpServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request_id = single_header(&headers, REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
    let result = async {
        let binding = tenant_binding(&headers)?;
        let query = parse_finding_query(uri.query())?;
        let requested_at = unix_now()?;
        authenticate(
            &state,
            &headers,
            &uri,
            "finding.search",
            HostedHttpMethod::Get,
            HostedPrincipalRole::Buyer,
            sha256_hex(&[]),
            None,
            requested_at,
        )
        .await?;
        let mut page = state
            .backend
            .findings(
                binding.tenant_id(),
                query.after.as_deref(),
                query.limit.unwrap_or(50),
            )
            .await
            .map_err(map_backend)?;
        page.items = page
            .items
            .into_iter()
            .map(|projection| {
                live_finding_payload(&projection, requested_at)
                    .map(|payload| payload.map(|_| projection))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        let finding_ids = page
            .items
            .iter()
            .map(|projection| projection.aggregate_id.clone())
            .collect::<Vec<_>>();
        let non_live = state
            .backend
            .non_live_findings(binding.tenant_id(), &finding_ids)
            .await
            .map_err(map_backend)?;
        ensure_non_live_subset(&finding_ids, &non_live)?;
        page.items
            .retain(|projection| !non_live.contains(&projection.aggregate_id));
        Ok(page)
    }
    .await;
    match result {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => error_response(error, request_id),
    }
}

fn ensure_non_live_subset(
    requested: &[String],
    non_live: &BTreeSet<String>,
) -> Result<(), HostedEdgeError> {
    if non_live
        .iter()
        .all(|finding_id| requested.iter().any(|candidate| candidate == finding_id))
    {
        Ok(())
    } else {
        Err(HostedEdgeError::IntegrityFailure)
    }
}

fn mutation_response(
    contract: HostedRequestContract,
    binding: HostedTenantBinding,
    mutation: HostedDomainMutation,
    outcome: HostedHttpBackendOutcome,
) -> Result<HostedMutationResponse, HostedEdgeError> {
    let payload_sha256 = canonical_json_bytes(&mutation.payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| HostedEdgeError::InvalidRequest)?;
    let outcome = match outcome {
        HostedHttpBackendOutcome::Inserted => HostedMutationOutcome::Applied,
        HostedHttpBackendOutcome::ExactReplay => HostedMutationOutcome::ExactReplay,
    };
    HostedMutationResponse::new(
        contract.request_id(),
        binding.tenant_id().clone(),
        mutation.event_id,
        outcome,
        mutation.aggregate_id,
        payload_sha256,
    )
}

fn parse_finding_query(query: Option<&str>) -> Result<FindingQuery, HostedEdgeError> {
    let mut seen = BTreeSet::new();
    let mut after = None;
    let mut limit = None;
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if !seen.insert(name.to_string()) {
            return Err(HostedEdgeError::InvalidRequest);
        }
        match name.as_ref() {
            "after" if !value.is_empty() => after = Some(value.into_owned()),
            "limit" => {
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| HostedEdgeError::InvalidRequest)?;
                if !(1..=100).contains(&parsed) {
                    return Err(HostedEdgeError::InvalidRequest);
                }
                limit = Some(parsed);
            }
            _ => return Err(HostedEdgeError::InvalidRequest),
        }
    }
    Ok(FindingQuery { after, limit })
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    state: &HostedHttpServerState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    action: &str,
    method: HostedHttpMethod,
    role: HostedPrincipalRole,
    body_sha256: String,
    idempotency_key: Option<&str>,
    now_unix_secs: u64,
) -> Result<crate::HostedAuthenticatedPrincipal, HostedEdgeError> {
    let binding = tenant_binding(headers)?;
    let credential = credential(headers)?;
    state
        .authenticator
        .authenticate(HostedAuthRequest {
            tenant_id: binding.tenant_id().clone(),
            action: action.to_owned(),
            method: method.as_str().to_owned(),
            canonical_target: canonical_target(&state.config.public_endpoint, uri)?,
            body_sha256,
            idempotency_key: idempotency_key.map(str::to_owned),
            required_role: role,
            credential,
            now_unix_secs,
        })
        .await
}

fn live_finding_payload(
    projection: &HostedHttpProjection,
    now_unix_secs: u64,
) -> Result<Option<serde_json::Value>, HostedEdgeError> {
    if projection.event_kind != "finding.published"
        || projection.aggregate_kind != "finding"
        || projection.artifact_schema != "chio.finding.v1"
    {
        return Err(HostedEdgeError::IntegrityFailure);
    }
    let canonical =
        canonical_json_bytes(&projection.payload).map_err(|_| HostedEdgeError::IntegrityFailure)?;
    if sha256_hex(&canonical) != projection.artifact_sha256 {
        return Err(HostedEdgeError::IntegrityFailure);
    }
    let finding: chio_finding::Finding =
        serde_json::from_slice(&canonical).map_err(|_| HostedEdgeError::IntegrityFailure)?;
    chio_finding::verify_finding(&finding).map_err(|_| HostedEdgeError::IntegrityFailure)?;
    if finding.finding_id != projection.aggregate_id || finding.issued_at > now_unix_secs {
        return Err(HostedEdgeError::IntegrityFailure);
    }
    if finding.expires_at <= now_unix_secs {
        return Ok(None);
    }
    Ok(Some(projection.payload.clone()))
}

fn credential(headers: &HeaderMap) -> Result<HostedAuthCredential, HostedEdgeError> {
    let key_id = single_header(headers, API_KEY_ID_HEADER);
    let key_secret = single_header(headers, API_KEY_SECRET_HEADER);
    let capability = single_header(headers, CAPABILITY_HEADER);
    let dpop = single_header(headers, DPOP_HEADER);
    match (key_id, key_secret, capability, dpop) {
        (Some(key_id), Some(secret), None, None) => Ok(HostedAuthCredential::ApiKey {
            key_id: key_id.to_owned(),
            secret: secret.to_owned(),
        }),
        (None, None, Some(capability), Some(dpop)) => Ok(HostedAuthCredential::CapabilityDpop {
            capability: Box::new(decode_canonical_credential(capability)?),
            proof: Box::new(decode_canonical_credential(dpop)?),
        }),
        _ => Err(HostedEdgeError::AuthenticationFailed),
    }
}

fn decode_canonical_credential<T: serde::de::DeserializeOwned + Serialize>(
    encoded: &str,
) -> Result<T, HostedEdgeError> {
    if encoded.is_empty() || encoded.len() > MAX_CREDENTIAL_BYTES * 2 {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| HostedEdgeError::AuthenticationFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| HostedEdgeError::AuthenticationFailed)?;
    let canonical =
        canonical_json_bytes_from_str(text).map_err(|_| HostedEdgeError::AuthenticationFailed)?;
    if canonical != bytes {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    serde_json::from_slice(&canonical).map_err(|_| HostedEdgeError::AuthenticationFailed)
}

fn tenant_binding(headers: &HeaderMap) -> Result<HostedTenantBinding, HostedEdgeError> {
    HostedTenantBinding::from_header(single_header(headers, HOSTED_TENANT_HEADER))
}

fn strict_canonical_body(body: &[u8]) -> Result<Vec<u8>, HostedEdgeError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(HostedEdgeError::InvalidRequest);
    }
    let text = std::str::from_utf8(body).map_err(|_| HostedEdgeError::InvalidRequest)?;
    let canonical =
        canonical_json_bytes_from_str(text).map_err(|_| HostedEdgeError::InvalidRequest)?;
    if canonical != body {
        return Err(HostedEdgeError::InvalidRequest);
    }
    Ok(canonical)
}

fn canonical_target(base: &str, uri: &axum::http::Uri) -> Result<String, HostedEdgeError> {
    let suffix = uri
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        .ok_or(HostedEdgeError::InvalidRequest)?;
    Ok(format!("{base}{suffix}"))
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, HostedEdgeError> {
    single_header(headers, name).ok_or(HostedEdgeError::InvalidRequest)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    Some(value)
}

fn unix_now() -> Result<u64, HostedEdgeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HostedEdgeError::DependencyUnavailable)
}

fn map_backend(error: HostedHttpBackendError) -> HostedEdgeError {
    match error {
        HostedHttpBackendError::Invalid => HostedEdgeError::InvalidRequest,
        HostedHttpBackendError::NotFound => HostedEdgeError::NotFound,
        HostedHttpBackendError::Conflict => HostedEdgeError::Conflict,
        HostedHttpBackendError::Integrity => HostedEdgeError::IntegrityFailure,
        HostedHttpBackendError::Capacity => HostedEdgeError::CapacityUnavailable,
        HostedHttpBackendError::Unavailable => HostedEdgeError::DependencyUnavailable,
    }
}

fn error_response(error: HostedEdgeError, request_id: &str) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(error.body(request_id))).into_response()
}

#[cfg(test)]
mod tests {
    use chio_core_types::crypto::Keypair;
    use chio_finding_market_port::{
        HostedApiKeyRecord, HostedAuthPort, HostedCapabilityAdmissionOutcome,
        HostedMarketPortError, HostedPrincipal, HostedTenantId,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        HostedAuthMethod, HostedAuthenticatorConfig, HostedTenantAuthPolicy, StaticApiKeyPepper,
    };

    struct ClosedAuthPort;

    #[async_trait]
    impl HostedAuthPort for ClosedAuthPort {
        async fn principal_by_capability_key(
            &self,
            _tenant: &HostedTenantId,
            _public_key_hex: &str,
            _now: u64,
        ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
            Ok(None)
        }

        async fn principal(
            &self,
            _tenant: &HostedTenantId,
            _principal_id: &str,
        ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
            Ok(None)
        }

        async fn active_api_key(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _now: u64,
        ) -> Result<Option<HostedApiKeyRecord>, HostedMarketPortError> {
            Ok(None)
        }

        async fn consume_capability_dpop_admission(
            &self,
            _tenant: &HostedTenantId,
            _capability_id: &str,
            _nonce_sha256: &str,
            _valid_through: u64,
            _max_invocations: u32,
            _expires_at: u64,
            _now: u64,
            _tenant_nonce_capacity: u64,
        ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError> {
            Ok(HostedCapabilityAdmissionOutcome::Replay)
        }
    }

    struct ClosedBackend;

    #[async_trait]
    impl HostedHttpBackend for ClosedBackend {
        async fn ready(&self) -> Result<(), HostedHttpBackendError> {
            Err(HostedHttpBackendError::Unavailable)
        }

        async fn append(
            &self,
            _tenant: &HostedTenantId,
            _event_kind: &str,
            _aggregate_kind: &str,
            _mutation: &HostedDomainMutation,
            _committed_at: u64,
        ) -> Result<HostedHttpBackendOutcome, HostedHttpBackendError> {
            Err(HostedHttpBackendError::Unavailable)
        }

        async fn finding(
            &self,
            _tenant: &HostedTenantId,
            _finding_id: &str,
        ) -> Result<Option<HostedHttpProjection>, HostedHttpBackendError> {
            Err(HostedHttpBackendError::Unavailable)
        }

        async fn findings(
            &self,
            _tenant: &HostedTenantId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<HostedHttpPage, HostedHttpBackendError> {
            Err(HostedHttpBackendError::Unavailable)
        }

        async fn non_live_findings(
            &self,
            _tenant: &HostedTenantId,
            _finding_ids: &[String],
        ) -> Result<BTreeSet<String>, HostedHttpBackendError> {
            Err(HostedHttpBackendError::Unavailable)
        }
    }

    fn server_state() -> Result<HostedHttpServerState, HostedEdgeError> {
        let tenant =
            HostedTenantId::new("tenant:test").map_err(|_| HostedEdgeError::Configuration)?;
        let authority = Keypair::from_seed(&[47_u8; 32]);
        let authenticator = HostedAuthenticator::new(
            HostedAuthenticatorConfig {
                deployment_id: "deployment:test".to_owned(),
                public_endpoint: "https://market.example".to_owned(),
                capability_authorities: vec![authority.public_key()],
                maximum_capability_ttl_secs: 300,
                dpop_proof_ttl_secs: 30,
                dpop_clock_skew_secs: 5,
                dpop_nonce_capacity_per_tenant: 1_000,
                tenant_policies: vec![HostedTenantAuthPolicy {
                    tenant_id: tenant,
                    allowed_methods: [HostedAuthMethod::ApiKey].into_iter().collect(),
                }],
            },
            Arc::new(ClosedAuthPort),
            Arc::new(StaticApiKeyPepper::new(vec![9_u8; 32])?),
        )?;
        let state = HostedHttpServerState::new(
            HostedHttpServerConfig {
                public_endpoint: "https://market.example".to_owned(),
                maximum_body_bytes: 1024 * 1024,
                penalty_authority_id: "market-penalty".to_owned(),
                penalty_authority_key: authority.public_key(),
                kernel_receipt_key: authority.public_key(),
                release_identity: HostedReleaseIdentity {
                    schema: HOSTED_RELEASE_IDENTITY_SCHEMA.to_owned(),
                    deployment_id: "deployment:test".to_owned(),
                    candidate_sha: "a".repeat(40),
                    artifact_sha256: "b".repeat(64),
                    configuration_revision: "revision:test".to_owned(),
                },
            },
            Arc::new(authenticator),
            Arc::new(ClosedBackend),
            Arc::new(trusted_proxy()?),
        )?;
        Ok(state)
    }

    fn router() -> Result<Router, HostedEdgeError> {
        server_state().map(hosted_market_router)
    }

    fn trusted_proxy() -> Result<crate::HostedTrustedProxy, HostedEdgeError> {
        crate::HostedTrustedProxy::new(crate::HostedTrustedProxyConfig {
            listen: "127.0.0.1:8080"
                .parse()
                .map_err(|_| HostedEdgeError::Configuration)?,
            trusted_peer_ips: ["127.0.0.1"
                .parse()
                .map_err(|_| HostedEdgeError::Configuration)?]
            .into_iter()
            .collect(),
            public_endpoint: "https://market.example".to_owned(),
            authentication_token: vec![b'p'; 43],
        })
    }

    fn proxied_request(mut builder: axum::http::request::Builder, body: Body) -> Request<Body> {
        builder = builder
            .header(
                "Forwarded",
                "for=192.0.2.10;proto=https;host=market.example",
            )
            .header(PROXY_AUTHENTICATION_HEADER, "p".repeat(43));
        let mut request = builder
            .body(body)
            .unwrap_or_else(|error| panic!("test request failed: {error}"));
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000"
                .parse::<SocketAddr>()
                .unwrap_or_else(|error| panic!("test peer failed: {error}")),
        ));
        request
    }

    #[test]
    fn credential_modes_are_exactly_one_complete_pair() {
        let mut headers = HeaderMap::new();
        headers.insert(
            API_KEY_ID_HEADER,
            "key-1"
                .parse()
                .unwrap_or_else(|error| panic!("test header failed: {error}")),
        );
        headers.insert(
            API_KEY_SECRET_HEADER,
            "secret"
                .parse()
                .unwrap_or_else(|error| panic!("test header failed: {error}")),
        );
        assert!(matches!(
            credential(&headers),
            Ok(HostedAuthCredential::ApiKey { .. })
        ));
        headers.insert(
            CAPABILITY_HEADER,
            "also-present"
                .parse()
                .unwrap_or_else(|error| panic!("test header failed: {error}")),
        );
        assert!(credential(&headers).is_err());
    }

    #[test]
    fn penalty_authority_binds_principal_and_both_body_identities() {
        let principal = crate::HostedAuthenticatedPrincipal {
            tenant_id: HostedTenantId::new("tenant:test")
                .unwrap_or_else(|error| panic!("test tenant failed: {error}")),
            principal_id: "market-penalty".to_owned(),
            role: HostedPrincipalRole::Operator,
            method: HostedAuthMethod::ApiKey,
            credential_id: "key:test".to_owned(),
            artifact_signer_key: Some(Keypair::from_seed(&[49_u8; 32]).public_key()),
        };
        let operation = HostedOperation::parse("penalty")
            .unwrap_or_else(|| panic!("test penalty operation missing"));
        let payload = serde_json::json!({
            "schema": "chio.registry.market-penalty.v1",
            "body": {
                "issuedBy": "market-penalty",
                "governingOperatorId": "market-penalty"
            }
        });
        assert_eq!(
            authenticated_artifact_authority(operation, &principal, &payload, "market-penalty"),
            Ok(Some("market-penalty".to_owned()))
        );
        let substituted = serde_json::json!({
            "body": {
                "issuedBy": "market-penalty",
                "governingOperatorId": "other-operator"
            }
        });
        assert!(matches!(
            authenticated_artifact_authority(operation, &principal, &substituted, "market-penalty"),
            Err(HostedEdgeError::AuthorizationFailed)
        ));
    }

    #[test]
    fn operations_are_closed_and_role_bound() {
        let operations = [
            "listing",
            "delivery",
            "challenge",
            "verified-fix",
            "retraction",
            "penalty",
        ];
        let parsed = operations
            .iter()
            .filter_map(|operation| HostedOperation::parse(operation))
            .collect::<Vec<_>>();
        assert_eq!(parsed.len(), operations.len());
        assert!(HostedOperation::parse("publish").is_none());
        assert!(HostedOperation::parse("custom").is_none());
        assert_eq!(PUBLISH_OPERATION.role, HostedPrincipalRole::Seller);
        for internal_only in [
            "admission",
            "participation",
            "purchase",
            "reveal",
            "failed-delivery",
            "challenge-outcome",
            "liability",
            "appeal",
            "purchase-terminal",
            "enforcement",
            "settlement",
            "status",
            "audit",
        ] {
            assert!(HostedOperation::parse(internal_only).is_none());
        }
    }

    #[test]
    fn artifact_signer_is_pinned_to_the_authenticated_principal() {
        let pinned = Keypair::from_seed(&[48_u8; 32]).public_key();
        let untrusted = Keypair::from_seed(&[49_u8; 32]).public_key();
        let principal = crate::HostedAuthenticatedPrincipal {
            tenant_id: HostedTenantId::new("tenant:test")
                .unwrap_or_else(|error| panic!("test tenant failed: {error}")),
            principal_id: "seller:test".to_owned(),
            role: HostedPrincipalRole::Seller,
            method: HostedAuthMethod::ApiKey,
            credential_id: "key:test".to_owned(),
            artifact_signer_key: Some(pinned.clone()),
        };
        let Some(signed) = HostedOperation::parse("listing") else {
            panic!("test signed operation missing");
        };
        assert_eq!(
            authenticated_artifact_signer(signed, &principal, Some(&pinned), &pinned),
            Ok(Some(pinned.clone()))
        );
        assert_eq!(
            authenticated_artifact_signer(signed, &principal, Some(&untrusted), &pinned),
            Err(HostedEdgeError::AuthorizationFailed)
        );
        let Some(penalty) = HostedOperation::parse("penalty") else {
            panic!("test penalty operation missing");
        };
        assert_eq!(
            authenticated_artifact_signer(penalty, &principal, Some(&pinned), &untrusted),
            Err(HostedEdgeError::AuthorizationFailed)
        );
        let mut unpinned = principal.clone();
        unpinned.artifact_signer_key = None;
        assert_eq!(
            authenticated_artifact_signer(signed, &unpinned, Some(&pinned), &pinned),
            Err(HostedEdgeError::AuthorizationFailed)
        );
        let Some(unsigned) = HostedOperation::parse("delivery") else {
            panic!("test unsigned operation missing");
        };
        assert_eq!(
            authenticated_artifact_signer(unsigned, &principal, None, &pinned),
            Ok(None)
        );
        assert_eq!(
            authenticated_artifact_signer(unsigned, &principal, Some(&pinned), &pinned),
            Err(HostedEdgeError::InvalidRequest)
        );
    }

    #[test]
    fn finding_query_is_closed_bounded_and_unambiguous() {
        let query = parse_finding_query(Some("after=finding%3A1&limit=100"))
            .unwrap_or_else(|error| panic!("test query failed: {error}"));
        assert_eq!(query.after.as_deref(), Some("finding:1"));
        assert_eq!(query.limit, Some(100));
        assert!(parse_finding_query(Some("limit=1&limit=2")).is_err());
        assert!(parse_finding_query(Some("limit=0")).is_err());
        assert!(parse_finding_query(Some("topic=secret")).is_err());
        assert!(parse_finding_query(Some("after=")).is_err());
    }

    #[test]
    fn catalog_status_results_must_be_a_subset_of_the_request() {
        let requested = vec!["a".repeat(64)];
        assert!(ensure_non_live_subset(&requested, &BTreeSet::new()).is_ok());
        assert!(
            ensure_non_live_subset(&requested, &[requested[0].clone()].into_iter().collect())
                .is_ok()
        );
        assert_eq!(
            ensure_non_live_subset(&requested, &["b".repeat(64)].into_iter().collect()),
            Err(HostedEdgeError::IntegrityFailure)
        );
    }

    #[test]
    fn public_endpoint_is_an_origin_and_release_identity_is_exact() {
        let mut config = HostedHttpServerConfig {
            public_endpoint: "https://market.example/api".to_owned(),
            maximum_body_bytes: 1024,
            penalty_authority_id: "market-penalty".to_owned(),
            penalty_authority_key: Keypair::from_seed(&[47_u8; 32]).public_key(),
            kernel_receipt_key: Keypair::from_seed(&[48_u8; 32]).public_key(),
            release_identity: HostedReleaseIdentity {
                schema: HOSTED_RELEASE_IDENTITY_SCHEMA.to_owned(),
                deployment_id: "deployment:test".to_owned(),
                candidate_sha: "a".repeat(40),
                artifact_sha256: "b".repeat(64),
                configuration_revision: "revision:test".to_owned(),
            },
        };
        assert!(config.validate().is_err());
        config.public_endpoint = "https://market.example".to_owned();
        assert!(config.validate().is_ok());
        config.release_identity.candidate_sha = "a".repeat(39);
        assert!(config.validate().is_err());
    }

    #[test]
    fn catalog_projection_expires_and_corruption_fails_closed() {
        let raw = include_str!(
            "../../../../fixtures/proof-room/finding/cognition-market-qualified-profile/finding.json"
        );
        let payload: serde_json::Value = serde_json::from_str(raw)
            .unwrap_or_else(|error| panic!("test finding fixture failed: {error}"));
        let finding: chio_finding::Finding = serde_json::from_value(payload.clone())
            .unwrap_or_else(|error| panic!("test finding decode failed: {error}"));
        let canonical = canonical_json_bytes(&payload)
            .unwrap_or_else(|error| panic!("test finding canonicalization failed: {error}"));
        let mut projection = HostedHttpProjection {
            event_kind: "finding.published".to_owned(),
            aggregate_kind: "finding".to_owned(),
            aggregate_id: finding.finding_id.clone(),
            event_id: "event:test".to_owned(),
            revision: 1,
            previous_event_sha256: None,
            event_sha256: "c".repeat(64),
            artifact_schema: "chio.finding.v1".to_owned(),
            artifact_sha256: sha256_hex(&canonical),
            payload,
            committed_at: finding.issued_at,
        };
        assert!(matches!(
            live_finding_payload(&projection, finding.expires_at.saturating_sub(1)),
            Ok(Some(_))
        ));
        assert_eq!(
            live_finding_payload(&projection, finding.expires_at),
            Ok(None)
        );
        projection.artifact_sha256 = "d".repeat(64);
        assert_eq!(
            live_finding_payload(&projection, finding.issued_at),
            Err(HostedEdgeError::IntegrityFailure)
        );
    }

    #[tokio::test]
    async fn listener_refuses_non_loopback_binding() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .unwrap_or_else(|error| panic!("test listener failed: {error}"));
        let state =
            server_state().unwrap_or_else(|error| panic!("test server state failed: {error}"));
        let error = match serve_hosted_market_loopback(listener, state).await {
            Err(error) => error,
            Ok(()) => panic!("non-loopback listener must fail closed"),
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn trusted_proxy_is_authenticated_and_forwarding_is_closed() {
        let service =
            router().unwrap_or_else(|error| panic!("test trusted proxy router failed: {error}"));
        let request = || proxied_request(Request::builder().uri("/health/live"), Body::empty());
        let accepted = service
            .clone()
            .oneshot(request())
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(accepted.status(), StatusCode::OK);

        let mut spoofed = request();
        spoofed.headers_mut().insert(
            "X-Forwarded-For",
            axum::http::HeaderValue::from_static("192.0.2.11"),
        );
        let rejected = service
            .oneshot(spoofed)
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn router_returns_stable_fail_closed_errors() {
        let service = router().unwrap_or_else(|error| panic!("test router failed: {error}"));
        let missing_tenant = service
            .clone()
            .oneshot(proxied_request(
                Request::builder()
                    .uri("/v1/findings")
                    .header(REQUEST_ID_HEADER, "request-1"),
                Body::empty(),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(missing_tenant.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(missing_tenant.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|error| panic!("test body failed: {error}"));
        let error: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|error| panic!("test JSON failed: {error}"));
        assert_eq!(error["schema"], crate::HOSTED_ERROR_SCHEMA);
        assert_eq!(error["requestId"], "request-1");

        let noncanonical = service
            .oneshot(proxied_request(
                Request::builder()
                    .method("POST")
                    .uri("/v1/findings/publish")
                    .header(REQUEST_ID_HEADER, "request-2"),
                Body::from("{ \"payload\": {} }"),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(noncanonical.status(), StatusCode::BAD_REQUEST);
    }
}
