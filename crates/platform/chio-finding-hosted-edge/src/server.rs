use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::crypto::PublicKey;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::{
    HostedAuthCredential, HostedAuthRequest, HostedAuthenticator, HostedDomainEventEnvelope,
    HostedEdgeError, HostedHttpMethod, HostedMutationOutcome, HostedMutationResponse,
    HostedPrincipalRole, HostedRequestContract, HostedTenantBinding, HOSTED_TENANT_HEADER,
};

const REQUEST_ID_HEADER: &str = "Chio-Request-ID";
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
const API_KEY_ID_HEADER: &str = "Chio-API-Key-ID";
const API_KEY_SECRET_HEADER: &str = "Chio-API-Key-Secret";
const CAPABILITY_HEADER: &str = "Chio-Capability";
const DPOP_HEADER: &str = "Chio-DPoP";
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct HostedHttpServerConfig {
    pub public_endpoint: String,
    pub maximum_body_bytes: usize,
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
            || endpoint.as_str().trim_end_matches('/') != self.public_endpoint
            || self.maximum_body_bytes == 0
            || self.maximum_body_bytes > MAX_BODY_BYTES
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedDomainMutation {
    pub aggregate_id: String,
    pub event_id: String,
    pub expected_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_event_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_signer_key: Option<PublicKey>,
    pub payload: serde_json::Value,
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
}

#[derive(Clone)]
pub struct HostedHttpServerState {
    config: HostedHttpServerConfig,
    authenticator: Arc<HostedAuthenticator>,
    backend: Arc<dyn HostedHttpBackend>,
}

impl HostedHttpServerState {
    pub fn new(
        config: HostedHttpServerConfig,
        authenticator: Arc<HostedAuthenticator>,
        backend: Arc<dyn HostedHttpBackend>,
    ) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        Ok(Self {
            config,
            authenticator,
            backend,
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

impl HostedOperation {
    fn parse(value: &str) -> Option<Self> {
        let operation = match value {
            "publish" => (
                "finding.published",
                "finding",
                "chio.finding.v1",
                "finding.publish",
                HostedPrincipalRole::Seller,
            ),
            "listing" => (
                "listing.activated",
                "listing",
                "chio.finding.market-terms.v1",
                "finding.listing.activate",
                HostedPrincipalRole::Seller,
            ),
            "admission" => (
                "admission.admitted",
                "admission",
                "chio.finding.admission.v1",
                "finding.admission.admit",
                HostedPrincipalRole::Operator,
            ),
            "participation" => (
                "participation.admitted",
                "participation",
                "chio.finding.claim-allocation.v1",
                "finding.participation.admit",
                HostedPrincipalRole::Operator,
            ),
            "purchase" => (
                "purchase.authorized",
                "purchase",
                "chio.finding.purchase-record.v1",
                "finding.purchase.authorize",
                HostedPrincipalRole::Buyer,
            ),
            "reveal" => (
                "reveal.committed",
                "reveal",
                "chio.finding.purchase-result.v1",
                "finding.reveal.commit",
                HostedPrincipalRole::Seller,
            ),
            "delivery" => (
                "delivery.accepted",
                "delivery",
                "chio.finding.delivery.v1",
                "finding.delivery.accept",
                HostedPrincipalRole::Operator,
            ),
            "purchase-terminal" => (
                "purchase.settled",
                "purchase_terminal",
                "chio.finding.purchase-result.v1",
                "finding.purchase.settle",
                HostedPrincipalRole::Operator,
            ),
            "failed-delivery" => (
                "delivery.failed",
                "failed_delivery",
                "chio.finding.failed-delivery.v1",
                "finding.delivery.fail",
                HostedPrincipalRole::Operator,
            ),
            "challenge" => (
                "challenge.submitted",
                "challenge",
                "chio.finding.challenge.v1",
                "finding.challenge.submit",
                HostedPrincipalRole::Buyer,
            ),
            "challenge-outcome" => (
                "challenge.finalized",
                "challenge_outcome",
                "chio.finding.challenge-outcome.v1",
                "finding.challenge.finalize",
                HostedPrincipalRole::Evaluator,
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
            "liability" => (
                "liability.assessed",
                "liability",
                "chio.finding.liability.v1",
                "finding.liability.assess",
                HostedPrincipalRole::Operator,
            ),
            "appeal" => (
                "appeal.finalized",
                "appeal",
                "chio.finding.challenge-enforcement.v1",
                "finding.appeal.finalize",
                HostedPrincipalRole::Evaluator,
            ),
            "penalty" => (
                "penalty.assessed",
                "penalty",
                "chio.registry.market-penalty.v1",
                "finding.penalty.assess",
                HostedPrincipalRole::Operator,
            ),
            "enforcement" => (
                "enforcement.finalized",
                "enforcement",
                "chio.finding.challenge-enforcement.v1",
                "finding.enforcement.finalize",
                HostedPrincipalRole::Operator,
            ),
            "settlement" => (
                "settlement.terminal",
                "settlement",
                "chio.commerce.settlement-packet.v1",
                "finding.settlement.record",
                HostedPrincipalRole::Operator,
            ),
            "status" => (
                "status.published",
                "status_epoch",
                "chio.finding.status-epoch.v1",
                "finding.status.publish",
                HostedPrincipalRole::Operator,
            ),
            "audit" => (
                "audit.finalized",
                "audit_round",
                "chio.finding.audit-report.v1",
                "finding.audit.finalize",
                HostedPrincipalRole::Auditor,
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
}

struct FindingQuery {
    after: Option<String>,
    limit: Option<u32>,
}

pub fn hosted_market_router(state: HostedHttpServerState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/v1/findings", get(list_findings))
        .route("/v1/findings/{finding_id}", get(get_finding))
        .route("/v1/findings/events/{operation}", post(mutate))
        .route("/v1/findings/publish", post(publish))
        .fallback(not_found)
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
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hosted cognition-market edge must listen on loopback",
        ));
    }
    axum::serve(listener, hosted_market_router(state)).await
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "live"})))
}

async fn not_found() -> Response {
    error_response(HostedEdgeError::InvalidRequest, "route-not-found")
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
        if finding.issued_at > received_at || finding.expires_at <= received_at {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let operation = HostedOperation::parse("publish").ok_or(HostedEdgeError::Configuration)?;
        let principal = authenticate(
            &state,
            &headers,
            &uri,
            operation.action,
            HostedHttpMethod::Post,
            operation.role,
            sha256_hex(&canonical_body),
            received_at,
        )
        .await?;
        let binding = tenant_binding(&headers)?;
        let event_id = required_header(&headers, IDEMPOTENCY_KEY_HEADER)?.to_owned();
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
            artifact_signer_key: Some(finding.issuer),
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
        let principal = authenticate(
            &state,
            &headers,
            &uri,
            operation.action,
            HostedHttpMethod::Post,
            operation.role,
            sha256_hex(&canonical_body),
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
            Some(required_header(&headers, IDEMPOTENCY_KEY_HEADER)?.to_owned()),
            received_at,
        )?;
        if mutation.event_id != contract.idempotency_key().unwrap_or_default() {
            return Err(HostedEdgeError::InvalidRequest);
        }
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
        authenticate(
            &state,
            &headers,
            &uri,
            "finding.read",
            HostedHttpMethod::Get,
            HostedPrincipalRole::Buyer,
            sha256_hex(&[]),
            unix_now()?,
        )
        .await?;
        state
            .backend
            .finding(binding.tenant_id(), &finding_id)
            .await
            .map_err(map_backend)?
            .ok_or(HostedEdgeError::NotFound)
    }
    .await;
    match result {
        Ok(projection) => (StatusCode::OK, Json(projection.payload)).into_response(),
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
        authenticate(
            &state,
            &headers,
            &uri,
            "finding.search",
            HostedHttpMethod::Get,
            HostedPrincipalRole::Buyer,
            sha256_hex(&[]),
            unix_now()?,
        )
        .await?;
        state
            .backend
            .findings(
                binding.tenant_id(),
                query.after.as_deref(),
                query.limit.unwrap_or(50),
            )
            .await
            .map_err(map_backend)
    }
    .await;
    match result {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => error_response(error, request_id),
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
            required_role: role,
            credential,
            now_unix_secs,
        })
        .await
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

#[allow(dead_code)]
fn projection_event_envelope(
    tenant: crate::HostedTenantId,
    projection: &HostedHttpProjection,
) -> Result<HostedDomainEventEnvelope, HostedEdgeError> {
    HostedDomainEventEnvelope::new(
        tenant,
        &projection.event_kind,
        &projection.aggregate_kind,
        &projection.aggregate_id,
        &projection.event_id,
        projection.revision,
        projection.previous_event_sha256.clone(),
        &projection.artifact_schema,
        &projection.artifact_sha256,
        projection.committed_at,
    )
}

#[allow(dead_code)]
async fn drain_rejected_body(request: Request<Body>) {
    let _ = to_bytes(request.into_body(), MAX_BODY_BYTES).await;
}

#[cfg(test)]
mod tests {
    use chio_core_types::crypto::Keypair;
    use chio_finding_market_port::{
        HostedApiKeyRecord, HostedAuthPort, HostedMarketPortError, HostedPrincipal, HostedTenantId,
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

        async fn consume_dpop_nonce(
            &self,
            _tenant: &HostedTenantId,
            _capability_id: &str,
            _nonce_sha256: &str,
            _valid_through: u64,
            _now: u64,
            _tenant_capacity: u64,
        ) -> Result<bool, HostedMarketPortError> {
            Ok(false)
        }

        async fn consume_capability_use(
            &self,
            _tenant: &HostedTenantId,
            _capability_id: &str,
            _max_invocations: u32,
            _expires_at: u64,
            _now: u64,
        ) -> Result<bool, HostedMarketPortError> {
            Ok(false)
        }
    }

    struct ClosedBackend;

    #[async_trait]
    impl HostedHttpBackend for ClosedBackend {
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
            },
            Arc::new(authenticator),
            Arc::new(ClosedBackend),
        )?;
        Ok(state)
    }

    fn router() -> Result<Router, HostedEdgeError> {
        server_state().map(hosted_market_router)
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
    fn operations_are_closed_and_role_bound() {
        let operations = [
            "publish",
            "listing",
            "admission",
            "participation",
            "purchase",
            "reveal",
            "delivery",
            "purchase-terminal",
            "failed-delivery",
            "challenge",
            "challenge-outcome",
            "verified-fix",
            "retraction",
            "liability",
            "appeal",
            "penalty",
            "enforcement",
            "settlement",
            "status",
            "audit",
        ];
        let parsed = operations
            .iter()
            .filter_map(|operation| HostedOperation::parse(operation))
            .collect::<Vec<_>>();
        assert_eq!(parsed.len(), operations.len());
        assert!(HostedOperation::parse("custom").is_none());
        assert_eq!(
            HostedOperation::parse("purchase").map(|operation| operation.role),
            Some(HostedPrincipalRole::Buyer)
        );
        assert_eq!(
            HostedOperation::parse("enforcement").map(|operation| operation.role),
            Some(HostedPrincipalRole::Operator)
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

    #[tokio::test]
    async fn listener_refuses_non_loopback_binding() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .unwrap_or_else(|error| panic!("test listener failed: {error}"));
        let state =
            server_state().unwrap_or_else(|error| panic!("test server state failed: {error}"));
        let error = serve_hosted_market_loopback(listener, state)
            .await
            .expect_err("non-loopback listener must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn router_returns_stable_fail_closed_errors() {
        let service = router().unwrap_or_else(|error| panic!("test router failed: {error}"));
        let missing_tenant = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/findings")
                    .header(REQUEST_ID_HEADER, "request-1")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("test request failed: {error}")),
            )
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
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/findings/publish")
                    .header(REQUEST_ID_HEADER, "request-2")
                    .body(Body::from("{ \"payload\": {} }"))
                    .unwrap_or_else(|error| panic!("test request failed: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(noncanonical.status(), StatusCode::BAD_REQUEST);
    }
}
