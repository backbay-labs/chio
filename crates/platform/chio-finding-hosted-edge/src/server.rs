use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex};
use chio_finding_market_port::{
    HostedDomainMutation, HostedHttpProjection, HostedMarketBackend, HostedMarketBackendError,
    HostedMarketBackendOutcome, HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

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
const MAX_CONCURRENT_REQUESTS: usize = 100_000;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
/// Schema identifier pinned by the release identity document.
pub const HOSTED_RELEASE_IDENTITY_SCHEMA: &str = "chio.finding.hosted-release-identity.v1";
/// The exact release the server claims to run: deployment id,
/// candidate commit, artifact digest, and configuration revision, all
/// shape-validated at construction.
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

/// Server contract: the https public endpoint, the request body cap,
/// the penalty authority identity and key, and the kernel receipt key.
/// Validated in full before serving.
#[derive(Clone, Debug)]
pub struct HostedHttpServerConfig {
    pub public_endpoint: String,
    pub maximum_body_bytes: usize,
    /// In-flight request ceiling; excess load sheds with 503 instead of
    /// queueing without bound.
    pub maximum_concurrent_requests: usize,
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
            || !(1..=MAX_CONCURRENT_REQUESTS).contains(&self.maximum_concurrent_requests)
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

/// Shared router state: configuration, authenticator, storage
/// backend, and the trusted proxy.
#[derive(Clone)]
pub struct HostedHttpServerState {
    config: HostedHttpServerConfig,
    authenticator: Arc<HostedAuthenticator>,
    backend: Arc<dyn HostedMarketBackend>,
    trusted_proxy: Arc<crate::HostedTrustedProxy>,
}

impl HostedHttpServerState {
    /// Fail closed unless the configuration validates.
    pub fn new(
        config: HostedHttpServerConfig,
        authenticator: Arc<HostedAuthenticator>,
        backend: Arc<dyn HostedMarketBackend>,
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
    event_kind: chio_finding_market_port::HostedMarketDomainEventKind::FindingPublished
        .event_kind(),
    aggregate_kind: chio_finding_market_port::HostedMarketDomainEventKind::FindingPublished
        .aggregate_kind()
        .label(),
    artifact_schema: chio_finding_market_port::HostedMarketDomainEventKind::FindingPublished
        .artifact_schema(),
    action: "finding.publish",
    role: HostedPrincipalRole::Seller,
};

impl HostedOperation {
    /// Resolve one HTTP write route to its domain event. The event kind,
    /// aggregate family, and artifact schema come from the canonical
    /// grammar; only the governed action name and the writing role are
    /// edge-owned.
    fn parse(value: &str) -> Option<Self> {
        use chio_finding_market_port::HostedMarketDomainEventKind as EventKind;
        let (event, action, role) = match value {
            "listing" => (
                EventKind::ListingActivated,
                "finding.listing.activate",
                HostedPrincipalRole::Seller,
            ),
            "delivery" => (
                EventKind::DeliveryAccepted,
                "finding.delivery.accept",
                HostedPrincipalRole::Operator,
            ),
            "challenge" => (
                EventKind::ChallengeSubmitted,
                "finding.challenge.submit",
                HostedPrincipalRole::Buyer,
            ),
            "verified-fix" => (
                EventKind::VerifiedFixSubmitted,
                "finding.verified_fix.submit",
                HostedPrincipalRole::Seller,
            ),
            "retraction" => (
                EventKind::RetractionVoluntary,
                "finding.retraction.submit",
                HostedPrincipalRole::Seller,
            ),
            "penalty" => (
                EventKind::PenaltyAssessed,
                "finding.penalty.assess",
                HostedPrincipalRole::Operator,
            ),
            _ => return None,
        };
        Some(Self {
            event_kind: event.event_kind(),
            aggregate_kind: event.aggregate_kind().label(),
            artifact_schema: event.artifact_schema(),
            action,
            role,
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
    if operation.event_kind == "challenge.submitted" {
        let authorization = payload
            .pointer("/body/authorization")
            .and_then(serde_json::Value::as_object)
            .ok_or(HostedEdgeError::InvalidRequest)?;
        if authorization.len() != 1 || !authorization.contains_key("buyer_submission") {
            return Err(HostedEdgeError::AuthorizationFailed);
        }
        return Ok(None);
    }
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

/// The authenticated hosted market router: health, release identity,
/// finding reads, and the governed write routes, behind the
/// trusted-proxy middleware and the configured body limit. Every write
/// authenticates against the tenant method policy before touching the
/// backend.
pub fn hosted_market_router(state: HostedHttpServerState) -> Router {
    // Liveness and readiness answer outside the limiter. The trusted proxy
    // probes them on this same pod, so shedding a probe would restart a
    // live sidecar exactly while the edge is saturated, dropping its
    // connections and removing capacity during the overload.
    //
    // Being outside the limiter, readiness carries its own bound: it is the
    // one probe that reaches the backend, and the proxy forwards every
    // public path, so an unauthenticated flood would otherwise become
    // arbitrarily many pooled database round trips.
    let health = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(HealthState {
            server: state.clone(),
            probe: ReadinessProbe::new(),
        });

    // Everything that reaches the backend is bounded. Shedding answers
    // before the request reaches a handler, in the same error envelope as
    // every other failure, so the trusted proxy reads the retryable flag
    // and retries against a healthy replica.
    //
    // These routes deliberately carry no request deadline. Authentication
    // durably consumes the DPoP nonce and the capability's invocation
    // budget before the domain write commits, so cancelling a request after
    // that point would burn a single-use capability on a mutation that
    // never landed. The trusted proxy owns the request deadline, where a
    // timeout cannot land between those two commits.
    let guarded = Router::new()
        .route("/v1/release", get(release_identity))
        .route("/v1/findings", get(list_findings))
        .route("/v1/findings/{finding_id}", get(get_finding))
        .route("/v1/findings/events/{operation}", post(mutate))
        .route("/v1/findings/publish", post(publish))
        .fallback(not_found)
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(
            state.config.maximum_body_bytes,
        ))
        .layer(axum::middleware::from_fn_with_state(
            RequestAdmissions {
                permits: Arc::new(Semaphore::new(state.config.maximum_concurrent_requests)),
            },
            shed_when_saturated,
        ));

    health
        .merge(guarded)
        .layer(axum::middleware::from_fn_with_state(
            state,
            enforce_trusted_proxy,
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

/// Serve the router with graceful shutdown; refuses any non-loopback
/// listener because the public endpoint must terminate at the
/// separately authenticated trusted proxy.
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

async fn ready(State(health): State<HealthState>) -> Response {
    if let Some(ready) = health.probe.fresh_answer() {
        return readiness_response(ready);
    }
    let Ok(_check) = Arc::clone(&health.probe.checking).try_acquire_owned() else {
        // The answer has aged out and another probe is already taking a new
        // one, so this probe has nothing current to report and does not
        // open a connection of its own to find out. Reporting the aged
        // answer instead would leave a backend that stopped responding
        // looking ready for as long as its check takes to fail.
        return readiness_response(false);
    };
    let ready = health.server.backend.ready().await.is_ok();
    health.probe.record(ready);
    readiness_response(ready)
}

fn readiness_response(ready: bool) -> Response {
    if ready {
        return (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))).into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"status": "not_ready"})),
    )
        .into_response()
}

/// How long one readiness answer is reused.
///
/// Kubernetes probes on an interval measured in seconds, so a real probe
/// still gets an answer taken for it, while a flood between two probes
/// costs the backend one round trip rather than one per request.
const READINESS_ANSWER_LIFETIME: Duration = Duration::from_secs(1);

/// The state the health routes carry: the server, and the bound on the one
/// probe that reaches the backend.
#[derive(Clone)]
struct HealthState {
    server: HostedHttpServerState,
    probe: ReadinessProbe,
}

/// Bounds the backend work public readiness probes can cause.
#[derive(Clone)]
struct ReadinessProbe {
    answer: Arc<Mutex<Option<(Instant, bool)>>>,
    checking: Arc<Semaphore>,
}

impl ReadinessProbe {
    fn new() -> Self {
        Self {
            answer: Arc::new(Mutex::new(None)),
            checking: Arc::new(Semaphore::new(1)),
        }
    }

    /// The last answer, if it is young enough to stand for this probe.
    fn fresh_answer(&self) -> Option<bool> {
        let answer = self.answer.lock().ok()?;
        answer.and_then(|(taken_at, ready)| {
            (taken_at.elapsed() < READINESS_ANSWER_LIFETIME).then_some(ready)
        })
    }

    fn record(&self, ready: bool) {
        if let Ok(mut answer) = self.answer.lock() {
            *answer = Some((Instant::now(), ready));
        }
    }
}

/// The permits that bound how much work the backend carries at once.
#[derive(Clone)]
struct RequestAdmissions {
    permits: Arc<Semaphore>,
}

/// Refuse a request that would exceed the configured concurrency rather
/// than queueing it behind the work already in flight.
async fn shed_when_saturated(
    State(admissions): State<RequestAdmissions>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Ok(_permit) = Arc::clone(&admissions.permits).try_acquire_owned() else {
        let request_id =
            single_header(request.headers(), REQUEST_ID_HEADER).unwrap_or("invalid-request-id");
        return error_response(HostedEdgeError::CapacityUnavailable, request_id);
    };
    next.run(request).await
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
    outcome: HostedMarketBackendOutcome,
) -> Result<HostedMutationResponse, HostedEdgeError> {
    let payload_sha256 = canonical_json_bytes(&mutation.payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| HostedEdgeError::InvalidRequest)?;
    let outcome = match outcome {
        HostedMarketBackendOutcome::Inserted => HostedMutationOutcome::Applied,
        HostedMarketBackendOutcome::ExactReplay => HostedMutationOutcome::ExactReplay,
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

fn map_backend(error: HostedMarketBackendError) -> HostedEdgeError {
    match error {
        HostedMarketBackendError::Invalid => HostedEdgeError::InvalidRequest,
        HostedMarketBackendError::NotFound => HostedEdgeError::NotFound,
        HostedMarketBackendError::Conflict => HostedEdgeError::Conflict,
        HostedMarketBackendError::Integrity => HostedEdgeError::IntegrityFailure,
        HostedMarketBackendError::Capacity => HostedEdgeError::CapacityUnavailable,
        HostedMarketBackendError::Unavailable => HostedEdgeError::DependencyUnavailable,
    }
}

fn error_response(error: HostedEdgeError, request_id: &str) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(error.body(request_id))).into_response()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chio_core_types::crypto::Keypair;
    use chio_finding_market_port::{
        HostedApiKeyRecord, HostedAuthPort, HostedCapabilityAdmissionOutcome, HostedHttpPage,
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
            _request_sha256: Option<&str>,
            _valid_through: u64,
            _max_invocations: u32,
            _expires_at: u64,
            _now: u64,
            _tenant_nonce_capacity: u64,
        ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError> {
            Ok(HostedCapabilityAdmissionOutcome::Replay)
        }
    }

    /// A backend that refuses everything, counting what readiness costs it.
    #[derive(Default)]
    struct ClosedBackend {
        readiness_checks: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl HostedMarketBackend for ClosedBackend {
        async fn ready(&self) -> Result<(), HostedMarketBackendError> {
            self.readiness_checks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(HostedMarketBackendError::Unavailable)
        }

        async fn append(
            &self,
            _tenant: &HostedTenantId,
            _event_kind: &str,
            _aggregate_kind: &str,
            _mutation: &HostedDomainMutation,
            _committed_at: u64,
        ) -> Result<HostedMarketBackendOutcome, HostedMarketBackendError> {
            Err(HostedMarketBackendError::Unavailable)
        }

        async fn finding(
            &self,
            _tenant: &HostedTenantId,
            _finding_id: &str,
        ) -> Result<Option<HostedHttpProjection>, HostedMarketBackendError> {
            Err(HostedMarketBackendError::Unavailable)
        }

        async fn findings(
            &self,
            _tenant: &HostedTenantId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<HostedHttpPage, HostedMarketBackendError> {
            Err(HostedMarketBackendError::Unavailable)
        }

        async fn non_live_findings(
            &self,
            _tenant: &HostedTenantId,
            _finding_ids: &[String],
        ) -> Result<BTreeSet<String>, HostedMarketBackendError> {
            Err(HostedMarketBackendError::Unavailable)
        }
    }

    fn server_state() -> Result<HostedHttpServerState, HostedEdgeError> {
        server_state_counting_readiness().map(|(state, _)| state)
    }

    fn server_state_counting_readiness(
    ) -> Result<(HostedHttpServerState, Arc<std::sync::atomic::AtomicUsize>), HostedEdgeError> {
        let auth_port: Arc<dyn HostedAuthPort> = Arc::new(ClosedAuthPort);
        let backend = ClosedBackend::default();
        let readiness_checks = Arc::clone(&backend.readiness_checks);
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
            auth_port,
            Arc::new(StaticApiKeyPepper::new(vec![9_u8; 32])?),
        )?;
        let state = HostedHttpServerState::new(
            HostedHttpServerConfig {
                public_endpoint: "https://market.example".to_owned(),
                maximum_body_bytes: 1024 * 1024,
                maximum_concurrent_requests: 64,
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
            Arc::new(backend),
            Arc::new(trusted_proxy()?),
        )?;
        Ok((state, readiness_checks))
    }

    fn router() -> Result<Router, HostedEdgeError> {
        server_state().map(hosted_market_router)
    }

    /// A shed request is the one failure a client cannot parse from the
    /// handler's own vocabulary, so it carries the same envelope: the
    /// retryable flag tells the proxy to try another replica, and the
    /// request id correlates the shed with the caller's log.
    #[tokio::test]
    async fn a_shed_request_carries_the_hosted_error_envelope() {
        let mut state = server_state().unwrap_or_else(|error| panic!("test state failed: {error}"));
        // No permit exists, so the limiter is saturated for every request.
        state.config.maximum_concurrent_requests = 0;
        let router = hosted_market_router(state);

        let shed = router
            .clone()
            .oneshot(proxied_request(
                Request::builder()
                    .uri("/v1/findings")
                    .header(REQUEST_ID_HEADER, "request-shed"),
                Body::empty(),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(shed.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|error| panic!("test body failed: {error}"));
        let error: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|error| panic!("test JSON failed: {error}"));
        assert_eq!(error["schema"], crate::HOSTED_ERROR_SCHEMA);
        assert_eq!(error["requestId"], "request-shed");
        assert_eq!(error["retryable"], true);

        // The probes answer from outside the limiter that just shed a
        // request, which is the whole point of mounting them there.
        let live = router
            .oneshot(proxied_request(
                Request::builder()
                    .uri("/health/live")
                    .header(REQUEST_ID_HEADER, "request-live-saturated"),
                Body::empty(),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(live.status(), StatusCode::OK);
        assert_eq!(probe_status(live).await, "live");
    }

    /// The proxy forwards every public path, so readiness is reachable
    /// without a tenant credential, and it is the one probe that reaches the
    /// backend. A flood of it must cost the pool one round trip rather than
    /// one per request.
    #[tokio::test]
    async fn a_readiness_flood_costs_one_backend_round_trip() {
        let (state, readiness_checks) = server_state_counting_readiness()
            .unwrap_or_else(|error| panic!("test state failed: {error}"));
        let router = hosted_market_router(state);
        for probe in 0..8 {
            let response = router
                .clone()
                .oneshot(proxied_request(
                    Request::builder()
                        .uri("/health/ready")
                        .header(REQUEST_ID_HEADER, format!("request-ready-{probe}")),
                    Body::empty(),
                ))
                .await
                .unwrap_or_else(|error| panic!("test response failed: {error}"));
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(probe_status(response).await, "not_ready");
        }
        assert_eq!(
            readiness_checks.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "probes within one answer's lifetime must share its round trip"
        );
    }

    /// Kubernetes probes this pod through the same listener that serves
    /// traffic. Both probes are mounted outside the guarded surface so an
    /// overload sheds requests instead of failing liveness and restarting a
    /// sidecar during the overload it is meant to ride out.
    #[tokio::test]
    async fn health_probes_answer_outside_the_guarded_surface() {
        let service = router().unwrap_or_else(|error| panic!("test router failed: {error}"));
        let live = service
            .oneshot(proxied_request(
                Request::builder()
                    .uri("/health/live")
                    .header(REQUEST_ID_HEADER, "request-live"),
                Body::empty(),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        assert_eq!(live.status(), StatusCode::OK);
        assert_eq!(probe_status(live).await, "live");

        let ready = router()
            .unwrap_or_else(|error| panic!("test router failed: {error}"))
            .oneshot(proxied_request(
                Request::builder()
                    .uri("/health/ready")
                    .header(REQUEST_ID_HEADER, "request-ready"),
                Body::empty(),
            ))
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        // The test backend is closed, so readiness reports that rather than
        // claiming the pod can serve. The body separates a handler answer
        // from a shed response, which carries the same status and no body.
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(probe_status(ready).await, "not_ready");
    }

    async fn probe_status(response: Response) -> String {
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|error| panic!("test body failed: {error}"));
        let probe: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|error| panic!("test JSON failed: {error}"));
        probe["status"].as_str().unwrap_or_default().to_owned()
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
    fn public_challenge_route_rejects_venue_audit_authorization() {
        let principal = crate::HostedAuthenticatedPrincipal {
            tenant_id: HostedTenantId::new("tenant:test")
                .unwrap_or_else(|error| panic!("test tenant failed: {error}")),
            principal_id: "buyer:test".to_owned(),
            role: HostedPrincipalRole::Buyer,
            method: HostedAuthMethod::ApiKey,
            credential_id: "key:test".to_owned(),
            artifact_signer_key: Some(Keypair::from_seed(&[49_u8; 32]).public_key()),
        };
        let operation = HostedOperation::parse("challenge")
            .unwrap_or_else(|| panic!("test challenge operation missing"));
        let buyer = serde_json::json!({
            "body": {"authorization": {"buyer_submission": {}}}
        });
        assert_eq!(
            authenticated_artifact_authority(operation, &principal, &buyer, "market-penalty"),
            Ok(None)
        );
        for forbidden in [
            serde_json::json!({
                "body": {"authorization": {"venue_audit": {}}}
            }),
            serde_json::json!({
                "body": {"authorization": {
                    "buyer_submission": {},
                    "venue_audit": {}
                }}
            }),
        ] {
            assert_eq!(
                authenticated_artifact_authority(
                    operation,
                    &principal,
                    &forbidden,
                    "market-penalty"
                ),
                Err(HostedEdgeError::AuthorizationFailed)
            );
        }
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
            maximum_concurrent_requests: 64,
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
