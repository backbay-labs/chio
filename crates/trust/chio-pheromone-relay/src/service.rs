use crate::{
    canonical_sha256, CatchupRequest, CatchupResponse, PeerDirectory, PeerDirectoryEntry,
    PheromoneRelayClient, PheromoneRelayError, PheromoneRelayHttpRequest, PheromoneRelayStore,
    RelayEventReport, RelayHealthReport, RelayHttpVerificationContext, RelayLadderRef,
    RelayMetricsFormat, RelayObservabilityInput, RelayObservabilityReport, RelayOperatorReport,
    RelayOutboxBatch, RelayProfile, RelayProfileLimits, RelayRole, RelayTickReport,
    SqlitePheromoneRelayStore, PHEROMONE_BATCH_RELAY_PATH, PHEROMONE_CATCHUP_RELAY_PATH,
    PHEROMONE_CATCHUP_REQUEST_SCHEMA, PHEROMONE_CATCHUP_RESPONSE_SCHEMA, PHEROMONE_HEALTH_PATH,
    PHEROMONE_READY_PATH, PHEROMONE_RELAY_DRILL_REPORT_SCHEMA, PHEROMONE_RELAY_EVENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_METRICS_PATH, PHEROMONE_RELAY_OBSERVABILITY_PATH,
    PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA, PHEROMONE_RELAY_PATH_PREFIX,
    PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA, PHEROMONE_RELAY_TICK_REPORT_SCHEMA,
};
use async_trait::async_trait;
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use axum::Json;
use axum::Router;
use chio_core_types::Keypair;
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};
use chio_pheromone_runtime::PheromoneReceiveReport;
use serde::Deserialize;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySupervisorProfileDocument {
    pub schema: String,
    pub profile: RelayProfile,
    pub service_name: String,
    pub listen: String,
    pub store_path: String,
    pub peer_directory_state_path: String,
    pub signing_key_path: String,
    pub health_path: String,
    pub ready_path: String,
    pub single_writer: bool,
    pub reverse_proxy: RelayReverseProxyProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayReverseProxyProfile {
    pub scheme: String,
    pub pinned_path_prefix: String,
    pub max_body_bytes: usize,
    pub redirects_disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDrillCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub generated_at_unix_ms: u64,
    pub checks: Vec<RelayDrillCheck>,
}

pub fn relay_supervisor_profile_from_json(
    json: &str,
) -> Result<RelaySupervisorProfileDocument, PheromoneRelayError> {
    let profile: RelaySupervisorProfileDocument = serde_json::from_str(json)?;
    if profile.schema != PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(profile.schema));
    }
    Ok(profile)
}

pub fn lint_relay_supervisor_profile(
    profile: &RelaySupervisorProfileDocument,
    now_unix_ms: u64,
) -> RelayDrillReport {
    let mut checks = Vec::new();
    push_drill_check(
        &mut checks,
        profile.schema == PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA,
        "supervisor_schema",
        "supervisor profile declares the current schema",
    );
    push_drill_check(
        &mut checks,
        profile.health_path == PHEROMONE_HEALTH_PATH,
        "health_path",
        "health endpoint path is pinned",
    );
    push_drill_check(
        &mut checks,
        profile.ready_path == PHEROMONE_READY_PATH,
        "ready_path",
        "readiness endpoint path is pinned",
    );
    push_drill_check(
        &mut checks,
        profile.single_writer,
        "single_writer",
        "profile declares a single relay writer boundary",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.pinned_path_prefix == PHEROMONE_RELAY_PATH_PREFIX,
        "pinned_path_prefix",
        "reverse proxy pins the Chio pheromone path prefix",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.redirects_disabled,
        "redirects_disabled",
        "reverse proxy disables upstream redirects",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.max_body_bytes
            <= RelayProfileLimits::production_defaults().max_body_bytes,
        "max_body_bytes",
        "reverse proxy body limit stays within production relay bounds",
    );
    let scheme_ok = match profile.profile {
        RelayProfile::LocalDev => {
            profile.reverse_proxy.scheme == "http" || profile.reverse_proxy.scheme == "https"
        }
        RelayProfile::Production => profile.reverse_proxy.scheme == "https",
    };
    push_drill_check(
        &mut checks,
        scheme_ok,
        "endpoint_scheme",
        "profile endpoint scheme is allowed for the selected relay profile",
    );
    let accepted = checks.iter().all(|check| check.accepted);
    RelayDrillReport {
        schema: PHEROMONE_RELAY_DRILL_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "supervisor_profile_invalid".to_string()
        },
        detail: if accepted {
            "relay supervisor profile accepted".to_string()
        } else {
            "relay supervisor profile rejected".to_string()
        },
        generated_at_unix_ms: now_unix_ms,
        checks,
    }
}

pub(crate) fn push_drill_check(
    checks: &mut Vec<RelayDrillCheck>,
    accepted: bool,
    code: &str,
    detail: &str,
) {
    checks.push(RelayDrillCheck {
        code: code.to_string(),
        accepted,
        detail: detail.to_string(),
    });
}

#[derive(Debug, Clone)]
pub struct PheromoneRelayConfig {
    pub local_kernel_id: String,
    pub profile: RelayProfile,
    pub now_unix_ms: u64,
    pub freshness_window_ms: u64,
    pub max_body_bytes: usize,
    pub use_system_clock: bool,
    pub operator_token: Option<String>,
    pub report_dir: Option<PathBuf>,
}

#[async_trait]
pub trait RelayBatchReceiver: Send + Sync {
    async fn receive_batch(
        &self,
        batch: PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError>;

    /// Return a previously durably-recorded receive report for `batch_sha256` SCOPED
    /// to `authenticated_sender_kernel_id`, if the runtime store committed one for that
    /// (batch, sender) pair. Used to recover the verdict after a crash in the
    /// commit-to-record window WITHOUT re-running `receive_batch` (which would re-enter
    /// the replay window and reject already-accepted deposits). The sender scope is
    /// mandatory: a batch hash is not sender-unique, so an unscoped lookup could return a
    /// cross-sender verdict and adopt it under the wrong (sender, nonce) inbox key.
    /// Default: `Ok(None)` (a receiver with no durable report cannot recover; the handler
    /// then keeps its fail-closed loser path).
    async fn recorded_report_for_batch(
        &self,
        _batch_sha256: &str,
        _authenticated_sender_kernel_id: &str,
    ) -> Result<Option<PheromoneReceiveReport>, PheromoneRelayError> {
        Ok(None)
    }
}

/// Optional process-wide metrics hook whose Prometheus output is appended to the
/// relay `/metrics` body.
///
/// DEPLOYABILITY (iroh DUAL transport): the iroh federation-transport metric
/// families live in `chio-federation-transport-iroh`, which already depends on
/// this crate. Naming that crate here would be a dependency cycle, so this crate
/// never references it. Instead the serving binary (`chio-cli`) injects a callback
/// that renders those process-global families, and [`handle_metrics`] appends the
/// callback output to its own Prometheus body. `None` (the default) keeps the
/// `/metrics` response byte-identical to the pre-hook behavior.
pub type ExtraMetricsHook = Arc<dyn Fn() -> String + Send + Sync>;

#[derive(Clone)]
pub struct PheromoneRelayService {
    config: PheromoneRelayConfig,
    directory: PeerDirectory,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
    extra_metrics: Option<ExtraMetricsHook>,
}

impl PheromoneRelayService {
    #[must_use]
    pub fn new(
        config: PheromoneRelayConfig,
        directory: PeerDirectory,
        receiver: Arc<dyn RelayBatchReceiver>,
        store: Arc<SqlitePheromoneRelayStore>,
    ) -> Self {
        Self {
            config,
            directory,
            receiver,
            store,
            extra_metrics: None,
        }
    }

    /// Attach an optional extra-metrics hook whose Prometheus output is appended to
    /// the relay `/metrics` body.
    ///
    /// Additive by construction: callers that never invoke this keep the default
    /// `None` and the `/metrics` response is byte-identical. Used to expose the
    /// iroh federation-transport metric families on the live relay `/metrics`
    /// surface WITHOUT this crate depending on the iroh transport crate (which
    /// already depends on this crate, so such a dependency would be a cycle).
    #[must_use]
    pub fn with_extra_metrics_hook(mut self, hook: ExtraMetricsHook) -> Self {
        self.extra_metrics = Some(hook);
        self
    }

    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), PheromoneRelayError> {
        let max_body_bytes = self.config.max_body_bytes;
        let router = Router::new()
            .route(PHEROMONE_BATCH_RELAY_PATH, post(handle_batch_relay))
            .route(PHEROMONE_CATCHUP_RELAY_PATH, post(handle_catchup_relay))
            .route(PHEROMONE_HEALTH_PATH, get(handle_health))
            .route(PHEROMONE_READY_PATH, get(handle_ready))
            .route(
                PHEROMONE_RELAY_OBSERVABILITY_PATH,
                get(handle_observability),
            )
            .route(PHEROMONE_RELAY_METRICS_PATH, get(handle_metrics))
            .layer(DefaultBodyLimit::max(max_body_bytes))
            .with_state(Arc::new(self));

        // The route-local body limit above is preserved; layer on the request
        // timeout, concurrency limit, connection cap, and graceful-shutdown
        // drain that this site lacked.
        let hygiene = ServeHygieneConfig::default();
        let router = apply_server_hygiene(router, &hygiene);
        let controller = ShutdownController::install();
        let listener =
            MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
        let server = axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

        // The relay store commits synchronously inside its handlers, so
        // completing in-flight requests during the drain is the whole fix;
        // nothing is queued to flush.
        run_until_drained(
            server,
            controller.subscribe(),
            hygiene.drain_timeout,
            async { Ok::<(), String>(()) },
        )
        .await
        .map(|_outcome| ())
        .map_err(|error| PheromoneRelayError::Http(error.to_string()))
    }

    fn request_now_unix_ms(&self) -> u64 {
        if self.config.use_system_clock {
            system_unix_ms().unwrap_or(self.config.now_unix_ms)
        } else {
            self.config.now_unix_ms
        }
    }

    fn emit_event_report(
        &self,
        event_kind: &str,
        accepted: bool,
        code: &str,
        detail: &str,
        generated_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let report = RelayEventReport {
            schema: PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
            accepted,
            code: code.to_string(),
            detail: detail.to_string(),
            local_kernel_id: self.config.local_kernel_id.clone(),
            generated_at_unix_ms,
            event_kind: event_kind.to_string(),
            stable_failure_code: if accepted {
                None
            } else {
                Some(code.to_string())
            },
        };
        self.store.record_event_report(&report)?;
        if let Some(report_dir) = &self.config.report_dir {
            std::fs::create_dir_all(report_dir)?;
            let report_hash = canonical_sha256(&report)?;
            let suffix = report_hash.chars().take(12).collect::<String>();
            let filename = format!(
                "{}-{}-{}.json",
                generated_at_unix_ms,
                sanitize_event_part(event_kind),
                suffix
            );
            let path = report_dir.join(filename);
            let json = serde_json::to_string_pretty(&report)?;
            std::fs::write(path, format!("{json}\n"))?;
        }
        Ok(())
    }
}

async fn handle_health(
    State(service): State<Arc<PheromoneRelayService>>,
) -> Result<Json<RelayHealthReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    service
        .store
        .health_report(
            &service.config.local_kernel_id,
            now,
            service.directory.version(),
        )
        .map(Json)
        .map_err(|error| relay_http_error(&service, error))
}

async fn handle_ready(
    State(service): State<Arc<PheromoneRelayService>>,
) -> Result<Json<RelayHealthReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let report = service
        .store
        .health_report(
            &service.config.local_kernel_id,
            now,
            service.directory.version(),
        )
        .map_err(|error| relay_http_error(&service, error))?;
    if report.accepted {
        Ok(Json(report))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RelayOperatorReport {
                schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
                accepted: false,
                code: report.code.clone(),
                detail: report.detail.clone(),
                local_kernel_id: report.local_kernel_id.clone(),
                generated_at_unix_ms: report.generated_at_unix_ms,
            }),
        ))
    }
}

async fn handle_observability(
    State(service): State<Arc<PheromoneRelayService>>,
    headers: HeaderMap,
) -> Result<Json<RelayObservabilityReport>, (StatusCode, Json<RelayOperatorReport>)> {
    authorize_operator(&service, &headers)?;
    let now = service.request_now_unix_ms();
    service
        .store
        .relay_observability_report(RelayObservabilityInput {
            local_kernel_id: &service.config.local_kernel_id,
            generated_at_unix_ms: now,
            peer_directory: Some(&service.directory),
            peer_directory_state: None,
            profile: service.config.profile,
            recent_failure_limit: 25,
        })
        .map(Json)
        .map_err(|error| relay_http_error(&service, error))
}

async fn handle_metrics(
    State(service): State<Arc<PheromoneRelayService>>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<RelayOperatorReport>)> {
    authorize_operator(&service, &headers)?;
    let now = service.request_now_unix_ms();
    let snapshot = service
        .store
        .relay_metrics_snapshot(&service.config.local_kernel_id, now)
        .map_err(|error| relay_http_error(&service, error))?;
    let mut body = snapshot.render(RelayMetricsFormat::Prometheus);
    if let Some(extra_metrics) = service.extra_metrics.as_ref() {
        // Append the injected metric families (e.g. the iroh federation-transport
        // process-global families) on the SAME scrape surface. Additive: with no
        // hook set this branch is skipped and the body is unchanged.
        body.push('\n');
        body.push_str(&extra_metrics());
    }
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response())
}

async fn handle_batch_relay(
    State(service): State<Arc<PheromoneRelayService>>,
    Json(request): Json<PheromoneRelayHttpRequest>,
) -> Result<Json<PheromoneReceiveReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let context = RelayHttpVerificationContext {
        local_kernel_id: service.config.local_kernel_id.clone(),
        method: "POST".to_string(),
        path: PHEROMONE_BATCH_RELAY_PATH.to_string(),
        now_unix_ms: now,
        freshness_window_ms: service.config.freshness_window_ms,
    };
    let batch: PheromoneGossipBatch = request
        .verify_payload(&service.directory, &context, service.store.as_ref())
        .map_err(|error| relay_http_error(&service, error))?;
    enforce_peer_batch_directory_scope(&service.directory, &request.sender_kernel_id, &batch)
        .map_err(|error| relay_http_error(&service, error))?;
    let report = service
        .receiver
        .receive_batch(batch.clone(), request.sender_kernel_id.clone(), now)
        .await
        .map_err(|error| relay_http_error(&service, error))?;
    service
        .store
        .record_inbox(&request.sender_kernel_id, &request.nonce, &batch, &report)
        .map_err(|error| relay_http_error(&service, error))?;
    let report_code = report
        .frames
        .iter()
        .find(|frame| !frame.accepted)
        .map(|frame| frame.code.as_str())
        .unwrap_or("accepted");
    service
        .emit_event_report(
            "batch_receive",
            report.accepted,
            report_code,
            "batch received",
            now,
        )
        .map_err(|error| relay_http_error(&service, error))?;
    Ok(Json(report))
}

/// Enforce the inbound per-peer directory scope for a submitted batch: the sender
/// must be an `Origin`/`Hub`, within its per-peer frame cap, subscribed to the
/// batch treaty, and carry only directory-pinned transit ladders. Fail-closed.
///
/// Exposed (in addition to its use by [`handle_batch_relay`]) so a second ingress
/// transport (the iroh federation-transport pheromone lane) can enforce the SAME
/// scope gate against the SAME peer directory before it hands a batch to
/// [`RelayBatchReceiver::receive_batch`]. Both transports therefore apply one gate.
pub fn enforce_peer_batch_directory_scope(
    directory: &PeerDirectory,
    sender_kernel_id: &str,
    batch: &PheromoneGossipBatch,
) -> Result<(), PheromoneRelayError> {
    let peer = directory.peer(sender_kernel_id)?;
    let frame_count = batch.frames.len();
    if !matches!(peer.relay_role, RelayRole::Origin | RelayRole::Hub) {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "peer {sender_kernel_id} is not authorized to submit inbound batches"
        )));
    }
    if frame_count > peer.max_batch_frames {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "peer {sender_kernel_id} submitted {frame_count} batch frames, exceeding directory max {}",
            peer.max_batch_frames
        )));
    }
    if !peer.treaty_subscriptions.contains(&batch.treaty_id) {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "peer {sender_kernel_id} is not subscribed to treaty {}",
            batch.treaty_id
        )));
    }
    enforce_peer_transit_ladder_pins(peer, sender_kernel_id, batch)?;
    Ok(())
}

async fn handle_catchup_relay(
    State(service): State<Arc<PheromoneRelayService>>,
    Json(request): Json<PheromoneRelayHttpRequest>,
) -> Result<Json<CatchupResponse>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let context = RelayHttpVerificationContext {
        local_kernel_id: service.config.local_kernel_id.clone(),
        method: "POST".to_string(),
        path: PHEROMONE_CATCHUP_RELAY_PATH.to_string(),
        now_unix_ms: now,
        freshness_window_ms: service.config.freshness_window_ms,
    };
    let catchup: CatchupRequest = request
        .verify_payload(&service.directory, &context, service.store.as_ref())
        .map_err(|error| relay_http_error(&service, error))?;
    validate_catchup_request(&service, &request.sender_kernel_id, &catchup)
        .map_err(|error| relay_http_error(&service, error))?;
    let peer = service
        .directory
        .peer(&request.sender_kernel_id)
        .map_err(|error| relay_http_error(&service, error))?;
    let (frames, next_cursor) = service
        .store
        .catchup_batches(
            &request.sender_kernel_id,
            &catchup.treaty_id,
            &catchup.after_cursor,
            catchup.limit,
            peer.max_catchup_bytes,
        )
        .map_err(|error| relay_http_error(&service, error))?;
    enforce_catchup_response_directory_scope(peer, &request.sender_kernel_id, &frames)
        .map_err(|error| relay_http_error(&service, error))?;
    let response = CatchupResponse {
        schema: PHEROMONE_CATCHUP_RESPONSE_SCHEMA.to_string(),
        accepted: true,
        responder_kernel_id: catchup.responder_kernel_id,
        requester_kernel_id: catchup.requester_kernel_id,
        treaty_id: catchup.treaty_id,
        frames,
        next_cursor,
        code: "accepted".to_string(),
    };
    service
        .emit_event_report("catchup", true, "accepted", "catch-up response served", now)
        .map_err(|error| relay_http_error(&service, error))?;
    Ok(Json(response))
}

pub(crate) fn validate_catchup_request(
    service: &PheromoneRelayService,
    authenticated_sender: &str,
    catchup: &CatchupRequest,
) -> Result<(), PheromoneRelayError> {
    if catchup.schema != PHEROMONE_CATCHUP_REQUEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            catchup.schema.clone(),
        ));
    }
    if catchup.requester_kernel_id != authenticated_sender {
        return Err(PheromoneRelayError::SenderMismatch(format!(
            "catch-up requester {} does not match authenticated sender {}",
            catchup.requester_kernel_id, authenticated_sender
        )));
    }
    if catchup.responder_kernel_id != service.config.local_kernel_id {
        return Err(PheromoneRelayError::RecipientMismatch(format!(
            "catch-up responder {} does not match local receiver {}",
            catchup.responder_kernel_id, service.config.local_kernel_id
        )));
    }
    let peer = service.directory.peer(authenticated_sender)?;
    if !matches!(peer.relay_role, RelayRole::Receiver | RelayRole::Hub) {
        return Err(PheromoneRelayError::CatchupDenied(format!(
            "peer {authenticated_sender} is not authorized for catch-up"
        )));
    }
    if catchup.limit == 0 || catchup.limit > peer.max_catchup_frames {
        return Err(PheromoneRelayError::CatchupDenied(format!(
            "catch-up limit {} exceeds peer bound {}",
            catchup.limit, peer.max_catchup_frames
        )));
    }
    if !peer.treaty_subscriptions.contains(&catchup.treaty_id) {
        return Err(PheromoneRelayError::CatchupDenied(format!(
            "peer {} is not subscribed to treaty {}",
            authenticated_sender, catchup.treaty_id
        )));
    }
    Ok(())
}

fn enforce_catchup_response_directory_scope(
    peer: &PeerDirectoryEntry,
    requester_kernel_id: &str,
    frames: &[PheromoneGossipBatch],
) -> Result<(), PheromoneRelayError> {
    for batch in frames {
        enforce_peer_transit_ladder_pins(peer, requester_kernel_id, batch).map_err(|error| {
            PheromoneRelayError::CatchupDenied(format!(
                "catch-up frame denied by directory pins: {error}"
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn authorize_operator(
    service: &PheromoneRelayService,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<RelayOperatorReport>)> {
    let Some(token) = service.config.operator_token.as_deref() else {
        return Ok(());
    };
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| provided.as_bytes().ct_eq(token.as_bytes()).into());
    if authorized {
        Ok(())
    } else {
        Err(relay_http_status_error(
            service,
            PheromoneRelayError::OperatorAuthRequired(
                "operator token is required for relay observability".to_string(),
            ),
            StatusCode::UNAUTHORIZED,
        ))
    }
}

pub(crate) fn relay_http_error(
    service: &PheromoneRelayService,
    error: PheromoneRelayError,
) -> (StatusCode, Json<RelayOperatorReport>) {
    relay_http_status_error(service, error, StatusCode::BAD_REQUEST)
}

pub(crate) fn relay_http_status_error(
    service: &PheromoneRelayService,
    error: PheromoneRelayError,
    status: StatusCode,
) -> (StatusCode, Json<RelayOperatorReport>) {
    let now = service.request_now_unix_ms();
    let code = error.code().to_string();
    let detail = error.to_string();
    let _ = service.emit_event_report("request_rejected", false, &code, &detail, now);
    (
        status,
        Json(RelayOperatorReport {
            schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
            accepted: false,
            code,
            detail,
            local_kernel_id: service.config.local_kernel_id.clone(),
            generated_at_unix_ms: now,
        }),
    )
}

pub async fn deliver_due_batches(
    store: &(impl PheromoneRelayStore + ?Sized),
    directory: PeerDirectory,
    keypair: Keypair,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<RelayTickReport, PheromoneRelayError> {
    let delivery_directory = directory.clone();
    let client = PheromoneRelayClient::new(directory, keypair, now_unix_ms, 60_000)?;
    let due = store.lease_due_batches(now_unix_ms, max_batches)?;
    let mut report = RelayTickReport {
        schema: PHEROMONE_RELAY_TICK_REPORT_SCHEMA.to_string(),
        accepted: true,
        delivered: 0,
        retried: 0,
        dead_lettered: 0,
        duplicate_idempotent: 0,
        failures: Vec::new(),
    };
    for entry in due {
        if entry.sender_kernel_id != sender_kernel_id {
            store.mark_retry(
                &entry.outbox_id,
                "sender_mismatch",
                now_unix_ms.saturating_add(60_000),
            )?;
            report.accepted = false;
            report.retried = report.retried.saturating_add(1);
            report
                .failures
                .push(format!("{}: sender_mismatch", entry.outbox_id));
            continue;
        }
        if let Err(error) = enforce_outbound_peer_batch_directory_scope(
            &delivery_directory,
            &entry.recipient_kernel_id,
            &entry.batch,
        ) {
            mark_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            continue;
        }
        let nonce = format!("relay-tick:{}:{}", entry.outbox_id, entry.attempts + 1);
        match client
            .post_batch(
                sender_kernel_id,
                &entry.recipient_kernel_id,
                &entry.batch,
                &nonce,
            )
            .await
        {
            Ok(receive_report) if receive_report.accepted => {
                store.mark_delivered(&entry.outbox_id)?;
                report.delivered = report.delivered.saturating_add(1);
            }
            Ok(receive_report) => {
                let code = receive_report
                    .frames
                    .iter()
                    .find(|frame| !frame.accepted)
                    .map(|frame| frame.code.as_str())
                    .unwrap_or("receiver_rejected");
                mark_delivery_failure(store, &entry, code, now_unix_ms, &mut report)?;
            }
            Err(error) => {
                mark_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            }
        }
    }
    Ok(report)
}

/// Enforce the OUTBOUND per-peer directory scope for a queued batch before it is
/// dialed: the recipient must be a `Receiver`/`Hub` in the CURRENT directory, within
/// its per-peer frame cap, subscribed to the batch treaty, and within its pinned
/// transit ladders. Mirrors [`enforce_peer_batch_directory_scope`] (the inbound gate)
/// on the send side.
///
/// The HTTP relay tick (`deliver_due_batches`) applies this before every
/// `post_batch`; it is exposed so an iroh outbound drain (the relay tick's
/// `--iroh-enable` path) applies the IDENTICAL scope gate against the same peer
/// directory before it dials a recipient over the transport (fail-closed).
pub fn enforce_outbound_peer_batch_directory_scope(
    directory: &PeerDirectory,
    recipient_kernel_id: &str,
    batch: &PheromoneGossipBatch,
) -> Result<(), PheromoneRelayError> {
    if batch.recipient_kernel_id != recipient_kernel_id {
        return Err(PheromoneRelayError::RecipientMismatch(format!(
            "queued batch recipient {} does not match outbox recipient {}",
            batch.recipient_kernel_id, recipient_kernel_id
        )));
    }
    let peer = directory.peer(recipient_kernel_id)?;
    let frame_count = batch.frames.len();
    if !matches!(peer.relay_role, RelayRole::Receiver | RelayRole::Hub) {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "recipient {recipient_kernel_id} is not authorized to receive outbound batches"
        )));
    }
    if frame_count > peer.max_batch_frames {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "recipient {recipient_kernel_id} is limited to {} batch frames but queued batch has {frame_count}",
            peer.max_batch_frames
        )));
    }
    if !peer.treaty_subscriptions.contains(&batch.treaty_id) {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "recipient {recipient_kernel_id} is not subscribed to treaty {}",
            batch.treaty_id
        )));
    }
    enforce_peer_transit_ladder_pins(peer, recipient_kernel_id, batch)?;
    Ok(())
}

fn enforce_peer_transit_ladder_pins(
    peer: &PeerDirectoryEntry,
    peer_kernel_id: &str,
    batch: &PheromoneGossipBatch,
) -> Result<(), PheromoneRelayError> {
    for frame in &batch.frames {
        let Some(chain) = frame.transit_chain.as_ref() else {
            continue;
        };
        for hop in &chain.hops {
            if hop.from_kernel_id != peer_kernel_id && hop.to_kernel_id != peer_kernel_id {
                continue;
            }
            if !relay_ladder_ref_matches(&peer.accepted_ladder_refs, hop) {
                return Err(PheromoneRelayError::RelayProfileDenied(format!(
                    "peer {peer_kernel_id} transit ladder {}:{} is not pinned in the directory",
                    hop.ladder_manifest_id, hop.ladder_manifest_sha256
                )));
            }
        }
    }
    Ok(())
}

fn relay_ladder_ref_matches(
    accepted: &[RelayLadderRef],
    hop: &chio_federation::pheromone_gossip::PheromoneTransitHop,
) -> bool {
    accepted.iter().any(|reference| {
        reference.ladder_manifest_id == hop.ladder_manifest_id
            && reference.ladder_manifest_sha256 == hop.ladder_manifest_sha256
            && reference.expires_at_unix_ms == hop.ladder_manifest_expires_at_unix_ms
    })
}

pub(crate) fn mark_delivery_failure(
    store: &(impl PheromoneRelayStore + ?Sized),
    entry: &RelayOutboxBatch,
    code: &str,
    now_unix_ms: u64,
    report: &mut RelayTickReport,
) -> Result<(), PheromoneRelayError> {
    report.accepted = false;
    report.failures.push(format!("{}: {code}", entry.outbox_id));
    if entry.attempts.saturating_add(1) >= 3 {
        store.mark_dead_letter(&entry.outbox_id, code)?;
        report.dead_lettered = report.dead_lettered.saturating_add(1);
    } else {
        let backoff_ms = 60_000u64.saturating_mul(entry.attempts.saturating_add(1));
        store.mark_retry(
            &entry.outbox_id,
            code,
            now_unix_ms.saturating_add(backoff_ms),
        )?;
        report.retried = report.retried.saturating_add(1);
    }
    Ok(())
}

pub(crate) fn system_unix_ms() -> Option<u64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

pub(crate) fn sanitize_event_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{PheromoneReceiveReport, RelayBatchReceiver};
    use crate::PheromoneRelayError;
    use async_trait::async_trait;
    use chio_federation::pheromone_gossip::PheromoneGossipBatch;

    struct SilentReceiver;

    #[async_trait]
    impl RelayBatchReceiver for SilentReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
            unreachable!("not exercised by this test")
        }
    }

    #[tokio::test]
    async fn recorded_report_for_batch_defaults_to_none() {
        let receiver = SilentReceiver;
        let recovered = receiver
            .recorded_report_for_batch("any-batch-hash", "did:chio:alice")
            .await
            .expect("default recovery method runs");
        assert!(
            recovered.is_none(),
            "a receiver with no durable report cannot recover"
        );
    }
}
