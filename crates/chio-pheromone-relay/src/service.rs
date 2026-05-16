use crate::{
    canonical_sha256, CatchupRequest, CatchupResponse, PeerDirectory, PheromoneRelayClient,
    PheromoneRelayError, PheromoneRelayHttpRequest, PheromoneRelayStore, RelayEventReport,
    RelayHealthReport, RelayHttpVerificationContext, RelayMetricsFormat, RelayObservabilityInput,
    RelayObservabilityReport, RelayOperatorReport, RelayOutboxBatch, RelayProfile,
    RelayProfileLimits, RelayTickReport, SqlitePheromoneRelayStore, PHEROMONE_BATCH_RELAY_PATH,
    PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_CATCHUP_RESPONSE_SCHEMA, PHEROMONE_HEALTH_PATH, PHEROMONE_READY_PATH,
    PHEROMONE_RELAY_DRILL_REPORT_SCHEMA, PHEROMONE_RELAY_EVENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_METRICS_PATH, PHEROMONE_RELAY_OBSERVABILITY_PATH,
    PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA, PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA,
    PHEROMONE_RELAY_TICK_REPORT_SCHEMA,
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
use chio_federation::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use serde::Deserialize;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
        profile.reverse_proxy.pinned_path_prefix == "/v1/chiodos/pheromone",
        "pinned_path_prefix",
        "reverse proxy pins the Chiodos pheromone path prefix",
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
}

#[derive(Clone)]
pub struct PheromoneRelayService {
    config: PheromoneRelayConfig,
    directory: PeerDirectory,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
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
        }
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
        axum::serve(listener, router)
            .await
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
    Ok((
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        snapshot.render(RelayMetricsFormat::Prometheus),
    )
        .into_response())
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
    enforce_peer_batch_frame_limit(&service.directory, &request.sender_kernel_id, &batch)
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

fn enforce_peer_batch_frame_limit(
    directory: &PeerDirectory,
    sender_kernel_id: &str,
    batch: &PheromoneGossipBatch,
) -> Result<(), PheromoneRelayError> {
    let peer = directory.peer(sender_kernel_id)?;
    let frame_count = batch.frames.len();
    if frame_count > peer.max_batch_frames {
        return Err(PheromoneRelayError::RelayProfileDenied(format!(
            "peer {sender_kernel_id} submitted {frame_count} batch frames, exceeding directory max {}",
            peer.max_batch_frames
        )));
    }
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
        .is_some_and(|value| value == format!("Bearer {token}"));
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
