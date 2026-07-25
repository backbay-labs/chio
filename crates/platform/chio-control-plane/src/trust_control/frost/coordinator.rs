use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chio_federation::frost::{
    resolve_active_roster_for_execution, ActiveFrostRosterResolver, FrostArtifactTrustStore,
    FrostAuthorizationBodyV1, FrostAuthorizationSlotAnchorWriter, FrostEpochAnchor,
    VerifiedActiveFrostRoster,
};
use chio_store_sqlite::{
    FrostCoordinatorCancellation, FrostCoordinatorCommitment, FrostCoordinatorLease,
    FrostCoordinatorSessionRecord, FrostCoordinatorSessionRequest, FrostCoordinatorShare,
    FrostCoordinatorSigningPackage, FrostStoreError, SqliteAuthorityStore, SqliteFrostStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 4096;
const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_COMMITMENT_BYTES: usize = 4096;
const MAX_SIGNER_IDENTIFIER_BYTES: usize = 128;
const MAX_SIGNATURE_SHARE_BYTES: usize = 1024;

pub const FROST_COORDINATOR_CLAIM_PATH: &str = "/v1/frost/coordinator/sessions/claim";
pub const FROST_COORDINATOR_RENEW_PATH: &str = "/v1/frost/coordinator/sessions/renew";
pub const FROST_COORDINATOR_COMMITMENT_PATH: &str = "/v1/frost/coordinator/sessions/commitments";
pub const FROST_COORDINATOR_PACKAGE_PATH: &str = "/v1/frost/coordinator/sessions/package";
pub const FROST_COORDINATOR_SHARE_PATH: &str = "/v1/frost/coordinator/sessions/shares";
pub const FROST_COORDINATOR_COMPLETE_PATH: &str = "/v1/frost/coordinator/sessions/complete";
pub const FROST_COORDINATOR_CANCEL_PATH: &str = "/v1/frost/coordinator/sessions/cancel";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrostCoordinatorPrincipalRole {
    Coordinator,
    Participant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostCoordinatorPrincipal {
    subject_id: String,
    coordinator_id: String,
    role: FrostCoordinatorPrincipalRole,
    participant_id: Option<String>,
}

impl FrostCoordinatorPrincipal {
    pub fn coordinator(
        subject_id: impl Into<String>,
        coordinator_id: impl Into<String>,
    ) -> Result<Self, FrostCoordinatorAuthError> {
        Self::new(
            subject_id.into(),
            coordinator_id.into(),
            FrostCoordinatorPrincipalRole::Coordinator,
            None,
        )
    }

    pub fn participant(
        subject_id: impl Into<String>,
        coordinator_id: impl Into<String>,
        participant_id: impl Into<String>,
    ) -> Result<Self, FrostCoordinatorAuthError> {
        Self::new(
            subject_id.into(),
            coordinator_id.into(),
            FrostCoordinatorPrincipalRole::Participant,
            Some(participant_id.into()),
        )
    }

    fn new(
        subject_id: String,
        coordinator_id: String,
        role: FrostCoordinatorPrincipalRole,
        participant_id: Option<String>,
    ) -> Result<Self, FrostCoordinatorAuthError> {
        validate_identity(&subject_id)?;
        validate_identity(&coordinator_id)?;
        if let Some(participant_id) = participant_id.as_deref() {
            validate_identity(participant_id)?;
        }
        if (role == FrostCoordinatorPrincipalRole::Coordinator && participant_id.is_some())
            || (role == FrostCoordinatorPrincipalRole::Participant && participant_id.is_none())
        {
            return Err(FrostCoordinatorAuthError::InvalidPrincipal);
        }
        Ok(Self {
            subject_id,
            coordinator_id,
            role,
            participant_id,
        })
    }

    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    #[must_use]
    pub fn coordinator_id(&self) -> &str {
        &self.coordinator_id
    }
}

pub struct FrostCoordinatorCredential {
    bearer_token: String,
    principal: FrostCoordinatorPrincipal,
}

impl std::fmt::Debug for FrostCoordinatorCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostCoordinatorCredential")
            .field("bearer_token", &"<redacted>")
            .field("principal", &self.principal)
            .finish()
    }
}

impl FrostCoordinatorCredential {
    pub fn new(
        bearer_token: impl Into<String>,
        principal: FrostCoordinatorPrincipal,
    ) -> Result<Self, FrostCoordinatorAuthError> {
        let bearer_token = bearer_token.into();
        validate_token(&bearer_token)?;
        Ok(Self {
            bearer_token,
            principal,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrostCoordinatorAuthError {
    #[error("invalid FROST coordinator principal")]
    InvalidPrincipal,
    #[error("invalid FROST coordinator bearer token")]
    InvalidToken,
    #[error("duplicate FROST coordinator bearer credential")]
    DuplicateCredential,
}

#[derive(Clone)]
pub struct FrostCoordinatorCredentialRegistry {
    credentials: Arc<Vec<StoredCredential>>,
}

impl std::fmt::Debug for FrostCoordinatorCredentialRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostCoordinatorCredentialRegistry")
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

#[derive(Clone)]
struct StoredCredential {
    token_digest: [u8; 32],
    principal: FrostCoordinatorPrincipal,
}

impl FrostCoordinatorCredentialRegistry {
    pub fn new(
        credentials: impl IntoIterator<Item = FrostCoordinatorCredential>,
    ) -> Result<Self, FrostCoordinatorAuthError> {
        let mut stored = Vec::new();
        let mut digests = BTreeSet::new();
        for credential in credentials {
            let digest = token_digest(&credential.bearer_token);
            if !digests.insert(digest) {
                return Err(FrostCoordinatorAuthError::DuplicateCredential);
            }
            stored.push(StoredCredential {
                token_digest: digest,
                principal: credential.principal,
            });
        }
        if stored.is_empty() {
            return Err(FrostCoordinatorAuthError::InvalidToken);
        }
        Ok(Self {
            credentials: Arc::new(stored),
        })
    }

    fn authenticate(&self, token: &str) -> Option<FrostCoordinatorPrincipal> {
        if validate_token(token).is_err() {
            return None;
        }
        let candidate = token_digest(token);
        let mut matched = None;
        for credential in self.credentials.iter() {
            if bool::from(candidate.ct_eq(&credential.token_digest)) {
                matched = Some(credential.principal.clone());
            }
        }
        matched
    }
}

pub trait FrostCoordinatorClock: Send + Sync {
    fn now_unix_ms(&self) -> Result<u64, FrostCoordinatorControlError>;
}

pub trait FrostSignerBurnFanout: Send + Sync {
    fn burn_signer_sessions(
        &self,
        request: &FrostSignerBurnRequest<'_>,
    ) -> Result<(), FrostSignerBurnFanoutError>;
}

pub struct FrostSignerBurnRequest<'a> {
    pub coordinator_id: &'a str,
    pub body: &'a FrostAuthorizationBodyV1,
    pub session_id: &'a str,
    pub participant_ids: &'a [String],
    pub reason: &'a str,
}

#[derive(Debug, thiserror::Error)]
#[error("FROST signer burn fanout failed: {0}")]
pub struct FrostSignerBurnFanoutError(pub String);

#[derive(Debug, Default)]
pub struct SystemFrostCoordinatorClock;

impl FrostCoordinatorClock for SystemFrostCoordinatorClock {
    fn now_unix_ms(&self) -> Result<u64, FrostCoordinatorControlError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FrostCoordinatorControlError::Clock)?
            .as_millis();
        u64::try_from(millis).map_err(|_| FrostCoordinatorControlError::Clock)
    }
}

pub struct FrostCoordinatorControl {
    authority: Arc<SqliteAuthorityStore>,
    store: SqliteFrostStore,
    roster_resolver: Arc<dyn ActiveFrostRosterResolver>,
    epoch_anchor: Arc<dyn FrostEpochAnchor>,
    slot_anchor: Arc<dyn FrostAuthorizationSlotAnchorWriter>,
    artifact_trust: FrostArtifactTrustStore,
    clock: Arc<dyn FrostCoordinatorClock>,
    signer_burn_fanout: Arc<dyn FrostSignerBurnFanout>,
}

impl std::fmt::Debug for FrostCoordinatorControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostCoordinatorControl")
            .finish_non_exhaustive()
    }
}

impl FrostCoordinatorControl {
    pub fn new(
        authority: Arc<SqliteAuthorityStore>,
        roster_resolver: Arc<dyn ActiveFrostRosterResolver>,
        epoch_anchor: Arc<dyn FrostEpochAnchor>,
        slot_anchor: Arc<dyn FrostAuthorizationSlotAnchorWriter>,
        artifact_trust: FrostArtifactTrustStore,
        clock: Arc<dyn FrostCoordinatorClock>,
        signer_burn_fanout: Arc<dyn FrostSignerBurnFanout>,
    ) -> Self {
        let store = authority.frost_store();
        Self {
            authority,
            store,
            roster_resolver,
            epoch_anchor,
            slot_anchor,
            artifact_trust,
            clock,
            signer_burn_fanout,
        }
    }

    fn now(&self) -> Result<u64, FrostCoordinatorControlError> {
        self.clock.now_unix_ms()
    }

    fn active_roster(
        &self,
        body: &FrostAuthorizationBodyV1,
        now: u64,
    ) -> Result<VerifiedActiveFrostRoster, FrostCoordinatorControlError> {
        resolve_active_roster_for_execution(
            &body.scope_id,
            self.roster_resolver.as_ref(),
            self.epoch_anchor.as_ref(),
            &self.artifact_trust,
            now,
        )
        .map_err(|error| FrostCoordinatorControlError::Trust(error.to_string()))
    }

    fn request<'a>(
        &'a self,
        body: &'a FrostAuthorizationBodyV1,
        active_roster: &'a VerifiedActiveFrostRoster,
        coordinator_id: &'a str,
    ) -> FrostCoordinatorSessionRequest<'a> {
        FrostCoordinatorSessionRequest {
            body,
            active_roster,
            epoch_anchor: self.epoch_anchor.as_ref(),
            slot_anchor: self.slot_anchor.as_ref(),
            artifact_trust: &self.artifact_trust,
            coordinator_id,
        }
    }

    pub fn claim(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorClaimRequest,
    ) -> Result<FrostCoordinatorLease, FrostCoordinatorControlError> {
        authorize_coordinator(principal)?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        self.store
            .claim_coordinator_session(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.worker_id,
                &input.lease_id,
                input.lease_ttl_ms,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn renew(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorRenewRequest,
    ) -> Result<FrostCoordinatorLease, FrostCoordinatorControlError> {
        authorize_coordinator(principal)?;
        authorize_lease(principal, &input.lease)?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        self.store
            .renew_coordinator_lease(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.lease,
                input.lease_ttl_ms,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn submit_commitment(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorCommitmentRequest,
    ) -> Result<FrostCoordinatorSessionRecord, FrostCoordinatorControlError> {
        authorize_lease(principal, &input.lease)?;
        let signer_identifier = decode_hex(
            &input.signer_identifier,
            MAX_SIGNER_IDENTIFIER_BYTES,
            "signer identifier",
        )?;
        let commitment_bytes = decode_hex(
            &input.commitment,
            MAX_COMMITMENT_BYTES,
            "signing commitment",
        )?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        authorize_participant(principal, &input.participant_id, &active)?;
        let commitment = FrostCoordinatorCommitment {
            participant_id: input.participant_id,
            signer_identifier,
            commitment_bytes,
        };
        self.store
            .submit_coordinator_commitment(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.lease,
                &commitment,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn build_package(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorLeaseRequest,
    ) -> Result<FrostCoordinatorSigningPackage, FrostCoordinatorControlError> {
        authorize_coordinator(principal)?;
        authorize_lease(principal, &input.lease)?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        self.store
            .build_coordinator_signing_package(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.lease,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn submit_share(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorShareRequest,
    ) -> Result<FrostCoordinatorSessionRecord, FrostCoordinatorControlError> {
        authorize_lease(principal, &input.lease)?;
        let share_bytes = decode_hex(
            &input.signature_share,
            MAX_SIGNATURE_SHARE_BYTES,
            "signature share",
        )?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        authorize_participant(principal, &input.participant_id, &active)?;
        let share = FrostCoordinatorShare {
            participant_id: input.participant_id,
            share_bytes,
        };
        self.store
            .submit_coordinator_share(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.lease,
                &share,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn complete(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorCompleteRequest,
    ) -> Result<chio_federation::frost::FrostAuthorizationV1, FrostCoordinatorControlError> {
        authorize_coordinator(principal)?;
        authorize_lease(principal, &input.lease)?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        self.store
            .complete_coordinator_session(
                &self.request(&input.body, &active, principal.coordinator_id()),
                &input.lease,
                &input.availability_receipt,
                &self.authority.mutation_fence(),
                now,
            )
            .map_err(Into::into)
    }

    pub fn cancel(
        &self,
        principal: &FrostCoordinatorPrincipal,
        input: FrostCoordinatorCancelRequest,
    ) -> Result<FrostCoordinatorCancellation, FrostCoordinatorControlError> {
        authorize_coordinator(principal)?;
        authorize_lease(principal, &input.lease)?;
        let now = self.now()?;
        let active = self.active_roster(&input.body, now)?;
        let cancellation = self.store.cancel_coordinator_session(
            &self.request(&input.body, &active, principal.coordinator_id()),
            &input.lease,
            &input.reason,
            &self.authority.mutation_fence(),
            now,
        )?;
        self.signer_burn_fanout
            .burn_signer_sessions(&FrostSignerBurnRequest {
                coordinator_id: principal.coordinator_id(),
                body: &input.body,
                session_id: &cancellation.session.session_id,
                participant_ids: &cancellation.participant_ids,
                reason: &input.reason,
            })
            .map_err(|error| FrostCoordinatorControlError::Fanout(error.to_string()))?;
        Ok(cancellation)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrostCoordinatorControlError {
    #[error("FROST coordinator principal is not authorized for this operation")]
    Unauthorized,
    #[error("invalid FROST coordinator request: {0}")]
    InvalidRequest(String),
    #[error("FROST coordinator trust resolution failed: {0}")]
    Trust(String),
    #[error("FROST coordinator clock is unavailable")]
    Clock,
    #[error("{0}")]
    Fanout(String),
    #[error(transparent)]
    Store(#[from] FrostStoreError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorClaimRequest {
    pub body: FrostAuthorizationBodyV1,
    pub worker_id: String,
    pub lease_id: String,
    pub lease_ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorRenewRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
    pub lease_ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorLeaseRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorCommitmentRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
    pub participant_id: String,
    pub signer_identifier: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorShareRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
    pub participant_id: String,
    pub signature_share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorCompleteRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
    pub availability_receipt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorCancelRequest {
    pub body: FrostAuthorizationBodyV1,
    pub lease: FrostCoordinatorLease,
    pub reason: String,
}

#[derive(Clone)]
struct FrostCoordinatorHttpState {
    control: Arc<FrostCoordinatorControl>,
    credentials: FrostCoordinatorCredentialRegistry,
}

pub fn frost_coordinator_router(
    control: Arc<FrostCoordinatorControl>,
    credentials: FrostCoordinatorCredentialRegistry,
) -> Router {
    Router::new()
        .route(FROST_COORDINATOR_CLAIM_PATH, post(handle_claim))
        .route(FROST_COORDINATOR_RENEW_PATH, post(handle_renew))
        .route(FROST_COORDINATOR_COMMITMENT_PATH, post(handle_commitment))
        .route(FROST_COORDINATOR_PACKAGE_PATH, post(handle_package))
        .route(FROST_COORDINATOR_SHARE_PATH, post(handle_share))
        .route(FROST_COORDINATOR_COMPLETE_PATH, post(handle_complete))
        .route(FROST_COORDINATOR_CANCEL_PATH, post(handle_cancel))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(FrostCoordinatorHttpState {
            control,
            credentials,
        })
}

async fn handle_claim(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorClaimRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.claim(&principal, input)).await
}

async fn handle_renew(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorRenewRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.renew(&principal, input)).await
}

async fn handle_commitment(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorCommitmentRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.submit_commitment(&principal, input)).await
}

async fn handle_package(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorLeaseRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.build_package(&principal, input)).await
}

async fn handle_share(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorShareRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.submit_share(&principal, input)).await
}

async fn handle_complete(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorCompleteRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.complete(&principal, input)).await
}

async fn handle_cancel(
    State(state): State<FrostCoordinatorHttpState>,
    headers: HeaderMap,
    Json(input): Json<FrostCoordinatorCancelRequest>,
) -> Response {
    let principal = match authenticate(&state.credentials, &headers) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    blocking(move || state.control.cancel(&principal, input)).await
}

async fn blocking<T, F>(operation: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> Result<T, FrostCoordinatorControlError> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => control_error_response(error),
        Err(_) => plain_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FROST coordinator worker failed",
        ),
    }
}

fn authenticate(
    credentials: &FrostCoordinatorCredentialRegistry,
    headers: &HeaderMap,
) -> Result<FrostCoordinatorPrincipal, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| plain_error(StatusCode::UNAUTHORIZED, "authentication required"))?;
    credentials
        .authenticate(token)
        .ok_or_else(|| plain_error(StatusCode::UNAUTHORIZED, "authentication required"))
}

fn authorize_coordinator(
    principal: &FrostCoordinatorPrincipal,
) -> Result<(), FrostCoordinatorControlError> {
    if principal.role == FrostCoordinatorPrincipalRole::Coordinator {
        Ok(())
    } else {
        Err(FrostCoordinatorControlError::Unauthorized)
    }
}

fn authorize_lease(
    principal: &FrostCoordinatorPrincipal,
    lease: &FrostCoordinatorLease,
) -> Result<(), FrostCoordinatorControlError> {
    if principal.coordinator_id == lease.coordinator_id {
        Ok(())
    } else {
        Err(FrostCoordinatorControlError::Unauthorized)
    }
}

fn authorize_participant(
    principal: &FrostCoordinatorPrincipal,
    participant_id: &str,
    active_roster: &VerifiedActiveFrostRoster,
) -> Result<(), FrostCoordinatorControlError> {
    authorize_participant_identity(
        principal,
        participant_id,
        active_roster
            .participant_verification_share(participant_id)
            .is_some(),
    )
}

fn authorize_participant_identity(
    principal: &FrostCoordinatorPrincipal,
    participant_id: &str,
    roster_contains_participant: bool,
) -> Result<(), FrostCoordinatorControlError> {
    if principal.role == FrostCoordinatorPrincipalRole::Participant
        && principal.participant_id.as_deref() == Some(participant_id)
        && roster_contains_participant
    {
        Ok(())
    } else {
        Err(FrostCoordinatorControlError::Unauthorized)
    }
}

fn decode_hex(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, FrostCoordinatorControlError> {
    if value.is_empty()
        || value.len() > max_bytes.saturating_mul(2)
        || !value.len().is_multiple_of(2)
    {
        return Err(FrostCoordinatorControlError::InvalidRequest(format!(
            "{field} length is outside the supported range"
        )));
    }
    hex::decode(value)
        .map_err(|_| FrostCoordinatorControlError::InvalidRequest(format!("{field} is not hex")))
}

fn validate_identity(value: &str) -> Result<(), FrostCoordinatorAuthError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(FrostCoordinatorAuthError::InvalidPrincipal)
    } else {
        Ok(())
    }
}

fn validate_token(token: &str) -> Result<(), FrostCoordinatorAuthError> {
    if token.len() < MIN_BEARER_TOKEN_BYTES
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || token.trim() != token
        || token.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(FrostCoordinatorAuthError::InvalidToken)
    } else {
        Ok(())
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn control_error_response(error: FrostCoordinatorControlError) -> Response {
    let status = match &error {
        FrostCoordinatorControlError::Unauthorized => StatusCode::FORBIDDEN,
        FrostCoordinatorControlError::InvalidRequest(_)
        | FrostCoordinatorControlError::Store(FrostStoreError::InvalidState(_)) => {
            StatusCode::BAD_REQUEST
        }
        FrostCoordinatorControlError::Store(FrostStoreError::Conflict(_))
        | FrostCoordinatorControlError::Store(FrostStoreError::Fenced) => StatusCode::CONFLICT,
        FrostCoordinatorControlError::Trust(_)
        | FrostCoordinatorControlError::Clock
        | FrostCoordinatorControlError::Fanout(_)
        | FrostCoordinatorControlError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    plain_error(status, &error.to_string())
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (status, Json(ErrorResponse { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(byte: char) -> String {
        std::iter::repeat_n(byte, MIN_BEARER_TOKEN_BYTES).collect()
    }

    #[test]
    fn credentials_are_unique_redacted_and_bound_to_one_role() {
        let coordinator = FrostCoordinatorPrincipal::coordinator("service-1", "coordinator-1")
            .unwrap_or_else(|error| panic!("coordinator principal: {error}"));
        let participant = FrostCoordinatorPrincipal::participant(
            "operator-service-1",
            "coordinator-1",
            "operator-1",
        )
        .unwrap_or_else(|error| panic!("participant principal: {error}"));
        let credential = FrostCoordinatorCredential::new(token('a'), coordinator.clone())
            .unwrap_or_else(|error| panic!("coordinator credential: {error}"));
        assert!(!format!("{credential:?}").contains(&token('a')));
        let registry = FrostCoordinatorCredentialRegistry::new([
            credential,
            FrostCoordinatorCredential::new(token('b'), participant.clone())
                .unwrap_or_else(|error| panic!("participant credential: {error}")),
        ])
        .unwrap_or_else(|error| panic!("credential registry: {error}"));
        assert_eq!(registry.authenticate(&token('a')), Some(coordinator));
        assert_eq!(registry.authenticate(&token('b')), Some(participant));
        assert!(registry.authenticate(&token('c')).is_none());
        assert!(FrostCoordinatorCredentialRegistry::new([
            FrostCoordinatorCredential::new(
                token('a'),
                FrostCoordinatorPrincipal::coordinator("service-1", "coordinator-1")
                    .unwrap_or_else(|error| panic!("coordinator principal: {error}")),
            )
            .unwrap_or_else(|error| panic!("first credential: {error}")),
            FrostCoordinatorCredential::new(
                token('a'),
                FrostCoordinatorPrincipal::coordinator("service-2", "coordinator-2")
                    .unwrap_or_else(|error| panic!("coordinator principal: {error}")),
            )
            .unwrap_or_else(|error| panic!("second credential: {error}")),
        ])
        .is_err());
    }

    #[test]
    fn participant_identity_must_match_both_credential_and_roster() {
        let participant = FrostCoordinatorPrincipal::participant(
            "operator-service-1",
            "coordinator-1",
            "operator-1",
        )
        .unwrap_or_else(|error| panic!("participant principal: {error}"));
        assert!(authorize_participant_identity(&participant, "operator-1", true).is_ok());
        assert!(authorize_participant_identity(&participant, "operator-2", true).is_err());
        assert!(authorize_participant_identity(&participant, "operator-1", false).is_err());
        let coordinator = FrostCoordinatorPrincipal::coordinator("service-1", "coordinator-1")
            .unwrap_or_else(|error| panic!("coordinator principal: {error}"));
        assert!(authorize_participant_identity(&coordinator, "operator-1", true).is_err());
    }

    #[test]
    fn wire_payload_decoding_is_bounded_and_strict() {
        assert_eq!(
            decode_hex("0102", 2, "value").unwrap_or_else(|error| panic!("decode value: {error}")),
            vec![1, 2]
        );
        assert!(decode_hex("0", 2, "value").is_err());
        assert!(decode_hex("000000", 2, "value").is_err());
        assert!(decode_hex("zz", 2, "value").is_err());
    }
}
