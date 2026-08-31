//! Authenticated HTTP ingress for durable cognition-market challenge filings.
//!
//! The request body is the registered signed challenge envelope itself. The
//! handler preserves those exact canonical bytes, resolves the exact immutable
//! Finding bytes from the venue store, and passes both views to an explicitly
//! configured submission executor. Deployments that do not configure that
//! executor fail closed before any filing side effect.

use axum::body::{Body, Bytes};
use axum::extract::Request;
use chio_finding::{verify_signed_challenge, Finding, SignedFindingChallenge};
use chio_store_sqlite::{
    FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass,
    FindingChallengeOutcomeRecord, FindingChallengeRecord, FindingChallengeState,
    FindingChallengeWriteOutcome,
};

use super::finding_challenge_coordinator::{
    ChallengeCoordinatorError, ChallengeSubmissionOutcome, FindingAuthorityStatusResolver,
    FindingChallengeCoordinator,
};
use super::finding_handlers::{
    finding_market_context, strict_artifact_ingress, FINDING_PUBLISH_MAX_BODY_BYTES,
};
use super::report_validation::validate_service_auth;
use super::*;

const FINDING_CHALLENGE_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/challenge.schema.json");
const FINDING_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/finding.schema.json");
const FINDING_CHALLENGE_SCHEMA_LABEL: &str = "chio-finding/v1/challenge.schema.json";
const FINDING_SCHEMA_LABEL: &str = "chio-finding/v1/finding.schema.json";

/// Maximum raw signed challenge-envelope size accepted at HTTP ingress.
///
/// The CLI bounds its operator evidence document at 512 KiB before adding
/// derived fields and the signed-envelope wrapper. One MiB admits every valid
/// CLI construction while keeping parsing and canonicalization bounded.
pub(crate) const FINDING_CHALLENGE_SUBMIT_MAX_BODY_BYTES: usize = 1024 * 1024;
const FINDING_CHALLENGE_BODY_READ_DEADLINE: Duration = Duration::from_secs(30);

/// Closed route request over the registered signed challenge envelope.
///
/// `transparent` keeps the wire bytes identical to `SignedFindingChallenge`.
/// There is no caller-supplied Finding field: the venue reloads its own exact
/// stored artifact bytes after the signed finding id is authenticated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct FindingChallengeSubmissionRequest {
    pub challenge: SignedFindingChallenge,
}

/// The authorization branch the durable coordinator accepted.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingChallengeSubmissionAuthorization {
    BuyerSubmission,
    VenueAudit,
}

/// Whether this request inserted the challenge row or replayed identical state.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingChallengeSubmissionWrite {
    Inserted,
    ExistingSame,
}

/// Closed stable response for one durable challenge submission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingChallengeSubmissionResponse {
    pub challenge_id: String,
    pub authorization_branch: FindingChallengeSubmissionAuthorization,
    pub write: FindingChallengeSubmissionWrite,
    pub dispute_fee_intent_key: Option<String>,
    pub dispute_bond_lock_id: Option<String>,
}

/// Stable authenticated projection of one durable challenge lifecycle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingChallengeStatusResponse {
    pub schema: String,
    pub challenge_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub challenge_envelope_sha256: String,
    pub authorization_branch: String,
    pub evidence_class: String,
    pub state: String,
    pub retry_count: u64,
    pub retry_deadline: Option<u64>,
    pub outcome_envelope_sha256: Option<String>,
    pub outcome: Option<serde_json::Value>,
    pub submitted_at: u64,
    pub updated_at: u64,
}

const FINDING_CHALLENGE_STATUS_SCHEMA: &str = "chio.finding.challenge-status.v1";

impl From<ChallengeSubmissionOutcome> for FindingChallengeSubmissionResponse {
    fn from(outcome: ChallengeSubmissionOutcome) -> Self {
        let authorization_branch = match outcome.branch {
            FindingChallengeAuthorizationBranch::BuyerSubmission => {
                FindingChallengeSubmissionAuthorization::BuyerSubmission
            }
            FindingChallengeAuthorizationBranch::VenueAudit => {
                FindingChallengeSubmissionAuthorization::VenueAudit
            }
        };
        let write = match outcome.write {
            FindingChallengeWriteOutcome::Inserted => FindingChallengeSubmissionWrite::Inserted,
            FindingChallengeWriteOutcome::ExistingSame => {
                FindingChallengeSubmissionWrite::ExistingSame
            }
        };
        Self {
            challenge_id: outcome.challenge_id,
            authorization_branch,
            write,
            dispute_fee_intent_key: outcome.dispute_fee_intent_key,
            dispute_bond_lock_id: outcome.dispute_bond_lock_id,
        }
    }
}

/// Production submission seam for a fully configured durable coordinator.
///
/// Runtime construction cannot derive the coordinator's private role keys or
/// published-artifact resolver from public configuration. An embedding
/// deployment therefore injects this executor explicitly. The default service
/// carries no executor and the route fails closed.
pub(crate) trait FindingChallengeSubmissionExecutor: Send + Sync {
    fn submit(
        &self,
        request: &FindingChallengeSubmissionRequest,
        raw_challenge_envelope: &str,
        raw_finding: &str,
        now: u64,
    ) -> Result<ChallengeSubmissionOutcome, ChallengeCoordinatorError>;

    fn challenge(&self, challenge_id: &str) -> Result<Option<FindingChallengeRecord>, String> {
        let _ = challenge_id;
        Err("challenge status resolution is not configured".to_owned())
    }

    fn outcome(
        &self,
        outcome_envelope_sha256: &str,
    ) -> Result<Option<FindingChallengeOutcomeRecord>, String> {
        let _ = outcome_envelope_sha256;
        Err("challenge outcome resolution is not configured".to_owned())
    }
}

/// Checked production composition for the live challenge route.
///
/// The authority store supplies the Finding bytes the route authenticates;
/// the coordinator charges and locks through sibling stores. Construction
/// accepts the pair only when all of those stores share the same active
/// serving fence, preventing a filing from being validated in one authority
/// database and committed in another.
pub struct FindingChallengeSubmissionRuntime {
    joint_authority_store: Arc<SqliteAuthorityStore>,
    market_config: FindingMarketConfig,
    executor: Arc<dyn FindingChallengeSubmissionExecutor>,
    authority_status_resolver: Arc<dyn FindingAuthorityStatusResolver>,
}

impl FindingChallengeSubmissionRuntime {
    pub fn new(
        joint_authority_store: Arc<SqliteAuthorityStore>,
        coordinator: Arc<FindingChallengeCoordinator>,
    ) -> Result<Self, ChallengeCoordinatorError> {
        if joint_authority_store.mutation_fence() != coordinator.mutation_fence() {
            return Err(ChallengeCoordinatorError::Configuration(
                "challenge coordinator does not share the serving authority".to_string(),
            ));
        }
        let market_config = coordinator.market_config().clone();
        let authority_status_resolver = coordinator.authority_status_resolver();
        Ok(Self {
            joint_authority_store,
            market_config,
            executor: coordinator,
            authority_status_resolver,
        })
    }

    #[must_use]
    pub const fn market_config(&self) -> &FindingMarketConfig {
        &self.market_config
    }

    #[must_use]
    pub fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence {
        self.joint_authority_store.mutation_fence()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Arc<SqliteAuthorityStore>,
        Arc<dyn FindingChallengeSubmissionExecutor>,
        Arc<dyn FindingAuthorityStatusResolver>,
    ) {
        (
            self.joint_authority_store,
            self.executor,
            self.authority_status_resolver,
        )
    }
}

impl FindingChallengeSubmissionExecutor for FindingChallengeCoordinator {
    fn submit(
        &self,
        request: &FindingChallengeSubmissionRequest,
        raw_challenge_envelope: &str,
        raw_finding: &str,
        now: u64,
    ) -> Result<ChallengeSubmissionOutcome, ChallengeCoordinatorError> {
        let canonical = chio_core::canonical_json_bytes(&request.challenge)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if canonical.as_slice() != raw_challenge_envelope.as_bytes() {
            return Err(ChallengeCoordinatorError::Canonical);
        }
        FindingChallengeCoordinator::submit(self, &request.challenge, raw_finding, now)
    }

    fn challenge(&self, challenge_id: &str) -> Result<Option<FindingChallengeRecord>, String> {
        self.challenge_record(challenge_id)
            .map_err(|error| error.to_string())
    }

    fn outcome(
        &self,
        outcome_envelope_sha256: &str,
    ) -> Result<Option<FindingChallengeOutcomeRecord>, String> {
        self.challenge_outcome(outcome_envelope_sha256)
            .map_err(|error| error.to_string())
    }
}

/// POST /v1/findings/{finding_id}/challenges (service authenticated).
pub(crate) async fn handle_submit_finding_challenge(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    request: Request,
) -> Response {
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(executor) = state.finding_challenge_executor.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "finding challenge submission coordinator is not configured",
        );
    };

    let permit = match try_acquire_challenge_lane(&state.finding_challenge_submission_lane) {
        Ok(permit) => permit,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "finding challenge submission lane is busy",
            )
        }
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let (raw_challenge_envelope, permit) =
        match collect_challenge_body(body, permit, FINDING_CHALLENGE_BODY_READ_DEADLINE).await {
            Ok(collected) => collected,
            Err(response) => return response,
        };
    let executor = Arc::clone(executor);
    let purchase_executor = state.finding_purchase_executor.clone();
    let service_token = state.config.service_token.clone();
    let response = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let raw_challenge_envelope = match std::str::from_utf8(&raw_challenge_envelope) {
            Ok(raw) => raw,
            Err(_) => {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "finding challenge body is not UTF-8",
                )
            }
        };
        let (_, request) = match strict_artifact_ingress::<FindingChallengeSubmissionRequest>(
            raw_challenge_envelope,
            FINDING_CHALLENGE_SUBMIT_MAX_BODY_BYTES,
            FINDING_CHALLENGE_SCHEMA_JSON,
            FINDING_CHALLENGE_SCHEMA_LABEL,
        ) {
            Ok(accepted) => accepted,
            Err(response) => return response,
        };
        if request.challenge.body.finding_id != finding_id {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "challenge finding id does not match the request path",
            );
        }

        match &request.challenge.body.authorization {
            chio_finding::FindingChallengeAuthorization::BuyerSubmission(submission) => {
                let authenticated = purchase_executor.as_ref().and_then(|executor| {
                    bearer_token(&headers).and_then(|token| executor.authenticate_buyer(token).ok())
                });
                if let Some(buyer) = authenticated {
                    if buyer.public_key() != &submission.challenger {
                        return plain_http_error(
                            StatusCode::UNAUTHORIZED,
                            "buyer challenge credential does not match the challenger",
                        );
                    }
                } else if purchase_executor.is_some() {
                    return plain_http_error(
                        StatusCode::UNAUTHORIZED,
                        "buyer challenge authentication failed",
                    );
                } else if let Err(response) = validate_service_auth(&headers, &service_token) {
                    return response;
                }
            }
            chio_finding::FindingChallengeAuthorization::VenueAudit(_) => {
                if let Err(response) = validate_service_auth(&headers, &service_token) {
                    return response;
                }
            }
        }

        // A buyer signs for itself, while a venue audit signs under the
        // authority retained for the round it names. The coordinator resolves
        // that historical policy after binding the exact durable envelope.
        // Checking an audit against only the deployment's current key here
        // would strand an otherwise valid in-flight round after rotation.
        if matches!(
            &request.challenge.body.authorization,
            chio_finding::FindingChallengeAuthorization::BuyerSubmission(_)
        ) {
            let audit_authority = match config.audit_authority.key() {
                Ok(authority) => authority,
                Err(_) => {
                    return plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "finding challenge audit authority is misconfigured",
                    )
                }
            };
            if verify_signed_challenge(&request.challenge, &audit_authority).is_err() {
                return plain_http_error(StatusCode::BAD_REQUEST, "signed challenge rejected");
            }
        }

        let raw_finding = match store.get_finding_bytes(&finding_id) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return plain_http_error(StatusCode::NOT_FOUND, "unknown finding"),
            Err(_) => {
                return plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "finding store is unavailable",
                )
            }
        };
        let (_, stored_finding) = match strict_artifact_ingress::<Finding>(
            &raw_finding,
            FINDING_PUBLISH_MAX_BODY_BYTES,
            FINDING_SCHEMA_JSON,
            FINDING_SCHEMA_LABEL,
        ) {
            Ok(accepted) => accepted,
            Err(_) => {
                return plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "stored finding failed integrity verification",
                )
            }
        };
        if chio_finding::verify_finding(&stored_finding).is_err()
            || stored_finding.finding_id != finding_id
        {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "stored finding failed integrity verification",
            );
        }
        if chio_core::sha256_hex(raw_finding.as_bytes())
            != request.challenge.body.finding_artifact_sha256
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "challenge does not bind the stored finding",
            );
        }

        match executor.submit(
            &request,
            raw_challenge_envelope,
            &raw_finding,
            unix_timestamp_now(),
        ) {
            Ok(outcome) => Json(FindingChallengeSubmissionResponse::from(outcome)).into_response(),
            Err(error) if coordinator_unavailable(&error) => {
                plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
            }
            Err(error) => plain_http_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
        }
    })
    .await;
    match response {
        Ok(response) => response,
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding challenge submission worker failed",
        ),
    }
}

/// GET /v1/findings/{finding_id}/challenges/{challenge_id}.
///
/// A buyer credential may read only the challenge filed by its signing key.
/// The service credential may read either authorization branch for operator
/// reconciliation. The response omits the challenge evidence body and exposes
/// a signed outcome only after its retained bytes pass canonical and digest
/// checks again.
pub(crate) async fn handle_get_finding_challenge(
    State(state): State<TrustServiceState>,
    AxumPath((finding_id, challenge_id)): AxumPath<(String, String)>,
    request: Request,
) -> Response {
    if !is_lower_hex_64(&finding_id) || !is_lower_hex_64(&challenge_id) {
        return plain_http_error(StatusCode::BAD_REQUEST, "invalid challenge identity");
    }
    let Some(executor) = state.finding_challenge_executor.clone() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "finding challenge coordinator is not configured",
        );
    };
    let permit = match try_acquire_challenge_lane(&state.finding_challenge_submission_lane) {
        Ok(permit) => permit,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "finding challenge lane is busy",
            )
        }
    };
    let headers = request.headers().clone();
    let purchase_executor = state.finding_purchase_executor.clone();
    let service_token = state.config.service_token.clone();
    let response = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let record = match executor.challenge(&challenge_id) {
            Ok(Some(record)) if record.finding_id == finding_id => record,
            Ok(Some(_)) | Ok(None) => {
                return plain_http_error(StatusCode::NOT_FOUND, "unknown finding challenge")
            }
            Err(_) => {
                return plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "finding challenge store is unavailable",
                )
            }
        };
        let service_authenticated = validate_service_auth(&headers, &service_token).is_ok();
        match record.authorization_branch {
            FindingChallengeAuthorizationBranch::BuyerSubmission if !service_authenticated => {
                let authenticated = purchase_executor.as_ref().and_then(|purchase| {
                    bearer_token(&headers).and_then(|token| purchase.authenticate_buyer(token).ok())
                });
                if authenticated
                    .as_ref()
                    .map(|buyer| buyer.public_key().to_hex())
                    != record.challenger_hex
                {
                    return plain_http_error(
                        StatusCode::UNAUTHORIZED,
                        "finding challenge authentication failed",
                    );
                }
            }
            FindingChallengeAuthorizationBranch::VenueAudit if !service_authenticated => {
                return plain_http_error(
                    StatusCode::UNAUTHORIZED,
                    "finding challenge authentication failed",
                )
            }
            _ => {}
        }

        let outcome = match record.outcome_envelope_sha256.as_deref() {
            Some(digest) => match executor.outcome(digest) {
                Ok(Some(outcome)) if outcome.challenge_id == record.challenge_id => {
                    match checked_outcome_json(&outcome) {
                        Ok(value) => Some(value),
                        Err(()) => {
                            return plain_http_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "retained challenge outcome failed integrity verification",
                            )
                        }
                    }
                }
                Ok(Some(_)) | Ok(None) | Err(_) => {
                    return plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "retained challenge outcome is unavailable",
                    )
                }
            },
            None => None,
        };
        Json(FindingChallengeStatusResponse {
            schema: FINDING_CHALLENGE_STATUS_SCHEMA.to_owned(),
            challenge_id: record.challenge_id,
            finding_id: record.finding_id,
            listing_id: record.listing_id,
            challenge_envelope_sha256: record.challenge_envelope_sha256,
            authorization_branch: challenge_authorization_name(record.authorization_branch)
                .to_owned(),
            evidence_class: challenge_evidence_name(record.evidence_class).to_owned(),
            state: challenge_state_name(record.state).to_owned(),
            retry_count: record.retry_count,
            retry_deadline: record.retry_deadline,
            outcome_envelope_sha256: record.outcome_envelope_sha256,
            outcome,
            submitted_at: record.submitted_at,
            updated_at: record.updated_at,
        })
        .into_response()
    })
    .await;
    match response {
        Ok(response) => response,
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding challenge status worker failed",
        ),
    }
}

fn checked_outcome_json(outcome: &FindingChallengeOutcomeRecord) -> Result<serde_json::Value, ()> {
    let raw = std::str::from_utf8(&outcome.outcome_envelope_json).map_err(|_| ())?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| ())?;
    if canonical != outcome.outcome_envelope_json
        || chio_core::sha256_hex(&outcome.outcome_envelope_json) != outcome.outcome_envelope_sha256
    {
        return Err(());
    }
    serde_json::from_slice(&outcome.outcome_envelope_json).map_err(|_| ())
}

const fn challenge_authorization_name(branch: FindingChallengeAuthorizationBranch) -> &'static str {
    match branch {
        FindingChallengeAuthorizationBranch::BuyerSubmission => "buyer_submission",
        FindingChallengeAuthorizationBranch::VenueAudit => "venue_audit",
    }
}

const fn challenge_evidence_name(class: FindingChallengeEvidenceClass) -> &'static str {
    match class {
        FindingChallengeEvidenceClass::DigestMismatch => "digest_mismatch",
        FindingChallengeEvidenceClass::EvidenceInvalid => "evidence_invalid",
        FindingChallengeEvidenceClass::ReplayContradiction => "replay_contradiction",
    }
}

const fn challenge_state_name(state: FindingChallengeState) -> &'static str {
    match state {
        FindingChallengeState::Submitted => "submitted",
        FindingChallengeState::Evaluating => "evaluating",
        FindingChallengeState::Rejected => "rejected",
        FindingChallengeState::IndeterminateRetryable => "indeterminate_retryable",
        FindingChallengeState::IndeterminateClosed => "indeterminate_closed",
        FindingChallengeState::Upheld => "upheld",
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn collect_challenge_body(
    body: Body,
    permit: tokio::sync::OwnedSemaphorePermit,
    deadline: Duration,
) -> Result<(Bytes, tokio::sync::OwnedSemaphorePermit), Response> {
    match tokio::time::timeout(
        deadline,
        axum::body::to_bytes(body, FINDING_CHALLENGE_SUBMIT_MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok((bytes, permit)),
        Ok(Err(_)) => Err(plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "finding challenge exceeds the body bound",
        )),
        Err(_) => Err(plain_http_error(
            StatusCode::REQUEST_TIMEOUT,
            "finding challenge body read timed out",
        )),
    }
}

fn try_acquire_challenge_lane(
    lane: &Arc<tokio::sync::Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    lane.clone().try_acquire_owned()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn coordinator_unavailable(error: &ChallengeCoordinatorError) -> bool {
    matches!(
        error,
        ChallengeCoordinatorError::Configuration(_)
            | ChallengeCoordinatorError::AuthorityPinMismatch(_)
            | ChallengeCoordinatorError::AuthorityLifecycle { .. }
            | ChallengeCoordinatorError::FeeRail(_)
            | ChallengeCoordinatorError::DisputeBondRail(_)
            | ChallengeCoordinatorError::FilingResolver(_)
            | ChallengeCoordinatorError::ChallengeStore(_)
            | ChallengeCoordinatorError::PurchaseStore(_)
            | ChallengeCoordinatorError::ChallengeEnvelope(_)
            | ChallengeCoordinatorError::Signing
            | ChallengeCoordinatorError::Canonical
    )
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_authorization_name, challenge_evidence_name, challenge_state_name,
        checked_outcome_json, collect_challenge_body, coordinator_unavailable, is_lower_hex_64,
        try_acquire_challenge_lane,
    };
    use crate::trust_control::finding_challenge_coordinator::ChallengeCoordinatorError;
    use axum::body::{Body, Bytes};
    use axum::http::StatusCode;
    use chio_store_sqlite::{
        FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass,
        FindingChallengeOutcomeRecord, FindingChallengeState,
    };
    use futures_util::stream;
    use std::time::Duration;

    #[test]
    fn dispute_bond_rail_failures_are_retryable_service_outages() {
        assert!(coordinator_unavailable(
            &ChallengeCoordinatorError::DisputeBondRail("rail unavailable".to_owned())
        ));
        assert!(!coordinator_unavailable(
            &ChallengeCoordinatorError::DisputeBondWindow
        ));
        assert!(coordinator_unavailable(
            &ChallengeCoordinatorError::FilingResolver("store unavailable".to_owned())
        ));
    }

    #[test]
    fn challenge_submission_lane_is_non_queued() {
        let lane = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = try_acquire_challenge_lane(&lane)
            .unwrap_or_else(|error| panic!("first challenge permit: {error}"));
        assert!(try_acquire_challenge_lane(&lane).is_err());
        drop(permit);
        assert!(try_acquire_challenge_lane(&lane).is_ok());
    }

    #[test]
    fn challenge_status_projection_has_closed_vocabulary() {
        assert_eq!(
            challenge_authorization_name(FindingChallengeAuthorizationBranch::BuyerSubmission),
            "buyer_submission"
        );
        assert_eq!(
            challenge_evidence_name(FindingChallengeEvidenceClass::ReplayContradiction),
            "replay_contradiction"
        );
        assert_eq!(
            challenge_state_name(FindingChallengeState::IndeterminateRetryable),
            "indeterminate_retryable"
        );
        assert!(is_lower_hex_64(&"a".repeat(64)));
        assert!(!is_lower_hex_64(&"A".repeat(64)));
    }

    #[test]
    fn challenge_status_rechecks_retained_outcome_bytes() {
        let raw = br#"{"body":{"challenge_id":"challenge-1"},"schema":"outcome"}"#.to_vec();
        let digest = chio_core::sha256_hex(&raw);
        let valid = FindingChallengeOutcomeRecord {
            challenge_id: "challenge-1".to_owned(),
            outcome_envelope_sha256: digest,
            outcome_envelope_json: raw.clone(),
            recorded_at: 1,
        };
        assert!(checked_outcome_json(&valid).is_ok());

        let tampered = FindingChallengeOutcomeRecord {
            outcome_envelope_json: br#"{"schema":"outcome"}"#.to_vec(),
            ..valid
        };
        assert!(checked_outcome_json(&tampered).is_err());
    }

    #[tokio::test]
    async fn challenge_body_deadline_releases_the_submission_lane() {
        let lane = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = try_acquire_challenge_lane(&lane)
            .unwrap_or_else(|error| panic!("challenge permit: {error}"));
        let body = Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        assert!(try_acquire_challenge_lane(&lane).is_err());
        let response = match collect_challenge_body(body, permit, Duration::from_millis(10)).await {
            Ok(_) => panic!("stalled challenge body unexpectedly completed"),
            Err(response) => response,
        };
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(try_acquire_challenge_lane(&lane).is_ok());
    }
}
