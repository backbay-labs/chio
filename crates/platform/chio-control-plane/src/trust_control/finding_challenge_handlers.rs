//! Authenticated HTTP ingress for durable cognition-market challenge filings.
//!
//! The request body is the registered signed challenge envelope itself. The
//! handler preserves those exact canonical bytes, resolves the exact immutable
//! Finding bytes from the venue store, and passes both views to an explicitly
//! configured submission executor. Deployments that do not configure that
//! executor fail closed before any filing side effect.

use chio_finding::{verify_signed_challenge, Finding, SignedFindingChallenge};
use chio_store_sqlite::{FindingChallengeAuthorizationBranch, FindingChallengeWriteOutcome};

use super::finding_challenge_coordinator::{
    ChallengeCoordinatorError, ChallengeSubmissionOutcome, FindingChallengeCoordinator,
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
        Ok(Self {
            joint_authority_store,
            market_config,
            executor: coordinator,
        })
    }

    #[must_use]
    pub const fn market_config(&self) -> &FindingMarketConfig {
        &self.market_config
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Arc<SqliteAuthorityStore>,
        Arc<dyn FindingChallengeSubmissionExecutor>,
    ) {
        (self.joint_authority_store, self.executor)
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
}

/// POST /v1/findings/{finding_id}/challenges (service authenticated).
pub(crate) async fn handle_submit_finding_challenge(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    headers: HeaderMap,
    raw_challenge_envelope: String,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
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

    let (_, request) = match strict_artifact_ingress::<FindingChallengeSubmissionRequest>(
        &raw_challenge_envelope,
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
        &raw_challenge_envelope,
        &raw_finding,
        unix_timestamp_now(),
    ) {
        Ok(outcome) => Json(FindingChallengeSubmissionResponse::from(outcome)).into_response(),
        Err(error) if coordinator_unavailable(&error) => {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    }
}

fn coordinator_unavailable(error: &ChallengeCoordinatorError) -> bool {
    matches!(
        error,
        ChallengeCoordinatorError::Configuration(_)
            | ChallengeCoordinatorError::AuthorityPinMismatch(_)
            | ChallengeCoordinatorError::AuthorityLifecycle { .. }
            | ChallengeCoordinatorError::FeeRail(_)
            | ChallengeCoordinatorError::ChallengeStore(_)
            | ChallengeCoordinatorError::PurchaseStore(_)
            | ChallengeCoordinatorError::ChallengeEnvelope(_)
            | ChallengeCoordinatorError::Signing
            | ChallengeCoordinatorError::Canonical
    )
}
