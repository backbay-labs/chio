//! Scoped seller ingress for the single-operator verified-fix workflow.
//!
//! A seller submits ordinary repository coordinates and test commands. The
//! deployment-owned executor performs privileged package authoring and
//! admission without disclosing operator keys or the global service token.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::{plain_http_error, TrustServiceState};

pub const FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA: &str = "chio.finding.verified-fix-submission.v1";
pub const FINDING_VOLUNTARY_RETRACTION_REQUEST_SCHEMA: &str =
    "chio.finding.voluntary-retraction-request.v1";
const VERIFIED_FIX_SUBMISSION_ID_DOMAIN: &[u8] = b"chio.finding.verified-fix-submission-id.v1\0";
// Validated text rejects control characters, so quote and backslash escaping
// can at most double its bytes. This cap covers that complete worst case plus
// the fixed JSON field, schema, request-id, and integer overhead.
pub(crate) const FINDING_VERIFIED_FIX_SUBMISSION_MAX_BODY_BYTES: usize = 256 * 1024;
const VOLUNTARY_RETRACTION_REQUEST_ID_DOMAIN: &[u8] =
    b"chio.finding.voluntary-retraction-request-id.v1\0";
const MAX_REPOSITORY_BYTES: usize = 4096;
const MAX_REVISION_BYTES: usize = 256;
const MAX_TOPIC_BYTES: usize = 512;
const MAX_TEST_BYTES: usize = 4096;
const MAX_TESTS: usize = 16;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingVerifiedFixSubmissionRequest {
    pub schema: String,
    pub request_id: String,
    pub repository: String,
    pub base_revision: String,
    pub candidate_revision: String,
    pub tests: Vec<String>,
    pub topic: String,
    pub price_units: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingVerifiedFixSubmissionIdentity<'a> {
    schema: &'static str,
    repository: &'a str,
    base_revision: &'a str,
    candidate_revision: &'a str,
    tests: &'a [String],
    topic: &'a str,
    price_units: u64,
}

impl FindingVerifiedFixSubmissionRequest {
    pub fn new(
        repository: String,
        base_revision: String,
        candidate_revision: String,
        tests: Vec<String>,
        topic: String,
        price_units: u64,
    ) -> Result<Self, String> {
        let request_id = derive_verified_fix_submission_id(
            &repository,
            &base_revision,
            &candidate_revision,
            &tests,
            &topic,
            price_units,
        )?;
        let request = Self {
            schema: FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA.to_owned(),
            request_id,
            repository,
            base_revision,
            candidate_revision,
            tests,
            topic,
            price_units,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA {
            return Err("unsupported verified-fix submission schema".to_owned());
        }
        require_text(&self.repository, MAX_REPOSITORY_BYTES, "repository")?;
        require_text(&self.base_revision, MAX_REVISION_BYTES, "base_revision")?;
        require_text(
            &self.candidate_revision,
            MAX_REVISION_BYTES,
            "candidate_revision",
        )?;
        require_text(&self.topic, MAX_TOPIC_BYTES, "topic")?;
        if self.base_revision == self.candidate_revision {
            return Err("base and candidate revisions must differ".to_owned());
        }
        if self.tests.is_empty() || self.tests.len() > MAX_TESTS {
            return Err("verified-fix submission requires between 1 and 16 tests".to_owned());
        }
        for test in &self.tests {
            require_text(test, MAX_TEST_BYTES, "test")?;
        }
        if self.price_units == 0 || self.price_units > I_JSON_MAX_SAFE_INTEGER {
            return Err("price_units must be a nonzero I-JSON safe integer".to_owned());
        }
        let expected = derive_verified_fix_submission_id(
            &self.repository,
            &self.base_revision,
            &self.candidate_revision,
            &self.tests,
            &self.topic,
            self.price_units,
        )?;
        if self.request_id != expected {
            return Err("request_id does not bind the verified-fix inputs".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingVerifiedFixSubmissionResponse {
    pub schema: String,
    pub request_id: String,
    pub seller_principal: String,
    pub finding_id: String,
    pub proof_bundle: String,
    pub activation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingVoluntaryRetractionRequest {
    pub schema: String,
    pub request_id: String,
    pub finding_id: String,
}

impl FindingVoluntaryRetractionRequest {
    pub fn new(finding_id: String) -> Result<Self, String> {
        require_digest(&finding_id, "finding_id")?;
        let request_id = derive_voluntary_retraction_request_id(&finding_id);
        Ok(Self {
            schema: FINDING_VOLUNTARY_RETRACTION_REQUEST_SCHEMA.to_owned(),
            request_id,
            finding_id,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_VOLUNTARY_RETRACTION_REQUEST_SCHEMA {
            return Err("unsupported voluntary retraction request schema".to_owned());
        }
        require_digest(&self.finding_id, "finding_id")?;
        if self.request_id != derive_voluntary_retraction_request_id(&self.finding_id) {
            return Err("request_id does not bind the retracted Finding".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingVoluntaryRetractionResponse {
    pub schema: String,
    pub request_id: String,
    pub finding_id: String,
    pub intent_id: String,
    pub proof_sha256: String,
    pub map_epoch: u64,
    pub status: String,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum FindingSellerSubmissionError {
    #[error("seller authentication failed")]
    Authentication,
    #[error("verified-fix submission is invalid: {0}")]
    Invalid(String),
    #[error("verified-fix submission conflicts with durable state")]
    Conflict,
    #[error("verified-fix submission is still pending: {0}")]
    Pending(String),
    #[error("verified-fix submission failed: {0}")]
    Internal(String),
}

pub trait FindingSellerSubmissionExecutor: Send + Sync {
    fn submit(
        &self,
        bearer_token: &str,
        request: &FindingVerifiedFixSubmissionRequest,
    ) -> Result<FindingVerifiedFixSubmissionResponse, FindingSellerSubmissionError>;

    fn retract(
        &self,
        bearer_token: &str,
        request: &FindingVoluntaryRetractionRequest,
    ) -> Result<FindingVoluntaryRetractionResponse, FindingSellerSubmissionError>;
}

#[must_use]
pub fn derive_voluntary_retraction_request_id(finding_id: &str) -> String {
    let mut preimage =
        Vec::with_capacity(VOLUNTARY_RETRACTION_REQUEST_ID_DOMAIN.len() + finding_id.len());
    preimage.extend_from_slice(VOLUNTARY_RETRACTION_REQUEST_ID_DOMAIN);
    preimage.extend_from_slice(finding_id.as_bytes());
    chio_core::sha256_hex(&preimage)
}

pub type SharedFindingSellerSubmissionExecutor = Arc<dyn FindingSellerSubmissionExecutor>;

pub fn derive_verified_fix_submission_id(
    repository: &str,
    base_revision: &str,
    candidate_revision: &str,
    tests: &[String],
    topic: &str,
    price_units: u64,
) -> Result<String, String> {
    let identity = FindingVerifiedFixSubmissionIdentity {
        schema: FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA,
        repository,
        base_revision,
        candidate_revision,
        tests,
        topic,
        price_units,
    };
    let canonical = chio_core::canonical_json_bytes(&identity)
        .map_err(|_| "verified-fix submission identity cannot be canonicalized".to_owned())?;
    let mut preimage =
        Vec::with_capacity(VERIFIED_FIX_SUBMISSION_ID_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(VERIFIED_FIX_SUBMISSION_ID_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(chio_core::sha256_hex(&preimage))
}

pub(crate) async fn handle_submit_verified_fix(
    State(state): State<TrustServiceState>,
    request: Request,
) -> Response {
    let Some(executor) = state.finding_seller_submission_executor.clone() else {
        return seller_error(
            StatusCode::CONFLICT,
            "verified-fix seller submission is not configured",
        );
    };
    let bearer = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let Some(bearer) = bearer else {
        return seller_authentication_failed();
    };
    let raw = match axum::body::to_bytes(
        request.into_body(),
        FINDING_VERIFIED_FIX_SUBMISSION_MAX_BODY_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return seller_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "verified-fix submission exceeds the body bound",
            )
        }
    };
    let submission = match parse_submission(&raw) {
        Ok(submission) => submission,
        Err(error) => return seller_error(StatusCode::BAD_REQUEST, &error),
    };
    let outcome = tokio::task::spawn_blocking(move || executor.submit(&bearer, &submission)).await;
    match outcome {
        Ok(Ok(response)) => match chio_core::canonical_json_bytes(&response) {
            Ok(bytes) => (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response(),
            Err(_) => seller_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "verified-fix response cannot be canonicalized",
            ),
        },
        Ok(Err(FindingSellerSubmissionError::Authentication)) => seller_authentication_failed(),
        Ok(Err(FindingSellerSubmissionError::Invalid(message))) => {
            seller_error(StatusCode::BAD_REQUEST, &message)
        }
        Ok(Err(FindingSellerSubmissionError::Conflict)) => seller_error(
            StatusCode::CONFLICT,
            "verified-fix submission conflicts with durable state",
        ),
        Ok(Err(FindingSellerSubmissionError::Pending(message))) => {
            seller_error(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        Ok(Err(FindingSellerSubmissionError::Internal(message))) => {
            seller_error(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
        Err(_) => seller_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "verified-fix submission worker failed",
        ),
    }
}

pub(crate) async fn handle_submit_voluntary_retraction(
    State(state): State<TrustServiceState>,
    request: Request,
) -> Response {
    let Some(executor) = state.finding_seller_submission_executor.clone() else {
        return seller_error(
            StatusCode::CONFLICT,
            "voluntary retraction is not configured",
        );
    };
    let bearer = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let Some(bearer) = bearer else {
        return seller_authentication_failed();
    };
    let raw = match axum::body::to_bytes(request.into_body(), 4096).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return seller_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "retraction request is too large",
            )
        }
    };
    let request: FindingVoluntaryRetractionRequest = match parse_canonical_request(&raw) {
        Ok(request) => request,
        Err(error) => return seller_error(StatusCode::BAD_REQUEST, &error),
    };
    if let Err(error) = request.validate() {
        return seller_error(StatusCode::BAD_REQUEST, &error);
    }
    let outcome = tokio::task::spawn_blocking(move || executor.retract(&bearer, &request)).await;
    match outcome {
        Ok(Ok(response)) => match chio_core::canonical_json_bytes(&response) {
            Ok(bytes) => (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response(),
            Err(_) => seller_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "retraction response cannot be canonicalized",
            ),
        },
        Ok(Err(FindingSellerSubmissionError::Authentication)) => seller_authentication_failed(),
        Ok(Err(FindingSellerSubmissionError::Invalid(message))) => {
            seller_error(StatusCode::BAD_REQUEST, &message)
        }
        Ok(Err(FindingSellerSubmissionError::Conflict)) => seller_error(
            StatusCode::CONFLICT,
            "retraction conflicts with durable state",
        ),
        Ok(Err(FindingSellerSubmissionError::Pending(message))) => {
            seller_error(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        Ok(Err(FindingSellerSubmissionError::Internal(message))) => {
            seller_error(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
        Err(_) => seller_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retraction worker failed",
        ),
    }
}

fn parse_submission(raw: &[u8]) -> Result<FindingVerifiedFixSubmissionRequest, String> {
    let text =
        std::str::from_utf8(raw).map_err(|_| "verified-fix submission is not UTF-8".to_owned())?;
    let strict = chio_core::canonical::canonical_json_bytes_from_str(text)
        .map_err(|_| "verified-fix submission is not strict canonical JSON".to_owned())?;
    if strict != raw {
        return Err("verified-fix submission is not strict canonical JSON".to_owned());
    }
    let request: FindingVerifiedFixSubmissionRequest = serde_json::from_slice(raw)
        .map_err(|_| "verified-fix submission has an unsupported shape".to_owned())?;
    let typed = chio_core::canonical_json_bytes(&request)
        .map_err(|_| "verified-fix submission cannot be canonicalized".to_owned())?;
    if typed != strict {
        return Err("verified-fix submission typed bytes are unstable".to_owned());
    }
    request.validate()?;
    Ok(request)
}

fn parse_canonical_request<T>(raw: &[u8]) -> Result<T, String>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let text = std::str::from_utf8(raw).map_err(|_| "request is not UTF-8".to_owned())?;
    let strict = chio_core::canonical::canonical_json_bytes_from_str(text)
        .map_err(|_| "request is not strict canonical JSON".to_owned())?;
    if strict != raw {
        return Err("request is not strict canonical JSON".to_owned());
    }
    let request: T =
        serde_json::from_slice(raw).map_err(|_| "request has an unsupported shape".to_owned())?;
    if chio_core::canonical_json_bytes(&request)
        .map_err(|_| "request cannot be canonicalized".to_owned())?
        != strict
    {
        return Err("request typed bytes are unstable".to_owned());
    }
    Ok(request)
}

fn require_text(value: &str, maximum: usize, field: &str) -> Result<(), String> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is empty, padded, or oversized"));
    }
    Ok(())
}

fn require_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be canonical lowercase 64-hex"));
    }
    Ok(())
}

fn seller_authentication_failed() -> Response {
    plain_http_error(StatusCode::UNAUTHORIZED, "seller authentication failed")
}

fn seller_error(status: StatusCode, message: &str) -> Response {
    plain_http_error(status, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_identity_binds_every_input() {
        let request = FindingVerifiedFixSubmissionRequest::new(
            "/srv/repository".to_owned(),
            "base".to_owned(),
            "candidate".to_owned(),
            vec!["./check.sh".to_owned()],
            "rust/fix".to_owned(),
            300,
        )
        .unwrap_or_else(|error| panic!("valid request: {error}"));
        assert!(request.validate().is_ok());
        let mut altered = request.clone();
        altered.price_units = 301;
        assert!(altered.validate().is_err());
        assert!(FindingVerifiedFixSubmissionRequest::new(
            "/srv/repository".to_owned(),
            "base".to_owned(),
            "candidate".to_owned(),
            vec!["printf '\u{0001}'".to_owned()],
            "rust/fix".to_owned(),
            300,
        )
        .is_err());
        assert!(FindingVerifiedFixSubmissionRequest::new(
            "/srv/repository".to_owned(),
            "base".to_owned(),
            "candidate".to_owned(),
            vec!["./check.sh".to_owned()],
            "rust/fix".to_owned(),
            I_JSON_MAX_SAFE_INTEGER + 1,
        )
        .is_err());
    }

    #[test]
    fn every_maximum_valid_submission_fits_the_transport_bound() {
        let repeated = |character: char, length: usize| {
            std::iter::repeat_n(character, length).collect::<String>()
        };
        let request = FindingVerifiedFixSubmissionRequest::new(
            repeated('\\', MAX_REPOSITORY_BYTES),
            repeated('\\', MAX_REVISION_BYTES),
            repeated('"', MAX_REVISION_BYTES),
            (0..MAX_TESTS)
                .map(|_| repeated('\\', MAX_TEST_BYTES))
                .collect(),
            repeated('"', MAX_TOPIC_BYTES),
            I_JSON_MAX_SAFE_INTEGER,
        )
        .unwrap_or_else(|error| panic!("maximum valid request: {error}"));
        let bytes = chio_core::canonical_json_bytes(&request)
            .unwrap_or_else(|error| panic!("canonical maximum request: {error}"));
        assert!(bytes.len() <= FINDING_VERIFIED_FIX_SUBMISSION_MAX_BODY_BYTES);
        parse_submission(&bytes)
            .unwrap_or_else(|error| panic!("maximum valid request must parse: {error}"));
    }
}
