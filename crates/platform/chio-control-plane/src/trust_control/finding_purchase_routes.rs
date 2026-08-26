//! Public HTTP boundary for a complete cognition-market purchase.
//!
//! The route deliberately accepts only buyer policy inputs. Signed asks,
//! admissions, reservation receipts, reveal carriers, and seller payloads stay
//! behind [`FindingPurchaseExecutor`], which is the deployment-owned adapter
//! boundary. A production adapter is expected to drive the existing
//! `FindingPurchaseCoordinator`, durable purchase store, and purchase-aware
//! kernel. This module does not duplicate their state machine.
//!
//! The default trust-control service does not install an executor. An operator
//! must inject one explicitly with
//! [`super::serve_with_finding_purchase_executor`], together with the rail and
//! authority-status resolver that keep its market views and mutations live.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Request, State};
use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE},
    HeaderValue, StatusCode,
};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_finding::{
    verify_signed_admission, verify_signed_failed_delivery, verify_signed_purchase_record, Finding,
    FindingHoldReleaseTerminal, SignedFindingAdmission, SignedFindingFailedDelivery,
    SignedFindingPurchaseRecord,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use chio_store_sqlite::{
    FindingPublicPurchaseRequestBinding, FindingPublicPurchaseTerminal,
    FindingPublicPurchaseTerminalKind, SqliteFindingPurchaseStore,
};
use serde::{Deserialize, Serialize};

use super::report_validation::validate_service_auth;
use super::{plain_http_error, TrustServiceState};

#[path = "finding_purchase_routes/bounded_serving.rs"]
mod bounded_serving;

/// Stable request schema for the public purchase surface.
pub const FINDING_PURCHASE_REQUEST_SCHEMA: &str = "chio.finding.purchase-request.v1";
/// Stable terminal response schema for the public purchase surface.
pub const FINDING_PURCHASE_RESULT_SCHEMA: &str = "chio.finding.purchase-result.v1";
/// Stable structured error schema for the public purchase surface.
pub const FINDING_PURCHASE_ERROR_SCHEMA: &str = "chio.finding.purchase-error.v1";

/// Maximum canonical request size accepted at the public route.
pub const FINDING_PURCHASE_MAX_BODY_BYTES: usize = 16 * 1024;
/// Maximum decoded purchased payload returned through this route. This is
/// intentionally no smaller than the kernel's pre-settlement raw-outcome
/// ceiling. Any output large enough to violate this route bound is therefore
/// denied by the kernel before capture, so a captured terminal remains
/// returnable on its first response and every idempotent replay.
pub const FINDING_PURCHASE_MAX_OUTPUT_BYTES: usize =
    chio_kernel::tool_outcome::MAX_RAW_INVOCATION_OUTCOME_BYTES;
/// Maximum canonical terminal response size, including base64 expansion and
/// signed settlement evidence.
pub const FINDING_PURCHASE_MAX_RESULT_BYTES: usize =
    FINDING_PURCHASE_MAX_OUTPUT_BYTES.div_ceil(3) * 4 + 2 * 1024 * 1024;
pub const FINDING_PROOF_BUNDLE_MAX_BYTES: usize = 24 * 1024 * 1024;
/// Maximum caller-selected delivery window.
pub const FINDING_PURCHASE_MAX_DEADLINE_SECS: u64 = 7 * 24 * 60 * 60;

const PURCHASE_REQUEST_ID_DOMAIN: &[u8] = b"chio.finding.public-purchase-request.v1\0";
const MAX_PAYER_BYTES: usize = 512;
const MAX_MEDIA_TYPE_BYTES: usize = 255;

/// Buyer policy inputs for one end-to-end purchase.
///
/// `request_id` is derived from every other member. Identical requests replay
/// under one stable identity, while changing any price, payer, or deadline
/// input produces a different identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingPurchaseRequest {
    pub schema: String,
    pub request_id: String,
    pub finding_id: String,
    pub max_price: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingPurchaseRequestIdInput<'a> {
    schema: &'static str,
    finding_id: &'a str,
    max_price: &'a MonetaryAmount,
    payer: Option<&'a str>,
    deadline_secs: Option<u64>,
}

impl FindingPurchaseRequest {
    /// Construct and validate a request, deriving its stable idempotency key.
    pub fn new(
        finding_id: String,
        max_price_units: u64,
        currency: String,
        payer: Option<String>,
        deadline_secs: Option<u64>,
    ) -> Result<Self, String> {
        let max_price = MonetaryAmount {
            units: max_price_units,
            currency,
        };
        let request_id = derive_finding_purchase_request_id(
            &finding_id,
            &max_price,
            payer.as_deref(),
            deadline_secs,
        )?;
        let request = Self {
            schema: FINDING_PURCHASE_REQUEST_SCHEMA.to_owned(),
            request_id,
            finding_id,
            max_price,
            payer,
            deadline_secs,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate the closed request shape and its derived identity.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_PURCHASE_REQUEST_SCHEMA {
            return Err("unsupported purchase request schema".to_owned());
        }
        require_hex64(&self.finding_id, "finding_id")?;
        if self.max_price.units == 0 {
            return Err("max_price.units must be nonzero".to_owned());
        }
        require_currency(&self.max_price.currency)?;
        if let Some(payer) = self.payer.as_deref() {
            require_bounded_text(payer, MAX_PAYER_BYTES, "payer")?;
        }
        if let Some(deadline_secs) = self.deadline_secs {
            if deadline_secs == 0 || deadline_secs > FINDING_PURCHASE_MAX_DEADLINE_SECS {
                return Err("deadline_secs is outside the supported range".to_owned());
            }
        }
        let expected = derive_finding_purchase_request_id(
            &self.finding_id,
            &self.max_price,
            self.payer.as_deref(),
            self.deadline_secs,
        )?;
        if self.request_id != expected {
            return Err("request_id does not bind the purchase inputs".to_owned());
        }
        Ok(())
    }
}

/// Derive the request identity committed by the public purchase route.
pub fn derive_finding_purchase_request_id(
    finding_id: &str,
    max_price: &MonetaryAmount,
    payer: Option<&str>,
    deadline_secs: Option<u64>,
) -> Result<String, String> {
    let input = FindingPurchaseRequestIdInput {
        schema: FINDING_PURCHASE_REQUEST_SCHEMA,
        finding_id,
        max_price,
        payer,
        deadline_secs,
    };
    let canonical = chio_core::canonical_json_bytes(&input)
        .map_err(|_| "purchase request identity canonicalization failed".to_owned())?;
    let mut preimage = Vec::with_capacity(PURCHASE_REQUEST_ID_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(PURCHASE_REQUEST_ID_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

/// Closed financial terminal exposed by the public route.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingPurchaseSettlementTerminal {
    Captured,
    Released,
}

/// Closed kernel verdict exposed by the public route.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingPurchaseVerdict {
    Allow,
    Deny,
}

/// Revealed payload. It exists only on a captured Allow terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingPurchasedOutput {
    pub media_type: String,
    pub payload_b64: String,
}

/// Complete terminal returned by a configured purchase executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingPurchaseResult {
    pub schema: String,
    pub request_id: String,
    pub finding_id: String,
    /// Deployment-resolved payer principal.
    pub payer: String,
    /// Exact public key bound by the coordinator reservation.
    pub payer_key: PublicKey,
    pub reservation_id: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    pub verdict: FindingPurchaseVerdict,
    pub settlement: FindingPurchaseSettlementTerminal,
    pub accepted_price: MonetaryAmount,
    pub realized_spend: MonetaryAmount,
    pub delivery_receipt: ChioReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_record: Option<SignedFindingPurchaseRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_delivery: Option<SignedFindingFailedDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<FindingPurchasedOutput>,
}

impl FindingPurchaseResult {
    fn validate_payer_binding(payer: &str, payer_key: &PublicKey) -> Result<(), String> {
        if payer != payer_key.to_hex() {
            return Err("purchase payer does not bind its signed payer key".to_owned());
        }
        Ok(())
    }

    /// Validate the response shape and all caller-visible conservation rules.
    /// This verifies embedded signatures, but only the route's stronger
    /// `validate_authorized` check pins the purchase authorities.
    pub fn validate_shape(&self, request: &FindingPurchaseRequest) -> Result<(), String> {
        if self.schema != FINDING_PURCHASE_RESULT_SCHEMA {
            return Err("unsupported purchase result schema".to_owned());
        }
        if self.request_id != request.request_id || self.finding_id != request.finding_id {
            return Err("purchase result does not bind the request".to_owned());
        }
        require_bounded_text(&self.payer, MAX_PAYER_BYTES, "payer")?;
        Self::validate_payer_binding(&self.payer, &self.payer_key)?;
        if request
            .payer
            .as_deref()
            .is_some_and(|requested| requested != self.payer)
        {
            return Err("purchase result changed the requested payer".to_owned());
        }
        require_hex64(&self.reservation_id, "reservation_id")?;
        require_hex64(&self.purchase_intent_id, "purchase_intent_id")?;
        require_hex64(
            &self.authoritative_payment_operation_id,
            "authoritative_payment_operation_id",
        )?;
        if self.purchase_intent_id != derive_purchase_intent_id(&self.reservation_id)
            || self.authoritative_payment_operation_id
                != derive_payment_operation_id(&self.reservation_id)
        {
            return Err("purchase result ids do not derive from the reservation".to_owned());
        }
        require_currency(&self.accepted_price.currency)?;
        require_currency(&self.realized_spend.currency)?;
        if self.accepted_price.units == 0
            || self.accepted_price.currency != request.max_price.currency
            || self.accepted_price.units > request.max_price.units
            || self.realized_spend.currency != self.accepted_price.currency
            || self.realized_spend.units > self.accepted_price.units
        {
            return Err("purchase result violates the price ceiling".to_owned());
        }
        if !matches!(self.delivery_receipt.verify_signature(), Ok(true))
            || !matches!(self.delivery_receipt.action.verify_hash(), Ok(true))
        {
            return Err("delivery receipt signature or action hash is invalid".to_owned());
        }
        let Some(parameters) = self.delivery_receipt.action.parameters.as_object() else {
            return Err("delivery receipt action parameters are not an object".to_owned());
        };
        if parameters.len() != 1
            || parameters
                .get("finding_id")
                .and_then(serde_json::Value::as_str)
                != Some(self.finding_id.as_str())
        {
            return Err("delivery receipt action does not bind the finding".to_owned());
        }

        match (self.verdict, self.settlement) {
            (FindingPurchaseVerdict::Allow, FindingPurchaseSettlementTerminal::Captured) => {
                if !matches!(self.delivery_receipt.decision, Some(Decision::Allow))
                    || self.realized_spend.units == 0
                    || self.output.is_none()
                    || self.purchase_record.is_none()
                    || self.failed_delivery.is_some()
                {
                    return Err("captured purchase is not a complete Allow terminal".to_owned());
                }
            }
            (FindingPurchaseVerdict::Deny, FindingPurchaseSettlementTerminal::Released) => {
                if !matches!(self.delivery_receipt.decision, Some(Decision::Deny { .. }))
                    || self.realized_spend.units != 0
                    || self.output.is_some()
                    || self.purchase_record.is_some()
                    || self.failed_delivery.is_none()
                {
                    return Err("released purchase is not a complete Deny terminal".to_owned());
                }
            }
            _ => return Err("purchase result is not a forced financial terminal".to_owned()),
        }

        if let Some(record) = self.purchase_record.as_ref() {
            if record.body.validate().is_err() || !matches!(record.verify_signature(), Ok(true)) {
                return Err("purchase record body or embedded signature is invalid".to_owned());
            }
        }
        if let Some(failed) = self.failed_delivery.as_ref() {
            if failed.body.validate().is_err() || !matches!(failed.verify_signature(), Ok(true)) {
                return Err("failed-delivery body or embedded signature is invalid".to_owned());
            }
        }

        if let Some(output) = self.output.as_ref() {
            require_bounded_text(&output.media_type, MAX_MEDIA_TYPE_BYTES, "media_type")?;
            let encoded_bound = FINDING_PURCHASE_MAX_OUTPUT_BYTES
                .saturating_mul(4)
                .saturating_div(3)
                .saturating_add(4);
            if output.payload_b64.len() > encoded_bound {
                return Err("purchased payload exceeds the output bound".to_owned());
            }
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&output.payload_b64)
                .map_err(|_| "purchased payload is not canonical base64".to_owned())?;
            if payload.len() > FINDING_PURCHASE_MAX_OUTPUT_BYTES
                || base64::engine::general_purpose::STANDARD.encode(&payload) != output.payload_b64
            {
                return Err(
                    "purchased payload exceeds its bound or is not canonical base64".to_owned(),
                );
            }
        }
        Ok(())
    }

    /// Verify the complete terminal against its exact public request and the
    /// retained Finding/admission trust boundary.
    pub fn validate_authorized(
        &self,
        request: &FindingPurchaseRequest,
        finding: &Finding,
        admission: &SignedFindingAdmission,
    ) -> Result<(), String> {
        self.validate_shape(request)?;
        if finding.finding_id != self.finding_id || admission.body.finding_id != self.finding_id {
            return Err("purchase result names a different finding artifact".to_owned());
        }
        match self.verdict {
            FindingPurchaseVerdict::Allow => {
                let output = self
                    .output
                    .as_ref()
                    .ok_or_else(|| "captured purchase omitted its output".to_owned())?;
                if output.media_type != finding.payload_media_type {
                    return Err("purchased output media type does not match the finding".to_owned());
                }
                let payload = base64::engine::general_purpose::STANDARD
                    .decode(&output.payload_b64)
                    .map_err(|_| "purchased output is not canonical base64".to_owned())?;
                let digest = chio_finding::finding_payload_sha256(&output.media_type, &payload)
                    .map_err(|_| "purchased output canonicalization failed".to_owned())?;
                if digest != finding.payload_sha256
                    || self.delivery_receipt.content_hash != finding.payload_sha256
                {
                    return Err("purchased output does not match the finding commitment".to_owned());
                }
                let record = self
                    .purchase_record
                    .as_ref()
                    .ok_or_else(|| "captured purchase omitted its purchase record".to_owned())?;
                if record.body.venue_admission_envelope_sha256
                    != chio_core::canonical_json_bytes(admission)
                        .map(|bytes| sha256_hex(&bytes))
                        .map_err(|_| "retained admission canonicalization failed".to_owned())?
                    || record.body.recorded_at < admission.body.purchase_authority.valid_from
                    || record.body.recorded_at >= admission.body.purchase_authority.valid_until
                {
                    return Err(
                        "purchase record is outside its retained admission policy".to_owned()
                    );
                }
                verify_signed_purchase_record(record, &admission.body.purchase_authority.key)
                    .map_err(|_| "purchase record authority verification failed".to_owned())?;
                if record.body.finding_id != self.finding_id
                    || record.body.purchase_intent_id != self.purchase_intent_id
                    || record.body.authoritative_payment_operation_id
                        != self.authoritative_payment_operation_id
                    || record.body.payer != self.payer_key
                    || record.body.buyer != self.payer_key
                    || record.body.accepted_price != self.accepted_price
                    || record.body.realized_spend != self.realized_spend
                    || record.body.delivery_receipt_id != self.delivery_receipt.id
                {
                    return Err("purchase record does not bind the route terminal".to_owned());
                }
            }
            FindingPurchaseVerdict::Deny => {
                let failed = self.failed_delivery.as_ref().ok_or_else(|| {
                    "released purchase omitted failed-delivery evidence".to_owned()
                })?;
                if failed.body.venue_admission_envelope_sha256
                    != chio_core::canonical_json_bytes(admission)
                        .map(|bytes| sha256_hex(&bytes))
                        .map_err(|_| "retained admission canonicalization failed".to_owned())?
                    || failed.body.recorded_at < admission.body.failed_delivery_authority.valid_from
                    || failed.body.recorded_at
                        >= admission.body.failed_delivery_authority.valid_until
                {
                    return Err(
                        "failed-delivery terminal is outside its retained admission policy"
                            .to_owned(),
                    );
                }
                verify_signed_failed_delivery(
                    failed,
                    &admission.body.failed_delivery_authority.key,
                )
                .map_err(|_| "failed-delivery authority verification failed".to_owned())?;
                let receipt_sha256 = chio_core::canonical_json_bytes(&self.delivery_receipt)
                    .map(|bytes| sha256_hex(&bytes))
                    .map_err(|_| "delivery receipt canonicalization failed".to_owned())?;
                if failed.body.finding_id != self.finding_id
                    || failed.body.reservation_id != self.reservation_id
                    || failed.body.purchase_intent_id != self.purchase_intent_id
                    || failed.body.authoritative_payment_operation_id
                        != self.authoritative_payment_operation_id
                    || failed.body.hold_attempt_reference != self.authoritative_payment_operation_id
                    || failed.body.buyer != self.payer_key
                    || failed.body.release_terminal != FindingHoldReleaseTerminal::Released
                    || failed.body.deny_receipt_id != self.delivery_receipt.id
                    || failed.body.deny_receipt_sha256 != receipt_sha256
                    || failed.body.realized_spend_units != 0
                    || failed.body.currency != self.realized_spend.currency
                {
                    return Err(
                        "failed-delivery artifact does not bind the route terminal".to_owned()
                    );
                }
            }
        }
        Ok(())
    }
}

/// Fail-closed executor outcomes. The route maps these to stable public codes
/// and never exposes adapter-provided detail.
#[derive(Debug, thiserror::Error)]
pub enum FindingPurchaseExecutionError {
    #[error("purchase rejected: {0}")]
    Rejected(String),
    #[error("purchase conflicts with durable state: {0}")]
    Conflict(String),
    #[error("purchase remains pending: {0}")]
    Pending(String),
    #[error("purchase executor is temporarily unavailable: {0}")]
    Unavailable(String),
    #[error("purchase executor failed: {0}")]
    Internal(String),
}

/// Authenticated buyer identity resolved from a deployment-owned scoped
/// credential. Fields are private so callers cannot construct an identity
/// without the validating constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedFindingBuyer {
    principal_id: String,
    payer: String,
    public_key: PublicKey,
}

impl AuthenticatedFindingBuyer {
    /// Construct a bounded buyer identity after deployment authentication.
    pub fn new(principal_id: String, payer: String, public_key: PublicKey) -> Result<Self, String> {
        require_bounded_text(&principal_id, MAX_PAYER_BYTES, "principal_id")?;
        require_bounded_text(&payer, MAX_PAYER_BYTES, "payer")?;
        Ok(Self {
            principal_id,
            payer,
            public_key,
        })
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    #[must_use]
    pub fn payer(&self) -> &str {
        &self.payer
    }

    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Coarse scoped-authentication failure. Public routes never reveal whether a
/// token, principal, or key mapping was absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingBuyerAuthenticationError;

/// Deployment-owned end-to-end purchase adapter.
///
/// Implementations must authenticate or immutably resolve `payer`, keep all
/// seller-signed artifacts out of caller authority, use
/// `FindingPurchaseCoordinator` for reserve/slot/finalize transitions, and
/// return only a replay-stable captured Allow or released Deny. An ambiguous
/// or incomplete operation must return `Pending`, never a fabricated terminal.
/// A new request must revalidate finding liveness and current admission before
/// reserving. A completed idempotent replay must return its durable terminal
/// even if either has since expired. Every new public reservation must bind
/// the complete request policy through `reserve_for_public_request`; returning
/// an internal or differently bound durable terminal is invalid.
#[async_trait::async_trait]
pub trait FindingPurchaseExecutor: Send + Sync {
    /// Active serving fence of the authority store that records purchases.
    /// The combined market runtime rejects an executor whose fence differs
    /// from the challenge runtime before either route is installed.
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence;

    /// Resolve one bearer credential to a buyer principal. Production
    /// implementations must use a constant-time token comparison and must not
    /// accept the global control-plane service credential.
    fn authenticate_buyer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedFindingBuyer, FindingBuyerAuthenticationError>;

    /// Publish or refresh one live non-inclusion proof. This is an
    /// operator-only admission seam and is never authorized by a buyer token.
    fn publish_live_status(&self, _finding_id: &str, _now: u64) -> Result<String, String> {
        Err("finding status publication is unavailable".to_owned())
    }

    /// Resolve the exact public proof bundle retained at admission.
    fn public_proof(&self, _finding_id: &str) -> Result<Vec<u8>, String> {
        Err("finding proof bundle is unavailable".to_owned())
    }

    async fn execute(
        &self,
        buyer: AuthenticatedFindingBuyer,
        request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError>;
}

/// GET /v1/findings/{finding_id}/proof (public).
pub(crate) async fn handle_get_finding_proof_bundle(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
) -> Response {
    if require_hex64(&finding_id, "finding_id").is_err() {
        return plain_http_error(StatusCode::BAD_REQUEST, "finding id is invalid");
    }
    let Some(executor) = state.finding_purchase_executor.clone() else {
        return plain_http_error(StatusCode::NOT_FOUND, "finding proof bundle is unavailable");
    };
    bounded_serving::serve_public_proof(executor, finding_id, state.finding_proof_egress_lane).await
}

/// POST /v1/findings/{finding_id}/operator/live-status (service-authenticated).
///
/// The route exists for the explicit local operator workflow. It is separate
/// from buyer purchase authentication and cannot publish a retraction.
pub(crate) async fn handle_publish_live_finding_status(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if require_hex64(&finding_id, "finding_id").is_err() {
        return plain_http_error(StatusCode::BAD_REQUEST, "finding id is invalid");
    }
    let Some(executor) = state.finding_purchase_executor.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "finding status publication is not configured",
        );
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "finding status clock is unavailable",
            )
        }
    };
    match executor.publish_live_status(&finding_id, now) {
        Ok(proof_sha256) => canonical_response(
            StatusCode::OK,
            &serde_json::json!({
                "findingId": finding_id,
                "proofSha256": proof_sha256,
            }),
        ),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error),
    }
}

/// Shared executor handle installed explicitly by a deployment.
pub type SharedFindingPurchaseExecutor = Arc<dyn FindingPurchaseExecutor>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingPurchaseErrorResponse {
    schema: &'static str,
    code: &'static str,
    message: &'static str,
}

fn canonical_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match chio_core::canonical_json_bytes(value) {
        Ok(bytes) => (status, [(CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(_) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "purchase response canonicalization failed",
        ),
    }
}

fn purchase_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    canonical_response(
        status,
        &FindingPurchaseErrorResponse {
            schema: FINDING_PURCHASE_ERROR_SCHEMA,
            code,
            message,
        },
    )
}

fn purchase_terminal_response(result: &FindingPurchaseResult) -> Response {
    match chio_core::canonical_json_bytes(result) {
        Ok(bytes) if bytes.len() <= FINDING_PURCHASE_MAX_RESULT_BYTES => {
            (StatusCode::OK, [(CONTENT_TYPE, "application/json")], bytes).into_response()
        }
        Ok(_) => purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_too_large",
            "purchase executor returned an oversized terminal",
        ),
        Err(_) => purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_invalid",
            "purchase executor returned an invalid terminal",
        ),
    }
}

fn require_exact_durable_terminal(
    store: &SqliteFindingPurchaseStore,
    result: &FindingPurchaseResult,
) -> Result<(), ()> {
    match result.verdict {
        FindingPurchaseVerdict::Allow => {
            let record = result.purchase_record.as_ref().ok_or(())?;
            let record_json = chio_core::canonical_json_bytes(record).map_err(|_| ())?;
            let record_sha256 = sha256_hex(&record_json);
            let stored = store
                .get_purchase_record(&record.body.purchase_key)
                .map_err(|_| ())?
                .ok_or(())?;
            if stored.purchase_key != record.body.purchase_key
                || stored.reservation_id != result.reservation_id
                || stored.record_json != record_json
                || stored.record_sha256 != record_sha256
                || stored.delivery_receipt_id != result.delivery_receipt.id
                || !retained_at_or_after_terminal(stored.recorded_at, record.body.recorded_at)
            {
                return Err(());
            }
        }
        FindingPurchaseVerdict::Deny => {
            let failed = result.failed_delivery.as_ref().ok_or(())?;
            let record_json = chio_core::canonical_json_bytes(failed).map_err(|_| ())?;
            let record_sha256 = sha256_hex(&record_json);
            let stored = store
                .get_failed_delivery_record(&failed.body.failed_delivery_id)
                .map_err(|_| ())?
                .ok_or(())?;
            if stored.failed_delivery_id != failed.body.failed_delivery_id
                || stored.reservation_id != result.reservation_id
                || stored.record_json != record_json
                || stored.record_sha256 != record_sha256
                || stored.deny_receipt_id != result.delivery_receipt.id
                || !retained_at_or_after_terminal(stored.recorded_at, failed.body.recorded_at)
            {
                return Err(());
            }
        }
    }
    Ok(())
}

fn retained_at_or_after_terminal(stored_at: u64, terminal_at: u64) -> bool {
    // The signed JSON fixes the authenticated terminal time. The row time is
    // the later local transaction time and need not fall in the same second.
    stored_at >= terminal_at
}

fn parse_request(raw: &str) -> Result<FindingPurchaseRequest, Response> {
    if raw.len() > FINDING_PURCHASE_MAX_BODY_BYTES {
        return Err(purchase_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "purchase_request_too_large",
            "purchase request exceeds the body bound",
        ));
    }
    let strict = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
        purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_request_not_canonical",
            "purchase request is not strict canonical I-JSON",
        )
    })?;
    if strict.as_slice() != raw.as_bytes() {
        return Err(purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_request_not_canonical",
            "purchase request bytes are not canonical",
        ));
    }
    let request: FindingPurchaseRequest = serde_json::from_str(raw).map_err(|_| {
        purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_request_invalid",
            "purchase request has an invalid closed shape",
        )
    })?;
    let typed = chio_core::canonical_json_bytes(&request).map_err(|_| {
        purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_request_invalid",
            "purchase request cannot be canonicalized",
        )
    })?;
    if typed != strict || request.validate().is_err() {
        return Err(purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_request_invalid",
            "purchase request failed validation",
        ));
    }
    Ok(request)
}

fn parse_stored_finding(raw: &str) -> Result<Finding, Response> {
    let strict = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
        purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_finding_invalid",
            "stored finding is not strict canonical I-JSON",
        )
    })?;
    if strict.as_slice() != raw.as_bytes() {
        return Err(purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_finding_invalid",
            "stored finding bytes are not canonical",
        ));
    }
    let finding: Finding = serde_json::from_str(raw).map_err(|_| {
        purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_finding_invalid",
            "stored finding failed typed parsing",
        )
    })?;
    let typed = chio_core::canonical_json_bytes(&finding).map_err(|_| {
        purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_finding_invalid",
            "stored finding failed canonicalization",
        )
    })?;
    if typed != strict || chio_finding::verify_finding(&finding).is_err() {
        return Err(purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_finding_invalid",
            "stored finding failed verification",
        ));
    }
    Ok(finding)
}

/// POST /v1/findings/{finding_id}/purchase (authenticated).
pub(crate) async fn handle_purchase_finding(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    request: Request,
) -> Response {
    let executor = state.finding_purchase_executor.clone();
    let authenticated_buyer = if let Some(executor) = executor.as_ref() {
        let bearer_token = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty());
        match bearer_token.and_then(|token| executor.authenticate_buyer(token).ok()) {
            Some(buyer) => Some(buyer),
            None => return purchase_authentication_failed(),
        }
    } else {
        if let Err(response) = validate_service_auth(request.headers(), &state.config.service_token)
        {
            return if response.status() == StatusCode::UNAUTHORIZED {
                purchase_authentication_failed()
            } else {
                purchase_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "purchase_auth_unconfigured",
                    "purchase request authentication is unavailable",
                )
            };
        }
        None
    };
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return purchase_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "purchase_content_type_invalid",
            "purchase request content type must be application/json",
        );
    }
    let raw = match axum::body::to_bytes(request.into_body(), FINDING_PURCHASE_MAX_BODY_BYTES).await
    {
        Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
            Ok(raw) => raw,
            Err(_) => {
                return purchase_error(
                    StatusCode::BAD_REQUEST,
                    "purchase_request_not_utf8",
                    "purchase request is not UTF-8",
                )
            }
        },
        Err(_) => {
            return purchase_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "purchase_request_too_large",
                "purchase request exceeds the body bound",
            )
        }
    };
    let request = match parse_request(&raw) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Some(buyer) = authenticated_buyer.as_ref() {
        match request.payer.as_deref() {
            None => {
                return purchase_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "purchase_payer_required",
                    "purchase request must name its authenticated payer",
                )
            }
            Some(payer) if payer != buyer.payer() => {
                return purchase_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "purchase_payer_mismatch",
                    "purchase payer does not match the authenticated buyer",
                )
            }
            Some(_) => {}
        }
    }
    if request.finding_id != finding_id {
        return purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_path_mismatch",
            "purchase path and body name different findings",
        );
    }
    if state.config.finding_market.is_none() {
        return purchase_error(
            StatusCode::CONFLICT,
            "finding_market_unconfigured",
            "finding market is not configured",
        );
    }
    let Some(authority) = state.joint_authority_store.as_ref() else {
        return purchase_error(
            StatusCode::CONFLICT,
            "finding_market_store_unavailable",
            "finding market durable store is unavailable",
        );
    };
    let store = authority.finding_market_store();
    let purchase_store = authority.finding_purchase_store();
    let raw_finding = match store.get_finding_bytes(&finding_id) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return purchase_error(
                StatusCode::NOT_FOUND,
                "finding_not_found",
                "finding is not published",
            )
        }
        Err(_) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "finding_store_failed",
                "finding store lookup failed",
            )
        }
    };
    let finding = match parse_stored_finding(&raw_finding) {
        Ok(finding) => finding,
        Err(response) => return response,
    };
    let Some(executor) = executor else {
        return purchase_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "purchase_executor_unavailable",
            "finding purchase executor is not configured",
        );
    };
    let Some(authenticated_buyer) = authenticated_buyer else {
        return purchase_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "purchase_auth_unconfigured",
            "purchase request authentication is unavailable",
        );
    };

    let execution = match bounded_serving::execute_purchase(
        executor,
        authenticated_buyer,
        request.clone(),
        state.finding_purchase_execution_lane,
    )
    .await
    {
        Ok(execution) => execution,
        Err(bounded_serving::PurchaseLaneError::Busy) => {
            return purchase_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "purchase_busy",
                "finding purchase execution lane is busy",
            )
        }
        Err(bounded_serving::PurchaseLaneError::Worker) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_executor_failed",
                "finding purchase execution worker failed",
            )
        }
    };
    let result = match execution {
        Ok(result) => result,
        Err(FindingPurchaseExecutionError::Rejected(error)) => {
            tracing::warn!(error = %error, finding_id = %finding_id, "finding purchase rejected");
            return purchase_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "purchase_rejected",
                "purchase executor rejected the request",
            );
        }
        Err(FindingPurchaseExecutionError::Conflict(error)) => {
            tracing::warn!(error = %error, finding_id = %finding_id, "finding purchase conflicted");
            return purchase_error(
                StatusCode::CONFLICT,
                "purchase_conflict",
                "purchase conflicts with durable state",
            );
        }
        Err(FindingPurchaseExecutionError::Pending(error)) => {
            tracing::info!(error = %error, finding_id = %finding_id, "finding purchase pending");
            return purchase_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "purchase_pending",
                "purchase has no safe terminal result yet",
            );
        }
        Err(FindingPurchaseExecutionError::Unavailable(error)) => {
            tracing::error!(error = %error, finding_id = %finding_id, "finding purchase storage unavailable");
            return purchase_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "purchase_executor_unavailable",
                "finding purchase executor is temporarily unavailable",
            );
        }
        Err(FindingPurchaseExecutionError::Internal(error)) => {
            tracing::error!(error = %error, finding_id = %finding_id, "finding purchase executor failed");
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_executor_failed",
                "finding purchase executor failed",
            );
        }
    };
    let admission_digest = match result.verdict {
        FindingPurchaseVerdict::Allow => result
            .purchase_record
            .as_ref()
            .map(|record| record.body.venue_admission_envelope_sha256.as_str()),
        FindingPurchaseVerdict::Deny => result
            .failed_delivery
            .as_ref()
            .map(|failed| failed.body.venue_admission_envelope_sha256.as_str()),
    };
    let Some(admission_digest) = admission_digest else {
        return purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_invalid",
            "purchase executor returned an invalid terminal",
        );
    };
    let admission_json = match store.get_admission_by_envelope_sha256(admission_digest) {
        Ok(Some(json)) => json,
        Ok(None) | Err(_) => {
            return purchase_error(
                StatusCode::BAD_GATEWAY,
                "purchase_terminal_invalid",
                "purchase executor returned an invalid terminal",
            )
        }
    };
    let admission: SignedFindingAdmission = match serde_json::from_str(&admission_json) {
        Ok(admission) => admission,
        Err(_) => {
            return purchase_error(
                StatusCode::BAD_GATEWAY,
                "purchase_terminal_invalid",
                "purchase executor returned an invalid terminal",
            )
        }
    };
    if verify_signed_admission(&admission, &admission.body.venue, &admission.body.venue_id).is_err()
    {
        return purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_invalid",
            "purchase executor returned an invalid terminal",
        );
    }
    let payer_hex = result.payer_key.to_hex();
    let public_request = FindingPublicPurchaseRequestBinding {
        request_id: &request.request_id,
        finding_id: &request.finding_id,
        requested_payer: request.payer.as_deref(),
        resolved_payer: &result.payer,
        payer_hex: &payer_hex,
        max_price_units: request.max_price.units,
        currency: &request.max_price.currency,
        deadline_secs: request.deadline_secs,
    };
    let public_terminal = match result.verdict {
        FindingPurchaseVerdict::Allow => {
            result
                .purchase_record
                .as_ref()
                .map(|record| FindingPublicPurchaseTerminal {
                    kind: FindingPublicPurchaseTerminalKind::PurchaseRecord,
                    terminal_id: record.body.purchase_key.as_str(),
                    receipt_id: result.delivery_receipt.id.as_str(),
                })
        }
        FindingPurchaseVerdict::Deny => {
            result
                .failed_delivery
                .as_ref()
                .map(|failed| FindingPublicPurchaseTerminal {
                    kind: FindingPublicPurchaseTerminalKind::FailedDelivery,
                    terminal_id: failed.body.failed_delivery_id.as_str(),
                    receipt_id: result.delivery_receipt.id.as_str(),
                })
        }
    };
    let Some(public_terminal) = public_terminal else {
        return purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_invalid",
            "purchase executor returned an invalid terminal",
        );
    };
    if result
        .validate_authorized(&request, &finding, &admission)
        .is_err()
        || require_exact_durable_terminal(&purchase_store, &result).is_err()
        || purchase_store
            .verify_public_purchase_terminal(
                &public_request,
                &result.reservation_id,
                &public_terminal,
            )
            .is_err()
    {
        return purchase_error(
            StatusCode::BAD_GATEWAY,
            "purchase_terminal_invalid",
            "purchase executor returned an invalid terminal",
        );
    }
    purchase_terminal_response(&result)
}

fn purchase_authentication_failed() -> Response {
    let mut response = purchase_error(
        StatusCode::UNAUTHORIZED,
        "purchase_unauthorized",
        "purchase request authentication failed",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn require_hex64(value: &str, field: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{field} must be 64 lowercase hex characters"))
    }
}

fn require_currency(currency: &str) -> Result<(), String> {
    if currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err("currency must be three uppercase ASCII letters".to_owned())
    }
}

fn require_bounded_text(value: &str, max_bytes: usize, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(format!(
            "{field} is empty, unbounded, or contains unsafe characters"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chio_core::Keypair;

    use super::{retained_at_or_after_terminal, FindingPurchaseResult};

    #[test]
    fn durable_terminal_row_may_be_recorded_after_the_signed_terminal() {
        assert!(retained_at_or_after_terminal(101, 100));
        assert!(retained_at_or_after_terminal(100, 100));
        assert!(!retained_at_or_after_terminal(99, 100));
    }

    #[test]
    fn purchase_payer_text_must_name_the_signed_payer_key() {
        let payer_key = Keypair::from_seed(&[1; 32]).public_key();
        let other_key = Keypair::from_seed(&[2; 32]).public_key();
        assert_eq!(payer_key.to_hex().len(), 64);
        assert_ne!(payer_key, other_key);
        assert_eq!(
            FindingPurchaseResult::validate_payer_binding(&payer_key.to_hex(), &payer_key),
            Ok(())
        );

        let payer = other_key.to_hex();
        assert_ne!(payer, payer_key.to_hex());
        assert_eq!(
            FindingPurchaseResult::validate_payer_binding(&payer, &payer_key),
            Err("purchase payer does not bind its signed payer key".to_owned())
        );
    }
}
