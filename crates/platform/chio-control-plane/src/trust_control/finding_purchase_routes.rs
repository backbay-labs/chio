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
//! [`super::serve_with_finding_purchase_executor`].

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Request, State};
use axum::http::{
    header::{CONTENT_TYPE, WWW_AUTHENTICATE},
    HeaderValue, StatusCode,
};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_finding::{
    verify_signed_failed_delivery, verify_signed_purchase_record, Finding,
    FindingHoldReleaseTerminal, SignedFindingFailedDelivery, SignedFindingPurchaseRecord,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use serde::{Deserialize, Serialize};

use super::report_validation::validate_service_auth;
use super::{plain_http_error, TrustServiceState};

/// Stable request schema for the public purchase surface.
pub const FINDING_PURCHASE_REQUEST_SCHEMA: &str = "chio.finding.purchase-request.v1";
/// Stable terminal response schema for the public purchase surface.
pub const FINDING_PURCHASE_RESULT_SCHEMA: &str = "chio.finding.purchase-result.v1";
/// Stable structured error schema for the public purchase surface.
pub const FINDING_PURCHASE_ERROR_SCHEMA: &str = "chio.finding.purchase-error.v1";

/// Maximum canonical request size accepted at the public route.
pub const FINDING_PURCHASE_MAX_BODY_BYTES: usize = 16 * 1024;
/// Maximum decoded purchased payload returned through this route.
pub const FINDING_PURCHASE_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical terminal response size, including base64 expansion and
/// signed settlement evidence.
pub const FINDING_PURCHASE_MAX_RESULT_BYTES: usize =
    FINDING_PURCHASE_MAX_OUTPUT_BYTES.div_ceil(3) * 4 + 2 * 1024 * 1024;
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

    fn validate_authorized(
        &self,
        request: &FindingPurchaseRequest,
        finding: &Finding,
        purchase_authority: &PublicKey,
        failed_delivery_authority: &PublicKey,
    ) -> Result<(), String> {
        self.validate_shape(request)?;
        if finding.finding_id != self.finding_id {
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
                let reveal = serde_json::json!({
                    "media_type": output.media_type,
                    "payload_b64": output.payload_b64,
                });
                let digest = chio_core::canonical_json_bytes(&reveal)
                    .map(|bytes| sha256_hex(&bytes))
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
                verify_signed_purchase_record(record, purchase_authority)
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
                verify_signed_failed_delivery(failed, failed_delivery_authority)
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

/// Deployment-owned end-to-end purchase adapter.
///
/// Implementations must authenticate or immutably resolve `payer`, keep all
/// seller-signed artifacts out of caller authority, use
/// `FindingPurchaseCoordinator` for reserve/slot/finalize transitions, and
/// return only a replay-stable captured Allow or released Deny. An ambiguous
/// or incomplete operation must return `Pending`, never a fabricated terminal.
/// A new request must revalidate finding liveness and current admission before
/// reserving. A completed idempotent replay must return its durable terminal
/// even if either has since expired.
#[async_trait::async_trait]
pub trait FindingPurchaseExecutor: Send + Sync {
    /// Active serving fence of the authority store that records purchases.
    /// The combined market runtime rejects an executor whose fence differs
    /// from the challenge runtime before either route is installed.
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence;

    async fn execute(
        &self,
        request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError>;
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
    if let Err(response) = validate_service_auth(request.headers(), &state.config.service_token) {
        return if response.status() == StatusCode::UNAUTHORIZED {
            let mut response = purchase_error(
                StatusCode::UNAUTHORIZED,
                "purchase_unauthorized",
                "purchase request authentication failed",
            );
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            response
        } else {
            purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_auth_unconfigured",
                "purchase request authentication is unavailable",
            )
        };
    }
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
    if request.finding_id != finding_id {
        return purchase_error(
            StatusCode::BAD_REQUEST,
            "purchase_path_mismatch",
            "purchase path and body name different findings",
        );
    }
    let Some(config) = state.config.finding_market.as_ref() else {
        return purchase_error(
            StatusCode::CONFLICT,
            "finding_market_unconfigured",
            "finding market is not configured",
        );
    };
    let Some(authority) = state.joint_authority_store.as_ref() else {
        return purchase_error(
            StatusCode::CONFLICT,
            "finding_market_store_unavailable",
            "finding market durable store is unavailable",
        );
    };
    let store = authority.finding_market_store();
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
    let Some(executor) = state.finding_purchase_executor.as_ref() else {
        return purchase_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "purchase_executor_unavailable",
            "finding purchase executor is not configured",
        );
    };

    let result = match executor.execute(request.clone()).await {
        Ok(result) => result,
        Err(FindingPurchaseExecutionError::Rejected(_)) => {
            return purchase_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "purchase_rejected",
                "purchase executor rejected the request",
            )
        }
        Err(FindingPurchaseExecutionError::Conflict(_)) => {
            return purchase_error(
                StatusCode::CONFLICT,
                "purchase_conflict",
                "purchase conflicts with durable state",
            )
        }
        Err(FindingPurchaseExecutionError::Pending(_)) => {
            return purchase_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "purchase_pending",
                "purchase has no safe terminal result yet",
            )
        }
        Err(FindingPurchaseExecutionError::Unavailable(_)) => {
            return purchase_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "purchase_executor_unavailable",
                "finding purchase executor is temporarily unavailable",
            )
        }
        Err(FindingPurchaseExecutionError::Internal(_)) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_executor_failed",
                "finding purchase executor failed",
            )
        }
    };
    let purchase_authority = match config.purchase.key() {
        Ok(key) => key,
        Err(_) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_authority_invalid",
                "configured purchase authority is invalid",
            )
        }
    };
    let failed_delivery_authority = match config.failed_delivery.key() {
        Ok(key) => key,
        Err(_) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed_delivery_authority_invalid",
                "configured failed-delivery authority is invalid",
            )
        }
    };
    if result
        .validate_authorized(
            &request,
            &finding,
            &purchase_authority,
            &failed_delivery_authority,
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
