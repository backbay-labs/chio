use std::time::Duration;

use chio_core::{capability::scope::MonetaryAmount, receipt::economics::SettlementStatus};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const MAX_PAYMENT_RAIL_IDENTIFIER_BYTES: usize = 512;

/// Result of a payment authorization or settlement hold.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether the rail already considers the funds fully settled.
    pub settled: bool,
    /// Rail transaction identifier for an already-settled authorization.
    ///
    /// Adapters should provide this when `settled` is true. For compatibility
    /// with prepaid adapters that predate this field, the kernel falls back to
    /// `authorization_id` as the settlement reference when it is omitted.
    pub settlement_transaction_id: Option<String>,
    /// Rail-specific metadata such as idempotency keys, quote IDs, or expiry.
    pub metadata: serde_json::Value,
}

/// Result of a capture, settlement, release, or refund operation.
///
/// Built-in adapters mark `metadata.remote_acknowledged` to distinguish a
/// response returned by a configured rail endpoint from compatibility-mode
/// local bookkeeping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentResult {
    /// Stable rail reference for the resulting financial operation.
    #[serde(alias = "transaction_id")]
    pub transaction_id: String,
    /// Richer rail-side settlement state, mapped onto the canonical receipt enum.
    #[serde(alias = "settlement_status")]
    pub settlement_status: RailSettlementStatus,
    /// Rail-specific metadata such as confirmations or idempotency keys.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl PaymentResult {
    #[must_use]
    pub(crate) fn is_local_bookkeeping(&self) -> bool {
        self.metadata
            .get("remote_acknowledged")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    }
}

/// Richer settlement states surfaced by payment rails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailSettlementStatus {
    Authorized,
    Captured,
    Settled,
    Pending,
    Failed,
    Released,
    Refunded,
}

/// Exact terminal rail action used to unwind a pre-dispatch authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreDispatchPaymentUnwindStatus {
    Released,
    Refunded,
}

/// Single-use credential disposition after payment authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCredentialDisposition {
    NonePresent,
    RetainedAfterAuthorization,
    RetentionOutcomeUnknown,
}

/// Typed evidence embedded in a signed terminal receipt after a clean unwind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreDispatchPaymentUnwindEvidence {
    pub authorization_id: String,
    pub transaction_id: String,
    pub settlement_status: PreDispatchPaymentUnwindStatus,
    pub credential_disposition: PaymentCredentialDisposition,
}

impl RailSettlementStatus {
    /// Map rail-specific settlement states onto the receipt-side canonical enum.
    #[must_use]
    pub const fn to_receipt_status(self) -> SettlementStatus {
        match self {
            Self::Authorized | Self::Captured | Self::Pending => SettlementStatus::Pending,
            Self::Settled | Self::Released | Self::Refunded => SettlementStatus::Settled,
            Self::Failed => SettlementStatus::Failed,
        }
    }
}

/// Canonical settlement fields as they appear on signed financial receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSettlement {
    pub payment_reference: Option<String>,
    pub settlement_status: SettlementStatus,
}

/// Governed request details forwarded to payment rails when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedPaymentContext {
    pub intent_id: String,
    pub intent_hash: String,
    pub purpose: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
}

/// Commerce approval details forwarded to seller-scoped payment rails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommercePaymentContext {
    pub seller: String,
    pub shared_payment_token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
}

/// Canonical authorization request forwarded to a payment rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAuthorizeRequest {
    pub amount_units: u64,
    pub currency: String,
    pub payer: String,
    pub payee: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed: Option<GovernedPaymentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<CommercePaymentContext>,
}

impl ReceiptSettlement {
    #[must_use]
    pub const fn not_applicable() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::NotApplicable,
        }
    }

    #[must_use]
    pub const fn settled() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
        }
    }

    #[must_use]
    pub const fn failed() -> Self {
        Self {
            payment_reference: None,
            settlement_status: SettlementStatus::Failed,
        }
    }

    #[must_use]
    pub fn from_authorization(authorization: &PaymentAuthorization) -> Self {
        Self {
            payment_reference: if authorization.settled {
                Some(
                    authorization
                        .settlement_transaction_id
                        .clone()
                        .unwrap_or_else(|| authorization.authorization_id.clone()),
                )
            } else {
                Some(authorization.authorization_id.clone())
            },
            settlement_status: if authorization.settled {
                SettlementStatus::Settled
            } else {
                SettlementStatus::Pending
            },
        }
    }

    #[must_use]
    pub fn from_payment_result(result: &PaymentResult) -> Self {
        Self {
            payment_reference: Some(result.transaction_id.clone()),
            settlement_status: result.settlement_status.to_receipt_status(),
        }
    }

    #[must_use]
    pub fn into_receipt_parts(self) -> (Option<String>, SettlementStatus) {
        (self.payment_reference, self.settlement_status)
    }
}

/// Side-effect-free snapshot of a rail's view of a prior authorization,
/// returned by [`PaymentAdapter::settlement_state`]. Distinct from
/// [`PaymentResult`] because the crash window this query answers spans a
/// case `PaymentResult` cannot express on its own: a hold that exists but
/// has not settled. Carrying that distinction explicitly lets
/// reconciliation release a proven hold-only authorization while never
/// releasing, and thereby erasing the only record of, funds the rail
/// already moved.
#[derive(Debug, Clone, PartialEq)]
pub enum RailSettlementState {
    /// The rail has no hold or settlement for this reference: `authorize`
    /// never took effect. Reconciliation reverses the local budget hold and
    /// closes the journal; funds never moved.
    NoAuthorization,
    /// A hold exists but no funds have moved. Carries the rail-assigned
    /// `authorization_id` so reconciliation can release it.
    Held {
        /// Rail-assigned identifier for the open, unsettled hold.
        authorization_id: String,
    },
    /// Funds already moved on the rail. Carries the rail-assigned
    /// `authorization_id` and the settled result so reconciliation records
    /// the id and emits a durable receipt for the already-moved amount
    /// instead of releasing it.
    Settled {
        /// Rail-assigned identifier for the settled authorization.
        authorization_id: String,
        /// The rail's settlement result for the moved funds.
        result: PaymentResult,
    },
}

/// Trait for executing payments against an external rail.
pub trait PaymentAdapter: Send + Sync {
    /// Stable identifier of the rail this adapter drives, recorded on
    /// monetary dispatch intents so an operator can reconcile a monetary
    /// orphan against the correct rail without guessing.
    fn rail_id(&self) -> &str {
        "payment"
    }

    /// Authorize or prepay up to `amount_units` before the tool executes.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `request.reference` (the durable request id the kernel records
    /// before the call). A repeated authorize with the same reference
    /// returns the same authorization and places AT MOST ONE rail-side
    /// hold, so crash recovery can re-drive the call without stacking
    /// holds.
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `(authorization_id, reference)`. A repeated call with the same key
    /// returns an equivalent [`PaymentResult`] and moves money AT MOST
    /// ONCE; boot reconciliation replays a committed capture relying on
    /// this.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
    ///
    /// Contract: implementations MUST be idempotent keyed on
    /// `(authorization_id, reference)`, releasing the hold AT MOST ONCE.
    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Refund a previously executed payment.
    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Query the current rail-side settlement state for a prior
    /// authorization WITHOUT moving funds. Idempotent and side-effect-free.
    ///
    /// Keyed on `reference` (the durable request id recorded before
    /// authorize) so it stays answerable in the crash window where no
    /// authorization id is durable yet; `authorization_id` is an optional
    /// refinement passed once known. The returned `RailSettlementState`
    /// distinguishes a live, unsettled hold from funds that already moved,
    /// so reconciliation releases only a proven hold and never mistakes an
    /// already-settled charge for one. Defaulted to `Unavailable` so an
    /// adapter that cannot answer forces a fail-closed operator incident
    /// during reconciliation rather than a silent close.
    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let _ = (reference, authorization_id);
        Err(PaymentError::Unavailable(
            "settlement_state query not implemented by this adapter".to_string(),
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("payment declined: {0}")]
    Declined(String),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("payment rail unavailable: {0}")]
    Unavailable(String),

    #[error("payment rail error: {0}")]
    RailError(String),

    #[error("payment rail operation not configured: {0}")]
    NotConfigured(String),
}

impl PaymentError {
    #[must_use]
    pub(crate) const fn outcome_unknown(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::RailError(_))
    }
}

#[derive(Debug)]
pub(crate) struct PaymentAuthorizationFailure {
    reason: String,
    outcome_unknown: bool,
}

impl PaymentAuthorizationFailure {
    pub(crate) fn before_rail(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            outcome_unknown: false,
        }
    }

    pub(crate) fn from_adapter_error(error: PaymentError) -> Self {
        let outcome_unknown = error.outcome_unknown();
        Self {
            reason: error.to_string(),
            outcome_unknown,
        }
    }

    pub(crate) fn adapter_panicked() -> Self {
        Self {
            reason: "payment adapter panicked during authorization".to_string(),
            outcome_unknown: true,
        }
    }

    pub(crate) fn invalid_authorization_id(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            outcome_unknown: true,
        }
    }

    pub(crate) fn outcome_unknown_reason(&self) -> Option<&str> {
        self.outcome_unknown.then_some(self.reason.as_str())
    }
}

impl std::fmt::Display for PaymentAuthorizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

pub(crate) fn validate_payment_rail_identifier(kind: &str, identifier: &str) -> Result<(), String> {
    if identifier.trim().is_empty() {
        return Err(format!("payment rail {kind} must not be empty"));
    }
    if identifier.trim() != identifier {
        return Err(format!("payment rail {kind} must not be padded"));
    }
    if identifier.len() > MAX_PAYMENT_RAIL_IDENTIFIER_BYTES {
        return Err(format!(
            "payment rail {kind} exceeds {MAX_PAYMENT_RAIL_IDENTIFIER_BYTES} bytes"
        ));
    }
    Ok(())
}

/// Durable money-path journal state. One row per priced request, written
/// before the rail is touched and advanced around every rail call, so a
/// crash in any window leaves a recoverable record instead of moved funds
/// with no trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentJournalState {
    /// Row written with the budget hold, before the rail authorize call.
    HoldPlaced,
    /// The rail authorize returned; the authorization id is recorded.
    Authorized,
    /// About to call capture or release; the rail may move money next.
    Settling,
    /// Capture returned settled or release returned released.
    Settled,
    /// Receipt persisted; terminal success.
    Closed,
    /// Boot reconciliation could not settle or determine the outcome;
    /// operator incident.
    ReconcileFailed,
}

/// Terminal action committed before entering [`PaymentJournalState::Settling`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettleAction {
    /// Capture the recorded amount from the hold.
    Capture,
    /// Release the whole hold without capturing.
    Release,
}

/// The committed settle decision, stamped atomically with the advance to
/// `Settling` so reconciliation replays the exact operation rather than
/// guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentSettleIntent {
    /// The rail call recovery must replay for an in-flight settle.
    pub action: PaymentSettleAction,
    /// Exact capture amount for `Capture`; `None` for `Release`.
    pub amount_units: Option<u64>,
}

/// One durable payment-journal row, keyed by the request id the kernel also
/// uses as the rail idempotency reference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentJournalRecord {
    pub request_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    pub rail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub amount_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_action: Option<PaymentSettleAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_amount_units: Option<u64>,
    pub currency: String,
    pub state: PaymentJournalState,
    pub created_at_unix_ms: u64,
    /// Tenant that owns this request, resolved exactly as the terminal
    /// receipt resolves it (request-scoped entry first, thread-local scope
    /// otherwise). `None` in single-tenant deployments. Threaded onto a
    /// reconciliation receipt so a recovered charge is never dropped from
    /// the owning tenant's receipt view (see [`crate::kernel::ChioKernel`]
    /// reconciliation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Thin HTTP payment bridge for x402-style per-request settlement.
///
/// Authorization is always remote. For compatibility, capture, release, and
/// refund use explicitly marked local bookkeeping when their acknowledgement
/// paths are absent. Configure the corresponding paths for remote
/// acknowledgement, or call
/// [`Self::requiring_remote_settlement_acknowledgements`] to fail closed when a
/// path is absent.
#[derive(Debug, Clone)]
pub struct X402PaymentAdapter {
    base_url: String,
    authorize_path: String,
    capture_path: Option<String>,
    release_path: Option<String>,
    refund_path: Option<String>,
    local_bookkeeping_fallback: bool,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

/// Thin shared-payment-token payment bridge for ACP-style commerce approvals.
///
/// Authorization is always remote. For compatibility, capture, release, and
/// refund use explicitly marked local bookkeeping when their acknowledgement
/// paths are absent. Configure the corresponding paths for remote
/// acknowledgement, or call
/// [`Self::requiring_remote_settlement_acknowledgements`] to fail closed when a
/// path is absent.
#[derive(Debug, Clone)]
pub struct AcpPaymentAdapter {
    base_url: String,
    authorize_path: String,
    capture_path: Option<String>,
    release_path: Option<String>,
    refund_path: Option<String>,
    local_bookkeeping_fallback: bool,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

impl X402PaymentAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            authorize_path: "/authorize".to_string(),
            capture_path: None,
            release_path: None,
            refund_path: None,
            local_bookkeeping_fallback: true,
            bearer_token: None,
            http: build_http_agent(Duration::from_secs(5)),
        }
    }

    #[must_use]
    pub fn with_authorize_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_path = normalize_http_path(&path.into());
        self
    }

    #[must_use]
    pub fn with_capture_path(mut self, path: impl Into<String>) -> Self {
        self.capture_path = Some(normalize_http_path(&path.into()));
        self
    }

    #[must_use]
    pub fn with_release_path(mut self, path: impl Into<String>) -> Self {
        self.release_path = Some(normalize_http_path(&path.into()));
        self
    }

    #[must_use]
    pub fn with_refund_path(mut self, path: impl Into<String>) -> Self {
        self.refund_path = Some(normalize_http_path(&path.into()));
        self
    }

    /// Require configured endpoints for capture, release, and refund.
    ///
    /// The default preserves the legacy local-bookkeeping behavior and marks
    /// its results as not remotely acknowledged. This builder disables that
    /// fallback for deployments that require rail-confirmed terminal actions.
    #[must_use]
    pub fn requiring_remote_settlement_acknowledgements(mut self) -> Self {
        self.local_bookkeeping_fallback = false;
        self
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = build_http_agent(timeout);
        self
    }
}

impl AcpPaymentAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            authorize_path: "/authorize".to_string(),
            capture_path: None,
            release_path: None,
            refund_path: None,
            local_bookkeeping_fallback: true,
            bearer_token: None,
            http: build_http_agent(Duration::from_secs(5)),
        }
    }

    #[must_use]
    pub fn with_authorize_path(mut self, path: impl Into<String>) -> Self {
        self.authorize_path = normalize_http_path(&path.into());
        self
    }

    #[must_use]
    pub fn with_capture_path(mut self, path: impl Into<String>) -> Self {
        self.capture_path = Some(normalize_http_path(&path.into()));
        self
    }

    #[must_use]
    pub fn with_release_path(mut self, path: impl Into<String>) -> Self {
        self.release_path = Some(normalize_http_path(&path.into()));
        self
    }

    #[must_use]
    pub fn with_refund_path(mut self, path: impl Into<String>) -> Self {
        self.refund_path = Some(normalize_http_path(&path.into()));
        self
    }

    /// Require configured endpoints for capture, release, and refund.
    ///
    /// The default preserves the legacy local-bookkeeping behavior and marks
    /// its results as not remotely acknowledged. This builder disables that
    /// fallback for deployments that require rail-confirmed terminal actions.
    #[must_use]
    pub fn requiring_remote_settlement_acknowledgements(mut self) -> Self {
        self.local_bookkeeping_fallback = false;
        self
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = build_http_agent(timeout);
        self
    }
}

impl PaymentAdapter for X402PaymentAdapter {
    fn rail_id(&self) -> &str {
        "x402"
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        // Prepaid rail: funds move at authorize and capture is a local
        // no-op, so a durable authorization id is proof authorize returned
        // and the truthful answer is Settled - reconciliation must never
        // release a hold discovered through it. With only the reference
        // (the HoldPlaced crash window) authorize may never have reached
        // the rail, and this thin bridge has no reference-keyed rail
        // query: answering Settled would fabricate a reconciliation
        // receipt for money that may never have moved, so fail closed to
        // an operator incident instead.
        let Some(authorization_id) = authorization_id else {
            return Err(PaymentError::Unavailable(format!(
                "x402 adapter cannot confirm settlement for reference `{reference}` without \
                 a durable authorization id"
            )));
        };
        let authorization_id = authorization_id.to_string();
        Ok(RailSettlementState::Settled {
            authorization_id: authorization_id.clone(),
            result: PaymentResult {
                transaction_id: authorization_id,
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({
                    "adapter": "x402",
                    "mode": "prepaid",
                    "action": "settlement_state",
                    "reference": reference
                }),
            },
        })
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let response: X402AuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            request,
        )?;
        let (authorization_id, settlement_transaction_id) = resolve_authorization_response_ids(
            response.authorization_id,
            response.transaction_id,
            response.settled,
        )?;
        Ok(PaymentAuthorization {
            authorization_id,
            settled: response.settled,
            settlement_transaction_id,
            metadata: merge_json_values(
                Some(response.metadata),
                Some(serde_json::json!({
                    "adapter": "x402",
                    "mode": "prepaid"
                })),
            )
            .unwrap_or_else(|| serde_json::json!({ "adapter": "x402", "mode": "prepaid" })),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.capture_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "x402 capture acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "x402",
                "prepaid",
                "capture",
                authorization_id,
                RailSettlementStatus::Settled,
                reference,
                Some(amount_units),
                Some(currency),
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: Some(authorization_id),
                transaction_id: None,
                amount_units: Some(amount_units),
                currency: Some(currency),
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.release_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "x402 release acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "x402",
                "prepaid",
                "release",
                authorization_id,
                RailSettlementStatus::Released,
                reference,
                None,
                None,
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: Some(authorization_id),
                transaction_id: None,
                amount_units: None,
                currency: None,
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.refund_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "x402 refund acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "x402",
                "prepaid",
                "refund",
                transaction_id,
                RailSettlementStatus::Refunded,
                reference,
                Some(amount_units),
                Some(currency),
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: None,
                transaction_id: Some(transaction_id),
                amount_units: Some(amount_units),
                currency: Some(currency),
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }
}

impl PaymentAdapter for AcpPaymentAdapter {
    fn rail_id(&self) -> &str {
        "acp"
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        // The shared-payment-token hold settles at authorize time and the
        // local capture/release are no-ops, so a durable authorization id
        // is proof authorize returned and the truthful answer is Settled -
        // reconciliation must never release a hold discovered through it.
        // With only the reference (the HoldPlaced crash window) authorize
        // may never have reached the rail, and this thin bridge has no
        // reference-keyed rail query: answering Settled would fabricate a
        // reconciliation receipt for money that may never have moved, so
        // fail closed to an operator incident instead.
        let Some(authorization_id) = authorization_id else {
            return Err(PaymentError::Unavailable(format!(
                "acp adapter cannot confirm settlement for reference `{reference}` without \
                 a durable authorization id"
            )));
        };
        let authorization_id = authorization_id.to_string();
        Ok(RailSettlementState::Settled {
            authorization_id: authorization_id.clone(),
            result: PaymentResult {
                transaction_id: authorization_id,
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({
                    "adapter": "acp",
                    "mode": "shared_payment_token_hold",
                    "action": "settlement_state",
                    "reference": reference
                }),
            },
        })
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let response: AcpAuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            request,
        )?;
        let (authorization_id, settlement_transaction_id) = resolve_authorization_response_ids(
            response.authorization_id,
            response.transaction_id,
            response.settled,
        )?;
        Ok(PaymentAuthorization {
            authorization_id,
            settled: response.settled,
            settlement_transaction_id,
            metadata: merge_json_values(
                Some(response.metadata),
                Some(serde_json::json!({
                    "adapter": "acp",
                    "mode": "shared_payment_token_hold"
                })),
            )
            .unwrap_or_else(|| {
                serde_json::json!({
                    "adapter": "acp",
                    "mode": "shared_payment_token_hold"
                })
            }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.capture_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "ACP capture acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "acp",
                "shared_payment_token_hold",
                "capture",
                authorization_id,
                RailSettlementStatus::Settled,
                reference,
                Some(amount_units),
                Some(currency),
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: Some(authorization_id),
                transaction_id: None,
                amount_units: Some(amount_units),
                currency: Some(currency),
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.release_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "ACP release acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "acp",
                "shared_payment_token_hold",
                "release",
                authorization_id,
                RailSettlementStatus::Released,
                reference,
                None,
                None,
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: Some(authorization_id),
                transaction_id: None,
                amount_units: None,
                currency: None,
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let Some(path) = self.refund_path.as_deref() else {
            if !self.local_bookkeeping_fallback {
                return Err(PaymentError::NotConfigured(
                    "ACP refund acknowledgement endpoint is not configured".to_string(),
                ));
            }
            return Ok(local_bookkeeping_result(
                "acp",
                "shared_payment_token_hold",
                "refund",
                transaction_id,
                RailSettlementStatus::Refunded,
                reference,
                Some(amount_units),
                Some(currency),
            ));
        };
        let result: PaymentResult = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &PaymentOperationRequest {
                authorization_id: None,
                transaction_id: Some(transaction_id),
                amount_units: Some(amount_units),
                currency: Some(currency),
                reference,
            },
        )?;
        Ok(mark_remote_acknowledgement(result))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentOperationRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_units: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<&'a str>,
    reference: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402AuthorizeResponse {
    #[serde(default, alias = "authorization_id")]
    authorization_id: Option<String>,
    #[serde(default, alias = "transaction_id")]
    transaction_id: Option<String>,
    #[serde(default = "default_true")]
    settled: bool,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcpAuthorizeResponse {
    #[serde(
        alias = "authorization_id",
        alias = "token_id",
        alias = "tokenId",
        alias = "authorizationId"
    )]
    authorization_id: Option<String>,
    #[serde(default, alias = "transaction_id")]
    transaction_id: Option<String>,
    #[serde(default)]
    settled: bool,
    #[serde(default)]
    metadata: serde_json::Value,
}

fn resolve_authorization_response_ids(
    authorization_id: Option<String>,
    transaction_id: Option<String>,
    settled: bool,
) -> Result<(String, Option<String>), PaymentError> {
    let authorization_id = authorization_id
        .or_else(|| transaction_id.clone())
        .ok_or_else(|| {
            PaymentError::RailError(
                "authorization response omitted both authorizationId and transactionId".to_string(),
            )
        })?;
    let settlement_transaction_id = if settled {
        Some(transaction_id.unwrap_or_else(|| authorization_id.clone()))
    } else {
        transaction_id
    };
    Ok((authorization_id, settlement_transaction_id))
}

#[allow(clippy::too_many_arguments)]
fn local_bookkeeping_result(
    adapter: &str,
    mode: &str,
    action: &str,
    transaction_id: &str,
    settlement_status: RailSettlementStatus,
    reference: &str,
    amount_units: Option<u64>,
    currency: Option<&str>,
) -> PaymentResult {
    PaymentResult {
        transaction_id: transaction_id.to_string(),
        settlement_status,
        metadata: serde_json::json!({
            "adapter": adapter,
            "mode": mode,
            "action": action,
            "reference": reference,
            "amount_units": amount_units,
            "currency": currency,
            "acknowledgement": "local_bookkeeping",
            "remote_acknowledged": false
        }),
    }
}

fn mark_remote_acknowledgement(mut result: PaymentResult) -> PaymentResult {
    let mut metadata = match std::mem::take(&mut result.metadata) {
        serde_json::Value::Object(metadata) => metadata,
        serde_json::Value::Null => serde_json::Map::new(),
        rail_metadata => {
            let mut metadata = serde_json::Map::new();
            metadata.insert("rail_metadata".to_string(), rail_metadata);
            metadata
        }
    };
    metadata.insert(
        "acknowledgement".to_string(),
        serde_json::Value::String("remote".to_string()),
    );
    metadata.insert(
        "remote_acknowledged".to_string(),
        serde_json::Value::Bool(true),
    );
    result.metadata = serde_json::Value::Object(metadata);
    result
}

fn post_json<B: Serialize, T: DeserializeOwned>(
    http: &ureq::Agent,
    base_url: &str,
    bearer_token: Option<&str>,
    path: &str,
    body: &B,
) -> Result<T, PaymentError> {
    let url = format!("{base_url}{path}");
    let payload = serde_json::to_value(body)
        .map_err(|error| PaymentError::RailError(format!("invalid request payload: {error}")))?;
    let mut request = http.post(&url);
    if let Some(token) = bearer_token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.send_json(payload) {
        Ok(response) => {
            let body = response.into_string().map_err(|error| {
                PaymentError::RailError(format!(
                    "failed to read payment rail response body: {error}"
                ))
            })?;
            serde_json::from_str(&body).map_err(|error| {
                PaymentError::RailError(format!(
                    "failed to decode payment rail response body: {error}"
                ))
            })
        }
        Err(error) => Err(map_http_payment_error(error)),
    }
}

fn build_http_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build()
}

fn normalize_http_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn default_true() -> bool {
    true
}

fn map_http_payment_error(error: ureq::Error) -> PaymentError {
    match error {
        ureq::Error::Status(402, _response) => PaymentError::InsufficientFunds,
        // A 409 can mean the idempotent operation raced with a request the
        // rail may already have processed. Other 4xx responses are explicit
        // client-side rejections and are safe to retry with a fresh request.
        ureq::Error::Status(status @ 400..=499, response) if status != 409 => {
            PaymentError::Declined(response_error_message(response))
        }
        ureq::Error::Status(status, response) => PaymentError::Unavailable(format!(
            "HTTP {status}: {}",
            response_error_message(response)
        )),
        ureq::Error::Transport(error) => PaymentError::Unavailable(error.to_string()),
    }
}

fn response_error_message(response: ureq::Response) -> String {
    let status_text = response.status_text().to_string();
    match response.into_string() {
        Ok(body) if !body.trim().is_empty() => serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|json| {
                json.get("error")
                    .or_else(|| json.get("message"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or(body),
        _ => status_text,
    }
}

fn merge_json_values(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (None, extra) => extra,
        (Some(base), None) => Some(base),
        (Some(mut base), Some(extra)) => {
            if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
                for (key, value) in extra_obj {
                    base_obj.insert(key.clone(), value.clone());
                }
                Some(base)
            } else {
                Some(base)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn settlement_state_default_fails_closed_to_unavailable() {
        struct BareAdapter;
        impl PaymentAdapter for BareAdapter {
            fn authorize(
                &self,
                _request: &PaymentAuthorizeRequest,
            ) -> Result<PaymentAuthorization, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn capture(
                &self,
                _authorization_id: &str,
                _amount_units: u64,
                _currency: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn release(
                &self,
                _authorization_id: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
            fn refund(
                &self,
                _transaction_id: &str,
                _amount_units: u64,
                _currency: &str,
                _reference: &str,
            ) -> Result<PaymentResult, PaymentError> {
                Err(PaymentError::Unavailable("test".to_string()))
            }
        }
        let adapter = BareAdapter;
        assert_eq!(adapter.rail_id(), "payment");
        // The default forces a fail-closed reconcile incident rather than a
        // silent close for adapters that cannot answer the query.
        match adapter.settlement_state("req-1", None) {
            Err(PaymentError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn prepaid_adapters_answer_settlement_state_without_moving_funds() {
        // The base URLs are never contacted: the prepaid state query is a
        // pure read. With a durable authorization id (proof authorize
        // returned) both adapters report Settled, never Held, because
        // their funds move at authorize: reconciliation must never release
        // a hold discovered through this query.
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1");
        match x402
            .settlement_state("req-x", Some("auth-x"))
            .expect("prepaid settlement state answers")
        {
            RailSettlementState::Settled {
                authorization_id,
                result,
            } => {
                assert_eq!(authorization_id, "auth-x");
                assert_eq!(result.transaction_id, "auth-x");
                assert!(matches!(
                    result.settlement_status,
                    RailSettlementStatus::Settled
                ));
            }
            other => panic!("expected Settled, got {other:?}"),
        }

        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1");
        assert_eq!(acp.rail_id(), "acp");
        match acp
            .settlement_state("req-a", Some("auth-a"))
            .expect("acp settlement state answers")
        {
            RailSettlementState::Settled { result, .. } => {
                assert!(matches!(
                    result.settlement_status,
                    RailSettlementStatus::Settled
                ));
            }
            other => panic!("expected Settled, got {other:?}"),
        }
    }

    #[test]
    fn prepaid_adapters_never_fabricate_settlement_for_a_bare_reference() {
        // The HoldPlaced crash window queries by reference with no
        // authorization id precisely because authorize may never have
        // reached the rail. These thin bridges have no reference-keyed
        // rail query, so the only truthful answer is an error that lands
        // reconciliation in a ReconcileFailed incident - never a
        // fabricated Settled that would emit a reconciliation receipt for
        // money that may never have moved.
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1");
        match x402.settlement_state("req-x", None) {
            Err(PaymentError::Unavailable(detail)) => {
                assert!(detail.contains("req-x"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }

        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1");
        match acp.settlement_state("req-a", None) {
            Err(PaymentError::Unavailable(detail)) => {
                assert!(detail.contains("req-a"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn rail_settlement_status_maps_to_canonical_receipt_states() {
        assert_eq!(
            RailSettlementStatus::Authorized.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Captured.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Pending.to_receipt_status(),
            SettlementStatus::Pending
        );
        assert_eq!(
            RailSettlementStatus::Settled.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Released.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Refunded.to_receipt_status(),
            SettlementStatus::Settled
        );
        assert_eq!(
            RailSettlementStatus::Failed.to_receipt_status(),
            SettlementStatus::Failed
        );
    }

    #[test]
    fn authorization_maps_to_receipt_reference_and_state() {
        let pending = PaymentAuthorization {
            authorization_id: "auth_123".to_string(),
            settled: false,
            settlement_transaction_id: None,
            metadata: serde_json::json!({ "provider": "stripe" }),
        };
        let settled = PaymentAuthorization {
            authorization_id: "auth_456".to_string(),
            settled: true,
            settlement_transaction_id: Some("txn_456".to_string()),
            metadata: serde_json::json!({ "provider": "x402" }),
        };
        let settled_legacy = PaymentAuthorization {
            authorization_id: "auth_legacy".to_string(),
            settled: true,
            settlement_transaction_id: None,
            metadata: serde_json::json!({ "provider": "legacy-prepaid" }),
        };

        let pending_receipt = ReceiptSettlement::from_authorization(&pending);
        let settled_receipt = ReceiptSettlement::from_authorization(&settled);
        let settled_legacy_receipt = ReceiptSettlement::from_authorization(&settled_legacy);

        assert_eq!(
            pending_receipt.payment_reference.as_deref(),
            Some("auth_123")
        );
        assert_eq!(pending_receipt.settlement_status, SettlementStatus::Pending);
        assert_eq!(
            settled_receipt.payment_reference.as_deref(),
            Some("txn_456")
        );
        assert_eq!(settled_receipt.settlement_status, SettlementStatus::Settled);
        assert_eq!(
            settled_legacy_receipt.payment_reference.as_deref(),
            Some("auth_legacy")
        );
        assert_eq!(
            settled_legacy_receipt.settlement_status,
            SettlementStatus::Settled
        );
    }

    #[test]
    fn payment_result_maps_to_receipt_reference_and_state() {
        let result = PaymentResult {
            transaction_id: "txn_123".to_string(),
            settlement_status: RailSettlementStatus::Failed,
            metadata: serde_json::json!({ "provider": "stablecoin" }),
        };

        let receipt = ReceiptSettlement::from_payment_result(&result);

        assert_eq!(receipt.payment_reference.as_deref(), Some("txn_123"));
        assert_eq!(receipt.settlement_status, SettlementStatus::Failed);
    }

    #[test]
    fn x402_adapter_posts_authorize_request_and_returns_settled_payment() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_123",
                "transactionId": "x402_txn_123",
                "settled": true,
                "metadata": {
                    "network": "base"
                }
            }),
        );
        let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: 125,
                currency: "USD".to_string(),
                payer: "agent-1".to_string(),
                payee: "tool-server".to_string(),
                reference: "req-1".to_string(),
                governed: None,
                commerce: None,
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /authorize HTTP/1.1"));
        assert!(request.contains("\"amountUnits\":125"));
        assert!(request.contains("\"currency\":\"USD\""));
        assert!(request.contains("\"payer\":\"agent-1\""));
        assert!(request.contains("\"payee\":\"tool-server\""));
        assert!(request.contains("\"reference\":\"req-1\""));

        assert_eq!(authorization.authorization_id, "x402_txn_123");
        assert!(authorization.settled);
        assert_eq!(
            authorization.settlement_transaction_id.as_deref(),
            Some("x402_txn_123")
        );
        assert_eq!(authorization.metadata["adapter"], "x402");
        assert_eq!(authorization.metadata["network"], "base");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn authorize_transaction_id_falls_back_as_authorization_identity() {
        for adapter_kind in ["x402", "acp"] {
            let (url, _request_rx, handle) = spawn_once_json_server(
                200,
                serde_json::json!({
                    "transactionId": format!("{adapter_kind}_txn_only"),
                    "settled": true
                }),
            );
            let request = PaymentAuthorizeRequest {
                amount_units: 1,
                currency: "USD".to_string(),
                payer: "agent".to_string(),
                payee: "server".to_string(),
                reference: format!("req-{adapter_kind}"),
                governed: None,
                commerce: None,
            };
            let authorization = if adapter_kind == "x402" {
                X402PaymentAdapter::new(url).authorize(&request)
            } else {
                AcpPaymentAdapter::new(url).authorize(&request)
            }
            .expect("transaction-only authorization response remains supported");
            let expected = format!("{adapter_kind}_txn_only");
            assert_eq!(authorization.authorization_id, expected);
            assert_eq!(
                authorization.settlement_transaction_id.as_deref(),
                Some(expected.as_str())
            );
            handle.join().expect("server thread should exit cleanly");
        }
    }

    #[test]
    fn x402_adapter_maps_http_402_to_insufficient_funds() {
        let (url, _request_rx, handle) = spawn_once_json_server(
            402,
            serde_json::json!({
                "error": "insufficient funds"
            }),
        );
        let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

        let error = adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: 125,
                currency: "USD".to_string(),
                payer: "agent-1".to_string(),
                payee: "tool-server".to_string(),
                reference: "req-1".to_string(),
                governed: None,
                commerce: None,
            })
            .expect_err("authorization should fail");

        assert!(matches!(error, PaymentError::InsufficientFunds));

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn x402_adapter_treats_http_conflict_as_outcome_unknown() {
        let (url, _request_rx, handle) = spawn_once_json_server(
            409,
            serde_json::json!({ "error": "authorization outcome unknown" }),
        );
        let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

        let error = adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: 125,
                currency: "USD".to_string(),
                payer: "agent-1".to_string(),
                payee: "tool-server".to_string(),
                reference: "req-http-409".to_string(),
                governed: None,
                commerce: None,
            })
            .expect_err("ambiguous HTTP response must fail closed");

        assert!(matches!(error, PaymentError::Unavailable(_)));
        assert!(error.outcome_unknown());
        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn x402_adapter_treats_non_conflict_client_errors_as_known_declines() {
        for status in [406, 408, 413, 425, 429, 451] {
            let (url, _request_rx, handle) = spawn_once_json_server(
                status,
                serde_json::json!({ "error": "request rejected before processing" }),
            );
            let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

            let error = adapter
                .authorize(&PaymentAuthorizeRequest {
                    amount_units: 125,
                    currency: "USD".to_string(),
                    payer: "agent-1".to_string(),
                    payee: "tool-server".to_string(),
                    reference: format!("req-http-{status}"),
                    governed: None,
                    commerce: None,
                })
                .expect_err("explicit HTTP rejection must fail cleanly");

            assert!(matches!(error, PaymentError::Declined(_)));
            assert!(!error.outcome_unknown());
            handle.join().expect("server thread should exit cleanly");
        }
    }

    #[test]
    fn x402_adapter_uses_custom_path_bearer_token_and_governed_payload() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_custom",
                "transactionId": "x402_txn_custom",
                "settled": true,
                "metadata": {
                    "network": "base-sepolia"
                }
            }),
        );
        let adapter = X402PaymentAdapter::new(url)
            .with_authorize_path("/paywall/authorize")
            .with_bearer_token("secret-token")
            .with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: 4200,
                currency: "USD".to_string(),
                payer: "agent-2".to_string(),
                payee: "payments-api".to_string(),
                reference: "req-governed-x402".to_string(),
                governed: Some(GovernedPaymentContext {
                    intent_id: "intent-42".to_string(),
                    intent_hash: "intent-hash-42".to_string(),
                    purpose: "purchase premium dataset".to_string(),
                    server_id: "payments-api".to_string(),
                    tool_name: "fetch_dataset".to_string(),
                    approval_token_id: Some("approval-42".to_string()),
                }),
                commerce: None,
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /paywall/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer secret-token"));
        assert!(request.contains("\"governed\":{"));
        assert!(request.contains("\"intentId\":\"intent-42\""));
        assert!(request.contains("\"approvalTokenId\":\"approval-42\""));

        assert_eq!(authorization.authorization_id, "x402_txn_custom");
        assert_eq!(authorization.metadata["adapter"], "x402");
        assert_eq!(authorization.metadata["mode"], "prepaid");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn acp_adapter_posts_authorize_request_with_commerce_context_and_returns_hold() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "acp_hold_123",
                "settled": false,
                "metadata": {
                    "provider": "stripe",
                    "seller": "merchant.example"
                }
            }),
        );
        let adapter = AcpPaymentAdapter::new(url)
            .with_authorize_path("/commerce/authorize")
            .with_bearer_token("acp-secret")
            .with_timeout(Duration::from_secs(2));

        let authorization = adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: 4200,
                currency: "USD".to_string(),
                payer: "agent-9".to_string(),
                payee: "merchant.example".to_string(),
                reference: "req-acp-1".to_string(),
                governed: Some(GovernedPaymentContext {
                    intent_id: "intent-acp-1".to_string(),
                    intent_hash: "intent-hash-acp-1".to_string(),
                    purpose: "purchase governed commerce result".to_string(),
                    server_id: "commerce-srv".to_string(),
                    tool_name: "checkout".to_string(),
                    approval_token_id: Some("approval-acp-1".to_string()),
                }),
                commerce: Some(CommercePaymentContext {
                    seller: "merchant.example".to_string(),
                    shared_payment_token_id: "spt_live_123".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 5000,
                        currency: "USD".to_string(),
                    }),
                }),
            })
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer acp-secret"));
        assert!(request.contains("\"commerce\":{"));
        assert!(request.contains("\"seller\":\"merchant.example\""));
        assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_123\""));
        assert!(request.contains("\"maxAmount\":{"));
        assert!(request.contains("\"units\":5000"));

        assert_eq!(authorization.authorization_id, "acp_hold_123");
        assert!(!authorization.settled);
        assert_eq!(authorization.metadata["adapter"], "acp");
        assert_eq!(authorization.metadata["mode"], "shared_payment_token_hold");
        assert_eq!(authorization.metadata["provider"], "stripe");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn default_built_in_adapters_use_explicit_local_bookkeeping() {
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1");
        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1");

        for (result, expected_status) in [
            (
                x402.capture("auth", 1, "USD", "request"),
                RailSettlementStatus::Settled,
            ),
            (
                x402.release("auth", "request"),
                RailSettlementStatus::Released,
            ),
            (
                x402.refund("auth", 1, "USD", "request"),
                RailSettlementStatus::Refunded,
            ),
            (
                acp.capture("auth", 1, "USD", "request"),
                RailSettlementStatus::Settled,
            ),
            (
                acp.release("auth", "request"),
                RailSettlementStatus::Released,
            ),
            (
                acp.refund("auth", 1, "USD", "request"),
                RailSettlementStatus::Refunded,
            ),
        ] {
            let result = result.expect("default adapter must preserve local bookkeeping");
            assert_eq!(result.settlement_status, expected_status);
            assert!(result.is_local_bookkeeping());
            assert_eq!(result.metadata["acknowledgement"], "local_bookkeeping");
        }
    }

    #[test]
    fn strict_built_in_adapters_reject_missing_acknowledgement_endpoints() {
        let x402 = X402PaymentAdapter::new("http://127.0.0.1:1")
            .requiring_remote_settlement_acknowledgements();
        let acp = AcpPaymentAdapter::new("http://127.0.0.1:1")
            .requiring_remote_settlement_acknowledgements();

        for result in [
            x402.capture("auth", 1, "USD", "request"),
            x402.release("auth", "request"),
            x402.refund("auth", 1, "USD", "request"),
            acp.capture("auth", 1, "USD", "request"),
            acp.release("auth", "request"),
            acp.refund("auth", 1, "USD", "request"),
        ] {
            let error = result.expect_err("strict mode requires a remote endpoint");
            assert!(matches!(error, PaymentError::NotConfigured(_)));
            assert!(!error.outcome_unknown());
        }
    }

    #[test]
    fn configured_settlement_endpoint_returns_acknowledged_result() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "transactionId": "txn-captured",
                "settlementStatus": "settled",
                "metadata": { "network": "base" }
            }),
        );
        let adapter = X402PaymentAdapter::new(url).with_capture_path("/payments/capture");
        let result = adapter
            .capture("auth-1", 42, "USD", "req-capture")
            .expect("configured endpoint should acknowledge capture");
        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /payments/capture HTTP/1.1"));
        assert!(request.contains("\"authorizationId\":\"auth-1\""));
        assert!(request.contains("\"amountUnits\":42"));
        assert_eq!(result.transaction_id, "txn-captured");
        assert_eq!(result.settlement_status, RailSettlementStatus::Settled);
        assert!(!result.is_local_bookkeeping());
        assert_eq!(result.metadata["remote_acknowledged"], true);
        assert_eq!(result.metadata["acknowledgement"], "remote");
        handle.join().expect("server thread should exit cleanly");
    }

    fn spawn_once_json_server(
        status_code: u16,
        body: serde_json::Value,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should expose local address");
        let (request_tx, request_rx) = mpsc::channel();
        let body_text = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let mut header_end = None;
            let mut content_length = 0_usize;

            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server should configure read timeout");
            loop {
                let read = stream
                    .read(&mut chunk)
                    .expect("server should read request bytes");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);

                if header_end.is_none() {
                    header_end = find_header_end(&request);
                    if let Some(end) = header_end {
                        content_length = parse_content_length(&request[..end]);
                    }
                }

                if let Some(end) = header_end {
                    if request.len() >= end + content_length {
                        break;
                    }
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .expect("request should be sent to test");
            let response = format!(
                "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_text(status_code),
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("server should write response");
        });
        (format!("http://{address}"), request_rx, handle)
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn status_text(status_code: u16) -> &'static str {
        match status_code {
            200 => "OK",
            402 => "Payment Required",
            _ => "Error",
        }
    }
}
