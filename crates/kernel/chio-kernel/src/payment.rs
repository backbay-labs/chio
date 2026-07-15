use std::time::Duration;

use chio_core::{capability::scope::MonetaryAmount, receipt::economics::SettlementStatus};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Result of a payment authorization or settlement hold.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether the rail already considers the funds fully settled.
    pub settled: bool,
    /// Rail-specific metadata such as idempotency keys, quote IDs, or expiry.
    pub metadata: serde_json::Value,
}

/// Result of a capture, settlement, release, or refund operation.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentResult {
    /// Stable rail reference for the resulting financial operation.
    pub transaction_id: String,
    /// Richer rail-side settlement state, mapped onto the canonical receipt enum.
    pub settlement_status: RailSettlementStatus,
    /// Rail-specific metadata such as confirmations or idempotency keys.
    pub metadata: serde_json::Value,
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
            payment_reference: Some(authorization.authorization_id.clone()),
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

/// Trait for executing payments against an external rail.
pub trait PaymentAdapter: Send + Sync {
    /// Stable identifier of the rail this adapter drives, recorded on
    /// monetary dispatch intents so an operator can reconcile a monetary
    /// orphan against the correct rail without guessing.
    fn rail_id(&self) -> &str {
        "payment"
    }

    /// Authorize or prepay up to `amount_units` before the tool executes.
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
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
}

/// Thin prepaid HTTP payment bridge for x402-style per-request settlement.
///
/// The adapter intentionally stays narrow: it only performs one remote
/// authorization request and treats later capture/release/refund actions as
/// prepaid bookkeeping. This keeps the bridge small while still giving the
/// kernel a real external authorization hop before execution.
#[derive(Debug, Clone)]
pub struct X402PaymentAdapter {
    base_url: String,
    authorize_path: String,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

/// Thin shared-payment-token payment bridge for ACP-style commerce approvals.
///
/// This adapter performs one remote authorization call before execution and
/// then lets the kernel reconcile the local hold as capture/release/refund
/// bookkeeping after tool execution. This keeps ACP-specific logic adapter
/// scoped while still exercising a real external authorization hop.
#[derive(Debug, Clone)]
pub struct AcpPaymentAdapter {
    base_url: String,
    authorize_path: String,
    bearer_token: Option<String>,
    http: ureq::Agent,
}

impl X402PaymentAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            authorize_path: "/authorize".to_string(),
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
        Ok(PaymentAuthorization {
            authorization_id: response.authorization_id,
            settled: response.settled,
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
        _amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "capture",
                "reference": reference
            }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "release",
                "reference": reference
            }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({
                "adapter": "x402",
                "mode": "prepaid",
                "action": "refund",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }
}

impl PaymentAdapter for AcpPaymentAdapter {
    fn rail_id(&self) -> &str {
        "acp"
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
        Ok(PaymentAuthorization {
            authorization_id: response.authorization_id,
            settled: response.settled,
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
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "capture",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "release",
                "reference": reference
            }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({
                "adapter": "acp",
                "mode": "shared_payment_token_hold",
                "action": "refund",
                "amount_units": amount_units,
                "currency": currency,
                "reference": reference
            }),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402AuthorizeResponse {
    #[serde(
        alias = "authorization_id",
        alias = "transaction_id",
        alias = "transactionId"
    )]
    authorization_id: String,
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
    authorization_id: String,
    #[serde(default)]
    settled: bool,
    #[serde(default)]
    metadata: serde_json::Value,
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
        ureq::Error::Status(status, response) if (400..500).contains(&status) => {
            PaymentError::Declined(response_error_message(response))
        }
        ureq::Error::Status(_, response) => {
            PaymentError::Unavailable(response_error_message(response))
        }
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
            metadata: serde_json::json!({ "provider": "stripe" }),
        };
        let settled = PaymentAuthorization {
            authorization_id: "auth_456".to_string(),
            settled: true,
            metadata: serde_json::json!({ "provider": "x402" }),
        };

        let pending_receipt = ReceiptSettlement::from_authorization(&pending);
        let settled_receipt = ReceiptSettlement::from_authorization(&settled);

        assert_eq!(
            pending_receipt.payment_reference.as_deref(),
            Some("auth_123")
        );
        assert_eq!(pending_receipt.settlement_status, SettlementStatus::Pending);
        assert_eq!(
            settled_receipt.payment_reference.as_deref(),
            Some("auth_456")
        );
        assert_eq!(settled_receipt.settlement_status, SettlementStatus::Settled);
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
        assert_eq!(authorization.metadata["adapter"], "x402");
        assert_eq!(authorization.metadata["network"], "base");

        handle.join().expect("server thread should exit cleanly");
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
    fn x402_adapter_uses_custom_path_bearer_token_and_governed_payload() {
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_custom",
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
