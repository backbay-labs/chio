//! Shared payment authorization, settlement, and commerce context types.

use chio_core::{capability::scope::MonetaryAmount, receipt::economics::SettlementStatus};
use serde::{Deserialize, Serialize};

/// Result of a payment authorization or settlement hold.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether authorization created a reversible hold or completed final prepayment.
    pub state: PaymentAuthorizationState,
    /// Rail-specific metadata such as idempotency keys, quote IDs, or expiry.
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAuthorizationState {
    Held,
    PrepaidFinal,
}

impl PaymentAuthorizationState {
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::PrepaidFinal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRailMode {
    ReversibleHold,
    PrepaidFinal,
}

/// Single-use credential disposition after payment authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCredentialDisposition {
    NonePresent,
    RetainedAfterAuthorization,
    RetentionOutcomeUnknown,
}

/// Exact terminal rail action used to unwind a pre-dispatch authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreDispatchPaymentUnwindStatus {
    Released,
    Refunded,
}

/// Typed evidence embedded in a signed terminal receipt after a clean unwind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreDispatchPaymentUnwindEvidence {
    pub authorization_id: String,
    pub transaction_id: String,
    pub settlement_status: PreDispatchPaymentUnwindStatus,
    pub credential_disposition: PaymentCredentialDisposition,
}

impl PaymentRailMode {
    #[must_use]
    pub const fn accepts(self, state: PaymentAuthorizationState) -> bool {
        matches!(
            (self, state),
            (Self::ReversibleHold, PaymentAuthorizationState::Held)
                | (Self::PrepaidFinal, PaymentAuthorizationState::PrepaidFinal)
        )
    }
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

#[derive(Debug, Clone, PartialEq)]
pub enum RailSettlementState {
    NoAuthorization,
    Held {
        authorization_id: String,
    },
    Settled {
        authorization_id: String,
        result: PaymentResult,
    },
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
    pub settlement_destination_ref: String,
    pub payee_binding_digest: String,
    pub pre_action_authority_digest: String,
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
            settlement_status: if authorization.state.is_final() {
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
