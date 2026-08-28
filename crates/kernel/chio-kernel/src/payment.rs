use std::time::Duration;

use chio_core::{
    canonical_json_bytes, capability::scope::MonetaryAmount, receipt::economics::SettlementStatus,
    sha256,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod sim;
pub use sim::SimPaymentAdapter;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentJournalState {
    HoldPlaced,
    Authorized,
    Settling,
    Settled,
    Closed,
    ReconcileFailed,
}

impl PaymentJournalState {
    #[must_use]
    pub const fn can_advance_to(self, next: Self, rail_mode: PaymentRailMode) -> bool {
        matches!(
            (rail_mode, self, next),
            (
                PaymentRailMode::ReversibleHold,
                Self::HoldPlaced,
                Self::Authorized | Self::ReconcileFailed
            ) | (
                PaymentRailMode::ReversibleHold,
                Self::Authorized,
                Self::Settling | Self::ReconcileFailed
            ) | (
                PaymentRailMode::ReversibleHold,
                Self::Settling,
                Self::Settled | Self::ReconcileFailed
            ) | (
                // A reconciliation failure records that the rail rejected the
                // settlement intent, not that the intent is abandoned. The journal
                // retains its settle action and authorization, so a later pass can
                // re-drive the same intent to completion.
                PaymentRailMode::ReversibleHold,
                Self::ReconcileFailed,
                Self::Settled
            ) | (_, Self::Settled, Self::Closed)
                | (_, Self::HoldPlaced, Self::Closed)
                | (
                    PaymentRailMode::PrepaidFinal,
                    Self::HoldPlaced,
                    Self::Settled | Self::ReconcileFailed
                )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettleAction {
    Capture,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaymentJournalTransition {
    AuthorizationHeld {
        authorization_id: String,
    },
    PrepaymentSettled {
        authorization_id: String,
    },
    CancelBeforeAuthorization,
    BeginCapture {
        amount_units: u64,
    },
    BeginRelease {
        authority: PaymentReleaseAuthorityBinding,
    },
    SettlementCompleted {
        transaction_id: String,
    },
    ReconcileFailed,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentReleaseAuthorityKind {
    PreDispatchNoEffect,
    TransportNotAccepted,
    ContractualZeroCharge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReleaseAuthorityBinding {
    pub kind: PaymentReleaseAuthorityKind,
    pub operation_id: String,
    pub operation_version: u64,
    pub evidence_id: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentJournalRecord {
    pub operation_id: String,
    pub journal_version: u64,
    pub request_namespace_digest: String,
    pub request_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    pub rail: String,
    pub rail_mode: PaymentRailMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub amount_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_action: Option<PaymentSettleAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_amount_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_authority: Option<PaymentReleaseAuthorityBinding>,
    pub currency: String,
    pub state: PaymentJournalState,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid payment journal record: {0}")]
pub struct PaymentJournalError(String);

impl PaymentJournalRecord {
    #[must_use]
    pub fn matches_hold_replay(&self, proposed: &Self) -> bool {
        if proposed.state != PaymentJournalState::HoldPlaced
            || proposed.journal_version != 1
            || self.validate().is_err()
            || proposed.validate().is_err()
        {
            return false;
        }
        self.operation_id == proposed.operation_id
            && self.request_namespace_digest == proposed.request_namespace_digest
            && self.request_id == proposed.request_id
            && self.capability_id == proposed.capability_id
            && self.grant_index == proposed.grant_index
            && self.hold_id == proposed.hold_id
            && self.rail == proposed.rail
            && self.rail_mode == proposed.rail_mode
            && self.amount_units == proposed.amount_units
            && self.currency == proposed.currency
    }

    pub fn validate(&self) -> Result<(), PaymentJournalError> {
        validate_payment_text("operation_id", &self.operation_id)?;
        if self.journal_version == 0 || self.journal_version > ((1_u64 << 53) - 1) {
            return Err(PaymentJournalError(
                "journal_version must be a positive I-JSON safe integer".to_owned(),
            ));
        }
        validate_payment_digest("request_namespace_digest", &self.request_namespace_digest)?;
        validate_payment_text("request_id", &self.request_id)?;
        validate_payment_text("capability_id", &self.capability_id)?;
        let hold_id = self
            .hold_id
            .as_deref()
            .ok_or_else(|| PaymentJournalError("hold_id is required".to_owned()))?;
        validate_payment_text("hold_id", hold_id)?;
        validate_payment_text("rail", &self.rail)?;
        if self.rail == "unspecified" {
            return Err(PaymentJournalError(
                "rail must identify a recoverable payment adapter".to_owned(),
            ));
        }
        if self.amount_units == 0 || self.amount_units > ((1_u64 << 53) - 1) {
            return Err(PaymentJournalError(
                "amount_units must be a positive I-JSON safe integer".to_owned(),
            ));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(PaymentJournalError(
                "currency must be a three-letter uppercase code".to_owned(),
            ));
        }
        if self.created_at_unix_ms == 0 || self.created_at_unix_ms > ((1_u64 << 53) - 1) {
            return Err(PaymentJournalError(
                "created_at_unix_ms must be a positive I-JSON safe integer".to_owned(),
            ));
        }
        self.authorization_id
            .as_deref()
            .map(|value| validate_payment_text("authorization_id", value))
            .transpose()?;
        self.transaction_id
            .as_deref()
            .map(|value| validate_payment_text("transaction_id", value))
            .transpose()?;
        match self.state {
            PaymentJournalState::HoldPlaced => {
                if self.journal_version != 1 {
                    return Err(PaymentJournalError(
                        "hold_placed must be journal version 1".to_owned(),
                    ));
                }
                self.validate_empty_settlement("hold_placed")?;
            }
            PaymentJournalState::Authorized => {
                if self.rail_mode != PaymentRailMode::ReversibleHold {
                    return Err(PaymentJournalError(
                        "only a reversible rail can retain an authorized hold".to_owned(),
                    ));
                }
                self.require_authorization_id("authorized")?;
                if self.transaction_id.is_some()
                    || self.settle_action.is_some()
                    || self.settle_amount_units.is_some()
                    || self.release_authority.is_some()
                {
                    return Err(PaymentJournalError(
                        "authorized state cannot contain a terminal settle result".to_owned(),
                    ));
                }
            }
            PaymentJournalState::Settling => {
                if self.rail_mode != PaymentRailMode::ReversibleHold {
                    return Err(PaymentJournalError(
                        "only a reversible rail can enter settling".to_owned(),
                    ));
                }
                self.require_authorization_id("settling")?;
                if self.transaction_id.is_some() {
                    return Err(PaymentJournalError(
                        "settling cannot contain a terminal transaction_id".to_owned(),
                    ));
                }
                self.validate_settle_intent()?;
            }
            PaymentJournalState::Closed if self.authorization_id.is_none() => {
                if self.journal_version != 2 {
                    return Err(PaymentJournalError(
                        "pre-authorization cancellation must be journal version 2".to_owned(),
                    ));
                }
                self.validate_empty_settlement("pre-authorization cancellation")?;
            }
            PaymentJournalState::Settled | PaymentJournalState::Closed => {
                self.require_authorization_id("terminal")?;
                match self.rail_mode {
                    PaymentRailMode::PrepaidFinal => {
                        if self.transaction_id.is_some()
                            || self.settle_action.is_some()
                            || self.settle_amount_units.is_some()
                            || self.release_authority.is_some()
                        {
                            return Err(PaymentJournalError(
                                "final prepayment cannot contain synthetic settlement fields"
                                    .to_owned(),
                            ));
                        }
                    }
                    PaymentRailMode::ReversibleHold => {
                        if self.transaction_id.is_none() {
                            return Err(PaymentJournalError(
                                "a terminal reversible hold requires transaction_id".to_owned(),
                            ));
                        }
                        self.validate_settle_intent()?;
                    }
                }
            }
            PaymentJournalState::ReconcileFailed => self.validate_reconcile_shape()?,
        }
        Ok(())
    }

    pub fn apply_transition(
        &self,
        transition: &PaymentJournalTransition,
    ) -> Result<Self, PaymentJournalError> {
        self.validate()?;
        let mut next = self.clone();
        next.journal_version = self
            .journal_version
            .checked_add(1)
            .ok_or_else(|| PaymentJournalError("journal_version overflowed".to_owned()))?;
        let next_state = match transition {
            PaymentJournalTransition::AuthorizationHeld { authorization_id } => {
                if self.state != PaymentJournalState::HoldPlaced
                    || self.rail_mode != PaymentRailMode::ReversibleHold
                {
                    return Err(PaymentJournalError(
                        "held authorization requires a reversible hold_placed journal".to_owned(),
                    ));
                }
                next.authorization_id = Some(authorization_id.clone());
                PaymentJournalState::Authorized
            }
            PaymentJournalTransition::PrepaymentSettled { authorization_id } => {
                if self.state != PaymentJournalState::HoldPlaced
                    || self.rail_mode != PaymentRailMode::PrepaidFinal
                {
                    return Err(PaymentJournalError(
                        "final prepayment requires a prepaid hold_placed journal".to_owned(),
                    ));
                }
                next.authorization_id = Some(authorization_id.clone());
                PaymentJournalState::Settled
            }
            PaymentJournalTransition::CancelBeforeAuthorization => {
                if self.state != PaymentJournalState::HoldPlaced {
                    return Err(PaymentJournalError(
                        "pre-authorization cancellation requires a hold_placed journal".to_owned(),
                    ));
                }
                PaymentJournalState::Closed
            }
            PaymentJournalTransition::BeginCapture { amount_units } => {
                if self.state != PaymentJournalState::Authorized {
                    return Err(PaymentJournalError(
                        "capture intent requires an authorized journal".to_owned(),
                    ));
                }
                next.settle_action = Some(PaymentSettleAction::Capture);
                next.settle_amount_units = Some(*amount_units);
                PaymentJournalState::Settling
            }
            PaymentJournalTransition::BeginRelease { authority } => {
                if self.state != PaymentJournalState::Authorized {
                    return Err(PaymentJournalError(
                        "release intent requires an authorized journal".to_owned(),
                    ));
                }
                next.settle_action = Some(PaymentSettleAction::Release);
                next.release_authority = Some(authority.clone());
                PaymentJournalState::Settling
            }
            PaymentJournalTransition::SettlementCompleted { transaction_id } => {
                if !matches!(
                    self.state,
                    PaymentJournalState::Settling | PaymentJournalState::ReconcileFailed
                ) {
                    return Err(PaymentJournalError(
                        "settlement completion requires a settling or reconcile_failed journal"
                            .to_owned(),
                    ));
                }
                next.transaction_id = Some(transaction_id.clone());
                PaymentJournalState::Settled
            }
            PaymentJournalTransition::ReconcileFailed => {
                if matches!(
                    self.state,
                    PaymentJournalState::Settled
                        | PaymentJournalState::Closed
                        | PaymentJournalState::ReconcileFailed
                ) {
                    return Err(PaymentJournalError(
                        "terminal payment journal cannot enter reconciliation failure".to_owned(),
                    ));
                }
                PaymentJournalState::ReconcileFailed
            }
            PaymentJournalTransition::Close => {
                if self.state != PaymentJournalState::Settled {
                    return Err(PaymentJournalError(
                        "only a settled payment journal can close".to_owned(),
                    ));
                }
                PaymentJournalState::Closed
            }
        };
        if !self.state.can_advance_to(next_state, self.rail_mode) {
            return Err(PaymentJournalError(
                "payment journal transition is not permitted".to_owned(),
            ));
        }
        next.state = next_state;
        next.validate()?;
        Ok(next)
    }

    fn require_authorization_id(&self, state: &str) -> Result<(), PaymentJournalError> {
        if self.authorization_id.is_none() {
            return Err(PaymentJournalError(format!(
                "{state} state requires authorization_id"
            )));
        }
        Ok(())
    }

    fn validate_empty_settlement(&self, state: &str) -> Result<(), PaymentJournalError> {
        if self.authorization_id.is_some()
            || self.transaction_id.is_some()
            || self.settle_action.is_some()
            || self.settle_amount_units.is_some()
            || self.release_authority.is_some()
        {
            return Err(PaymentJournalError(format!(
                "{state} cannot contain rail results or a settle intent"
            )));
        }
        Ok(())
    }

    fn validate_settle_intent(&self) -> Result<(), PaymentJournalError> {
        match self.settle_action {
            Some(PaymentSettleAction::Capture) => {
                let amount = self.settle_amount_units.ok_or_else(|| {
                    PaymentJournalError("capture requires settle_amount_units".to_owned())
                })?;
                if amount == 0 || amount > self.amount_units {
                    return Err(PaymentJournalError(
                        "settle_amount_units must be within the authorized amount".to_owned(),
                    ));
                }
                if self.release_authority.is_some() {
                    return Err(PaymentJournalError(
                        "capture cannot contain release authority".to_owned(),
                    ));
                }
            }
            Some(PaymentSettleAction::Release) => {
                if self.settle_amount_units.is_some() {
                    return Err(PaymentJournalError(
                        "release cannot contain settle_amount_units".to_owned(),
                    ));
                }
                self.release_authority
                    .as_ref()
                    .ok_or_else(|| {
                        PaymentJournalError("release requires verified authority".to_owned())
                    })?
                    .validate_for(&self.operation_id)?;
            }
            None => {
                return Err(PaymentJournalError(
                    "settling requires a committed action".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_reconcile_shape(&self) -> Result<(), PaymentJournalError> {
        if self.transaction_id.is_some() && self.authorization_id.is_none() {
            return Err(PaymentJournalError(
                "reconcile_failed transaction requires authorization_id".to_owned(),
            ));
        }
        match self.settle_action {
            Some(_) => {
                if self.rail_mode != PaymentRailMode::ReversibleHold {
                    return Err(PaymentJournalError(
                        "final prepayment cannot contain a settle intent".to_owned(),
                    ));
                }
                self.require_authorization_id("reconcile_failed")?;
                self.validate_settle_intent()
            }
            None => {
                if self.settle_amount_units.is_some() || self.release_authority.is_some() {
                    return Err(PaymentJournalError(
                        "reconcile_failed contains an incomplete settle intent".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

impl PaymentReleaseAuthorityBinding {
    fn validate_for(&self, operation_id: &str) -> Result<(), PaymentJournalError> {
        if self.operation_id != operation_id {
            return Err(PaymentJournalError(
                "release authority is bound to another operation".to_owned(),
            ));
        }
        if self.operation_version == 0 || self.operation_version > ((1_u64 << 53) - 1) {
            return Err(PaymentJournalError(
                "release authority version must be a positive I-JSON safe integer".to_owned(),
            ));
        }
        validate_payment_text("release evidence_id", &self.evidence_id)?;
        validate_payment_digest("release evidence_digest", &self.evidence_digest)
    }
}

fn validate_payment_text(field: &str, value: &str) -> Result<(), PaymentJournalError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(PaymentJournalError(format!(
            "{field} must contain 1 to 512 non-control bytes"
        )));
    }
    Ok(())
}

fn validate_payment_digest(field: &str, value: &str) -> Result<(), PaymentJournalError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PaymentJournalError(format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
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

/// Trait for executing payments against an external rail.
pub trait PaymentAdapter: Send + Sync {
    fn rail_id(&self) -> &'static str {
        "unspecified"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        None
    }

    /// Authorize or prepay up to `amount_units` before the tool executes.
    ///
    /// Implementations must be idempotent by `request.reference`: repeating the
    /// same request returns the same authorization and creates at most one
    /// rail-side hold or prepayment.
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    ///
    /// Implementations must be idempotent by `(authorization_id, reference)`.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
    ///
    /// Implementations must be idempotent by `(authorization_id, reference)`.
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

    /// Return the side-effect-free rail state for a durable reference.
    ///
    /// This query must remain answerable when `authorization_id` is absent so
    /// recovery can close the crash window after authorization but before the
    /// rail-assigned identifier reaches the local journal.
    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let _ = (reference, authorization_id);
        Err(PaymentError::Unavailable(
            "settlement_state query is unsupported by this payment adapter".to_owned(),
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

/// Shared-payment-token payment bridge for ACP-style commerce approvals.
///
/// Every monetary transition is confirmed by the external facilitator. Each
/// response must echo the digest of the exact operation binding, and recovery
/// queries use the same durable reference as the journaled request.
#[derive(Debug, Clone)]
pub struct AcpPaymentAdapter {
    base_url: String,
    authorize_path: String,
    capture_path: String,
    release_path: String,
    refund_path: String,
    settlement_state_path: String,
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
            capture_path: "/capture".to_string(),
            release_path: "/release".to_string(),
            refund_path: "/refund".to_string(),
            settlement_state_path: "/settlement-state".to_string(),
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
        self.capture_path = normalize_http_path(&path.into());
        self
    }

    #[must_use]
    pub fn with_release_path(mut self, path: impl Into<String>) -> Self {
        self.release_path = normalize_http_path(&path.into());
        self
    }

    #[must_use]
    pub fn with_refund_path(mut self, path: impl Into<String>) -> Self {
        self.refund_path = normalize_http_path(&path.into());
        self
    }

    #[must_use]
    pub fn with_settlement_state_path(mut self, path: impl Into<String>) -> Self {
        self.settlement_state_path = normalize_http_path(&path.into());
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
    fn rail_id(&self) -> &'static str {
        "x402"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
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
        let state = if response.settled {
            PaymentAuthorizationState::PrepaidFinal
        } else {
            PaymentAuthorizationState::Held
        };
        if !PaymentRailMode::PrepaidFinal.accepts(state) {
            return Err(PaymentError::RailError(
                "x402 authorization did not complete final prepayment".to_owned(),
            ));
        }
        Ok(PaymentAuthorization {
            authorization_id: response.authorization_id,
            state,
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
    fn rail_id(&self) -> &'static str {
        "acp"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let request_digest = acp_request_digest(request)?;
        let envelope = AcpAuthorizeRequest {
            schema: ACP_AUTHORIZE_REQUEST_SCHEMA,
            request_digest: &request_digest,
            request,
        };
        let response: AcpAuthorizeResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.authorize_path,
            &envelope,
        )?;
        response.validate(&request_digest, request)?;
        Ok(PaymentAuthorization {
            authorization_id: response.authorization_id,
            state: PaymentAuthorizationState::Held,
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
        let binding = AcpTerminalOperationBinding {
            authorization_id,
            transaction_id: None,
            amount_units: Some(amount_units),
            currency: Some(currency),
            reference,
        };
        self.execute_terminal_operation(AcpTerminalOperation::Capture, &self.capture_path, &binding)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let binding = AcpTerminalOperationBinding {
            authorization_id,
            transaction_id: None,
            amount_units: None,
            currency: None,
            reference,
        };
        self.execute_terminal_operation(AcpTerminalOperation::Release, &self.release_path, &binding)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let binding = AcpTerminalOperationBinding {
            authorization_id: "",
            transaction_id: Some(transaction_id),
            amount_units: Some(amount_units),
            currency: Some(currency),
            reference,
        };
        self.execute_terminal_operation(AcpTerminalOperation::Refund, &self.refund_path, &binding)
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        let binding = AcpSettlementStateBinding {
            reference,
            authorization_id,
        };
        let request_digest = acp_request_digest(&binding)?;
        let response: AcpSettlementStateResponse = get_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            &self.settlement_state_path,
            &[
                ("schema", ACP_SETTLEMENT_STATE_REQUEST_SCHEMA),
                ("requestDigest", request_digest.as_str()),
                ("reference", reference),
                ("authorizationId", authorization_id.unwrap_or_default()),
            ],
        )?;
        response.into_state(&request_digest, &binding)
    }
}

impl AcpPaymentAdapter {
    fn execute_terminal_operation(
        &self,
        operation: AcpTerminalOperation,
        path: &str,
        binding: &AcpTerminalOperationBinding<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        binding.validate(operation)?;
        let request_digest = acp_request_digest(binding)?;
        let request = AcpTerminalOperationRequest {
            schema: ACP_TERMINAL_OPERATION_REQUEST_SCHEMA,
            operation,
            request_digest: &request_digest,
            binding,
        };
        let response: AcpTerminalOperationResponse = post_json(
            &self.http,
            &self.base_url,
            self.bearer_token.as_deref(),
            path,
            &request,
        )?;
        response.into_result(operation, &request_digest, binding)
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

const ACP_AUTHORIZE_REQUEST_SCHEMA: &str = "chio.payment.acp-authorize-request.v1";
const ACP_AUTHORIZE_RESPONSE_SCHEMA: &str = "chio.payment.acp-authorize-response.v1";
const ACP_TERMINAL_OPERATION_REQUEST_SCHEMA: &str =
    "chio.payment.acp-terminal-operation-request.v1";
const ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA: &str =
    "chio.payment.acp-terminal-operation-response.v1";
const ACP_SETTLEMENT_STATE_REQUEST_SCHEMA: &str = "chio.payment.acp-settlement-state-request.v1";
const ACP_SETTLEMENT_STATE_RESPONSE_SCHEMA: &str = "chio.payment.acp-settlement-state-response.v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcpAuthorizeRequest<'a> {
    schema: &'static str,
    request_digest: &'a str,
    request: &'a PaymentAuthorizeRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcpAuthorizeResponse {
    schema: String,
    request_digest: String,
    reference: String,
    authorization_id: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

impl AcpAuthorizeResponse {
    fn validate(
        &self,
        request_digest: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<(), PaymentError> {
        if self.schema != ACP_AUTHORIZE_RESPONSE_SCHEMA
            || self.request_digest != request_digest
            || self.reference != request.reference
            || self.authorization_id.is_empty()
        {
            return Err(PaymentError::RailError(
                "ACP authorization response binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcpTerminalOperation {
    Capture,
    Release,
    Refund,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcpTerminalOperationBinding<'a> {
    authorization_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_units: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<&'a str>,
    reference: &'a str,
}

impl AcpTerminalOperationBinding<'_> {
    fn validate(&self, operation: AcpTerminalOperation) -> Result<(), PaymentError> {
        let base_valid = !self.reference.is_empty()
            && !self.reference.chars().any(char::is_control)
            && self.reference.len() <= 512;
        let shape_valid = match operation {
            AcpTerminalOperation::Capture => {
                !self.authorization_id.is_empty()
                    && self.transaction_id.is_none()
                    && self.amount_units.is_some_and(|amount| amount > 0)
                    && self.currency.is_some_and(|currency| !currency.is_empty())
            }
            AcpTerminalOperation::Release => {
                !self.authorization_id.is_empty()
                    && self.transaction_id.is_none()
                    && self.amount_units.is_none()
                    && self.currency.is_none()
            }
            AcpTerminalOperation::Refund => {
                self.authorization_id.is_empty()
                    && self
                        .transaction_id
                        .is_some_and(|transaction| !transaction.is_empty())
                    && self.amount_units.is_some_and(|amount| amount > 0)
                    && self.currency.is_some_and(|currency| !currency.is_empty())
            }
        };
        if !base_valid || !shape_valid {
            return Err(PaymentError::RailError(
                "ACP terminal operation request is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcpTerminalOperationRequest<'a> {
    schema: &'static str,
    operation: AcpTerminalOperation,
    request_digest: &'a str,
    binding: &'a AcpTerminalOperationBinding<'a>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcpTerminalOperationResponse {
    schema: String,
    operation: AcpTerminalOperation,
    request_digest: String,
    reference: String,
    #[serde(default)]
    authorization_id: Option<String>,
    transaction_id: String,
    settlement_status: RailSettlementStatus,
    #[serde(default)]
    metadata: serde_json::Value,
}

impl AcpTerminalOperationResponse {
    fn into_result(
        self,
        operation: AcpTerminalOperation,
        request_digest: &str,
        binding: &AcpTerminalOperationBinding<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let expected_status = match operation {
            AcpTerminalOperation::Capture => RailSettlementStatus::Settled,
            AcpTerminalOperation::Release => RailSettlementStatus::Released,
            AcpTerminalOperation::Refund => RailSettlementStatus::Refunded,
        };
        let authorization_matches = match operation {
            AcpTerminalOperation::Refund => self.authorization_id.is_none(),
            AcpTerminalOperation::Capture | AcpTerminalOperation::Release => {
                self.authorization_id.as_deref() == Some(binding.authorization_id)
            }
        };
        if self.schema != ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA
            || self.operation != operation
            || self.request_digest != request_digest
            || self.reference != binding.reference
            || self.transaction_id.is_empty()
            || self.settlement_status != expected_status
            || !authorization_matches
        {
            return Err(PaymentError::RailError(
                "ACP terminal operation response binding is invalid".to_owned(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: self.transaction_id,
            settlement_status: self.settlement_status,
            metadata: merge_json_values(
                Some(self.metadata),
                Some(serde_json::json!({
                    "adapter": "acp",
                    "mode": "shared_payment_token_hold",
                    "operation": operation,
                    "requestDigest": request_digest
                })),
            )
            .unwrap_or_else(|| serde_json::json!({})),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcpSettlementStateBinding<'a> {
    reference: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcpSettlementStateKind {
    NoAuthorization,
    Held,
    Settled,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcpSettlementStateResponse {
    schema: String,
    request_digest: String,
    reference: String,
    state: AcpSettlementStateKind,
    #[serde(default)]
    authorization_id: Option<String>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(default)]
    settlement_status: Option<RailSettlementStatus>,
    #[serde(default)]
    metadata: serde_json::Value,
}

impl AcpSettlementStateResponse {
    fn into_state(
        self,
        request_digest: &str,
        binding: &AcpSettlementStateBinding<'_>,
    ) -> Result<RailSettlementState, PaymentError> {
        if self.schema != ACP_SETTLEMENT_STATE_RESPONSE_SCHEMA
            || self.request_digest != request_digest
            || self.reference != binding.reference
            || binding
                .authorization_id
                .is_some_and(|expected| self.authorization_id.as_deref() != Some(expected))
        {
            return Err(PaymentError::RailError(
                "ACP settlement-state response binding is invalid".to_owned(),
            ));
        }
        match self.state {
            AcpSettlementStateKind::NoAuthorization
                if self.authorization_id.is_none()
                    && self.transaction_id.is_none()
                    && self.settlement_status.is_none() =>
            {
                Ok(RailSettlementState::NoAuthorization)
            }
            AcpSettlementStateKind::Held
                if self.transaction_id.is_none() && self.settlement_status.is_none() =>
            {
                let authorization_id = self.authorization_id.ok_or_else(|| {
                    PaymentError::RailError(
                        "ACP held state omits the authorization identifier".to_owned(),
                    )
                })?;
                Ok(RailSettlementState::Held { authorization_id })
            }
            AcpSettlementStateKind::Settled => {
                let authorization_id = self.authorization_id.ok_or_else(|| {
                    PaymentError::RailError(
                        "ACP settled state omits the authorization identifier".to_owned(),
                    )
                })?;
                let transaction_id = self.transaction_id.ok_or_else(|| {
                    PaymentError::RailError(
                        "ACP settled state omits the transaction identifier".to_owned(),
                    )
                })?;
                let settlement_status = self.settlement_status.ok_or_else(|| {
                    PaymentError::RailError(
                        "ACP settled state omits the settlement status".to_owned(),
                    )
                })?;
                if !matches!(
                    settlement_status,
                    RailSettlementStatus::Settled
                        | RailSettlementStatus::Released
                        | RailSettlementStatus::Refunded
                ) {
                    return Err(PaymentError::RailError(
                        "ACP settled state is not terminal".to_owned(),
                    ));
                }
                Ok(RailSettlementState::Settled {
                    authorization_id,
                    result: PaymentResult {
                        transaction_id,
                        settlement_status,
                        metadata: self.metadata,
                    },
                })
            }
            _ => Err(PaymentError::RailError(
                "ACP settlement-state response shape is invalid".to_owned(),
            )),
        }
    }
}

fn acp_request_digest<T: Serialize>(value: &T) -> Result<String, PaymentError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        PaymentError::RailError(format!(
            "failed to canonicalize ACP request binding: {error}"
        ))
    })?;
    Ok(sha256(&canonical).to_hex())
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

fn get_json<T: DeserializeOwned>(
    http: &ureq::Agent,
    base_url: &str,
    bearer_token: Option<&str>,
    path: &str,
    query: &[(&str, &str)],
) -> Result<T, PaymentError> {
    let url = format!("{base_url}{path}");
    let mut request = http.get(&url);
    for (name, value) in query {
        request = request.query(name, value);
    }
    if let Some(token) = bearer_token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.call() {
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

    fn hold_placed_payment_journal() -> PaymentJournalRecord {
        PaymentJournalRecord {
            operation_id: "op-1".to_owned(),
            journal_version: 1,
            request_namespace_digest:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            request_id: "request-1".to_owned(),
            capability_id: "capability-1".to_owned(),
            grant_index: 0,
            hold_id: Some("hold-1".to_owned()),
            rail: "acp".to_owned(),
            rail_mode: PaymentRailMode::ReversibleHold,
            authorization_id: None,
            transaction_id: None,
            amount_units: 125,
            settle_action: None,
            settle_amount_units: None,
            release_authority: None,
            currency: "USD".to_owned(),
            state: PaymentJournalState::HoldPlaced,
            created_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn payment_journal_accepts_durable_hold_placed_record() {
        let record = hold_placed_payment_journal();

        assert_eq!(record.validate(), Ok(()));
    }

    #[test]
    fn payment_journal_requires_reversible_mode_for_authorized_hold() {
        let mut record = hold_placed_payment_journal();
        record.state = PaymentJournalState::Authorized;
        record.rail_mode = PaymentRailMode::PrepaidFinal;
        record.authorization_id = Some("authorization-1".to_owned());

        assert!(record.validate().is_err());
    }

    #[test]
    fn payment_journal_requires_committed_action_while_settling() {
        let mut record = hold_placed_payment_journal();
        record.state = PaymentJournalState::Settling;
        record.authorization_id = Some("authorization-1".to_owned());

        assert!(record.validate().is_err());
    }

    #[test]
    fn payment_journal_rejects_cross_operation_release_authority() {
        let mut record = hold_placed_payment_journal();
        record.state = PaymentJournalState::Settling;
        record.authorization_id = Some("authorization-1".to_owned());
        record.settle_action = Some(PaymentSettleAction::Release);
        record.release_authority = Some(PaymentReleaseAuthorityBinding {
            kind: PaymentReleaseAuthorityKind::PreDispatchNoEffect,
            operation_id: "another-operation".to_owned(),
            operation_version: 2,
            evidence_id: "release-evidence-1".to_owned(),
            evidence_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        });

        assert!(record.validate().is_err());
    }

    #[test]
    fn payment_journal_rejects_synthetic_capture_for_final_prepayment() {
        let mut record = hold_placed_payment_journal();
        record.state = PaymentJournalState::Settled;
        record.rail = "x402".to_owned();
        record.rail_mode = PaymentRailMode::PrepaidFinal;
        record.authorization_id = Some("authorization-1".to_owned());
        record.transaction_id = Some("transaction-1".to_owned());
        record.settle_action = Some(PaymentSettleAction::Capture);
        record.settle_amount_units = Some(125);

        assert!(record.validate().is_err());
    }

    #[test]
    fn payment_journal_generic_advancement_cannot_skip_terminal_evidence() {
        assert!(PaymentJournalState::HoldPlaced.can_advance_to(
            PaymentJournalState::Authorized,
            PaymentRailMode::ReversibleHold
        ));
        assert!(PaymentJournalState::HoldPlaced
            .can_advance_to(PaymentJournalState::Settled, PaymentRailMode::PrepaidFinal));
        assert!(PaymentJournalState::HoldPlaced
            .can_advance_to(PaymentJournalState::Closed, PaymentRailMode::ReversibleHold));
        assert!(!PaymentJournalState::Authorized
            .can_advance_to(PaymentJournalState::Closed, PaymentRailMode::ReversibleHold));
    }

    #[test]
    fn payment_journal_reconcile_failure_replays_its_settlement_intent() {
        let settling = hold_placed_payment_journal()
            .apply_transition(&PaymentJournalTransition::AuthorizationHeld {
                authorization_id: "authorization-1".to_owned(),
            })
            .expect("record held authorization")
            .apply_transition(&PaymentJournalTransition::BeginCapture { amount_units: 75 })
            .expect("record capture intent");
        let failed = settling
            .apply_transition(&PaymentJournalTransition::ReconcileFailed)
            .expect("record reconciliation failure");

        // The intent survives the seal, so a later pass has everything it needs.
        assert_eq!(failed.state, PaymentJournalState::ReconcileFailed);
        assert_eq!(failed.settle_action, Some(PaymentSettleAction::Capture));
        assert_eq!(failed.settle_amount_units, Some(75));
        assert_eq!(failed.authorization_id.as_deref(), Some("authorization-1"));
        assert_eq!(failed.validate(), Ok(()));

        let settled = failed
            .apply_transition(&PaymentJournalTransition::SettlementCompleted {
                transaction_id: "transaction-1".to_owned(),
            })
            .expect("retry a reconcile_failed settlement");

        assert_eq!(settled.state, PaymentJournalState::Settled);
        assert_eq!(settled.transaction_id.as_deref(), Some("transaction-1"));
        assert_eq!(settled.validate(), Ok(()));
    }

    #[test]
    fn payment_journal_reconcile_failure_stays_sealed_for_final_prepayment() {
        let mut record = hold_placed_payment_journal();
        record.rail = "x402".to_owned();
        record.rail_mode = PaymentRailMode::PrepaidFinal;
        let failed = record
            .apply_transition(&PaymentJournalTransition::ReconcileFailed)
            .expect("record reconciliation failure");

        // A final prepayment carries no replayable settle intent, so the seal holds.
        assert!(!PaymentJournalState::ReconcileFailed
            .can_advance_to(PaymentJournalState::Settled, PaymentRailMode::PrepaidFinal));
        assert!(failed
            .apply_transition(&PaymentJournalTransition::SettlementCompleted {
                transaction_id: "transaction-1".to_owned(),
            })
            .is_err());
    }

    #[test]
    fn payment_journal_cancels_before_authorization_without_settlement_fields() {
        let cancelled = hold_placed_payment_journal()
            .apply_transition(&PaymentJournalTransition::CancelBeforeAuthorization)
            .expect("cancel unstarted payment");

        assert_eq!(cancelled.journal_version, 2);
        assert_eq!(cancelled.state, PaymentJournalState::Closed);
        assert!(cancelled.authorization_id.is_none());
        assert!(cancelled.transaction_id.is_none());
        assert!(cancelled.settle_action.is_none());
        assert_eq!(cancelled.validate(), Ok(()));
        assert!(cancelled
            .apply_transition(&PaymentJournalTransition::CancelBeforeAuthorization)
            .is_err());
    }

    #[test]
    fn payment_journal_capture_transition_is_monotonic_and_replayable() {
        let authorized = hold_placed_payment_journal()
            .apply_transition(&PaymentJournalTransition::AuthorizationHeld {
                authorization_id: "authorization-1".to_owned(),
            })
            .expect("record held authorization");
        let settling = authorized
            .apply_transition(&PaymentJournalTransition::BeginCapture { amount_units: 75 })
            .expect("record capture intent");
        let settled = settling
            .apply_transition(&PaymentJournalTransition::SettlementCompleted {
                transaction_id: "transaction-1".to_owned(),
            })
            .expect("record settlement result");

        assert_eq!(authorized.journal_version, 2);
        assert_eq!(authorized.state, PaymentJournalState::Authorized);
        assert_eq!(settling.journal_version, 3);
        assert_eq!(settling.settle_action, Some(PaymentSettleAction::Capture));
        assert_eq!(settling.settle_amount_units, Some(75));
        assert_eq!(settled.journal_version, 4);
        assert_eq!(settled.state, PaymentJournalState::Settled);
        assert_eq!(settled.transaction_id.as_deref(), Some("transaction-1"));
    }

    #[test]
    fn payment_journal_final_prepayment_skips_releasable_states() {
        let mut record = hold_placed_payment_journal();
        record.rail = "x402".to_owned();
        record.rail_mode = PaymentRailMode::PrepaidFinal;

        let settled = record
            .apply_transition(&PaymentJournalTransition::PrepaymentSettled {
                authorization_id: "prepayment-1".to_owned(),
            })
            .expect("record final prepayment");

        assert_eq!(settled.state, PaymentJournalState::Settled);
        assert_eq!(settled.journal_version, 2);
        assert!(settled.transaction_id.is_none());
        assert!(settled
            .apply_transition(&PaymentJournalTransition::BeginCapture { amount_units: 125 })
            .is_err());
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
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "provider": "stripe" }),
        };
        let settled = PaymentAuthorization {
            authorization_id: "auth_456".to_string(),
            state: PaymentAuthorizationState::PrepaidFinal,
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
        assert_eq!(authorization.state, PaymentAuthorizationState::PrepaidFinal);
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
        let payment_request = PaymentAuthorizeRequest {
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
                settlement_destination_ref: "acct:merchant-primary".to_string(),
                payee_binding_digest: "payee-binding-acp-1".to_string(),
                pre_action_authority_digest: "approval-digest-acp-1".to_string(),
                shared_payment_token_id: "spt_live_123".to_string(),
                max_amount: Some(MonetaryAmount {
                    units: 5000,
                    currency: "USD".to_string(),
                }),
            }),
        };
        let request_digest = acp_request_digest(&payment_request)
            .expect("ACP authorization request should canonicalize");
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_AUTHORIZE_RESPONSE_SCHEMA,
                "requestDigest": request_digest,
                "reference": "req-acp-1",
                "authorizationId": "acp_hold_123",
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
            .authorize(&payment_request)
            .expect("authorization should succeed");

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer acp-secret"));
        assert!(request.contains(ACP_AUTHORIZE_REQUEST_SCHEMA));
        assert!(request.contains("\"request\":{"));
        assert!(request.contains("\"commerce\":{"));
        assert!(request.contains("\"seller\":\"merchant.example\""));
        assert!(request.contains("\"settlementDestinationRef\":\"acct:merchant-primary\""));
        assert!(request.contains("\"payeeBindingDigest\":\"payee-binding-acp-1\""));
        assert!(request.contains("\"preActionAuthorityDigest\":\"approval-digest-acp-1\""));
        assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_123\""));
        assert!(request.contains("\"maxAmount\":{"));
        assert!(request.contains("\"units\":5000"));

        assert_eq!(authorization.authorization_id, "acp_hold_123");
        assert_eq!(authorization.state, PaymentAuthorizationState::Held);
        assert_eq!(authorization.metadata["adapter"], "acp");
        assert_eq!(authorization.metadata["mode"], "shared_payment_token_hold");
        assert_eq!(authorization.metadata["provider"], "stripe");

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn acp_adapter_externalizes_capture_release_and_refund() {
        let capture_binding = AcpTerminalOperationBinding {
            authorization_id: "auth-1",
            transaction_id: None,
            amount_units: Some(700),
            currency: Some("USD"),
            reference: "capture-1",
        };
        let capture_digest = acp_request_digest(&capture_binding)
            .expect("capture request binding should canonicalize");
        let (capture_url, capture_rx, capture_handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA,
                "operation": "capture",
                "requestDigest": capture_digest,
                "reference": "capture-1",
                "authorizationId": "auth-1",
                "transactionId": "txn-1",
                "settlementStatus": "settled",
                "metadata": {"providerReference": "provider-capture-1"}
            }),
        );
        let capture = AcpPaymentAdapter::new(capture_url)
            .capture("auth-1", 700, "USD", "capture-1")
            .expect("capture should be confirmed by the facilitator");
        assert_eq!(capture.transaction_id, "txn-1");
        assert_eq!(capture.settlement_status, RailSettlementStatus::Settled);
        let capture_request = capture_rx
            .recv()
            .expect("capture request should be recorded");
        assert!(capture_request.starts_with("POST /capture HTTP/1.1"));
        assert!(capture_request.contains("\"operation\":\"capture\""));
        capture_handle
            .join()
            .expect("capture server should exit cleanly");

        let release_binding = AcpTerminalOperationBinding {
            authorization_id: "auth-2",
            transaction_id: None,
            amount_units: None,
            currency: None,
            reference: "release-1",
        };
        let release_digest = acp_request_digest(&release_binding)
            .expect("release request binding should canonicalize");
        let (release_url, release_rx, release_handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA,
                "operation": "release",
                "requestDigest": release_digest,
                "reference": "release-1",
                "authorizationId": "auth-2",
                "transactionId": "release-txn-1",
                "settlementStatus": "released"
            }),
        );
        let release = AcpPaymentAdapter::new(release_url)
            .release("auth-2", "release-1")
            .expect("release should be confirmed by the facilitator");
        assert_eq!(release.settlement_status, RailSettlementStatus::Released);
        assert!(release_rx
            .recv()
            .expect("release request should be recorded")
            .starts_with("POST /release HTTP/1.1"));
        release_handle
            .join()
            .expect("release server should exit cleanly");

        let refund_binding = AcpTerminalOperationBinding {
            authorization_id: "",
            transaction_id: Some("txn-2"),
            amount_units: Some(225),
            currency: Some("USD"),
            reference: "refund-1",
        };
        let refund_digest = acp_request_digest(&refund_binding)
            .expect("refund request binding should canonicalize");
        let (refund_url, refund_rx, refund_handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA,
                "operation": "refund",
                "requestDigest": refund_digest,
                "reference": "refund-1",
                "transactionId": "refund-txn-1",
                "settlementStatus": "refunded"
            }),
        );
        let refund = AcpPaymentAdapter::new(refund_url)
            .refund("txn-2", 225, "USD", "refund-1")
            .expect("refund should be confirmed by the facilitator");
        assert_eq!(refund.settlement_status, RailSettlementStatus::Refunded);
        assert!(refund_rx
            .recv()
            .expect("refund request should be recorded")
            .starts_with("POST /refund HTTP/1.1"));
        refund_handle
            .join()
            .expect("refund server should exit cleanly");
    }

    #[test]
    fn acp_adapter_queries_bound_settlement_state() {
        let binding = AcpSettlementStateBinding {
            reference: "reconcile-1",
            authorization_id: Some("auth-3"),
        };
        let request_digest =
            acp_request_digest(&binding).expect("settlement-state request should canonicalize");
        let (url, request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_SETTLEMENT_STATE_RESPONSE_SCHEMA,
                "requestDigest": request_digest,
                "reference": "reconcile-1",
                "state": "settled",
                "authorizationId": "auth-3",
                "transactionId": "txn-3",
                "settlementStatus": "settled",
                "metadata": {"providerReference": "provider-3"}
            }),
        );
        let state = AcpPaymentAdapter::new(url)
            .settlement_state("reconcile-1", Some("auth-3"))
            .expect("settlement state should be verified");
        assert!(matches!(
            state,
            RailSettlementState::Settled {
                authorization_id,
                result: PaymentResult { transaction_id, .. }
            } if authorization_id == "auth-3" && transaction_id == "txn-3"
        ));
        let request = request_rx.recv().expect("state request should be captured");
        assert!(request.starts_with("GET /settlement-state?"));
        assert!(request.contains("reference=reconcile-1"));
        assert!(request.contains("authorizationId=auth-3"));
        handle.join().expect("state server should exit cleanly");
    }

    #[test]
    fn acp_adapter_rejects_unbound_terminal_response() {
        let binding = AcpTerminalOperationBinding {
            authorization_id: "auth-4",
            transaction_id: None,
            amount_units: Some(10),
            currency: Some("USD"),
            reference: "capture-4",
        };
        let request_digest =
            acp_request_digest(&binding).expect("capture request binding should canonicalize");
        let (url, _request_rx, handle) = spawn_once_json_server(
            200,
            serde_json::json!({
                "schema": ACP_TERMINAL_OPERATION_RESPONSE_SCHEMA,
                "operation": "capture",
                "requestDigest": request_digest,
                "reference": "another-reference",
                "authorizationId": "auth-4",
                "transactionId": "txn-4",
                "settlementStatus": "settled"
            }),
        );
        let error = AcpPaymentAdapter::new(url)
            .capture("auth-4", 10, "USD", "capture-4")
            .expect_err("an unbound response must fail closed");
        assert!(matches!(error, PaymentError::RailError(_)));
        handle.join().expect("server should exit cleanly");
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
