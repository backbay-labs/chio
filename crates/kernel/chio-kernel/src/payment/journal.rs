//! Durable payment journal state and transition validation.

use serde::{Deserialize, Serialize};

use super::PaymentRailMode;

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
