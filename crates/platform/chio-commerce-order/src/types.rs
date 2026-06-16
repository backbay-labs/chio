use serde::{Deserialize, Serialize};

use super::error::CommerceOrderError;
use super::ids::COMMERCE_ORDER_CONTEXT_SCHEMA_ID;
use super::validation::{
    require_non_empty, validate_bundle_relative_path, validate_money, validate_sha256_hex,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderContext {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub order_id: String,
    pub buyer_subject: String,
    pub agent_subject: String,
    pub merchant_subject: String,
    pub quote_id: String,
    pub quote_amount_minor: u64,
    pub quote_currency: String,
    pub event_log_sha256: String,
    pub event_log_path: String,
    pub payment_lifecycle_sha256: String,
    pub payment_lifecycle_path: String,
    pub mandate_ledger_sha256: String,
    pub mandate_ledger_path: String,
    pub current_state: String,
}

impl CommerceOrderContext {
    pub fn validate_shape(&self) -> Result<(), CommerceOrderError> {
        if self.schema != COMMERCE_ORDER_CONTEXT_SCHEMA_ID {
            return Err(CommerceOrderError::UnsupportedSchema {
                field: "order context",
                schema: self.schema.clone(),
            });
        }
        for (field, value) in [
            ("id", &self.id),
            ("issued_at", &self.issued_at),
            ("order_id", &self.order_id),
            ("buyer_subject", &self.buyer_subject),
            ("agent_subject", &self.agent_subject),
            ("merchant_subject", &self.merchant_subject),
            ("quote_id", &self.quote_id),
            ("quote_currency", &self.quote_currency),
            ("current_state", &self.current_state),
        ] {
            require_non_empty(value, field).map_err(|message| {
                CommerceOrderError::InvalidArtifact {
                    field: "order context",
                    message,
                }
            })?;
        }
        validate_money(
            self.quote_amount_minor,
            &self.quote_currency,
            "quote amount",
        )
        .map_err(|message| CommerceOrderError::InvalidArtifact {
            field: "order context",
            message,
        })?;
        for (field, digest) in [
            ("event_log_sha256", &self.event_log_sha256),
            ("payment_lifecycle_sha256", &self.payment_lifecycle_sha256),
            ("mandate_ledger_sha256", &self.mandate_ledger_sha256),
        ] {
            validate_sha256_hex(digest).map_err(|_| CommerceOrderError::InvalidArtifact {
                field: "order context",
                message: format!("invalid {field}: {digest}"),
            })?;
        }
        for (field, path) in [
            ("event_log_path", &self.event_log_path),
            ("payment_lifecycle_path", &self.payment_lifecycle_path),
            ("mandate_ledger_path", &self.mandate_ledger_path),
        ] {
            validate_bundle_relative_path(path).map_err(|_| {
                CommerceOrderError::InvalidArtifact {
                    field: "order context",
                    message: format!("unsafe {field}: {path}"),
                }
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderVerificationBundle {
    pub order_context: CommerceOrderContext,
    pub event_log_bytes: Vec<u8>,
    pub payment_lifecycle_bytes: Vec<u8>,
    pub mandate_ledger_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderPassportReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub order_id: String,
    pub current_state: String,
    pub verified_claims: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommercePaymentLifecycle {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) order_id: String,
    pub(super) merchant_subject: String,
    pub(super) psp: String,
    pub(super) payment_intent_id: String,
    pub(super) amount_minor: u64,
    pub(super) currency: String,
    pub(super) payment_status: String,
    pub(super) capture_mode: String,
    pub(super) capture_before: String,
    pub(super) captured_at: String,
    pub(super) transfer_group: String,
    pub(super) fraud_outcome: String,
    pub(super) dispute_status: String,
    pub(super) refund_status: String,
    pub(super) chargeback_status: String,
    pub(super) transfer_reversal_status: String,
}
