//! `chio.finding.failed-delivery.v1`: the failed-delivery-authority-signed
//! terminal for a reveal that was denied before any value moved.
//!
//! This artifact is the positive evidence that a denied purchase left the
//! buyer whole. Silence is not evidence: without a signed terminal, a
//! reservation that was held and then released is indistinguishable from
//! one that was captured and lost. The body therefore names the exact hold
//! attempt, its release terminal, and both halves of the deny evidence
//! (receipt and checkpoint), and it asserts the two facts that make the
//! terminal safe: nothing was spent, and nothing is payable.
//!
//! `realized_spend_units` MUST be zero and `payout_eligible` MUST be false.
//! Both are encoded rather than implied so a nonzero spend on a
//! failed-delivery path is a schema-level rejection, not a reconciliation
//! surprise.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_nonzero, FindingError,
};

/// Failed-delivery-authority-signed denial terminal.
pub const FINDING_FAILED_DELIVERY_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA;

/// How the payment hold ended. Closed enum: a terminal this vocabulary
/// cannot name fails at parse time rather than settling as "something
/// else".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingHoldReleaseTerminal {
    /// An authorized hold was released without capture.
    Released,
    /// The attempt was cancelled before any authorization existed.
    CancelledBeforeAuthorization,
}

/// Failed-delivery terminal body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingFailedDelivery {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `failed_delivery_id` cleared.
    pub failed_delivery_id: String,
    pub buyer: PublicKey,
    pub finding_id: String,
    pub listing_id: String,
    pub accepted_bid_envelope_sha256: String,
    pub reservation_id: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    /// The exact hold attempt this terminal closes.
    pub hold_attempt_reference: String,
    pub release_terminal: FindingHoldReleaseTerminal,
    pub deny_receipt_id: String,
    pub deny_receipt_sha256: String,
    pub deny_checkpoint_ref: String,
    pub deny_checkpoint_sha256: String,
    /// Always zero on this path.
    pub realized_spend_units: u64,
    pub currency: String,
    /// Always false on this path.
    pub payout_eligible: bool,
    pub recorded_at: u64,
}

/// Failed-delivery-authority-signed envelope for the terminal.
pub type SignedFindingFailedDelivery = SignedExportEnvelope<FindingFailedDelivery>;

impl FindingFailedDelivery {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_FAILED_DELIVERY_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.failed_delivery_id, "failed_delivery_id")?;
        require_ed25519(&self.buyer, "buyer")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(
            &self.accepted_bid_envelope_sha256,
            "accepted_bid_envelope_sha256",
        )?;
        require_bounded_id(&self.reservation_id, "reservation_id")?;
        require_bounded_id(&self.purchase_intent_id, "purchase_intent_id")?;
        require_bounded_id(
            &self.authoritative_payment_operation_id,
            "authoritative_payment_operation_id",
        )?;
        require_bounded_id(&self.hold_attempt_reference, "hold_attempt_reference")?;
        require_bounded_id(&self.deny_receipt_id, "deny_receipt_id")?;
        require_hex64(&self.deny_receipt_sha256, "deny_receipt_sha256")?;
        require_bounded_id(&self.deny_checkpoint_ref, "deny_checkpoint_ref")?;
        require_hex64(&self.deny_checkpoint_sha256, "deny_checkpoint_sha256")?;
        if self.realized_spend_units != 0 {
            return Err(FindingError::InvalidField("realized_spend_units"));
        }
        require_currency(&self.currency, "currency")?;
        if self.payout_eligible {
            return Err(FindingError::InvalidField("payout_eligible"));
        }
        require_nonzero(self.recorded_at, "recorded_at")?;
        self.verify_failed_delivery_id()
    }

    /// Recompute and compare the content-addressed terminal id.
    pub fn verify_failed_delivery_id(&self) -> Result<(), FindingError> {
        let expected = compute_failed_delivery_id(self)?;
        if expected == self.failed_delivery_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("failed_delivery_id"))
        }
    }
}

/// Content-addressed terminal id: sha256 over the canonical body with
/// `failed_delivery_id` cleared.
pub fn compute_failed_delivery_id(
    failed_delivery: &FindingFailedDelivery,
) -> Result<String, FindingError> {
    let mut body = failed_delivery.clone();
    body.failed_delivery_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed failed-delivery terminal against the externally pinned
/// failed-delivery authority. The body names the buyer, never the signing
/// authority, so the pin is the only thing that authorizes this terminal.
pub fn verify_signed_failed_delivery(
    signed: &SignedFindingFailedDelivery,
    pinned_failed_delivery_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(
        signed,
        pinned_failed_delivery_authority,
        "failed_delivery",
    )
}
