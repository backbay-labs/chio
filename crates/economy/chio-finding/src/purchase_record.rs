//! `chio.finding.purchase-record.v1`: the purchase-authority-signed record
//! of one settled finding sale.
//!
//! The record's identity is NOT content-addressed over its own body. A
//! purchase is the pairing of one accepted bid with one authoritative
//! payment operation, and that pair must name the same record no matter
//! what the coordinator later learns about delivery, encumbrance, or
//! payout. So `purchase_key` derives from a domain-separated preimage over
//! exactly those two members, which makes the key the natural idempotency
//! key for the settling store: a retry of the same sale recomputes the same
//! key, while a second payment operation for the same bid cannot silently
//! reuse it.
//!
//! `realized_spend` may fall below `accepted_price` (partial capture) but
//! never exceed it, and both amounts share one currency.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_i_json_u64, require_nonzero,
    FindingError,
};

/// Purchase-authority-signed settled purchase record.
pub const FINDING_PURCHASE_RECORD_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA;

/// Domain separator for the purchase-key preimage. The trailing NUL keeps
/// the separator unambiguous against any digest text that follows it.
const PURCHASE_KEY_DOMAIN: &[u8] = b"chio.finding.purchase.v1\0";

/// Settled purchase record body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPurchaseRecord {
    pub schema: String,
    /// Derived from the accepted-bid envelope digest and the authoritative
    /// payment operation; see [`derive_purchase_key`].
    pub purchase_key: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    pub buyer: PublicKey,
    /// The principal the rail actually debited, which may be a sponsor
    /// rather than the buyer.
    pub payer: PublicKey,
    pub finding_id: String,
    pub listing_id: String,
    pub accepted_bid_envelope_sha256: String,
    pub venue_admission_envelope_sha256: String,
    pub accepted_price: MonetaryAmount,
    /// Never above `accepted_price`; a partial capture settles below it.
    pub realized_spend: MonetaryAmount,
    pub seller_backing_envelope_sha256: String,
    pub encumbrance_id: String,
    pub delivery_receipt_id: String,
    pub payment_reference: String,
    /// Buyer-selected EVM destination for a later harm payout. The purchase
    /// authority copies this from the buyer-signed bid before signing the
    /// record, so neither the seller nor a challenge can redirect it.
    pub payout_destination: String,
    pub recorded_at: u64,
}

/// Purchase-authority-signed envelope for the record.
pub type SignedFindingPurchaseRecord = SignedExportEnvelope<FindingPurchaseRecord>;

impl FindingPurchaseRecord {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_PURCHASE_RECORD_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.purchase_key, "purchase_key")?;
        require_bounded_id(&self.purchase_intent_id, "purchase_intent_id")?;
        require_bounded_id(
            &self.authoritative_payment_operation_id,
            "authoritative_payment_operation_id",
        )?;
        require_ed25519(&self.buyer, "buyer")?;
        require_ed25519(&self.payer, "payer")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(
            &self.accepted_bid_envelope_sha256,
            "accepted_bid_envelope_sha256",
        )?;
        require_hex64(
            &self.venue_admission_envelope_sha256,
            "venue_admission_envelope_sha256",
        )?;
        require_nonzero(self.accepted_price.units, "accepted_price")?;
        require_currency(&self.accepted_price.currency, "accepted_price.currency")?;
        require_i_json_u64(self.realized_spend.units, "realized_spend")?;
        require_currency(&self.realized_spend.currency, "realized_spend.currency")?;
        if self.accepted_price.currency != self.realized_spend.currency {
            return Err(FindingError::CurrencyMismatch("purchase_record"));
        }
        if self.realized_spend.units > self.accepted_price.units {
            return Err(FindingError::InvalidField("realized_spend"));
        }
        require_hex64(
            &self.seller_backing_envelope_sha256,
            "seller_backing_envelope_sha256",
        )?;
        require_bounded_id(&self.encumbrance_id, "encumbrance_id")?;
        require_bounded_id(&self.delivery_receipt_id, "delivery_receipt_id")?;
        require_bounded_id(&self.payment_reference, "payment_reference")?;
        validate_evm_payout_destination(&self.payout_destination)?;
        require_nonzero(self.recorded_at, "recorded_at")?;
        self.verify_purchase_key()
    }

    /// Recompute and compare the derived purchase key.
    pub fn verify_purchase_key(&self) -> Result<(), FindingError> {
        let expected = derive_purchase_key(
            &self.accepted_bid_envelope_sha256,
            &self.authoritative_payment_operation_id,
        );
        if expected == self.purchase_key {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("purchase_key"))
        }
    }
}

/// Validate the EVM address shape consumed by the enforcement rail.
///
/// Control of the address is established by the buyer-signed bid and the
/// purchase-authority-signed record. This helper checks only the portable
/// representation so an otherwise valid purchase cannot become impossible
/// to settle after a challenge is upheld.
pub fn validate_evm_payout_destination(destination: &str) -> Result<(), FindingError> {
    require_bounded_id(destination, "payout_destination")?;
    let Some(hex) = destination.strip_prefix("0x") else {
        return Err(FindingError::InvalidField("payout_destination"));
    };
    if hex.len() != 40
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(FindingError::InvalidField("payout_destination"));
    }
    Ok(())
}

/// Canonicalize a buyer-signed EVM destination before it occupies a
/// bounded payout slot. Address comparison on the enforcement rail is
/// case-insensitive, while the durable store is byte-keyed, so retaining
/// lowercase prevents one address consuming several immutable slots.
pub fn canonical_evm_payout_destination(destination: &str) -> Result<String, FindingError> {
    let Some(hex) = destination.strip_prefix("0x") else {
        return Err(FindingError::InvalidField("payout_destination"));
    };
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FindingError::InvalidField("payout_destination"));
    }
    let canonical = format!("0x{}", hex.to_ascii_lowercase());
    validate_evm_payout_destination(&canonical)?;
    Ok(canonical)
}

/// Derive the purchase key: sha256 over the domain-separated preimage of the
/// accepted-bid envelope digest and the authoritative payment operation id,
/// separated by a NUL so no two distinct pairs share a preimage.
pub fn derive_purchase_key(
    accepted_bid_envelope_sha256: &str,
    authoritative_payment_operation_id: &str,
) -> String {
    let mut preimage = Vec::with_capacity(
        PURCHASE_KEY_DOMAIN.len()
            + accepted_bid_envelope_sha256.len()
            + 1
            + authoritative_payment_operation_id.len(),
    );
    preimage.extend_from_slice(PURCHASE_KEY_DOMAIN);
    preimage.extend_from_slice(accepted_bid_envelope_sha256.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(authoritative_payment_operation_id.as_bytes());
    chio_core_types::crypto::sha256_hex(&preimage)
}

/// Verify a signed purchase record against the externally pinned purchase
/// authority. The body names the buyer and payer, never the signing
/// authority, so the pin is the only thing that authorizes this record.
pub fn verify_signed_purchase_record(
    signed: &SignedFindingPurchaseRecord,
    pinned_purchase_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, pinned_purchase_authority, "purchase_record")
}
