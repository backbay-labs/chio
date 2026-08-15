//! `chio.finding.purchase-context.v1`: the UNSIGNED bounded carrier a buyer
//! presents at reveal admission.
//!
//! The carrier is transport, never authority. It holds the exact canonical
//! JSON TEXT of every artifact the reveal path must re-verify, because the
//! only thing a buyer can be trusted to supply is bytes: the consumer
//! re-derives every identity and digest from those bytes and rejects any
//! member it cannot canonicalize back to itself. Like the replay-recipe
//! input, this schema registers in the public registry and manifest but
//! MUST NOT enter the signed-artifact allowlist.
//!
//! Members stay opaque text for two independent reasons. The open-market
//! envelopes (bid, ask, accepted bid, reservation receipt) are owned by
//! `chio-open-market`, which this crate must not depend on, so the verifier
//! layer parses them. And `token_offer_json` is compared for BYTE identity
//! against the token the ask embedded, which a typed round-trip through a
//! Rust value would silently normalize away.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::validate::{require_bounded_id, require_canonical_json_text, FindingError};

/// Unsigned buyer-presented purchase context.
pub const PURCHASE_CONTEXT_SCHEMA: &str = "chio.finding.purchase-context.v1";

/// Bound on the decoded canonical JSON, and on each canonical member the
/// carrier holds.
pub const PURCHASE_CONTEXT_MAX_CANONICAL_BYTES: usize = 262_144;

/// Bound on the base64 transport encoding, enforced BEFORE any decode so an
/// oversized presentation costs no decode work.
pub const PURCHASE_CONTEXT_MAX_ENCODED_BYTES: usize =
    PURCHASE_CONTEXT_MAX_CANONICAL_BYTES.div_ceil(3) * 4;

/// The buyer-presented purchase context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPurchaseContext {
    pub schema: String,
    /// The signed Finding artifact as its exact canonical JSON text. The
    /// finding family signs inline, so there is no envelope to carry.
    pub finding_json: String,
    pub listing_envelope_json: String,
    pub pricing_hint_envelope_json: String,
    pub venue_admission_envelope_json: String,
    pub market_terms_envelope_json: String,
    pub seller_authorization_envelope_json: String,
    pub verifier_profile_envelope_json: String,
    pub seller_backing_envelope_json: String,
    pub verifier_report_envelope_json: String,
    pub bid_request_envelope_json: String,
    pub ask_response_envelope_json: String,
    pub accepted_bid_envelope_json: String,
    pub reservation_receipt_envelope_json: String,
    /// Authoritative coordinator store key for the reservation.
    pub reservation_store_key: String,
    /// The exact capability token bytes as canonical JSON text.
    pub token_offer_json: String,
}

impl FindingPurchaseContext {
    /// Every carried canonical-JSON member, paired with the field name its
    /// rejection reports.
    fn canonical_members(&self) -> [(&'static str, &str); 14] {
        [
            ("finding_json", &self.finding_json),
            ("listing_envelope_json", &self.listing_envelope_json),
            (
                "pricing_hint_envelope_json",
                &self.pricing_hint_envelope_json,
            ),
            (
                "venue_admission_envelope_json",
                &self.venue_admission_envelope_json,
            ),
            (
                "market_terms_envelope_json",
                &self.market_terms_envelope_json,
            ),
            (
                "seller_authorization_envelope_json",
                &self.seller_authorization_envelope_json,
            ),
            (
                "verifier_profile_envelope_json",
                &self.verifier_profile_envelope_json,
            ),
            (
                "seller_backing_envelope_json",
                &self.seller_backing_envelope_json,
            ),
            (
                "verifier_report_envelope_json",
                &self.verifier_report_envelope_json,
            ),
            ("bid_request_envelope_json", &self.bid_request_envelope_json),
            (
                "ask_response_envelope_json",
                &self.ask_response_envelope_json,
            ),
            (
                "accepted_bid_envelope_json",
                &self.accepted_bid_envelope_json,
            ),
            (
                "reservation_receipt_envelope_json",
                &self.reservation_receipt_envelope_json,
            ),
            ("token_offer_json", &self.token_offer_json),
        ]
    }

    /// Structural validation. Every member must be present, individually
    /// size-bounded, and strictly canonical on its own, and the members
    /// together must fit the carrier bound. Resolving the members against
    /// each other (digest agreement, token byte identity, reservation
    /// state) is the consumer's obligation, not a carrier check.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != PURCHASE_CONTEXT_SCHEMA {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        let mut total = 0_usize;
        for (field, value) in self.canonical_members() {
            require_canonical_json_text(value, field, PURCHASE_CONTEXT_MAX_CANONICAL_BYTES)?;
            total = total
                .checked_add(value.len())
                .ok_or(FindingError::SizeLimitExceeded("purchase_context"))?;
        }
        if total > PURCHASE_CONTEXT_MAX_CANONICAL_BYTES {
            return Err(FindingError::SizeLimitExceeded("purchase_context"));
        }
        require_bounded_id(&self.reservation_store_key, "reservation_store_key")
    }
}

/// Parse a raw purchase context, fail-closed.
///
/// The decoded bound is checked first, then the raw text must canonicalize
/// to itself under the strict I-JSON rules (which reject duplicate keys and
/// non-canonical numbers), and the typed value must re-serialize to the
/// exact same bytes. Only then does structural validation run.
pub fn parse_purchase_context(raw: &[u8]) -> Result<FindingPurchaseContext, FindingError> {
    if raw.is_empty() || raw.len() > PURCHASE_CONTEXT_MAX_CANONICAL_BYTES {
        return Err(FindingError::SizeLimitExceeded("purchase_context"));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| FindingError::NonCanonicalBytes("purchase_context"))?;
    let strict = chio_core_types::canonical_json_bytes_from_str(text)
        .map_err(|_| FindingError::NonCanonicalBytes("purchase_context"))?;
    if strict.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes("purchase_context"));
    }
    let context: FindingPurchaseContext =
        serde_json::from_slice(raw).map_err(|_| FindingError::InvalidField("purchase_context"))?;
    let reserialized = chio_core_types::canonical_json_bytes(&context)
        .map_err(|_| FindingError::Canonicalization)?;
    if reserialized.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes("purchase_context"));
    }
    context.validate()?;
    Ok(context)
}

/// Decode and parse a base64 purchase context, fail-closed.
///
/// The encoded bound is enforced BEFORE the decode so an oversized
/// presentation never allocates a decode buffer.
pub fn decode_purchase_context_b64(encoded: &str) -> Result<FindingPurchaseContext, FindingError> {
    if encoded.is_empty() || encoded.len() > PURCHASE_CONTEXT_MAX_ENCODED_BYTES {
        return Err(FindingError::SizeLimitExceeded("purchase_context.encoded"));
    }
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| FindingError::InvalidField("purchase_context.encoded"))?;
    parse_purchase_context(&raw)
}
