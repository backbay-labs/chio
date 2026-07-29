//! Deterministic verification of a buyer-presented purchase context.
//!
//! The reveal-time kernel gate delegates here through its injected
//! verifier seam. Everything in this module is a pure function of the
//! carrier bytes plus pinned deployment authorities, so the durable
//! finalizer can replay it from the frozen request and reach the same
//! verdict after a crash. Clocked liveness bounds and authoritative
//! reservation state live with the caller's admission-time check, never
//! here.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use chio_finding::{
    decode_purchase_context_b64, verify_finding, verify_signed_admission,
    verify_signed_seller_authorization, Finding, FindingPurchaseContext, SignedFindingAdmission,
    SignedFindingSellerAuthorization,
};

use crate::bidding::{
    SignedAcceptedBid, SignedAskResponse, SignedBidRequest, SignedReservationReceipt,
    VerifiedReservationReceipt,
};
use crate::canonical_json_bytes;
use crate::capability::token::CapabilityToken;
use crate::crypto::{sha256_hex, PublicKey};
use crate::listing::{SignedGenericListing, SignedListingPricingHint};

/// Domain separator for the deterministic purchase-intent identity.
const PURCHASE_INTENT_DOMAIN: &str = "chio.finding.purchase-intent.v1";

/// Domain separator for the deterministic payment-operation identity.
const PAYMENT_OPERATION_DOMAIN: &str = "chio.finding.payment-operation.v1";

/// Derive the preallocated purchase-intent identity for a reservation.
///
/// The identity is fixed by the reservation at reserve time, so no
/// post-effect caller value can choose it and every re-derivation from
/// the same reservation recovers the same identity.
#[must_use]
pub fn derive_purchase_intent_id(reservation_id: &str) -> String {
    sha256_hex(format!("{PURCHASE_INTENT_DOMAIN}\0{reservation_id}").as_bytes())
}

/// Derive the preallocated authoritative payment-operation identity for a
/// reservation.
#[must_use]
pub fn derive_payment_operation_id(reservation_id: &str) -> String {
    sha256_hex(format!("{PAYMENT_OPERATION_DOMAIN}\0{reservation_id}").as_bytes())
}

/// Typed rejections from [`verify_purchase_context_pure`]. Every variant
/// denies the reveal.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PurchaseVerificationError {
    #[error("purchase context rejected: {0}")]
    Carrier(chio_finding::FindingError),
    #[error("purchase context member {0} failed strict parsing")]
    Member(&'static str),
    #[error("signed finding rejected: {0}")]
    Finding(chio_finding::FindingError),
    #[error("purchase context does not bind the marked finding sale")]
    MarkerMismatch,
    #[error("finding payload commitment does not equal the grant digest")]
    PayloadDigestMismatch,
    #[error("finding advertises no reveal media type")]
    MediaTypeMissing,
    #[error("{0} envelope signature is not verifiable")]
    EnvelopeSignature(&'static str),
    #[error("venue admission rejected: {0}")]
    Admission(chio_finding::FindingError),
    #[error("admission does not bind the carried {0} envelope")]
    AdmissionBindingMismatch(&'static str),
    #[error("seller authorization rejected: {0}")]
    SellerAuthorization(chio_finding::FindingError),
    #[error("seller authorization does not cover this sale")]
    SellerAuthorizationScope,
    #[error("token issuer is neither the finding issuer nor an authorized seller")]
    UnauthorizedIssuer,
    #[error("handshake envelopes do not cross-bind: {0}")]
    HandshakeBinding(&'static str),
    #[error("presented capability is not the exact ask token offer")]
    TokenByteMismatch,
    #[error("reservation receipt rejected")]
    ReservationReceipt,
    #[error("reservation does not bind this purchase: {0}")]
    ReservationBinding(&'static str),
    #[error("request arguments do not name the sold finding")]
    ArgumentMismatch,
}

/// Pinned deployment authorities the pure verification checks envelopes
/// against. Every key comes from configuration, never from the carrier.
#[derive(Clone)]
pub struct PurchaseVerificationAuthorities {
    pub venue_authority: PublicKey,
    pub venue_id: String,
    pub reservation_authority: PublicKey,
}

/// The exact inputs of one pure verification run.
pub struct PurchaseVerificationInputs<'a> {
    /// Marker identities from the selected grant.
    pub marker_finding_id: &'a str,
    pub marker_listing_id: &'a str,
    /// The output digest the grant committed to.
    pub expected_output_digest: &'a str,
    /// The base64 purchase-context carrier from the governed intent.
    pub context_b64: &'a str,
    /// The capability presented with the reveal request.
    pub capability: &'a CapabilityToken,
    /// Target server and tool of the reveal request.
    pub server_id: &'a str,
    pub tool_name: &'a str,
    /// The exact request arguments.
    pub arguments: &'a serde_json::Value,
}

/// Everything the kernel needs from a verified purchase, plus the parsed
/// constituents the coordinator re-uses at admission time.
pub struct PurchaseVerificationOutcome {
    pub finding: Finding,
    pub admission: SignedFindingAdmission,
    pub accepted_bid_envelope_sha256: String,
    pub venue_admission_envelope_sha256: String,
    pub reservation_id: String,
    pub reservation_store_key: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    pub payer_key_hex: String,
    pub accepted_price: crate::capability::scope::MonetaryAmount,
}

fn parse_member<T: serde::de::DeserializeOwned>(
    text: &str,
    member: &'static str,
) -> Result<T, PurchaseVerificationError> {
    serde_json::from_str(text).map_err(|_| PurchaseVerificationError::Member(member))
}

fn canonical_digest_of(
    text: &str,
    member: &'static str,
) -> Result<String, PurchaseVerificationError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| PurchaseVerificationError::Member(member))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| PurchaseVerificationError::Member(member))?;
    Ok(sha256_hex(&bytes))
}

/// Verify one purchase context deterministically against the marked sale.
///
/// The verification chain follows the signed finding as the anchor: the
/// finding binds identity to the payload commitment; the venue admission
/// binds the listing, pricing, terms, backing, profile, and report
/// envelopes by digest under the pinned venue key; the seller
/// authorization connects the token issuer to the finding issuer; the
/// handshake envelopes cross-bind bid, ask, accepted bid, and the exact
/// token offer; and the reservation receipt binds the funds pointer under
/// the pinned reservation authority. Liveness bounds and authoritative
/// reservation state are the caller's admission-time responsibility.
pub fn verify_purchase_context_pure(
    inputs: &PurchaseVerificationInputs<'_>,
    authorities: &PurchaseVerificationAuthorities,
) -> Result<PurchaseVerificationOutcome, PurchaseVerificationError> {
    let context: FindingPurchaseContext = decode_purchase_context_b64(inputs.context_b64)
        .map_err(PurchaseVerificationError::Carrier)?;

    // The anchor: the signed finding binds identity to commitment.
    let finding: Finding = parse_member(&context.finding_json, "finding_json")?;
    verify_finding(&finding).map_err(PurchaseVerificationError::Finding)?;
    if finding.finding_id != inputs.marker_finding_id {
        return Err(PurchaseVerificationError::MarkerMismatch);
    }
    if finding.payload_sha256 != inputs.expected_output_digest {
        return Err(PurchaseVerificationError::PayloadDigestMismatch);
    }
    if finding.payload_media_type.trim().is_empty() {
        return Err(PurchaseVerificationError::MediaTypeMissing);
    }
    let argument_finding_id = inputs
        .arguments
        .get("finding_id")
        .and_then(serde_json::Value::as_str);
    if argument_finding_id != Some(finding.finding_id.as_str()) {
        return Err(PurchaseVerificationError::ArgumentMismatch);
    }

    // The venue admission, under the pinned venue key, binds every other
    // authority envelope by digest. Deep constituent validity was proved
    // at activation and reservation time; the reveal re-proves the exact
    // envelope identities.
    let admission: SignedFindingAdmission =
        parse_member(&context.venue_admission_envelope_json, "venue_admission")?;
    verify_signed_admission(
        &admission,
        &authorities.venue_authority,
        &authorities.venue_id,
    )
    .map_err(PurchaseVerificationError::Admission)?;
    if admission.body.finding_id != finding.finding_id
        || admission.body.listing_id != inputs.marker_listing_id
    {
        return Err(PurchaseVerificationError::MarkerMismatch);
    }
    let venue_admission_envelope_sha256 =
        canonical_digest_of(&context.venue_admission_envelope_json, "venue_admission")?;
    for (member, text, bound_digest) in [
        (
            "listing",
            &context.listing_envelope_json,
            &admission.body.listing_envelope_sha256,
        ),
        (
            "pricing_hint",
            &context.pricing_hint_envelope_json,
            &admission.body.pricing_hint_envelope_sha256,
        ),
        (
            "market_terms",
            &context.market_terms_envelope_json,
            &admission.body.terms_envelope_sha256,
        ),
        (
            "seller_backing",
            &context.seller_backing_envelope_json,
            &admission.body.backing_envelope_sha256,
        ),
        (
            "verifier_profile",
            &context.verifier_profile_envelope_json,
            &admission.body.profile_envelope_sha256,
        ),
        (
            "verifier_report",
            &context.verifier_report_envelope_json,
            &admission.body.verifier_report_envelope_sha256,
        ),
    ] {
        if &canonical_digest_of(text, "venue_admission")? != bound_digest {
            return Err(PurchaseVerificationError::AdmissionBindingMismatch(member));
        }
    }

    // Listing and pricing identity under the admitted envelopes.
    let listing: SignedGenericListing = parse_member(&context.listing_envelope_json, "listing")?;
    if !matches!(listing.verify_signature(), Ok(true)) {
        return Err(PurchaseVerificationError::EnvelopeSignature("listing"));
    }
    let pricing: SignedListingPricingHint =
        parse_member(&context.pricing_hint_envelope_json, "pricing_hint")?;
    if !matches!(pricing.verify_signature(), Ok(true)) {
        return Err(PurchaseVerificationError::EnvelopeSignature("pricing_hint"));
    }
    if pricing.body.listing_id != inputs.marker_listing_id
        || pricing.body.capability_scope != format!("finding:{}", finding.finding_id)
    {
        return Err(PurchaseVerificationError::HandshakeBinding("pricing_scope"));
    }

    // The seller authorization connects every economic party to the
    // finding issuer, scoped to exactly this sale surface.
    let authorization: SignedFindingSellerAuthorization = parse_member(
        &context.seller_authorization_envelope_json,
        "seller_authorization",
    )?;
    verify_signed_seller_authorization(&authorization)
        .map_err(PurchaseVerificationError::SellerAuthorization)?;
    if authorization.body.finding_id != finding.finding_id
        || authorization.body.listing_id != inputs.marker_listing_id
        || authorization.body.issuer != finding.issuer
        || authorization.body.provider_server_id != inputs.server_id
        || authorization.body.provider_tool != inputs.tool_name
    {
        return Err(PurchaseVerificationError::SellerAuthorizationScope);
    }

    // Handshake: bid, ask, accepted bid, and the exact token offer.
    let ask: SignedAskResponse = parse_member(&context.ask_response_envelope_json, "ask_response")?;
    if !matches!(ask.verify_signature(), Ok(true)) {
        return Err(PurchaseVerificationError::EnvelopeSignature("ask_response"));
    }
    if ask.body.token_offer.issuer != ask.signer_key {
        return Err(PurchaseVerificationError::HandshakeBinding("ask_issuer"));
    }
    if ask.signer_key != finding.issuer && ask.signer_key != authorization.body.seller {
        return Err(PurchaseVerificationError::UnauthorizedIssuer);
    }
    let bid: SignedBidRequest = parse_member(&context.bid_request_envelope_json, "bid_request")?;
    if !matches!(bid.verify_signature(), Ok(true)) {
        return Err(PurchaseVerificationError::EnvelopeSignature("bid_request"));
    }
    let bid_digest = canonical_digest_of(&context.bid_request_envelope_json, "bid_request")
        .and_then(|_| {
            canonical_json_bytes(&bid.body)
                .map(|bytes| sha256_hex(&bytes))
                .map_err(|_| PurchaseVerificationError::Member("bid_request"))
        })?;
    if bid_digest != ask.body.bid_digest
        || bid.body.listing_id != inputs.marker_listing_id
        || bid.body.requested_scope.max_invocations != Some(1)
        || bid.body.requested_scope.server_id != inputs.server_id
        || bid.body.requested_scope.tool_name != inputs.tool_name
    {
        return Err(PurchaseVerificationError::HandshakeBinding("bid_request"));
    }
    let accepted: SignedAcceptedBid =
        parse_member(&context.accepted_bid_envelope_json, "accepted_bid")?;
    if !matches!(accepted.verify_signature(), Ok(true)) {
        return Err(PurchaseVerificationError::EnvelopeSignature("accepted_bid"));
    }
    let ask_digest = canonical_json_bytes(&ask.body)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| PurchaseVerificationError::Member("ask_response"))?;
    if accepted.signer_key != ask.body.token_offer.subject
        || accepted.body.ask_digest != ask_digest
        || accepted.body.bid_digest != ask.body.bid_digest
        || accepted.body.listing_id != ask.body.listing_id
        || accepted.body.agent_id != ask.body.agent_id
        || accepted.body.quoted_price != ask.body.quoted_price
        || accepted.body.token_id != ask.body.token_offer.id
        || accepted.body.token_subject != ask.body.token_offer.subject
        || accepted.body.token_expires_at != ask.body.token_offer.expires_at
    {
        return Err(PurchaseVerificationError::HandshakeBinding("accepted_bid"));
    }

    // The presented capability must be canonical-byte identical to the
    // embedded token offer; sharing an id, subject, or expiry is not
    // enough.
    let offered_token_bytes = canonical_json_bytes(&ask.body.token_offer)
        .map_err(|_| PurchaseVerificationError::Member("token_offer"))?;
    let carried_token: serde_json::Value =
        parse_member(&context.token_offer_json, "token_offer_json")?;
    let carried_token_bytes = canonical_json_bytes(&carried_token)
        .map_err(|_| PurchaseVerificationError::Member("token_offer_json"))?;
    let presented_token_bytes = canonical_json_bytes(inputs.capability)
        .map_err(|_| PurchaseVerificationError::Member("capability"))?;
    if offered_token_bytes != carried_token_bytes || offered_token_bytes != presented_token_bytes {
        return Err(PurchaseVerificationError::TokenByteMismatch);
    }

    // The reservation compatibility pointer under the pinned authority.
    let reservation_signed: SignedReservationReceipt = parse_member(
        &context.reservation_receipt_envelope_json,
        "reservation_receipt",
    )?;
    let reservation = VerifiedReservationReceipt::from_signed(
        &reservation_signed,
        &authorities.reservation_authority,
    )
    .map_err(|_| PurchaseVerificationError::ReservationReceipt)?;
    if reservation_signed.body.agent_id != ask.body.agent_id {
        return Err(PurchaseVerificationError::ReservationBinding("agent"));
    }
    if reservation_signed.body.listing_id != ask.body.listing_id {
        return Err(PurchaseVerificationError::ReservationBinding("listing"));
    }
    if reservation_signed.body.ask_digest != ask_digest {
        return Err(PurchaseVerificationError::ReservationBinding("ask_digest"));
    }
    if reservation_signed.body.receipt_id != accepted.body.bid_receipt_id {
        return Err(PurchaseVerificationError::ReservationBinding("receipt_id"));
    }
    if reservation_signed.body.reserved_amount != ask.body.quoted_price {
        return Err(PurchaseVerificationError::ReservationBinding("amount"));
    }

    let reservation_id = reservation.receipt_id().to_owned();
    let accepted_bid_envelope_sha256 =
        canonical_digest_of(&context.accepted_bid_envelope_json, "accepted_bid")?;
    Ok(PurchaseVerificationOutcome {
        purchase_intent_id: derive_purchase_intent_id(&reservation_id),
        authoritative_payment_operation_id: derive_payment_operation_id(&reservation_id),
        payer_key_hex: ask.body.token_offer.subject.to_hex(),
        accepted_price: ask.body.quoted_price.clone(),
        reservation_store_key: context.reservation_store_key.clone(),
        accepted_bid_envelope_sha256,
        venue_admission_envelope_sha256,
        reservation_id,
        finding,
        admission,
    })
}
