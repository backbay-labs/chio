//! Capability marketplace bid/ask protocol.
//!
//! A [`BidRequest`] is an agent's signed offer to purchase a time-bounded
//! capability under a published listing. The provider resolves the listing
//! via [`chio_listing::search`], applies the discovered pricing hint, mints
//! a scoped [`CapabilityToken`], and returns an [`AskResponse`] binding the
//! ask to a signed quote. [`accept`] signs acceptance against a pre-verified
//! funds reservation so settlement can verify the canonical bid/ask pair.
//!
//! Every step is fail-closed:
//!
//! - A listing that is revoked / retired / suspended / superseded refuses
//!   to mint.
//! - A listing whose pricing hint is stale (past `expires_at`) refuses to
//!   mint.
//! - A listing whose freshness window has elapsed refuses to mint.
//! - A bid above the provider's advertised ceiling is clamped
//!   (fail-closed: we reject rather than silently quote a lower cap).

use serde::{Deserialize, Serialize};

use crate::capability::{
    scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use crate::crypto::{sha256_hex, Keypair, PublicKey};
use crate::listing::{
    canonical_json_bytes, normalize_namespace, provider_signing_key, GenericListingStatus, Listing,
};
use crate::receipt::lineage::SignedExportEnvelope;

/// Schema for bid requests that the marketplace signs canonically.
pub const BID_REQUEST_SCHEMA: &str = "chio.marketplace.bid-request.v1";

/// Schema for signed ask responses.
pub const ASK_RESPONSE_SCHEMA: &str = "chio.marketplace.ask-response.v1";

/// Schema for accepted bid records.
pub const ACCEPTED_BID_SCHEMA: &str = "chio.marketplace.accepted-bid.v1";

/// Schema for signed funds reservation receipts.
pub const RESERVATION_RECEIPT_SCHEMA: &str = "chio.marketplace.reservation-receipt.v1";

/// Outcome kinds returned when a bid cannot be honored.
#[derive(Debug, thiserror::Error, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "message")]
pub enum BiddingError {
    #[error("bid request invalid: {0}")]
    InvalidRequest(String),
    #[error("bid request signature is not verifiable")]
    BidSignatureInvalid,
    #[error("listing signature is not verifiable")]
    ListingSignatureInvalid,
    #[error("listing pricing hint signature is not verifiable")]
    PricingSignatureInvalid,
    #[error("listing is not active in the marketplace")]
    ListingNotActive,
    #[error("listing is stale: freshness window has elapsed")]
    ListingStale,
    #[error("listing pricing hint has expired")]
    PricingExpired,
    #[error("bid listing id does not match resolved listing")]
    ListingMismatch,
    #[error("bid currency does not match the advertised pricing currency")]
    CurrencyMismatch,
    #[error("bid ceiling is below the quoted price")]
    BidCeilingTooLow,
    #[error("requested scope capability_scope prefix does not match listing")]
    ScopeOutsideListing,
    #[error("requested window is outside the allowed bounds")]
    WindowOutOfBounds,
    #[error("max_total_cost overflow: advertised price * max_invocations exceeds u64")]
    TotalCostOverflow,
    #[error("listing, pricing, or issuer authority is not bound to the provider")]
    AuthorityMismatch,
    #[error("capability token offer signature is not verifiable")]
    TokenSignatureInvalid,
    #[error("funds reservation receipt is invalid for the accepted bid")]
    ReservationReceiptInvalid,
}

fn invalid_request(message: impl Into<String>) -> BiddingError {
    BiddingError::InvalidRequest(message.into())
}

fn validate_required_field(value: &str, field: &str) -> Result<(), BiddingError> {
    if value.trim().is_empty() {
        Err(invalid_request(format!("{field} must not be empty")))
    } else if value.trim() != value {
        Err(invalid_request(format!(
            "{field} must not contain surrounding whitespace"
        )))
    } else {
        Ok(())
    }
}

/// A bid request issued by an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BidRequest {
    pub schema: String,
    pub agent_id: String,
    pub listing_id: String,
    pub max_price_per_call: MonetaryAmount,
    pub window_seconds: u64,
    pub requested_scope: RequestedScope,
    pub issued_at: u64,
}

impl BidRequest {
    pub fn validate(&self) -> Result<(), BiddingError> {
        if self.schema != BID_REQUEST_SCHEMA {
            return Err(invalid_request(format!(
                "unsupported bid request schema: {}",
                self.schema
            )));
        }
        validate_required_field(&self.agent_id, "agent_id")?;
        validate_required_field(&self.listing_id, "listing_id")?;
        if self.max_price_per_call.units == 0 {
            return Err(invalid_request(
                "max_price_per_call.units must be greater than zero",
            ));
        }
        validate_required_field(
            &self.max_price_per_call.currency,
            "max_price_per_call.currency",
        )?;
        if self.window_seconds == 0 {
            return Err(BiddingError::WindowOutOfBounds);
        }
        self.requested_scope.validate()?;
        Ok(())
    }
}

/// Requested scope narrowing for the minted capability token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestedScope {
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    /// Capability scope prefix the listing must advertise.
    pub capability_scope_prefix: String,
}

impl RequestedScope {
    pub fn validate(&self) -> Result<(), BiddingError> {
        validate_required_field(&self.server_id, "requested_scope.server_id")?;
        validate_required_field(&self.tool_name, "requested_scope.tool_name")?;
        validate_required_field(
            &self.capability_scope_prefix,
            "requested_scope.capability_scope_prefix",
        )?;
        Ok(())
    }
}

pub type SignedBidRequest = SignedExportEnvelope<BidRequest>;

/// The provider's signed response quoting a price and minting a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AskResponse {
    pub schema: String,
    pub listing_id: String,
    pub agent_id: String,
    /// Canonicalized SHA-256 digest of the originating [`BidRequest`].
    pub bid_digest: String,
    pub quoted_price: MonetaryAmount,
    /// Minted capability token bound to the agent subject with the
    /// provider's issuer key.
    pub token_offer: CapabilityToken,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub type SignedAskResponse = SignedExportEnvelope<AskResponse>;

/// Settlement acceptance record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedBid {
    pub schema: String,
    pub listing_id: String,
    pub agent_id: String,
    pub bid_digest: String,
    /// Digest of the signed [`AskResponse`] being accepted.
    pub ask_digest: String,
    /// The receipt identifier issued by the kernel when the agent's funds
    /// were reserved for this ask.
    pub bid_receipt_id: String,
    pub quoted_price: MonetaryAmount,
    pub accepted_at: u64,
    pub token_id: String,
    pub token_subject: PublicKey,
    pub token_expires_at: u64,
}

pub type SignedAcceptedBid = SignedExportEnvelope<AcceptedBid>;

/// Signed funds reservation receipt material.
///
/// The open-market crate deliberately does not depend on a receipt store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReservationReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub agent_id: String,
    pub listing_id: String,
    pub ask_digest: String,
    pub reserved_amount: MonetaryAmount,
}

impl ReservationReceipt {
    fn validate(&self) -> Result<(), BiddingError> {
        if self.schema != RESERVATION_RECEIPT_SCHEMA {
            return Err(invalid_request(format!(
                "unsupported reservation receipt schema: {}",
                self.schema
            )));
        }
        validate_required_field(&self.receipt_id, "reservation.receipt_id")?;
        validate_required_field(&self.agent_id, "reservation.agent_id")?;
        validate_required_field(&self.listing_id, "reservation.listing_id")?;
        validate_required_field(
            &self.reserved_amount.currency,
            "reservation.reserved_amount.currency",
        )?;
        if self.reserved_amount.units == 0 {
            return Err(BiddingError::ReservationReceiptInvalid);
        }
        if !is_lowercase_sha256(&self.ask_digest) {
            return Err(BiddingError::ReservationReceiptInvalid);
        }
        Ok(())
    }
}

pub type SignedReservationReceipt = SignedExportEnvelope<ReservationReceipt>;

/// Verified funds reservation witness accepted by the market.
///
/// Construct this through [`VerifiedReservationReceipt::from_signed`] after
/// the caller has selected the expected settlement reservation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReservationReceipt {
    receipt_id: String,
    agent_id: String,
    listing_id: String,
    ask_digest: String,
    reserved_amount: MonetaryAmount,
}

impl VerifiedReservationReceipt {
    pub fn from_signed(
        receipt: &SignedReservationReceipt,
        expected_reservation_authority: &PublicKey,
    ) -> Result<Self, BiddingError> {
        receipt.body.validate()?;
        if &receipt.signer_key != expected_reservation_authority {
            return Err(BiddingError::ReservationReceiptInvalid);
        }
        match receipt.verify_signature() {
            Ok(true) => {}
            _ => return Err(BiddingError::ReservationReceiptInvalid),
        }
        Ok(Self {
            receipt_id: receipt.body.receipt_id.clone(),
            agent_id: receipt.body.agent_id.clone(),
            listing_id: receipt.body.listing_id.clone(),
            ask_digest: receipt.body.ask_digest.clone(),
            reserved_amount: receipt.body.reserved_amount.clone(),
        })
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
}

/// Parameters the provider supplies when minting a token under a bid.
#[derive(Clone)]
pub struct BidMintContext<'a> {
    /// The listing (plus pricing hint, publisher, freshness) the provider
    /// is offering.
    pub listing: &'a Listing,
    /// Issuer key used to sign the minted [`CapabilityToken`] as well as
    /// the enclosing [`SignedAskResponse`].
    pub issuer_keypair: &'a Keypair,
    /// The agent's subject key the token will bind to.
    pub agent_subject: PublicKey,
    /// Opaque, unique token id (the caller supplies UUIDv7-style ids).
    pub token_id: String,
    /// Unix seconds when the provider evaluates the bid. Used as the
    /// `issued_at` on the ask and the minted token.
    pub now: u64,
}

/// Execute the bid/ask flow: validate the request, apply fail-closed checks
/// against the resolved listing, mint a capability token, and return a
/// signed ask response.
pub fn bid(
    request: &SignedBidRequest,
    context: BidMintContext<'_>,
) -> Result<SignedAskResponse, BiddingError> {
    request.body.validate()?;
    match request.verify_signature() {
        Ok(true) => {}
        _ => return Err(BiddingError::BidSignatureInvalid),
    }
    let listing = context.listing;

    // Fail-closed: verify the underlying artifacts haven't been tampered.
    match listing.listing.verify_signature() {
        Ok(true) => {}
        _ => return Err(BiddingError::ListingSignatureInvalid),
    }
    match listing.pricing.verify_signature() {
        Ok(true) => {}
        _ => return Err(BiddingError::PricingSignatureInvalid),
    }

    // Identity checks: bid must reference this listing.
    if listing.listing_id() != request.body.listing_id {
        return Err(BiddingError::ListingMismatch);
    }
    if listing.pricing.body.listing_id != listing.listing_id() {
        return Err(BiddingError::ListingMismatch);
    }
    if normalize_namespace(&listing.pricing.body.namespace)
        != normalize_namespace(&listing.listing.body.namespace)
    {
        return Err(BiddingError::ListingMismatch);
    }
    if listing.pricing.body.provider_operator_id != listing.publisher.operator_id
        || listing.pricing.body.provider_operator_id
            != listing.listing.body.namespace_ownership.owner_id
        || listing.pricing.signer_key != listing.listing.body.namespace_ownership.signer_public_key
        || listing.listing.signer_key != listing.listing.body.namespace_ownership.signer_public_key
    {
        return Err(BiddingError::AuthorityMismatch);
    }
    if context.issuer_keypair.public_key() != *provider_signing_key(listing) {
        return Err(BiddingError::AuthorityMismatch);
    }

    // Fail-closed: revoked/retired/suspended listings can never be minted.
    if !matches!(listing.listing.body.status, GenericListingStatus::Active) {
        return Err(BiddingError::ListingNotActive);
    }
    if !listing.is_admissible_at(context.now) {
        // Decide which fail-closed reason applies so callers can discriminate.
        if !listing.pricing.body.is_live_at(context.now) {
            return Err(BiddingError::PricingExpired);
        }
        return Err(BiddingError::ListingStale);
    }

    let advertised_price = &listing.pricing.body.price_per_call;
    if advertised_price.currency != request.body.max_price_per_call.currency {
        return Err(BiddingError::CurrencyMismatch);
    }
    if request.body.max_price_per_call.units < advertised_price.units {
        return Err(BiddingError::BidCeilingTooLow);
    }
    if !capability_scope_covers(
        &request.body.requested_scope.capability_scope_prefix,
        &listing.pricing.body.capability_scope,
    ) {
        return Err(BiddingError::ScopeOutsideListing);
    }
    if request.body.requested_scope.server_id != listing.listing.body.subject.actor_id {
        return Err(BiddingError::ScopeOutsideListing);
    }

    let issued_at = context.now;
    let expires_at = issued_at
        .checked_add(request.body.window_seconds)
        .ok_or(BiddingError::WindowOutOfBounds)?;

    // Mint a scoped capability token.
    let token_body = CapabilityTokenBody {
        id: context.token_id.clone(),
        issuer: context.issuer_keypair.public_key(),
        subject: context.agent_subject.clone(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: listing.listing.body.subject.actor_id.clone(),
                tool_name: request.body.requested_scope.tool_name.clone(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: request.body.requested_scope.max_invocations,
                max_cost_per_invocation: Some(advertised_price.clone()),
                max_total_cost: match request.body.requested_scope.max_invocations {
                    Some(count) => Some(MonetaryAmount {
                        units: advertised_price
                            .units
                            .checked_mul(u64::from(count))
                            .ok_or(BiddingError::TotalCostOverflow)?,
                        currency: advertised_price.currency.clone(),
                    }),
                    None => None,
                },
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    let token = CapabilityToken::sign(token_body, context.issuer_keypair)
        .map_err(|error| invalid_request(error.to_string()))?;

    let bid_digest = canonical_digest(&request.body)?;

    let ask = AskResponse {
        schema: ASK_RESPONSE_SCHEMA.to_string(),
        listing_id: listing.listing_id().to_string(),
        agent_id: request.body.agent_id.clone(),
        bid_digest,
        quoted_price: advertised_price.clone(),
        token_offer: token,
        issued_at,
        expires_at,
    };
    SignedAskResponse::sign(ask, context.issuer_keypair)
        .map_err(|error| invalid_request(error.to_string()))
}

/// Record signed bid acceptance against a verified settlement reservation.
pub fn accept(
    ask: &SignedAskResponse,
    reservation: &VerifiedReservationReceipt,
    acceptor_keypair: &Keypair,
    accepted_at: u64,
) -> Result<SignedAcceptedBid, BiddingError> {
    if ask.body.schema != ASK_RESPONSE_SCHEMA {
        return Err(invalid_request(format!(
            "unsupported ask response schema: {}",
            ask.body.schema
        )));
    }
    validate_required_field(&reservation.receipt_id, "reservation.receipt_id")?;
    match ask.verify_signature() {
        Ok(true) => {}
        _ => return Err(BiddingError::PricingSignatureInvalid),
    }
    if ask.body.token_offer.issuer != ask.signer_key {
        return Err(BiddingError::AuthorityMismatch);
    }
    match ask.body.token_offer.verify_signature() {
        Ok(true) => {}
        _ => return Err(BiddingError::TokenSignatureInvalid),
    }
    if ask.body.token_offer.issued_at > ask.body.issued_at
        || ask.body.token_offer.expires_at < ask.body.expires_at
    {
        return Err(BiddingError::WindowOutOfBounds);
    }
    if accepted_at < ask.body.issued_at {
        return Err(invalid_request(
            "accepted_at must not precede ask issued_at",
        ));
    }
    if accepted_at >= ask.body.expires_at {
        return Err(BiddingError::PricingExpired);
    }
    if acceptor_keypair.public_key() != ask.body.token_offer.subject {
        return Err(BiddingError::AuthorityMismatch);
    }
    let ask_digest = canonical_digest(&ask.body)?;
    let required_reservation_amount = token_offer_total_liability(&ask.body)?;
    if reservation.agent_id != ask.body.agent_id
        || reservation.listing_id != ask.body.listing_id
        || reservation.ask_digest != ask_digest
        || reservation.reserved_amount.currency != required_reservation_amount.currency
        || reservation.reserved_amount.units < required_reservation_amount.units
    {
        return Err(BiddingError::ReservationReceiptInvalid);
    }
    let accepted = AcceptedBid {
        schema: ACCEPTED_BID_SCHEMA.to_string(),
        listing_id: ask.body.listing_id.clone(),
        agent_id: ask.body.agent_id.clone(),
        bid_digest: ask.body.bid_digest.clone(),
        ask_digest,
        bid_receipt_id: reservation.receipt_id.clone(),
        quoted_price: ask.body.quoted_price.clone(),
        accepted_at,
        token_id: ask.body.token_offer.id.clone(),
        token_subject: ask.body.token_offer.subject.clone(),
        token_expires_at: ask.body.token_offer.expires_at,
    };
    let signed = SignedAcceptedBid::sign(accepted, acceptor_keypair)
        .map_err(|error| invalid_request(error.to_string()))?;
    match signed.verify_signature() {
        Ok(true) => Ok(signed),
        _ => Err(invalid_request(
            "signed accepted bid signature is not verifiable",
        )),
    }
}

fn token_offer_total_liability(ask: &AskResponse) -> Result<MonetaryAmount, BiddingError> {
    let mut total_units = 0_u64;
    for grant in &ask.token_offer.scope.grants {
        let Some(max_total_cost) = grant.max_total_cost.as_ref() else {
            return Err(BiddingError::ReservationReceiptInvalid);
        };
        if max_total_cost.currency != ask.quoted_price.currency {
            return Err(BiddingError::ReservationReceiptInvalid);
        }
        total_units = total_units
            .checked_add(max_total_cost.units)
            .ok_or(BiddingError::TotalCostOverflow)?;
    }
    if total_units == 0 {
        return Err(BiddingError::ReservationReceiptInvalid);
    }
    Ok(MonetaryAmount {
        units: total_units,
        currency: ask.quoted_price.currency.clone(),
    })
}

fn capability_scope_covers(candidate: &str, advertised: &str) -> bool {
    let candidate_segments: Vec<&str> = candidate.split(':').collect();
    let advertised_segments: Vec<&str> = advertised.split(':').collect();
    if candidate_segments.iter().any(|segment| segment.is_empty())
        || advertised_segments.iter().any(|segment| segment.is_empty())
    {
        return false;
    }
    if advertised_segments.len() > candidate_segments.len() {
        return false;
    }
    advertised_segments
        .iter()
        .zip(candidate_segments.iter())
        .all(|(expected, actual)| expected == actual)
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String, BiddingError> {
    let bytes = canonical_json_bytes(value).map_err(|error| invalid_request(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests;
