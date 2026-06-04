//! Capability marketplace bid/ask protocol.
//!
//! A [`BidRequest`] is an agent's signed offer to purchase a time-bounded
//! capability under a published listing. The provider resolves the listing
//! via [`chio_listing::search`], applies the discovered pricing hint, mints
//! a scoped [`CapabilityToken`], and returns an [`AskResponse`] binding the
//! ask to a signed quote. [`accept`] records acceptance so settlement can
//! reference the canonical bid/ask pair.
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
    CapabilityToken, CapabilityTokenBody, ChioScope, MonetaryAmount, Operation, ToolGrant,
};
use crate::crypto::{sha256_hex, Keypair, PublicKey};
use crate::listing::{
    canonical_json_bytes, normalize_namespace, provider_signing_key, GenericListingStatus, Listing,
};
use crate::receipt::SignedExportEnvelope;

/// Schema for bid requests that the marketplace signs canonically.
pub const BID_REQUEST_SCHEMA: &str = "chio.marketplace.bid-request.v1";

/// Schema for signed ask responses.
pub const ASK_RESPONSE_SCHEMA: &str = "chio.marketplace.ask-response.v1";

/// Schema for accepted bid records.
pub const ACCEPTED_BID_SCHEMA: &str = "chio.marketplace.accepted-bid.v1";

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
    /// The receipt identifier issued by the kernel for the acceptance
    /// event; this links the marketplace record to the existing
    /// settlement flow without adding new receipt body fields.
    pub bid_receipt_id: String,
    pub quoted_price: MonetaryAmount,
    pub accepted_at: u64,
    pub token_id: String,
    pub token_subject: PublicKey,
    pub token_expires_at: u64,
}

pub type SignedAcceptedBid = SignedExportEnvelope<AcceptedBid>;

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

/// Record bid acceptance against an existing settlement receipt identifier.
/// The `bid_receipt_id` argument is the identifier of the receipt that the
/// kernel signed when the agent's funds were reserved; this keeps the
/// marketplace record referenceable without introducing new receipt body
/// fields.
pub fn accept(
    ask: &SignedAskResponse,
    bid_receipt_id: &str,
    accepted_at: u64,
) -> Result<AcceptedBid, BiddingError> {
    if ask.body.schema != ASK_RESPONSE_SCHEMA {
        return Err(invalid_request(format!(
            "unsupported ask response schema: {}",
            ask.body.schema
        )));
    }
    validate_required_field(bid_receipt_id, "bid_receipt_id")?;
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
    Ok(AcceptedBid {
        schema: ACCEPTED_BID_SCHEMA.to_string(),
        listing_id: ask.body.listing_id.clone(),
        agent_id: ask.body.agent_id.clone(),
        bid_digest: ask.body.bid_digest.clone(),
        ask_digest: canonical_digest(&ask.body)?,
        bid_receipt_id: bid_receipt_id.to_string(),
        quoted_price: ask.body.quoted_price.clone(),
        accepted_at,
        token_id: ask.body.token_offer.id.clone(),
        token_subject: ask.body.token_offer.subject.clone(),
        token_expires_at: ask.body.token_offer.expires_at,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn invalid_request_helper_preserves_variant_message() {
        assert_eq!(
            invalid_request("agent_id must not be empty"),
            BiddingError::InvalidRequest("agent_id must not be empty".to_string())
        );
    }

    #[test]
    fn bid_request_rejects_padded_required_fields() {
        let mut request = bid_request(" agent-alpha", 200, 300, 120);
        let error = request
            .validate()
            .test_expect_err("padded agent id rejected");
        assert!(
            matches!(error, BiddingError::InvalidRequest(message) if message.contains("agent_id"))
        );

        request = bid_request("agent-alpha", 200, 300, 120);
        request.requested_scope.tool_name = "search ".to_string();
        let error = request
            .validate()
            .test_expect_err("padded tool name rejected");
        assert!(
            matches!(error, BiddingError::InvalidRequest(message) if message.contains("tool_name"))
        );
    }

    fn namespace(keypair: &Keypair) -> GenericNamespaceOwnership {
        GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: "operator-a".to_string(),
            owner_name: Some("Operator A".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: keypair.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        }
    }

    fn listing(
        keypair: &Keypair,
        listing_id: &str,
        status: GenericListingStatus,
    ) -> SignedGenericListing {
        let body = GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: listing_id.to_string(),
            namespace: "https://registry.chio.example".to_string(),
            published_at: 10,
            expires_at: Some(5_000),
            status,
            namespace_ownership: namespace(keypair),
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: "demo-server".to_string(),
                display_name: None,
                metadata_url: None,
                resolution_url: None,
                homepage_url: None,
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: format!("artifact-{listing_id}"),
                source_artifact_sha256: format!("sha-{listing_id}"),
            },
            boundary: GenericListingBoundary::default(),
        };
        SignedGenericListing::sign(body, keypair).test_expect("sign listing")
    }

    fn publisher() -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: "operator-a".to_string(),
            operator_name: Some("Operator A".to_string()),
            registry_url: "https://operator-a.chio.example".to_string(),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn fresh_freshness() -> GenericListingReplicaFreshness {
        GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 20,
            max_age_secs: 300,
            valid_until: 1_000,
            generated_at: 100,
        }
    }

    fn pricing(
        signer: &Keypair,
        listing_id: &str,
        units: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> SignedListingPricingHint {
        SignedListingPricingHint::sign(
            ListingPricingHint {
                schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                listing_id: listing_id.to_string(),
                namespace: "https://registry.chio.example".to_string(),
                provider_operator_id: "operator-a".to_string(),
                capability_scope: "tools:search".to_string(),
                price_per_call: MonetaryAmount {
                    units,
                    currency: "USD".to_string(),
                },
                sla: ListingSla {
                    max_latency_ms: 250,
                    availability_bps: 9_990,
                    throughput_rps: 100,
                },
                revocation_rate_bps: 5,
                recent_receipts_volume: 1_000,
                issued_at,
                expires_at,
            },
            signer,
        )
        .test_expect("sign hint")
    }

    fn listing_entry(
        _registry_keypair: &Keypair,
        operator_keypair: &Keypair,
        status: GenericListingStatus,
        price_units: u64,
        pricing_issued_at: u64,
        pricing_expires_at: u64,
    ) -> Listing {
        Listing {
            rank: 1,
            listing: listing(operator_keypair, "listing-1", status),
            pricing: pricing(
                operator_keypair,
                "listing-1",
                price_units,
                pricing_issued_at,
                pricing_expires_at,
            ),
            publisher: publisher(),
            freshness: fresh_freshness(),
        }
    }

    fn bid_request(agent_id: &str, max_units: u64, window: u64, now: u64) -> BidRequest {
        BidRequest {
            schema: BID_REQUEST_SCHEMA.to_string(),
            agent_id: agent_id.to_string(),
            listing_id: "listing-1".to_string(),
            max_price_per_call: MonetaryAmount {
                units: max_units,
                currency: "USD".to_string(),
            },
            window_seconds: window,
            requested_scope: RequestedScope {
                server_id: "demo-server".to_string(),
                tool_name: "search".to_string(),
                max_invocations: Some(10),
                capability_scope_prefix: "tools:search".to_string(),
            },
            issued_at: now,
        }
    }

    fn signed_bid_request(
        agent_keypair: &Keypair,
        agent_id: &str,
        max_units: u64,
        window: u64,
        now: u64,
    ) -> SignedBidRequest {
        SignedBidRequest::sign(bid_request(agent_id, max_units, window, now), agent_keypair)
            .test_expect("sign bid")
    }

    fn resign_bid_request(agent_keypair: &Keypair, request: &BidRequest) -> SignedBidRequest {
        SignedBidRequest::sign(request.clone(), agent_keypair).test_expect("re-sign bid")
    }

    #[test]
    fn bid_happy_path_mints_scoped_capability_token() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);

        let ask = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect("bid succeeds");

        assert_eq!(ask.body.listing_id, "listing-1");
        assert_eq!(ask.body.agent_id, "agent-alpha");
        assert_eq!(ask.body.quoted_price.units, 100);
        assert_eq!(ask.body.token_offer.id, "token-1");
        assert_eq!(ask.body.token_offer.scope.grants.len(), 1);
        assert_eq!(
            ask.body.token_offer.scope.grants[0].server_id,
            "demo-server"
        );
        assert_eq!(
            ask.body.token_offer.scope.grants[0]
                .max_cost_per_invocation
                .as_ref()
                .test_expect("max cost")
                .units,
            100
        );
        // `max_total_cost` computed from invocations * per-call.
        assert_eq!(
            ask.body.token_offer.scope.grants[0]
                .max_total_cost
                .as_ref()
                .test_expect("max total")
                .units,
            1_000
        );
        assert!(ask.verify_signature().test_expect("verify ask"));
        assert!(ask
            .body
            .token_offer
            .verify_signature()
            .test_expect("verify token"));
    }

    #[test]
    fn bid_rejects_unbound_token_issuer() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let attacker_issuer = Keypair::generate();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &attacker_issuer,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("unbound issuer rejected");

        assert_eq!(error, BiddingError::AuthorityMismatch);
    }

    #[test]
    fn bid_rejects_scope_widening_outside_listing_server() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let mut request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
        request.body.requested_scope.server_id = "other-server".to_string();
        request = resign_bid_request(&agent_keypair, &request.body);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("scope widening rejected");
        assert_eq!(error, BiddingError::ScopeOutsideListing);
    }

    #[test]
    fn bid_fails_closed_on_revoked_listing() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Revoked,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("revoked listing rejected");
        assert_eq!(error, BiddingError::ListingNotActive);
    }

    #[test]
    fn bid_fails_closed_on_stale_pricing_hint() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        // Pricing hint expires at 200.
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            200,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 250);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 250,
            },
        )
        .test_expect_err("stale pricing rejected");
        assert_eq!(error, BiddingError::PricingExpired);
    }

    #[test]
    fn bid_fails_closed_on_tampered_listing_signature() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let mut listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        // Tamper the signed listing body.
        listing.listing.body.subject.actor_id = "forged-server".to_string();
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("tampered listing rejected");
        assert_eq!(error, BiddingError::ListingSignatureInvalid);
    }

    #[test]
    fn bid_fails_closed_when_max_price_below_advertised() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        // Ceiling below advertised units (100).
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 50, 300, 120);

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("under-priced bid rejected");
        assert_eq!(error, BiddingError::BidCeilingTooLow);
    }

    #[test]
    fn accept_records_receipt_and_verifies_ask_signature() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
        let ask = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect("bid succeeds");

        let accepted = accept(&ask, "receipt-42", 130).test_expect("accept succeeds");
        assert_eq!(accepted.listing_id, "listing-1");
        assert_eq!(accepted.bid_receipt_id, "receipt-42");
        assert_eq!(accepted.agent_id, "agent-alpha");
        assert_eq!(accepted.token_id, "token-1");
        assert!(!accepted.ask_digest.is_empty());
        assert!(!accepted.bid_digest.is_empty());
    }

    #[test]
    fn accept_rejects_tampered_ask_signature() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
        let mut ask = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect("bid succeeds");
        ask.body.agent_id = "agent-evil".to_string();

        let error = accept(&ask, "receipt-42", 130).test_expect_err("tampered ask rejected");
        assert_eq!(error, BiddingError::PricingSignatureInvalid);
    }

    #[test]
    fn accept_rejects_tampered_token_offer_signature() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
        let mut ask = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect("bid succeeds");
        ask.body.token_offer.expires_at = ask.body.expires_at + 1;
        ask = SignedAskResponse::sign(ask.body, &issuer_keypair).test_expect("re-sign ask");

        let error =
            accept(&ask, "receipt-42", 130).test_expect_err("tampered token offer rejected");
        assert_eq!(error, BiddingError::TokenSignatureInvalid);
    }

    #[test]
    fn accept_rejects_expired_ask() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 50, 120);
        let ask = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect("bid succeeds");
        // window_seconds = 50; ask expires at 170.
        let error = accept(&ask, "receipt-42", 200).test_expect_err("expired ask rejected");
        assert_eq!(error, BiddingError::PricingExpired);
    }

    #[test]
    fn bid_rejects_tampered_bid_signature() {
        let registry_keypair = Keypair::generate();
        let operator_keypair = Keypair::generate();
        let issuer_keypair = operator_keypair.clone();
        let agent_keypair = Keypair::generate();
        let listing = listing_entry(
            &registry_keypair,
            &operator_keypair,
            GenericListingStatus::Active,
            100,
            110,
            600,
        );
        let mut request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
        request.body.window_seconds = 999;

        let error = bid(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &issuer_keypair,
                agent_subject: agent_keypair.public_key(),
                token_id: "token-1".to_string(),
                now: 120,
            },
        )
        .test_expect_err("tampered bid rejected");
        assert_eq!(error, BiddingError::BidSignatureInvalid);
    }
}
