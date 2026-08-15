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
    assert!(matches!(error, BiddingError::InvalidRequest(message) if message.contains("agent_id")));

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

fn reservation_for(
    ask: &SignedAskResponse,
    receipt_id: &str,
    reservation_keypair: &Keypair,
) -> VerifiedReservationReceipt {
    let receipt = ReservationReceipt {
        schema: RESERVATION_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.to_string(),
        agent_id: ask.body.agent_id.clone(),
        listing_id: ask.body.listing_id.clone(),
        ask_digest: canonical_digest(&ask.body).test_expect("ask digest"),
        reserved_amount: token_offer_total_liability(&ask.body).test_expect("total liability"),
    };
    let signed = SignedReservationReceipt::sign(receipt, reservation_keypair)
        .test_expect("sign reservation");
    VerifiedReservationReceipt::from_signed(&signed, &reservation_keypair.public_key())
        .test_expect("verify reservation")
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
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
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let reservation = reservation_for(&ask, "receipt-42", &issuer_keypair);
    let accepted = accept(&ask, &reservation, &agent_keypair, 130).test_expect("accept succeeds");
    assert_eq!(accepted.body.listing_id, "listing-1");
    assert_eq!(accepted.body.bid_receipt_id, "receipt-42");
    assert_eq!(accepted.body.agent_id, "agent-alpha");
    assert_eq!(accepted.body.token_id, "token-1");
    assert!(!accepted.body.ask_digest.is_empty());
    assert!(!accepted.body.bid_digest.is_empty());
    assert!(accepted
        .verify_signature()
        .test_expect("verify accepted bid"));
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
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    ask.body.agent_id = "agent-evil".to_string();

    let reservation = reservation_for(&ask, "receipt-42", &issuer_keypair);
    let error =
        accept(&ask, &reservation, &agent_keypair, 130).test_expect_err("tampered ask rejected");
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
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    ask.body.token_offer.expires_at = ask.body.expires_at + 1;
    ask = SignedAskResponse::sign(ask.body, &issuer_keypair).test_expect("re-sign ask");

    let reservation = reservation_for(&ask, "receipt-42", &issuer_keypair);
    let error = accept(&ask, &reservation, &agent_keypair, 130)
        .test_expect_err("tampered token offer rejected");
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
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    // window_seconds = 50; ask expires at 170.
    let reservation = reservation_for(&ask, "receipt-42", &issuer_keypair);
    let error =
        accept(&ask, &reservation, &agent_keypair, 200).test_expect_err("expired ask rejected");
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
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("tampered bid rejected");
    assert_eq!(error, BiddingError::BidSignatureInvalid);
}
