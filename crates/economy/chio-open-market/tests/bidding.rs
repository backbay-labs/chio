//! Integration coverage for the capability marketplace bid/ask protocol.

use chio_open_market::{
    bidding::{
        accept, bid, BidMintContext, BidRequest, BiddingError, RequestedScope, ReservationReceipt,
        SignedAskResponse, SignedBidRequest, SignedReservationReceipt, VerifiedReservationReceipt,
        ACCEPTED_BID_SCHEMA, ASK_RESPONSE_SCHEMA, BID_REQUEST_SCHEMA, RESERVATION_RECEIPT_SCHEMA,
    },
    canonical_json_bytes,
    capability::scope::MonetaryAmount,
    crypto::{sha256_hex, Keypair},
    listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    },
};

use chio_test_support::prelude::*;

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

fn signed_listing(
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

fn fresh() -> GenericListingReplicaFreshness {
    GenericListingReplicaFreshness {
        state: GenericListingFreshnessState::Fresh,
        age_secs: 20,
        max_age_secs: 300,
        valid_until: 1_000,
        generated_at: 100,
    }
}

fn pricing_hint(
    operator: &Keypair,
    listing_id: &str,
    units: u64,
    issued_at: u64,
    expires_at: u64,
) -> SignedListingPricingHint {
    pricing_hint_with_scope(
        operator,
        listing_id,
        units,
        issued_at,
        expires_at,
        "tools:search",
    )
}

fn pricing_hint_with_scope(
    operator: &Keypair,
    listing_id: &str,
    units: u64,
    issued_at: u64,
    expires_at: u64,
    capability_scope: &str,
) -> SignedListingPricingHint {
    SignedListingPricingHint::sign(
        ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
            listing_id: listing_id.to_string(),
            namespace: "https://registry.chio.example".to_string(),
            provider_operator_id: "operator-a".to_string(),
            capability_scope: capability_scope.to_string(),
            price_per_call: MonetaryAmount {
                units,
                currency: "USD".to_string(),
            },
            sla: ListingSla {
                max_latency_ms: 200,
                availability_bps: 9_995,
                throughput_rps: 100,
            },
            revocation_rate_bps: 5,
            recent_receipts_volume: 2_500,
            issued_at,
            expires_at,
        },
        operator,
    )
    .test_expect("sign hint")
}

fn listing_entry(
    _registry_keypair: &Keypair,
    operator_keypair: &Keypair,
    status: GenericListingStatus,
    price_units: u64,
    pricing_expires_at: u64,
) -> Listing {
    Listing {
        rank: 1,
        listing: signed_listing(operator_keypair, "listing-1", status),
        pricing: pricing_hint(
            operator_keypair,
            "listing-1",
            price_units,
            110,
            pricing_expires_at,
        ),
        publisher: publisher(),
        freshness: fresh(),
    }
}

fn bid_request(agent_id: &str, max_units: u64, window_seconds: u64, now: u64) -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: agent_id.to_string(),
        payout_destination: None,
        listing_id: "listing-1".to_string(),
        max_price_per_call: MonetaryAmount {
            units: max_units,
            currency: "USD".to_string(),
        },
        window_seconds,
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
    window_seconds: u64,
    now: u64,
) -> SignedBidRequest {
    SignedBidRequest::sign(
        bid_request(agent_id, max_units, window_seconds, now),
        agent_keypair,
    )
    .test_expect("sign bid")
}

fn reservation_receipt(ask: &SignedAskResponse) -> ReservationReceipt {
    ReservationReceipt {
        schema: RESERVATION_RECEIPT_SCHEMA.to_string(),
        receipt_id: "receipt-from-settlement".to_string(),
        agent_id: ask.body.agent_id.clone(),
        listing_id: ask.body.listing_id.clone(),
        ask_digest: sha256_hex(
            &canonical_json_bytes(&ask.body).test_expect("canonical ask response bytes"),
        ),
        reserved_amount: total_token_liability(ask),
    }
}

fn total_token_liability(ask: &SignedAskResponse) -> MonetaryAmount {
    let mut units = 0_u64;
    for grant in &ask.body.token_offer.scope.grants {
        let max_total_cost = grant
            .max_total_cost
            .as_ref()
            .test_expect("token grant has max total cost");
        assert_eq!(max_total_cost.currency, ask.body.quoted_price.currency);
        units = units
            .checked_add(max_total_cost.units)
            .test_expect("token liability does not overflow");
    }
    MonetaryAmount {
        units,
        currency: ask.body.quoted_price.currency.clone(),
    }
}

fn verified_reservation_receipt(
    ask: &SignedAskResponse,
    reservation_keypair: &Keypair,
) -> VerifiedReservationReceipt {
    let receipt = reservation_receipt(ask);
    let signed = SignedReservationReceipt::sign(receipt, reservation_keypair)
        .test_expect("sign reservation");
    VerifiedReservationReceipt::from_signed(&signed, &reservation_keypair.public_key())
        .test_expect("verify reservation")
}

fn verified_reservation_from_body(
    receipt: ReservationReceipt,
    reservation_keypair: &Keypair,
) -> VerifiedReservationReceipt {
    let signed = SignedReservationReceipt::sign(receipt, reservation_keypair)
        .test_expect("sign reservation");
    VerifiedReservationReceipt::from_signed(&signed, &reservation_keypair.public_key())
        .test_expect("verify reservation")
}

fn resign_bid_request(agent_keypair: &Keypair, request: &BidRequest) -> SignedBidRequest {
    SignedBidRequest::sign(request.clone(), agent_keypair).test_expect("re-sign bid")
}

#[test]
fn bid_happy_path_mints_token_and_accept_records_settlement() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 600, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    assert_eq!(ask.body.schema, ASK_RESPONSE_SCHEMA);
    assert_eq!(ask.body.quoted_price.units, 100);
    assert!(ask.verify_signature().test_expect("verify ask"));

    let reservation_receipt = verified_reservation_receipt(&ask, &issuer_keypair);
    let accepted =
        accept(&ask, &reservation_receipt, &agent_keypair, 130).test_expect("accept succeeds");
    assert_eq!(accepted.body.schema, ACCEPTED_BID_SCHEMA);
    assert_eq!(accepted.body.bid_receipt_id, "receipt-from-settlement");
    assert_eq!(accepted.body.quoted_price.units, 100);
    assert!(accepted
        .verify_signature()
        .test_expect("verify accepted bid"));
}

#[test]
fn accept_rejects_timestamp_before_ask_issuance() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let reservation_receipt = verified_reservation_receipt(&ask, &issuer_keypair);
    let error = accept(&ask, &reservation_receipt, &agent_keypair, 119)
        .test_expect_err("acceptance before issuance rejected");
    assert_eq!(
        error,
        BiddingError::InvalidRequest("accepted_at must not precede ask issued_at".to_string())
    );
}

#[test]
fn accept_rejects_bogus_reservation_receipt() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let mut receipt = reservation_receipt(&ask);
    receipt.ask_digest = "0".repeat(64);
    let reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &agent_keypair, 130)
        .test_expect_err("bogus reservation rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn reservation_receipt_verification_rejects_wrong_authority() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let wrong_authority_keypair = Keypair::generate();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let signed = SignedReservationReceipt::sign(reservation_receipt(&ask), &issuer_keypair)
        .test_expect("sign reservation");
    let error =
        VerifiedReservationReceipt::from_signed(&signed, &wrong_authority_keypair.public_key())
            .test_expect_err("wrong reservation authority rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn accept_rejects_underfunded_reservation_receipt() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let mut receipt = reservation_receipt(&ask);
    receipt.reserved_amount.units -= 1;
    let reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &agent_keypair, 130)
        .test_expect_err("underfunded reservation rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn accept_rejects_single_call_reservation_for_multi_invocation_token() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    assert_eq!(
        total_token_liability(&ask).units,
        ask.body.quoted_price.units * 10
    );

    let mut receipt = reservation_receipt(&ask);
    receipt.reserved_amount = ask.body.quoted_price.clone();
    let reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &agent_keypair, 130)
        .test_expect_err("single-call reservation rejected for multi-call token");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn accept_rejects_reservation_identity_mismatch() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let mut receipt = reservation_receipt(&ask);
    receipt.agent_id = "agent-other".to_string();
    let bad_reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &bad_reservation_receipt, &agent_keypair, 130)
        .test_expect_err("mismatched reservation agent rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));

    let mut receipt = reservation_receipt(&ask);
    receipt.listing_id = "listing-other".to_string();
    let reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &agent_keypair, 130)
        .test_expect_err("mismatched reservation listing rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn accept_rejects_reservation_currency_mismatch() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");

    let mut receipt = reservation_receipt(&ask);
    receipt.reserved_amount.currency = "EUR".to_string();
    let reservation_receipt = verified_reservation_from_body(receipt, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &agent_keypair, 130)
        .test_expect_err("mismatched reservation currency rejected");
    assert!(matches!(error, BiddingError::ReservationReceiptInvalid));
}

#[test]
fn bid_fails_closed_on_stale_listing_freshness() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let mut listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    listing.freshness.state = GenericListingFreshnessState::Stale;
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("stale listing rejected");
    assert_eq!(error, BiddingError::ListingStale);
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
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("revoked listing rejected");
    assert_eq!(error, BiddingError::ListingNotActive);
}

#[test]
fn bid_refuses_mismatched_listing_id() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let mut request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    request.body.listing_id = "listing-999".to_string();
    request = resign_bid_request(&agent_keypair, &request.body);

    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("mismatched listing rejected");
    assert_eq!(error, BiddingError::ListingMismatch);
}

#[test]
fn bid_allows_deeper_scope_prefix_without_rewriting_tool_name() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let mut listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    listing.pricing = pricing_hint_with_scope(
        &operator_keypair,
        "listing-1",
        100,
        110,
        600,
        "tools:search:premium",
    );

    let mut request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 600, 120);
    request.body.requested_scope.capability_scope_prefix = "tools:search:premium".to_string();
    request.body.requested_scope.tool_name = "search".to_string();
    request = resign_bid_request(&agent_keypair, &request.body);

    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-premium".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds for deeper capability scope");

    assert_eq!(ask.body.token_offer.scope.grants[0].tool_name, "search");
}

#[test]
fn bid_rejects_sibling_scope_prefixes() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );

    let mut request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 600, 120);
    request.body.requested_scope.capability_scope_prefix = "tools:searchable".to_string();
    request = resign_bid_request(&agent_keypair, &request.body);

    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-sibling".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("sibling scope should be rejected");

    assert_eq!(error, BiddingError::ScopeOutsideListing);
}

#[test]
fn accept_refuses_empty_bid_receipt_id() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    let mut receipt = reservation_receipt(&ask);
    receipt.receipt_id = String::new();
    let signed =
        SignedReservationReceipt::sign(receipt, &issuer_keypair).test_expect("sign reservation");
    let error = VerifiedReservationReceipt::from_signed(&signed, &issuer_keypair.public_key())
        .test_expect_err("empty receipt rejected");
    assert!(matches!(error, BiddingError::InvalidRequest(_)));
}

#[test]
fn accept_rejects_non_agent_acceptor_signature() {
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        100,
        600,
    );
    let request = signed_bid_request(&agent_keypair, "agent-alpha", 200, 300, 120);
    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-abc".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("bid succeeds");
    let reservation_receipt = verified_reservation_receipt(&ask, &issuer_keypair);

    let error = accept(&ask, &reservation_receipt, &issuer_keypair, 130)
        .test_expect_err("provider cannot sign agent acceptance");
    assert_eq!(error, BiddingError::AuthorityMismatch);
}

#[test]
fn bid_rejects_max_total_cost_overflow_instead_of_silently_saturating() {
    // Minting a token must fail-closed when `advertised_price *
    // max_invocations` overflows u64, rather than saturating the cost
    // ceiling at u64::MAX and accepting the bid.
    let registry_keypair = Keypair::generate();
    let operator_keypair = Keypair::generate();
    let issuer_keypair = operator_keypair.clone();
    let agent_keypair = Keypair::generate();
    // Advertise a price near the top of u64; any non-trivial
    // max_invocations will overflow the multiplication.
    let listing = listing_entry(
        &registry_keypair,
        &operator_keypair,
        GenericListingStatus::Active,
        u64::MAX / 2,
        600,
    );
    let mut bid_body = bid_request("agent-alpha", u64::MAX, 300, 120);
    bid_body.requested_scope.max_invocations = Some(u32::MAX);
    let request = SignedBidRequest::sign(bid_body, &agent_keypair).test_expect("sign overflow bid");

    let error = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &issuer_keypair,
            agent_subject: agent_keypair.public_key(),
            token_id: "token-overflow".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect_err("overflowing total cost is rejected");
    assert_eq!(error, BiddingError::TotalCostOverflow);
}
