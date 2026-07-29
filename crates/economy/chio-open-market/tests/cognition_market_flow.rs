//! Coverage for the parts of a cognition-market purchase that ride the
//! generic marketplace path: a finding listing clears the real `bid()`
//! flow under the colon-segment scope convention, the bid shape needs no
//! finding-specific fields, and the buyer-local bid ceiling is
//! deterministic and budget-capped.
//!
//! The admission-gated and delivery-committed mint paths are covered by
//! `tests/finding_admission.rs`; the reveal-time purchase-context verifier
//! by `tests/purchase_verification.rs`; and publish through discovery,
//! reservation, reveal, and settlement by the control-plane wedge purchase
//! test in `chio-control-plane`.
//!
//! `docs/adr/ADR-0017-cognition-market-finding-artifacts.md` describes the
//! artifact family these tests buy against.

use chio_finding::{
    compute_finding_id, sign_finding, verify_finding, Finding, FindingDescriptor,
    FindingEvidenceClass, FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
};
use chio_open_market::{
    bidding::{
        bid, BidMintContext, BidRequest, BiddingError, RequestedScope, SignedBidRequest,
        ASK_RESPONSE_SCHEMA, BID_REQUEST_SCHEMA,
    },
    capability::scope::MonetaryAmount,
    crypto::Keypair,
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

const FINDING_SERVER_ID: &str = "finding-server.seller.example";
const FINDING_LISTING_ID: &str = "listing-finding-bid-path-0001";

fn hex64(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

/// Colon-segment scope for one finding, per the real marketplace
/// semantics: `capability_scope_covers` splits on `:` and requires the
/// advertised scope to be a segment-prefix of the requested one.
fn finding_scope(finding: &Finding) -> String {
    format!("finding:{}", finding.finding_id)
}

/// Buyer-local elicitation arithmetic: a supplied re-derivation estimate
/// discounted by planner-owned priors and capped by a supplied budget
/// remainder. No authenticated quote producer or authoritative allocation
/// is wired here.
struct FindingBidBasis {
    rederivation_estimate_units: u64,
    would_have_run_bps: u16,
    sibling_redundancy_bps: u16,
    guarantee_class_bps: u16,
    budget_remaining_units: u64,
}

fn finding_bid_ceiling(basis: &FindingBidBasis) -> u64 {
    const BPS: u128 = 10_000;
    let would = u128::from(basis.would_have_run_bps.min(10_000));
    let keep = BPS - u128::from(basis.sibling_redundancy_bps.min(10_000));
    let class = u128::from(basis.guarantee_class_bps.min(10_000));
    let discounted =
        u128::from(basis.rederivation_estimate_units) * would / BPS * keep / BPS * class / BPS;
    u64::try_from(discounted)
        .unwrap_or(u64::MAX)
        .min(basis.budget_remaining_units)
}

fn sealed_negative_result() -> Finding {
    let issuer = Keypair::from_seed(&[11_u8; 32]);
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#flaky-suite-investigation".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::NullResult,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: vec!["receipt-0001".to_string(), "receipt-0002".to_string()],
        evidence_checkpoint_ref: "checkpoint-0001".to_string(),
        evidence_cost: MonetaryAmount {
            units: 4_200,
            currency: "USD".to_string(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(hex64('c')),
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-listing-slashable-01".to_string(),
        status_feed_ref: "finding-status-feed-01".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: 1_784_880_000,
        expires_at: 1_792_656_000,
        signature: String::new(),
    };
    finding.finding_id = match compute_finding_id(&finding) {
        Ok(finding_id) => finding_id,
        Err(err) => panic!("finding id computation failed: {err}"),
    };
    match sign_finding(finding, &issuer) {
        Ok(finding) => finding,
        Err(err) => panic!("finding signing failed: {err}"),
    }
}

/// Marketplace fixtures for the bid-path test, mirroring the construction
/// in `tests/bidding.rs` with finding-flavored values. The listed subject
/// is the seller's finding server under the existing `ToolServer` actor
/// kind, so no listing-schema change is involved.
fn finding_namespace(keypair: &Keypair) -> GenericNamespaceOwnership {
    GenericNamespaceOwnership {
        namespace: "https://registry.seller.example".to_string(),
        owner_id: "seller-operator".to_string(),
        owner_name: Some("Seller Operator".to_string()),
        registry_url: "https://registry.seller.example".to_string(),
        signer_public_key: keypair.public_key(),
        registered_at: 1,
        transferred_from_owner_id: None,
    }
}

fn signed_finding_listing(keypair: &Keypair, finding: &Finding) -> SignedGenericListing {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: FINDING_LISTING_ID.to_string(),
        namespace: "https://registry.seller.example".to_string(),
        published_at: 10,
        expires_at: Some(5_000),
        status: GenericListingStatus::Active,
        namespace_ownership: finding_namespace(keypair),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: FINDING_SERVER_ID.to_string(),
            display_name: Some("Finding server".to_string()),
            metadata_url: Some(format!(
                "https://registry.seller.example/finding/{}",
                finding.finding_id
            )),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: format!("artifact-{FINDING_LISTING_ID}"),
            source_artifact_sha256: format!("sha-{FINDING_LISTING_ID}"),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(body, keypair).test_expect("sign finding listing")
}

fn finding_listing_entry(operator: &Keypair, finding: &Finding, price_units: u64) -> Listing {
    Listing {
        rank: 1,
        listing: signed_finding_listing(operator, finding),
        pricing: SignedListingPricingHint::sign(
            ListingPricingHint {
                schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                listing_id: FINDING_LISTING_ID.to_string(),
                namespace: "https://registry.seller.example".to_string(),
                provider_operator_id: "seller-operator".to_string(),
                capability_scope: finding_scope(finding),
                price_per_call: MonetaryAmount {
                    units: price_units,
                    currency: "USD".to_string(),
                },
                sla: ListingSla {
                    max_latency_ms: 200,
                    availability_bps: 9_995,
                    throughput_rps: 100,
                },
                revocation_rate_bps: 5,
                recent_receipts_volume: 2_500,
                issued_at: 110,
                expires_at: 600,
            },
            operator,
        )
        .test_expect("sign finding pricing hint"),
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: "seller-operator".to_string(),
            operator_name: Some("Seller Operator".to_string()),
            registry_url: "https://registry.seller.example".to_string(),
            upstream_registry_urls: Vec::new(),
        },
        freshness: GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 20,
            max_age_secs: 300,
            valid_until: 1_000,
            generated_at: 100,
        },
    }
}

fn finding_bid_request(finding: &Finding, max_price_units: u64) -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: "buyer-agent-7".to_string(),
        listing_id: FINDING_LISTING_ID.to_string(),
        max_price_per_call: MonetaryAmount {
            units: max_price_units,
            currency: "USD".to_string(),
        },
        window_seconds: 3_600,
        requested_scope: RequestedScope {
            server_id: FINDING_SERVER_ID.to_string(),
            tool_name: "read_finding".to_string(),
            max_invocations: Some(1),
            capability_scope_prefix: finding_scope(finding),
        },
        issued_at: 120,
    }
}

/// Buying a finding reuses the existing marketplace bid shape unchanged.
/// The listing id points at a finding listing instead of a tool listing;
/// the bid itself needs zero new fields.
#[test]
fn finding_purchase_reuses_marketplace_bid_shape() {
    let finding = sealed_negative_result();
    assert!(verify_finding(&finding).is_ok());
    assert!(finding_bid_request(&finding, 900).validate().is_ok());
}

/// A finding listing clears the real `bid()` path with the colon-segment
/// scope convention, and the minted token is a generic one-shot priced
/// grant. The generic path mints exactly the provider-supplied constraints
/// it is handed and nothing more; the delivery commitment and the purchase
/// marker are authored by the finding purchase mint instead.
#[test]
fn finding_purchase_clears_the_real_bid_path() {
    let operator = Keypair::generate();
    let agent = Keypair::generate();
    let finding = sealed_negative_result();
    let listing = finding_listing_entry(&operator, &finding, 900);
    let request = SignedBidRequest::sign(finding_bid_request(&finding, 900), &agent)
        .test_expect("sign finding bid");
    let expected_scope = finding_scope(&finding);
    assert_eq!(listing.pricing.body.capability_scope, expected_scope);
    assert_eq!(
        request.body.requested_scope.capability_scope_prefix,
        expected_scope
    );

    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &operator,
            agent_subject: agent.public_key(),
            token_id: "finding-token-0001".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .test_expect("finding bid clears the marketplace path");

    assert_eq!(ask.body.schema, ASK_RESPONSE_SCHEMA);
    assert_eq!(ask.body.quoted_price.units, 900);
    let grant = &ask.body.token_offer.scope.grants[0];
    assert_eq!(grant.tool_name, "read_finding");
    assert_eq!(grant.max_invocations, Some(1));
    assert_eq!(
        grant.max_total_cost,
        Some(MonetaryAmount {
            units: 900,
            currency: "USD".to_string(),
        })
    );
    // Nothing the caller did not supply: an empty constraint list and a
    // bearer grant.
    assert!(grant.constraints.is_empty());
    assert_eq!(grant.dpop_required, None);
}

/// The buyer-local ceiling is deterministic, monotone in the supplied
/// re-derivation estimate, and capped by the supplied budget remainder. It
/// makes no claim about true value or authoritative funds.
#[test]
fn finding_bid_ceiling_is_bounded_and_budget_capped() {
    let mut basis = FindingBidBasis {
        rederivation_estimate_units: 4_200,
        would_have_run_bps: 6_000,
        sibling_redundancy_bps: 2_500,
        guarantee_class_bps: 10_000,
        budget_remaining_units: 10_000,
    };
    let ceiling = finding_bid_ceiling(&basis);
    // 4200 x 0.60 x 0.75 x 1.00 = 1890.
    assert_eq!(ceiling, 1_890);
    assert!(ceiling <= basis.rederivation_estimate_units);

    let mut higher_quote = FindingBidBasis {
        rederivation_estimate_units: 8_400,
        ..basis
    };
    assert!(finding_bid_ceiling(&higher_quote) >= ceiling);

    let operator = Keypair::generate();
    let agent = Keypair::generate();
    let finding = sealed_negative_result();
    let affordable_listing = finding_listing_entry(&operator, &finding, ceiling);
    let affordable_request = SignedBidRequest::sign(finding_bid_request(&finding, ceiling), &agent)
        .test_expect("sign affordable finding bid");
    assert!(bid(
        &affordable_request,
        BidMintContext {
            listing: &affordable_listing,
            issuer_keypair: &operator,
            agent_subject: agent.public_key(),
            token_id: "finding-token-at-ceiling".to_string(),
            now: 120,
            grant_constraints: Vec::new(),
            dpop_required: None,
        },
    )
    .is_ok());

    let overpriced_listing = finding_listing_entry(&operator, &finding, ceiling + 1);
    let overpriced_request = SignedBidRequest::sign(finding_bid_request(&finding, ceiling), &agent)
        .test_expect("sign over-ceiling finding bid");
    assert!(matches!(
        bid(
            &overpriced_request,
            BidMintContext {
                listing: &overpriced_listing,
                issuer_keypair: &operator,
                agent_subject: agent.public_key(),
                token_id: "finding-token-over-ceiling".to_string(),
                now: 120,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
        ),
        Err(BiddingError::BidCeilingTooLow)
    ));

    basis.budget_remaining_units = 500;
    assert_eq!(finding_bid_ceiling(&basis), 500);

    higher_quote.would_have_run_bps = 0;
    assert_eq!(finding_bid_ceiling(&higher_quote), 0);
}
