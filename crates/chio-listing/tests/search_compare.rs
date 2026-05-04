//! Integration coverage for the marketplace `search` and `compare`
//! extensions in `chio-listing::discovery`.

use chio_listing::{
    canonical_json_bytes, compare, crypto::Keypair, search, GenericListingActorKind,
    GenericListingArtifact, GenericListingBoundary, GenericListingCompatibilityReference,
    GenericListingFreshnessState, GenericListingFreshnessWindow, GenericListingQuery,
    GenericListingReport, GenericListingSearchPolicy, GenericListingStatus, GenericListingSubject,
    GenericListingSummary, GenericNamespaceOwnership, GenericRegistryPublisher,
    GenericRegistryPublisherRole, Listing, ListingPricingHint, ListingQuery, ListingSla,
    MonetaryAmount, SignedGenericListing, SignedListingPricingHint,
    GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_LISTING_REPORT_SCHEMA, LISTING_COMPARISON_SCHEMA,
    LISTING_PRICING_HINT_SCHEMA, LISTING_SEARCH_SCHEMA,
};

fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
where
    E: std::fmt::Debug,
{
    result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
}

fn require_some<T>(value: Option<T>, context: &'static str) -> T {
    value.unwrap_or_else(|| panic!("{context}"))
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
            actor_id: format!("server-{listing_id}"),
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
    require_ok(SignedGenericListing::sign(body, keypair), "sign listing")
}

fn publisher(operator_id: &str) -> GenericRegistryPublisher {
    GenericRegistryPublisher {
        role: GenericRegistryPublisherRole::Origin,
        operator_id: operator_id.to_string(),
        operator_name: Some(format!("Operator {operator_id}")),
        registry_url: format!("https://{operator_id}.chio.example"),
        upstream_registry_urls: Vec::new(),
    }
}

fn report(
    keypair: &Keypair,
    operator_id: &str,
    generated_at: u64,
    listings: Vec<SignedGenericListing>,
) -> GenericListingReport {
    GenericListingReport {
        schema: GENERIC_LISTING_REPORT_SCHEMA.to_string(),
        generated_at,
        query: GenericListingQuery::default(),
        namespace: namespace(keypair),
        publisher: publisher(operator_id),
        freshness: GenericListingFreshnessWindow {
            max_age_secs: 300,
            valid_until: generated_at + 300,
        },
        search_policy: GenericListingSearchPolicy::default(),
        summary: GenericListingSummary {
            matching_listings: listings.len() as u64,
            returned_listings: listings.len() as u64,
            active_listings: listings.len() as u64,
            suspended_listings: 0,
            superseded_listings: 0,
            revoked_listings: 0,
            retired_listings: 0,
        },
        listings,
    }
}

fn pricing_hint(
    operator_keypair: &Keypair,
    operator_id: &str,
    listing_id: &str,
    scope: &str,
    units: u64,
    issued_at: u64,
    expires_at: u64,
) -> SignedListingPricingHint {
    let body = ListingPricingHint {
        schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
        listing_id: listing_id.to_string(),
        namespace: "https://registry.chio.example".to_string(),
        provider_operator_id: operator_id.to_string(),
        capability_scope: scope.to_string(),
        price_per_call: MonetaryAmount {
            units,
            currency: "USD".to_string(),
        },
        sla: ListingSla {
            max_latency_ms: 250,
            availability_bps: 9_990,
            throughput_rps: 50,
        },
        revocation_rate_bps: 10,
        recent_receipts_volume: 500,
        issued_at,
        expires_at,
    };
    require_ok(
        SignedListingPricingHint::sign(body, operator_keypair),
        "sign hint",
    )
}

#[test]
fn search_orders_results_by_price_and_emits_signed_schema_fields() {
    let registry_keypair = Keypair::generate();
    let cheap = listing(
        &registry_keypair,
        "listing-cheap",
        GenericListingStatus::Active,
    );
    let mid = listing(
        &registry_keypair,
        "listing-mid",
        GenericListingStatus::Active,
    );
    let pricey = listing(
        &registry_keypair,
        "listing-pricey",
        GenericListingStatus::Active,
    );

    let rep = report(
        &registry_keypair,
        "operator-a",
        100,
        vec![cheap.clone(), mid.clone(), pricey.clone()],
    );

    let operator_keypair = registry_keypair.clone();
    let hints = vec![
        pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-cheap",
            "tools:search",
            50,
            110,
            600,
        ),
        pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-mid",
            "tools:search",
            100,
            110,
            600,
        ),
        pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-pricey",
            "tools:search",
            300,
            110,
            600,
        ),
    ];

    let response = search(&[rep], &hints, &ListingQuery::default(), 120);
    assert_eq!(response.schema, LISTING_SEARCH_SCHEMA);
    assert_eq!(response.result_count, 3);
    assert_eq!(response.results[0].listing_id(), "listing-cheap");
    assert_eq!(response.results[1].listing_id(), "listing-mid");
    assert_eq!(response.results[2].listing_id(), "listing-pricey");
    assert_eq!(response.results[0].rank, 1);
    assert_eq!(response.results[2].rank, 3);
}

#[test]
fn search_rejects_hint_mismatched_to_publisher_operator() {
    let registry_keypair = Keypair::generate();
    let active = listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
    let rep = report(&registry_keypair, "operator-a", 100, vec![active]);

    let operator_keypair = registry_keypair.clone();
    // Hint claims "operator-b" but publisher is "operator-a".
    let hint = pricing_hint(
        &operator_keypair,
        "operator-b",
        "listing-1",
        "tools:search",
        100,
        110,
        600,
    );

    let response = search(&[rep], &[hint], &ListingQuery::default(), 120);
    assert_eq!(response.result_count, 0);
    assert!(response
        .errors
        .iter()
        .any(|error| error.error.contains("provider does not match publisher")));
}

#[test]
fn search_rejects_pricing_hint_not_signed_by_listing_authority() {
    let registry_keypair = Keypair::generate();
    let active = listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
    let rep = report(&registry_keypair, "operator-a", 100, vec![active]);

    let attacker_keypair = Keypair::generate();
    assert_ne!(registry_keypair.public_key(), attacker_keypair.public_key());
    let hint = pricing_hint(
        &attacker_keypair,
        "operator-a",
        "listing-1",
        "tools:search",
        1,
        110,
        600,
    );

    let response = search(&[rep], &[hint], &ListingQuery::default(), 120);
    assert_eq!(
        response.result_count, 0,
        "self-signed pricing hints must not be admitted by operator id alone"
    );
    assert!(
        response
            .errors
            .iter()
            .any(|error| error.error.contains("pricing authority")),
        "expected pricing authority binding error, got: {:?}",
        response.errors
    );
}

#[test]
fn search_filters_by_provider_operator_id_and_require_fresh() {
    let registry_keypair = Keypair::generate();
    let active = listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
    let rep = report(&registry_keypair, "operator-a", 100, vec![active]);

    let operator_keypair = registry_keypair.clone();
    let hint = pricing_hint(
        &operator_keypair,
        "operator-a",
        "listing-1",
        "tools:search",
        100,
        110,
        600,
    );

    let matching = ListingQuery {
        provider_operator_id: Some("operator-a".to_string()),
        ..ListingQuery::default()
    };
    let missing = ListingQuery {
        provider_operator_id: Some("operator-z".to_string()),
        ..ListingQuery::default()
    };

    let response_matching = search(
        std::slice::from_ref(&rep),
        std::slice::from_ref(&hint),
        &matching,
        120,
    );
    let response_missing = search(&[rep], &[hint], &missing, 120);
    assert_eq!(response_matching.result_count, 1);
    assert_eq!(response_missing.result_count, 0);
}

#[test]
fn compare_ranks_cheapest_at_10000_bps() {
    let registry_keypair = Keypair::generate();
    let listing_a = listing(&registry_keypair, "listing-a", GenericListingStatus::Active);
    let listing_b = listing(&registry_keypair, "listing-b", GenericListingStatus::Active);
    let rep = report(
        &registry_keypair,
        "operator-a",
        100,
        vec![listing_a, listing_b],
    );

    let operator_keypair = registry_keypair.clone();
    let hints = vec![
        pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-a",
            "tools:search",
            100,
            110,
            600,
        ),
        pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-b",
            "tools:search",
            250,
            110,
            600,
        ),
    ];
    let response = search(&[rep], &hints, &ListingQuery::default(), 120);
    let comparison = compare(&response.results);
    assert_eq!(comparison.schema, LISTING_COMPARISON_SCHEMA);
    assert_eq!(comparison.entry_count, 2);
    let row_a = require_some(
        comparison
            .rows
            .iter()
            .find(|row| row.listing_id == "listing-a"),
        "row a",
    );
    let row_b = require_some(
        comparison
            .rows
            .iter()
            .find(|row| row.listing_id == "listing-b"),
        "row b",
    );
    assert_eq!(row_a.price_index_bps, 10_000);
    assert_eq!(row_b.price_index_bps, 25_000);
    // Canonical JSON of the comparison is stable and signable.
    let bytes = require_ok(canonical_json_bytes(&comparison), "canonical compare bytes");
    assert!(!bytes.is_empty());
}

#[test]
fn compare_empty_input_produces_empty_comparison() {
    let comparison = compare(&Vec::<Listing>::new());
    assert_eq!(comparison.entry_count, 0);
    assert!(comparison.rows.is_empty());
    assert!(comparison.currency_consistent);
}

#[test]
fn search_rejects_listing_signed_by_attacker_when_namespace_owner_key_is_pinned() {
    // Regression: an attacker mirror cannot republish a listing for a
    // namespace whose declared `signer_public_key` belongs to a different
    // owner. The aggregator must verify that the envelope's `signer_key`
    // matches the namespace ownership signer.
    let owner_keypair = Keypair::generate();
    let attacker_keypair = Keypair::generate();
    assert_ne!(owner_keypair.public_key(), attacker_keypair.public_key());

    // Build a listing whose body declares the legitimate owner key but
    // whose envelope is signed by an attacker key.
    let body = chio_listing::GenericListingArtifact {
        schema: chio_listing::GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: "listing-spoof".to_string(),
        namespace: "https://registry.chio.example".to_string(),
        published_at: 10,
        expires_at: Some(5_000),
        status: GenericListingStatus::Active,
        namespace_ownership: chio_listing::GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: "operator-a".to_string(),
            owner_name: Some("Operator A".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: owner_keypair.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        },
        subject: chio_listing::GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: "server-spoof".to_string(),
            display_name: None,
            metadata_url: None,
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: chio_listing::GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: "artifact-spoof".to_string(),
            source_artifact_sha256: "sha-spoof".to_string(),
        },
        boundary: chio_listing::GenericListingBoundary::default(),
    };
    // Sign with attacker key; envelope.signer_key will not match
    // namespace_ownership.signer_public_key.
    let spoofed = require_ok(
        SignedGenericListing::sign(body, &attacker_keypair),
        "sign spoofed listing",
    );
    let rep = report(&owner_keypair, "operator-a", 100, vec![spoofed]);

    let operator_keypair = owner_keypair.clone();
    let hint = pricing_hint(
        &operator_keypair,
        "operator-a",
        "listing-spoof",
        "tools:search",
        50,
        110,
        600,
    );

    let response = search(&[rep], &[hint], &ListingQuery::default(), 120);
    assert_eq!(
        response.result_count, 0,
        "spoofed listing must not appear in search results"
    );
    assert!(
        response
            .errors
            .iter()
            .any(|err| err.error.contains("signer does not match")),
        "expected a namespace-ownership signer pinning error, got: {:?}",
        response.errors,
    );
}

#[test]
fn search_honors_require_fresh_equals_false_allows_passthrough() {
    // The aggregator drops stale reports before search ever sees them, so
    // this test documents the require_fresh=false path on fresh reports.
    let registry_keypair = Keypair::generate();
    let active = listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
    let rep = report(&registry_keypair, "operator-a", 100, vec![active]);

    let operator_keypair = registry_keypair.clone();
    let hint = pricing_hint(
        &operator_keypair,
        "operator-a",
        "listing-1",
        "tools:search",
        100,
        110,
        600,
    );
    let query = ListingQuery {
        require_fresh: false,
        ..ListingQuery::default()
    };
    let response = search(&[rep], &[hint], &query, 120);
    assert_eq!(response.result_count, 1);
    assert_eq!(
        response.results[0].freshness.state,
        GenericListingFreshnessState::Fresh
    );
}
