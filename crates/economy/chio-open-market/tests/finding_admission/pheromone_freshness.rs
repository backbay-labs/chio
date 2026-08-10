fn finding_current_listing_assertion(
    listing: &Listing,
    namespace_owner: &Keypair,
) -> SignedFindingCurrentListingAssertion {
    SignedFindingCurrentListingAssertion::sign(
        FindingCurrentListingAssertion {
            schema: FINDING_CURRENT_LISTING_ASSERTION_SCHEMA_V1.to_owned(),
            listing_id: listing.listing_id().to_owned(),
            namespace: listing.listing.body.namespace.clone(),
            registry_operator_id: listing.publisher.operator_id.clone(),
            listing_envelope_sha256: signed_envelope_sha256(&listing.listing)
                .test_expect("listing assertion listing digest"),
            pricing_hint_envelope_sha256: signed_envelope_sha256(&listing.pricing)
                .test_expect("listing assertion pricing digest"),
            generated_at: listing.freshness.generated_at,
            max_age_secs: listing.freshness.max_age_secs,
            valid_until: listing.freshness.valid_until,
        },
        namespace_owner,
    )
    .test_expect("sign current listing assertion")
}

#[test]
fn finding_pheromone_pins_current_listing_to_registry_authority() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let registry = keypair(84);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let mut convention = finding_pheromone_convention();
        convention.registry_key = registry.public_key();
        let registry_assertion = finding_current_listing_assertion(&listing, &registry);
        admit_and_resolve_finding_pheromone_hint(
            &InMemoryPheromoneSubstrate::new(),
            finding_pheromone_deposit(&web, &listing, &passport, "hint-registry-signed", 125),
            &finding_pheromone_context(&passport, &kernel),
            &convention,
            AuthenticatedCurrentFindingListing::new(&listing, &registry_assertion),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect("pinned registry assertion admits the current listing");

        let provider_assertion = finding_current_listing_assertion(&listing, &web.operator);
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                finding_pheromone_deposit(
                    &web,
                    &listing,
                    &passport,
                    "hint-provider-self-signed",
                    125,
                ),
                &finding_pheromone_context(&passport, &kernel),
                &convention,
                AuthenticatedCurrentFindingListing::new(&listing, &provider_assertion),
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Listing(_))
        ));
    });
}

#[test]
fn finding_pheromone_rejects_weak_listing_authority_signatures() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let mut listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let weak_key =
            PublicKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
                .test_expect("construct weak listing authority key");
        let forged_signature = chio_open_market::crypto::Signature::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .test_expect("construct forged weak-key signature");
        listing.listing.body.namespace_ownership.signer_public_key = weak_key.clone();
        listing.listing.signer_key = weak_key.clone();
        listing.listing.signature = forged_signature.clone();
        listing.pricing.signer_key = weak_key;
        listing.pricing.signature = forged_signature;
        let assertion = finding_current_listing_assertion(&listing, &web.operator);

        let error = admit_and_resolve_finding_pheromone_hint(
            &InMemoryPheromoneSubstrate::new(),
            finding_pheromone_deposit(&web, &listing, &passport, "hint-weak-owner", 125),
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            AuthenticatedCurrentFindingListing::new(&listing, &assertion),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect_err("weak listing authority must fail strict verification");
        assert!(matches!(
            error,
            FindingPheromoneError::Listing(message) if message.contains("weak")
        ));
    });
}

#[test]
fn finding_pheromone_assertion_cannot_predate_pricing_issuance() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let mut listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let mut pricing = listing.pricing.body.clone();
        pricing.issued_at = listing.freshness.generated_at + 1;
        listing.pricing = SignedListingPricingHint::sign(pricing, &web.operator)
            .test_expect("sign not-yet-issued pricing hint");
        let assertion = finding_current_listing_assertion(&listing, &web.operator);

        let error = admit_and_resolve_finding_pheromone_hint(
            &InMemoryPheromoneSubstrate::new(),
            finding_pheromone_deposit(&web, &listing, &passport, "hint-pricing-issued-later", 125),
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            AuthenticatedCurrentFindingListing::new(&listing, &assertion),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect_err("current-listing assertion cannot predate the pricing hint");
        assert!(matches!(
            error,
            FindingPheromoneError::Listing(message) if message.contains("binding is invalid")
        ));
    });
}

#[test]
fn finding_pheromone_rejects_non_ascii_registry_operator_policy() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let assertion = finding_current_listing_assertion(&listing, &web.operator);
        let mut convention = finding_pheromone_convention();
        convention.registry_operator_id = "seller-operatör".to_owned();

        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                finding_pheromone_deposit(
                    &web,
                    &listing,
                    &passport,
                    "hint-non-ascii-registry",
                    125,
                ),
                &finding_pheromone_context(&passport, &kernel),
                &convention,
                AuthenticatedCurrentFindingListing::new(&listing, &assertion),
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Convention("receiver policy"))
        ));
    });
}

#[test]
fn finding_pheromone_bounds_listing_assertions_before_signature_verification() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let mut assertion = finding_current_listing_assertion(&listing, &web.operator);
        assertion.body.namespace = "é".repeat(300);
        let error = admit_and_resolve_finding_pheromone_hint(
            &InMemoryPheromoneSubstrate::new(),
            finding_pheromone_deposit(&web, &listing, &passport, "hint-oversized-assertion", 125),
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            AuthenticatedCurrentFindingListing::new(&listing, &assertion),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect_err("oversized assertion rejects before its stale signature is checked");
        assert!(matches!(
            error,
            FindingPheromoneError::Listing(message) if message.contains("shape is invalid")
        ));
    });
}

#[test]
fn finding_pheromone_bounds_listing_envelopes_before_hashing() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let mut listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let assertion = finding_current_listing_assertion(&listing, &web.operator);
        listing.listing.body.subject.actor_id = "x".repeat(513);

        let error = admit_and_resolve_finding_pheromone_hint(
            &InMemoryPheromoneSubstrate::new(),
            finding_pheromone_deposit(&web, &listing, &passport, "hint-oversized-listing", 125),
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            AuthenticatedCurrentFindingListing::new(&listing, &assertion),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect_err("oversized listing rejects before hashing its stale envelope");
        assert!(matches!(
            error,
            FindingPheromoneError::Listing(message) if message.contains("bounded printable")
        ));
    });
}

#[test]
fn finding_pheromone_requires_authenticated_current_listing_freshness() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let mut listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let current_listing_assertion = finding_current_listing_assertion(&listing, &web.operator);
        listing.freshness.generated_at = NOW;
        listing.freshness.age_secs = 0;
        listing.freshness.state = GenericListingFreshnessState::Fresh;
        let deposit =
            finding_pheromone_deposit(&web, &listing, &passport, "hint-forged-freshness", 125);

        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                deposit,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                AuthenticatedCurrentFindingListing::new(&listing, &current_listing_assertion),
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Listing(_))
        ));
    });
}
