#[test]
fn finding_pheromone_positive_hint_re_resolves_current_listing_without_purchase_authority() {
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
        let deposit = finding_pheromone_deposit(&web, &listing, &passport, "hint-positive", 125);
        let substrate = InMemoryPheromoneSubstrate::new();
        let resolved = admit_and_resolve_finding_pheromone_hint(
            &substrate,
            deposit,
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            AuthenticatedCurrentFindingListing::new(
                &listing,
                &finding_current_listing_assertion(&listing, &web.operator),
            ),
            &web.admission,
            &web.context(resolver),
        )
        .test_expect("fully admit and resolve finding pheromone");
        assert_eq!(resolved.indicator.finding_id, web.finding.finding_id);
        assert_eq!(resolved.admission.listing_id(), FINDING_LISTING_ID);
        assert!(!resolved.grants_purchase_authority());
    });
}

#[test]
fn finding_pheromone_rejects_oversized_indicator_before_authenticated_resolution() {
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
        let mut oversized =
            finding_pheromone_deposit(&web, &listing, &passport, "hint-oversized", 125);
        oversized.body.indicator = serde_json::json!({
            "schema": FINDING_PHEROMONE_INDICATOR_SCHEMA_V1,
            "finding_id": web.finding.finding_id.clone(),
            "listing_id": "x".repeat(1_000_000),
            "listing_envelope_sha256": "a".repeat(64),
            "admission_envelope_sha256": "b".repeat(64),
            "capability_scope": format!("finding:{}", web.finding.finding_id),
        });
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                oversized,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                AuthenticatedCurrentFindingListing::new(
                    &listing,
                    &finding_current_listing_assertion(&listing, &web.operator),
                ),
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::IndicatorMalformed)
        ));

        let mut invalid_carrier =
            finding_pheromone_deposit(&web, &listing, &passport, "hint-carrier", 125);
        invalid_carrier.body.schema = "chio.pheromone-deposit.future".to_owned();
        invalid_carrier.body.indicator = serde_json::json!(["x".repeat(1_000_000)]);
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                invalid_carrier,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                AuthenticatedCurrentFindingListing::new(
                    &listing,
                    &finding_current_listing_assertion(&listing, &web.operator),
                ),
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::CarrierMalformed)
        ));
    });
}
