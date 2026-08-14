fn coordinator_with_listing(
    authority: &SqliteAuthorityStore,
    authority_status: Arc<dyn FindingAuthorityStatusResolver>,
    listing: &FindingAuthorityPin,
) -> Result<FindingPurchaseCoordinator, PurchaseCoordinatorError> {
    FindingPurchaseCoordinator::new(
        authority.finding_purchase_store(),
        authority.finding_market_store(),
        authority.admission_operation_store(),
        authority.tool_outcome_store(),
        keypair(16),
        &keypair(16).public_key(),
        keypair(17),
        &keypair(17).public_key(),
        authority_status,
        &authority_pin(37, "authority-status"),
        &market_config().status_feed_operator,
        &market_config().status_feed_service_bond,
        market_config().status_max_epoch_age_secs,
        listing,
        &market_config().venue,
        VENUE_ID,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_reserve_requires_live_listing_authority() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let now = unix_timestamp_now();
    let listing = market_config().listing;
    let revoked = coordinator_with_listing(
        &fixture.authority,
        Arc::new(TestTerminalAuthorityStatusResolver::revoked(
            &listing.authority_id,
        )),
        &listing,
    )?;
    assert!(matches!(
        revoked.reserve(
            &fixture.exchange.bid,
            &fixture.exchange.ask,
            &fixture.exchange.buyer_signature_hex,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::AuthorityLifecycle {
            role: "listing",
            ..
        })
    ));

    let mut expired_listing = listing.clone();
    expired_listing.valid_until = now;
    let expired = coordinator_with_listing(
        &fixture.authority,
        Arc::new(TestTerminalAuthorityStatusResolver::live()),
        &expired_listing,
    )?;
    assert!(matches!(
        expired.reserve(
            &fixture.exchange.bid,
            &fixture.exchange.ask,
            &fixture.exchange.buyer_signature_hex,
            &fixture.deployment.web.admission,
            &fixture.deployment.web.authorization,
            EXPOSURE_UNITS,
            RESERVATION_TTL_SECS,
            now,
        ),
        Err(PurchaseCoordinatorError::AuthorityLifecycle {
            role: "listing",
            ..
        })
    ));
    assert!(fixture
        .authority
        .finding_purchase_store()
        .get_reservation(&fixture.exchange.reservation_id)?
        .is_none());

    let mut short_lived_listing = listing;
    short_lived_listing.valid_until = now.saturating_add(1);
    let short_lived = coordinator_with_listing(
        &fixture.authority,
        Arc::new(TestTerminalAuthorityStatusResolver::live()),
        &short_lived_listing,
    )?;
    short_lived.reserve(
        &fixture.exchange.bid,
        &fixture.exchange.ask,
        &fixture.exchange.buyer_signature_hex,
        &fixture.deployment.web.admission,
        &fixture.deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    let reservation = short_lived.resolve(&fixture.exchange.reservation_id)?;
    assert_eq!(reservation.expires_at, short_lived_listing.valid_until);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_listing_pin_must_be_independent() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    for aliased_listing_pin in [
        authority_pin(16, "purchase-as-listing"),
        authority_pin(17, "failed-delivery-as-listing"),
        authority_pin(37, "authority-status-as-listing"),
        authority_pin(36, "status-operator-as-listing"),
        market_config().venue,
    ] {
        assert!(matches!(
            coordinator_with_listing(
                &fixture.authority,
                Arc::new(TestTerminalAuthorityStatusResolver::live()),
                &aliased_listing_pin,
            ),
            Err(PurchaseCoordinatorError::ListingPin | PurchaseCoordinatorError::VenuePin)
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_exact_replay_ignores_later_listing_retirement() -> TestResult {
    let fixture = open_reserve_fixture().await?;
    let now = unix_timestamp_now();
    let first = fixture.reserve_with(&fixture.deployment.web.admission, now)?;
    let listing = market_config().listing;

    let revoked = coordinator_with_listing(
        &fixture.authority,
        Arc::new(TestTerminalAuthorityStatusResolver::revoked(
            &listing.authority_id,
        )),
        &listing,
    )?;
    let replay_after_revocation = revoked.reserve(
        &fixture.exchange.bid,
        &fixture.exchange.ask,
        &fixture.exchange.buyer_signature_hex,
        &fixture.deployment.web.admission,
        &fixture.deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    assert_eq!(
        canonical_json_bytes(&first)?,
        canonical_json_bytes(&replay_after_revocation)?
    );

    let mut expired_listing = listing;
    expired_listing.valid_until = now;
    let expired = coordinator_with_listing(
        &fixture.authority,
        Arc::new(TestTerminalAuthorityStatusResolver::live()),
        &expired_listing,
    )?;
    let replay_after_expiry = expired.reserve(
        &fixture.exchange.bid,
        &fixture.exchange.ask,
        &fixture.exchange.buyer_signature_hex,
        &fixture.deployment.web.admission,
        &fixture.deployment.web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        now,
    )?;
    assert_eq!(
        canonical_json_bytes(&first)?,
        canonical_json_bytes(&replay_after_expiry)?
    );
    Ok(())
}
