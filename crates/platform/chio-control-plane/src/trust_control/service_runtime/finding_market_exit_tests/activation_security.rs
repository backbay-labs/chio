use super::*;

#[test]
fn activation_rejects_reports_predating_signed_inputs() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let governance = keypair(1);
    let profile = build_profile(
        &governance,
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let config = market_config();
    let evaluation_time = stack.web.report.body.evaluation_time;
    let now = evaluation_time.saturating_add(FINDING_AUTHORITY_STATUS_MAX_AGE_SECS + 1);
    let live_status = signed_verifier_authority_status(now, None)?;

    let mut postdated_profile_body = profile.body.clone();
    postdated_profile_body.issued_at = evaluation_time.saturating_add(1);
    postdated_profile_body.profile_id = compute_profile_id(&postdated_profile_body)?;
    let postdated_profile = SignedExportEnvelope::sign(postdated_profile_body, &governance)?;
    assert!(verify_report_authority_lifecycle(
        &stack.web.report,
        &live_status,
        &postdated_profile,
        &stack.web.finding,
        &config,
        now,
    )
    .is_err());

    let mut postdated_finding = stack.web.finding.clone();
    postdated_finding.issued_at = evaluation_time.saturating_add(1);
    assert!(verify_report_authority_lifecycle(
        &stack.web.report,
        &live_status,
        &profile,
        &postdated_finding,
        &config,
        now,
    )
    .is_err());
    Ok(())
}

#[test]
fn activation_requires_profile_pinned_settlement_authorities() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let profile = build_profile(
        &keypair(1),
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let config = market_config();
    verify_profile_settlement_authorities(&profile, &stack.web.admission, &config)
        .map_err(std::io::Error::other)?;

    let mut changed_admission = stack.web.admission.clone();
    changed_admission
        .body
        .purchase_authority
        .rotation_policy_ref
        .push_str("-other");
    assert!(verify_profile_settlement_authorities(&profile, &changed_admission, &config).is_err());

    let mut changed_config = config;
    changed_config.failed_delivery.valid_from =
        changed_config.failed_delivery.valid_from.saturating_add(1);
    assert!(
        verify_profile_settlement_authorities(&profile, &stack.web.admission, &changed_config)
            .is_err()
    );
    Ok(())
}

#[test]
fn venue_lifecycle_rejects_an_expired_deployment_pin() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let now = unix_timestamp_now();
    let mut config = market_config();
    config.venue.valid_until = now;
    let status = signed_venue_authority_status(now, None)?;
    assert!(verify_venue_authority_lifecycle(&stack.web.admission, &status, &config, now).is_err());
    Ok(())
}

#[tokio::test]
async fn retracted_finding_is_hidden_and_cannot_open_market_state() -> TestResult {
    let mut activation = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    activation.seed_market().await?;
    let activation_authority = activation
        .state
        .joint_authority_store
        .as_ref()
        .ok_or_else(|| missing("activation authority"))?;
    retract_finding(
        activation_authority,
        &activation.web.finding_id,
        "pre-activation",
    )?;
    let (status, body) = activation.activate().await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("pending or retracted"));
    assert_not_admitted_with_allocation(&activation, FindingAllocationState::Live).await?;
    assert!(activation
        .store
        .get_fee_event(&activation.publication_fee_key())?
        .is_none());

    let mut participation = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    participation.seed_market().await?;
    let (status, body) = participation.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let participation_authority = participation
        .state
        .joint_authority_store
        .as_ref()
        .ok_or_else(|| missing("participation authority"))?;
    retract_finding(
        participation_authority,
        &participation.web.finding_id,
        "pre-renewal",
    )?;
    assert!(
        participation.admission_marker().await?.is_none(),
        "a retracted Finding must disappear from public discovery"
    );
    let (status, _) = send(
        &participation.state,
        public_get(&format!(
            "/v1/findings/{}/admission",
            participation.web.finding_id
        ))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let renewal = participation_request(&participation.web.schedule, None)?;
    let (status, body) = send(
        &participation.state,
        authed_post(
            &format!(
                "/v1/findings/{}/participation",
                participation.web.finding_id
            ),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("pending or retracted"));
    let renewal_key = finding_fee_idempotency_key(
        &participation.web.schedule_sha256,
        &FindingFeeEvent::ParticipationEpoch { epoch_index: 1 },
        &participation.web.finding_id,
        LISTING_ID,
    );
    assert!(participation.store.get_fee_event(&renewal_key)?.is_none());
    Ok(())
}

#[tokio::test]
async fn participation_rejects_revoked_status_operator_before_fee_intent() -> TestResult {
    let mut stack = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let revoked_at = unix_timestamp_now();
    let renewal = participation_request(&stack.web.schedule, Some(revoked_at))?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            &format!("/v1/findings/{}/participation", stack.web.finding_id),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body)
        .contains("status operator is revoked at participation renewal"));
    let renewal_key = finding_fee_idempotency_key(
        &stack.web.schedule_sha256,
        &FindingFeeEvent::ParticipationEpoch { epoch_index: 1 },
        &stack.web.finding_id,
        LISTING_ID,
    );
    assert!(stack.store.get_fee_event(&renewal_key)?.is_none());
    Ok(())
}

#[tokio::test]
async fn admission_views_recheck_current_status_operator_standing() -> TestResult {
    let mut stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let resolver = Arc::new(TestStatusOperatorAuthorityResolver::default());
    stack.state.finding_authority_status_resolver = Some(resolver.clone());
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(stack.admission_marker().await?.is_some());

    resolver.revoke(unix_timestamp_now());
    assert!(stack.admission_marker().await?.is_none());
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn admission_views_recheck_current_venue_standing() -> TestResult {
    let mut stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let resolver = Arc::new(TestVenueAuthorityResolver::default());
    stack.state.finding_authority_status_resolver = Some(resolver.clone());
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(stack.admission_marker().await?.is_some());

    resolver.revoke(unix_timestamp_now());
    assert!(stack.admission_marker().await?.is_none());
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}
