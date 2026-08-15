fn profile_registration_raw(
    profile: &SignedFindingChallengeVerifierProfile,
    observed_at: u64,
    revoked_from: Option<u64>,
) -> Result<String, AnyError> {
    let pin = authority_pin(1, "governance");
    let governance_key = pin.key()?;
    let status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: pin.revocation_status_ref,
            authority_id: pin.authority_id,
            key: governance_key,
            key_epoch: pin.key_epoch,
            revoked_from,
            observed_at,
        },
        &keypair(37),
    )?;
    canonical_string(&serde_json::json!({
        "profile": serde_json::to_value(profile)?,
        "governanceAuthorityStatus": serde_json::to_value(status)?,
    }))
}

fn profile_registration_raw_from_profile_bytes(profile_raw: &str) -> Result<String, AnyError> {
    let profile: SignedFindingChallengeVerifierProfile = serde_json::from_str(profile_raw)?;
    profile_registration_raw(&profile, unix_timestamp_now(), None)
}

#[tokio::test]
async fn profile_not_signed_by_governance_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let interloper = keypair(9);
    let checkpoint_id = checkpoint_log_id(&stack.web.checkpoint);
    let forged_profile = build_profile(
        &interloper,
        checkpoint_id,
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&forged_profile, unix_timestamp_now(), None)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

#[tokio::test]
async fn profile_registration_requires_live_unrevoked_governance() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let profile: SignedFindingChallengeVerifierProfile =
        serde_json::from_str(&stack.web.profile_raw)?;
    let now = unix_timestamp_now();

    let mut expired_state = stack.state.clone();
    expired_state
        .config
        .finding_market
        .as_mut()
        .ok_or("finding market config")?
        .governance_root
        .valid_until = now;
    let (status, body) = send(
        &expired_state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&profile, now, None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("not live at registration"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&profile, now, Some(now))?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("revoked at profile registration"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    let mut newly_issued = profile.body.clone();
    newly_issued.issued_at = now;
    newly_issued.profile_id = String::new();
    newly_issued.profile_id = compute_profile_id(&newly_issued)?;
    let newly_issued = SignedExportEnvelope::sign(newly_issued, &keypair(1))?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&newly_issued, now.saturating_sub(1), None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("predates profile issuance"));

    let mut expired = profile.body.clone();
    expired.expires_at = now;
    expired.profile_id = String::new();
    expired.profile_id = compute_profile_id(&expired)?;
    let expired = SignedExportEnvelope::sign(expired, &keypair(1))?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&expired, now, None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("not live at registration"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    let mut future = profile.body.clone();
    future.issued_at = now.saturating_add(60);
    future.profile_id = String::new();
    future.profile_id = compute_profile_id(&future)?;
    let future = SignedExportEnvelope::sign(future, &keypair(1))?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&future, now, None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("not live at registration"));

    let mut late_governance_state = stack.state.clone();
    late_governance_state
        .config
        .finding_market
        .as_mut()
        .ok_or("finding market config")?
        .governance_root
        .valid_from = profile.body.issued_at.saturating_add(1);
    let (status, body) = send(
        &late_governance_state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&profile, now, None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("outside the governance key"));
    assert!(stack
        .store
        .get_recipe_blob(&stack.web.profile_sha256)?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn collateral_registration_requires_live_unrevoked_authority() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let now = unix_timestamp_now();

    let mut expired_state = stack.state.clone();
    expired_state
        .config
        .finding_market
        .as_mut()
        .ok_or("finding market config")?
        .collateral
        .valid_until = now;
    let (status, body) = send(
        &expired_state,
        authed_post(
            "/v1/findings/collateral",
            collateral_registration_raw(&stack.web.backing, now, None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("finding collateral authority is not live"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/collateral",
            collateral_registration_raw(&stack.web.backing, now, Some(now))?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("collateral authority is revoked"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(stack.store.get_allocation(&stack.web.allocation_id)?.is_none());
    Ok(())
}

#[tokio::test]
async fn unsupported_profile_rejects_before_registration_or_activation() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let mut body: SignedFindingChallengeVerifierProfile =
        serde_json::from_str(&stack.web.profile_raw)?;
    body.body
        .required_facets
        .push(FindingFacetKind::KernelAndRevocationTrust);
    body.body.profile_id = String::new();
    body.body.profile_id = compute_profile_id(&body.body)?;
    let unsupported = SignedExportEnvelope::sign(body.body, &keypair(1))?;
    let unsupported_bytes = canonical_json_bytes(&unsupported)?;
    let unsupported_digest = sha256_hex(&unsupported_bytes);

    let (status, response) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&unsupported, unix_timestamp_now(), None)?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&response).contains("profile"));
    assert!(stack.store.get_recipe_blob(&unsupported_digest)?.is_none());

    let error = match verify_profile_for_activation(
        &unsupported,
        &unsupported_digest,
        &signed_governance_authority_status(unix_timestamp_now(), None)?,
        &market_config(),
        unix_timestamp_now(),
    ) {
        Ok(_) => return Err("unsupported profile activated".into()),
        Err(error) => error,
    };
    assert!(error.contains("profile"), "unexpected error: {error}");
    Ok(())
}

#[tokio::test]
async fn profile_body_authority_must_match_governance() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let governance = keypair(1);
    let interloper = keypair(9);
    let checkpoint_id = checkpoint_log_id(&stack.web.checkpoint);
    let profile = build_profile(
        &interloper,
        checkpoint_id,
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let mismatched_profile = SignedExportEnvelope::sign(profile.body, &governance)?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            "/v1/findings/profiles",
            profile_registration_raw(&mismatched_profile, unix_timestamp_now(), None)?,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}
