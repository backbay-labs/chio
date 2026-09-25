use super::*;

#[test]
fn finding_challenge_an_evaluator_key_outside_its_pinned_lifecycle_signs_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let at = NOW + 4;

    // The epoch the outcome carries states which key adjudicated, so a
    // caller may not declare one the pin does not hold.
    let mut request = evaluation_request(&case.challenge, &challenged, &evidence, &collateral, at);
    request.evaluator_key_epoch = PINNED_KEY_EPOCH + 1;
    assert!(matches!(
        coordinator
            .evaluate(&request)
            .expect_err("an epoch the pin does not carry adjudicates nothing"),
        ChallengeCoordinatorError::EvaluatorKeyEpoch
    ));

    // Status is returned by the injected resolver, then authenticated
    // against the independent status-authority pin. A governance-root
    // self-signature, another source, a revoked key, and a stale reading
    // all refuse before adjudication.
    let readings = [
        (
            TestAuthorityStatusResolver {
                status_ref_override: Some("revocations/some-other-roster".to_string()),
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status does not bind the configured pin",
        ),
        (
            TestAuthorityStatusResolver {
                revoked_authority: Some("challenge-evaluator".to_string()),
                ..TestAuthorityStatusResolver::live()
            },
            "key was revoked when the role acted",
        ),
        (
            TestAuthorityStatusResolver {
                observed_at_override: Some(at - 86_400),
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status is not a fresh post-action reading",
        ),
        (
            TestAuthorityStatusResolver {
                signer_seed: 1,
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status signature is invalid",
        ),
    ];
    for (resolver, refused) in readings {
        let coordinator = deployment.coordinator_under_with_status(
            &market_config(),
            Arc::new(resolver),
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let request = evaluation_request(&case.challenge, &challenged, &evidence, &collateral, at);
        match coordinator
            .evaluate(&request)
            .expect_err("an unusable revocation status adjudicates nothing")
        {
            ChallengeCoordinatorError::EvaluatorRevocation(detail) => assert_eq!(detail, refused),
            other => return Err(format!("unexpected rejection for {refused}: {other}").into()),
        }
    }

    // A pin whose window has closed at the venue clock signs nothing, even
    // though the key material still matches.
    let mut retired = market_config();
    retired.challenge_evaluator.valid_until = at;
    let retired =
        deployment.coordinator_under(&retired, FindingDisputeLockDisposition::Forfeited)?;
    assert!(matches!(
        retired
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                at,
            ))
            .expect_err("an expired evaluator key adjudicates nothing"),
        ChallengeCoordinatorError::EvaluatorKeyWindow
    ));

    let mut retired_status = market_config();
    retired_status.authority_status.valid_until = at;
    let retired_status =
        deployment.coordinator_under(&retired_status, FindingDisputeLockDisposition::Forfeited)?;
    let error = retired_status
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            at,
        ))
        .err()
        .ok_or("an expired status authority was accepted")?;
    assert!(matches!(
        error,
        ChallengeCoordinatorError::EvaluatorRevocation(
            "status authority is outside its configured validity window"
        )
    ));

    // None of that consumed an evaluation attempt against the challenge.
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("the challenge is durable")?
            .state,
        FindingChallengeState::Submitted
    );

    // The same adjudication under a live key signs an outcome carrying the
    // deployment's epoch.
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            at,
        ))?
        .ok_or("a live evaluator key adjudicates")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(evaluated.outcome.body.evaluator_key_epoch, PINNED_KEY_EPOCH);
    Ok(())
}
#[test]
fn finding_challenge_uphold_uses_the_recorded_historical_evaluator_policy() -> TestResult {
    let deployment = deployment()?;
    let original = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let ready = ready_to_uphold(&deployment, &original)?;

    let mut rotated_config = market_config();
    rotated_config.challenge_evaluator = authority_pin(40, "challenge-evaluator");
    rotated_config.challenge_evaluator.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.challenge_evaluator.valid_from = NOW + 2;
    let rotated = deployment.coordinator_under_with_evaluator_and_status(
        &rotated_config,
        keypair(40),
        Arc::new(TestAuthorityStatusResolver::live()),
        FindingDisputeLockDisposition::Forfeited,
    )?;

    let governance = governance()?;
    let stake = usd(300);
    let required = usd(5_000);
    let upheld = uphold_across_claim_window(
        &rotated,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &ready.challenge,
        &ready.outcome,
        &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
        0,
        &[],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    assert_eq!(
        upheld.liability_key,
        derive_liability_key(
            &derive_defect_key(&ready.finding.finding_id),
            VENUE_ID,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
        )
    );
    Ok(())
}
#[test]
fn finding_challenge_evaluation_resolves_the_profiles_historical_governance_policy() -> TestResult {
    let deployment = deployment()?;
    let original = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(
        &deployment,
        "profile-rotation",
        BUYER_ONE_DESTINATION,
        50,
        NOW,
    )?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    original.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let mut rotated_config = market_config();
    rotated_config.governance_root = authority_pin(49, "governance-rotated");
    rotated_config.governance_root.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.governance_root.valid_from = NOW + 2;
    let rotated =
        deployment.coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = rotated
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("a retained profile survives governance-key rotation")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    Ok(())
}
#[test]
fn finding_challenge_uphold_resolves_the_audits_historical_policy() -> TestResult {
    let deployment = deployment()?;
    let original = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, raw) = finding_artifact()?;
    let challenge = venue_audit_challenge()?;
    original.submit(&challenge, &raw, NOW)?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id, 0, "USD")?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        NOW + 1,
    )?;

    let mut rotated_config = market_config();
    rotated_config.audit_authority = authority_pin(50, "audit-authority-rotated");
    rotated_config.audit_authority.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.audit_authority.valid_from = NOW + 2;
    let rotated =
        deployment.coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?;
    let stake = usd(300);
    let required = usd(5_000);
    let upheld = uphold_across_claim_window(
        &rotated,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &challenge,
        &outcome,
        &liability_identity(&finding.finding_id, &deployment.allocation_id),
        0,
        &[],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    assert_eq!(upheld.liability_key.len(), 64);
    Ok(())
}
#[test]
fn finding_challenge_submit_resolves_the_rounds_historical_role_policies() -> TestResult {
    let deployment = deployment()?;
    let (_, raw) = finding_artifact()?;
    let challenge = venue_audit_challenge()?;
    let mut rotated_config = market_config();
    rotated_config.audit_authority = authority_pin(50, "audit-authority-rotated");
    rotated_config.audit_authority.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.audit_authority.valid_from = NOW + 1;
    rotated_config.audit_randomness_witness = authority_pin(51, "audit-witness-rotated");
    rotated_config.audit_randomness_witness.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.audit_randomness_witness.valid_from = NOW + 1;
    rotated_config.governance_root = authority_pin(52, "audit-governance-rotated");
    rotated_config.governance_root.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.governance_root.valid_from = NOW + 1;
    let rotated =
        deployment.coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?;

    let submitted = rotated.submit(&challenge, &raw, NOW + 2)?;
    assert_eq!(
        submitted.write,
        FindingChallengeWriteOutcome::Inserted,
        "a retained round remains fileable under its authenticated signer and policies after rotation"
    );
    Ok(())
}
#[test]
fn finding_challenge_audit_policy_is_retained_by_exact_round() -> TestResult {
    let original_round = published_audit_round()?;
    let renewed_round = unrelated_audit_round()?;
    let config = market_config();
    let original_policy = config.audit_authority.clone();
    let mut renewed_policy = original_policy.clone();
    renewed_policy.key_epoch += 1;
    renewed_policy.valid_from = NOW + 1;
    renewed_policy.valid_until += 1;
    renewed_policy.revocation_status_ref = "status:audit-authority-renewed".to_string();

    let filings = PublishedArtifacts::default()
        .publish_round(
            &original_round,
            original_policy.clone(),
            config.audit_randomness_witness.clone(),
            config.governance_root.clone(),
        )?
        .publish_round(
            &renewed_round,
            renewed_policy.clone(),
            config.audit_randomness_witness,
            config.governance_root,
        )?;
    let original_digest = signed_envelope_sha256(&original_round.epoch)?;
    let renewed_digest = signed_envelope_sha256(&renewed_round.epoch)?;

    assert_eq!(
        filings.audit_policy_for_epoch(&original_digest),
        Ok(Some(original_policy))
    );
    assert_eq!(
        filings.audit_policy_for_epoch(&renewed_digest),
        Ok(Some(renewed_policy))
    );
    Ok(())
}
#[test]
fn finding_challenge_every_value_bearing_role_enforces_authenticated_lifecycle() -> TestResult {
    // Venue admission.
    {
        let deployment = deployment()?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let challenged = challenged_finding()?;
        let sale = settle_purchase(&deployment, "venue-life", BUYER_ONE_DESTINATION, 50, NOW)?;
        let case = evidence_invalid_case(
            &challenged,
            ProductionShape::ForeignSignature,
            &sale,
            Filing::Buyer,
        )?;
        live.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
        let revoked = deployment
            .coordinator_with_revoked_role("venue", FindingDisputeLockDisposition::Forfeited)?;
        let stake = usd(300);
        let required = usd(5_000);
        let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
        let evidence = case.evidence();
        let error = revoked
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                NOW + 2,
            ))
            .expect_err("a revoked venue cannot authorize its admission");
        assert!(
            matches!(
                error,
                ChallengeCoordinatorError::AuthorityLifecycle {
                    role: "historical venue",
                    ..
                }
            ),
            "unexpected error: {error:?}"
        );
    }

    // Bondless audit authorization.
    {
        let deployment = deployment()?;
        let revoked = deployment.coordinator_with_revoked_role(
            "audit-authority",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let challenge = venue_audit_challenge()?;
        let (_, raw) = finding_artifact()?;
        assert!(matches!(
            revoked
                .submit(&challenge, &raw, NOW)
                .expect_err("a revoked audit authority files no audit"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "historical audit",
                ..
            }
        ));
    }

    {
        let mut deployment = deployment()?;
        let challenge = venue_audit_challenge()?;
        let audit_epoch_envelope_sha256 = match &challenge.body.authorization {
            FindingChallengeAuthorization::VenueAudit(audit) => {
                audit.audit_epoch_envelope_sha256.clone()
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => {
                return Err("venue audit fixture used the buyer branch".into())
            }
        };
        Arc::make_mut(&mut deployment.filings)
            .audit_policies
            .get_mut(&audit_epoch_envelope_sha256)
            .ok_or("retained audit policy")?
            .valid_until = NOW + 1;
        let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let (_, raw) = finding_artifact()?;
        let error = coordinator
            .submit(&challenge, &raw, NOW + 1)
            .err()
            .ok_or("a retired historical audit key filed a new audit")?;
        assert!(matches!(
            error,
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "historical audit",
                reason: "role action is outside the configured validity window",
            }
        ));
    }

    // Governance and penalty authorities both fail before a liability is
    // opened, while the upheld-verdict quarantine remains in force.
    for (authority, role) in [
        ("governance", "historical governance case"),
        ("market-penalty", "penalty"),
    ] {
        let deployment = deployment()?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let ready = ready_to_uphold(&deployment, &live)?;
        let governance = governance()?;
        let revoked = deployment
            .coordinator_with_revoked_role(authority, FindingDisputeLockDisposition::Forfeited)?;
        let stake = usd(300);
        let required = usd(5_000);
        assert!(matches!(
            revoked
                .uphold(
                    &ready.challenge_id,
                    &ready.challenge,
                    &ready.outcome,
                    &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
                    &market_terms(CLAIM_WINDOW_SECS)?,
                    0,
                    &[],
                    &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
                    &governance.context(),
                    &governance.sanction_case,
                    NOW + 2,
                )
                .expect_err("a revoked authority opens no liability"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: actual,
                ..
            } if actual == role
        ));
        assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
        assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    }

    // Purchase records are authenticated before the liability transaction
    // starts; a rejected record cannot lift the verdict quarantine.
    {
        let deployment = deployment()?;
        let sale = settle_purchase(&deployment, "purchase-life", BUYER_ONE_DESTINATION, 50, NOW)?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let ready = ready_to_uphold_with_open_exposure(&deployment, &live, 100)?;
        let governance = governance()?;
        let revoked = deployment.coordinator_with_revoked_role(
            "authority-purchase",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let stake = usd(300);
        let required = usd(5_000);
        assert!(matches!(
            revoked
                .uphold(
                    &ready.challenge_id,
                    &ready.challenge,
                    &ready.outcome,
                    &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
                    &market_terms(CLAIM_WINDOW_SECS)?,
                    1,
                    std::slice::from_ref(&sale.purchase_key),
                    &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
                    &governance.context(),
                    &governance.sanction_case,
                    NOW + 2,
                )
                .expect_err("a revoked purchase authority contributes no claim"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "retained purchase",
                ..
            }
        ));
        assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
        assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    }

    // Finalization signs nothing under a revoked key.
    {
        let case = upheld_liability()?;
        let revoked = case.deployment.coordinator_with_revoked_role(
            "venue-finalization",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
        assert!(matches!(
            revoked
                .resolve_appeal(
                    &case.upheld.liability_key,
                    &case.outcome,
                    &identity,
                    Some(&case.upheld.sealed),
                    &case.governance.context(),
                    &AppealDisposition::Final {
                        sanction_case: &case.governance.sanction_case,
                    },
                    &case.upheld.sanction_case_id,
                    &case.upheld.hold,
                    &hex64('7'),
                    APPEAL_FINAL_AT,
                )
                .expect_err("a revoked finalization authority signs no enforcement"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "finalization",
                ..
            }
        ));
    }
    Ok(())
}
#[test]
fn finding_challenge_listing_ceiling_comes_from_the_signed_schedule() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "ceiling", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    let stake = usd(300);
    let attacker_selected_ceiling = usd(50_000);
    let collateral = collateral_facts(
        &stake,
        &attacker_selected_ceiling,
        &deployment.allocation_id,
        5_000,
    );
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the challenge adjudicates")?;
    assert_eq!(
        evaluated
            .outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or("upheld outcome has a calculation")?
            .listing_required_amount_units,
        5_000,
        "the caller's inflated ceiling is not part of the calculation"
    );
    Ok(())
}
#[test]
fn finding_challenge_purchase_standing_requires_retention_and_live_authority() -> TestResult {
    // A valid signature over a record that the venue never settled is not
    // standing, even when another deployment retained those same bytes.
    {
        let source = deployment()?;
        let unretained = settle_purchase(
            &source,
            "unretained-standing",
            BUYER_ONE_DESTINATION,
            50,
            NOW,
        )?;
        let deployment = deployment()?;
        let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let challenged = challenged_finding()?;
        let case = evidence_invalid_case(
            &challenged,
            ProductionShape::ForeignSignature,
            &unretained,
            Filing::Buyer,
        )?;
        coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
        let stake = usd(300);
        let required = usd(5_000);
        let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
        let evidence = case.evidence();
        assert!(matches!(
            coordinator
                .evaluate(&evaluation_request(
                    &case.challenge,
                    &challenged,
                    &evidence,
                    &collateral,
                    NOW + 2,
                ))
                .expect_err("an unretained record establishes no standing"),
            ChallengeCoordinatorError::UnknownPurchaseRecord(_)
        ));
    }

    // A retained record still fails closed when its admission-pinned
    // purchase authority was revoked when the record claims it settled.
    {
        let deployment = deployment()?;
        let sale = settle_purchase(
            &deployment,
            "revoked-standing",
            BUYER_ONE_DESTINATION,
            50,
            NOW,
        )?;
        let coordinator = deployment.coordinator_with_revoked_role(
            "authority-purchase",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let challenged = challenged_finding()?;
        let case = evidence_invalid_case(
            &challenged,
            ProductionShape::ForeignSignature,
            &sale,
            Filing::Buyer,
        )?;
        coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
        let stake = usd(300);
        let required = usd(5_000);
        let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
        let evidence = case.evidence();
        assert!(matches!(
            coordinator
                .evaluate(&evaluation_request(
                    &case.challenge,
                    &challenged,
                    &evidence,
                    &collateral,
                    NOW + 2,
                ))
                .expect_err("revoked purchase authority establishes no standing"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "purchase standing",
                ..
            }
        ));
        assert_eq!(
            deployment
                .challenges
                .get_challenge(&case.challenge.body.challenge_id)?
                .ok_or("the refused challenge remains submitted")?
                .state,
            FindingChallengeState::Submitted
        );
    }
    Ok(())
}
#[test]
fn finding_challenge_evaluation_refuses_an_unsigned_penalty_stake() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "stake-binding", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let unsigned_stake = usd(301);
    let required = usd(5_000);
    let collateral = collateral_facts(&unsigned_stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let refused = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))
        .expect_err("a seller-unsigned stake must not produce a verdict");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::TermsBinding("base_finding_stake")
    ));
    let record = deployment
        .challenges
        .get_challenge(&case.challenge.body.challenge_id)?
        .ok_or("submitted challenge remains recorded")?;
    assert_eq!(record.state, FindingChallengeState::Submitted);
    assert!(record.outcome_envelope_sha256.is_none());
    assert!(
        !deployment.purchases.sales_blocked(LISTING_ID)?,
        "a refused evaluation must not wedge the listing"
    );
    Ok(())
}
#[test]
fn finding_challenge_a_generic_digest_denial_cannot_sanction() -> TestResult {
    // No finding-delivery overlay: nothing establishes that the expectation
    // was the seller's own commitment or that the transform plan was frozen.
    assert_denial_cannot_sanction(
        &DenyShape {
            include_overlay: false,
            ..DenyShape::seller_origin()
        },
        "denial_not_seller_origin",
    )
}
#[test]
fn finding_challenge_an_output_policy_denial_cannot_sanction() -> TestResult {
    // The kernel compared the output against an expectation the operator
    // chose rather than the digest the signed finding committed.
    assert_denial_cannot_sanction(
        &DenyShape {
            expected_digest: Some(hex64('f')),
            ..DenyShape::seller_origin()
        },
        "denial_output_policy_expectation",
    )
}
#[test]
fn finding_challenge_every_cross_class_evidence_pairing_is_inadmissible() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;

    let digest = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    for challenge in [&digest.challenge, &invalid.challenge, &replay.challenge] {
        coordinator.submit(challenge, &challenged.raw_finding, NOW + 1)?;
    }

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = replay.reproductions();
    let bundles = [
        digest.evidence(),
        invalid.evidence(),
        replay.evidence(&reproductions),
    ];
    let challenges = [&digest.challenge, &invalid.challenge, &replay.challenge];

    for (challenge_index, challenge) in challenges.iter().enumerate() {
        for (bundle_index, bundle) in bundles.iter().enumerate() {
            if challenge_index == bundle_index {
                continue;
            }
            let evaluated = coordinator.evaluate(&evaluation_request(
                challenge,
                &challenged,
                bundle,
                &collateral,
                NOW + 2,
            ))?;
            assert!(
                evaluated.is_none(),
                "evidence from another class produces no verdict"
            );
            let record = deployment
                .challenges
                .get_challenge(&challenge.body.challenge_id)?
                .ok_or("the challenge is durable")?;
            assert_eq!(
                record.state,
                FindingChallengeState::Submitted,
                "an inadmissible submission never enters evaluation"
            );
            assert!(record.outcome_envelope_sha256.is_none());
        }
    }

    // The same three submissions adjudicate against the evidence their own
    // class selects, so the refusals above came from the pairing and not
    // from a submission that could never have been evaluated.
    for (challenge, bundle) in challenges.iter().zip(&bundles) {
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                challenge,
                &challenged,
                bundle,
                &collateral,
                NOW + 3,
            ))?
            .ok_or("the matching class pairing is admissible")?;
        assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    }
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        0
    );
    Ok(())
}
#[test]
fn finding_challenge_a_foreign_recipe_preimage_never_reaches_a_verdict() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;

    // A recipe that is canonical and binds the admitted profile, and is
    // not the recipe the finding committed.
    let mut foreign = replay_recipe(&challenged.profile_envelope_sha256);
    foreign.parameters_sha256 = hex64('d');
    let foreign_preimage = canonical_json_string(&foreign)?;
    assert_ne!(
        sha256_hex(foreign_preimage.as_bytes()),
        challenged.recipe_sha256
    );

    let phases = [PhaseShape::baseline_fails(), PhaseShape::candidate_fails()];
    let case = replay_case(
        &challenged,
        "foreign",
        &phases,
        Some(&foreign_preimage),
        &sale,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluated = coordinator.evaluate(&evaluation_request(
        &case.challenge,
        &challenged,
        &evidence,
        &collateral,
        NOW + 2,
    ))?;
    assert!(
        evaluated.is_none(),
        "a preimage that is not the committed recipe is a different document"
    );
    let record = deployment
        .challenges
        .get_challenge(&case.challenge.body.challenge_id)?
        .ok_or("the challenge is durable")?;
    assert_eq!(record.state, FindingChallengeState::Submitted);
    assert!(record.outcome_envelope_sha256.is_none());

    // The same reproduction set against the committed recipe adjudicates,
    // so the refusal above is the preimage and nothing else.
    let committed = replay_case(&challenged, "committed", &phases, None, &sale)?;
    coordinator.submit(&committed.challenge, &challenged.raw_finding, NOW + 3)?;
    let reproductions = committed.reproductions();
    let evidence = committed.evidence(&reproductions);
    let adjudicated = coordinator
        .evaluate(&evaluation_request(
            &committed.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 4,
        ))?
        .ok_or("the committed recipe preimage is admissible")?;
    assert_eq!(adjudicated.state, FindingChallengeState::Upheld);
    Ok(())
}
#[test]
fn finding_challenge_a_malformed_recipe_preimage_is_refused_at_submission() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let sound = replay_case(
        &challenged,
        "sound",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    let FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        purchase_record_envelope_sha256,
        ..
    } = &sound.challenge.body.evidence
    else {
        return Err("a replay challenge carries a replay evidence branch".into());
    };

    // A preimage that is absent, and one whose bytes are not the canonical
    // encoding of the recipe they claim to be. Neither is the seller's
    // precommitment, so neither may open an adjudication at all.
    let non_canonical =
        serde_json::to_string_pretty(&replay_recipe(&challenged.profile_envelope_sha256))?;
    for preimage in [String::new(), non_canonical] {
        let branch = FindingChallengeEvidence::ReplayContradiction {
            reproduction: reproduction.clone(),
            recipe_preimage: preimage,
            purchase_record_envelope_sha256: purchase_record_envelope_sha256.clone(),
        };
        let authorization = challenged.buyer_authorization(
            "malformed",
            FindingChallengeStanding::FinalizedPurchase {
                purchase_key: sale.purchase_key.clone(),
                purchase_record_envelope_sha256: sale.record_envelope_sha256.clone(),
            },
        )?;
        let challenge = challenged.sign_challenge(
            authorization,
            branch,
            sound.challenge.body.affected_deliveries.clone(),
        )?;
        let refused = coordinator
            .submit(&challenge, &challenged.raw_finding, NOW + 1)
            .expect_err("a malformed recipe preimage is not a filing");
        let ChallengeCoordinatorError::ChallengeEnvelope(detail) = &refused else {
            return Err(format!("unexpected rejection: {refused}").into());
        };
        assert!(
            detail.contains("replay_contradiction.recipe_preimage"),
            "the carried preimage is what the validator refused: {detail}"
        );
        assert!(
            deployment
                .challenges
                .get_challenge(&challenge.body.challenge_id)?
                .is_none(),
            "a refused filing writes no challenge row"
        );
    }
    assert!(
        deployment.rail.charges().is_empty(),
        "a refused filing collects no dispute fee"
    );

    // The same filing carrying the committed preimage is admitted, so the
    // refusals above are the preimage and not the rest of the submission.
    coordinator.submit(&sound.challenge, &challenged.raw_finding, NOW + 1)?;
    assert!(deployment
        .challenges
        .get_challenge(&sound.challenge.body.challenge_id)?
        .is_some());
    Ok(())
}
#[test]
fn finding_challenge_harmed_buyer_allocation_is_capped_and_exactly_summed() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let challenger_sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let other_sale = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 50, NOW + 1)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &challenger_sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;

    // Live collateral below the checked candidate is the binding cap, and
    // it is below the verified harm as well, so every unit slashed reaches
    // a harmed buyer and none reaches the community fund.
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 80);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        2,
        &[
            challenger_sale.purchase_key.clone(),
            other_sale.purchase_key.clone(),
        ],
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    let sealed = &upheld.sealed;
    assert_eq!(sealed.distribution.slash, usd(80));
    assert_eq!(sealed.total_realized_spend_units, 100);
    assert_eq!(sealed.distribution.buyer_pool_units, 80);
    assert_eq!(sealed.distribution.community_fund_units, 0);
    let allocation = allocation_by_destination(&sealed.distribution);
    assert_eq!(
        allocation,
        std::collections::BTreeMap::from([
            (buyer_destination(41), 40),
            (buyer_destination(42), 40),
        ])
    );
    let summed: u64 = allocation.values().sum();
    assert_eq!(summed, sealed.distribution.slash.units);

    // Every destination in the distribution was admitted by the sale path.
    let admitted: Vec<String> = deployment
        .purchases
        .list_payout_destinations(&deployment.allocation_id)?
        .into_iter()
        .map(|(_, destination)| destination)
        .collect();
    for destination in allocation.keys() {
        assert!(
            admitted.contains(destination),
            "a payout destination that was never admitted must not be paid"
        );
    }
    assert!(!allocation.contains_key(CHALLENGER_BOUNTY_DESTINATION));
    Ok(())
}
#[test]
fn finding_challenge_a_purchase_that_lost_payout_standing_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase_with(
        &deployment,
        &deployment.allocation_id,
        "alpha",
        BUYER_ONE_DESTINATION,
        50,
        "USD",
        NOW,
        PayoutStanding::RemovedAfterSettlement,
    )?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    remove_payout_standing_for_test(
        &deployment,
        &deployment.allocation_id,
        &sale.record.body.payout_destination,
    )?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let refused = coordinator
        .uphold(
            &case.challenge.body.challenge_id,
            &case.challenge,
            &evaluated.outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            1,
            std::slice::from_ref(&sale.purchase_key),
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 3,
        )
        .expect_err("a purchase that lost payout standing cannot be paid");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(reason)
            if reason.contains("changed outside its serving-owner connection")
    ));
    let snapshots = rusqlite::Connection::open(&deployment.database)?.query_row(
        "SELECT COUNT(*) FROM claim_snapshots",
        [],
        |row| row.get::<_, i64>(0),
    );
    assert_eq!(snapshots?, 0, "the corrupted index seals no accounting");
    Ok(())
}
#[test]
fn finding_challenge_a_clean_venue_audit_without_revocation_status_transfers_nothing() -> TestResult
{
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::Sound,
        &sale,
        Filing::VenueAudit,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    let submitted = coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    assert!(submitted.dispute_fee_intent_key.is_none());
    assert!(submitted.dispute_bond_lock_id.is_none());

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence_without_production_status();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("a resolvable audit is adjudicated")?;
    assert_eq!(
        evaluated.state,
        FindingChallengeState::IndeterminateRetryable
    );
    assert_eq!(
        evaluated.outcome.body.reason,
        "evidence_key_revocation_not_established"
    );
    assert!(evaluated.outcome.body.penalty_calculation.is_none());
    assert_eq!(
        evaluated.bond_disposition, None,
        "a bondless audit has no disposition under any verdict"
    );

    assert!(
        deployment.rail.charges().is_empty(),
        "a clean audit moves nothing on the rail"
    );
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .is_none());
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        0
    );
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
#[test]
fn finding_challenge_an_indeterminate_result_closes_without_revocation_status() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(&challenged, ProductionShape::Sound, &sale, Filing::Buyer)?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);

    // The resolver handed back a checkpoint that is not the artifact the
    // reference names. Nothing about the seller is established.
    let unresolved = case.unresolved_evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &unresolved,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("an unresolved input is still an adjudication")?;
    assert_eq!(
        first.outcome.body.verdict,
        chio_finding::FindingChallengeVerdict::Indeterminate
    );
    assert_eq!(
        first.outcome.body.reason,
        "evidence_checkpoint_not_established"
    );
    assert_eq!(first.state, FindingChallengeState::IndeterminateRetryable);
    assert_eq!(
        first.outcome.body.retry_deadline,
        Some(RETRY_POLICY_DEADLINE),
        "the evaluator signs the signed-artifact-derived retry horizon"
    );
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("challenge is durable")?
            .retry_deadline,
        Some(RETRY_POLICY_DEADLINE)
    );
    assert_eq!(first.bond_disposition, None);
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Locked,
        "an indeterminate result never forfeits an infrastructure failure"
    );

    // The retry resolves the checkpoint but still has no authenticated
    // revocation status for the production key. The bounded retry closes
    // indeterminate and returns the buyer's lock rather than treating an
    // unknown authority fact as innocence.
    let resolved = case.evidence_without_production_status();
    let second = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &resolved,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the retry adjudicates")?;
    assert_eq!(second.state, FindingChallengeState::IndeterminateClosed);
    assert_eq!(
        second.outcome.body.reason,
        "evidence_key_revocation_not_established"
    );
    assert_eq!(
        second.bond_disposition,
        Some(FindingDisputeLockDisposition::Returned)
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "the retry adds only the terminal bond return to the original fee and funding"
    );
    Ok(())
}
#[test]
fn finding_challenge_retry_exhaustion_closes_indeterminate_and_returns_the_lock_once() -> TestResult
{
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(&challenged, ProductionShape::Sound, &sale, Filing::Buyer)?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let unresolved = case.unresolved_evidence();
    for (attempt, expected) in [
        (NOW + 2, FindingChallengeState::IndeterminateRetryable),
        (NOW + 3, FindingChallengeState::IndeterminateClosed),
    ] {
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &unresolved,
                &collateral,
                attempt,
            ))?
            .ok_or("an unresolved input is still an adjudication")?;
        assert_eq!(evaluated.state, expected);
        assert_eq!(
            evaluated.outcome.body.verdict,
            chio_finding::FindingChallengeVerdict::Indeterminate
        );
        if expected == FindingChallengeState::IndeterminateClosed {
            assert_eq!(evaluated.outcome.body.retry_deadline, None);
        }
    }

    // The single retry the store grants is spent, so a live window no
    // longer keeps the challenge open, and the lock comes back once.
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .ok_or("lock is durable")?;
    assert_eq!(lock.state, FindingDisputeLockState::Returned);
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge_id, NOW + 4)?,
        Some(FindingDisputeLockDisposition::Returned),
        "replaying the disposition returns the same terminal"
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "an exhausted retry collects no second fee, funding, or return"
    );
    Ok(())
}
#[test]
fn finding_challenge_the_nested_replay_mapping_holds_through_the_coordinator() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);

    let cases = [
        (
            vec![PhaseShape::baseline_fails(), PhaseShape::candidate_passes()],
            FindingReplayPredicateResult::Consistent,
            chio_finding::FindingChallengeVerdict::Rejected,
            FindingChallengeState::Rejected,
        ),
        (
            vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
            FindingReplayPredicateResult::ConfirmedContradiction,
            chio_finding::FindingChallengeVerdict::Upheld,
            FindingChallengeState::Upheld,
        ),
        (
            vec![PhaseShape::baseline_fails()],
            FindingReplayPredicateResult::Indeterminate,
            chio_finding::FindingChallengeVerdict::Indeterminate,
            FindingChallengeState::IndeterminateRetryable,
        ),
    ];
    for (index, (phases, predicate_result, verdict, state)) in cases.into_iter().enumerate() {
        // Each filing posts its own exclusive lock, so the reproduction
        // sets reach the store as distinct challenges.
        let case = replay_case(
            &challenged,
            &format!("replay-{index}"),
            &phases,
            None,
            &sale,
        )?;
        coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

        let reproductions = case.reproductions();
        let evidence = case.evidence(&reproductions);
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                NOW + 2,
            ))?
            .ok_or("every reproduction set above is admissible")?;
        assert_eq!(evaluated.outcome.body.verdict, verdict);
        assert_eq!(evaluated.state, state);
        let FindingChallengeFacet::ReplayContradiction(facet) = &evaluated.outcome.body.facet
        else {
            return Err("a replay challenge carries a replay facet".into());
        };
        assert_eq!(facet.predicate_result, predicate_result);
    }
    Ok(())
}
#[test]
fn finding_challenge_a_second_challenge_for_one_defect_authorizes_no_second_slash() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);

    // Two independent filings against the same defect: one contests the
    // evidence, the other reproduces the recipe.
    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    coordinator.submit(&invalid.challenge, &challenged.raw_finding, NOW + 1)?;
    coordinator.submit(&replay.challenge, &challenged.raw_finding, NOW + 1)?;

    let invalid_evidence = invalid.evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &invalid.challenge,
            &challenged,
            &invalid_evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the evidence filing is adjudicated")?;
    let reproductions = replay.reproductions();
    let replay_evidence = replay.evidence(&reproductions);
    let second = coordinator
        .evaluate(&evaluation_request(
            &replay.challenge,
            &challenged,
            &replay_evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;
    assert_eq!(first.state, FindingChallengeState::Upheld);
    assert_eq!(second.state, FindingChallengeState::Upheld);

    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &invalid.challenge,
        &first.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    let refused = coordinator
        .uphold(
            &replay.challenge.body.challenge_id,
            &replay.challenge,
            &second.outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            1,
            std::slice::from_ref(&sale.purchase_key),
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 5,
        )
        .expect_err("one defect carries exactly one slashable liability");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));

    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1,
        "a second corroborating challenge joins the head rather than opening one"
    );
    let sealed = coordinator
        .sealed_claim(&upheld.liability_key)?
        .ok_or("the accounting is sealed once")?;
    assert_eq!(sealed.0, upheld.sealed.snapshot_digest);
    assert_eq!(sealed.1, upheld.sealed.allocation_digest);
    assert_eq!(
        deployment
            .challenges
            .get_liability(&upheld.liability_key)?
            .ok_or("liability head is durable")?
            .upheld_challenge_id,
        Some(invalid.challenge.body.challenge_id.clone()),
        "the head still names the challenge that carried it"
    );
    Ok(())
}
#[test]
fn finding_challenge_concurrent_upholds_authorize_one_slash() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let candidates = [sale.purchase_key.clone()];

    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    coordinator.submit(&invalid.challenge, &challenged.raw_finding, NOW + 1)?;
    coordinator.submit(&replay.challenge, &challenged.raw_finding, NOW + 1)?;
    let invalid_evidence = invalid.evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &invalid.challenge,
            &challenged,
            &invalid_evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the evidence filing is adjudicated")?;
    let reproductions = replay.reproductions();
    let replay_evidence = replay.evidence(&reproductions);
    let second = coordinator
        .evaluate(&evaluation_request(
            &replay.challenge,
            &challenged,
            &replay_evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;

    // Both filings race the upheld transaction against the same liability
    // head, once at the call that opens the claim window and again at the
    // call that seals the payout past it. The compare-and-set admits one
    // of them and only one, in both races.
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let race = |now: u64| {
        let filings = [
            (&invalid.challenge, &first.outcome),
            (&replay.challenge, &second.outcome),
        ];
        std::thread::scope(|scope| {
            let handles: Vec<_> = filings
                .into_iter()
                .map(|(challenge, outcome)| {
                    let coordinator = &coordinator;
                    let governance = &governance;
                    let identity = &identity;
                    let collateral = &collateral;
                    let candidates = &candidates;
                    let terms = &terms;
                    scope.spawn(move || {
                        coordinator.uphold(
                            &challenge.body.challenge_id,
                            challenge,
                            outcome,
                            identity,
                            terms,
                            1,
                            candidates,
                            collateral,
                            &governance.context(),
                            &governance.sanction_case,
                            now,
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(std::thread::ScopedJoinHandle::join)
                .collect::<Vec<_>>()
        })
    };

    let mut opened = 0_usize;
    for result in race(NOW + 4 - CLAIM_WINDOW_SECS) {
        if matches!(
            result.map_err(|_| "the upheld transaction panicked")?,
            Err(ChallengeCoordinatorError::ClaimWindowOpen)
        ) {
            opened += 1;
        }
    }
    assert_eq!(
        opened, 1,
        "one filing freezes the claim window and the other is refused"
    );

    let joined = race(NOW + 4);
    let mut upheld = Vec::new();
    let mut refused = 0_usize;
    for result in joined {
        match result.map_err(|_| "the upheld transaction panicked")? {
            Ok(liability) => upheld.push(liability),
            Err(_) => refused += 1,
        }
    }
    assert_eq!(upheld.len(), 1, "one defect authorizes exactly one slash");
    assert_eq!(refused, 1);
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1
    );

    let winner = upheld.first().ok_or("one filing carried the liability")?;
    let sealed = coordinator
        .sealed_claim(&winner.liability_key)?
        .ok_or("the accounting is sealed once")?;
    assert_eq!(sealed.0, winner.sealed.snapshot_digest);
    assert_eq!(sealed.1, winner.sealed.allocation_digest);
    assert_eq!(winner.sealed.distribution.buyer_pool_units, 50);
    Ok(())
}
#[test]
fn finding_challenge_a_restart_resumes_the_same_durable_state() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let allocation_id = deployment.allocation_id.clone();
    let collateral = collateral_facts(&stake, &required, &allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;
    let identity = liability_identity(&challenged.finding.finding_id, &allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;

    drop(coordinator);
    let deployment = deployment.restart()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;

    // The durable state survives the restart exactly as it was left.
    let record = deployment
        .challenges
        .get_challenge(&challenge_id)?
        .ok_or("the challenge is durable")?;
    assert_eq!(record.state, FindingChallengeState::Upheld);
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Returned
    );
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);

    // A resumed worker replays the filing and the upheld transaction. The
    // fee reconciles against the settled charge, the lock replays as the
    // same lock, and the penalty is the one already minted rather than a
    // second one.
    let resubmitted = coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 4)?;
    assert_eq!(
        resubmitted.write,
        chio_store_sqlite::FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "a restarted filing collects no second fee, funding, or return"
    );
    let replayed = coordinator.uphold(
        &challenge_id,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        &market_terms(CLAIM_WINDOW_SECS)?,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;
    assert_eq!(replayed.liability_key, upheld.liability_key);
    assert_eq!(replayed.sealed, upheld.sealed);
    assert_eq!(
        replayed.hold.penalty_envelope_sha256, upheld.hold.penalty_envelope_sha256,
        "the replay re-derives the penalty it already minted"
    );
    assert_eq!(
        replayed.hold.evaluation.penalty_id,
        upheld.hold.evaluation.penalty_id
    );
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1
    );
    Ok(())
}
#[test]
fn finding_challenge_construction_refuses_a_key_reused_across_roles() -> TestResult {
    let deployment = deployment()?;
    let mut config = market_config();
    // One key adjudicating and finalizing collapses the separation the
    // whole lane rests on.
    config.venue_finalization = authority_pin(31, "venue-finalization");
    let refused = FindingChallengeCoordinator::new_with_status_commit_clock(
        deployment.challenges.clone(),
        deployment.purchases.clone(),
        deployment.status.clone(),
        &config,
        keypair(31),
        keypair(31),
        keypair(33),
        Arc::new(TestAuthorityStatusResolver::live()),
        deployment.rail.clone(),
        deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    );
    match refused {
        Err(ChallengeCoordinatorError::Configuration(_)) => {}
        Err(other) => return Err(format!("unexpected rejection: {other}").into()),
        Ok(_) => return Err("a key reused across roles must not load".into()),
    }
    Ok(())
}
#[test]
fn finding_challenge_an_expired_reservation_neither_wedges_nor_inflates_the_claim() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, raw) = finding_artifact()?;
    let harmed = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;

    // A purchase that took the next slot and was then abandoned: nothing
    // settles it, denies it, or releases it, and its expiry passes before
    // adjudication. Without the expiry sweep it would hold slot two open
    // forever, and its encumbrance would inflate the sealed slash.
    deployment
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: "reservation-abandoned",
            purchase_intent_id: "intent-abandoned",
            authoritative_payment_operation_id: "payment-abandoned",
            payer_hex: &keypair(41).public_key().to_hex(),
            agent_id: "agent-buyer-01",
            payout_destination: EVM_BUYER_DESTINATION,
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &digest("bid-abandoned"),
            ask_digest: &digest("ask-abandoned"),
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
            fee_schedule_envelope_sha256: &deployment.fee_schedule_envelope_sha256,
            participation_epoch: 0,
            amount_units: 100,
            currency: "USD",
            expires_at: NOW + 5,
            encumbrance_id: "encumbrance-abandoned",
            allocation_id: &deployment.allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW + 1,
        })?;
    deployment
        .purchases
        .reserve_slot("reservation-abandoned", NOW + 1)?;

    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW + 2)?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id, 100, "USD")?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    deployment
        .purchases
        .expire_reservations(NOW + 6, usize::MAX)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        NOW + 6,
    )?;

    let stake = usd(300);
    let required = usd(5_000);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &challenge,
        &outcome,
        &liability_identity(&finding.finding_id, &deployment.allocation_id),
        2,
        &[harmed.purchase_key],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 7,
    )?;

    let reservation = deployment
        .purchases
        .get_reservation("reservation-abandoned")?
        .ok_or("abandoned reservation is durable")?;
    assert_eq!(
        reservation.state,
        chio_store_sqlite::FindingPurchaseReservationState::Expired,
        "the claim path retires the reservation instead of waiting on it"
    );
    // The sealed accounting reads live exposure only: the base stake plus
    // the settled sale's retained encumbrance, with nothing from the
    // reservation that could never settle.
    assert_eq!(upheld.sealed.distribution.slash.units, 400);
    assert_eq!(upheld.sealed.distribution.buyer_pool_units, 60);
    assert_eq!(upheld.sealed.total_realized_spend_units, 60);
    Ok(())
}
#[test]
fn finding_challenge_uphold_refuses_an_outcome_for_a_different_challenge() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, _) = finding_artifact()?;

    // Two distinct challenges on one finding and listing, each closed
    // upheld under its own signed outcome.
    let first = venue_audit_challenge()?;
    let mut second_body = first.body.clone();
    second_body.filed_at = NOW + 1;
    second_body.challenge_id = compute_challenge_id(&second_body)?;
    let second = SignedExportEnvelope::sign(second_body, &keypair(35))?;
    let mut outcomes = Vec::new();
    for (challenge, at) in [(&first, NOW), (&second, NOW + 1)] {
        deployment
            .challenges
            .submit_challenge(&chio_store_sqlite::FindingChallengeSubmission {
                challenge_id: &challenge.body.challenge_id,
                finding_id: &finding.finding_id,
                listing_id: LISTING_ID,
                challenge_envelope_sha256: &signed_envelope_sha256(challenge)?,
                challenge_envelope_json: &canonical_json_bytes(challenge)?,
                authorization_branch:
                    chio_store_sqlite::FindingChallengeAuthorizationBranch::VenueAudit,
                evidence_class: chio_store_sqlite::FindingChallengeEvidenceClass::EvidenceInvalid,
                challenger_hex: None,
                submitted_at: at,
            })?;
        let outcome = upheld_outcome(challenge, &deployment.allocation_id, 0, "USD")?;
        let outcome_json = canonical_json_bytes(&outcome)?;
        close_challenge(
            &deployment,
            &challenge.body.challenge_id,
            FindingChallengeVerdict::Upheld,
            &signed_envelope_sha256(&outcome)?,
            &outcome_json,
            at + 2,
        )?;
        outcomes.push(outcome);
    }
    let first_outcome = outcomes.remove(0);

    // The first challenge's outcome presented under the second
    // challenge's id: both are upheld on this finding and listing, so
    // only the envelope binding separates them.
    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&finding.finding_id, &deployment.allocation_id);
    let refused = coordinator
        .uphold(
            &second.body.challenge_id,
            &second,
            &first_outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 4,
        )
        .expect_err("an outcome upholds only the challenge its envelope digest names");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    assert_eq!(
        liability_heads(&deployment, &finding.finding_id)?,
        0,
        "a cross-bound outcome opens no liability"
    );

    // The true pair still upholds: the binding admits exactly the
    // challenge the outcome adjudicated.
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &first,
        &first_outcome,
        &identity,
        0,
        &[],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 6,
    )?;
    assert_eq!(upheld.sealed.distribution.slash.units, 300);
    Ok(())
}
