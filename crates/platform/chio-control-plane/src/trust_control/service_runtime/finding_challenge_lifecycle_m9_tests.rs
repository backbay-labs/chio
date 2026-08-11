use super::*;

#[test]
fn finding_challenge_governance_charter_must_be_issued_inside_the_pinned_window() -> TestResult {
    let mut deployment = deployment()?;
    let governance = governance()?;
    let mut historical_policy = market_config().governance_root;
    historical_policy.valid_from = NOW - 650;
    Arc::make_mut(&mut deployment.filings)
        .case_governance_policies
        .insert(
            signed_envelope_sha256(&governance.charter)?,
            historical_policy,
        );
    let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let ready = ready_to_uphold(&deployment, &live)?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let stake = usd(300);
    let required = usd(5_000);

    let refused = coordinator
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
        .expect_err("a same-key charter predating the configured lifecycle opens no liability");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AuthorityLifecycle {
            role: "historical governance charter",
            ..
        }
    ));
    assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
