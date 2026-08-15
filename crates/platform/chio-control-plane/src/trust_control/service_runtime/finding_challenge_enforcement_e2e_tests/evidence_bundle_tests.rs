use super::*;

#[test]
fn finding_challenge_evidence_bundle_commits_resolved_membership_inputs() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(&challenged, ProductionShape::Sound, &sale, Filing::Buyer)?;
    let status_resolver = TestAuthorityStatusResolver::live();
    let purchase_pin = market_config().purchase;
    let purchase_status = status_resolver
        .resolve(&purchase_pin, NOW + 2)
        .map_err(std::io::Error::other)?;
    let later_purchase_status = status_resolver
        .resolve(&purchase_pin, NOW + 3)
        .map_err(std::io::Error::other)?;
    let governance_pin = market_config().governance_root;
    let governance_status = status_resolver
        .resolve(&governance_pin, NOW + 2)
        .map_err(std::io::Error::other)?;
    let later_governance_status = status_resolver
        .resolve(&governance_pin, NOW + 3)
        .map_err(std::io::Error::other)?;

    let resolved = case.evidence();
    let unresolved = case.unresolved_evidence();
    let resolved_digest = coordinator.evidence_bundle_digest(
        &case.challenge.body,
        &resolved,
        Some(&purchase_status),
        &governance_status,
        None,
    )?;
    let unresolved_digest = coordinator.evidence_bundle_digest(
        &case.challenge.body,
        &unresolved,
        Some(&purchase_status),
        &governance_status,
        None,
    )?;

    assert_ne!(
        resolved_digest, unresolved_digest,
        "checkpoint and transparency substitutions must change the signed evidence commitment"
    );
    assert_ne!(
        resolved_digest,
        coordinator.evidence_bundle_digest(
            &case.challenge.body,
            &resolved,
            Some(&later_purchase_status),
            &governance_status,
            None,
        )?,
        "purchase standing substitutions must change the evidence-invalid commitment"
    );
    assert_ne!(
        resolved_digest,
        coordinator.evidence_bundle_digest(
            &case.challenge.body,
            &resolved,
            Some(&purchase_status),
            &later_governance_status,
            None,
        )?,
        "governance status substitutions must change the evidence commitment"
    );

    let replay = replay_case(
        &challenged,
        "bundle-status",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_passes()],
        None,
        &sale,
    )?;
    let reproductions = replay.reproductions();
    let replay_evidence = replay.evidence(&reproductions);
    let replay_digest = coordinator.evidence_bundle_digest(
        &replay.challenge.body,
        &replay_evidence,
        Some(&purchase_status),
        &governance_status,
        None,
    )?;
    assert_ne!(
        replay_digest,
        coordinator.evidence_bundle_digest(
            &replay.challenge.body,
            &replay_evidence,
            Some(&later_purchase_status),
            &governance_status,
            None,
        )?,
        "purchase standing substitutions must change the replay commitment"
    );
    Ok(())
}
