use super::*;

#[test]
fn finding_challenge_a_reorged_transaction_receipt_never_settles() -> TestResult {
    let case = finalizing_liability()?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &ReorgedReceiptPublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a transaction missing from the immediate canonical recheck cannot settle");
    assert!(matches!(refused, ChallengeCoordinatorError::Settlement(_)));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Failed,
        "a receipt that failed its immediate recheck is not confirmed"
    );
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(parked.quarantined);
    assert!(parked.publication_pending);
    Ok(())
}
#[test]
fn finding_challenge_a_confirmed_impairment_settles_without_dispatching_again() -> TestResult {
    let case = finalizing_liability()?;
    // An attempt that confirmed the impairment and died before it could
    // settle the head leaves exactly this durable state.
    case.confirm_impairment(SETTLEMENT_NOW)?;
    case.mark_status_eligible(&chain_hash(0x77), SETTLEMENT_NOW)?;
    case.publish_status(SETTLEMENT_NOW + 1)?;

    let resumed = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 2)?;
    assert_eq!(resumed, FindingFinalization::AlreadyConfirmed);
    let settled = case.head()?;
    assert_eq!(
        settled.state,
        FindingLiabilityState::Settled,
        "the resumed attempt finishes the settlement the interrupted one owed"
    );
    assert!(!settled.publication_pending);
    Ok(())
}
#[test]
fn finding_challenge_confirmed_recovery_reobserves_transaction_finality() -> TestResult {
    let case = finalizing_liability()?;
    case.confirm_impairment(SETTLEMENT_NOW)?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &ReorgedReceiptPublisher,
            SETTLEMENT_NOW + 1,
        )?
        .expect_err("recovery cannot inherit an earlier receipt observation");
    assert!(matches!(refused, ChallengeCoordinatorError::Settlement(_)));
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(parked.quarantined);
    Ok(())
}
#[test]
fn finding_challenge_confirmed_impairment_waits_for_retraction_before_settlement() -> TestResult {
    let case = finalizing_liability_pending_retraction()?;
    case.confirm_impairment(SETTLEMENT_NOW)?;

    let waiting = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 1)?;
    assert_eq!(waiting, FindingFinalization::AwaitingStatusPublication);
    let pending = case.head()?;
    assert_eq!(pending.state, FindingLiabilityState::Finalizing);
    assert!(pending.publication_pending);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);

    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.retraction_key,
            state,
            SETTLEMENT_NOW + 2,
        )?;
    }
    case.mark_status_eligible(&chain_hash(0x77), SETTLEMENT_NOW + 2)?;
    case.publish_status(SETTLEMENT_NOW + 3)?;
    let settled = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 4)?;
    assert_eq!(settled, FindingFinalization::AlreadyConfirmed);
    let head = case.head()?;
    assert_eq!(head.state, FindingLiabilityState::Settled);
    assert!(!head.publication_pending);
    Ok(())
}
#[test]
fn finding_challenge_finalization_reuses_pending_voluntary_retraction() -> TestResult {
    let case = finalizing_liability_with_prior_retraction(
        EnforcementRoot::Confirmed,
        true,
        PriorVoluntaryRetraction::Pending,
    )?;
    let resolved = case
        .deployment
        .status
        .get_retraction_intent_for_effect(
            &case.retraction_key,
            "status-feed/venue-challenge",
            &case.enforcement.body.finding_id,
        )?
        .ok_or("voluntary retraction satisfies the enforcement effect")?;
    assert_eq!(resolved.intent_id, case.status_intent_key);
    assert_eq!(
        resolved.source,
        chio_store_sqlite::FindingRetractionIntentSource::Voluntary
    );
    case.confirm_impairment(SETTLEMENT_NOW)?;

    assert_eq!(
        case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 1)?,
        FindingFinalization::AwaitingStatusPublication
    );
    case.publish_status(SETTLEMENT_NOW + 2)?;
    assert_eq!(
        case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 3)?,
        FindingFinalization::AlreadyConfirmed
    );
    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    Ok(())
}
#[test]
fn finding_challenge_finalization_reuses_published_voluntary_retraction() -> TestResult {
    let case = finalizing_liability_with_prior_retraction(
        EnforcementRoot::Confirmed,
        true,
        PriorVoluntaryRetraction::Published,
    )?;
    case.confirm_impairment(SETTLEMENT_NOW)?;

    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    Ok(())
}
#[test]
fn finding_challenge_confirmed_impairment_settles_after_snapshot_expiry() -> TestResult {
    let case = finalizing_liability_pending_retraction()?;
    case.confirm_impairment(SETTLEMENT_NOW)?;

    let stale_at = OBSERVED_AT + MAX_SNAPSHOT_AGE_SECS + 1;
    assert_eq!(
        case.finalize(&UnreachablePublisher, stale_at)?,
        FindingFinalization::AwaitingStatusPublication,
        "a landed impairment waits on signed status without revalidating its old snapshot"
    );
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.retraction_key,
            state,
            stale_at + 1,
        )?;
    }
    case.mark_status_eligible(&chain_hash(0x77), stale_at + 1)?;
    case.publish_status(stale_at + 2)?;
    assert_eq!(
        case.finalize(&UnreachablePublisher, stale_at + 3)?,
        FindingFinalization::AlreadyConfirmed
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Settled);
    Ok(())
}
#[test]
fn finding_challenge_published_retraction_reconciles_after_status_bond_expiry() -> TestResult {
    let mut case = finalizing_liability_pending_retraction()?;
    case.confirm_impairment(SETTLEMENT_NOW)?;

    assert_eq!(
        case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 1)?,
        FindingFinalization::AwaitingStatusPublication
    );
    case.publish_status(SETTLEMENT_NOW + 2)?;

    let mut expired_status_bond = market_config();
    expired_status_bond.status_feed_service_bond.valid_until = SETTLEMENT_NOW + 2;
    case.coordinator = case.deployment.coordinator_under(
        &expired_status_bond,
        FindingDisputeLockDisposition::Forfeited,
    )?;
    assert_eq!(
        case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 3)?,
        FindingFinalization::AlreadyConfirmed,
        "a published retraction reconciles from retained evidence without a new SLA"
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Settled);
    Ok(())
}
#[test]
fn finding_challenge_a_superseded_sanction_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    // Another sanction recorded after the enforcement was signed and
    // fenced supersedes the one its penalty names. The head is still a
    // sanction, but it is not the exact authority this impairment binds.
    let head = case.head()?;
    case.deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: "case-sanction-replacement-01",
            finding_id: &head.finding_id,
            listing_id: LISTING_ID,
            liability_key: &case.liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Sanction,
            case_state: "enforced",
            appeal_of_case_id: None,
            supersedes_case_id: Some(FIXTURE_SANCTION_CASE_ID),
            recorded_at: SETTLEMENT_NOW - 1,
        },
    )?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a superseded sanction authorizes no impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "the impairment intent is never even dispatched"
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_every_transient_publisher_failure_counts_one_attempt() -> TestResult {
    let case = finalizing_liability()?;
    for attempt in 1..=3_u64 {
        let refused = case
            .finalize_observing(
                &ScriptedObservations::qualified(),
                &UnreachableChainPublisher,
                SETTLEMENT_NOW + attempt,
            )?
            .expect_err("a publisher that cannot reach the chain reports no outcome");
        assert!(matches!(refused, ChallengeCoordinatorError::Publisher(_)));
        let intent = case.intent()?;
        assert_eq!(
            intent.attempt_count, attempt,
            "every dispatch an operator paid for is on the record"
        );
        assert_eq!(
            intent.state,
            FindingEffectIntentState::Failed,
            "the impairment stays dispatchable after a failure to reach the chain"
        );
    }
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
#[test]
fn finding_challenge_an_unpublished_enforcement_root_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability_rooted(EnforcementRoot::Unpublished)?;
    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("the vault call is authorized by a root that has not been published");
    assert!(
        matches!(
            refused,
            ChallengeCoordinatorError::EnforcementRootUnconfirmed(_)
        ),
        "unexpected refusal: {refused:?}"
    );
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "nothing was dispatched, so the impairment never left its fence"
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
#[test]
fn finding_challenge_a_confirmed_different_merkle_root_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability_rooted(EnforcementRoot::Mismatched)?;
    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a confirmation for another Merkle root authorizes no vault call");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_an_anchor_leaf_bound_elsewhere_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability_without_anchor()?;
    // The same anchored receipt is already committed to other terms, which
    // is what a proof reused across enforcements looks like once the leaf
    // is fenced.
    case.deployment.challenges.record_effect_intent(
        &derive_anchor_evidence_intent_key(&anchor_evidence_hash(&case.enforcement)?),
        chio_store_sqlite::FindingEffectIntentKind::RootIntent,
        &digest("an impairment this proof already authorized"),
        Some(&case.liability_key),
        false,
        NOW + 7,
    )?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("one anchored leaf authorizes one impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_a_reorged_bond_observation_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    // The observer signed for a block the chain no longer carries at that
    // height, so what it reported about the collateral is unknown.
    let reorged = FindingBondObservationRecheck {
        block_hash: Some(chain_hash(0xcd)),
        ..qualified_observation()
    };

    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![reorged]),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a snapshot whose block was reorged out authorizes nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "nothing was dispatched, so the intent never left its fence"
    );
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
#[test]
fn finding_challenge_an_observer_cannot_weaken_deployment_finality() -> TestResult {
    let case = finalizing_liability_before_root_binding()?;

    // The trusted observer signs a self-consistent snapshot at one
    // confirmation, then the finalization authority binds that exact
    // snapshot. The deployment still requires 64 confirmations, so neither
    // signature may weaken the operator-pinned chain policy.
    let mut snapshot_body = case.snapshot.body.clone();
    snapshot_body.finality_policy = "confirmations>=1".to_string();
    snapshot_body.observed_finality = FindingObservedFinality::Confirmations { depth: 1 };
    snapshot_body.snapshot_id = String::new();
    snapshot_body.snapshot_id = compute_snapshot_id(&snapshot_body)?;
    let snapshot = SignedExportEnvelope::sign(snapshot_body, &keypair(34))?;

    let refused = case
        .coordinator
        .refresh_finalizing_enforcement(
            &case.authorized()?,
            &snapshot,
            &case.seller,
            SETTLEMENT_NOW,
        )
        .expect_err("the observer cannot choose a shallower finality policy");
    assert!(
        matches!(
            &refused,
            ChallengeCoordinatorError::Settlement(detail)
                if detail.contains("does not match the pinned finality requirement")
        ),
        "{refused:?}"
    );
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_snapshot_seller_must_match_the_durable_liability() -> TestResult {
    let case = finalizing_liability()?;
    let substituted_seller = keypair(74).public_key();
    let mut snapshot_body = case.snapshot.body.clone();
    snapshot_body.seller = substituted_seller.clone();
    snapshot_body.snapshot_id = String::new();
    snapshot_body.snapshot_id = compute_snapshot_id(&snapshot_body)?;
    let snapshot = SignedExportEnvelope::sign(snapshot_body, &keypair(34))?;

    let mut enforcement_body = case.enforcement.body.clone();
    enforcement_body.bond_snapshot_envelope_sha256 = signed_envelope_sha256(&snapshot)?;
    enforcement_body.enforcement_id = String::new();
    enforcement_body.enforcement_id = compute_enforcement_id(&enforcement_body)?;
    let enforcement = SignedExportEnvelope::sign(enforcement_body, &keypair(32))?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &enforcement,
            &case.penalty,
            &snapshot,
            &substituted_seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&enforcement)?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("an observer cannot substitute the liability's admitted seller");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityIdentity("seller")
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    Ok(())
}
#[test]
fn finding_challenge_regressed_confirmation_depth_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    let shallow = FindingBondObservationRecheck {
        observed_finality: FindingObservedFinality::Confirmations { depth: 63 },
        ..qualified_observation()
    };

    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![shallow]),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a snapshot below the current confirmation floor authorizes nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_confirmed_impairment_recovers_across_observer_and_operator_rotation(
) -> TestResult {
    let case = finalizing_liability()?;
    let publisher = MiningPublisher::new();

    // The first attempt broadcasts and comes back unmined, which leaves
    // the intent dispatchable.
    case.finalize(&publisher, SETTLEMENT_NOW)?;
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Failed);

    // The transaction then mines and finalizes, but the operator identity
    // the observation was qualified under rotated in the meantime. The
    // impairment is real and the intent confirms; the head must not.
    let rotated = FindingBondObservationRecheck {
        operator_key_epoch: 4,
        ..qualified_observation()
    };
    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![qualified_observation(), rotated]),
            &publisher,
            SETTLEMENT_NOW + 60,
        )?
        .expect_err("a rotated operator leaves the impairment for reconciliation");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Confirmed,
        "the transaction was proved to be this intent, so it is never redispatched"
    );
    let parked = case.head()?;
    assert_eq!(
        parked.state,
        FindingLiabilityState::Finalizing,
        "the head stays open for the operator who has to reconcile it"
    );
    assert!(parked.quarantined);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);

    let still_rotated = FindingBondObservationRecheck {
        operator_key_epoch: 4,
        ..qualified_observation()
    };
    let mut rotated_config = market_config();
    rotated_config.settlement_observer = authority_pin(51, "settlement-observer-rotated");
    let rotated_coordinator = FindingChallengeCoordinator::new_with_status_commit_clock(
        case.deployment.challenges.clone(),
        case.deployment.purchases.clone(),
        case.deployment.status.clone(),
        &rotated_config,
        keypair(31),
        keypair(32),
        keypair(33),
        Arc::new(TestAuthorityStatusResolver::live()),
        case.deployment.rail.clone(),
        case.deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    )?;
    let recovered = rotated_coordinator.finalize(
        &case.liability_key,
        &case.enforcement,
        &case.penalty,
        &case.snapshot,
        &case.seller,
        &settlement_config()?,
        &settlement_config()?.operator_address,
        &evm_vault_snapshot(),
        &enforcement_anchor_proof(&case.enforcement)?,
        &ScriptedObservations::then_qualified(vec![still_rotated]),
        &UnreachablePublisher,
        SETTLEMENT_NOW + 120,
    )?;
    assert_eq!(recovered, FindingFinalization::AwaitingStatusPublication);
    let reconciled = case.head()?;
    assert_eq!(reconciled.state, FindingLiabilityState::Finalizing);
    assert!(!reconciled.quarantined);

    case.publish_status(SETTLEMENT_NOW + 181)?;
    let completed = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 182)?;
    assert_eq!(completed, FindingFinalization::AlreadyConfirmed);
    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.quarantined);
    Ok(())
}
#[test]
fn finding_challenge_enforcement_recovers_across_finalization_authority_rotation() -> TestResult {
    let case = finalizing_liability()?;
    let mut rotated = market_config();
    rotated.venue_finalization = authority_pin(49, "venue-finalization-rotated");
    let coordinator = FindingChallengeCoordinator::new_with_status_commit_clock(
        case.deployment.challenges.clone(),
        case.deployment.purchases.clone(),
        case.deployment.status.clone(),
        &rotated,
        keypair(31),
        keypair(49),
        keypair(33),
        Arc::new(TestAuthorityStatusResolver::live()),
        case.deployment.rail.clone(),
        case.deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    )?;
    let publisher = MiningPublisher::new();
    let finalize = || -> Result<FindingFinalization, AnyError> {
        Ok(coordinator.finalize(
            &case.liability_key,
            &case.enforcement,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&case.enforcement)?,
            &ScriptedObservations::qualified(),
            &publisher,
            SETTLEMENT_NOW,
        )?)
    };

    finalize()?;
    let recovered = finalize()?;
    assert!(matches!(
        recovered,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Confirmed { .. })
    ));
    assert_eq!(publisher.attempts(), 2);
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Confirmed);
    Ok(())
}
#[test]
fn finding_challenge_penalty_recovers_across_penalty_authority_rotation() -> TestResult {
    let case = finalizing_liability()?;
    let mut rotated = market_config();
    rotated.market_penalty = authority_pin(50, "market-penalty-rotated");
    let coordinator = FindingChallengeCoordinator::new_with_status_commit_clock(
        case.deployment.challenges.clone(),
        case.deployment.purchases.clone(),
        case.deployment.status.clone(),
        &rotated,
        keypair(31),
        keypair(32),
        keypair(50),
        Arc::new(TestAuthorityStatusResolver::live()),
        case.deployment.rail.clone(),
        case.deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    )?;
    let publisher = MiningPublisher::new();
    let finalize = || -> Result<FindingFinalization, AnyError> {
        Ok(coordinator.finalize(
            &case.liability_key,
            &case.enforcement,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&case.enforcement)?,
            &ScriptedObservations::qualified(),
            &publisher,
            SETTLEMENT_NOW,
        )?)
    };

    finalize()?;
    let recovered = finalize()?;
    assert!(matches!(
        recovered,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Confirmed { .. })
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Confirmed);
    Ok(())
}
#[test]
fn finding_challenge_finalization_requires_the_retained_enforcement_envelope() -> TestResult {
    let case = finalizing_liability()?;
    let mut body = case.enforcement.body.clone();
    let [buyer, community] = body.destinations.as_mut_slice() else {
        return Err("the retained enforcement carries two payout destinations".into());
    };
    buyer.amount.units += 1;
    community.amount.units -= 1;
    body.enforcement_id.clear();
    body.enforcement_id = compute_enforcement_id(&body)?;
    let substituted = SignedExportEnvelope::sign(body, &keypair(32))?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &substituted,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&substituted)?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("a newly signed payout envelope cannot replace retained authorization");
    let ChallengeCoordinatorError::Settlement(detail) = refused else {
        return Err(format!("unexpected substituted-enforcement rejection: {refused:?}").into());
    };
    assert!(
        detail.contains("retained finalizing authorization")
            || detail.contains("retained enforcement semantics")
            || detail.contains("snapshot refresh is outside the retained authorization"),
        "unexpected substituted-enforcement settlement rejection: {detail}"
    );
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    Ok(())
}
#[test]
fn finding_challenge_an_enforcement_naming_another_vault_never_reaches_the_publisher() -> TestResult
{
    let case = finalizing_liability()?;
    // An instruction, an observation, and a live contract read that all
    // agree with each other about a vault this liability was never opened
    // against. Every check downstream of the head is satisfied.
    let elsewhere = chain_hash(0x45);
    let (enforcement, snapshot) = enforcement_pair_at_vault(
        &case.liability_key,
        &case.enforcement.body.finding_id,
        &case.seller,
        &case.intent_key,
        &case.enforcement.body.penalty_envelope_sha256,
        &elsewhere,
    )?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &enforcement,
            &case.penalty,
            &snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot_for(&elsewhere),
            &enforcement_anchor_proof(&enforcement)?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("one liability may only impair the vault it was opened against");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityIdentity("vault_id")
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}
#[test]
fn finding_challenge_a_snapshot_from_an_expired_observer_key_authorizes_nothing() -> TestResult {
    let case = finalizing_liability()?;
    let mut config = market_config();
    config.settlement_observer.valid_until = case.snapshot.body.observed_at.saturating_add(1);
    let coordinator = case
        .deployment
        .coordinator_under(&config, FindingDisputeLockDisposition::Forfeited)?;

    let refused = coordinator
        .finalize(
            &case.liability_key,
            &case.enforcement,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&case.enforcement)?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("an expired observer key cannot authorize impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::SettlementObserverLifecycle(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);

    let config = market_config();
    let revoked = case.deployment.coordinator_under_with_status(
        &config,
        Arc::new(TestAuthorityStatusResolver {
            revoked_authority: Some(config.settlement_observer.authority_id.clone()),
            revoked_from_override: Some(case.snapshot.body.observed_at.saturating_add(1)),
            ..TestAuthorityStatusResolver::live()
        }),
        FindingDisputeLockDisposition::Forfeited,
    )?;
    let refused = revoked.finalize(
        &case.liability_key,
        &case.enforcement,
        &case.penalty,
        &case.snapshot,
        &case.seller,
        &settlement_config()?,
        &settlement_config()?.operator_address,
        &evm_vault_snapshot(),
        &anchor_proof()?,
        &ScriptedObservations::qualified(),
        &UnreachablePublisher,
        SETTLEMENT_NOW,
    );
    assert!(matches!(
        refused,
        Err(ChallengeCoordinatorError::SettlementObserverLifecycle(_))
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    Ok(())
}
#[test]
fn finding_challenge_revoked_status_operator_blocks_impairment_dispatch() -> TestResult {
    let case = finalizing_liability()?;
    let authority_id = market_config().status_feed_operator.authority.authority_id;
    let coordinator = case
        .deployment
        .coordinator_with_revoked_role(&authority_id, FindingDisputeLockDisposition::Forfeited)?;

    let refused = coordinator
        .finalize(
            &case.liability_key,
            &case.enforcement,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&case.enforcement)?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("a revoked status operator cannot precede impairment dispatch");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AuthorityLifecycle {
            role: "status feed operator",
            ..
        }
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    Ok(())
}
#[test]
fn finding_challenge_observer_and_vault_operator_epochs_rotate_independently() -> TestResult {
    let case = finalizing_liability_before_root_binding()?;
    let authorized = case.authorized()?;
    let mut body = case.snapshot.body.clone();
    body.operator_key_epoch = PINNED_KEY_EPOCH + 1;
    body.snapshot_id = String::new();
    body.snapshot_id = compute_snapshot_id(&body)?;
    let independently_rotated = SignedExportEnvelope::sign(body, &keypair(34))?;

    let refreshed = case.coordinator.refresh_finalizing_enforcement(
        &authorized,
        &independently_rotated,
        &case.seller,
        SETTLEMENT_NOW + 1,
    )?;
    assert_eq!(
        refreshed.enforcement.body.bond_snapshot_envelope_sha256,
        signed_envelope_sha256(&independently_rotated)?
    );
    Ok(())
}
#[test]
fn finding_challenge_rotated_snapshot_cannot_replace_a_bound_enforcement_root() -> TestResult {
    let case = finalizing_liability()?;
    let authorized = case.authorized()?;
    let mut body = case.snapshot.body.clone();
    body.operator_key_epoch = PINNED_KEY_EPOCH + 1;
    body.snapshot_id = String::new();
    body.snapshot_id = compute_snapshot_id(&body)?;
    let independently_rotated = SignedExportEnvelope::sign(body, &keypair(34))?;

    let refused = case
        .coordinator
        .refresh_finalizing_enforcement(
            &authorized,
            &independently_rotated,
            &case.seller,
            SETTLEMENT_NOW + 1,
        )
        .expect_err("a rotated snapshot cannot rewrite a bound enforcement root");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::Settlement(detail)
            if detail.contains("only before anchor binding or dispatch")
    ));
    Ok(())
}
#[test]
fn finding_challenge_digest_mismatch_reaches_an_enforced_sanction() -> TestResult {
    run_finding_challenge_digest_mismatch()
}
#[test]
fn finding_challenge_evidence_invalid_reaches_an_enforced_sanction() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let challenger_sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let other_sale = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 50, NOW + 1)?;

    // The finding's own production evidence carries a signature that
    // belongs to another body, which is affirmative invalidity.
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &challenger_sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 3)?,
        EvaluationAdmission::Admitted
    );

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
            NOW + 4,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(evaluated.outcome.body.reason, "evidence_signature_invalid");
    let FindingChallengeFacet::EvidenceInvalid(facet) = &evaluated.outcome.body.facet else {
        return Err("an evidence-invalid challenge carries an evidence-invalid facet".into());
    };
    assert_eq!(
        facet.invalidity,
        FindingEvidenceInvalidity::SignatureInvalid
    );

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
        NOW + 5,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    assert_eq!(
        deployment
            .challenges
            .get_liability(&upheld.liability_key)?
            .ok_or("liability head is durable")?
            .purchase_cutoff_slot,
        Some(2)
    );

    // Two retained sales keep 100 units of exposure encumbered each, so the
    // checked candidate is the 300-unit base stake plus 200 units of open
    // encumbrance, inside the 5000-unit signed requirement.
    let sealed = &upheld.sealed;
    assert_eq!(sealed.total_realized_spend_units, 100);
    assert_eq!(sealed.distribution.slash, usd(500));
    assert_eq!(sealed.distribution.buyer_pool_units, 100);
    assert_eq!(sealed.distribution.community_fund_units, 400);
    let allocation = allocation_by_destination(&sealed.distribution);
    assert_eq!(
        allocation,
        std::collections::BTreeMap::from([
            (buyer_destination(41), 50),
            (buyer_destination(42), 50),
            (COMMUNITY_FUND_DESTINATION.to_string(), 400),
        ]),
        "each harmed buyer takes exactly its pro rata share and the remainder goes to the fund"
    );
    let summed: u64 = allocation.values().sum();
    assert_eq!(summed, sealed.distribution.slash.units);
    // The challenger filed this dispute and was also harmed by it. It is
    // paid as a buyer and nothing more: no bounty destination and no
    // challenge-administration pool appears in the distribution.
    assert!(!allocation.contains_key(CHALLENGER_BOUNTY_DESTINATION));
    assert!(!allocation.contains_key(CHALLENGE_POOL_DESTINATION));

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    assert_eq!(authorized.enforcement.body.amount, usd(500));
    assert_eq!(authorized.slash.penalty.body.penalty_amount, usd(500));
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    for destination in &authorized.enforcement.body.destinations {
        assert_ne!(destination.destination, CHALLENGER_BOUNTY_DESTINATION);
        assert_ne!(destination.destination, CHALLENGE_POOL_DESTINATION);
    }
    Ok(())
}
#[test]
fn finding_challenge_replay_contradiction_reaches_an_enforced_sanction() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;

    // The seller claimed the predicate holds; the reproduction shows the
    // candidate phase failing too.
    let case = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 2)?,
        EvaluationAdmission::Admitted
    );

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("a completed contradicting reproduction is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(
        evaluated.outcome.body.reason,
        "replay_contradiction_confirmed"
    );
    let FindingChallengeFacet::ReplayContradiction(facet) = &evaluated.outcome.body.facet else {
        return Err("a replay challenge carries a replay facet".into());
    };
    assert_eq!(
        facet.predicate_result,
        FindingReplayPredicateResult::ConfirmedContradiction
    );
    assert_eq!(facet.recipe_sha256, challenged.recipe_sha256);

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
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
        NOW + 4,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    assert_eq!(upheld.sealed.total_realized_spend_units, 60);
    // One retained sale keeps 100 units encumbered against the allocation.
    assert_eq!(upheld.sealed.distribution.slash, usd(400));
    assert_eq!(upheld.sealed.distribution.buyer_pool_units, 60);
    assert_eq!(
        allocation_by_destination(&upheld.sealed.distribution),
        std::collections::BTreeMap::from([
            (buyer_destination(41), 60),
            (COMMUNITY_FUND_DESTINATION.to_string(), 340),
        ])
    );

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    assert_eq!(authorized.enforcement.body.amount, usd(400));
    assert_eq!(authorized.slash.penalty.body.penalty_amount, usd(400));
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    Ok(())
}
#[test]
fn finding_market_configuration_validates_listing_and_snapshot_pins() -> TestResult {
    let mut duplicate_listing = market_config();
    duplicate_listing
        .listing
        .key_hex
        .clone_from(&duplicate_listing.venue.key_hex);
    assert!(duplicate_listing.validate().is_err());

    let mut circular_status_authority = market_config();
    circular_status_authority
        .authority_status
        .key_hex
        .clone_from(&circular_status_authority.governance_root.key_hex);
    assert!(circular_status_authority.validate().is_err());

    let mut unbounded_snapshot = market_config();
    unbounded_snapshot.max_snapshot_age_secs = 0;
    assert!(unbounded_snapshot.validate().is_err());

    let mut non_i_json_evaluator = market_config();
    non_i_json_evaluator.challenge_evaluator.key_epoch = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(non_i_json_evaluator.validate().is_err());
    Ok(())
}
