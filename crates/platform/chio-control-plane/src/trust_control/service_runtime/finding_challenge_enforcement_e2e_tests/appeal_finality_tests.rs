use super::*;

#[test]
fn finding_challenge_an_appeal_case_id_cannot_be_substituted() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let refused = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            Some(&case.upheld.sealed),
            &case.governance.context(),
            &AppealDisposition::Successful {
                appeal_case: &case.governance.appeal_case,
                appeal_case_id: "case-appeal-substituted-01",
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            NOW + 20,
        )
        .expect_err("an unsigned appeal case id can supersede nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head remains durable")?;
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert_eq!(
        case.deployment
            .challenges
            .resolve_case_head(&case.upheld.liability_key)?
            .ok_or("sanction remains live")?
            .case_id,
        case.upheld.sanction_case_id
    );
    Ok(())
}
#[test]
fn finding_challenge_an_unauthenticated_appeal_supersedes_nothing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // An appeal filed under a key the governance root never delegated to,
    // naming the real sanction. It is exactly the filing an attacker can
    // produce, and the index must be left able to accept the real one.
    let forged = sample_case(
        &keypair(99),
        &case.governance.listing,
        &case.governance.activation,
        &case.governance.charter,
        GenericGovernanceCaseKind::Appeal,
        Some(case.upheld.sanction_case_id.clone()),
        Some(case.upheld.sanction_case_id.clone()),
    )?;

    let refused = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            Some(&case.upheld.sealed),
            &case.governance.context(),
            &AppealDisposition::Successful {
                appeal_case: &forged,
                appeal_case_id: &forged.body.case_id,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            NOW + 20,
        )
        .expect_err("an appeal no pinned authority signed reverses nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::UnknownGovernanceCasePolicy
    ));

    let cases = case
        .deployment
        .challenges
        .list_governance_cases(&case.upheld.liability_key)?;
    assert_eq!(
        cases.len(),
        1,
        "a refused appeal leaves no case head behind it"
    );
    let sanction = cases.first().ok_or("the sanction is indexed")?;
    assert_eq!(sanction.case_id, case.upheld.sanction_case_id);
    assert_eq!(
        sanction.superseded_by_case_id, None,
        "the sanction still governs the liability"
    );

    // The legitimate appeal that follows must still be able to supersede.
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &case.governance.appeal_case,
            appeal_case_id: &case.governance.appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 40,
    )?;
    assert!(matches!(
        resolution,
        AppealResolution::ReversedBeforeImpairment { .. }
    ));
    let head = case
        .deployment
        .challenges
        .resolve_case_head(&case.upheld.liability_key)?
        .ok_or("the appeal is the live case head")?;
    assert_eq!(head.case_id, case.governance.appeal_case.body.case_id);
    Ok(())
}
#[test]
fn finding_challenge_appeal_finality_impairs_and_fences_every_effect_intent() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
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
    )?;
    let AppealResolution::Finalizing(authorized) = resolution else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("the finalizing liability remains durable")?;
    let stable_penalty_issued_at = liability
        .appeal_deadline
        .and_then(|deadline| deadline.checked_add(1))
        .ok_or("the appeal deadline has a representable successor")?;
    assert_eq!(
        authorized.slash.penalty.body.opened_at, stable_penalty_issued_at,
        "the final penalty is issued from the durable appeal boundary"
    );
    assert_eq!(
        authorized.slash.penalty.body.updated_at, stable_penalty_issued_at,
        "a retry clock cannot change the signed penalty bytes"
    );
    assert_eq!(
        authorized.enforcement.body.amount,
        case.upheld.sealed.distribution.slash
    );
    assert_eq!(
        authorized.enforcement.body.purchase_snapshot_digest,
        case.upheld.sealed.snapshot_digest
    );

    // Every domain-keyed intent is durable and pending before anything is
    // dispatched, and the retraction stays dispatch-ineligible until a
    // confirmed impairment releases it.
    let intents = case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?;
    assert_eq!(
        intents.len(),
        5,
        "seller impairment, root anchor, retraction, collected fee, and bond disposition"
    );
    for intent in &intents {
        assert!(intent.settlement_required);
        let expected = if matches!(
            intent.kind,
            chio_store_sqlite::FindingEffectIntentKind::ChallengeBond
                | chio_store_sqlite::FindingEffectIntentKind::Fee
        ) {
            FindingEffectIntentState::Confirmed
        } else {
            FindingEffectIntentState::Pending
        };
        assert_eq!(intent.state, expected);
    }
    let has = |kind: chio_store_sqlite::FindingEffectIntentKind| {
        intents.iter().any(|intent| intent.kind == kind)
    };
    assert!(has(
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair
    ));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::RootIntent));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::Retraction));
    assert!(has(
        chio_store_sqlite::FindingEffectIntentKind::ChallengeBond
    ));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::Fee));
    assert_eq!(authorized.effect_intent_keys.len(), 5);

    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.state, FindingLiabilityState::Finalizing);
    assert!(liability.publication_pending);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}
#[test]
fn finding_challenge_final_penalty_uses_the_rotated_authority_window() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let deadline = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .and_then(|liability| liability.appeal_deadline)
        .ok_or("the upheld liability carries an appeal deadline")?;
    let mut rotated_config = market_config();
    rotated_config.market_penalty = authority_pin(50, "market-penalty-rotated");
    rotated_config.market_penalty.valid_from = deadline + 5;
    let resolved_at = deadline + 10;
    let coordinator = FindingChallengeCoordinator::new_with_status_commit_clock(
        case.deployment.challenges.clone(),
        case.deployment.purchases.clone(),
        case.deployment.status.clone(),
        &rotated_config,
        keypair(31),
        keypair(32),
        keypair(50),
        Arc::new(TestAuthorityStatusResolver::live()),
        case.deployment.rail.clone(),
        case.deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    )?;

    let resolution = coordinator.resolve_appeal(
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
        resolved_at,
    )?;
    let AppealResolution::Finalizing(authorized) = resolution else {
        return Err("appeal finality under the rotated penalty key must authorize".into());
    };
    assert_eq!(
        authorized.slash.penalty.body.opened_at,
        rotated_config.market_penalty.valid_from
    );
    assert_eq!(
        authorized.slash.penalty.body.updated_at,
        rotated_config.market_penalty.valid_from
    );
    Ok(())
}
#[test]
fn finding_challenge_final_penalty_requires_current_authority_standing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let deadline = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .and_then(|liability| liability.appeal_deadline)
        .ok_or("the upheld liability carries an appeal deadline")?;
    let config = market_config();
    let coordinator = case.deployment.coordinator_under_with_status(
        &config,
        Arc::new(TestAuthorityStatusResolver {
            revoked_authority: Some(config.market_penalty.authority_id.clone()),
            revoked_from_override: Some(deadline.saturating_add(5)),
            ..TestAuthorityStatusResolver::live()
        }),
        FindingDisputeLockDisposition::Forfeited,
    )?;
    let refused = coordinator.resolve_appeal(
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
        deadline.saturating_add(10),
    );
    assert!(matches!(
        refused,
        Err(ChallengeCoordinatorError::AuthorityLifecycle {
            role: "penalty",
            ..
        })
    ));
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("the refused finality keeps its liability")?;
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    Ok(())
}
#[test]
fn finding_challenge_appeal_finality_uses_the_sanctions_retained_governance_policy() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let mut rotated_config = market_config();
    rotated_config.governance_root = authority_pin(52, "governance-rotated");
    rotated_config.governance_root.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.governance_root.valid_from = NOW + 1;
    let rotated = case
        .deployment
        .coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?;

    let resolution = rotated.resolve_appeal(
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
    )?;
    assert!(matches!(resolution, AppealResolution::Finalizing(_)));
    Ok(())
}
#[test]
fn finding_challenge_snapshot_refresh_stops_once_exact_enforcement_is_anchored() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let authorized = impair_after_appeal(
        &case.coordinator,
        &case.governance,
        &case.upheld,
        &case.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    let seller = keypair(22).public_key();
    let observed_at = APPEAL_FINAL_AT + 10;
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: authorized.enforcement.body.vault.chain_id.clone(),
        vault_contract: authorized.enforcement.body.vault.vault_contract.clone(),
        vault_id: authorized.enforcement.body.vault.vault_id.clone(),
        seller: seller.clone(),
        allocation_id: authorized.enforcement.body.seller_allocation_id.clone(),
        locked_amount: 5_000,
        held_amount: authorized.enforcement.body.amount.units,
        slashed_amount: 0,
        currency: authorized.enforcement.body.amount.currency.clone(),
        block_number: 21_000_200,
        block_hash: chain_hash(0xbd),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        observed_at,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    let snapshot = SignedExportEnvelope::sign(snapshot, &keypair(34))?;
    let refreshed = case.coordinator.refresh_finalizing_enforcement(
        &authorized,
        &snapshot,
        &seller,
        observed_at + 1,
    )?;
    assert_eq!(
        refreshed.enforcement.body.bond_snapshot_envelope_sha256,
        signed_envelope_sha256(&snapshot)?
    );
    assert_ne!(
        refreshed.enforcement_envelope_sha256,
        authorized.enforcement_envelope_sha256
    );

    let proof = enforcement_anchor_proof(&refreshed.enforcement)?;
    let evidence_hash = anchor_evidence_hash(&refreshed.enforcement)?;
    let merkle_root = proof.receipt_inclusion.merkle_root.to_hex_prefixed();
    let root_intent = refreshed
        .enforcement
        .body
        .effect_intents
        .iter()
        .find(|binding| binding.kind == chio_finding::FindingEffectIntentKind::RootIntent)
        .map(|binding| binding.intent_id.as_str())
        .ok_or("refreshed enforcement carries its root intent")?;
    case.deployment.challenges.bind_effect_root(
        root_intent,
        &refreshed.enforcement.body.liability_key,
        &merkle_root,
        &evidence_hash,
        observed_at + 2,
    )?;

    let refused = case
        .coordinator
        .refresh_finalizing_enforcement(&refreshed, &snapshot, &seller, observed_at + 3)
        .expect_err("an anchored enforcement cannot be re-signed around another snapshot");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::Settlement(detail)
            if detail.contains("only before anchor binding or dispatch")
    ));
    Ok(())
}
#[test]
fn finding_challenge_failed_impairment_renews_snapshot_and_retains_root_lineage() -> TestResult {
    let case = finalizing_liability()?;
    let publisher = MiningPublisher::new();
    case.finalize(&publisher, SETTLEMENT_NOW)?;
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Failed);
    let original_binding = case
        .deployment
        .challenges
        .get_effect_root_binding(&enforcement_root_intent_key())?
        .ok_or("the first published root is retained")?;

    let refresh_at = SETTLEMENT_NOW + 120;
    let mut snapshot_body = case.snapshot.body.clone();
    snapshot_body.observed_at = refresh_at - 1;
    snapshot_body.snapshot_id.clear();
    snapshot_body.snapshot_id = compute_snapshot_id(&snapshot_body)?;
    let snapshot = SignedExportEnvelope::sign(snapshot_body, &keypair(34))?;
    let refreshed = case.coordinator.refresh_finalizing_enforcement(
        &case.authorized()?,
        &snapshot,
        &case.seller,
        refresh_at,
    )?;
    let completed = case.coordinator.finalize(
        &case.liability_key,
        &refreshed.enforcement,
        &case.penalty,
        &snapshot,
        &case.seller,
        &settlement_config()?,
        &settlement_config()?.operator_address,
        &evm_vault_snapshot(),
        &enforcement_anchor_proof(&refreshed.enforcement)?,
        &ScriptedObservations::qualified(),
        &publisher,
        refresh_at + 1,
    )?;
    assert!(matches!(
        completed,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Confirmed { .. })
    ));
    let current_binding = case
        .deployment
        .challenges
        .get_effect_root_binding(&enforcement_root_intent_key())?
        .ok_or("the renewed published root is retained")?;
    assert_ne!(current_binding, original_binding);
    let connection = rusqlite::Connection::open(&case.deployment.database)?;
    let refreshes = connection.query_row(
        "SELECT COUNT(*) FROM effect_root_bindings_refreshes WHERE intent_key = ?1",
        [&enforcement_root_intent_key()],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(refreshes, 1, "the original root remains in the base row");
    Ok(())
}
#[test]
fn finding_challenge_appeal_finality_refuses_a_window_that_has_not_closed() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let deadline = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability is durable")?
        .appeal_deadline
        .ok_or("appeal deadline is frozen")?;
    let close_at = |now: u64| {
        case.coordinator.resolve_appeal(
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
            now,
        )
    };

    // The seller-signed deadline governs through its exact final instant.
    let early =
        close_at(deadline).expect_err("finality is only reached once the deadline has passed");
    assert!(matches!(
        early,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));

    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an open appeal window fences no impairment effect"
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert!(!liability.publication_pending);

    // The same call once the window has genuinely closed authorizes it.
    assert!(matches!(
        close_at(deadline + 1)?,
        AppealResolution::Finalizing(_)
    ));
    Ok(())
}
#[test]
fn finding_challenge_a_live_appeal_case_blocks_appeal_finality() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // An appeal filed against the sanction and still open. It supersedes
    // nothing yet, so the liability now carries two live cases and no
    // single case can be said to govern it.
    case.deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: "case-appeal-open-01",
            finding_id: &case.finding_id,
            listing_id: LISTING_ID,
            liability_key: &case.upheld.liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Appeal,
            case_state: "open",
            appeal_of_case_id: Some(&case.upheld.sanction_case_id),
            supersedes_case_id: None,
            recorded_at: NOW + 10,
        },
    )?;

    let refused = resolve_final(&case, &identity, &case.outcome, APPEAL_FINAL_AT)
        .expect_err("a live appeal is not a denial and authorizes no impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an unresolved case head fences no impairment effect"
    );
    assert_eq!(
        case.deployment
            .challenges
            .get_liability(&case.upheld.liability_key)?
            .ok_or("liability head is durable")?
            .state,
        FindingLiabilityState::PendingAppeal
    );
    Ok(())
}
#[test]
fn finding_challenge_unresolved_appeal_quarantines_rather_than_impairing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Unresolved {
            reason: "appeal is open",
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 20,
    )?;
    assert!(matches!(resolution, AppealResolution::Quarantined { .. }));
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(
        liability.state,
        FindingLiabilityState::PendingAppeal,
        "an open appeal is not a denial and impairs nothing"
    );
    assert!(liability.quarantined);
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an unresolved appeal fences no impairment effect"
    );
    Ok(())
}
#[test]
fn finding_challenge_sealed_accounting_cannot_be_substituted_at_appeal_finality() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let mut tampered = case.upheld.sealed.clone();
    tampered.distribution.entries[0].amount_units = tampered.distribution.entries[0]
        .amount_units
        .saturating_add(1);
    let error = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            Some(&tampered),
            &case.governance.context(),
            &AppealDisposition::Final {
                sanction_case: &case.governance.sanction_case,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            APPEAL_FINAL_AT,
        )
        .expect_err("a substituted distribution must not authorize an impairment");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::SealedClaimMismatch
    ));
    Ok(())
}
#[test]
fn finding_challenge_appeal_finality_refuses_an_identity_the_head_does_not_carry() -> TestResult {
    let case = upheld_liability()?;
    let mut elsewhere = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    elsewhere.vault_id = "vault-99";

    let refused = resolve_final(&case, &elsewhere, &case.outcome, APPEAL_FINAL_AT)
        .expect_err("a liability may only be impaired at the vault it was opened against");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityIdentity("vault_id")
    ));
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "a substituted target fences no effect"
    );
    assert_eq!(
        case.deployment
            .challenges
            .get_liability(&case.upheld.liability_key)?
            .ok_or("liability head is durable")?
            .state,
        FindingLiabilityState::PendingAppeal
    );
    Ok(())
}
#[test]
fn finding_challenge_a_rejected_outcome_never_authorizes_an_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let mut body = case.outcome.body.clone();
    body.verdict = chio_finding::FindingChallengeVerdict::Rejected;
    body.facet =
        FindingChallengeFacet::EvidenceInvalid(chio_finding::FindingEvidenceInvalidFacet {
            challenged_receipt_ids: vec!["receipt-evidence-01".to_string()],
            invalidity: FindingEvidenceInvalidity::NoAffirmativeInvalidity,
        });
    body.reason = "evidence_resolved_valid".to_string();
    body.penalty_calculation = None;
    body.outcome_id = chio_finding::derive_outcome_id(&body)?;
    body.validate()?;
    let rejected = SignedExportEnvelope::sign(body, &keypair(31))?;

    let refused = resolve_final(&case, &identity, &rejected, APPEAL_FINAL_AT)
        .expect_err("only an upheld adjudication reaches the penalty lane");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    assert!(case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?
        .is_empty());
    Ok(())
}
#[test]
fn finding_challenge_an_outcome_the_store_never_recorded_authorizes_no_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // Same verdict, same bindings, adjudicated one second later: a second
    // upheld envelope for this defect that the verdict record never named.
    let mut body = case.outcome.body.clone();
    body.evaluated_at = body.evaluated_at.saturating_add(1);
    body.outcome_id = chio_finding::derive_outcome_id(&body)?;
    body.validate()?;
    let substituted = SignedExportEnvelope::sign(body, &keypair(31))?;

    let refused = resolve_final(&case, &identity, &substituted, APPEAL_FINAL_AT)
        .expect_err("only the recorded adjudication may authorize the impairment");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    Ok(())
}
#[test]
fn finding_challenge_a_second_appeal_finality_mints_no_new_root_intent() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let AppealResolution::Finalizing(first) =
        resolve_final(&case, &identity, &case.outcome, APPEAL_FINAL_AT)?
    else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };

    // A later retry returns the exact authorization committed with the
    // finalizing transition. It neither mints fresh bytes nor requires the
    // caller to have retained the first return value across a crash.
    let AppealResolution::Finalizing(second) = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        None,
        &case.governance.context(),
        &AppealDisposition::Final {
            sanction_case: &case.governance.sanction_case,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        APPEAL_FINAL_AT + 20,
    )?
    else {
        return Err("finalizing recovery returns the retained authorization".into());
    };
    assert_eq!(
        canonical_json_bytes(&first.enforcement)?,
        canonical_json_bytes(&second.enforcement)?
    );
    assert_eq!(
        canonical_json_bytes(&first.slash.penalty)?,
        canonical_json_bytes(&second.slash.penalty)?
    );
    assert_eq!(first.effect_intent_keys, second.effect_intent_keys);
    let intents = case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?;
    assert_eq!(
        intents.len(),
        5,
        "the replay records no sixth intent beside the five already fenced"
    );
    assert_eq!(first.effect_intent_keys.len(), 5);
    assert!(case
        .deployment
        .challenges
        .get_finalizing_authorization(&case.upheld.liability_key)?
        .is_some());
    Ok(())
}
#[test]
fn finding_challenge_quarantined_reconciliation_leaves_purchases_blocked() -> TestResult {
    let case = finalizing_liability()?;
    let outcome = case.finalize(&AmbiguousPublisher, SETTLEMENT_NOW)?;
    assert_eq!(
        outcome,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::StoredTransactionMissing
        }),
        "a consumed evidence hash with no transaction behind it is never a slash"
    );

    let liability = case.head()?;
    assert_eq!(liability.state, FindingLiabilityState::Finalizing);
    assert!(liability.publication_pending);
    assert!(liability.quarantined);
    assert!(
        case.deployment.purchases.sales_blocked(LISTING_ID)?,
        "a quarantined impairment keeps purchases denied"
    );
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Quarantined,
        "an evidence hash burned by an unknown transaction needs an operator"
    );
    Ok(())
}
#[test]
fn finding_status_retraction_enforced_challenge_stays_pending_until_the_broadcast_lands(
) -> TestResult {
    run_enforced_challenge_status_retraction()
}
