/// Whether the enforcement root behind a finalizing liability has been
/// published, as the operator's anchoring step would leave it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnforcementRoot {
    Confirmed,
    Mismatched,
    Unpublished,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PriorVoluntaryRetraction {
    None,
    Pending,
    Published,
}

/// One liability head driven to `finalizing` with its seller-impairment
/// intent fenced, paired with the enforcement the settlement choke point
/// verifies. The head carries exactly the allocation and vault the
/// enforcement names, as the appeal path leaves it.
struct FinalizingLiability {
    deployment: Deployment,
    coordinator: FindingChallengeCoordinator,
    liability_key: String,
    seller: PublicKey,
    intent_key: String,
    retraction_key: String,
    status_intent_key: String,
    enforcement: SignedFindingChallengeEnforcement,
    penalty: SignedOpenMarketPenalty,
    slash: FindingPenaltyOutcome,
    snapshot: SignedFindingFinalizedBondSnapshot,
}

fn finalizing_liability() -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(EnforcementRoot::Confirmed, true)
}

fn finalizing_liability_rooted(root: EnforcementRoot) -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(root, true)
}

fn finalizing_liability_pending_retraction() -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(EnforcementRoot::Confirmed, true)
}

fn finalizing_liability_without_anchor() -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(EnforcementRoot::Confirmed, false)
}

fn finalizing_liability_with(
    root: EnforcementRoot,
    anchor_fenced: bool,
) -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with_prior_retraction(
        root,
        anchor_fenced,
        PriorVoluntaryRetraction::None,
    )
}

fn finalizing_liability_with_prior_retraction(
    root: EnforcementRoot,
    anchor_fenced: bool,
    prior_retraction: PriorVoluntaryRetraction,
) -> Result<FinalizingLiability, AnyError> {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &digest("upheld-outcome"),
        b"upheld-outcome",
        NOW + 1,
    )?;

    let liability_key = byte_hex64(0xb1);
    let seller = keypair(73).public_key();
    let seller_hex = seller.to_hex();
    deployment
        .challenges
        .open_liability(&chio_store_sqlite::FindingLiabilityInput {
            liability_key: &liability_key,
            defect_key: &derive_defect_key(&finding.finding_id),
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            allocation_id: &byte_hex64(0xa1),
            seller_hex: &seller_hex,
            venue_id: VENUE_ID,
            chain_id: &settlement_config()?.chain_id,
            vault_contract: BOND_VAULT_CONTRACT,
            vault_id: &chain_hash(0x44),
            opened_at: NOW,
        })?;
    deployment.challenges.uphold_liability(
        &liability_key,
        &challenge.body.challenge_id,
        1,
        NOW + 2 + CLAIM_WINDOW_SECS,
        NOW + 2,
    )?;
    deployment
        .purchases
        .register_community_fund_destination(&byte_hex64(0xa1), EVM_COMMUNITY_FUND, NOW + 2)?;
    deployment
        .purchases
        .admit_payout_destination(&byte_hex64(0xa1), EVM_BUYER_DESTINATION, NOW + 2)?;
    // The sanction the impairment settles under. Dispatch requires it to
    // still be the live case head, exactly as the coordinator records it
    // when it upholds a liability.
    deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: FIXTURE_SANCTION_CASE_ID,
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            liability_key: &liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Sanction,
            case_state: "enforced",
            appeal_of_case_id: None,
            supersedes_case_id: None,
            recorded_at: NOW + 2,
        },
    )?;
    deployment.challenges.begin_appeal_window(
        &liability_key,
        FindingLiabilityState::UpheldPendingClaims,
        &admitted_terms_digest()?,
        259_200,
        NOW + 3,
    )?;
    let intent_key = byte_hex64(0xc1);
    let penalty = fixture_slash_penalty()?;
    let penalty_envelope_sha256 = signed_envelope_sha256(&penalty)?;
    deployment
        .filings
        .retain_penalty_policy(&penalty_envelope_sha256, &market_config().market_penalty)?;
    deployment.challenges.record_effect_intent(
        &intent_key,
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair,
        &byte_hex64(0xd1),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    // The enforcement root the vault checks the impairment proof against,
    // fenced under the commitment this liability and penalty derive and
    // then driven to whatever the anchoring step left it in.
    deployment.challenges.record_effect_intent(
        &enforcement_root_intent_key(),
        chio_store_sqlite::FindingEffectIntentKind::RootIntent,
        &sha256_hex(root_intent_commitment(&liability_key, &penalty_envelope_sha256).as_bytes()),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    if root == EnforcementRoot::Mismatched {
        let merkle_root = chain_hash(0xee);
        let evidence_hash = anchor_evidence_hash()?;
        deployment.challenges.bind_effect_root(
            &enforcement_root_intent_key(),
            &liability_key,
            &merkle_root,
            &evidence_hash,
            NOW + 5,
        )?;
        deployment.challenges.advance_effect_intent(
            &enforcement_root_intent_key(),
            FindingEffectIntentState::Dispatched,
            NOW + 6,
        )?;
        deployment.challenges.confirm_effect_root(
            &enforcement_root_intent_key(),
            &merkle_root,
            &evidence_hash,
            NOW + 6,
        )?;
    }
    let retraction_key = byte_hex64(0xc3);
    let status_intent_key = if prior_retraction == PriorVoluntaryRetraction::None {
        retraction_key.clone()
    } else {
        let voluntary_intent_id = byte_hex64(0xc4);
        let voluntary_bytes = canonical_json_bytes(&serde_json::json!({
            "finding_id": finding.finding_id,
            "reason": "seller_voluntary_retraction",
            "schema": "chio.finding.voluntary-retraction.v1",
        }))?;
        deployment.status.issue_retraction_intent(
            &chio_store_sqlite::FindingRetractionIntentInput {
                intent_id: &voluntary_intent_id,
                feed_id: "status-feed/venue-challenge",
                operator_id: "status-operator",
                finding_id: &finding.finding_id,
                source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                intent_bytes: &voluntary_bytes,
                issued_at: NOW + 4,
                inclusion_deadline: NOW + 3_604,
                created_at: NOW + 4,
            },
        )?;
        if prior_retraction == PriorVoluntaryRetraction::Published {
            let config = market_config();
            let publisher = crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
                deployment.status.clone(),
                config.status_feed_operator,
                config.status_feed_service_bond,
                keypair(36),
                config.status_max_epoch_age_secs,
            )?;
            publisher.publish_retraction(&voluntary_intent_id, &[], NOW + 4)?;
        }
        voluntary_intent_id
    };
    deployment.challenges.record_effect_intent(
        &retraction_key,
        chio_store_sqlite::FindingEffectIntentKind::Retraction,
        &digest("status retraction"),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    let (enforcement, snapshot) = enforcement_pair(
        &liability_key,
        &finding.finding_id,
        &seller,
        &intent_key,
        &penalty_envelope_sha256,
    )?;
    let anchor = enforcement_anchor_proof(&enforcement)?;
    let settlement = settlement_config()?;
    let beneficiaries = enforcement
        .body
        .destinations
        .iter()
        .map(|destination| destination.destination.clone())
        .collect::<Vec<_>>();
    let shares = enforcement
        .body
        .destinations
        .iter()
        .map(|destination| destination.amount.clone())
        .collect::<Vec<_>>();
    let prepared = prepare_bond_impair(
        &settlement,
        &settlement.operator_address,
        &evm_vault_snapshot(),
        &enforcement.body.amount,
        &beneficiaries,
        &shares,
        &anchor,
    )?;
    let anchor_key = derive_anchor_evidence_intent_key(&prepared.evidence_hash);
    let anchor_commitment = anchor_evidence_intent_commitment(
        &liability_key,
        &intent_key,
        &penalty_envelope_sha256,
        &prepared.merkle_root,
    );
    if anchor_fenced {
        deployment.challenges.record_effect_intent(
            &anchor_key,
            chio_store_sqlite::FindingEffectIntentKind::RootIntent,
            &anchor_commitment,
            Some(&liability_key),
            false,
            NOW + 5,
        )?;
        deployment.challenges.bind_effect_root(
            &anchor_key,
            &liability_key,
            &prepared.merkle_root,
            &prepared.evidence_hash,
            NOW + 5,
        )?;
        if prior_retraction != PriorVoluntaryRetraction::None {
            deployment.challenges.advance_effect_intent(
                &anchor_key,
                FindingEffectIntentState::Dispatched,
                NOW + 6,
            )?;
            deployment.challenges.confirm_effect_root(
                &anchor_key,
                &prepared.merkle_root,
                &prepared.evidence_hash,
                NOW + 6,
            )?;
        }
    }
    if root == EnforcementRoot::Confirmed
        && prior_retraction != PriorVoluntaryRetraction::None
    {
        deployment.challenges.bind_effect_root(
            &enforcement_root_intent_key(),
            &liability_key,
            &prepared.merkle_root,
            &prepared.evidence_hash,
            NOW + 5,
        )?;
        deployment.challenges.advance_effect_intent(
            &enforcement_root_intent_key(),
            FindingEffectIntentState::Dispatched,
            NOW + 6,
        )?;
        deployment.challenges.confirm_effect_root(
            &enforcement_root_intent_key(),
            &prepared.merkle_root,
            &prepared.evidence_hash,
            NOW + 6,
        )?;
    }
    let penalty_body = &penalty.body;
    let slash = FindingPenaltyOutcome {
        penalty: penalty.clone(),
        penalty_envelope_sha256: penalty_envelope_sha256.clone(),
        evaluation: OpenMarketPenaltyEvaluation {
            listing_id: penalty_body.listing_id.clone(),
            namespace: penalty_body.namespace.clone(),
            fee_schedule_id: penalty_body.fee_schedule_id.clone(),
            charter_id: penalty_body.charter_id.clone(),
            case_id: penalty_body.case_id.clone(),
            penalty_id: penalty_body.penalty_id.clone(),
            governing_operator_id: penalty_body.governing_operator_id.clone(),
            action: penalty_body.action,
            state: penalty_body.state,
            effective_state: OpenMarketPenaltyEffectiveState::BondSlashed,
            evaluated_at: penalty_body.updated_at,
            publication_fee: None,
            dispute_fee: None,
            market_participation_fee: None,
            bond_requirement: None,
            blocks_admission: true,
            findings: Vec::new(),
        },
    };
    let retained = serde_json::json!({
        "enforcement": enforcement.clone(),
        "slash": slash.clone(),
        "finalizationPolicy": market_config().venue_finalization,
        "sanctionCaseId": FIXTURE_SANCTION_CASE_ID,
        "heldPenaltyId": FIXTURE_HELD_PENALTY_ID,
    });
    let authorization_json = canonical_json_bytes(&retained)?;
    let authorization_sha256 = sha256_hex(&authorization_json);
    let enforcement_bytes = canonical_json_bytes(&enforcement)?;
    deployment.status.begin_finalizing_with_retraction(
        &liability_key,
        FIXTURE_SANCTION_CASE_ID,
        &chio_store_sqlite::FindingFinalizingAuthorizationInput {
            liability_key: &liability_key,
            authorization_json: &authorization_json,
            authorization_sha256: &authorization_sha256,
            recorded_at: NOW + 5,
        },
        &chio_store_sqlite::FindingRetractionIntentInput {
            intent_id: &retraction_key,
            feed_id: "status-feed/venue-challenge",
            operator_id: "status-operator",
            finding_id: &finding.finding_id,
            source: chio_store_sqlite::FindingRetractionIntentSource::Enforcement,
            intent_bytes: &enforcement_bytes,
            issued_at: NOW + 5,
            inclusion_deadline: NOW + 3_605,
            created_at: NOW + 5,
        },
        NOW + 5,
    )?;
    let case = FinalizingLiability {
        deployment,
        coordinator,
        liability_key,
        seller,
        intent_key,
        retraction_key,
        status_intent_key,
        enforcement,
        penalty,
        slash,
        snapshot,
    };
    if root == EnforcementRoot::Confirmed
        && prior_retraction == PriorVoluntaryRetraction::None
    {
        let refused = case
            .finalize_observing(
                &ScriptedObservations::qualified(),
                &UnreachablePublisher,
                SETTLEMENT_NOW,
            )?
            .expect_err("the first attempt prepares the root before publication");
        if !matches!(
            refused,
            ChallengeCoordinatorError::EnforcementRootUnconfirmed(_)
        ) {
            return Err(format!("unexpected root preparation result: {refused:?}").into());
        }
        let binding = case
            .deployment
            .challenges
            .get_effect_root_binding(&enforcement_root_intent_key())?
            .ok_or("root preparation binds the concrete proof")?;
        case.deployment.challenges.advance_effect_intent(
            &enforcement_root_intent_key(),
            FindingEffectIntentState::Dispatched,
            NOW + 6,
        )?;
        case.deployment.challenges.confirm_effect_root(
            &enforcement_root_intent_key(),
            &binding.merkle_root,
            &binding.evidence_hash,
            NOW + 6,
        )?;
    }
    Ok(case)
}

impl FinalizingLiability {
    fn authorized(&self) -> Result<AuthorizedImpairment, AnyError> {
        Ok(AuthorizedImpairment {
            enforcement: self.enforcement.clone(),
            enforcement_envelope_sha256: signed_envelope_sha256(&self.enforcement)?,
            slash: self.slash.clone(),
            effect_intent_keys: vec![
                (
                    FindingEffectIntentKind::SellerImpair,
                    self.intent_key.clone(),
                ),
                (
                    FindingEffectIntentKind::RootIntent,
                    enforcement_root_intent_key(),
                ),
                (
                    FindingEffectIntentKind::Retraction,
                    self.retraction_key.clone(),
                ),
            ],
        })
    }

    /// Run the settlement choke point against this head with the given
    /// publisher.
    fn finalize(
        &self,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<FindingFinalization, AnyError> {
        Ok(self.finalize_observing(&ScriptedObservations::qualified(), publisher, now)??)
    }

    /// The same run against a caller-scripted view of the chain, so a test
    /// can move the state the signed snapshot rests on under it.
    fn finalize_observing(
        &self,
        observations: &dyn chio_settle::FindingBondObservationSource,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<Result<FindingFinalization, ChallengeCoordinatorError>, AnyError> {
        Ok(self.coordinator.finalize(
            &self.liability_key,
            &self.enforcement,
            &self.penalty,
            &self.snapshot,
            &self.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &enforcement_anchor_proof(&self.enforcement)?,
            observations,
            publisher,
            now,
        ))
    }

    fn intent_state(&self) -> Result<FindingEffectIntentState, AnyError> {
        Ok(self.intent()?.state)
    }

    fn intent(&self) -> Result<chio_store_sqlite::FindingEffectIntentRecord, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_effect_intent(&self.intent_key)?
            .ok_or("the impairment intent is durable")?)
    }

    fn head(&self) -> Result<chio_store_sqlite::FindingLiabilityRecord, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_liability(&self.liability_key)?
            .ok_or("liability head is durable")?)
    }

    fn mark_status_eligible(&self, tx_hash: &str, now: u64) -> Result<(), AnyError> {
        let evidence = canonical_json_bytes(&serde_json::json!({
            "schema": "chio.finding.impairment-finality.v1",
            "enforcement_id": self.enforcement.body.enforcement_id,
            "finding_id": self.enforcement.body.finding_id,
            "liability_key": self.enforcement.body.liability_key,
            "tx_hash": tx_hash,
        }))?;
        self.deployment.status.mark_retraction_dispatch_eligible(
            &byte_hex64(0xc3),
            &evidence,
            now,
            market_config().status_feed_service_bond.inclusion_sla_secs,
        )?;
        Ok(())
    }

    fn publish_status(&self, now: u64) -> Result<(), AnyError> {
        let config = market_config();
        let publisher =
            crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
                self.deployment.status.clone(),
                config.status_feed_operator,
                config.status_feed_service_bond,
                keypair(36),
                config.status_max_epoch_age_secs,
            )?;
        publisher.publish_retraction(&self.status_intent_key, &[], now)?;
        Ok(())
    }
}

/// Domain-keyed identity of the enforcement-root effect the pair binds.
fn enforcement_root_intent_key() -> String {
    byte_hex64(0xc2)
}

/// The penalty-authority-signed slash the manual finalization fixture
/// binds. Its case id is the durable sanction head, so final dispatch can
/// compare the exact authority rather than merely seeing a sanction kind.
fn fixture_slash_penalty() -> Result<SignedOpenMarketPenalty, AnyError> {
    let artifact = OpenMarketPenaltyArtifact {
        schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_string(),
        penalty_id: "market-penalty-finalizing-fixture".to_string(),
        fee_schedule_id: "fee-schedule-finalizing-fixture".to_string(),
        charter_id: "charter-finalizing-fixture".to_string(),
        case_id: FIXTURE_SANCTION_CASE_ID.to_string(),
        governing_operator_id: OPERATOR_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        listing_id: LISTING_ID.to_string(),
        activation_id: None,
        subject_operator_id: Some(OPERATOR_ID.to_string()),
        abuse_class: OpenMarketAbuseClass::FraudulentListing,
        bond_class: OpenMarketBondClass::Listing,
        action: OpenMarketPenaltyAction::SlashBond,
        state: OpenMarketPenaltyState::Enforced,
        penalty_amount: usd(250),
        opened_at: NOW + 4,
        updated_at: NOW + 4,
        expires_at: Some(KEY_VALID_UNTIL),
        evidence_refs: vec![OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::External,
            reference_id: byte_hex64(0xb3),
            uri: None,
            sha256: Some(byte_hex64(0xb4)),
        }],
        supersedes_penalty_id: Some(FIXTURE_HELD_PENALTY_ID.to_string()),
        issued_by: "market@chio.example".to_string(),
        note: None,
    };
    artifact.validate()?;
    Ok(SignedOpenMarketPenalty::sign(artifact, &keypair(33))?)
}

/// The exact settlement pair the choke point verifies, plus the finding
/// and listing identities the liability head must carry.
fn enforcement_pair(
    liability_key: &str,
    finding_id: &str,
    seller: &PublicKey,
    seller_impair_intent_id: &str,
    penalty_envelope_sha256: &str,
) -> Result<
    (
        SignedFindingChallengeEnforcement,
        SignedFindingFinalizedBondSnapshot,
    ),
    AnyError,
> {
    enforcement_pair_at_vault(
        liability_key,
        finding_id,
        seller,
        seller_impair_intent_id,
        penalty_envelope_sha256,
        &chain_hash(0x44),
    )
}

/// The same pair against a caller-named vault, so a test can present an
/// instruction and observation that agree with each other and with the
/// live contract read while naming a vault the liability never did.
fn enforcement_pair_at_vault(
    liability_key: &str,
    finding_id: &str,
    seller: &PublicKey,
    seller_impair_intent_id: &str,
    penalty_envelope_sha256: &str,
    vault_id: &str,
) -> Result<
    (
        SignedFindingChallengeEnforcement,
        SignedFindingFinalizedBondSnapshot,
    ),
    AnyError,
> {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: settlement_config()?.chain_id,
        vault_contract: BOND_VAULT_CONTRACT.to_string(),
        vault_id: vault_id.to_string(),
        seller: seller.clone(),
        allocation_id: byte_hex64(0xa1),
        locked_amount: 500_000,
        held_amount: 120_000,
        slashed_amount: 0,
        currency: "USD".to_string(),
        block_number: 21_000_000,
        block_hash: chain_hash(0xbb),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        observed_at: OBSERVED_AT,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    let signed_snapshot = SignedExportEnvelope::sign(snapshot, &keypair(34))?;
    let snapshot_digest = signed_envelope_sha256(&signed_snapshot)?;
    let mut enforcement = FindingChallengeEnforcement {
        schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_string(),
        enforcement_id: String::new(),
        liability_key: liability_key.to_string(),
        finding_id: finding_id.to_string(),
        listing_id: LISTING_ID.to_string(),
        outcome_id: byte_hex64(0xb3),
        outcome_envelope_sha256: byte_hex64(0xb4),
        penalty_envelope_sha256: penalty_envelope_sha256.to_string(),
        bond_snapshot_envelope_sha256: snapshot_digest,
        purchase_snapshot_digest: byte_hex64(0xb6),
        deterministic_allocation_digest: byte_hex64(0xb7),
        seller_allocation_id: byte_hex64(0xa1),
        vault: FindingVaultReference {
            chain_id: settlement_config()?.chain_id,
            vault_contract: BOND_VAULT_CONTRACT.to_string(),
            vault_id: vault_id.to_string(),
        },
        amount: usd(250),
        destinations: vec![
            FindingEnforcementDestination {
                destination: EVM_BUYER_DESTINATION.to_string(),
                amount: usd(150),
            },
            FindingEnforcementDestination {
                destination: EVM_COMMUNITY_FUND.to_string(),
                amount: usd(100),
            },
        ],
        effect_intents: vec![
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::SellerImpair,
                intent_id: seller_impair_intent_id.to_string(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::RootIntent,
                intent_id: enforcement_root_intent_key(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::Retraction,
                intent_id: byte_hex64(0xc3),
            },
        ],
        penalty_authority_id: "market-penalty".to_owned(),
        penalty_key: keypair(33).public_key(),
        penalty_key_epoch: PINNED_KEY_EPOCH,
        penalty_valid_from: 1,
        penalty_valid_until: I_JSON_MAX_SAFE_INTEGER,
        penalty_revocation_status_ref: REVOCATION_STATUS_REF.to_owned(),
        finalization_authority_id: "venue-finalization".to_owned(),
        finalization_key: keypair(32).public_key(),
        finalization_key_epoch: PINNED_KEY_EPOCH,
        finalization_valid_from: 1,
        finalization_valid_until: I_JSON_MAX_SAFE_INTEGER,
        finalization_revocation_status_ref: REVOCATION_STATUS_REF.to_owned(),
        finalized_at: OBSERVED_AT + 100,
    };
    enforcement.enforcement_id = compute_enforcement_id(&enforcement)?;
    Ok((
        SignedExportEnvelope::sign(enforcement, &keypair(32))?,
        signed_snapshot,
    ))
}
