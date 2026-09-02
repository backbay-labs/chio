// Enforcement finalization, penalty minting, and digest commitments.

impl FindingChallengeCoordinator {
    /// Recover the exact authorization retained atomically with a prior
    /// `pending_appeal -> finalizing` transition.
    fn recover_finalizing_authorization(
        &self,
        record: &FindingLiabilityRecord,
        outcome: &SignedFindingChallengeOutcome,
        sanction_case_id: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        self.require_sanction_governs(&record.liability_key, sanction_case_id)?;
        let (retained, retained_at) =
            self.load_retained_finalizing_authorization(&record.liability_key)?;
        let enforcement = &retained.enforcement;
        enforcement
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        self.require_enforcement_signature(enforcement, &retained.finalization_policy, now)?;
        let snapshot = self
            .challenges
            .get_claim_snapshot(&record.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
        let sealed = SealedClaimSnapshot {
            liability_key: snapshot.liability_key,
            cutoff_slot: snapshot.cutoff_slot,
            snapshot_digest: snapshot.snapshot_digest,
            allocation_digest: snapshot.allocation_digest,
            total_realized_spend_units: snapshot.total_realized_spend_units,
            distribution: SlashDistribution {
                slash: enforcement.body.amount.clone(),
                buyer_pool_units: snapshot.buyer_pool_units,
                community_fund_units: snapshot.community_fund_units,
                entries: enforcement
                    .body
                    .destinations
                    .iter()
                    .map(|destination| DistributionEntry {
                        destination: destination.destination.clone(),
                        amount_units: destination.amount.units,
                    })
                    .collect(),
            },
        };
        self.require_sealed_matches_store(&record.liability_key, &sealed)?;
        let outcome_digest = self.envelope_digest(outcome)?;
        if retained_at != enforcement.body.finalized_at
            || enforcement.body.liability_key != record.liability_key
            || enforcement.body.finding_id != record.finding_id
            || enforcement.body.listing_id != record.listing_id
            || enforcement.body.outcome_id != outcome.body.outcome_id
            || enforcement.body.outcome_envelope_sha256 != outcome_digest
            || enforcement.body.purchase_snapshot_digest != sealed.snapshot_digest
            || enforcement.body.deterministic_allocation_digest != sealed.allocation_digest
            || enforcement.body.seller_allocation_id != record.allocation_id
            || retained.sanction_case_id != sanction_case_id
            || retained.slash.penalty.body.case_id != retained.sanction_case_id
            || retained.slash.penalty.body.supersedes_penalty_id.as_deref()
                != Some(retained.held_penalty_id.as_str())
            || retained.slash.evaluation.penalty_id != retained.slash.penalty.body.penalty_id
            || !retained.slash.evaluation.findings.is_empty()
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "retained finalizing authorization conflicts with the durable liability".to_owned(),
            ));
        }
        self.require_penalty_matches_enforcement(
            record,
            enforcement,
            &retained.slash.penalty,
            now,
        )?;
        let effect_intent_keys = enforcement_effect_intent_keys(enforcement);
        for (kind, key) in &effect_intent_keys {
            let intent = self
                .challenges
                .get_effect_intent(key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
            if intent.kind != *kind
                || intent.liability_key.as_deref() != Some(record.liability_key.as_str())
                || !intent.settlement_required
            {
                return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
            }
        }
        let enforcement_envelope_sha256 = self.envelope_digest(enforcement)?;
        Ok(AppealResolution::Finalizing(Box::new(
            AuthorizedImpairment {
                enforcement: retained.enforcement,
                enforcement_envelope_sha256,
                slash: retained.slash,
                effect_intent_keys,
            },
        )))
    }

    /// Sign the enforcement instruction and fence every domain-keyed
    /// effect intent before the liability enters finalizing.
    ///
    /// Every field of the instruction that names a target comes from the
    /// durable head rather than from the call, so the signed authorization
    /// can only ever point at the allocation and vault the liability was
    /// opened against.
    #[allow(clippy::too_many_arguments)]
    fn finalize_enforcement(
        &self,
        record: &FindingLiabilityRecord,
        outcome: &SignedFindingChallengeOutcome,
        sealed: &SealedClaimSnapshot,
        slash: &FindingPenaltyOutcome,
        sanction_case_id: &str,
        held_penalty_id: &str,
        authenticated_admission: &SignedFindingAdmission,
        operator_id: &str,
        bond_snapshot_envelope_sha256: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        if sealed.distribution.slash.units == 0 || sealed.distribution.entries.is_empty() {
            return Err(ChallengeCoordinatorError::NothingToImpair);
        }
        if slash.penalty.body.case_id != sanction_case_id
            || slash.penalty.body.supersedes_penalty_id.as_deref() != Some(held_penalty_id)
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "final penalty does not follow the authenticated appeal lineage".to_owned(),
            ));
        }
        self.require_finalizing_status_feed_binding(record, authenticated_admission)?;
        let liability_key = record.liability_key.as_str();
        let outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        let seller_impair_key = derive_seller_impair_intent_key(
            &record.chain_id,
            &record.vault_contract,
            liability_key,
            &sealed.allocation_digest,
        );
        let root_intent_key = derive_root_intent_key(
            operator_id,
            liability_key,
            &outcome.body.outcome_id,
            &sealed.allocation_digest,
        );
        let retraction_intent_id = sha256_hex(
            format!(
                "{RETRACTION_INTENT_DOMAIN}\0{liability_key}\0{outcome}",
                outcome = outcome.body.outcome_id
            )
            .as_bytes(),
        );
        let retraction_key = derive_retraction_intent_key(
            &record.finding_id,
            &self.status_feed_operator_ref,
            &retraction_intent_id,
        );

        let mut bindings = vec![
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::SellerImpair,
                intent_id: seller_impair_key.clone(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::RootIntent,
                intent_id: root_intent_key.clone(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::Retraction,
                intent_id: retraction_key.clone(),
            },
        ];
        let mut fenced = vec![
            (
                FindingEffectIntentKind::SellerImpair,
                seller_impair_key.clone(),
                // The commitment carries the vault the impairment targets
                // as well as the money it moves, so two enforcements for
                // one liability naming different vaults collide on this
                // key and reject instead of reconciling as identical.
                format!(
                    "{EFFECT_SELLER_IMPAIR_DOMAIN}\0{chain}\0{contract}\0{vault}\0{allocation}",
                    chain = record.chain_id,
                    contract = record.vault_contract,
                    vault = record.vault_id,
                    allocation = sealed.allocation_digest,
                ),
            ),
            (
                FindingEffectIntentKind::RootIntent,
                root_intent_key.clone(),
                root_intent_commitment(liability_key, &slash.penalty_envelope_sha256),
            ),
            (
                FindingEffectIntentKind::Retraction,
                retraction_key.clone(),
                retraction_intent_id.clone(),
            ),
        ];

        // The challenge-bond disposition is a separate effect with its own
        // key, so a bond return can never reconcile against the seller
        // impairment or the fee.
        if let Some(challenge_id) = record.upheld_challenge_id.as_deref() {
            if let Some(lock) = self
                .challenges
                .get_dispute_lock(challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            {
                if lock.state != FindingDisputeLockState::Returned {
                    return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
                }
                let collected_fee_key = dispute_fee_intent_key(challenge_id);
                let collected_fee = self
                    .challenges
                    .get_effect_intent(&collected_fee_key)
                    .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                    .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
                if collected_fee.kind != FindingEffectIntentKind::Fee
                    || collected_fee.liability_key.is_some()
                    || collected_fee.settlement_required
                    || collected_fee.state != FindingEffectIntentState::Confirmed
                {
                    return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
                }
                let fee_key = derive_fee_intent_key(liability_key, &collected_fee_key);
                let fee_commitment = format!(
                    "{EFFECT_FEE_DOMAIN}\0collected\0{collected_fee_key}\0{digest}",
                    digest = collected_fee.intent_digest,
                );
                bindings.push(FindingEffectIntentBinding {
                    kind: chio_finding::FindingEffectIntentKind::Fee,
                    intent_id: fee_key.clone(),
                });
                fenced.push((FindingEffectIntentKind::Fee, fee_key, fee_commitment));
                let key = derive_challenge_bond_intent_key(challenge_id, &lock.lock_id);
                // The commitment separately binds the disposition, amount,
                // currency, and destination, so two conflicting
                // dispositions of one bond collide and reject.
                let digest = sha256_hex(
                    format!(
                        "{EFFECT_CHALLENGE_BOND_DOMAIN}\0returned\0{units}\0{currency}\0{owner}",
                        units = lock.amount_units,
                        currency = lock.currency,
                        owner = lock.owner_hex,
                    )
                    .as_bytes(),
                );
                bindings.push(FindingEffectIntentBinding {
                    kind: chio_finding::FindingEffectIntentKind::ChallengeBond,
                    intent_id: key.clone(),
                });
                fenced.push((FindingEffectIntentKind::ChallengeBond, key, digest));
            }
        }

        for (kind, key, commitment) in &fenced {
            self.challenges
                .record_effect_intent(
                    key,
                    *kind,
                    &sha256_hex(commitment.as_bytes()),
                    Some(liability_key),
                    true,
                    now,
                )
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
            if matches!(
                *kind,
                FindingEffectIntentKind::ChallengeBond | FindingEffectIntentKind::Fee
            ) {
                let state = self
                    .challenges
                    .get_effect_intent(key)
                    .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                    .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?
                    .state;
                if state == FindingEffectIntentState::Pending {
                    self.challenges
                        .advance_effect_intent(key, FindingEffectIntentState::Dispatched, now)
                        .map_err(|error| {
                            ChallengeCoordinatorError::ChallengeStore(error.to_string())
                        })?;
                    self.challenges
                        .advance_effect_intent(key, FindingEffectIntentState::Confirmed, now)
                        .map_err(|error| {
                            ChallengeCoordinatorError::ChallengeStore(error.to_string())
                        })?;
                }
            }
        }

        let destinations = sealed
            .distribution
            .entries
            .iter()
            .map(|entry: &DistributionEntry| FindingEnforcementDestination {
                destination: entry.destination.clone(),
                amount: MonetaryAmount {
                    units: entry.amount_units,
                    currency: sealed.distribution.slash.currency.clone(),
                },
            })
            .collect();
        let mut enforcement = FindingChallengeEnforcement {
            schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_owned(),
            enforcement_id: String::new(),
            liability_key: liability_key.to_owned(),
            finding_id: record.finding_id.clone(),
            listing_id: record.listing_id.clone(),
            outcome_id: outcome.body.outcome_id.clone(),
            outcome_envelope_sha256,
            penalty_envelope_sha256: slash.penalty_envelope_sha256.clone(),
            bond_snapshot_envelope_sha256: bond_snapshot_envelope_sha256.to_owned(),
            purchase_snapshot_digest: sealed.snapshot_digest.clone(),
            deterministic_allocation_digest: sealed.allocation_digest.clone(),
            seller_allocation_id: record.allocation_id.clone(),
            vault: chio_finding::FindingVaultReference {
                chain_id: record.chain_id.clone(),
                vault_contract: record.vault_contract.clone(),
                vault_id: record.vault_id.clone(),
            },
            amount: sealed.distribution.slash.clone(),
            destinations,
            effect_intents: bindings,
            penalty_authority_id: self.penalty_pin.authority_id.clone(),
            penalty_key: self.penalty_authority.public_key(),
            penalty_key_epoch: self.penalty_pin.key_epoch,
            penalty_valid_from: self.penalty_pin.valid_from,
            penalty_valid_until: self.penalty_pin.valid_until,
            penalty_revocation_status_ref: self.penalty_pin.revocation_status_ref.clone(),
            finalization_authority_id: self.finalization_pin.authority_id.clone(),
            finalization_key: self.finalization_authority.public_key(),
            finalization_key_epoch: self.finalization_pin.key_epoch,
            finalization_valid_from: self.finalization_pin.valid_from,
            finalization_valid_until: self.finalization_pin.valid_until,
            finalization_revocation_status_ref: self.finalization_pin.revocation_status_ref.clone(),
            finalized_at: now,
        };
        enforcement.enforcement_id = compute_enforcement_id(&enforcement)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        enforcement
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        self.require_live_role(&self.finalization_pin, now, now, "finalization")?;
        let signed = SignedFindingChallengeEnforcement::sign_with_backend(
            enforcement,
            self.finalization_authority.as_ref(),
        )
        .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let enforcement_envelope_sha256 = self.envelope_digest(&signed)?;
        let authorized = AuthorizedImpairment {
            enforcement: signed.clone(),
            enforcement_envelope_sha256,
            slash: slash.clone(),
            effect_intent_keys: fenced
                .into_iter()
                .map(|(kind, key, _)| (kind, key))
                .collect(),
        };
        let retained = RetainedAuthorizedImpairment {
            enforcement: authorized.enforcement.clone(),
            slash: authorized.slash.clone(),
            finalization_policy: self.finalization_pin.clone(),
            settlement_observer_policy: self.pins.settlement_observer.clone(),
            sanction_case_id: sanction_case_id.to_owned(),
            held_penalty_id: held_penalty_id.to_owned(),
        };
        let authorization_json =
            canonical_json_bytes(&retained).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let authorization_sha256 = sha256_hex(&authorization_json);
        let inclusion_deadline = now
            .checked_add(self.status_feed_service_bond.inclusion_sla_secs)
            .ok_or_else(|| {
                ChallengeCoordinatorError::Configuration(
                    "finding status inclusion deadline overflowed".to_owned(),
                )
            })?;
        require_status_feed_through(
            &self.status_feed_operator,
            &self.status_feed_service_bond,
            &self.status_feed_operator_ref,
            now,
            inclusion_deadline,
        )
        .map_err(|error| ChallengeCoordinatorError::Configuration(error.to_string()))?;
        let enforcement_bytes = chio_core::canonical_json_bytes(&signed)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        // The appeal-final transition and exact status outbox item share one
        // SQLite transaction. Nothing before this edge can make the finding
        // sticky pending, and no finalizing head can exist without the item
        // needed to clear publication_pending.
        self.status
            .begin_finalizing_with_retraction(
                liability_key,
                &slash.penalty.body.case_id,
                &FindingFinalizingAuthorizationInput {
                    liability_key,
                    authorization_json: &authorization_json,
                    authorization_sha256: &authorization_sha256,
                    recorded_at: now,
                },
                &FindingRetractionIntentInput {
                    intent_id: &retraction_key,
                    feed_id: &self.status_feed_operator_ref,
                    operator_id: &self.status_feed_operator.authority.authority_id,
                    finding_id: &record.finding_id,
                    source: FindingRetractionIntentSource::Enforcement,
                    intent_bytes: &enforcement_bytes,
                    issued_at: now,
                    inclusion_deadline,
                    created_at: now,
                },
                FindingRetractionIntentCommitLiveness {
                    valid_from: self
                        .status_feed_operator
                        .authority
                        .valid_from
                        .max(self.status_feed_service_bond.valid_from),
                    valid_until: self
                        .status_feed_operator
                        .authority
                        .valid_until
                        .min(
                            self.status_feed_operator
                                .revoked_from
                                .unwrap_or(self.status_feed_operator.authority.valid_until),
                        )
                        .min(self.status_feed_service_bond.valid_until),
                },
                || self.status_commit_clock.now_unix_secs(now),
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        Ok(AppealResolution::Finalizing(Box::new(authorized)))
    }

    /// Mint one finding penalty under the pinned penalty authority and
    /// evaluate it through the composing wrapper.
    ///
    /// Every finding-specific field is set here rather than accepted from
    /// a caller: the abuse class, the bond class, the branch's action and
    /// state, the single external evidence reference bound to the signed
    /// outcome, and the checked amount. The wrapper then runs the generic
    /// evaluation first and refuses any result carrying findings.
    ///
    /// The authority set the whole penalty lane authenticates against is
    /// built from the pinned governance root for the charter, case, and
    /// activation, the exact schedule signer bound by the authenticated
    /// historical admission, and this coordinator's own penalty key. A
    /// key that appears only in an unadmitted artifact never joins that
    /// set, so a self-signed governance case cannot authorize a slash.
    #[allow(clippy::too_many_arguments)]
    fn mint_penalty(
        &self,
        branch: FindingPenaltyBranch,
        governance: &FindingPenaltyGovernance<'_>,
        case: &SignedGenericGovernanceCase,
        prior_penalty: Option<&SignedOpenMarketPenalty>,
        checked_amount: &MonetaryAmount,
        outcome: &SignedFindingChallengeOutcome,
        sanction_case_id: &str,
        hold_penalty_id: Option<&str>,
        issued_at: u64,
        now: u64,
    ) -> Result<FindingPenaltyOutcome, ChallengeCoordinatorError> {
        self.require_current_role(&self.penalty_pin, issued_at, now, "penalty")?;
        let penalty_key = self.penalty_authority.public_key();
        let mut trusted = self.require_pinned_governance(governance, case, prior_penalty, now)?;
        let outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        let (action, state, supersedes) = match branch {
            FindingPenaltyBranch::PendingAppeal => (
                OpenMarketPenaltyAction::HoldBond,
                OpenMarketPenaltyState::Enforced,
                None,
            ),
            FindingPenaltyBranch::SuccessfulAppeal => (
                OpenMarketPenaltyAction::ReverseSlash,
                OpenMarketPenaltyState::Reversed,
                hold_penalty_id,
            ),
            FindingPenaltyBranch::AppealFinalImpairment => (
                OpenMarketPenaltyAction::SlashBond,
                OpenMarketPenaltyState::Enforced,
                hold_penalty_id,
            ),
        };
        let issue = OpenMarketPenaltyIssueRequest {
            fee_schedule: governance.fee_schedule.clone(),
            charter: governance.charter.clone(),
            case: case.clone(),
            listing: governance.listing.clone(),
            activation: governance.activation.cloned(),
            abuse_class: OpenMarketAbuseClass::FraudulentListing,
            bond_class: OpenMarketBondClass::Listing,
            action,
            state,
            penalty_amount: checked_amount.clone(),
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::External,
                reference_id: outcome.body.outcome_id.clone(),
                uri: None,
                sha256: Some(outcome_envelope_sha256.clone()),
            }],
            subject_operator_id: Some(governance.subject_operator_id.to_owned()),
            supersedes_penalty_id: supersedes.map(str::to_owned),
            issued_by: governance.issued_by.to_owned(),
            opened_at: Some(issued_at),
            updated_at: Some(issued_at),
            expires_at: governance.penalty_expires_at,
            note: None,
        };
        for key in [governance.fee_schedule.signer_key.clone(), penalty_key] {
            if !trusted.contains(&key) {
                trusted.push(key);
            }
        }
        let artifact = build_open_market_penalty_artifact_with_trusted_signers(
            governance.local_operator_id,
            &issue,
            issued_at,
            &trusted,
        )
        .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        let penalty =
            SignedOpenMarketPenalty::sign_with_backend(artifact, self.penalty_authority.as_ref())
                .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let penalty_envelope_sha256 = self.envelope_digest(&penalty)?;
        let request = OpenMarketPenaltyEvaluationRequest {
            fee_schedule: governance.fee_schedule.clone(),
            listing: governance.listing.clone(),
            current_publisher: governance.current_publisher.clone(),
            activation: governance.activation.cloned(),
            charter: governance.charter.clone(),
            case: case.clone(),
            penalty: penalty.clone(),
            prior_penalty: prior_penalty.cloned(),
            evaluated_at: Some(now),
        };
        let evaluation = evaluate_finding_penalty(
            &request,
            branch,
            &FindingPenaltyContext {
                outcome_id: &outcome.body.outcome_id,
                outcome_envelope_sha256: &outcome_envelope_sha256,
                checked_amount,
                sanction_case_id,
                hold_penalty_id,
            },
            now,
            &trusted,
        )
        .map_err(|error| ChallengeCoordinatorError::PenaltyEvaluation(error.to_string()))?;
        self.filings
            .retain_penalty_policy(&penalty_envelope_sha256, &self.penalty_pin)
            .map_err(ChallengeCoordinatorError::PenaltyPolicyRetention)?;
        Ok(FindingPenaltyOutcome {
            penalty,
            penalty_envelope_sha256,
            evaluation,
        })
    }
    /// Evidence-bundle commitment over the exact selected branch and inputs.
    pub(crate) fn evidence_bundle_digest(
        &self,
        challenge: &FindingChallenge,
        evidence: &FindingChallengeClassEvidence<'_>,
        purchase_authority_status: Option<&SignedFindingAuthorityStatus>,
        governance_authority_status: &SignedFindingAuthorityStatus,
        audit_selection: Option<&ResolvedFindingAuditSelection>,
    ) -> Result<String, ChallengeCoordinatorError> {
        let bytes = chio_core::canonical_json_bytes(&challenge.evidence)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let (branch, mut supplemental_digests) = match evidence {
            FindingChallengeClassEvidence::EvidenceInvalid(resolved) => {
                let standing = &resolved.purchase_standing;
                let mut digests = vec![
                    self.envelope_digest(standing.purchase_record)?,
                    self.resolved_receipt_digest(
                        &standing.delivery_receipt.canonical_receipt_bytes,
                        &standing.delivery_receipt.inclusion_proof,
                    )?,
                    self.canonical_digest(standing.delivery_checkpoint)?,
                    self.canonical_digest(standing.delivery_checkpoint_transparency)?,
                    self.envelope_digest(standing.delivery_authority_status)?,
                    self.envelope_digest(resolved.checkpoint_authority_status)?,
                    self.envelope_digest(resolved.production_authority_status)?,
                ];
                if let Some(status) = purchase_authority_status {
                    digests.push(self.envelope_digest(status)?);
                }
                for receipt in resolved.challenged_receipts {
                    digests.push(self.resolved_receipt_digest(
                        &receipt.canonical_receipt_bytes,
                        &receipt.inclusion_proof,
                    )?);
                }
                digests.push(self.canonical_digest(resolved.challenged_checkpoint)?);
                digests.push(self.canonical_digest(resolved.checkpoint_transparency)?);
                for proof in resolved.revoked_keys {
                    digests.push(self.envelope_digest(proof.statement)?);
                    digests.push(self.envelope_digest(proof.publication_status)?);
                    digests.push(self.envelope_digest(proof.governance_authority_status)?);
                }
                ("evidence_invalid", digests)
            }
            FindingChallengeClassEvidence::DigestMismatch(resolved) => (
                "digest_mismatch",
                vec![
                    self.envelope_digest(resolved.failed_delivery)?,
                    self.envelope_digest(resolved.failed_delivery_authority_status)?,
                    self.envelope_digest(resolved.delivery_authority_status)?,
                    self.resolved_receipt_digest(
                        &resolved.deny_receipt.canonical_receipt_bytes,
                        &resolved.deny_receipt.inclusion_proof,
                    )?,
                    self.canonical_digest(resolved.deny_checkpoint)?,
                    self.canonical_digest(resolved.checkpoint_transparency)?,
                ],
            ),
            FindingChallengeClassEvidence::ReplayContradiction(resolved) => {
                let standing = &resolved.purchase_standing;
                let mut digests = vec![
                    self.envelope_digest(standing.purchase_record)?,
                    self.resolved_receipt_digest(
                        &standing.delivery_receipt.canonical_receipt_bytes,
                        &standing.delivery_receipt.inclusion_proof,
                    )?,
                    self.canonical_digest(standing.delivery_checkpoint)?,
                    self.canonical_digest(standing.delivery_checkpoint_transparency)?,
                    self.envelope_digest(standing.delivery_authority_status)?,
                    self.envelope_digest(resolved.replay_authority_status)?,
                ];
                if let Some(status) = purchase_authority_status {
                    digests.push(self.envelope_digest(status)?);
                }
                for reproduction in resolved.reproductions {
                    let reproduction_digest = self.canonical_digest(&(
                        self.resolved_receipt_digest(
                            &reproduction.receipt.canonical_receipt_bytes,
                            &reproduction.receipt.inclusion_proof,
                        )?,
                        self.canonical_digest(reproduction.checkpoint)?,
                        self.canonical_digest(reproduction.checkpoint_transparency)?,
                    ))?;
                    digests.push(reproduction_digest);
                }
                ("replay_contradiction", digests)
            }
        };
        supplemental_digests.insert(0, self.envelope_digest(governance_authority_status)?);
        if let Some(selection) = audit_selection {
            supplemental_digests.push(self.envelope_digest(&selection.round.epoch)?);
            supplemental_digests.push(self.envelope_digest(&selection.round.authorization)?);
            supplemental_digests.push(self.canonical_digest(&selection.round.revealed_seed)?);
            supplemental_digests.push(
                derive_eligible_snapshot_digest(&selection.round.eligible)
                    .map_err(|_| ChallengeCoordinatorError::Canonical)?,
            );
            supplemental_digests.push(self.canonical_digest(&selection.audit_authority.to_hex())?);
            supplemental_digests
                .push(self.canonical_digest(&selection.randomness_witness.to_hex())?);
            supplemental_digests
                .push(self.canonical_digest(&selection.governance_authority.to_hex())?);
        }
        let resolved_bytes = self.canonical_bytes(&(branch, supplemental_digests))?;
        let mut preimage = Vec::with_capacity(
            EVIDENCE_BUNDLE_DOMAIN.len() + 1 + bytes.len() + 1 + resolved_bytes.len(),
        );
        preimage.extend_from_slice(EVIDENCE_BUNDLE_DOMAIN.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&bytes);
        preimage.push(0);
        preimage.extend_from_slice(&resolved_bytes);
        Ok(sha256_hex(&preimage))
    }

    fn resolved_receipt_digest<T: Serialize>(
        &self,
        canonical_receipt_bytes: &[u8],
        inclusion_proof: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        self.canonical_digest(&(sha256_hex(canonical_receipt_bytes), inclusion_proof))
    }

    fn canonical_digest<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<String, ChallengeCoordinatorError> {
        Ok(sha256_hex(&self.canonical_bytes(value)?))
    }

    fn canonical_bytes<T: Serialize>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, ChallengeCoordinatorError> {
        canonical_json_bytes(value).map_err(|_| ChallengeCoordinatorError::Canonical)
    }

    fn envelope_digest<T: serde::Serialize>(
        &self,
        envelope: &chio_core::receipt::lineage::SignedExportEnvelope<T>,
    ) -> Result<String, ChallengeCoordinatorError> {
        signed_envelope_sha256(envelope).map_err(|_| ChallengeCoordinatorError::Canonical)
    }
}
