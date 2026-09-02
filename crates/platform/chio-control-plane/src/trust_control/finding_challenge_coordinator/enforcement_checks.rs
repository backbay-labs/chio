// Collateral, window, root, and appeal enforcement requirements.

impl FindingChallengeCoordinator {
    /// Resolve the instant this liability's claim window closes.
    ///
    /// The length is a term the seller signed for this exact finding and
    /// listing, never an operator's choice: the snapshot it gates is what
    /// harmed buyers and omission proofs are paid from, so the venue must
    /// not be able to shorten it once adjudication has landed. Terms for
    /// another listing, or an envelope the embedded seller did not sign,
    /// bind nothing here.
    fn require_claim_window(
        &self,
        terms: &SignedFindingMarketTerms,
        identity: &FindingLiabilityIdentity<'_>,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        verify_signed_market_terms(terms)
            .map_err(|error| ChallengeCoordinatorError::TermsEnvelope(error.to_string()))?;
        if terms.body.finding_id != identity.finding_id {
            return Err(ChallengeCoordinatorError::TermsBinding("finding_id"));
        }
        if terms.body.listing_id != identity.listing_id {
            return Err(ChallengeCoordinatorError::TermsBinding("listing_id"));
        }
        now.checked_add(terms.body.claim_window_secs)
            .ok_or(ChallengeCoordinatorError::TermsBinding("claim_window_secs"))
    }

    /// Require penalty facts to carry the seller's signed base stake before
    /// either an outcome or a liability transition can become durable.
    ///
    /// The evaluation and liability-opening paths consume the same facts at
    /// different times. Checking only when the liability opens would let the
    /// evaluator sign and record an upheld verdict that can never progress.
    fn require_signed_base_stake(
        terms: &SignedFindingMarketTerms,
        collateral: &FindingCollateralFacts<'_>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let signed_stake = &terms.body.backing_requirement.base_finding_stake;
        if collateral.base_finding_stake.units != signed_stake.units
            || collateral.base_finding_stake.currency != signed_stake.currency
        {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "base_finding_stake",
            ));
        }
        Ok(())
    }

    /// Exposure still outstanding against one allocation, read after the
    /// expiry sweep has retired every reservation whose expiry has
    /// passed.
    ///
    /// The sweep releases exposure no purchase can realize any more, so
    /// the figure every slash input reads is backed by reservations that
    /// can still settle. The store serializes the sweep and the read on
    /// one connection, and the query applies the same expiry rule itself,
    /// so a lagging sweep can only overstate the encumbrance, never let a
    /// dead reservation slip back in.
    fn outstanding_exposure(
        &self,
        allocation_id: &str,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        self.purchases
            .expire_reservations(now, usize::MAX)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        self.purchases
            .list_outstanding_exposure_total(allocation_id, now)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))
    }

    /// Require the collateral behind this defect to be able to fund a
    /// nonzero impairment, on the same inputs the sealed accounting is
    /// computed from.
    fn require_impairable_collateral(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        let open = self.outstanding_exposure(&collateral.bond_snapshot.body.allocation_id, now)?;
        let candidate = collateral
            .base_finding_stake
            .units
            .checked_add(open)
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic(
                    "computed exposure overflowed".to_owned(),
                )
            })?;
        if candidate.min(live_allocated_collateral) == 0 {
            return Err(ChallengeCoordinatorError::NothingToImpair);
        }
        Ok(())
    }

    /// Authenticate and derive the only live collateral figure penalty math
    /// may consume.
    fn authenticated_live_collateral(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        now: u64,
    ) -> Result<u64, ChallengeCoordinatorError> {
        let snapshot = &collateral.bond_snapshot;
        self.require_live_settlement_observer(snapshot, now)?;
        let (settlement_observer, settlement_observer_status) = self.resolve_live_role(
            &self.pins.settlement_observer,
            snapshot.body.observed_at,
            now,
            "settlement observer",
        )?;
        let authority_status_authority = self
            .pins
            .authority_status
            .key()
            .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("authority status"))?;
        let settlement_observer_policy =
            settlement_penalty_authority_policy(&self.pins.settlement_observer)?;
        if snapshot.body.currency != collateral.base_finding_stake.currency {
            return Err(ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot currency does not match the signed base stake",
            ));
        }
        verify_finding_collateral_snapshot(
            snapshot,
            &settlement_observer,
            FindingSettlementObserverEvidence {
                retained_policy: &settlement_observer_policy,
                signed_status: &settlement_observer_status,
                status_authority: &authority_status_authority,
                max_status_age_secs: MAX_REVOCATION_STATUS_AGE_SECS,
            },
            self.pins.settlement_finality_requirement,
            self.market_config.max_snapshot_age_secs,
            now,
        )
        .map_err(|_| {
            ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot signature, finality, freshness, or balance is invalid",
            )
        })
    }

    /// Require the caller's identity to be exactly the one the durable
    /// head carries, and that head to be the one that identity derives.
    fn require_identity_matches_head(
        &self,
        liability_key: &str,
        identity: &FindingLiabilityIdentity<'_>,
        record: &FindingLiabilityRecord,
    ) -> Result<(), ChallengeCoordinatorError> {
        let fields: [(&str, &str, &'static str); 6] = [
            (&record.finding_id, identity.finding_id, "finding_id"),
            (&record.listing_id, identity.listing_id, "listing_id"),
            (
                &record.allocation_id,
                identity.allocation_id,
                "allocation_id",
            ),
            (&record.chain_id, identity.chain_id, "chain_id"),
            (
                &record.vault_contract,
                identity.vault_contract,
                "vault_contract",
            ),
            (&record.vault_id, identity.vault_id, "vault_id"),
        ];
        for (durable, supplied, label) in fields {
            if durable != supplied {
                return Err(ChallengeCoordinatorError::LiabilityIdentity(label));
            }
        }
        // The key is a commitment to this exact identity, so re-deriving
        // it proves the head named by the key is the head that identity
        // belongs to rather than one that merely exists.
        if derive_liability_key(
            &derive_defect_key(&record.finding_id),
            &self.venue_id,
            identity,
        ) != liability_key
        {
            return Err(ChallengeCoordinatorError::LiabilityIdentity(
                "liability_key",
            ));
        }
        Ok(())
    }

    /// Require the exact root this impairment carries to be published and
    /// confirmed.
    ///
    /// The vault checks the impairment proof against a root, so the call
    /// is only authorized once that root is on chain. The instruction
    /// names the intent that fences it, but naming is not evidence: the
    /// durable record has to belong to this liability, carry the
    /// commitment this exact penalty derives, and sit in `confirmed`.
    fn require_confirmed_enforcement_root(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        planned: &chio_settle::FindingImpairmentIntent,
    ) -> Result<(), ChallengeCoordinatorError> {
        self.require_confirmed_enforcement_root_binding(
            liability_key,
            verified.root_intent_id(),
            &verified.enforcement().penalty_envelope_sha256,
            planned,
        )
    }

    fn require_confirmed_reconciliation_root(
        &self,
        liability_key: &str,
        verified: &ReconciledFindingEnforcement,
        planned: &PlannedFindingImpairmentReconciliation,
    ) -> Result<(), ChallengeCoordinatorError> {
        self.require_confirmed_enforcement_root_binding(
            liability_key,
            verified.root_intent_id(),
            &verified.enforcement().penalty_envelope_sha256,
            planned.intent(),
        )
    }

    fn require_confirmed_enforcement_root_binding(
        &self,
        liability_key: &str,
        root_intent_id: &str,
        penalty_envelope_sha256: &str,
        planned: &chio_settle::FindingImpairmentIntent,
    ) -> Result<(), ChallengeCoordinatorError> {
        let root = self
            .challenges
            .get_effect_intent(root_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if root.kind != FindingEffectIntentKind::RootIntent
            || root.liability_key.as_deref() != Some(liability_key)
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the named root intent does not fence this liability",
            ));
        }
        let expected =
            sha256_hex(root_intent_commitment(liability_key, penalty_envelope_sha256).as_bytes());
        if root.intent_digest != expected {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the fenced root does not commit to the penalty this enforcement pays",
            ));
        }
        let binding = self
            .challenges
            .get_effect_root_binding(root_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the enforcement root has no prepared anchor binding",
            ))?;
        if binding.liability_key != liability_key
            || binding.merkle_root != planned.merkle_root
            || binding.evidence_hash != planned.evidence_hash
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the confirmed root does not bind this Merkle root and evidence hash",
            ));
        }
        if root.state != FindingEffectIntentState::Confirmed {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the enforcement root has not been published",
            ));
        }
        Ok(())
    }

    /// Re-read the exact stored transaction and require it still to be a
    /// canonical finalized execution of the frozen impairment call.
    fn require_reobserved_impairment(
        &self,
        planned: &PlannedFindingImpairment,
        publisher: &dyn FindingImpairmentPublisher,
        expected_tx_hash: Option<&str>,
    ) -> Result<ConfirmedFindingImpairmentReconciliation, ChallengeCoordinatorError> {
        let outcome = reobserve_finding_impairment(planned, publisher)
            .map_err(|error| ChallengeCoordinatorError::Publisher(error.to_string()))?;
        Self::require_reobserved_impairment_outcome(outcome, expected_tx_hash)
    }

    fn require_reobserved_reconciliation(
        &self,
        planned: &PlannedFindingImpairmentReconciliation,
        publisher: &dyn FindingImpairmentPublisher,
        expected_tx_hash: Option<&str>,
    ) -> Result<ConfirmedFindingImpairmentReconciliation, ChallengeCoordinatorError> {
        let outcome = reobserve_finding_impairment_for_reconciliation(planned, publisher)
            .map_err(|error| ChallengeCoordinatorError::Publisher(error.to_string()))?;
        Self::require_reobserved_impairment_outcome(outcome, expected_tx_hash)
    }

    fn require_reobserved_impairment_outcome(
        outcome: FindingImpairmentOutcome,
        expected_tx_hash: Option<&str>,
    ) -> Result<ConfirmedFindingImpairmentReconciliation, ChallengeCoordinatorError> {
        match outcome {
            FindingImpairmentOutcome::Confirmed { reconciliation }
                if expected_tx_hash.is_none_or(|expected| expected == reconciliation.tx_hash()) =>
            {
                Ok(reconciliation)
            }
            FindingImpairmentOutcome::Confirmed { .. } => {
                Err(ChallengeCoordinatorError::Settlement(
                    "re-observed impairment transaction does not match the published transaction"
                        .to_owned(),
                ))
            }
            FindingImpairmentOutcome::Quarantined { .. }
            | FindingImpairmentOutcome::Failed { .. } => {
                Err(ChallengeCoordinatorError::Settlement(
                    "re-observed impairment transaction is not finalized on the canonical chain"
                        .to_owned(),
                ))
            }
        }
    }

    /// Fence the anchored evidence leaf this impairment burns.
    ///
    /// The anchor proof arrives beside the instruction and authenticates
    /// only as a proof: nothing in it names the enforcement it is being
    /// spent on. The leaf is therefore committed here, before the call
    /// leaves, to the liability, the stable seller-impair intent, and the
    /// penalty it pays, under a key that is the leaf itself. The stable
    /// intent survives an allowed observer-snapshot refresh, while one
    /// anchored receipt still authorizes exactly one impairment: presenting
    /// it again under different terms collides with what is already durable
    /// and rejects, and replaying the same terms reconciles.
    fn fence_anchor_evidence(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        intent: &chio_settle::FindingImpairmentIntent,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let commitment = anchor_evidence_intent_commitment(
            liability_key,
            &intent.intent_id,
            &verified.enforcement().penalty_envelope_sha256,
            &intent.merkle_root,
        );
        let anchor_key = derive_anchor_evidence_intent_key(&intent.evidence_hash);
        self.challenges
            .record_effect_intent(
                &anchor_key,
                FindingEffectIntentKind::RootIntent,
                &commitment,
                Some(liability_key),
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        self.challenges
            .bind_effect_root(
                &anchor_key,
                liability_key,
                &intent.merkle_root,
                &intent.evidence_hash,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(())
    }

    /// Re-read the chain and identity state behind a verified snapshot and
    /// require it to still qualify.
    ///
    /// The read itself is injected, so a source that cannot complete it
    /// denies rather than returning state it is unsure of. Unknown chain
    /// state and a disqualified observation are the same answer here:
    /// neither authorizes moving collateral.
    fn require_qualified_observation(
        &self,
        verified: &VerifiedFindingEnforcement,
        observations: &dyn FindingBondObservationSource,
    ) -> Result<(), ChallengeCoordinatorError> {
        let observed = observations
            .observe(verified)
            .map_err(|error| ChallengeCoordinatorError::BondObservation(error.to_string()))?;
        let verdict = recheck_finding_bond_observation(verified, &observed);
        if !verdict.is_qualified() {
            return Err(ChallengeCoordinatorError::BondObservation(
                verdict.reason().to_owned(),
            ));
        }
        Ok(())
    }

    /// Require a successful appeal to have been opened inside the exact
    /// seller-signed window frozen when the liability entered pending
    /// appeal. Resolution may finish later; filing itself must be timely.
    fn require_timely_appeal(
        &self,
        record: &FindingLiabilityRecord,
        appeal_case: &SignedGenericGovernanceCase,
        appeal_case_id: &str,
    ) -> Result<(), ChallengeCoordinatorError> {
        if appeal_case.body.case_id != appeal_case_id {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal case id does not match the signed case",
            ));
        }
        let opened =
            record
                .appeal_window_opened_at
                .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                    "appeal window was not frozen",
                ))?;
        let deadline = record
            .appeal_deadline
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "appeal deadline was not frozen",
            ))?;
        if appeal_case.body.opened_at < opened {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal predates the durable appeal window",
            ));
        }
        if appeal_case.body.opened_at > deadline {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal was opened after the durable deadline",
            ));
        }
        Ok(())
    }

    /// Require the appeal window on this liability to be provably closed
    /// with the presented sanction still governing it. The deadline is
    /// the value frozen from seller-signed terms, never a caller input.
    fn require_appeal_window_closed(
        &self,
        record: &FindingLiabilityRecord,
        sanction_case: &SignedGenericGovernanceCase,
        sanction_case_id: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        if sanction_case.body.case_id != sanction_case_id {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "sanction case does not name the sanction being closed",
            ));
        }
        let head = self
            .challenges
            .resolve_case_head(&record.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "liability carries no live governance case",
            ))?;
        if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id
        {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "the sanction is no longer the live case on this liability",
            ));
        }
        let appeal_deadline =
            record
                .appeal_deadline
                .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                    "appeal deadline was not frozen",
                ))?;
        if now <= appeal_deadline {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "appeal deadline has not passed at the venue clock",
            ));
        }
        Ok(())
    }

    /// Require a sanction to still be the live governance case on this
    /// liability before its impairment dispatches.
    ///
    /// The appeal window was proved closed when the enforcement was
    /// signed, but the durable case index can move between that instant
    /// and this dispatch: a recorded successful appeal supersedes the
    /// sanction, and an impairment sent afterwards would slash under an
    /// authority that no longer governs. The head is re-read here, and
    /// anything but a live sanction (including an ambiguous head) refuses
    /// the dispatch.
    fn require_sanction_governs(
        &self,
        liability_key: &str,
        sanction_case_id: &str,
    ) -> Result<(), ChallengeCoordinatorError> {
        let head = self
            .challenges
            .resolve_case_head(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                "liability carries no live governance case",
            ))?;
        if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id
        {
            return Err(ChallengeCoordinatorError::AppealNotFinal(
                "the sanction no longer governs this liability",
            ));
        }
        Ok(())
    }

    /// Authenticate the exact slash penalty the enforcement commits to.
    ///
    /// The enforcement carries only an envelope digest. Presenting the
    /// signed artifact here recovers the governance case identity behind
    /// that digest, while the pinned penalty key prevents a caller from
    /// inventing a different case under otherwise self-consistent bytes.
    fn require_penalty_matches_enforcement(
        &self,
        liability: &FindingLiabilityRecord,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        now: u64,
    ) -> Result<(SignedFindingAuthorityStatus, FindingAuthorityPin), ChallengeCoordinatorError>
    {
        penalty
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let digest = self.envelope_digest(penalty)?;
        let historical_pin = self
            .filings
            .penalty_policy_for_penalty(&digest)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownPenaltyAuthorityPolicy)?;
        if enforcement.body.penalty_authority_id != historical_pin.authority_id
            || enforcement.body.penalty_key.to_hex() != historical_pin.key_hex
            || enforcement.body.penalty_key_epoch != historical_pin.key_epoch
            || enforcement.body.penalty_valid_from != historical_pin.valid_from
            || enforcement.body.penalty_valid_until != historical_pin.valid_until
            || enforcement.body.penalty_revocation_status_ref
                != historical_pin.revocation_status_ref
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement penalty authority does not match retained governance policy"
                    .to_owned(),
            ));
        }
        let (historical_key, status) = self.resolve_live_role(
            &historical_pin,
            penalty.body.updated_at,
            now,
            "historical penalty",
        )?;
        verify_pinned_envelope(penalty, &historical_key, "market penalty")
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        if digest != enforcement.body.penalty_envelope_sha256 {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement does not bind the presented penalty envelope".to_owned(),
            ));
        }
        if penalty.body.listing_id != liability.listing_id {
            return Err(ChallengeCoordinatorError::Settlement(
                "penalty does not name this liability's listing".to_owned(),
            ));
        }
        if penalty.body.action != OpenMarketPenaltyAction::SlashBond
            || penalty.body.state != OpenMarketPenaltyState::Enforced
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "finalization requires an enforced slash penalty".to_owned(),
            ));
        }
        if penalty.body.penalty_amount != enforcement.body.amount {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement amount does not match the bound penalty".to_owned(),
            ));
        }
        Ok((status, historical_pin))
    }

    /// Resolve the durable operator policy that is independent of the signed
    /// enforcement. Buyer destinations and the community fund were admitted
    /// before finalization and are immutable for one collateral allocation.
    fn settlement_destination_allowlist(
        &self,
        allocation_id: &str,
    ) -> Result<BTreeSet<String>, ChallengeCoordinatorError> {
        let destinations = self
            .purchases
            .list_payout_destinations(allocation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .into_iter()
            .map(|(_, destination)| destination)
            .collect::<BTreeSet<_>>();
        if destinations.is_empty() {
            return Err(ChallengeCoordinatorError::Settlement(
                "settlement destination allowlist is empty".to_owned(),
            ));
        }
        Ok(destinations)
    }

    /// Require the presented outcome to be the exact upheld adjudication
    /// this liability was opened on.
    ///
    /// The envelope digest is compared against the one the store recorded
    /// with the verdict, so neither a differently signed outcome for the
    /// same challenge nor an upheld outcome from another defect can carry
    /// an impairment.
    fn require_outcome_upheld_this_liability(
        &self,
        outcome: &SignedFindingChallengeOutcome,
        record: &FindingLiabilityRecord,
    ) -> Result<(), ChallengeCoordinatorError> {
        if outcome.body.verdict != chio_finding::FindingChallengeVerdict::Upheld {
            return Err(ChallengeCoordinatorError::VerdictNotUpheld);
        }
        if outcome.body.finding_id != record.finding_id
            || outcome.body.listing_id != record.listing_id
            || outcome.body.backing_allocation_id != record.allocation_id
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let challenge_id = record
            .upheld_challenge_id
            .as_deref()
            .ok_or(ChallengeCoordinatorError::LiabilityState("upheld"))?;
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let presented = self.envelope_digest(outcome)?;
        if challenge.outcome_envelope_sha256.as_deref() != Some(presented.as_str()) {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        Ok(())
    }

    /// Verify the exact durable adjudication with the evaluator policy that
    /// covered its historical signing time, not the coordinator's current
    /// post-rotation key.
    fn require_recorded_outcome_signature(
        &self,
        challenge_id: &str,
        outcome: &SignedFindingChallengeOutcome,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let presented = self.envelope_digest(outcome)?;
        if challenge.outcome_envelope_sha256.as_deref() != Some(presented.as_str()) {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        outcome
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        let historical_pin = self
            .filings
            .evaluator_policy_for_outcome(&presented)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownEvaluatorPolicy)?;
        if historical_pin.authority_id != outcome.body.evaluator_authority_id
            || historical_pin.key_hex != outcome.body.evaluator_key.to_hex()
            || historical_pin.key_epoch != outcome.body.evaluator_key_epoch
            || historical_pin.valid_from != outcome.body.evaluator_valid_from
            || historical_pin.valid_until != outcome.body.evaluator_valid_until
            || historical_pin.revocation_status_ref != outcome.body.evaluator_revocation_status_ref
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let evaluator = self
            .require_live_role(
                &historical_pin,
                outcome.body.evaluated_at,
                now,
                "historical evaluator",
            )
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::EvaluatorRevocation(reason)
                }
                other => other,
            })?;
        verify_signed_challenge_outcome(outcome, &evaluator)
            .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))
    }
}
