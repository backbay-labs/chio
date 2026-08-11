impl FindingChallengeCoordinator {
    fn retraction_effect_key<'a>(
        &self,
        enforcement: &'a SignedFindingChallengeEnforcement,
    ) -> Result<&'a str, ChallengeCoordinatorError> {
        let mut keys = enforcement
            .body
            .effect_intents
            .iter()
            .filter_map(|binding| {
                (binding.kind == chio_finding::FindingEffectIntentKind::Retraction)
                    .then_some(binding.intent_id.as_str())
            });
        let Some(key) = keys.next() else {
            return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
        };
        if keys.next().is_some() {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement carries more than one retraction effect".to_owned(),
            ));
        }
        Ok(key)
    }

    fn mark_retraction_dispatch_eligible(
        &self,
        enforcement: &SignedFindingChallengeEnforcement,
        tx_hash: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let intent_id = self.retraction_effect_key(enforcement)?;
        let evidence = chio_core::canonical_json_bytes(&serde_json::json!({
            "schema": "chio.finding.impairment-finality.v1",
            "enforcement_id": enforcement.body.enforcement_id,
            "finding_id": enforcement.body.finding_id,
            "liability_key": enforcement.body.liability_key,
            "tx_hash": tx_hash,
        }))
        .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let record = self
            .status
            .get_retraction_intent_for_effect(
                intent_id,
                &self.status_feed_operator_ref,
                &enforcement.body.finding_id,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        match (record.source, record.state) {
            (
                FindingRetractionIntentSource::Voluntary,
                FindingRetractionIntentState::DispatchEligible
                | FindingRetractionIntentState::Published,
            ) => {}
            (
                FindingRetractionIntentSource::Enforcement,
                FindingRetractionIntentState::WaitingFinality,
            ) => {
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
                self.status
                    .mark_retraction_dispatch_eligible(
                        &record.intent_id,
                        &evidence,
                        now,
                        self.status_feed_service_bond.inclusion_sla_secs,
                    )
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            (
                FindingRetractionIntentSource::Enforcement,
                FindingRetractionIntentState::DispatchEligible
                | FindingRetractionIntentState::Published,
            ) => {
                let evidence_sha256 = sha256_hex(&evidence);
                if record.finality_evidence_sha256.as_deref() != Some(evidence_sha256.as_str())
                    || record.finality_evidence_bytes.as_deref() != Some(evidence.as_slice())
                {
                    return Err(ChallengeCoordinatorError::Settlement(
                        "status outbox finality evidence conflicts with the confirmed impairment"
                            .to_owned(),
                    ));
                }
            }
            (
                FindingRetractionIntentSource::Voluntary,
                FindingRetractionIntentState::WaitingFinality,
            ) => {
                return Err(ChallengeCoordinatorError::Settlement(
                    "voluntary retraction is not dispatch eligible".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn confirm_effect_intent(
        &self,
        intent_key: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let intent = self
            .challenges
            .get_effect_intent(intent_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        match intent.state {
            FindingEffectIntentState::Pending | FindingEffectIntentState::Failed => {
                self.challenges
                    .advance_effect_intent(intent_key, FindingEffectIntentState::Dispatched, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingEffectIntentState::Dispatched => {}
            FindingEffectIntentState::Confirmed => return Ok(()),
            FindingEffectIntentState::Quarantined => {
                return Err(ChallengeCoordinatorError::Settlement(
                    "a quarantined effect cannot be confirmed by status publication".to_owned(),
                ));
            }
        }
        if intent.kind == FindingEffectIntentKind::RootIntent {
            let binding = self
                .challenges
                .get_effect_root_binding(intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
            self.challenges
                .confirm_effect_root(
                    intent_key,
                    &binding.merkle_root,
                    &binding.evidence_hash,
                    now,
                )
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        } else {
            self.challenges
                .advance_effect_intent(intent_key, FindingEffectIntentState::Confirmed, now)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        }
        Ok(())
    }

    fn confirm_fenced_anchor_effect(
        &self,
        liability_key: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let effects = self
            .challenges
            .list_effect_intents(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let mut anchors = effects.iter().filter(|effect| {
            effect.kind == FindingEffectIntentKind::RootIntent && !effect.settlement_required
        });
        let anchor = anchors
            .next()
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if anchors.next().is_some() {
            return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
        }
        self.confirm_effect_intent(&anchor.intent_key, now)
    }

    fn reconcile_status_publication_and_settle(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        now: u64,
    ) -> Result<bool, ChallengeCoordinatorError> {
        let retraction_key = self.retraction_effect_key(enforcement)?;
        let status = self
            .status
            .get_retraction_intent_for_effect(
                retraction_key,
                &self.status_feed_operator_ref,
                &enforcement.body.finding_id,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if status.state != FindingRetractionIntentState::Published {
            return Ok(false);
        }
        self.confirm_effect_intent(retraction_key, now)?;
        let effects = self
            .challenges
            .list_effect_intents(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if effects.is_empty()
            || effects
                .iter()
                .any(|effect| effect.state != FindingEffectIntentState::Confirmed)
        {
            return Ok(false);
        }
        self.challenges
            .settle_liability(liability_key, FindingLiabilityState::Finalizing, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(true)
    }

    /// Finish a previously confirmed impairment without dispatching it
    /// again.
    ///
    /// The liability is loaded again here because another finalizer may
    /// have quarantined it after this caller's initial read. Settlement
    /// repeats the same check in its write transaction, closing the race
    /// between this read and the lifecycle transition.
    fn finish_confirmed_impairment(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        observations: &dyn FindingBondObservationSource,
        tx_hash: &str,
        now: u64,
    ) -> Result<FindingFinalization, ChallengeCoordinatorError> {
        let liability = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        // If a post-dispatch chain recheck quarantined the liability,
        // recovery must explicitly authenticate the original snapshot and
        // re-observe its block and operator qualification before the
        // quarantine can be cleared.
        if liability.quarantined {
            self.require_live_settlement_observer(bond_snapshot, now)?;
            let settlement_observer = self.require_live_role(
                &self.pins.settlement_observer,
                bond_snapshot.body.observed_at,
                now,
                "settlement observer",
            )?;
            let seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
                ChallengeCoordinatorError::ChallengeStore(
                    "liability carries an invalid durable seller key".to_owned(),
                )
            })?;
            let pins = FindingEnforcementPins {
                finalization_authority: self.finalization_authority.public_key(),
                settlement_observer,
                seller,
                finality_requirement: self.pins.settlement_finality_requirement,
                max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
            };
            let verified = verify_finding_enforcement_for_reconciliation(
                enforcement,
                bond_snapshot,
                &pins,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
            self.require_qualified_observation(&verified, observations)?;
            self.challenges
                .set_liability_quarantine(liability_key, false, now)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        }
        self.confirm_fenced_anchor_effect(liability_key, now)?;
        self.mark_retraction_dispatch_eligible(enforcement, tx_hash, now)?;
        if self.reconcile_status_publication_and_settle(liability_key, enforcement, now)? {
            Ok(FindingFinalization::AlreadyConfirmed)
        } else {
            Ok(FindingFinalization::AwaitingStatusPublication)
        }
    }

    /// The sealed claim snapshot for one liability, when one exists.
    pub fn sealed_claim(
        &self,
        liability_key: &str,
    ) -> Result<Option<(String, String)>, ChallengeCoordinatorError> {
        Ok(self
            .challenges
            .get_claim_snapshot(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .map(|record| (record.snapshot_digest, record.allocation_digest)))
    }
}
