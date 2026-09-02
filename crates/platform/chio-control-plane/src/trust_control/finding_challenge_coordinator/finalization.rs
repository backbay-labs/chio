// Finalizing-enforcement refresh and liability finalization.

impl FindingChallengeCoordinator {
    /// Re-sign a finalizing enforcement against a fresh, verified bond
    /// snapshot before the seller impairment has ever been dispatched.
    ///
    /// Snapshot freshness is intentionally checked at publication time,
    /// but queueing or reconciliation delay can age out the snapshot that
    /// closed the appeal. The liability and every semantic effect remain
    /// frozen; only the observer-signed snapshot digest and finalization
    /// instant change. Before a first attempt, no root may be bound. After a
    /// retryable failed attempt, the published root stays in its append-only
    /// lineage and the next exact proof replaces only the active refinement.
    pub fn refresh_finalizing_enforcement(
        &self,
        authorized: &AuthorizedImpairment,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        seller: &PublicKey,
        now: u64,
    ) -> Result<AuthorizedImpairment, ChallengeCoordinatorError> {
        let old = &authorized.enforcement;
        if self.envelope_digest(old)? != authorized.enforcement_envelope_sha256 {
            return Err(ChallengeCoordinatorError::Settlement(
                "authorized impairment digest does not match its enforcement".to_owned(),
            ));
        }
        let liability = self
            .challenges
            .get_liability(&old.body.liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(ChallengeCoordinatorError::LiabilityState("finalizing"));
        }
        let durable_seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
            ChallengeCoordinatorError::ChallengeStore(
                "liability carries an invalid durable seller key".to_owned(),
            )
        })?;
        if seller != &durable_seller {
            return Err(ChallengeCoordinatorError::LiabilityIdentity("seller"));
        }
        let (penalty_status, penalty_authority) = self.require_penalty_matches_enforcement(
            &liability,
            old,
            &authorized.slash.penalty,
            now,
        )?;
        let seller_intent_id = old
            .body
            .effect_intents
            .iter()
            .find(|binding| binding.kind == chio_finding::FindingEffectIntentKind::SellerImpair)
            .map(|binding| binding.intent_id.as_str())
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let seller_intent = self
            .challenges
            .get_effect_intent(seller_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if seller_intent.kind != FindingEffectIntentKind::SellerImpair
            || seller_intent.liability_key.as_deref() != Some(old.body.liability_key.as_str())
            || !matches!(
                seller_intent.state,
                FindingEffectIntentState::Pending | FindingEffectIntentState::Failed
            )
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "bond snapshot refresh is permitted only before anchor binding or dispatch"
                    .to_owned(),
            ));
        }
        let mut root_intents =
            old.body.effect_intents.iter().filter(|binding| {
                binding.kind == chio_finding::FindingEffectIntentKind::RootIntent
            });
        let root_intent_id = root_intents
            .next()
            .map(|binding| binding.intent_id.as_str())
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if root_intents.next().is_some() {
            return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
        }
        let root_intent = self
            .challenges
            .get_effect_intent(root_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let root_binding = self
            .challenges
            .get_effect_root_binding(root_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let root_is_refreshable = match seller_intent.state {
            FindingEffectIntentState::Pending => {
                root_intent.state == FindingEffectIntentState::Pending
                    && root_intent.attempt_count == 0
                    && root_binding.is_none()
            }
            FindingEffectIntentState::Failed => {
                root_intent.state == FindingEffectIntentState::Confirmed && root_binding.is_some()
            }
            FindingEffectIntentState::Dispatched
            | FindingEffectIntentState::Confirmed
            | FindingEffectIntentState::Quarantined => false,
        };
        if root_intent.kind != FindingEffectIntentKind::RootIntent
            || root_intent.liability_key.as_deref() != Some(old.body.liability_key.as_str())
            || !root_is_refreshable
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "bond snapshot refresh is permitted only before anchor binding or dispatch"
                    .to_owned(),
            ));
        }
        let retained = self.require_retained_finalizing_authorization(
            &old.body.liability_key,
            old,
            &authorized.slash.penalty,
            true,
        )?;
        self.require_enforcement_signature(old, &retained.finalization_policy, now)?;

        let mut body = old.body.clone();
        body.bond_snapshot_envelope_sha256 = self.envelope_digest(bond_snapshot)?;
        body.finalized_at = now;
        body.finalization_authority_id = self.finalization_pin.authority_id.clone();
        body.finalization_key = self.finalization_authority.public_key();
        body.finalization_key_epoch = self.finalization_pin.key_epoch;
        body.finalization_valid_from = self.finalization_pin.valid_from;
        body.finalization_valid_until = self.finalization_pin.valid_until;
        body.finalization_revocation_status_ref =
            self.finalization_pin.revocation_status_ref.clone();
        body.enforcement_id.clear();
        body.enforcement_id =
            compute_enforcement_id(&body).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        body.validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let (_, finalization_status) =
            self.resolve_live_role(&self.finalization_pin, now, now, "finalization")?;
        let refreshed = SignedFindingChallengeEnforcement::sign_with_backend(
            body,
            self.finalization_authority.as_ref(),
        )
        .map_err(|_| ChallengeCoordinatorError::Signing)?;

        self.require_live_settlement_observer(bond_snapshot, now)?;
        let (settlement_observer, settlement_observer_status) = self.resolve_live_role(
            &self.pins.settlement_observer,
            bond_snapshot.body.observed_at,
            now,
            "settlement observer",
        )?;
        let pins = FindingEnforcementPins {
            finalization_authority: self.finalization_authority.public_key(),
            settlement_observer,
            seller: durable_seller,
            finality_requirement: self.pins.settlement_finality_requirement,
            max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
        };
        let dispatch_policy = FindingDispatchPolicy {
            penalty_authority: settlement_penalty_authority_policy(&penalty_authority)?,
            finalization_authority: settlement_penalty_authority_policy(&self.finalization_pin)?,
            settlement_observer: settlement_penalty_authority_policy(
                &self.pins.settlement_observer,
            )?,
            settlement_observer_status,
            authority_status_authority: self
                .pins
                .authority_status
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("authority status"))?,
            max_authority_status_age_secs: MAX_REVOCATION_STATUS_AGE_SECS,
            expected_sanction_case_id: retained.sanction_case_id.clone(),
            expected_held_penalty_id: retained.held_penalty_id.clone(),
            allowed_destinations: self
                .settlement_destination_allowlist(&liability.allocation_id)?,
        };
        verify_finding_enforcement(
            &refreshed,
            &authorized.slash.penalty,
            &penalty_status,
            &finalization_status,
            bond_snapshot,
            &pins,
            &dispatch_policy,
            now,
        )
        .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let refreshed_authorization = AuthorizedImpairment {
            enforcement_envelope_sha256: self.envelope_digest(&refreshed)?,
            enforcement: refreshed,
            slash: authorized.slash.clone(),
            effect_intent_keys: authorized.effect_intent_keys.clone(),
        };
        let previous_json =
            canonical_json_bytes(&retained).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let refreshed_retained = RetainedAuthorizedImpairment {
            enforcement: refreshed_authorization.enforcement.clone(),
            slash: refreshed_authorization.slash.clone(),
            finalization_policy: self.finalization_pin.clone(),
            settlement_observer_policy: self.pins.settlement_observer.clone(),
            sanction_case_id: retained.sanction_case_id,
            held_penalty_id: retained.held_penalty_id,
        };
        let refreshed_json = canonical_json_bytes(&refreshed_retained)
            .map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let refreshed_sha256 = sha256_hex(&refreshed_json);
        self.challenges
            .refresh_finalizing_authorization(
                &sha256_hex(&previous_json),
                &FindingFinalizingAuthorizationInput {
                    liability_key: &old.body.liability_key,
                    authorization_json: &refreshed_json,
                    authorization_sha256: &refreshed_sha256,
                    recorded_at: now,
                },
                &seller_intent,
                &root_intent,
                root_binding.as_ref(),
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(refreshed_authorization)
    }

    /// Verify the enforcement pair, prepare the exact authorized call,
    /// dispatch it through the injected publisher, and reconcile.
    ///
    /// Only a reconciliation that proved a finalized transaction is this
    /// exact frozen intent settles the liability. A quarantined
    /// reconciliation is not a slash and is never reported as one: the
    /// liability stays `finalizing`, publication stays pending, and
    /// purchases stay blocked. A clean vault rejection leaves the intent
    /// failed and retryable, in the same state.
    ///
    /// The terminal `quarantined` intent state is reserved for external
    /// state no further attempt can disambiguate. A receipt that has not
    /// arrived, has not finalized, or reverted is the ordinary shape of a
    /// broadcast that has not landed yet, so those leave the intent failed
    /// and dispatchable rather than closing the only edge out.
    ///
    /// Resumable. The confirmed intent and the settled head are two
    /// transactions, so an attempt can die between them. A re-entry that
    /// finds the fenced intent already confirmed dispatches nothing, resumes
    /// the status-publication gate, and settles only after every durable
    /// effect is confirmed.
    ///
    /// Live state. A signed snapshot attests what an observer saw at one
    /// block, which is not the same as what is true now. Before dispatch,
    /// the injected observation source is read against that snapshot both
    /// before the call is prepared and before the head settles. Recovery
    /// instead re-observes the exact confirmed transaction, so an operator
    /// rotation cannot either authorize a new dispatch or strand collateral
    /// that already moved.
    ///
    /// Authorization to broadcast. The vault verifies the impairment
    /// against a published root, so both effects the instruction binds are
    /// resolved before anything leaves: the enforcement root must be
    /// confirmed for this liability and this penalty, and the anchored
    /// evidence leaf is fenced under its own key so one proof can
    /// authorize one impairment and no more.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        bond_snapshot: &SignedFindingFinalizedBondSnapshot,
        seller: &PublicKey,
        settlement_config: &SettlementChainConfig,
        operator_address: &str,
        vault_snapshot: &EvmBondSnapshot,
        anchor_proof: &AnchorInclusionProof,
        observations: &dyn FindingBondObservationSource,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<FindingFinalization, ChallengeCoordinatorError> {
        let liability = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(ChallengeCoordinatorError::LiabilityState("finalizing"));
        }
        let durable_seller = PublicKey::from_hex(&liability.seller_hex).map_err(|_| {
            ChallengeCoordinatorError::ChallengeStore(
                "liability carries an invalid durable seller key".to_owned(),
            )
        })?;
        if seller != &durable_seller {
            return Err(ChallengeCoordinatorError::LiabilityIdentity("seller"));
        }
        if enforcement.body.liability_key != liability_key {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement does not name this liability".to_owned(),
            ));
        }
        // Everything downstream binds the vault, the allocation, and the
        // seller to the enforcement's own self-declaration. The head is
        // what anchors that triple to the defect being settled, so one
        // liability can never authorize an impairment against a target it
        // was not opened against.
        let body = &enforcement.body;
        let bindings: [(&str, &str, &'static str); 6] = [
            (&liability.finding_id, &body.finding_id, "finding_id"),
            (&liability.listing_id, &body.listing_id, "listing_id"),
            (
                &liability.allocation_id,
                &body.seller_allocation_id,
                "allocation_id",
            ),
            (&liability.chain_id, &body.vault.chain_id, "chain_id"),
            (
                &liability.vault_contract,
                &body.vault.vault_contract,
                "vault_contract",
            ),
            (&liability.vault_id, &body.vault.vault_id, "vault_id"),
        ];
        for (durable, declared, label) in bindings {
            if durable != declared {
                return Err(ChallengeCoordinatorError::LiabilityIdentity(label));
            }
        }
        let (penalty_status, penalty_authority) =
            self.require_penalty_matches_enforcement(&liability, enforcement, penalty, now)?;
        let seller_intent_id = enforcement
            .body
            .effect_intents
            .iter()
            .find(|binding| binding.kind == chio_finding::FindingEffectIntentKind::SellerImpair)
            .map(|binding| binding.intent_id.as_str())
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let seller_intent = self
            .challenges
            .get_effect_intent(seller_intent_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if seller_intent.kind != FindingEffectIntentKind::SellerImpair
            || seller_intent.liability_key.as_deref() != Some(liability_key)
            || !seller_intent.settlement_required
        {
            return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
        }
        let retained = self.require_retained_finalizing_authorization(
            liability_key,
            enforcement,
            penalty,
            matches!(
                seller_intent.state,
                FindingEffectIntentState::Pending
                    | FindingEffectIntentState::Failed
                    | FindingEffectIntentState::Confirmed
            ),
        )?;
        let (finalization_authority, finalization_status) =
            self.require_enforcement_signature(enforcement, &retained.finalization_policy, now)?;
        let seller_was_confirmed = seller_intent.state == FindingEffectIntentState::Confirmed;
        let (settlement_observer, settlement_observer_status) = if seller_was_confirmed {
            // The finalization authority content-bound this exact signed
            // snapshot before dispatch. Recovery authenticates that frozen
            // history under its original observer even after the configured
            // operator rotates; the confirmed transaction itself is
            // independently re-observed below.
            (
                self.require_live_role(
                    &retained.settlement_observer_policy,
                    bond_snapshot.body.observed_at,
                    now,
                    "historical settlement observer",
                )?,
                None,
            )
        } else {
            self.require_live_settlement_observer(bond_snapshot, now)?;
            let (key, status) = self.resolve_live_role(
                &self.pins.settlement_observer,
                bond_snapshot.body.observed_at,
                now,
                "settlement observer",
            )?;
            (key, Some(status))
        };
        let pins = FindingEnforcementPins {
            finalization_authority,
            settlement_observer,
            seller: durable_seller,
            finality_requirement: self.pins.settlement_finality_requirement,
            max_snapshot_age_secs: self.market_config.max_snapshot_age_secs,
        };
        let anchor_publisher = self.authenticate_anchor_publisher(anchor_proof, now)?;
        if seller_was_confirmed {
            // Recovery authenticates the frozen observation but does not
            // require it to remain publication-fresh. The transaction and
            // its canonical receipt are independently re-observed below.
            let reconciled = verify_finding_enforcement_for_reconciliation(
                enforcement,
                bond_snapshot,
                &pins,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
            let planned = plan_finding_impairment_for_reconciliation(
                settlement_config,
                &reconciled,
                operator_address,
                vault_snapshot,
                anchor_proof,
                anchor_publisher.evidence(),
            )
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
            let intent = self
                .challenges
                .get_effect_intent(&planned.intent().intent_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
            if intent.state != FindingEffectIntentState::Confirmed {
                return Err(ChallengeCoordinatorError::EffectIntentUnfenced);
            }
            self.require_confirmed_reconciliation_root(liability_key, &reconciled, &planned)?;
            // Reconciliation authority exposes no dispatchable plan. It can
            // only re-read the transaction already fenced by this confirmed
            // intent.
            let reconciliation =
                match self.require_reobserved_reconciliation(&planned, publisher, None) {
                    Ok(reconciliation) => reconciliation,
                    Err(error) => {
                        self.challenges
                            .set_liability_quarantine(liability_key, true, now)
                            .map_err(|store| {
                                ChallengeCoordinatorError::ChallengeStore(store.to_string())
                            })?;
                        return Err(error);
                    }
                };
            return self.finish_confirmed_impairment(
                liability_key,
                enforcement,
                bond_snapshot,
                &reconciliation,
                RecoveryObservationAuthority::Reconciled(&reconciled),
                observations,
                now,
            );
        }

        let dispatch_policy =
            FindingDispatchPolicy {
                penalty_authority: settlement_penalty_authority_policy(&penalty_authority)?,
                finalization_authority: settlement_penalty_authority_policy(
                    &retained.finalization_policy,
                )?,
                settlement_observer: settlement_penalty_authority_policy(
                    &self.pins.settlement_observer,
                )?,
                settlement_observer_status: settlement_observer_status.ok_or(
                    ChallengeCoordinatorError::SettlementObserverLifecycle(
                        "fresh dispatch lacks an authenticated observer status",
                    ),
                )?,
                authority_status_authority: self.pins.authority_status.key().map_err(|_| {
                    ChallengeCoordinatorError::AuthorityPinMismatch("authority status")
                })?,
                max_authority_status_age_secs: MAX_REVOCATION_STATUS_AGE_SECS,
                expected_sanction_case_id: retained.sanction_case_id.clone(),
                expected_held_penalty_id: retained.held_penalty_id.clone(),
                allowed_destinations: self
                    .settlement_destination_allowlist(&liability.allocation_id)?,
            };
        let verified = verify_finding_enforcement(
            enforcement,
            penalty,
            &penalty_status,
            &finalization_status,
            bond_snapshot,
            &pins,
            &dispatch_policy,
            now,
        )
        .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        // Before dispatch, the snapshot's signature proves who observed the
        // collateral, not that what they observed is still true. A reorg or
        // operator rotation leaves the authorized amount unknown, so the
        // chain is re-read before preparing the call.
        self.require_qualified_observation(&verified, observations)?;
        let planned = plan_finding_impairment(
            settlement_config,
            &verified,
            operator_address,
            vault_snapshot,
            anchor_proof,
            anchor_publisher.evidence(),
        )
        .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let intent_key = planned.intent().intent_id.clone();
        // The intent must already be durable: the publisher contract
        // refuses an unfenced dispatch, and so does this coordinator.
        let intent = self
            .challenges
            .get_effect_intent(&intent_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        if intent.state == FindingEffectIntentState::Confirmed {
            self.require_confirmed_enforcement_root(liability_key, &verified, planned.intent())?;
            // The impairment already landed and was proved to be this
            // intent. Dispatching again would ask the vault to move the
            // same collateral twice. Re-read the stored transaction before
            // settlement so a later reorg or loss of finality cannot inherit
            // an earlier confirmation as current chain truth.
            let reconciliation = match self.require_reobserved_impairment(&planned, publisher, None)
            {
                Ok(reconciliation) => reconciliation,
                Err(error) => {
                    self.challenges
                        .set_liability_quarantine(liability_key, true, now)
                        .map_err(|store| {
                            ChallengeCoordinatorError::ChallengeStore(store.to_string())
                        })?;
                    return Err(error);
                }
            };
            self.require_confirmed_enforcement_root(liability_key, &verified, planned.intent())?;
            self.recover_anchor_binding(liability_key, &verified, planned.intent(), now)?;
            return self.finish_confirmed_impairment(
                liability_key,
                enforcement,
                bond_snapshot,
                &reconciliation,
                RecoveryObservationAuthority::Fresh(&verified),
                observations,
                now,
            );
        }
        self.require_sanction_governs(liability_key, &retained.sanction_case_id)?;
        self.require_current_role(
            &self.status_feed_operator.authority,
            now,
            now,
            "status feed operator",
        )?;
        self.bind_enforcement_root(liability_key, &verified, planned.intent(), now)?;
        self.require_confirmed_enforcement_root(liability_key, &verified, planned.intent())?;
        self.fence_anchor_evidence(liability_key, &verified, planned.intent(), now)?;
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let outcome = match dispatch_finding_impairment(&planned, publisher) {
            Ok(outcome) => outcome,
            Err(error) => {
                // A publisher that cannot say what happened leaves the
                // intent dispatchable, and it returns to `failed` to say
                // so. Leaving it in `dispatched` would be the same
                // resumable state, but the next attempt would reconcile
                // as an identical retry and count nothing, so every
                // attempt after the first would vanish from the record an
                // operator reads a stuck impairment out of.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|store| {
                        ChallengeCoordinatorError::ChallengeStore(store.to_string())
                    })?;
                return Err(ChallengeCoordinatorError::Publisher(error.to_string()));
            }
        };

        match &outcome {
            FindingImpairmentOutcome::Confirmed { reconciliation } => {
                let tx_hash = reconciliation.tx_hash();
                // Settling is the separate question. The head closes only
                // if the observation the amount was computed against is
                // still the canonical one at the receipt's finality; a
                // reorg or a rotation across the broadcast means an
                // operator has to reconcile what actually moved, and a
                // settled head would have closed the last edge to do it
                // from. Confirmation and quarantine are one store
                // transaction on that failure path, so no concurrent
                // finalizer can observe the confirmation without its
                // fail-closed head state.
                let confirmed =
                    match self.require_reobserved_impairment(&planned, publisher, Some(tx_hash)) {
                        Ok(confirmed) => confirmed,
                        Err(error) => {
                            // The publisher is idempotent by intent, so a failed
                            // recheck returns this intent to the recoverable lane
                            // without authorizing another semantic impairment.
                            self.challenges
                                .advance_effect_intent(
                                    &intent_key,
                                    FindingEffectIntentState::Failed,
                                    now,
                                )
                                .map_err(|store| {
                                    ChallengeCoordinatorError::ChallengeStore(store.to_string())
                                })?;
                            self.challenges
                                .set_liability_quarantine(liability_key, true, now)
                                .map_err(|store| {
                                    ChallengeCoordinatorError::ChallengeStore(store.to_string())
                                })?;
                            return Err(error);
                        }
                    };
                if let Err(error) = self.require_qualified_observation(&verified, observations) {
                    self.challenges
                        .confirm_seller_impairment_and_quarantine(&confirmed, now)
                        .map_err(|store| {
                            ChallengeCoordinatorError::ChallengeStore(store.to_string())
                        })?;
                    return Err(error);
                }
                // Only a transaction that survived the immediate receipt,
                // canonical-block, finality, and collateral rechecks makes
                // the status retraction dispatchable.
                self.mark_retraction_dispatch_eligible(enforcement, tx_hash, now)?;
                // A finalized transaction was proved to be this exact
                // intent, so the intent is confirmed: leaving it
                // dispatchable would invite a second impairment of the
                // same collateral.
                self.challenges
                    .confirm_reconciled_seller_impairment(&confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                let anchor_key = derive_anchor_evidence_intent_key(&planned.intent().evidence_hash);
                self.confirm_effect_intent(&anchor_key, now)?;
                self.reconcile_status_publication_and_settle(liability_key, enforcement, now)?;
            }
            FindingImpairmentOutcome::Quarantined { reason } if quarantine_is_pending(*reason) => {
                // A broadcast whose receipt has not arrived, has not
                // finalized, or reverted is an observation still in
                // flight. It leaves the intent failed and dispatchable,
                // because the terminal quarantined state would close the
                // only edge the same transaction can still be proved on.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingImpairmentOutcome::Quarantined { .. } => {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Quarantined, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                self.challenges
                    .set_liability_quarantine(liability_key, true, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            FindingImpairmentOutcome::Failed { .. } => {
                // A clean vault rejection is unambiguous and retryable, so
                // the intent returns to failed rather than quarantined.
                // The liability keeps blocking purchases either way.
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
        }
        Ok(FindingFinalization::Reconciled(outcome))
    }
}
